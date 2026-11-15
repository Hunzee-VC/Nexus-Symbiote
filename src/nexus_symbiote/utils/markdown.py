"""The text of a Markdown file outside its code, as CommonMark reads it.

A host that loads instructions written in Markdown, such as a Claude Code memory file,
takes ``@path`` imports from its text and not from its code. Which is which is decided
by the block structure of the whole file and by how backticks pair across the lines of
a paragraph, so a reader that looks at one line at a time can be led to take text for
code.

:func:`text_outside_code` reads blocks as commonmark.js, the reference implementation
of CommonMark 0.31.2, reads them: lines end only at CR, LF or CRLF, and block quotes,
list items, fenced and indented code, HTML blocks, headings and paragraphs start and
end where it starts and ends them. Code spans pair as CommonMark pairs them, with
backslash escapes. Where readers that hosts use, such as markdown-it and marked, read
the same text another way, or the reading turns on what is not modelled here, the
text is left as written, so that nothing a host may read as text is taken for code:
the rest of a paragraph after a bracket that can close a link and is followed by a
link label or by a destination that is not plain, or after a ``<`` that could open an
autolink or raw HTML holding a backtick or closing bracket; a paragraph that can open with a link
reference definition; and the whole file where such a definition, a lazy line indented
four columns or a form feed after a list marker can change the block structure, or
where containers nest or match past a bound. Indented code and HTML blocks are
returned as written too.

:func:`hidden_text` reads the same blocks for what a rendered view shows nothing of:
the link reference definitions that no link uses, and the raw HTML that HTML parsers
read as comments. It errs the other way, toward reporting: a reference counts as a use
only where every reader makes a link of it.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from collections.abc import Callable
from dataclasses import dataclass, field

_LINE_END = re.compile(r"\r\n|\r|\n")
# Containers nested this deep, or more container lines matched than the text has
# characters plus this many, make the whole text be returned: each blank line matches
# every open list item again.
_MAX_NESTING = 64
_SPARE_MATCHES = 4096
_CODE_INDENT = 4
_SPACE_OR_TAB = (" ", "\t")
_MAYBE_SPECIAL = re.compile(r"[#`~*+_=<>0-9-]")
_ATX_HEADING = re.compile(r"#{1,6}(?:[ \t]+|$)")
_OPENING_FENCE = re.compile(r"`{3,}(?!.*`)|~{3,}")
_CLOSING_FENCE = re.compile(r"(?:`{3,}|~{3,})(?=[ \t]*$)")
_THEMATIC_BREAK = re.compile(r"(?:(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|(?:-[ \t]*){3,})$")
_SETEXT_UNDERLINE = re.compile(r"(?:=+|-+)[ \t]*$")
_LIST_MARKER = re.compile(r"[*+-]|(\d{1,9})[.)]")
_LIST_STARTS = frozenset("*+-0123456789")
_NON_SPACE = re.compile(r"[^ \t\f\v\r\n]")
# Whitespace as the JavaScript readers that hosts use match it in HTML.
_WHITESPACE = "[\t\n\x0b\x0c\r \xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]"
_OPEN_TAG = (
    rf"<[A-Za-z][A-Za-z0-9-]*(?:{_WHITESPACE}+[a-zA-Z_:][a-zA-Z0-9:._-]*"
    rf"(?:{_WHITESPACE}*={_WHITESPACE}*(?:[^\"'=<>`\x00-\x20]+|'[^']*'|\"[^\"]*\"))?)*"
    rf"{_WHITESPACE}*/?>"
)
_CLOSE_TAG = rf"</[A-Za-z][A-Za-z0-9-]*{_WHITESPACE}*>"
_BLOCK_TAG_NAMES = (
    "address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd"
    "|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset"
    "|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol"
    "|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title"
    "|tr|track|ul"
)
# The seven start conditions of an HTML block, and the end conditions of the first five;
# the last two end at a blank line.
_HTML_BLOCK_STARTS = (
    re.compile(rf"<(?:pre|script|style|textarea)(?:{_WHITESPACE}|>|$)", re.I),
    re.compile(r"<!--"),
    re.compile(r"<\?"),
    re.compile(r"<![A-Za-z]"),
    re.compile(r"<!\[CDATA\["),
    re.compile(rf"</?(?:{_BLOCK_TAG_NAMES})(?:{_WHITESPACE}|/?>|$)", re.I),
    re.compile(rf"(?:{_OPEN_TAG}|{_CLOSE_TAG}){_WHITESPACE}*$"),
)
_HTML_BLOCK_ENDS: tuple[re.Pattern[str] | str, ...] = (
    re.compile(r"</(?:pre|script|style|textarea)>", re.I),
    "-->",
    "?>",
    ">",
    "]]>",
)
"""End conditions of HTML block types 1 to 5; types 2 to 5 end at a literal string."""


def _html_block_ends(kind: int, line: str, offset: int) -> bool:
    end = _HTML_BLOCK_ENDS[kind - 1]
    if isinstance(end, str):
        return line.find(end, offset) >= 0
    return end.search(line, offset) is not None


# Inline: what pairs backticks, and what can take one out of a code span.
_INLINE_SPECIAL = re.compile(r"[\\`\[\]<]")
_BACKTICKS = re.compile(r"`+")
_ESCAPABLE = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
_DEFINITION = re.compile(r"\[(?:[^\\\[\]]|\\.){0,1000}\]:", re.S)
# After a link reference definition commonmark.js reads a line as part of its paragraph,
# while markdown-it and marked start a new block there: a line that is lazy, indented
# four columns, or that starts with one of these, can then start a different block.
_AFTER_DEFINITION = frozenset("<0123456789-*+=")
# A destination that holds nothing a link could take out of a code span, read the same
# whether or not the brackets before it form a link.
_PLAIN_DESTINATION = re.compile(r"\([^\s()<>\[\]\\`\"']*\)")
# What an autolink or raw HTML would take from the text if a reader found one, which
# readers that follow different versions of CommonMark do not agree on.
_TAKEN = re.compile(r"[`\]]")


class _AmbiguousError(Exception):
    """The block structure turns on what the reader does not model."""


@dataclass(slots=True)
class _Block:
    kind: str
    lines: list[str] = field(default_factory=list)
    children: int = 0
    definitions: int = 0
    definition: bool = False
    marker: str = ""
    width: int = 0
    fence: str = ""
    fence_offset: int = 0
    html: int = 0


def text_outside_code(text: str) -> list[str]:
    """The parts of ``text`` that a CommonMark reader does not read as code.

    Each paragraph and heading is one part, with its code spans replaced by a space;
    an HTML block or indented code line is returned as written, and fenced code is left
    out. A file whose reading this cannot settle is returned whole.
    """
    lines = _LINE_END.split(text)
    if text.endswith("\n"):
        lines.pop()
    reader = _Reader(len(text) + _SPARE_MATCHES)
    try:
        for line in lines:
            reader.read(line)
        reader.finish()
    except _AmbiguousError:
        return [text]
    return reader.parts


class _Reader:
    """commonmark.js block parsing, keeping only what decides code from text."""

    def __init__(self, matches: int) -> None:
        self.matches = matches
        self.parts: list[str] = []
        # Each paragraph, heading and HTML block as written, with its kind, in order.
        self.blocks: list[tuple[str, str]] = []
        self.stack = [_Block("document")]
        self.line = ""
        self.offset = self.column = 0
        self.next_nonspace = self.next_column = self.indent = 0
        self.blank = self.indented = self.partial = False
        self.all_closed = True
        self.matched = 0
        # The first nonspace character after the offset, and its column; columns count
        # from the start of the line, so it stays found while the offset stays before it.
        self.found = (-1, 0)

    def read(self, line: str) -> None:
        self.line = line
        self.offset = self.column = 0
        self.blank = self.partial = False
        self.found = (-1, 0)
        stack = self.stack
        old_tip = len(stack) - 1
        self.matches -= old_tip
        if self.matches < 0:
            raise _AmbiguousError
        container = 0
        for depth in range(1, len(stack)):
            self._find_next_nonspace()
            outcome = self._continue(stack[depth], depth == old_tip)
            if outcome == 2:
                return
            if outcome == 1:
                break
            container = depth
        self.all_closed = container == old_tip
        self.matched = container
        leaf = stack[container].kind in ("fence", "indented", "html")
        while not leaf:
            self._find_next_nonspace()
            if not self.indented and not _MAYBE_SPECIAL.match(line, self.next_nonspace):
                self._advance_next_nonspace()
                break
            started = self._start(container)
            if not started:
                self._advance_next_nonspace()
                break
            container = len(stack) - 1
            leaf = started == 2
        if not self.all_closed and not self.blank and stack[-1].kind == "paragraph":
            # markdown-it measures a lazy line's indentation from the content of the
            # container it left, where it can start a block.
            if stack[-1].definition or self.indented:
                raise _AmbiguousError
            self._add_line()
            return
        self._close_unmatched()
        block = stack[container]
        if block.definition and (
            self.indented or self._peek(self.next_nonspace) in _AFTER_DEFINITION
        ):
            raise _AmbiguousError
        if block.kind in ("paragraph", "fence", "indented", "html"):
            self._add_line()
            if 1 <= block.html <= 5 and _html_block_ends(block.html, line, self.offset):
                self._finalize()
        elif self.offset < len(line) and not self.blank:
            self._add_child("paragraph")
            self._advance_next_nonspace()
            self._add_line()

    def finish(self) -> None:
        while len(self.stack) > 1:
            self._finalize()

    def _peek(self, index: int) -> str:
        return self.line[index : index + 1]

    def _find_next_nonspace(self) -> None:
        index, column = self.found
        if index < self.offset:
            line, index, column = self.line, self.offset, self.column
            while index < len(line):
                char = line[index]
                if char == " ":
                    column += 1
                elif char == "\t":
                    column += 4 - column % 4
                else:
                    break
                index += 1
            self.found = (index, column)
        self.blank = index == len(self.line)
        self.next_nonspace, self.next_column = index, column
        self.indent = column - self.column
        self.indented = self.indent >= _CODE_INDENT

    def _advance_next_nonspace(self) -> None:
        self.offset, self.column, self.partial = self.next_nonspace, self.next_column, False

    def _advance(self, count: int, *, columns: bool) -> None:
        line = self.line
        while count > 0 and self.offset < len(line):
            if line[self.offset] == "\t":
                to_tab = 4 - self.column % 4
                if columns:
                    self.partial = to_tab > count
                    step = min(count, to_tab)
                    self.column += step
                    self.offset += 0 if self.partial else 1
                    count -= step
                else:
                    self.partial = False
                    self.column += to_tab
                    self.offset += 1
                    count -= 1
            else:
                self.partial = False
                self.offset += 1
                self.column += 1
                count -= 1

    def _continue(self, block: _Block, last: bool) -> int:
        """0 when ``block`` continues on this line, 1 when it does not, and 2 when the
        line closes a fence and holds nothing more."""
        kind = block.kind
        if kind == "quote":
            if self.indented and self._peek(self.next_nonspace) == ">":
                # markdown-it continues a block quote at a marker indented four columns.
                raise _AmbiguousError
            if self.indented or self._peek(self.next_nonspace) != ">":
                return 1
            self._advance_next_nonspace()
            self._advance(1, columns=False)
            if self._peek(self.offset) in _SPACE_OR_TAB:
                self._advance(1, columns=True)
        elif kind == "item":
            if self.blank:
                if not block.children:
                    return 1
                if last and block.children == block.definitions:
                    # commonmark.js drops a paragraph that held only link reference
                    # definitions, after which a blank line ends an empty item.
                    raise _AmbiguousError
                self._advance_next_nonspace()
            elif self.indent >= block.width:
                self._advance(block.width, columns=True)
            else:
                return 1
        elif kind == "fence":
            if self.indent <= 3 and self._peek(self.next_nonspace) == block.fence[0]:
                closing = _CLOSING_FENCE.match(self.line, self.next_nonspace)
                if closing is not None and len(closing.group()) >= len(block.fence):
                    self._finalize()
                    return 2
            skip = block.fence_offset
            while skip > 0 and self._peek(self.offset) in _SPACE_OR_TAB:
                self._advance(1, columns=True)
                skip -= 1
        elif kind == "indented":
            if self.indent >= _CODE_INDENT:
                self._advance(_CODE_INDENT, columns=True)
            elif self.blank:
                self._advance_next_nonspace()
            else:
                return 1
        elif kind == "html":
            return 1 if self.blank and block.html >= 6 else 0
        elif kind == "paragraph":
            return 1 if self.blank else 0
        elif kind in ("heading", "break"):
            return 1
        return 0

    def _start(self, container: int) -> int:
        """0 when no block starts here, 1 for a container and 2 for a leaf."""
        line, at = self.line, self.next_nonspace
        char = self._peek(at)
        parent = self.stack[container]
        if not self.indented:
            if char == ">":
                self._advance_next_nonspace()
                self._advance(1, columns=False)
                if self._peek(self.offset) in _SPACE_OR_TAB:
                    self._advance(1, columns=True)
                self._close_unmatched()
                self._add_child("quote")
                return 1
            heading = _ATX_HEADING.match(line, at) if char == "#" else None
            if heading is not None:
                self._advance_next_nonspace()
                self._advance(len(heading.group()), columns=False)
                self._close_unmatched()
                self._add_child("heading")
                self.parts.append(_outside_spans(line[self.offset :]))
                self.blocks.append(("heading", line[self.offset :]))
                self.offset = len(line)
                return 2
            fence = _OPENING_FENCE.match(line, at) if char in ("`", "~") else None
            if fence is not None:
                self._close_unmatched()
                block = self._add_child("fence")
                block.fence = fence.group()
                block.fence_offset = self.indent
                self._advance_next_nonspace()
                self._advance(len(block.fence), columns=False)
                return 2
            if char == "<":
                lazy = not self.all_closed and not self.blank and self.stack[-1].kind == "paragraph"
                for kind, start in enumerate(_HTML_BLOCK_STARTS, 1):
                    if start.match(line, at) and (
                        kind < 7 or (parent.kind != "paragraph" and not lazy)
                    ):
                        self._close_unmatched()
                        self._add_child("html").html = kind
                        return 2
            if (
                char in ("=", "-")
                and parent.kind == "paragraph"
                and _SETEXT_UNDERLINE.match(line, at)
            ):
                self._close_unmatched()
                content = "\n".join(parent.lines)
                if _DEFINITION.match(content):
                    # A paragraph of nothing but definitions is no heading.
                    raise _AmbiguousError
                self.parts.append(_outside_spans(content))
                self.blocks.append(("heading", content))
                parent.kind, parent.lines = "heading", []
                self.offset = len(line)
                return 2
            if char in ("*", "_", "-") and _THEMATIC_BREAK.match(line, at):
                self._close_unmatched()
                self._add_child("break")
                self.offset = len(line)
                return 2
        if (
            char in _LIST_STARTS
            and (not self.indented or parent.kind == "list")
            and self._list_item(parent)
        ):
            return 1
        if self.indented and self.stack[-1].kind != "paragraph" and not self.blank:
            self._advance(_CODE_INDENT, columns=True)
            self._close_unmatched()
            self._add_child("indented")
            return 2
        return 0

    def _list_item(self, parent: _Block) -> bool:
        line, at = self.line, self.next_nonspace
        if self.indent >= _CODE_INDENT:
            return False
        marker = _LIST_MARKER.match(line, at)
        if marker is None:
            return False
        ordered = marker.group(1)
        if ordered is not None and parent.kind == "paragraph" and int(ordered) != 1:
            return False
        end = marker.end()
        if self._peek(end) not in ("", " ", "\t"):
            return False
        if parent.kind == "paragraph" and not _NON_SPACE.search(line, end):
            if line[end:].strip(" \t"):
                # A form feed or vertical tab is blank to commonmark.js, not to others.
                raise _AmbiguousError
            return False
        self._advance_next_nonspace()
        self._advance(end - at, columns=True)
        spaces_column, spaces_offset = self.column, self.offset
        while True:
            self._advance(1, columns=True)
            if not (self.column - spaces_column < 5 and self._peek(self.offset) in _SPACE_OR_TAB):
                break
        spaces = self.column - spaces_column
        if spaces >= 5 or spaces < 1 or self._peek(self.offset) == "":
            padding = end - at + 1
            self.column, self.offset = spaces_column, spaces_offset
            if self._peek(self.offset) in _SPACE_OR_TAB:
                self._advance(1, columns=True)
        else:
            padding = end - at + spaces
        kind = ("ordered" + line[end - 1]) if ordered is not None else ("bullet" + line[at])
        self._close_unmatched()
        tip = self.stack[-1]
        if tip.kind != "list" or tip.marker != kind:
            self._add_child("list").marker = kind
        item = self._add_child("item")
        item.marker, item.width = kind, self.indent + padding
        return True

    def _add_line(self) -> None:
        tip = self.stack[-1]
        content = self.line[self.offset :]
        if tip.kind == "paragraph":
            if not tip.lines:
                tip.definition = bool(_DEFINITION.match(content)) or (
                    content.startswith("[") and "]" not in content
                )
            tip.lines.append(content)
        elif tip.kind in ("indented", "html"):
            self.parts.append(content)
            if tip.kind == "html":
                tip.lines.append(content)

    def _add_child(self, kind: str) -> _Block:
        while not _can_contain(self.stack[-1].kind, kind):
            self._finalize()
        if len(self.stack) > _MAX_NESTING:
            raise _AmbiguousError
        self.stack[-1].children += 1
        block = _Block(kind)
        self.stack.append(block)
        return block

    def _close_unmatched(self) -> None:
        if not self.all_closed:
            while len(self.stack) - 1 > self.matched:
                self._finalize()
            self.all_closed = True

    def _finalize(self) -> None:
        block = self.stack.pop()
        if block.kind == "paragraph":
            content = "\n".join(block.lines)
            if _DEFINITION.match(content):
                self.stack[-1].definitions += 1
            self.parts.append(_outside_spans(content))
            self.blocks.append(("paragraph", content))
        elif block.kind == "html":
            self.blocks.append(("html", "\n".join(block.lines)))


def _can_contain(parent: str, child: str) -> bool:
    if parent == "list":
        return child == "item"
    return parent in ("document", "quote", "item") and child != "item"


def _outside_spans(text: str) -> str:
    """``text`` with each code span replaced by a space, as CommonMark pairs backticks.

    A backslash escapes a backtick. What follows is left as written where a reader
    could take a backtick or a closing bracket into an autolink or raw HTML, every
    one of which ends at a ``>``; after a bracket that can close a link followed by a
    link label or by a destination that is not plain; and in a paragraph that can open
    with a link reference definition.
    """
    if _DEFINITION.match(text):
        return text
    runs: dict[int, list[int]] = {}
    for found_run in _BACKTICKS.finditer(text):
        runs.setdefault(found_run.end() - found_run.start(), []).append(found_run.start())
    last_close = text.rfind(">")
    taken = -1
    kept: list[str] = []
    copied = position = brackets = 0
    while (found := _INLINE_SPECIAL.search(text, position)) is not None:
        position = found.start()
        char = text[position]
        if char == "\\":
            position += 2 if text[position + 1 : position + 2] in _ESCAPABLE else 1
        elif char == "`":
            run = _BACKTICKS.match(text, position)
            end = position + 1 if run is None else run.end()
            starts = runs.get(end - position, [])
            index = bisect_left(starts, end)
            if index == len(starts):
                position = end
            else:
                kept += [text[copied:position], " "]
                position = copied = starts[index] + end - position
        elif char == "<":
            position += 1
            if text[position : position + 1].strip():
                if taken < position:
                    after = _TAKEN.search(text, position)
                    taken = len(text) if after is None else after.start()
                if taken < last_close:
                    break
        elif char == "[":
            brackets += 1
            position += 1
        else:
            position += 1
            if brackets:
                brackets -= 1
                following = text[position : position + 1]
                if following == "[" or (
                    following == "(" and not _PLAIN_DESTINATION.match(text, position)
                ):
                    break
    kept.append(text[copied:])
    return "".join(kept)


@dataclass(frozen=True, slots=True)
class HiddenText:
    """What a rendered view of a Markdown text shows nothing of, as written in it."""

    definitions: tuple[str, ...]
    """Link reference definitions that no link uses, and every later one of a label."""
    html: tuple[str, ...]
    """Processing instructions, declarations and CDATA sections, which HTML parsers
    read as comments."""


def hidden_text(text: str) -> HiddenText:
    """The link reference definitions and raw HTML of ``text`` that render as nothing.

    Blocks are read as :func:`text_outside_code` reads them, so code is left out. A
    definition is taken from the start of any line of a paragraph, with spaces or tabs
    between its parts, a title read as CommonMark reads it or, failing that, as the
    rest of its line, so that a reader that takes more definitions than commonmark.js
    does cannot hide one. A definition is visible only as the destination of the links
    that use it, so it is returned unless a reference that every reader takes for a
    link names its label: references in code, raw HTML, autolinks and link
    destinations do not count, nor do those after a link this cannot settle. HTML
    comments are left to the caller. A file whose blocks this cannot settle is read
    line by line, inside every container and code block, and each of its definitions
    is returned.
    """
    lines = _LINE_END.split(text)
    if text.endswith("\n"):
        lines.pop()
    reader = _Reader(len(text) + _SPARE_MATCHES)
    try:
        for line in lines:
            reader.read(line)
        reader.finish()
    except _AmbiguousError:
        return _hidden_in_whole(_LINE_END.sub("\n", text))
    spans: list[tuple[str, str]] = []
    html: list[str] = []
    readings: list[str] = []
    for kind, content in reader.blocks:
        if kind == "html":
            html += _hidden_html(content, block=True)
            continue
        inline = reading = content
        if kind == "paragraph":
            found = _definition_spans(content)
            spans += [(content[start:end], label) for start, end, label, _ in found]
            leading = _leading_definitions_end(content, found)
            later = [(start, end) for start, end, _, _ in found if start >= leading]
            inline = content[leading:]
            if any(_TAKEN_BY_INLINE.search(content, start, end) for start, end in later):
                reading = ""
            else:
                cuts = [leading, *(edge for span in later for edge in span), len(content)]
                pairs = zip(cuts[::2], cuts[1::2], strict=True)
                reading = "\n".join(content[a:b] for a, b in pairs)
        html += _hidden_html(_outside_spans(inline), block=False)
        readings.append(reading)
    defined = [_label_keys(label) for _, label in spans]
    folded = {keys[0] for keys in defined}
    lowered = {keys[1] for keys in defined}

    def is_defined(label: str) -> bool:
        keys = _label_keys(label)
        return keys[0] in folded or keys[1] in lowered

    used = [_label_keys(label) for part in readings for label in _references(part, is_defined)]
    used_folded = {keys[0] for keys in used}
    used_lowered = {keys[1] for keys in used}
    hidden: list[str] = []
    seen_folded: set[str] = set()
    seen_lowered: set[str] = set()
    for (definition, _), (fold, lower) in zip(spans, defined, strict=True):
        if (
            fold in seen_folded
            or lower in seen_lowered
            or fold not in used_folded
            or lower not in used_lowered
        ):
            hidden.append(definition)
        seen_folded.add(fold)
        seen_lowered.add(lower)
    return HiddenText(tuple(hidden), tuple(html))


_ASCII_WHITESPACE = " \t\n\r\x0b\x0c"
_ASCII_SPACE_RUN = re.compile(f"[{_ASCII_WHITESPACE}]+")
_PUNCTUATION = re.escape("".join(sorted(_ESCAPABLE)))
# Labels longer than this make no link in commonmark.js.
_MAX_LABEL = 999
# What can open a code span or raw HTML that runs past the end of a definition or link,
# when a reader reads that definition or link as text.
_TAKEN_BY_INLINE = re.compile(r"[`<]")
_DESTINATION_STOP = re.compile(rf"[\\(){_ASCII_WHITESPACE}]")
# Markdown-it reads no definition with one of these destinations.
_REFUSED_SCHEME = re.compile(r"<?[ \t]*(?:javascript|vbscript|file|data):", re.I)
# A definition as a reader that takes one from any line of a paragraph reads it: a label
# on one line, the destination on that line or the next, and a title that runs to the
# last quote or parenthesis of its line.
_LINE_DEFINITION = re.compile(
    r"\[([^\[\]\n]*+)\]:[ ]*+\n?[ ]*+\S++"
    r"(?:[ ]*+\n?[ ]*+(?:([\"'])[^\n]*\2|\([^\n]*\)))?[ ]*+(?=\n|\Z)"
)


def _label_keys(label: str) -> tuple[str, str]:
    """``label`` as cmark folds it, and as the JavaScript readers fold it."""
    return (
        _ASCII_SPACE_RUN.sub(" ", label).strip(" ").casefold(),
        " ".join(label.split()).lower().upper(),
    )


def _escaped(text: str, index: int) -> bool:
    run = index
    while run > 0 and text[run - 1] == "\\":
        run -= 1
    return (index - run) % 2 == 1


class _Positions:
    """Searches of one text for the next occurrence of a string, each remembered, so
    that searches from later starts do not read the same text again."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.found: dict[tuple[str, bool], tuple[int, int]] = {}

    def next(self, target: str, start: int, *, unescaped: bool = False) -> int:
        """The next ``target`` at or after ``start``; with ``unescaped``, the next that no
        backslash escapes."""
        key = (target, unescaped)
        known = self.found.get(key)
        if known is not None and known[0] <= start and (known[1] < 0 or start <= known[1]):
            return known[1]
        text = self.text
        index = text.find(target, start)
        while unescaped and index > 0 and _escaped(text, index):
            index = text.find(target, index + 1)
        self.found[key] = (start, index)
        return index


def _skip_gap(text: str, index: int, spaces: str) -> int:
    """Past the spaces at ``index``, at most one line ending and the spaces after it."""
    while index < len(text) and text[index] in spaces:
        index += 1
    if text.startswith("\n", index):
        index += 1
        while index < len(text) and text[index] in spaces:
            index += 1
    return index


def _line_end(text: str, index: int, spaces: str) -> int:
    while index < len(text) and text[index] in spaces:
        index += 1
    return index if index == len(text) or text[index] == "\n" else -1


def _destination_end(text: str, start: int) -> int:
    """The end of a destination that does not start with ``<``, or -1."""
    depth = 0
    index = start
    while (stop := _DESTINATION_STOP.search(text, index)) is not None:
        index = stop.start()
        char = text[index]
        if char == "\\":
            index += 2 if text[index + 1 : index + 2] in _ESCAPABLE else 1
            continue
        if char == "(":
            depth += 1
        elif char != ")" or not depth:
            break
        else:
            depth -= 1
        index += 1
    else:
        index = len(text)
    return -1 if index == start or depth else index


def _commonmark_end(positions: _Positions, colon: int, spaces: str) -> int:
    """The end of the definition whose label ends at ``colon``, as CommonMark reads it
    with ``spaces`` between its parts, or -1."""
    text = positions.text
    start = _skip_gap(text, colon + 1, spaces)
    if text.startswith("<", start):
        close = positions.next(">", start + 1, unescaped=True)
        if (
            close < 0
            or 0 <= positions.next("<", start + 1, unescaped=True) < close
            or 0 <= positions.next("\n", start + 1) < close
        ):
            return -1
        after = close + 1
    else:
        after = _destination_end(text, start)
        if after < 0:
            return -1
    title = _skip_gap(text, after, spaces)
    if after < title < len(text) and text[title] in "\"'(":
        closer = ")" if text[title] == "(" else text[title]
        close = positions.next(closer, title + 1, unescaped=True)
        if close >= 0 and not (
            closer == ")" and 0 <= positions.next("(", title + 1, unescaped=True) < close
        ):
            end = _line_end(text, close + 1, spaces)
            if end >= 0:
                return end
    return _line_end(text, after, spaces)


def _definition_spans(text: str) -> list[tuple[int, int, str, bool]]:
    """The start, end and label of each definition that starts a line of the paragraph
    ``text``, and whether commonmark.js and markdown-it both read it so."""
    positions = _Positions(text)
    spans = []
    line = 0
    while True:
        start = line
        while start < len(text) and text[start] in " \t":
            start += 1
        if text.startswith("[", start):
            close = positions.next("]", start + 1, unescaped=True)
            commonmark = -1
            if (
                close >= 0
                and text.startswith(":", close + 1)
                and not 0 <= positions.next("[", start + 1, unescaped=True) < close
            ):
                commonmark = _commonmark_end(positions, close + 1, " \t")
            plain = _LINE_DEFINITION.match(text, start)
            end = max(commonmark, -1 if plain is None else plain.end())
            if end >= 0:
                label = text[start + 1 : close]
                if commonmark < 0 and plain is not None:
                    label = plain.group(1)
                agreed = (
                    commonmark == end
                    and len(label) <= _MAX_LABEL
                    and bool(label.strip(_ASCII_WHITESPACE))
                    and _commonmark_end(positions, close + 1, " ") == end
                    and not _REFUSED_SCHEME.match(text, _skip_gap(text, close + 2, " \t"))
                )
                spans.append((start, end, label, agreed))
                line = end
        newline = text.find("\n", line)
        if newline < 0:
            return spans
        line = newline + 1


def _leading_definitions_end(text: str, spans: list[tuple[int, int, str, bool]]) -> int:
    """The end of the definitions that open the paragraph ``text``, which every reader
    takes out of it before reading the rest as inline text."""
    end = 0
    for start, span_end, _, agreed in spans:
        if not agreed or text[end:start].strip(" \t") != ("\n" if end else ""):
            break
        end = span_end
    return end


_HTML_OPENER = re.compile(r"<(?:\?|!\[CDATA\[|![A-Za-z])")
_HTML_CLOSERS = {"<?": "?>", "<![CDATA[": "]]>"}


def _hidden_html(text: str, *, block: bool) -> list[str]:
    """The processing instructions, declarations and CDATA sections in ``text``, also
    those in what may be a comment, since readers do not agree on where one ends. In an
    HTML ``block`` one runs to the end of the block when it is not closed, and a
    backslash escapes nothing."""
    positions = _Positions(text)
    found = []
    position = 0
    while (opener := _HTML_OPENER.search(text, position)) is not None:
        start = opener.start()
        closer = _HTML_CLOSERS.get(opener.group(), ">")
        close = positions.next(closer, opener.end())
        if not block and (close < 0 or _escaped(text, start)):
            position = start + 1
            continue
        stop = len(text) if close < 0 else close + len(closer)
        found.append(text[start:stop])
        position = stop
    return found


_DESTINATION_CHARACTER = rf"[^{_ASCII_WHITESPACE}()\\]|\\[{_PUNCTUATION}]|\\"
_LINK_TITLE = r"(?:\"(?:[^\"\\]|\\.)*+\"|'(?:[^'\\]|\\.)*+'|\((?:[^()\\]|\\.)*+\))"


def _inline_link(spaces: str) -> re.Pattern[str]:
    gap = f"{spaces}*+(?:\n{spaces}*+)?"
    destination = (
        r"(?><(?:[^<>\n\\]|\\[^\n])*+>"
        f"|(?!<)(?:{_DESTINATION_CHARACTER}|\\((?:{_DESTINATION_CHARACTER})*+\\))*+)"
    )
    title = f"(?:{gap}(?<=[{_ASCII_WHITESPACE}]){_LINK_TITLE})?+"
    return re.compile(f"\\({gap}{destination}{title}{gap}\\)", re.S)


# An inline link as commonmark.js reads one, nesting parentheses in its destination
# once; and as markdown-it reads one, which also takes tabs between its parts.
_INLINE_LINK = _inline_link(" ")
_LENIENT_INLINE_LINK = _inline_link("[ \t]")
_LINK_LABEL = re.compile(r"\[(?:[^\\\[\]]|\\.)*+\]", re.S)
_REFERENCE_SPECIAL = re.compile(r"[\\`\[\]<]")
_TAG_STOP = re.compile(r"[<>\"']")


def _html_end(positions: _Positions, start: int) -> int:
    """The end of the raw HTML or autolink that may start at ``start``, or -1.

    An open tag runs to the first ``>`` outside its quoted values, so this ends at or
    after the end of any tag a reader finds there.
    """
    text = positions.text
    if text.startswith("<!--", start):
        close = positions.next("-->", start + 2)
        if 0 <= close < start + 4:
            # Readers before CommonMark 0.31.2 do not close a comment with `<!-->`.
            close = max(close, positions.next("-->", start + 4))
        return close + 3 if close >= 0 else -1
    for opener, closer in _HTML_CLOSERS.items():
        if text.startswith(opener, start):
            close = positions.next(closer, start + len(opener))
            return close + len(closer) if close >= 0 else -1
    second = text[start + 1 : start + 2]
    third = text[start + 2 : start + 3]
    if second == "!" and third.isascii() and third.isalpha():
        close = positions.next(">", start + 2)
        return close + 1 if close >= 0 else -1
    if not (second.isascii() and second.isalpha()) and not (
        second == "/" and third.isascii() and third.isalpha()
    ):
        return -1
    index = start + 1
    while (stop := _TAG_STOP.search(text, index)) is not None:
        char = stop.group()
        if char == ">":
            return stop.end()
        if char == "<":
            return -1
        close = positions.next(char, stop.end())
        if close < 0:
            return -1
        index = close + 1
    return -1


def _references(text: str, defined: Callable[[str], bool]) -> list[str]:
    """The labels that the references in the inline ``text`` name, as CommonMark pairs
    brackets after code spans, raw HTML and autolinks.

    A label counts only where every reader makes a link of it: not in the text of an
    inline link or of a full reference, not with a ``|``, which a table cell can split,
    and nothing after a link whose extent this cannot settle the same for every reader.
    """
    runs: dict[int, list[int]] = {}
    for found_run in _BACKTICKS.finditer(text):
        runs.setdefault(found_run.end() - found_run.start(), []).append(found_run.start())
    positions = _Positions(text)
    labels: list[str] = []
    openers: list[int] = []
    last_closed = -1

    def name(label: str) -> None:
        if len(label) <= _MAX_LABEL and "|" not in label and label.strip(_ASCII_WHITESPACE):
            labels.append(label)

    position = 0
    while (found := _REFERENCE_SPECIAL.search(text, position)) is not None:
        position = found.start()
        char = text[position]
        if char == "\\":
            position += 2 if text[position + 1 : position + 2] in _ESCAPABLE else 1
        elif char == "`":
            run = _BACKTICKS.match(text, position)
            end = position + 1 if run is None else run.end()
            starts = runs.get(end - position, [])
            index = bisect_left(starts, end)
            position = end if index == len(starts) else starts[index] + end - position
        elif char == "<":
            end = _html_end(positions, position)
            if end < 0:
                position += 1
            elif "`" in text[position:end]:
                break
            else:
                position = end
        elif char == "[":
            openers.append(position)
            position += 1
        else:
            position += 1
            if not openers:
                continue
            opened = openers.pop()
            innermost = last_closed < opened
            last_closed = opened
            label = text[opened + 1 : position - 1]
            following = text[position : position + 1]
            if following == "(":
                link = _INLINE_LINK.match(text, position) if innermost else None
                if link is None:
                    link = _LENIENT_INLINE_LINK.match(text, position)
                    if link is None or _TAKEN_BY_INLINE.search(link.group()):
                        break
                position = link.end()
                continue
            if following != "[":
                if innermost:
                    name(label)
                continue
            reference = _LINK_LABEL.match(text, position)
            if reference is None:
                # Markdown-it takes balanced brackets here for a label, which names
                # nothing, where commonmark.js reads a shortcut reference.
                continue
            target = reference.group()[1:-1]
            if not innermost:
                # Brackets around a link are text to commonmark.js, which then reads
                # the label after them as brackets of its own; markdown-it reads a
                # full reference.
                continue
            if not target:
                name(label)
            elif not defined(target):
                # Brackets followed by a label that names nothing are not a shortcut
                # reference either; the label is read again as brackets of its own.
                continue
            elif _TAKEN_BY_INLINE.search(target):
                break
            else:
                name(target)
            position = reference.end()
    return labels


_CONTAINER_MARKS = re.compile(
    r"^[ \t]*+(?:(?:>|[-*+](?=[ \t])|\d{1,9}[.)](?=[ \t]))[ \t]*+)*+", re.M
)
_BLANK_LINE = re.compile(r"\n[ \t]*+\n")


def _hidden_in_whole(text: str) -> HiddenText:
    """Every definition at the start of a line, past any container marks, and all the
    hidden HTML of ``text`` read as one HTML block."""
    definitions = []
    for chunk in _BLANK_LINE.split(_CONTAINER_MARKS.sub("", text)):
        definitions += [chunk[start:end] for start, end, _, _ in _definition_spans(chunk)]
    return HiddenText(tuple(definitions), tuple(_hidden_html(text, block=True)))
