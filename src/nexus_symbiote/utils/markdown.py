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
"""

from __future__ import annotations

import re
from bisect import bisect_left
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
