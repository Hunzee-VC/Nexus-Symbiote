"""System prompt, instruction file, rule file, and skill definition scanner."""

from __future__ import annotations

import codecs
import hashlib
import re
import unicodedata
from collections import deque
from collections.abc import Collection
from pathlib import Path, PurePosixPath

from nexus_symbiote import limits
from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import PromptComponent, RiskAssessment, SkillPackageComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.utils.confined import CollectionError, ConfinedCollection, fold_name
from nexus_symbiote.utils.terminal import neutralize

INVISIBLE_CHARS: dict[str, str] = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "­": "SOFT HYPHEN",
}

BIDI_OVERRIDES: dict[str, str] = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}

# Marks that set the direction of neutral characters; ordinary in right-to-left text.
DIRECTIONAL_MARKS: dict[str, str] = {
    "‎": "LEFT-TO-RIGHT MARK",
    "‏": "RIGHT-TO-LEFT MARK",
    "؜": "ARABIC LETTER MARK",
}

TAG_CHAR_RANGE = re.compile(r"[\U000e0000-\U000e007f]")
# Code points that Unicode reserves as default-ignorable but has not assigned (property
# Other_Default_Ignorable_Code_Point, category Cn). Renderers draw nothing for them, and
# unicodedata exposes no property that identifies them, so they are listed; U+E0000 and
# U+E0002 to U+E001F, which are of the same kind, lie in the tag range above.
_UNASSIGNED_IGNORABLE = "\u2065\ufff0-\ufff8\U000e0080-\U000e00ff\U000e01f0-\U000e0fff"
_UNASSIGNED = re.compile(f"[{_UNASSIGNED_IGNORABLE}]")
# The plane-14 part lies beside the tag characters and variation selectors that
# encodings of hidden text use, and like them it has no legitimate use in instructions.
_UNASSIGNED_PLANE_14 = re.compile(r"[\U000e0080-\U000e00ff\U000e01f0-\U000e0fff]")

# Every default-ignorable code point of Unicode 15.1, assigned or not, every format
# character (category Cf) and the blank Braille pattern. The scan also checks each
# distinct character's category, so format characters added in later versions are
# found too.
_HIDDEN = re.compile(
    "[­͏؀-؅؜۝܏࢐࢑࣢ᅟᅠ"
    "឴឵᠋-᠏​-‏‪-‮⁠-⁤⁦-⁯"
    "⠀ㅤ︀-️﻿ﾠ￹-￻\U000110bd\U000110cd"
    "\U00013430-\U0001343f\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    f"\U000e0000-\U000e007f\U000e0100-\U000e01ef{_UNASSIGNED_IGNORABLE}]"
)
_ZWJ = "‍"
_PRESENTATION_SELECTORS = frozenset({"︎", "️"})
_SKIN_TONES = range(0x1F3FB, 0x1F400)
# The three subdivision flags that are recommended emoji: England, Scotland and Wales.
_FLAG_SEQUENCE = re.compile(
    "\U0001f3f4\U000e0067\U000e0062(?:\U000e0065\U000e006e\U000e0067"
    "|\U000e0073\U000e0063\U000e0074|\U000e0077\U000e006c\U000e0073)\U000e007f"
)
_MARKDOWN_COMMENT = re.compile(r"^[ \t]{0,3}\[(?://|comment|#)\]:[ \t]*(?:#|<>)", re.M)
# Characters of a large text file counted at once when no newline ends a segment sooner.
_MAX_SEGMENT = 1 << 20
# In a file with a NUL byte that is not UTF-8, which is binary, only runs this long count:
# random bytes form a hidden character now and then, but not runs of them, and text
# hidden in such characters takes one character per byte.
_BINARY_RUN = 4
_HIDDEN_RUN = re.compile(f"(?:{_HIDDEN.pattern}){{{_BINARY_RUN},}}")
# Plane-14 characters, which tag and variation selector encodings of hidden text use,
# all count in a binary file once this many of them lie within a window of this many
# characters, whatever separates them. Random bytes form one about once per MiB, so a
# count over the whole file would grow with its size; hidden text needs one per letter.
_BINARY_PLANE_14 = 16
_BINARY_PLANE_14_WINDOW = 4096
_PLANE_14 = re.compile("[\U000e0000-\U000e0fff]")
# Byte-order marks after which readers decode UTF-32 or UTF-16; UTF-32 LE first, since
# its mark starts with that of UTF-16 LE.
_BYTE_ORDER_MARKS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def _pictographic(char: str) -> bool:
    point = ord(char)
    return (
        0x1F000 <= point <= 0x1FAFF
        or 0x2190 <= point <= 0x21FF
        or 0x2300 <= point <= 0x23FF
        or 0x25A0 <= point <= 0x27BF
        or 0x2900 <= point <= 0x297F
        or 0x2B00 <= point <= 0x2BFF
        or point in {0xA9, 0xAE, 0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D, 0x3297, 0x3299}
    )


def _emoji_context(content: str, index: int) -> bool:
    """Whether a joiner or presentation selector at ``index`` belongs to an emoji."""
    char = content[index]
    before = index - 1
    if char == _ZWJ:
        while before >= 0 and (
            content[before] in _PRESENTATION_SELECTORS or ord(content[before]) in _SKIN_TONES
        ):
            before -= 1
        after = index + 1
        return (
            before >= 0
            and after < len(content)
            and _pictographic(content[before])
            and (_pictographic(content[after]))
        )
    if before < 0:
        return False
    previous = content[before]
    return (
        _pictographic(previous)
        or previous in "#*0123456789"
        or (0x2000 <= ord(previous) <= 0x2BFF or 0x3000 <= ord(previous) <= 0x32FF)
    )


def _character_name(char: str) -> str:
    unnamed = (
        "UNASSIGNED DEFAULT-IGNORABLE CODE POINT"
        if _UNASSIGNED.match(char)
        else "UNNAMED FORMAT CHARACTER"
    )
    return unicodedata.name(char, unnamed)


def detect_invisible_characters(content: str, source_name: str) -> list[RiskAssessment]:
    """Detect invisible Unicode characters that could be used for prompt trojans.

    Every format character (category Cf), variation selector, blank-rendering filler
    and unassigned default-ignorable code point is reported. Bidirectional
    embeddings, overrides and isolates, tag characters and the unassigned code points
    of plane 14 are critical; directional marks, which right-to-left text uses, are
    medium; the others are high. A zero-width joiner inside an emoji sequence, a
    presentation selector after a pictograph, a byte-order mark that starts the text
    and the England, Scotland and Wales flag sequences are ordinary text.
    """
    counts, tags = _hidden_counts(content, at_start=True)
    return _hidden_character_risks(counts, tags, source_name)


def _hidden_counts(content: str, *, at_start: bool) -> tuple[dict[str, int], int]:
    """Count the hidden characters of ``content``, and its tag characters outside a flag.

    ``at_start`` says whether ``content`` begins the text, where a byte-order mark is
    ordinary.
    """
    counts: dict[str, int] = {}
    if content.isascii():
        return counts, 0
    for match in _HIDDEN.finditer(content):
        char = match.group()
        if (char == _ZWJ or char in _PRESENTATION_SELECTORS) and _emoji_context(
            content, match.start()
        ):
            continue
        if char == "\ufeff" and at_start and match.start() == 0:
            continue
        counts[char] = counts.get(char, 0) + 1
    for char in set(content) - set(counts):
        if not char.isascii() and unicodedata.category(char) == "Cf" and not _HIDDEN.match(char):
            counts[char] = content.count(char)
    tags = len(TAG_CHAR_RANGE.findall(_FLAG_SEQUENCE.sub("", content)))
    for char in [char for char in counts if TAG_CHAR_RANGE.match(char)]:
        del counts[char]
    return counts, tags


class _HiddenCharacterStream:
    """The hidden-character counts of a file's text, read in chunks.

    The text is decoded as an agent's reader decodes it: as UTF-32 or UTF-16 after
    that byte-order mark, otherwise as UTF-8 with U+FFFD for an invalid sequence, so a
    stray byte or a UTF-16 file does not hide what the rest of it says. When the bytes
    are not UTF-8 and hold a NUL byte, without such a mark, the file is binary and only
    runs of ``_BINARY_RUN`` or more hidden characters count, and every plane-14 hidden
    character once ``_BINARY_PLANE_14`` of them lie within ``_BINARY_PLANE_14_WINDOW``
    characters.

    The text is counted in segments that end after a newline, which no emoji or flag
    sequence crosses, so the counts equal those of the whole text. A segment that
    reaches ``_MAX_SEGMENT`` characters without one is cut there; a cut can only add
    findings, never hide one, except that it can split a run in a binary file.
    """

    def __init__(self) -> None:
        self._decoder: codecs.IncrementalDecoder | None = None
        self._utf8 = True
        self._strict: codecs.IncrementalDecoder | None = None
        self._nul = False
        self._pending = ""
        self._at_start = True
        self._counts: dict[str, int] = {}
        self._tags = 0
        self._run_counts: dict[str, int] = {}
        self._run_tags = 0
        self._offset = 0
        self._plane_14: deque[int] = deque(maxlen=_BINARY_PLANE_14)
        self._dense_plane_14 = False

    @property
    def binary(self) -> bool:
        """Bytes that are not UTF-8, hold a NUL byte and declare no other encoding."""
        return self._nul and self._strict is None

    @property
    def counts(self) -> dict[str, int]:
        if not self.binary:
            return self._counts
        if not self._dense_plane_14:
            return self._run_counts
        plane_14 = {char: n for char, n in self._counts.items() if _PLANE_14.match(char)}
        return {**self._run_counts, **plane_14}

    @property
    def tags(self) -> int:
        if not self.binary:
            return self._tags
        return self._tags if self._dense_plane_14 else self._run_tags

    def feed(self, chunk: bytes, *, final: bool = False) -> None:
        if self._decoder is None:
            if not chunk and not final:
                return
            encoding = next(
                (name for mark, name in _BYTE_ORDER_MARKS if chunk.startswith(mark)), None
            )
            self._decoder = codecs.getincrementaldecoder(encoding or "utf-8")("replace")
            self._utf8 = encoding is None
            if self._utf8:
                self._strict = codecs.getincrementaldecoder("utf-8")()
        if self._utf8:
            self._nul = self._nul or b"\0" in chunk
        if self._strict is not None:
            try:
                self._strict.decode(chunk, final)
            except UnicodeDecodeError:
                self._strict = None
        text = self._pending + self._decoder.decode(chunk, final)
        end = len(text) if final else text.rfind("\n", len(self._pending)) + 1
        if not end and len(text) >= _MAX_SEGMENT:
            end = len(text)
        if not end:
            self._pending = text
            return
        segment = text[:end]
        counts, tags = _hidden_counts(segment, at_start=self._at_start)
        self._tags += tags
        for char, count in counts.items():
            self._counts[char] = self._counts.get(char, 0) + count
        if counts or tags:
            runs = "\n".join(_HIDDEN_RUN.findall(segment))
            counts, tags = _hidden_counts(runs, at_start=False)
            self._run_tags += tags
            for char, count in counts.items():
                self._run_counts[char] = self._run_counts.get(char, 0) + count
            for match in _PLANE_14.finditer(segment):
                self._plane_14.append(self._offset + match.start())
                if len(self._plane_14) == _BINARY_PLANE_14 and (
                    self._plane_14[-1] - self._plane_14[0] < _BINARY_PLANE_14_WINDOW
                ):
                    self._dense_plane_14 = True
        self._offset += end
        self._pending, self._at_start = text[end:], False


def _hidden_character_risks(
    counts: dict[str, int], tags: int, source_name: str
) -> list[RiskAssessment]:
    risks: list[RiskAssessment] = []
    shown = neutralize(source_name)
    # Counted, not listed: there are 3,728 of them, and they are rated with tag characters.
    plane_14 = sum(count for char, count in counts.items() if _UNASSIGNED_PLANE_14.match(char))
    invisible = [
        f"{INVISIBLE_CHARS.get(char) or _character_name(char)} (U+{ord(char):04X}) x{count}"
        for char, count in sorted(counts.items(), key=lambda item: ord(item[0]))
        if char not in BIDI_OVERRIDES
        and char not in DIRECTIONAL_MARKS
        and not _UNASSIGNED_PLANE_14.match(char)
    ]
    if invisible:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="invisible_characters",
                detail=(
                    f"'{shown}' contains invisible Unicode characters: "
                    f"{', '.join(invisible)}. "
                    "These are invisible in most editors and may alter LLM behavior."
                ),
                recommendation="Remove all zero-width characters or document their purpose.",
            )
        )

    found_bidi = [
        f"{name} (U+{ord(char):04X}) x{counts[char]}"
        for char, name in BIDI_OVERRIDES.items()
        if char in counts
    ]
    if found_bidi:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="bidi_override",
                detail=(
                    f"'{shown}' contains bidirectional override characters: "
                    f"{', '.join(found_bidi)}. "
                    "Bidi overrides can make malicious instructions appear as benign text."
                ),
                recommendation="Remove all bidirectional override characters immediately.",
            )
        )

    marks = [
        f"{name} (U+{ord(char):04X}) x{counts[char]}"
        for char, name in DIRECTIONAL_MARKS.items()
        if char in counts
    ]
    if marks:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category="directional_marks",
                detail=(
                    f"'{shown}' contains invisible directional marks: {', '.join(marks)}. "
                    "They are ordinary in right-to-left text but can reorder neutral characters."
                ),
                recommendation="Confirm that each directional mark belongs to right-to-left text.",
            )
        )

    if tags or plane_14:
        found = []
        removed = "tag characters"
        if tags:
            found.append(
                f"{tags} deprecated Unicode tag characters (U+E0000–U+E007F) outside a flag emoji"
            )
        if plane_14:
            found.append(
                f"{plane_14} unassigned default-ignorable code points of plane 14 "
                "(U+E0080–U+E00FF, U+E01F0–U+E0FFF)"
            )
            removed = "tag characters and unassigned code points"
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="tag_characters",
                detail=(
                    f"'{shown}' contains {' and '.join(found)}. These are "
                    "invisible and have no legitimate use in prompt files."
                ),
                recommendation=f"Remove all {removed} — likely a prompt trojan.",
            )
        )
    return risks


def detect_hidden_markup(content: str, source_name: str) -> list[RiskAssessment]:
    """Report HTML and Markdown comments, which renderers hide but agents read.

    Only counts and lengths are reported, never the hidden text.
    """
    count = length = 0
    position = 0
    while (start := content.find("<!--", position)) != -1:
        end = content.find("-->", start + 4)
        stop = len(content) if end == -1 else end + 3
        count += 1
        length += stop - start
        position = stop
    references = _MARKDOWN_COMMENT.findall(content)
    count += len(references)
    if not count:
        return []
    return [
        RiskAssessment(
            severity=RiskSeverity.LOW,
            category="hidden_markup",
            detail=(
                f"'{neutralize(source_name)}' contains {count} HTML or Markdown comment(s) "
                f"({length} characters of HTML comments) that rendered views hide and agents read."
            ),
            recommendation="Review comment text in the raw file; move notes out of agent instructions.",
        )
    ]


INSTRUCTION_FILES: dict[str, str] = {
    "CLAUDE.md": "system-prompt",
    ".claude/CLAUDE.md": "system-prompt",
    "CLAUDE.local.md": "system-prompt",
    "AGENTS.md": "system-prompt",
    "AGENTS.override.md": "system-prompt",
    "GEMINI.md": "system-prompt",
    "CODEX.md": "system-prompt",
    "codex.md": "system-prompt",
    ".cursorrules": "rules-file",
    ".clinerules": "rules-file",
    ".windsurfrules": "rules-file",
    ".github/copilot-instructions.md": "instruction",
    ".github/AGENTS.md": "instruction",
    ".codex/instructions.md": "instruction",
    "system_prompt.txt": "system-prompt",
    "system_prompt.md": "system-prompt",
}
# Both spellings are read; neither is a case variant of the other.
_CODEX_SPELLINGS = frozenset({"CODEX.md", "codex.md"})

# Instruction files a host loads from below the root: per-directory memory and context
# files, and the rules file of a project opened at that directory.
NESTED_INSTRUCTION_NAMES = {
    "CLAUDE.md": "system-prompt",
    "AGENTS.md": "system-prompt",
    "GEMINI.md": "system-prompt",
    ".cursorrules": "rules-file",
}
# Another spelling of one of them is the file a case-insensitive file system opens in
# its place, as at the root, so it is a failure wherever the walk meets it, unless a
# walk inventories it under its own name.
_FOLDED_NESTED_NAMES = {fold_name(name): name for name in NESTED_INSTRUCTION_NAMES}

# Subagent definitions and rule or prompt directories. Every file in them is inventoried
# by digest, and each directory is walked on its own, so a directory symlink out of one
# is followed. `.clinerules` is either a single rules file or a directory of them.
INSTRUCTION_DIRECTORIES: dict[str, str] = {
    ".clinerules": "rules-file",
    ".claude/rules": "rules-file",
    ".cursor/rules": "rules-file",
    ".windsurf/rules": "rules-file",
    ".roo/rules": "rules-file",
    ".kiro/steering": "rules-file",
    ".github/instructions": "instruction",
    ".github/prompts": "instruction",
    ".claude/output-styles": "instruction",
    ".claude/agents": "subagent",
    ".github/agents": "subagent",
}

SKILL_DIRECTORIES = [
    ".claude/skills",
    ".claude/commands",
    "skills",
    ".agents/skills",
    ".github/skills",
    ".cursor/skills",
    ".gemini/skills",
    ".cursor/commands",
    ".gemini/commands",
]
_SKILL_PARTS = tuple(PurePosixPath(directory).parts for directory in SKILL_DIRECTORIES)

# Skill and command declarations, read as text, which must be UTF-8; every other file of
# a skill or command directory, such as a bundled script, is a resource bound by digest.
_DECLARATION_SUFFIXES = frozenset(
    {".md", ".mdc", ".markdown", ".txt", ".yaml", ".yml", ".json", ".toml"}
)
_MARKUP_SUFFIXES = frozenset({".md", ".mdc", ".markdown"})
# Claude Code memory files and Gemini CLI context files import others with @path.
_IMPORTING_NAMES = frozenset({"CLAUDE.md", "CLAUDE.local.md", "GEMINI.md"})
_MAX_IMPORT_DEPTH = 5
_MAX_IMPORTS = 1000
# Distinct import targets looked up, and files whose imports are followed, in one
# collection. Each lookup of a missing file lists the directories on its path for case
# variants, and each file followed resolves up to _MAX_IMPORTS references, so file
# content must not be able to ask for an unbounded number of either.
_MAX_IMPORT_LOOKUPS = 5000
# Path characters that the `imports` and `imported_by` lists of one collection hold
# together. One reference can name a 4 KiB path, so a count of references alone would
# not bound the inventory.
_MAX_LISTED_IMPORT_CHARACTERS = 256 * 1024
_IMPORT = re.compile(r"(?<!\S)@(\S+)")
_FENCE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")
_CODE_SPAN = re.compile(r"`[^`\n]*`")
_DRIVE = re.compile(r"[A-Za-z]:[\\/]")
# Sentence punctuation after a reference; the file is inventoried without it.
_TRAILING = ".,;:!?)]}\"'"
# Common file systems refuse longer names and paths, but a host on another one may open
# them, so a resolved import beyond these limits is a coverage gap, not a lookup.
_MAX_NAME_BYTES = 255
_MAX_PATH_BYTES = 4096


def _markup(path: str) -> bool:
    suffix = PurePosixPath(path).suffix.lower()
    return suffix in _MARKUP_SUFFIXES or not suffix


def _resolve_import(directory: tuple[str, ...], token: str) -> tuple[list[str], bool, bool]:
    """The in-root paths an @path import in ``directory`` names, whether it leaves the
    root, and whether it names a path too long to look up.

    A token is resolved as hosts resolve it, collapsing ``.``, ``..`` and repeated
    separators, before any limit applies. A Windows host reads a backslash as a
    separator and a POSIX host as part of a name, so a token with one names both forms.
    Home-relative, absolute and drive paths, and paths that climb above the root, leave
    it. A token with a NUL character names no file any host can open.
    """
    if "\x00" in token or not token.strip("/\\"):
        return [], False, False
    forms = [token, token.replace("\\", "/")] if "\\" in token else [token]
    targets: list[str] = []
    outside = too_long = False
    for form in forms:
        if form.startswith(("~", "/")) or _DRIVE.match(form):
            outside = True
            continue
        parts = list(directory)
        for part in form.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if not parts:
                    outside = True
                    break
                parts.pop()
            else:
                parts.append(part)
        else:
            path = "/".join(parts)
            if len(path.encode()) > _MAX_PATH_BYTES or any(
                len(part.encode()) > _MAX_NAME_BYTES for part in parts
            ):
                too_long = True
            elif parts and path not in targets:
                targets.append(path)
    return targets, outside, too_long


def _import_tokens(text: str) -> list[str]:
    """@path references outside fenced code blocks and code spans."""
    tokens: list[str] = []
    fence = ""
    for line in text.splitlines():
        opened = _FENCE.match(line)
        if opened:
            marker = opened.group(1)
            if not fence:
                fence = marker[0] * len(marker)
            elif marker.startswith(fence):
                fence = ""
            continue
        if fence:
            continue
        tokens.extend(_IMPORT.findall(_CODE_SPAN.sub(" ", line)))
    return tokens


class _ImportListing:
    """The @path import references one collection lists on the files it records.

    A file's ``imports``, and the ``imported_by`` of a file that others import, are
    listed in full while all lists together hold at most
    ``_MAX_LISTED_IMPORT_CHARACTERS`` characters of paths. A list that does not fit is
    replaced by its count, and ``imports`` also by a digest of the paths, so a change to
    it is still drift; one failure says how many references are counted but not listed.
    """

    def __init__(self) -> None:
        self._remaining = _MAX_LISTED_IMPORT_CHARACTERS
        self._importers: dict[str, list[str]] = {}
        self._counts: dict[str, int] = {}
        self._overflowed: dict[str, None] = {}
        self._leaves: dict[str, bytes] = {}
        self._first: str | None = None
        self._unlisted = 0

    def add(self, importer: str, targets: Collection[str], component: PromptComponent) -> None:
        """Record that ``importer`` imports ``targets``, given in the order it names them."""
        if self._take(sum(map(len, targets))):
            component.properties["imports"] = sorted(targets)
        else:
            self._note(importer)
            self._unlisted += len(targets)
            component.properties["imports_count"] = len(targets)
            component.properties["imports_digest"] = self._digest(targets)
        for target in targets:
            self._counts[target] = self._counts.get(target, 0) + 1
            if target in self._overflowed:
                continue
            if self._take(len(importer)):
                self._importers.setdefault(target, []).append(importer)
            else:
                self._importers.pop(target, None)
                self._overflowed[target] = None
                self._note(target)

    def finish(self, recorded: dict[str, PromptComponent], failures: list[str]) -> None:
        for target, importers in self._importers.items():
            recorded[target].properties["imported_by"] = sorted(importers)
        for target in self._overflowed:
            recorded[target].properties["imported_by_count"] = self._counts[target]
            self._unlisted += self._counts[target]
        if self._first is not None:
            failures.append(
                f"{self._first}: @path import references exceed the inventory's recording "
                f"limit of {_MAX_LISTED_IMPORT_CHARACTERS} path characters; "
                f"{self._unlisted} are counted but not listed"
            )

    def _take(self, characters: int) -> bool:
        if characters > self._remaining:
            return False
        self._remaining -= characters
        return True

    def _note(self, path: str) -> None:
        if self._first is None:
            self._first = path

    def _digest(self, targets: Collection[str]) -> str:
        """SHA-256 over the sorted SHA-256 digests of the paths; each path is hashed once."""
        leaves = self._leaves
        for target in targets:
            if target not in leaves:
                leaves[target] = hashlib.sha256(target.encode()).digest()
        return hash_bytes(b"".join(sorted(leaves[target] for target in targets)))


def _report_skipped(skipped: list[Path], reported: set[Path], result: ScanResult) -> None:
    """A coverage gap for each entry that a walk of an agent configuration directory
    skipped because its name, such as ``venv`` or ``node_modules``, is excluded by
    default. A host reads such a skill or subagent file like any other, so it is not
    a dependency tree to leave out silently. Each path is reported once.
    """
    for path in skipped:
        if path not in reported:
            reported.add(path)
            result.surfaces_excluded.append(
                f"{path.as_posix()}: default-excluded name inside an agent configuration "
                "directory; not collected"
            )


class PromptScanner(Scanner):
    name = "prompt"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        with self._collection(project_root, result) as files:
            recorded: dict[str, PromptComponent] = {}
            texts: dict[str, str] = {}
            importers: list[str] = []
            # Other spellings of instruction names, each with the path it stands for; they
            # are reported once every walk has run.
            variants: list[tuple[Path, Path]] = []
            for rel_path, prompt_type in INSTRUCTION_FILES.items():
                if rel_path in INSTRUCTION_DIRECTORIES and files.is_directory(rel_path):
                    continue
                spellings = _CODEX_SPELLINGS if rel_path in _CODEX_SPELLINGS else ()
                content = files.read_bytes(rel_path, missing_ok=True, variants_read=spellings)
                if content is None:
                    continue
                # A case-insensitive checkout holds one file for the name and another
                # spelling beside it, with the content of whichever it wrote last.
                variants.extend(
                    (variant, Path(rel_path))
                    for variant in files.case_variants(rel_path)
                    if variant.as_posix() not in spellings and not files.excluded(variant)
                )
                component = self._record(rel_path, prompt_type, content, files, result)
                if component is not None:
                    recorded[rel_path] = component
                    texts[rel_path] = content.decode("utf-8")
                    if PurePosixPath(rel_path).name in _IMPORTING_NAMES:
                        importers.append(rel_path)

            # Instruction files below the root, found by name; a name takes precedence
            # over the directory that holds the file. A host that loads a nested CLAUDE.md
            # or GEMINI.md, as it does in a session started in that directory, expands its
            # imports too. Dependency trees and other default-excluded names stay skipped.
            for path in sorted(files.iter_files()):
                relative = path.as_posix()
                nested_type = NESTED_INSTRUCTION_NAMES.get(path.name)
                if nested_type is None and len(path.parts) > 1:
                    canonical = _FOLDED_NESTED_NAMES.get(fold_name(path.name))
                    if canonical is not None:
                        variants.append((path, path.with_name(canonical)))
                if (
                    nested_type is None
                    or len(path.parts) < 2
                    or relative in INSTRUCTION_FILES
                    or relative in recorded
                ):
                    continue
                content = files.read_bytes(path)
                if content is None:
                    continue
                component = self._record(relative, nested_type, content, files, result)
                if component is not None:
                    recorded[relative] = component
                    texts[relative] = content.decode("utf-8")
                    if path.name in _IMPORTING_NAMES:
                        importers.append(relative)

            reported: set[Path] = set()
            for directory, prompt_type in INSTRUCTION_DIRECTORIES.items():
                if directory in INSTRUCTION_FILES and not files.is_directory(directory):
                    continue
                skipped: list[Path] = []
                for path in files.iter_files(directory, skipped=skipped):
                    relative = path.as_posix()
                    if relative in recorded:
                        continue
                    content = files.read_bytes(path)
                    if content is None:
                        continue
                    component = self._record(relative, prompt_type, content, files, result)
                    if component is not None:
                        recorded[relative] = component
                        texts[relative] = content.decode("utf-8")
                _report_skipped(skipped, reported, result)

            importers += self._variant_importers(variants, texts, set(importers), files)
            self._follow_imports(importers, texts, recorded, files, result)
            self._scan_skills(files, result, reported)
            # A spelling that a walk inventories is recorded and checked under its own
            # name; any other is a file the collector does not read.
            inventoried = {component.source_path for component in result.components}
            for variant, named in variants:
                if variant.as_posix() not in inventoried:
                    files.report_case_variant(variant, named)

        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("prompts (no instruction files found)")

        return result

    @staticmethod
    def _variant_importers(
        variants: list[tuple[Path, Path]],
        texts: dict[str, str],
        importers: set[str],
        files: ConfinedCollection,
    ) -> list[str]:
        """The spellings of CLAUDE.md and GEMINI.md that a walk inventories, whose imports
        a host that opens one under that name expands, and that are not importers yet.

        A subagent, rule or prompt directory walk has recorded its text already. A skill
        or command directory walk records its file after imports are followed, so the
        text is read here; a file that cannot be read is that walk's failure.
        """
        found: dict[str, None] = {}
        for variant, canonical in variants:
            relative = variant.as_posix()
            if canonical.name not in _IMPORTING_NAMES or relative in found or relative in importers:
                continue
            if relative not in texts:
                if not any(variant.parts[: len(parts)] == parts for parts in _SKILL_PARTS):
                    continue
                content = files.read_bytes(variant)
                if content is None:
                    continue
                try:
                    texts[relative] = content.decode("utf-8")
                except UnicodeDecodeError:
                    continue
            found[relative] = None
        return list(found)

    def _record(
        self,
        rel_path: str,
        prompt_type: str,
        content: bytes,
        files: ConfinedCollection,
        result: ScanResult,
    ) -> PromptComponent | None:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            result.scan_failures.append(f"{rel_path}: invalid UTF-8 instruction")
            return None
        result.surfaces_scanned.append(rel_path)
        component = self._scan_instruction_file(
            Path(rel_path), rel_path, prompt_type, content, text
        )
        target = files.link_target(rel_path)
        if target is not None:
            component.properties["symlink_target"] = target
        result.components.append(component)
        return component

    def _follow_imports(
        self,
        importers: list[str],
        texts: dict[str, str],
        recorded: dict[str, PromptComponent],
        files: ConfinedCollection,
        result: ScanResult,
    ) -> None:
        """Inventory in-root files that memory files import with @path, to five hops.

        A host expands the imports of every file it loads this way, including a file
        the collector records under its own name, such as an imported AGENTS.md or a
        nested CLAUDE.md. Each target looked up, and each file whose imports are
        followed, counts against ``_MAX_IMPORT_LOOKUPS``, so at most that many times
        ``_MAX_IMPORTS`` references are resolved.
        """
        pending = deque((path, 0) for path in importers)
        followed = set(importers)
        looked_up: set[str] = set()
        # Each path is one object that every reference to it shares.
        paths = {path: path for path in recorded}
        listing = _ImportListing()
        spent = 0

        def spend(importer: str) -> bool:
            nonlocal spent
            if spent >= _MAX_IMPORT_LOOKUPS:
                result.scan_failures.append(
                    f"{importer}: more than {_MAX_IMPORT_LOOKUPS} distinct @path imports "
                    "in the project; the rest are not inventoried"
                )
                return False
            spent += 1
            return True

        while pending:
            importer, depth = pending.popleft()
            tokens = _import_tokens(texts[importer])
            if not tokens:
                continue
            if len(set(tokens)) > _MAX_IMPORTS:
                result.scan_failures.append(f"{importer}: too many @path imports to inventory")
                continue
            # A file found by a lookup was counted when it was looked up.
            if importer not in looked_up and not spend(importer):
                break
            imports: dict[str, None] = {}
            targets: list[str] = []
            outside = too_long = exhausted = False
            directory = PurePosixPath(importer).parent.parts
            for token in dict.fromkeys(token.rstrip(_TRAILING) for token in tokens):
                named, leaves, long = _resolve_import(directory, token)
                targets.extend(named)
                outside |= leaves
                too_long |= long
            for target in dict.fromkeys(targets):
                known = paths.get(target)
                if known is not None:
                    imports[known] = None
                    if known not in followed and depth + 1 <= _MAX_IMPORT_DEPTH:
                        followed.add(known)
                        pending.append((known, depth + 1))
                    continue
                if target in looked_up:
                    continue
                if not spend(importer):
                    exhausted = True
                    break
                looked_up.add(target)
                content = self._read_import(importer, target, files, result)
                if content is None:
                    continue
                if depth + 1 > _MAX_IMPORT_DEPTH:
                    result.surfaces_excluded.append(
                        f"{target}: imported more than {_MAX_IMPORT_DEPTH} hops from a memory "
                        "file and not inventoried"
                    )
                    continue
                component = self._record(target, "imported-instruction", content, files, result)
                if component is None:
                    continue
                component.bom_ref = f"prompt:import:{target}"
                recorded[target] = component
                paths[target] = target
                texts[target] = content.decode("utf-8")
                imports[target] = None
                followed.add(target)
                pending.append((target, depth + 1))
            if exhausted:
                break
            if outside:
                result.surfaces_excluded.append(
                    f"{importer}: imports a file outside the project root, which is not inventoried"
                )
            if too_long:
                result.surfaces_excluded.append(
                    f"{importer}: imports a path longer than {_MAX_PATH_BYTES} bytes or with a "
                    f"name longer than {_MAX_NAME_BYTES} bytes, which is not inventoried"
                )
            if imports and importer in recorded:
                listing.add(importer, imports, recorded[importer])
        listing.finish(recorded, result.scan_failures)

    @staticmethod
    def _read_import(
        importer: str, target: str, files: ConfinedCollection, result: ScanResult
    ) -> bytes | None:
        """An imported file's bytes, or None when it is absent, a directory or a gap."""
        if len(PurePosixPath(target).parts) > files.max_depth + 1:
            result.surfaces_excluded.append(
                f"{target}: imported by {importer} below the collection depth limit "
                "and not inventoried"
            )
            return None
        if files.excluded(target):
            # A host still loads it, as it would a dependency's instructions.
            result.surfaces_excluded.append(
                f"{target}: imported by {importer} but excluded from collection"
            )
            return None
        if files.is_directory(target):
            return None
        return files.read_bytes(target, missing_ok=True)

    def _scan_skills(
        self, files: ConfinedCollection, result: ScanResult, reported: set[Path]
    ) -> None:
        seen: set[str] = set()
        for skill_dir in SKILL_DIRECTORIES:
            skipped: list[Path] = []
            for path in files.iter_files(skill_dir, skipped=skipped):
                relative = path.as_posix()
                if relative in seen:
                    continue
                seen.add(relative)
                read = self._skill_file(path, files, result)
                if read is None:
                    continue
                digest, risks = read
                result.surfaces_scanned.append(relative)
                result.components.append(
                    SkillPackageComponent(
                        bom_ref=f"skill:{relative}",
                        name=relative,
                        skill_type=(
                            "skill"
                            if path.suffix.lower() in _DECLARATION_SUFFIXES
                            else "skill-resource"
                        ),
                        hashes={"sha256": digest},
                        source_path=relative,
                        trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                        risks=risks,
                    )
                )
            _report_skipped(skipped, reported, result)
        if not seen and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("skills (no skill or command files found)")

    @staticmethod
    def _skill_file(
        path: Path, files: ConfinedCollection, result: ScanResult
    ) -> tuple[str, list[RiskAssessment]] | None:
        """A bundle file's digest and the hidden-character findings of its text."""
        relative = path.as_posix()
        text_file = path.suffix.lower() in _DECLARATION_SUFFIXES
        found = files.regular_file(path)
        if found is not None and found[1] > files.max_file_bytes and not text_file:
            # A large asset, such as a sample PDF, is streamed within the collection's
            # byte budget instead of being read whole: digested, and checked for hidden
            # characters when it is UTF-8 text, such as instructions SKILL.md points to.
            return PromptScanner._stream_skill_file(found[0], relative, files)
        content = files.read_bytes(path)
        if content is None:
            return None
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            if text_file:
                result.scan_failures.append(f"{relative}: invalid UTF-8 skill declaration")
                return None
            # An agent's reader still decodes such a file; check the text it would read.
            stream = _HiddenCharacterStream()
            stream.feed(content, final=True)
            return hash_bytes(content), _hidden_character_risks(
                stream.counts, stream.tags, relative
            )
        risks = detect_invisible_characters(text, relative)
        if path.suffix.lower() in _MARKUP_SUFFIXES:
            risks.extend(detect_hidden_markup(text, relative))
        return hash_bytes(content), risks

    @staticmethod
    def _stream_skill_file(
        target: Path, relative: str, files: ConfinedCollection
    ) -> tuple[str, list[RiskAssessment]] | None:
        digest = hashlib.sha256()
        text = _HiddenCharacterStream()
        try:
            with files.open_regular(target, max_bytes=limits.bound("total-bytes")) as stream:
                while chunk := stream.read(65536):
                    digest.update(chunk)
                    text.feed(chunk)
        except (OSError, CollectionError):
            return None
        text.feed(b"", final=True)
        return f"sha256:{digest.hexdigest()}", _hidden_character_risks(
            text.counts, text.tags, relative
        )

    def _scan_instruction_file(
        self, path: Path, rel_path: str, prompt_type: str, raw: bytes, text: str
    ) -> PromptComponent:
        content_hash = hash_bytes(raw)
        file_size = len(raw)
        risks: list[RiskAssessment] = []

        if file_size > 50_000:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="prompt_size",
                    detail=f"'{neutralize(rel_path)}' is {file_size:,} bytes — large prompts increase injection surface.",
                    recommendation="Review for unnecessary content.",
                )
            )

        risks.extend(detect_invisible_characters(text, rel_path))
        if _markup(rel_path):
            risks.extend(detect_hidden_markup(text, rel_path))

        return PromptComponent(
            bom_ref=f"prompt:{rel_path}",
            name=rel_path,
            prompt_type=prompt_type,
            content_hash=content_hash,
            source_path=path.as_posix(),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
        )
