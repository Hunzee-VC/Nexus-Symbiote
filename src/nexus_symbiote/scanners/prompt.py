"""System prompt, instruction file, rule file, and skill definition scanner."""

from __future__ import annotations

import codecs
import hashlib
import re
import unicodedata
from collections import deque
from pathlib import Path, PurePosixPath

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import PromptComponent, RiskAssessment, SkillPackageComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.utils.confined import CollectionError, ConfinedCollection
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

# Every format character (category Cf) of Unicode 15.1, the variation selectors, and
# letters and marks that render as nothing. The scan also checks each distinct
# character's category, so format characters added in later versions are found too.
_HIDDEN = re.compile(
    "[­͏؀-؅؜۝܏࢐࢑࣢ᅟᅠ"
    "឴឵᠋-᠏​-‏‪-‮⁠-⁤⁦-⁯"
    "⠀ㅤ︀-️﻿ﾠ￹-￻\U000110bd\U000110cd"
    "\U00013430-\U0001343f\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
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
    return unicodedata.name(char, "UNNAMED FORMAT CHARACTER")


def detect_invisible_characters(content: str, source_name: str) -> list[RiskAssessment]:
    """Detect invisible Unicode characters that could be used for prompt trojans.

    Every format character (category Cf), variation selector and blank-rendering
    filler is reported. Bidirectional embeddings, overrides and isolates and tag
    characters are critical; directional marks, which right-to-left text uses, are
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
    """The hidden-character counts of UTF-8 text read in chunks.

    The text is counted in segments that end after a newline, which no emoji or flag
    sequence crosses, so the counts equal those of the whole text. A segment that
    reaches ``_MAX_SEGMENT`` characters without one is cut there; a cut can only add
    findings, never hide one.
    """

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")()
        self._pending = ""
        self._at_start = True
        self.counts: dict[str, int] = {}
        self.tags = 0
        self.is_text = True

    def feed(self, chunk: bytes, *, final: bool = False) -> None:
        if not self.is_text:
            return
        try:
            decoded = self._decoder.decode(chunk, final)
        except UnicodeDecodeError:
            self.is_text = False
            return
        text = self._pending + decoded
        end = len(text) if final else text.rfind("\n", len(self._pending)) + 1
        if not end and len(text) >= _MAX_SEGMENT:
            end = len(text)
        if not end:
            self._pending = text
            return
        counts, tags = _hidden_counts(text[:end], at_start=self._at_start)
        self._pending, self._at_start = text[end:], False
        for char, count in counts.items():
            self.counts[char] = self.counts.get(char, 0) + count
        self.tags += tags


def _hidden_character_risks(
    counts: dict[str, int], tags: int, source_name: str
) -> list[RiskAssessment]:
    risks: list[RiskAssessment] = []
    shown = neutralize(source_name)
    invisible = [
        f"{INVISIBLE_CHARS.get(char) or _character_name(char)} (U+{ord(char):04X}) x{count}"
        for char, count in sorted(counts.items(), key=lambda item: ord(item[0]))
        if char not in BIDI_OVERRIDES and char not in DIRECTIONAL_MARKS
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

    if tags:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="tag_characters",
                detail=(
                    f"'{shown}' contains {tags} deprecated Unicode tag "
                    "characters (U+E0000–U+E007F) outside a flag emoji. These are "
                    "invisible and have no legitimate use in prompt files."
                ),
                recommendation="Remove all tag characters — likely a prompt trojan.",
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

# Instruction files a host loads from below the root: per-directory memory files.
NESTED_INSTRUCTION_NAMES = {"CLAUDE.md": "system-prompt", "AGENTS.md": "system-prompt"}

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
# Distinct import targets looked up in one collection. Each lookup of a missing file
# lists the directories on its path for case variants, so file content must not be
# able to ask for an unbounded number of them.
_MAX_IMPORT_LOOKUPS = 5000
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


class PromptScanner(Scanner):
    name = "prompt"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        with self._collection(project_root, result) as files:
            recorded: dict[str, PromptComponent] = {}
            texts: dict[str, str] = {}
            importers: list[str] = []
            for rel_path, prompt_type in INSTRUCTION_FILES.items():
                if rel_path in INSTRUCTION_DIRECTORIES and files.is_directory(rel_path):
                    continue
                variants = _CODEX_SPELLINGS if rel_path in _CODEX_SPELLINGS else ()
                content = files.read_bytes(rel_path, missing_ok=True, variants_read=variants)
                if content is None:
                    continue
                component = self._record(rel_path, prompt_type, content, files, result)
                if component is not None:
                    recorded[rel_path] = component
                    texts[rel_path] = content.decode("utf-8")
                    if PurePosixPath(rel_path).name in _IMPORTING_NAMES:
                        importers.append(rel_path)

            # Memory files below the root, found by name; a name takes precedence over
            # the directory that holds the file.
            for path in sorted(files.iter_files()):
                relative = path.as_posix()
                nested_type = NESTED_INSTRUCTION_NAMES.get(path.name)
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

            for directory, prompt_type in INSTRUCTION_DIRECTORIES.items():
                if directory in INSTRUCTION_FILES and not files.is_directory(directory):
                    continue
                for path in files.iter_files(directory):
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

            self._follow_imports(importers, texts, recorded, files, result)
            self._scan_skills(files, result)

        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("prompts (no instruction files found)")

        return result

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
        the collector records under its own name, such as an imported AGENTS.md.
        """
        pending = deque((path, 0) for path in importers)
        followed = set(importers)
        looked_up: set[str] = set()
        imported_by: dict[str, set[str]] = {}
        exhausted = False
        while pending and not exhausted:
            importer, depth = pending.popleft()
            tokens = _import_tokens(texts[importer])
            if len(set(tokens)) > _MAX_IMPORTS:
                result.scan_failures.append(f"{importer}: too many @path imports to inventory")
                continue
            imports: set[str] = set()
            targets: list[str] = []
            outside = too_long = False
            directory = PurePosixPath(importer).parent.parts
            for token in dict.fromkeys(token.rstrip(_TRAILING) for token in tokens):
                named, leaves, long = _resolve_import(directory, token)
                targets.extend(named)
                outside |= leaves
                too_long |= long
            for target in dict.fromkeys(targets):
                if target in recorded:
                    imports.add(target)
                    if target not in followed and depth + 1 <= _MAX_IMPORT_DEPTH:
                        followed.add(target)
                        pending.append((target, depth + 1))
                    continue
                if target in looked_up:
                    continue
                if len(looked_up) >= _MAX_IMPORT_LOOKUPS:
                    result.scan_failures.append(
                        f"{importer}: more than {_MAX_IMPORT_LOOKUPS} distinct @path imports "
                        "in the project; the rest are not inventoried"
                    )
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
                texts[target] = content.decode("utf-8")
                imports.add(target)
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
                recorded[importer].properties["imports"] = sorted(imports)
                for target in imports:
                    imported_by.setdefault(target, set()).add(importer)
        for target, sources in imported_by.items():
            recorded[target].properties["imported_by"] = sorted(sources)

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

    def _scan_skills(self, files: ConfinedCollection, result: ScanResult) -> None:
        seen: set[str] = set()
        for skill_dir in SKILL_DIRECTORIES:
            for path in files.iter_files(skill_dir):
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
            return hash_bytes(content), []
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
            with files.open_regular(target, max_bytes=files.max_total_bytes) as stream:
                while chunk := stream.read(65536):
                    digest.update(chunk)
                    text.feed(chunk)
        except (OSError, CollectionError):
            return None
        text.feed(b"", final=True)
        risks = _hidden_character_risks(text.counts, text.tags, relative) if text.is_text else []
        return f"sha256:{digest.hexdigest()}", risks

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
