"""``instructions`` collector: instruction files, prompt templates and hooks (``spec/collectors.md``).

Every file an agent client loads as model-visible guidance becomes an ``Instruction`` identified by the
SHA-256 of its exact bytes: memory files (``CLAUDE.md``, ``AGENTS.md``, ``GEMINI.md`` at any depth), rules files
(Cursor, GitHub Copilot, Windsurf, Cline, Roo Code, Kiro, Claude Code), Claude Code sub-agents and slash
commands, and prompt files. Jinja prompt templates become ``PromptTemplate`` entities (``prompt/v1`` digest,
``template-execution`` risk) and each Claude Code hook becomes an ``Instruction(kind=hook)`` digested over the
RFC 8785 bytes of ``{event, matcher, type, command}``.

Content is never stored. Entities carry digests, sizes, line endings, sanitized frontmatter (JSON-safe scalars
only; secret-shaped values are dropped and recorded as redactions) and lint facts: hidden Unicode (the Rules
File Backdoor technique), secret-shaped text (flagged, never echoed), ``@`` imports and the remote URLs they load.
Files are read with a size bound; a larger file is still digested (streamed) but not analysed, and a path that
cannot be read or that escapes the scanned tree through a symlink is a coverage fact, never silent absence.

Locations are data (:data:`PROJECT_RULES`, :data:`USER_RULES`), so supporting a new client is a table entry.
"""

from __future__ import annotations

import os
import re
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Final, Literal
from urllib.parse import urlsplit

import yaml

from symbiote.collect._common import load_yaml, locator, parse_structured, read_bounded, url_facts
from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult, WalkReport
from symbiote.digest import (
    bytes_digest,
    canonical_bytes,
    file_digest,
    hidden_code_points,
    line_endings,
    parse_json_strict,
    prompt_digest,
    triage_digest,
)
from symbiote.digest.jcs import UndigestableError
from symbiote.model.common import Claim, DigestResult, Provenance, looks_like_secret
from symbiote.model.edges import Edge
from symbiote.model.entities import Instruction, PromptTemplate, Redaction
from symbiote.model.enums import (
    CapabilityClass,
    ClaimMethod,
    CollectorMode,
    CoverageStatus,
    DigestStatus,
    EdgeType,
    InstructionKind,
    LineEndings,
    PromptRole,
    RedactionClass,
    Surface,
    TemplateEngine,
    TemplateRiskClass,
    UnknownReason,
)
from symbiote.model.ids import make_id

__all__ = [
    "MAX_APPLIES_TO_TAGS",
    "MAX_FRONTMATTER_CHARS",
    "MAX_FRONTMATTER_STRING",
    "MAX_IMPORT_TAGS",
    "PRECEDENCE_DIRECTORY",
    "PRECEDENCE_PROJECT",
    "PRECEDENCE_USER",
    "PROJECT_RULES",
    "TOOL_CAPABILITIES",
    "USER_RULES",
    "USER_SEARCH",
    "BuiltInstruction",
    "FileFacts",
    "FrontmatterMode",
    "FrontmatterSanitizer",
    "HookDecl",
    "IdRegistry",
    "ImportScan",
    "InstructionInput",
    "InstructionRule",
    "InstructionsCollector",
    "RunState",
    "Scope",
    "applies_to_tags",
    "build_instruction",
    "capability_tags",
    "classify",
    "has_hidden_unicode",
    "is_jinja_template",
    "list_tree",
    "media_type_for",
    "os_error_class",
    "parse_frontmatter",
    "parse_hooks",
    "prompt_rule",
    "read_file_facts",
    "record_walk",
    "remote_display",
    "resolve_within",
    "scan_imports",
    "split_tools",
    "streamed_line_endings",
    "symlink_tag",
]

Scope = Literal["project", "user"]
Placement = Literal["fixed", "tree"]
FrontmatterMode = Literal["none", "lenient", "strict"]

PRECEDENCE_USER: Final = 3
PRECEDENCE_PROJECT: Final = 2
PRECEDENCE_DIRECTORY: Final = 1

#: Frontmatter blocks longer than this are not parsed (tag ``oversized-frontmatter``).
MAX_FRONTMATTER_CHARS: Final = 64 * 1024
#: Frontmatter strings longer than this are dropped: instruction bodies are never embedded (profile §3.5).
MAX_FRONTMATTER_STRING: Final = 4096
MAX_IMPORT_TAGS: Final = 20
MAX_APPLIES_TO_TAGS: Final = 20
#: Variable schemas larger than this are digested but not embedded in the ``PromptTemplate``.
MAX_EMBEDDED_SCHEMA_BYTES: Final = 64 * 1024
MAX_URL_CHARS: Final = 2048

_MAX_SAFE_INT: Final = 2**53 - 1
_CHUNK: Final = 1 << 20

# --------------------------------------------------------------------------------------------- location rules


@dataclass(frozen=True, slots=True)
class InstructionRule:
    """One family of instruction files.

    ``pattern`` is ``fullmatch``-ed against the POSIX path below the scope base (repository root or home).
    ``placement="tree"`` files apply to the directory they sit in: precedence 2 at the root, 1 when nested (the
    named group ``dir`` captures the nesting directory). ``template`` marks prompt files whose Jinja-templated
    members become ``PromptTemplate`` entities.
    """

    label: str
    pattern: re.Pattern[str]
    kind: InstructionKind
    placement: Placement = "fixed"
    frontmatter: bool = False
    imports: bool = False
    template: bool = False


def _rule(
    label: str,
    regex: str,
    kind: InstructionKind,
    *,
    placement: Placement = "fixed",
    frontmatter: bool = False,
    imports: bool = False,
    template: bool = False,
) -> InstructionRule:
    return InstructionRule(label, re.compile(regex), kind, placement, frontmatter, imports, template)


#: Project-scope rules, first match wins: exact locations, then client directories, then memory files found at
#: any depth (so ``.claude/agents/CLAUDE.md`` is a sub-agent definition, not a nested memory file).
PROJECT_RULES: Final[tuple[InstructionRule, ...]] = (
    _rule("claude-md", r"\.claude/CLAUDE\.md", InstructionKind.CLAUDE_MD, imports=True),
    _rule("agents-md", r"\.codex/AGENTS(?:\.override)?\.md", InstructionKind.AGENTS_MD, imports=True),
    _rule("cursor-rules", r"\.cursorrules", InstructionKind.CURSOR_RULES, imports=True),
    _rule(
        "cursor-rules",
        r"(?:(?P<dir>.+)/)?\.cursor/rules/(?:.+/)?[^/]+\.mdc",
        InstructionKind.CURSOR_RULES,
        placement="tree",
        frontmatter=True,
        imports=True,
    ),
    _rule("copilot-instructions", r"\.github/copilot-instructions\.md", InstructionKind.COPILOT_INSTRUCTIONS),
    _rule(
        "copilot-instructions",
        r"\.github/instructions/(?:.+/)?[^/]+\.instructions\.md",
        InstructionKind.COPILOT_INSTRUCTIONS,
        frontmatter=True,
    ),
    _rule(
        "copilot-prompts",
        r"\.github/prompts/(?:.+/)?[^/]+\.prompt\.md",
        InstructionKind.OTHER,
        frontmatter=True,
    ),
    _rule(
        "copilot-agents",
        r"\.github/agents/(?:.+/)?[^/]+\.agent\.md|\.github/chatmodes/(?:.+/)?[^/]+\.chatmode\.md",
        InstructionKind.OTHER,
        frontmatter=True,
    ),
    _rule("windsurf-rules", r"\.windsurfrules", InstructionKind.WINDSURF_RULES),
    _rule(
        "windsurf-rules",
        r"\.windsurf/rules/(?:.+/)?[^/]+\.md",
        InstructionKind.WINDSURF_RULES,
        frontmatter=True,
    ),
    _rule(
        "cline-rules", r"\.clinerules(?:/(?:.+/)?[^/]+\.md)?", InstructionKind.RULES_FILE, frontmatter=True
    ),
    _rule(
        "roo-rules",
        r"\.roorules(?:-[^/]+)?|\.roo/rules(?:-[^/]+)?/(?:.+/)?[^/]+\.(?:md|txt)",
        InstructionKind.RULES_FILE,
    ),
    _rule(
        "kiro-steering", r"\.kiro/steering/(?:.+/)?[^/]+\.md", InstructionKind.RULES_FILE, frontmatter=True
    ),
    _rule(
        "claude-rules",
        r"\.claude/rules/(?:.+/)?[^/]+\.md",
        InstructionKind.RULES_FILE,
        frontmatter=True,
        imports=True,
    ),
    _rule(
        "claude-agents", r"\.claude/agents/[^/]+\.md", InstructionKind.OTHER, frontmatter=True, imports=True
    ),
    _rule(
        "claude-commands",
        r"\.claude/commands/(?:.+/)?[^/]+\.md",
        InstructionKind.OTHER,
        frontmatter=True,
        imports=True,
    ),
    _rule(
        "claude-md",
        r"(?:(?P<dir>.+)/)?CLAUDE(?:\.local)?\.md",
        InstructionKind.CLAUDE_MD,
        placement="tree",
        imports=True,
    ),
    _rule(
        "agents-md",
        r"(?:(?P<dir>.+)/)?AGENTS(?:\.override)?\.md",
        InstructionKind.AGENTS_MD,
        placement="tree",
        imports=True,
    ),
    _rule(
        "gemini-md", r"(?:(?P<dir>.+)/)?GEMINI\.md", InstructionKind.GEMINI_MD, placement="tree", imports=True
    ),
)

#: User-scope rules (paths below ``~``); only consulted when the context carries a home directory.
USER_RULES: Final[tuple[InstructionRule, ...]] = (
    _rule("claude-md", r"\.claude/CLAUDE\.md", InstructionKind.CLAUDE_MD, imports=True),
    _rule(
        "claude-rules",
        r"\.claude/rules/(?:.+/)?[^/]+\.md",
        InstructionKind.RULES_FILE,
        frontmatter=True,
        imports=True,
    ),
    _rule(
        "claude-agents", r"\.claude/agents/[^/]+\.md", InstructionKind.OTHER, frontmatter=True, imports=True
    ),
    _rule(
        "claude-commands",
        r"\.claude/commands/(?:.+/)?[^/]+\.md",
        InstructionKind.OTHER,
        frontmatter=True,
        imports=True,
    ),
    _rule("agents-md", r"\.codex/AGENTS(?:\.override)?\.md", InstructionKind.AGENTS_MD, imports=True),
    _rule("gemini-md", r"\.gemini/GEMINI\.md", InstructionKind.GEMINI_MD, imports=True),
)

#: Where user-scope files are looked for (files, or directories listed recursively) — never the whole home.
USER_SEARCH: Final[tuple[str, ...]] = (
    ".claude/CLAUDE.md",
    ".claude/rules",
    ".claude/agents",
    ".claude/commands",
    ".codex/AGENTS.md",
    ".codex/AGENTS.override.md",
    ".gemini/GEMINI.md",
)

#: Single-file locations checked directly: the repository walk skips symlinks, and ``CLAUDE.md -> AGENTS.md``
#: style links are common, so these are followed when their target stays inside the repository.
#: Client configuration trees: vendor-directory pruning (build, dist, venv...) does not apply inside them, so a
#: rule or skill directory named like a build artefact cannot hide from the BOM.
_CLIENT_TREES: Final[tuple[str, ...]] = (
    ".claude", ".cursor", ".github", ".windsurf", ".kiro", ".roo", ".clinerules", ".gemini", ".codex", ".agents",
    ".continue", ".amazonq", ".junie", ".zed",
)  # fmt: skip
_FIXED_PROJECT_FILES: Final[tuple[str, ...]] = (
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "AGENTS.override.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".roorules",
    ".claude/CLAUDE.md",
    ".codex/AGENTS.md",
    ".github/copilot-instructions.md",
)

#: Claude Code settings files whose ``hooks`` object declares hook commands.
_PROJECT_HOOK_SETTINGS: Final[tuple[str, ...]] = (".claude/settings.json", ".claude/settings.local.json")
_USER_HOOK_SETTINGS: Final = ".claude/settings.json"

_MEDIA_TYPES: Final[Mapping[str, str]] = {
    ".md": "text/markdown",
    ".mdc": "text/markdown",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".j2": "text/x-jinja2",
    ".jinja": "text/x-jinja2",
    ".jinja2": "text/x-jinja2",
}
_TEMPLATE_SUFFIXES: Final = frozenset({".j2", ".jinja", ".jinja2", ".md", ".txt", ".prompt"})
_TEMPLATE_MARKERS: Final = (b"{{", b"{%")


def prompt_rule(directories: Sequence[str]) -> InstructionRule | None:
    """Rule for prompt files below the given repository-relative directories (``prompts/`` by default)."""
    names = [re.escape(d.strip("/")) for d in directories if d.strip("/")]
    if not names:
        return None
    return _rule(
        "prompts",
        rf"(?:{'|'.join(names)})/(?:.+/)?[^/]+\.(?:md|txt|j2|jinja|jinja2|prompt|ya?ml)",
        InstructionKind.SYSTEM_PROMPT,
        template=True,
    )


def classify(rel: str, rules: Sequence[InstructionRule]) -> tuple[InstructionRule, re.Match[str]] | None:
    """The first rule whose pattern matches the POSIX relative path ``rel``, with the match."""
    for rule in rules:
        match = rule.pattern.fullmatch(rel)
        if match is not None:
            return rule, match
    return None


def media_type_for(name: str) -> str:
    return _MEDIA_TYPES.get(PurePosixPath(name).suffix.lower(), "text/plain")


def is_jinja_template(name: str, data: bytes) -> bool:
    """A prompt file is a Jinja template when it has a template-capable extension, ``{{``/``{%`` markers and is
    valid UTF-8 (the ``prompt/v1`` digest is defined over the exact decoded string)."""
    if PurePosixPath(name).suffix.lower() not in _TEMPLATE_SUFFIXES or not any(
        m in data for m in _TEMPLATE_MARKERS
    ):
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


# --------------------------------------------------------------------------------------------- filesystem

_OS_ERROR_CLASSES: Final[tuple[tuple[type[BaseException], str], ...]] = (
    (PermissionError, "permission-denied"),
    (FileNotFoundError, "not-found"),
    (RuntimeError, "symlink-loop"),
)


def os_error_class(exc: BaseException) -> str:
    """Coverage ``error_class`` for a filesystem failure."""
    return next((name for kind, name in _OS_ERROR_CLASSES if isinstance(exc, kind)), "unreadable")


def resolve_within(path: Path, bounds: Path, *, directory: bool = False) -> tuple[Path | None, str | None]:
    """Resolve ``path`` (following symlinks) and require a regular file (or a directory) inside ``bounds``.

    ``bounds`` must already be resolved. Returns ``(real path, None)`` or ``(None, error_class)``:
    ``symlink-escape`` when the target leaves the scanned tree, ``broken-symlink``, ``not-a-regular-file`` for
    FIFOs, sockets and devices (reading them could block or never end), or the class of the OS error.
    """
    try:
        real = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        broken = isinstance(exc, FileNotFoundError) and path.is_symlink()
        return None, "broken-symlink" if broken else os_error_class(exc)
    if not real.is_relative_to(bounds):
        return None, "symlink-escape"
    if not (real.is_dir() if directory else real.is_file()):
        return None, "not-a-directory" if directory else "not-a-regular-file"
    return real, None


def symlink_tag(path: Path, *, base: Path, bounds: Path, prefix: str = "") -> str | None:
    """``symlink-to:<target>`` when ``path`` (below ``base``) reaches its content through a symlink in bounds."""
    try:
        real = path.resolve(strict=True)
        expected = bounds / path.relative_to(base)
    except (OSError, RuntimeError, ValueError):
        return None
    if real == expected or not real.is_relative_to(bounds):
        return None
    return f"symlink-to:{prefix}{real.relative_to(bounds).as_posix()}"


def list_tree(
    base: Path, *, exclude: Collection[str], limit: int
) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Non-directory entries below ``base`` in sorted order, plus ``(directory, error_class)`` for unreadable
    directories. Symlinked files are listed (callers resolve them within bounds); symlinked directories are
    not followed."""
    files: list[Path] = []
    problems: list[tuple[Path, str]] = []
    stack = [base]
    while stack and len(files) < limit:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name, reverse=True)
        except OSError as exc:
            problems.append((current, os_error_class(exc)))
            continue
        for entry in entries:
            if not entry.is_dir() or entry.is_symlink():
                files.append(entry)
            elif entry.name not in exclude:
                stack.append(entry)
    return sorted(files)[:limit], problems


def record_walk(result: CollectionResult, walked: int, limit: int) -> None:
    """Record the repository walk as a coverage source; hitting ``limit`` marks the surface truncated."""
    truncated = walked >= limit
    result.add_source(
        Surface.INSTRUCTIONS,
        "repo-walk",
        locator=".",
        ok=not truncated,
        error_class="truncated" if truncated else None,
    )
    if truncated:
        result.set_status(Surface.INSTRUCTIONS, CoverageStatus.TRUNCATED, truncated_at=limit)
        result.warnings.append(f"repository walk stopped at {limit} files; files beyond it were not examined")


# --------------------------------------------------------------------------------------------- bytes


@dataclass(frozen=True, slots=True)
class FileFacts:
    """Byte-level facts about one file. ``data`` is ``None`` when the file exceeded the analysis bound."""

    digest: str
    size: int
    line_endings: LineEndings
    data: bytes | None


_EOL: Final[Mapping[tuple[bool, bool], LineEndings]] = {
    (True, True): LineEndings.MIXED,
    (True, False): LineEndings.CRLF,
    (False, True): LineEndings.LF,
    (False, False): LineEndings.NONE,
}


def streamed_line_endings(path: Path) -> LineEndings:
    """:func:`symbiote.digest.line_endings` over a file read in chunks (a CRLF split across chunks counts once)."""
    crlf = lf = 0
    previous_cr = False
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            crlf += chunk.count(b"\r\n") + (1 if previous_cr and chunk.startswith(b"\n") else 0)
            lf += chunk.count(b"\n")
            previous_cr = chunk.endswith(b"\r")
    return _EOL[(crlf > 0, lf - crlf > 0)]


def read_file_facts(path: Path, max_bytes: int) -> tuple[FileFacts | None, str | None]:
    """Bounded read of one file. A file over ``max_bytes`` is still digested by streaming
    (:func:`symbiote.digest.file_digest`) but its bytes are not returned for analysis."""
    outcome = read_bounded(path, max_bytes)
    if outcome.data is not None:
        data = outcome.data
        return FileFacts(bytes_digest(data), len(data), line_endings(data), data), None
    if outcome.error_class != "too-large":
        return None, outcome.error_class
    try:
        digest, size = file_digest(path)
        eol = streamed_line_endings(path)
    except OSError as exc:
        return None, os_error_class(exc)
    return FileFacts(digest, size, eol, None), None


def has_hidden_unicode(text: str) -> bool:
    """Hidden or direction-altering code points (``symbiote.digest.hidden_code_points``); ASCII is never hidden."""
    return not text.isascii() and bool(hidden_code_points(text))


# --------------------------------------------------------------------------------------------- frontmatter

_FRONTMATTER: Final[Mapping[str, re.Pattern[str]]] = {
    # tolerant split for rules files: trailing blanks on fences, empty blocks, a closing fence at end of file
    "lenient": re.compile(r"\A---[ \t]*\r?\n(.*?)^---[ \t]*(?:\r?\n|\Z)", re.DOTALL | re.MULTILINE),
    # the Agent Skills split (spec/collectors.md): ^---\n(.*?)\n---\n, CRLF tolerated
    "strict": re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n", re.DOTALL),
}
_YAML_ERRORS: Final = (yaml.YAMLError, RecursionError, ValueError, TypeError)
# Greedy captures, stripped in Python: a lazy capture followed by ``[ \t]*`` backtracks quadratically on long
# whitespace runs, which a hostile rules file could use to stall the scan past its time budget.
_LENIENT_KEY: Final = re.compile(r"(?P<key>[A-Za-z_][\w.-]*)[ \t]*:(?P<value>.*)")
_LENIENT_ITEM: Final = re.compile(r"[ \t]*-[ \t]+(?P<value>.*)")
_LENIENT_BOOLEANS: Final[Mapping[str, bool]] = {"true": True, "false": False}


def parse_frontmatter(text: str, mode: FrontmatterMode) -> tuple[dict[str, Any] | None, str | None]:
    """Split and ``yaml.safe_load`` a frontmatter block: ``(mapping or None when absent, problem tag or None)``.

    ``lenient`` mode falls back to ``key: value`` lines when the block is not YAML (Cursor ``.mdc`` files often
    carry unquoted ``globs: *.ts``) and tags ``lenient-frontmatter``; ``strict`` mode (Agent Skills) reports
    ``invalid-frontmatter`` instead. Parse errors are never echoed: YAML messages quote the offending text.
    """
    pattern = _FRONTMATTER.get(mode)
    match = pattern.match(text) if pattern is not None else None
    if match is None:
        return None, None
    block = match.group(1)
    if len(block) > MAX_FRONTMATTER_CHARS:
        return None, "oversized-frontmatter"
    try:
        loaded = load_yaml(block, allow_aliases=False)  # frontmatter has no use for anchors
    except _YAML_ERRORS:
        return (
            (None, "invalid-frontmatter")
            if mode == "strict"
            else (_lenient_frontmatter(block), "lenient-frontmatter")
        )
    loaded = {} if loaded is None else loaded
    return (loaded, None) if isinstance(loaded, dict) else (None, "invalid-frontmatter")


def _lenient_scalar(raw: str) -> object:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return _LENIENT_BOOLEANS.get(value.lower(), value) if value else None


def _lenient_frontmatter(block: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    current: str | None = None
    for line in block.splitlines():
        item = _LENIENT_ITEM.fullmatch(line)
        if item is not None and current is not None:
            previous = out.get(current)
            out[current] = [
                *(previous if isinstance(previous, list) else []),
                _lenient_scalar(item.group("value")),
            ]
            continue
        pair = _LENIENT_KEY.fullmatch(line)
        if pair is not None:
            current = pair.group("key")
            out[current] = _lenient_scalar(pair.group("value"))
    return out


_DROP: Final = object()


@dataclass(slots=True)
class FrontmatterSanitizer:
    """Reduce parsed YAML to JSON-safe scalars and flat lists of scalars.

    Secret-shaped values (and keys) are dropped and counted in ``redacted`` (they become a ``Redaction``
    record); values carrying hidden Unicode or longer than :data:`MAX_FRONTMATTER_STRING` are dropped too, so
    the BOM never republishes a hidden payload. Dates become ISO strings; nested mappings are dropped.
    """

    redacted: int = 0

    def scalar(self, value: object) -> object:
        if isinstance(value, date):
            value = value.isoformat()
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int | float):
            return value if abs(value) <= _MAX_SAFE_INT else _DROP  # also drops NaN and infinities
        if not isinstance(value, str) or len(value) > MAX_FRONTMATTER_STRING or has_hidden_unicode(value):
            return _DROP
        if looks_like_secret(value):
            self.redacted += 1
            return _DROP
        return value

    def text(self, value: object) -> str | None:
        cleaned = self.scalar(value)
        return cleaned if isinstance(cleaned, str) else None

    def value(self, value: object) -> object:
        if isinstance(value, list):
            return [item for item in map(self.scalar, value) if item is not _DROP]
        return self.scalar(value)

    def mapping(self, data: Mapping[Any, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, raw in data.items():
            name = self.text(key)
            cleaned = self.value(raw) if name is not None else _DROP
            if name is not None and cleaned is not _DROP:
                out[name] = cleaned
        return out


_GLOB_KEYS: Final = ("globs", "applyTo", "fileMatchPattern", "paths")
_ALWAYS_ON: Final[tuple[tuple[str, object], ...]] = (
    ("alwaysApply", True),
    ("trigger", "always_on"),
    ("inclusion", "always"),
)


def applies_to_tags(frontmatter: Mapping[str, Any]) -> list[str]:
    """``applies-to:<glob>`` from ``globs`` (Cursor, Windsurf), ``applyTo`` (Copilot), ``fileMatchPattern`` (Kiro)
    and ``paths``; always-on rules (``alwaysApply: true``, ``trigger: always_on``, ``inclusion: always``) apply to
    ``**``. Comma-separated strings and lists are both accepted; at most :data:`MAX_APPLIES_TO_TAGS` tags."""
    globs: list[str] = ["**"] if any(frontmatter.get(k) == v for k, v in _ALWAYS_ON) else []
    for key in _GLOB_KEYS:
        raw = frontmatter.get(key)
        for item in raw if isinstance(raw, list) else [raw]:
            if isinstance(item, str):
                globs.extend(part.strip() for part in item.split(","))
    sanitizer = FrontmatterSanitizer()
    safe = [g for g in dict.fromkeys(globs) if g and len(g) <= 256 and sanitizer.text(g) is not None]
    return [f"applies-to:{g}" for g in safe[:MAX_APPLIES_TO_TAGS]]


# --------------------------------------------------------------------------------------------- tools & capabilities

#: Claude Code tool names that imply a capability class (``allowed-tools`` / ``tools`` frontmatter).
TOOL_CAPABILITIES: Final[Mapping[str, CapabilityClass]] = {
    "Bash": CapabilityClass.EXECUTE,
    "Write": CapabilityClass.WRITE,
    "Edit": CapabilityClass.WRITE,
    "MultiEdit": CapabilityClass.WRITE,
    "NotebookEdit": CapabilityClass.WRITE,
    "WebFetch": CapabilityClass.NETWORK_EGRESS,
    "WebSearch": CapabilityClass.NETWORK_EGRESS,
}
_PAREN_DEPTH: Final[Mapping[str, int]] = {"(": 1, ")": -1}


def _split_tool_string(text: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in text:
        if depth == 0 and (ch.isspace() or ch == ","):
            if buf:
                parts.append("".join(buf))
                buf = []
            continue
        depth = max(depth + _PAREN_DEPTH.get(ch, 0), 0)
        buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def split_tools(value: object) -> list[str]:
    """Tokenise a tool list: a space- or comma-delimited string, or a list of such strings. Parentheses group,
    so ``Bash(git add:*)`` stays one token."""
    items = value if isinstance(value, list) else [value]
    return [part for item in items if isinstance(item, str) for part in _split_tool_string(item)]


def capability_tags(tools: Iterable[str]) -> list[str]:
    """``capability:<class>`` hints from tool tokens (``Bash(...)`` / ``Bash`` ⇒ ``execute`` ...)."""
    found = {
        TOOL_CAPABILITIES[base] for t in tools if (base := t.split("(", 1)[0].strip()) in TOOL_CAPABILITIES
    }
    return sorted(f"capability:{c.value}" for c in found)


# --------------------------------------------------------------------------------------------- imports & URLs

_FENCE: Final = re.compile(r"[ \t]{0,3}(?:`{3,}|~{3,})")
_CODE_SPAN: Final = re.compile(r"`[^`]*`")
_AT_IMPORT: Final = re.compile(r"(?:^|(?<=\s))@(?P<target>\S+)")
_LOCAL_TARGET: Final = re.compile(r"[\w./~+-]{1,256}")
_REMOTE_SCHEMES: Final = ("http://", "https://")
_TRAILING_PUNCTUATION: Final = ".,;:!?)]}>'\""
_URL_IN_TEXT: Final = re.compile(r"""https?://[^\s'"`<>|;)\\]+""", re.IGNORECASE)


def remote_display(url: str, *, origin_only: bool = False) -> tuple[str, bool]:
    """A credential-free rendering of ``url`` and whether credential material was dropped.

    Userinfo, query and fragment are always dropped (:func:`symbiote.collect._common.url_facts`); the path is
    dropped as well when ``origin_only`` (hook commands embed tokens in webhook paths) or when it is
    secret-shaped, carries hidden Unicode or is unreasonably long.
    """
    try:
        facts = url_facts(url)
        parts = urlsplit(facts.display)
    except ValueError:
        return f"{url.split(':', 1)[0].lower()}://<unparseable>", False
    origin = f"{parts.scheme}://{parts.netloc}"
    # url_facts already replaced a credential-shaped path (or host) with <redacted> and reports it
    secret_path = facts.secret_in_path or looks_like_secret(facts.display)
    redacted = facts.had_userinfo or facts.secret_in_query or secret_path
    if has_hidden_unicode(origin) or len(origin) > MAX_URL_CHARS:
        return f"{parts.scheme}://<invalid-host>", redacted
    if origin_only:
        return origin, redacted
    if secret_path or has_hidden_unicode(facts.display) or len(facts.display) > MAX_URL_CHARS:
        return f"{origin}/<redacted>", redacted
    return facts.display, redacted


@dataclass(frozen=True, slots=True)
class ImportScan:
    """``@`` import directives found outside code: remote URLs (credential-free), local targets, redactions."""

    remote: tuple[str, ...] = ()
    remote_line: int | None = None
    local: tuple[str, ...] = ()
    redacted: int = 0


def _import_targets(text: str) -> Iterator[tuple[int, str]]:
    in_fence = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in _AT_IMPORT.finditer(_CODE_SPAN.sub(" ", line)):
            target = match.group("target").rstrip(_TRAILING_PUNCTUATION)
            if target:
                yield lineno, target


def scan_imports(text: str) -> ImportScan:
    """``@path`` and ``@https://...`` directives (Claude Code and Gemini CLI memory imports, Cursor ``@file``
    references) outside fenced code blocks and inline code spans. ``user@host`` is not an import: the ``@`` must
    start the line or follow whitespace. Secret-shaped targets are dropped and counted, never echoed."""
    remote: list[str] = []
    local: list[str] = []
    first_remote: int | None = None
    redacted = 0
    for lineno, target in _import_targets(text):
        if target.lower().startswith(_REMOTE_SCHEMES):
            display, dropped = remote_display(target)
            remote.append(display)
            redacted += int(dropped)
            first_remote = first_remote or lineno
        elif looks_like_secret(target):
            redacted += 1
        elif _LOCAL_TARGET.fullmatch(target) and any(ch.isalnum() for ch in target):
            local.append(target)
    return ImportScan(tuple(dict.fromkeys(remote)), first_remote, tuple(dict.fromkeys(local)), redacted)


# --------------------------------------------------------------------------------------------- hooks


@dataclass(frozen=True, slots=True)
class HookDecl:
    """One hook from a Claude Code settings file. ``body`` (the command or prompt text) is transient: it is
    digested and linted, never stored."""

    event: str
    group: int
    index: int
    matcher: object
    hook_type: str
    body_key: str
    body: str

    @property
    def pointer(self) -> tuple[str | int, ...]:
        return ("hooks", self.event, self.group, "hooks", self.index)

    def payload(self) -> dict[str, object]:
        """The digested object: ``{event, matcher, type, command}`` (``prompt`` instead of ``command`` for
        prompt hooks); an absent matcher is ``null``."""
        return {
            "event": self.event,
            "matcher": self.matcher,
            "type": self.hook_type,
            self.body_key: self.body,
        }


_HOOK_BODY_KEYS: Final[Mapping[str, str]] = {"command": "command", "prompt": "prompt"}

HookProblem = tuple[tuple[str | int, ...], str]


def _parse_hook_group(
    event: str, group_index: int, group: object, decls: list[HookDecl], problems: list[HookProblem]
) -> None:
    if not isinstance(group, Mapping) or not isinstance(group.get("hooks"), list):
        problems.append((("hooks", event, group_index), "invalid-hooks"))
        return
    matcher = group.get("matcher")
    for index, hook in enumerate(group["hooks"]):
        hook_type = hook.get("type") if isinstance(hook, Mapping) else None
        body_key = _HOOK_BODY_KEYS.get(hook_type) if isinstance(hook_type, str) else None
        body = hook.get(body_key) if isinstance(hook, Mapping) and body_key is not None else None
        if not isinstance(hook_type, str) or body_key is None or not isinstance(body, str):
            problems.append((("hooks", event, group_index, "hooks", index), "unsupported-hook"))
            continue
        decls.append(HookDecl(event, group_index, index, matcher, hook_type, body_key, body))


def parse_hooks(settings: object) -> tuple[list[HookDecl], list[HookProblem]]:
    """Hooks declared in a parsed Claude Code settings object (``hooks: {event: [{matcher, hooks: [{type,
    command}]}]}``), plus ``(pointer, problem)`` for entries that cannot be modelled: they become failed
    coverage sources, never silent absence."""
    hooks = settings.get("hooks") if isinstance(settings, Mapping) else None
    if hooks is None:
        return [], []
    if not isinstance(hooks, Mapping):
        return [], [(("hooks",), "invalid-hooks")]
    decls: list[HookDecl] = []
    problems: list[HookProblem] = []
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            problems.append((("hooks", str(event)), "invalid-hooks"))
            continue
        for group_index, group in enumerate(groups):
            _parse_hook_group(str(event), group_index, group, decls, problems)
    return decls, problems


def _safe_label(value: object) -> str | None:
    """``value`` when it may appear in an id, name or tag: a short string, not secret-shaped, no hidden text."""
    if not isinstance(value, str) or not value or len(value) > 128:
        return None
    return None if looks_like_secret(value) or has_hidden_unicode(value) else value


# --------------------------------------------------------------------------------------------- instruction builder


@dataclass(frozen=True, slots=True)
class InstructionInput:
    """Everything :func:`build_instruction` needs besides the bytes."""

    entity_id: str
    name: str
    display: str
    kind: InstructionKind
    precedence: int
    frontmatter: FrontmatterMode = "none"
    imports: bool = False
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BuiltInstruction:
    """An ``Instruction`` plus transient analysis inputs for callers that lint further (never stored)."""

    instruction: Instruction
    text: str | None
    frontmatter: dict[str, Any] | None
    frontmatter_problem: str | None
    redacted: int


@dataclass(frozen=True, slots=True)
class _TextLint:
    text: str
    utf8: bool
    secret_like: bool
    tags: tuple[str, ...]
    raw_frontmatter: dict[str, Any] | None
    frontmatter_problem: str | None
    frontmatter: dict[str, Any] | None
    imports: ImportScan | None
    redacted: int


def _lint(data: bytes, *, frontmatter: FrontmatterMode, imports: bool) -> _TextLint:
    try:
        decoded, utf8 = data.decode("utf-8"), True
    except UnicodeDecodeError:
        decoded, utf8 = data.decode("utf-8", errors="replace"), False
    text = decoded.removeprefix("\ufeff")
    secret = looks_like_secret(text)
    flags = (("not-utf8", not utf8), ("hidden-unicode", has_hidden_unicode(text)), ("secret-like", secret))
    tags = [tag for tag, on in flags if on]
    raw, problem = parse_frontmatter(text, frontmatter if utf8 else "none")
    sanitizer = FrontmatterSanitizer()
    clean = sanitizer.mapping(raw) if raw is not None else None
    if raw is not None:
        # capability and applicability facts come from the raw values: a hidden code point elsewhere in the
        # string must not hide a granted ``Bash`` from the BOM
        tags += applies_to_tags(raw)
        tags += capability_tags([*split_tools(raw.get("allowed-tools")), *split_tools(raw.get("tools"))])
    scan = scan_imports(text) if imports and utf8 else None
    if scan is not None:
        tags += [f"local-import:{target}" for target in scan.local[:MAX_IMPORT_TAGS]]
    if problem is not None:
        tags.append(problem)
    redacted = sanitizer.redacted + (scan.redacted if scan is not None else 0)
    return _TextLint(text, utf8, secret, tuple(tags), raw, problem, clean, scan, redacted)


def build_instruction(
    spec: InstructionInput, facts: FileFacts, *, collector: str, observed_at: datetime
) -> BuiltInstruction:
    """Turn one file's bytes into an ``Instruction`` (exact-bytes digest, triage digest, lint facts).

    The content is never stored. Without analysable bytes (``facts.data is None``) the entity carries only
    byte-level facts, the tag ``too-large-for-analysis`` and an ``unknown`` ``loads_remote`` claim.
    """
    provenance = Provenance(
        method=ClaimMethod.CONFIG, locator=spec.display, collector=collector, observed_at=observed_at
    )
    if facts.data is None:
        instruction = Instruction(
            id=spec.entity_id,
            name=spec.name,
            provenance=provenance,
            tags=sorted({*spec.tags, "too-large-for-analysis"}),
            instruction_kind=spec.kind,
            path=spec.display,
            media_type=media_type_for(spec.name),
            size=facts.size,
            digest=facts.digest,
            line_endings=facts.line_endings,
            precedence=spec.precedence,
            loads_remote=Claim.unknown(UnknownReason.TRUNCATED, locator=spec.display, collector=collector),
        )
        return BuiltInstruction(instruction, None, None, None, 0)
    lint = _lint(facts.data, frontmatter=spec.frontmatter, imports=spec.imports)
    loads_remote: Claim[list[str]]
    if spec.imports and not lint.utf8:
        loads_remote = Claim.unknown(
            UnknownReason.UNSUPPORTED_SOURCE, locator=spec.display, collector=collector
        )
    else:
        scan = lint.imports or ImportScan()
        loads_remote = Claim.declared(
            sorted(scan.remote),
            locator=f"{spec.display}:{scan.remote_line}" if scan.remote_line else spec.display,
            collector=collector,
            observed_at=observed_at,
        )
    instruction = Instruction(
        id=spec.entity_id,
        name=spec.name,
        provenance=provenance,
        tags=sorted({*spec.tags, *lint.tags}),
        instruction_kind=spec.kind,
        path=spec.display,
        media_type=media_type_for(spec.name),
        size=facts.size,
        digest=facts.digest,
        normalized_digest=triage_digest(facts.data),
        line_endings=facts.line_endings,
        precedence=spec.precedence,
        loads_remote=loads_remote,
        contains_secret_like=lint.secret_like,
        frontmatter=lint.frontmatter,
    )
    return BuiltInstruction(
        instruction, lint.text, lint.raw_frontmatter, lint.frontmatter_problem, lint.redacted
    )


# --------------------------------------------------------------------------------------------- run state


@dataclass(slots=True)
class IdRegistry:
    """Collision-free entity ids: a clashing slug gets a ``-<digest6>`` suffix (``spec/agentbom-profile.md`` §1.1)."""

    used: set[str] = field(default_factory=set)

    def claim(self, kind: str, *parts: str) -> str:
        seed = "\x00".join(parts)
        entity_id = make_id(kind, *parts)
        attempt = 0
        while entity_id in self.used:
            attempt += 1
            entity_id = make_id(kind, *parts, collision_seed=f"{seed}\x00{attempt}")
        self.used.add(entity_id)
        return entity_id


@dataclass(slots=True)
class RunState:
    """Per-run bookkeeping shared by the instruction-family collectors: ids, de-duplication, coverage failures,
    ``loadsInstruction`` edges and redaction accounting."""

    ctx: CollectContext
    result: CollectionResult
    ids: IdRegistry = field(default_factory=IdRegistry)
    seen: set[str] = field(default_factory=set)
    redacted: int = 0
    redacted_ids: set[str] = field(default_factory=set)

    def first_visit(self, path: Path) -> bool:
        """True the first time ``path`` is offered (a home inside the repository must not double-count)."""
        key = os.path.abspath(path)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True

    def redact(self, entity_id: str, count: int) -> None:
        if count > 0:
            self.redacted += count
            self.redacted_ids.add(entity_id)

    def fail(self, source: str, where: str, error_class: str, detail: str | None = None) -> None:
        self.result.add_source(Surface.INSTRUCTIONS, source, locator=where, ok=False, error_class=error_class)
        self.result.warnings.append(f"{where}: {error_class}" + (f" ({detail})" if detail else ""))

    def link(self, entity_id: str, precedence: int, declared_by: str) -> None:
        self.result.edges.append(
            Edge.model_validate(
                {
                    "type": EdgeType.LOADS_INSTRUCTION,
                    "from": self.ctx.agent_id,
                    "to": entity_id,
                    "qualifiers": {"precedence": precedence},
                    "declaredBy": declared_by,
                }
            )
        )

    def finish(self, applied_by: str) -> CollectionResult:
        if self.redacted:
            self.result.redactions.append(
                Redaction(
                    redaction_class=RedactionClass.CREDENTIAL_SHAPED_TOKEN.value,
                    count=self.redacted,
                    applied_by=applied_by,
                    applied_at=self.ctx.now,
                    ids=sorted(self.redacted_ids),
                )
            )
        return self.result


# --------------------------------------------------------------------------------------------- collector


@dataclass(frozen=True, slots=True)
class _Candidate:
    rel: str
    path: Path
    rule: InstructionRule
    match: re.Match[str]


@dataclass(frozen=True, slots=True)
class _Schema:
    """A prompt's sibling ``<stem>.schema.json``: ``parsed`` feeds the digest, ``embedded`` is stored."""

    parsed: dict[str, Any] | None = None
    embedded: dict[str, Any] | None = None
    digest: str | None = None
    tags: tuple[str, ...] = ()
    redacted: int = 0


def _json_strings(value: object) -> Iterator[str]:
    """Every string (keys included) in a parsed JSON value, iteratively (no recursion limit to hit)."""
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            yield current
        elif isinstance(current, Mapping):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def _parse_schema(data: bytes) -> dict[str, Any] | None:
    try:
        parsed = parse_json_strict(data)
    except (ValueError, RecursionError):  # includes UndigestableError and json's integer digit limit
        return None
    return parsed if isinstance(parsed, dict) else None


def _scope_tag(scope: Scope, precedence: int) -> str:
    return "scope:directory" if precedence == PRECEDENCE_DIRECTORY else f"scope:{scope}"


def _project_precedence(rule: InstructionRule, match: re.Match[str]) -> int:
    nested = rule.placement == "tree" and bool(match.groupdict().get("dir"))
    return PRECEDENCE_DIRECTORY if nested else PRECEDENCE_PROJECT


class InstructionsCollector(BaseCollector):
    """Instruction files, prompt templates and hooks for every supported agent client."""

    name = "instructions"
    version = "0.1.0"
    surfaces = (Surface.INSTRUCTIONS,)
    mode = CollectorMode.DECLARED

    def __init__(
        self,
        *,
        prompt_dirs: Sequence[str] = ("prompts",),
        project_rules: Sequence[InstructionRule] = PROJECT_RULES,
        user_rules: Sequence[InstructionRule] = USER_RULES,
    ) -> None:
        prompts = prompt_rule(prompt_dirs)
        self.project_rules: tuple[InstructionRule, ...] = (*project_rules, *([prompts] if prompts else []))
        self.user_rules: tuple[InstructionRule, ...] = tuple(user_rules)

    def detect(self, ctx: CollectContext) -> bool:
        del ctx
        return True  # absence of every instruction file is itself a fact worth recording (queried, 0 items)

    def collect(self, ctx: CollectContext) -> CollectionResult:
        run = RunState(ctx, self.new_result())
        root = ctx.root.resolve()
        for cand in self._project_candidates(run):
            precedence = _project_precedence(cand.rule, cand.match)
            self._emit_file(run, cand, scope="project", precedence=precedence, base=ctx.root, bounds=root)
        for rel in _PROJECT_HOOK_SETTINGS:
            self._emit_hooks(run, ctx.root / rel, scope="project", precedence=PRECEDENCE_PROJECT, bounds=root)
        if ctx.home is None:
            run.result.add_source(Surface.INSTRUCTIONS, "user-scope", ok=False, error_class="not-attempted")
        else:
            home = ctx.home.resolve()
            for cand in self._user_candidates(run, ctx.home):
                self._emit_file(
                    run, cand, scope="user", precedence=PRECEDENCE_USER, base=ctx.home, bounds=home
                )
            hooks = ctx.home / _USER_HOOK_SETTINGS
            self._emit_hooks(run, hooks, scope="user", precedence=PRECEDENCE_USER, bounds=home)
        return run.finish(self.ref)

    # ----------------------------------------------------------------------------------------- discovery

    def _project_candidates(self, run: RunState) -> list[_Candidate]:
        ctx = run.ctx
        found: dict[str, _Candidate] = {}
        report = WalkReport()
        for path in ctx.walk(report=report, keep_within=_CLIENT_TREES):
            self._consider(found, path.relative_to(ctx.root).as_posix(), path, self.project_rules)
        for rel in _FIXED_PROJECT_FILES:
            path = ctx.root / rel
            if rel not in found and (path.is_symlink() or path.is_file()):
                self._consider(found, rel, path, self.project_rules)
        # symlinked rule files anywhere in the tree: resolved within the repository by _emit_file, which records
        # an escape or a broken link as a coverage fact instead of dropping the file silently
        for rel in report.symlink_paths:
            if rel not in found:
                self._consider(found, rel, ctx.root / rel, self.project_rules)
        run.result.record_walk(Surface.INSTRUCTIONS, report)
        if report.truncated_at is not None:
            run.result.warnings.append(
                f"repository walk stopped at {report.truncated_at} files; files beyond it were not examined"
            )
        return [found[rel] for rel in sorted(found)]

    def _user_candidates(self, run: RunState, home: Path) -> list[_Candidate]:
        found: dict[str, _Candidate] = {}
        for rel in USER_SEARCH:
            base = home / rel
            files: list[Path] = [base] if os.path.lexists(base) and not base.is_dir() else []
            if base.is_dir():
                files, problems = list_tree(base, exclude=run.ctx.exclude_dirs, limit=run.ctx.max_files)
                for directory, error_class in problems:
                    run.fail("user-scope", run.ctx.display(directory), error_class)
            for path in files:
                self._consider(found, path.relative_to(home).as_posix(), path, self.user_rules)
        return [found[rel] for rel in sorted(found)]

    @staticmethod
    def _consider(
        found: dict[str, _Candidate], rel: str, path: Path, rules: Sequence[InstructionRule]
    ) -> None:
        hit = classify(rel, rules)
        if hit is not None:
            found.setdefault(rel, _Candidate(rel, path, *hit))

    # ----------------------------------------------------------------------------------------- files

    def _emit_file(
        self, run: RunState, cand: _Candidate, *, scope: Scope, precedence: int, base: Path, bounds: Path
    ) -> None:
        if not run.first_visit(cand.path):
            return
        ctx = run.ctx
        display = ctx.display(cand.path)
        source = f"{cand.rule.label}:{scope}"
        real, error = resolve_within(cand.path, bounds)
        if real is None:
            run.fail(source, display, error or "unreadable", "not analysed")
            return
        facts, error = read_file_facts(real, ctx.max_file_bytes)
        if facts is None:
            run.fail(source, display, error or "unreadable", "not analysed")
            return
        tags = [_scope_tag(scope, precedence)]
        link = symlink_tag(cand.path, base=base, bounds=bounds, prefix="~/" if scope == "user" else "")
        tags += [link] if link else []
        if cand.rule.template and facts.data is not None and is_jinja_template(cand.path.name, facts.data):
            self._emit_prompt(
                run, cand, facts, facts.data, display=display, source=source, tags=tags, bounds=bounds
            )
            return
        entity_id = run.ids.claim("instr", display)
        mode: FrontmatterMode = "lenient" if cand.rule.frontmatter else "none"
        spec = InstructionInput(
            entity_id,
            cand.path.name,
            display,
            cand.rule.kind,
            precedence,
            mode,
            cand.rule.imports,
            tuple(tags),
        )
        built = build_instruction(spec, facts, collector=self.ref, observed_at=ctx.now)
        run.result.entities.append(built.instruction)
        run.redact(entity_id, built.redacted)
        analysed = facts.data is not None
        run.result.add_source(
            Surface.INSTRUCTIONS,
            source,
            locator=display,
            ok=analysed,
            error_class=None if analysed else "too-large",
            items=1,
        )
        if not analysed:
            run.result.warnings.append(
                f"{display}: larger than {ctx.max_file_bytes} bytes; digested, not analysed"
            )
        run.link(entity_id, precedence, display)

    def _emit_prompt(
        self,
        run: RunState,
        cand: _Candidate,
        facts: FileFacts,
        data: bytes,
        *,
        display: str,
        source: str,
        tags: list[str],
        bounds: Path,
    ) -> None:
        template = data.decode(
            "utf-8"
        )  # exact string (a BOM stays part of it); is_jinja_template checked UTF-8
        text = template.removeprefix("\ufeff")
        lint = (("hidden-unicode", has_hidden_unicode(text)), ("secret-like", looks_like_secret(text)))
        schema = self._variables_schema(run, cand.path, bounds)
        try:
            digest = prompt_digest(
                engine=TemplateEngine.JINJA2.value,
                role=PromptRole.SYSTEM.value,
                template=template,
                variables_schema=schema.parsed,
            )
        except RecursionError:
            digest = DigestResult(
                algorithm="prompt/v1", status=DigestStatus.UNDIGESTABLE, reason="nesting-too-deep"
            )
        entity_id = run.ids.claim("prompt", display)
        run.result.entities.append(
            PromptTemplate(
                id=entity_id,
                name=cand.path.name,
                provenance=Provenance(
                    method=ClaimMethod.CONFIG, locator=display, collector=self.ref, observed_at=run.ctx.now
                ),
                tags=sorted({*tags, *schema.tags, *(tag for tag, on in lint if on)}),
                engine=TemplateEngine.JINJA2,
                role=PromptRole.SYSTEM,
                digest=digest,
                template_digest=facts.digest,
                variables_schema=schema.embedded,
                variables_schema_digest=schema.digest,
                path=display,
                risk_class=TemplateRiskClass.TEMPLATE_EXECUTION,
            )
        )
        run.redact(entity_id, schema.redacted)
        run.result.add_source(Surface.INSTRUCTIONS, source, locator=display, ok=True, items=1)
        run.link(entity_id, PRECEDENCE_PROJECT, display)

    @staticmethod
    def _variables_schema(run: RunState, template: Path, bounds: Path) -> _Schema:
        sibling = template.with_name(f"{template.stem}.schema.json")
        if not os.path.lexists(sibling):
            return _Schema()
        source = "prompt-schema:project"
        display = run.ctx.display(sibling)
        real, error = resolve_within(sibling, bounds)
        data: bytes | None = None
        if real is not None:
            outcome = read_bounded(real, run.ctx.max_file_bytes)
            data, error = outcome.data, outcome.error_class
        parsed = _parse_schema(data) if data is not None else None
        if data is None or parsed is None:
            run.fail(source, display, error or "parse-error", "variables schema ignored")
            return _Schema(tags=("variables-schema-invalid",))
        strings = list(_json_strings(parsed))
        secret = any(looks_like_secret(s) for s in strings)
        hidden = any(has_hidden_unicode(s) for s in strings)
        withheld = secret or hidden or len(data) > MAX_EMBEDDED_SCHEMA_BYTES
        flags = (
            ("secret-like", secret),
            ("hidden-unicode", hidden),
            ("variables-schema-not-embedded", withheld),
        )
        run.result.add_source(Surface.INSTRUCTIONS, source, locator=display, ok=True)
        return _Schema(
            parsed=parsed,
            embedded=None if withheld else parsed,
            digest=bytes_digest(data),
            tags=tuple(tag for tag, on in flags if on),
            redacted=int(secret),
        )

    # ----------------------------------------------------------------------------------------- hooks

    def _emit_hooks(self, run: RunState, path: Path, *, scope: Scope, precedence: int, bounds: Path) -> None:
        if not os.path.lexists(path) or not run.first_visit(path):
            return
        display = run.ctx.display(path)
        source = f"claude-code-hooks:{scope}"
        real, error = resolve_within(path, bounds)
        data: bytes | None = None
        if real is not None:
            outcome = read_bounded(real, run.ctx.max_file_bytes)
            data, error = outcome.data, outcome.error_class
        if data is None:
            run.fail(source, display, error or "unreadable", "hooks not analysed")
            return
        try:
            settings = parse_structured(data, "json")
        except (ValueError, UnicodeDecodeError, RecursionError):
            run.fail(source, display, "parse-error", "hooks not analysed")
            return
        decls, problems = parse_hooks(settings)
        disabled = isinstance(settings, Mapping) and settings.get("disableAllHooks") is True
        emitted = 0
        for decl in decls:
            emitted += self._emit_hook(
                run, decl, display, scope=scope, precedence=precedence, disabled=disabled
            )
        for pointer, problem in problems:
            run.fail(source, locator(display, *pointer), problem, "hook not modelled")
        run.result.add_source(Surface.INSTRUCTIONS, source, locator=display, ok=True, items=emitted)

    def _emit_hook(
        self, run: RunState, decl: HookDecl, display: str, *, scope: Scope, precedence: int, disabled: bool
    ) -> int:
        where = locator(display, *decl.pointer)
        try:
            digest = bytes_digest(canonical_bytes(decl.payload()))
        except (UndigestableError, RecursionError):
            run.fail(f"claude-code-hooks:{scope}", where, "undigestable", "hook not modelled")
            return 0
        body = decl.body.encode("utf-8")
        event = _safe_label(decl.event)
        matcher = _safe_label(decl.matcher)
        secret = looks_like_secret(decl.body)
        flags = (
            (f"event:{event}", event is not None),
            ("secret-like", secret),
            ("hidden-unicode", has_hidden_unicode(decl.body)),
            ("disabled", disabled),
        )
        urls = [remote_display(url, origin_only=True) for url in _URL_IN_TEXT.findall(decl.body)]
        entity_id = run.ids.claim(
            "instr", display, "hook", event or "event", str(decl.group), str(decl.index)
        )
        run.result.entities.append(
            Instruction(
                id=entity_id,
                name=f"{event or 'hook'}:{matcher or '*'}",
                provenance=Provenance(
                    method=ClaimMethod.CONFIG, locator=where, collector=self.ref, observed_at=run.ctx.now
                ),
                tags=sorted(
                    {
                        _scope_tag(scope, precedence),
                        f"hook-type:{decl.hook_type}",
                        *(t for t, on in flags if on),
                    }
                ),
                instruction_kind=InstructionKind.HOOK,
                path=display,
                media_type="application/json",
                size=len(body),
                digest=digest,
                line_endings=line_endings(body),
                precedence=precedence,
                loads_remote=Claim.declared(
                    sorted({url for url, _ in urls}),
                    locator=where,
                    collector=self.ref,
                    observed_at=run.ctx.now,
                ),
                contains_secret_like=secret,
            )
        )
        run.redact(entity_id, sum(1 for _, dropped in urls if dropped))
        run.link(entity_id, precedence, where)
        return 1
