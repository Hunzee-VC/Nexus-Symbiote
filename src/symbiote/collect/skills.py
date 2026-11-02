"""``skills`` collector: Agent Skills packages, i.e. ``SKILL.md`` directories (``spec/collectors.md``).

A skill is identified by the OpenSSF model-signing compatible root of a ``dirmanifest/v1`` manifest over every
file in its directory, so changing ``SKILL.md``, a script or a reference file changes the skill's digest. A
directory that cannot be digested (it contains a symlink) yields no ``Skill`` at all: it fails closed
(ADR-0004) and the gap is recorded in coverage.

Per skill the collector emits the ``SKILL.md`` ``Instruction`` (kind ``skill-md``, the same fields as the
``instructions`` collector) and a ``Skill`` with the Agent Skills frontmatter validated against the
specification (name format, length and directory match; description and compatibility limits), capability hints
from ``allowed-tools``, bundled scripts with their interpreter, the MCP servers ``SKILL.md`` references, and lint
facts: hidden Unicode and secret-shaped text in any text file of the skill (flagged, never echoed).

Skill directories are searched below ``.claude/skills/``, ``skills/``, ``.agents/skills/``, ``.github/skills/``,
``.codex/skills/``, the ``skills/`` directory of every Claude Code plugin (a directory holding
``.claude-plugin/plugin.json``) and, with a home directory, ``~/.claude/skills/`` and ``~/.codex/skills/``.
"""

from __future__ import annotations

import os
import re
from collections import deque
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Final

from symbiote.collect._common import read_bounded
from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult
from symbiote.collect.instructions import (
    PRECEDENCE_PROJECT,
    PRECEDENCE_USER,
    FrontmatterSanitizer,
    InstructionInput,
    RunState,
    Scope,
    build_instruction,
    capability_tags,
    has_hidden_unicode,
    os_error_class,
    read_file_facts,
    record_walk,
    resolve_within,
    split_tools,
    symlink_tag,
)
from symbiote.digest import build_dir_manifest
from symbiote.digest.jcs import UndigestableError
from symbiote.model.common import Provenance, looks_like_secret
from symbiote.model.entities import DirManifest, ManifestItem, ScriptRef, Skill, SkillFrontmatter
from symbiote.model.enums import ClaimMethod, CollectorMode, InstructionKind, Surface

__all__ = [
    "MAX_COMPATIBILITY_LENGTH",
    "MAX_DESCRIPTION_LENGTH",
    "MAX_NAME_LENGTH",
    "NAME_PATTERN",
    "PROJECT_SKILL_ROOTS",
    "SCRIPT_INTERPRETERS",
    "SKILL_FILE",
    "TEXT_SCAN_MAX_BYTES",
    "USER_SKILL_ROOTS",
    "FileScan",
    "FoundSkill",
    "SkillsCollector",
    "find_skill_dirs",
    "referenced_servers",
    "scan_skill_files",
    "script_ref",
    "shebang_interpreter",
    "skill_frontmatter",
    "validate_frontmatter",
]

SKILL_FILE: Final = "SKILL.md"
PROJECT_SKILL_ROOTS: Final[tuple[str, ...]] = (
    ".claude/skills",
    "skills",
    ".agents/skills",
    ".github/skills",
    ".codex/skills",
)
USER_SKILL_ROOTS: Final[tuple[str, ...]] = (".claude/skills", ".codex/skills")
_PLUGIN_DIR: Final = ".claude-plugin"
_PLUGIN_MANIFEST: Final = "plugin.json"

#: Agent Skills ``name``: lowercase letters, digits and single hyphens, not leading or trailing.
NAME_PATTERN: Final = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
MAX_NAME_LENGTH: Final = 64
MAX_DESCRIPTION_LENGTH: Final = 1024
MAX_COMPATIBILITY_LENGTH: Final = 500
#: Files up to this size are scanned for secret-shaped and hidden text; larger ones mark the scan partial.
TEXT_SCAN_MAX_BYTES: Final = 1 << 20
#: Skill directories are searched this many levels below a root (``skills/<category>/<skill>/SKILL.md``).
MAX_SEARCH_DEPTH: Final = 4
MAX_SEARCH_DIRS: Final = 10_000

#: Interpreter by extension, used when there is no shebang.
SCRIPT_INTERPRETERS: Final[Mapping[str, str]] = {
    ".py": "python",
    ".sh": "sh",
    ".bash": "bash",
    ".zsh": "zsh",
    ".js": "node",
    ".mjs": "node",
    ".cjs": "node",
    ".ts": "node",
    ".rb": "ruby",
    ".ps1": "powershell",
    ".bat": "cmd",
    ".cmd": "cmd",
    ".pl": "perl",
    ".php": "php",
    ".lua": "lua",
}
_HEAD_BYTES: Final = 256
_SHEBANG: Final = re.compile(rb"#![ \t]*(?P<line>[^\r\n]*)")
_SAFE_PROGRAM: Final = re.compile(r"[A-Za-z0-9._+-]{1,64}")
_NATIVE_MAGIC: Final = (
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
)
_PE_SUFFIXES: Final = frozenset({".exe", ".dll"})
_MCP_REFERENCE: Final = re.compile(r"\bmcp__(?P<rest>[A-Za-z0-9_-]+)")
#: ``SKILL.md`` instruction tags that describe the skill as a whole.
_PROPAGATED_TAGS: Final = frozenset(
    {"hidden-unicode", "secret-like", "not-utf8", "too-large-for-analysis", "oversized-frontmatter"}
)

# --------------------------------------------------------------------------------------------- frontmatter


def validate_frontmatter(
    raw: Mapping[str, Any] | None, directory: str, problem: str | None = None
) -> tuple[list[str], bool]:
    """Agent Skills specification checks as tags, and whether ``name`` equals the directory name.

    ``name`` is required (``missing-name``) and must be lowercase letters, digits and single hyphens, at most
    64 characters (``invalid-name``); ``description`` is required (``missing-description``) and at most 1024
    characters (``description-too-long``); ``compatibility`` is at most 500 characters; ``metadata`` is a map.
    """
    if raw is None:
        return [problem or "missing-frontmatter", "missing-name", "missing-description"], False
    name, description = raw.get("name"), raw.get("description")
    compatibility = raw.get("compatibility")
    blank_name = name is None or (isinstance(name, str) and not name.strip())
    blank_description = description is None or (isinstance(description, str) and not description.strip())
    checks = (
        ("missing-name", blank_name),
        (
            "invalid-name",
            not blank_name
            and (
                not isinstance(name, str) or len(name) > MAX_NAME_LENGTH or not NAME_PATTERN.fullmatch(name)
            ),
        ),
        ("missing-description", blank_description),
        ("invalid-description", not blank_description and not isinstance(description, str)),
        (
            "description-too-long",
            isinstance(description, str) and len(description) > MAX_DESCRIPTION_LENGTH,
        ),
        ("invalid-compatibility", compatibility is not None and not isinstance(compatibility, str)),
        (
            "compatibility-too-long",
            isinstance(compatibility, str) and len(compatibility) > MAX_COMPATIBILITY_LENGTH,
        ),
        (
            "invalid-metadata",
            raw.get("metadata") is not None and not isinstance(raw.get("metadata"), Mapping),
        ),
    )
    return [tag for tag, failed in checks if failed], isinstance(name, str) and name == directory


def skill_frontmatter(raw: Mapping[str, Any] | None, sanitizer: FrontmatterSanitizer) -> SkillFrontmatter:
    """The stored frontmatter: sanitized strings, ``allowed-tools`` tokens and JSON-safe ``metadata`` values."""
    if raw is None:
        return SkillFrontmatter()
    metadata = raw.get("metadata")
    return SkillFrontmatter(
        name=sanitizer.text(raw.get("name")),
        description=sanitizer.text(raw.get("description")),
        license=sanitizer.text(raw.get("license")),
        compatibility=sanitizer.text(raw.get("compatibility")),
        allowed_tools=[t for t in split_tools(raw.get("allowed-tools")) if sanitizer.text(t) is not None],
        metadata=sanitizer.mapping(metadata) if isinstance(metadata, Mapping) else {},
    )


def referenced_servers(text: str) -> list[str]:
    """Sorted MCP server names from ``mcp__<server>__<tool>`` (or bare ``mcp__<server>``) references."""
    servers = {m.group("rest").split("__", 1)[0].strip("_-") for m in _MCP_REFERENCE.finditer(text)}
    return sorted(s for s in servers if s and len(s) <= 128 and not looks_like_secret(s))


# --------------------------------------------------------------------------------------------- files & scripts


def shebang_interpreter(head: bytes) -> str | None:
    """The program a ``#!`` line runs (``#!/usr/bin/env -S deno run`` ⇒ ``deno``), or ``None``."""
    match = _SHEBANG.match(head)
    words = match.group("line").decode("utf-8", errors="replace").split() if match else []
    if words and re.split(r"[\\/]", words[0])[-1] == "env":
        words = [w for w in words[1:] if not w.startswith("-") and "=" not in w]
    program = re.split(r"[\\/]", words[0])[-1] if words else ""
    return program if _SAFE_PROGRAM.fullmatch(program) else None


def script_ref(item: ManifestItem, head: bytes, executable: bool) -> ScriptRef | None:
    """A ``ScriptRef`` when the file is code the agent may run: a script extension, an executable bit, a
    ``#!`` line or a native binary (``interpreter="native"``); otherwise ``None``."""
    suffix = PurePosixPath(item.name).suffix.lower()
    native = head.startswith(_NATIVE_MAGIC) or (suffix in _PE_SUFFIXES and head.startswith(b"MZ"))
    if not (suffix in SCRIPT_INTERPRETERS or executable or native or head.startswith(b"#!")):
        return None
    interpreter = (
        shebang_interpreter(head) or SCRIPT_INTERPRETERS.get(suffix) or ("native" if native else None)
    )
    return ScriptRef(path=item.name, digest=item.digest, interpreter=interpreter)


@dataclass(slots=True)
class FileScan:
    """Facts over every file of a skill: scripts, and whether any text file is secret-shaped or carries hidden
    Unicode. ``partial`` means some file was too large or unreadable for the text scan."""

    scripts: list[ScriptRef] = field(default_factory=list)
    secret_like: bool = False
    hidden_unicode: bool = False
    partial: bool = False


def _head(path: Path) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(_HEAD_BYTES)
    except OSError:
        return b""


def _executable(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & 0o111)
    except OSError:
        return False


def scan_skill_files(skill_dir: Path, manifest: DirManifest) -> FileScan:
    """Scripts and text lint over the files of a digested skill (the manifest lists regular files only)."""
    scan = FileScan()
    for item in manifest.resources:
        path = skill_dir.joinpath(*item.name.split("/"))
        data = read_bounded(path, TEXT_SCAN_MAX_BYTES).data
        scan.partial = scan.partial or data is None
        if data is not None and b"\x00" not in data:
            text = data.decode("utf-8", errors="replace").removeprefix("\ufeff")
            scan.secret_like = scan.secret_like or looks_like_secret(text)
            scan.hidden_unicode = scan.hidden_unicode or has_hidden_unicode(text)
        script = script_ref(item, data[:_HEAD_BYTES] if data is not None else _head(path), _executable(path))
        if script is not None:
            scan.scripts.append(script)
    return scan


# --------------------------------------------------------------------------------------------- discovery


@dataclass(frozen=True, slots=True)
class FoundSkill:
    """A directory holding ``SKILL.md``; ``base`` is the scope base it was found under (repository or home)."""

    path: Path
    scope: Scope
    base: Path
    bounds: Path
    plugin: str | None = None


def find_skill_dirs(
    root: Path,
    *,
    bounds: Path,
    exclude: Collection[str] = (),
    max_depth: int = MAX_SEARCH_DEPTH,
    max_dirs: int = MAX_SEARCH_DIRS,
) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Directories below ``root`` that contain ``SKILL.md`` (breadth first; a skill is not searched further).

    Symlinked directories are followed only while they stay inside ``bounds`` (already resolved); escapes,
    broken links and unreadable directories come back as ``(path, error_class)`` so coverage can say so.
    """
    found: list[Path] = []
    problems: list[tuple[Path, str]] = []
    visited: set[Path] = set()
    queue: deque[tuple[Path, int]] = deque([(root, 0)])
    while queue:
        directory, depth = queue.popleft()
        real, error = resolve_within(directory, bounds, directory=True)
        if real is None:
            problems.append((directory, error or "unreadable"))
            continue
        if depth > 0 and os.path.lexists(directory / SKILL_FILE):
            found.append(directory)
            continue
        if real in visited or depth >= max_depth:
            continue
        visited.add(real)
        if len(visited) > max_dirs:
            problems.append((root, "truncated"))
            break
        try:
            children = sorted(
                (c for c in directory.iterdir() if c.name not in exclude and _searchable(c)),
                key=lambda p: p.name,
            )
        except OSError as exc:
            problems.append((directory, os_error_class(exc)))
            continue
        queue.extend((child, depth + 1) for child in children)
    return found, problems


def _searchable(entry: Path) -> bool:
    """Directories (symlinked ones too) and broken links, which are reported rather than skipped."""
    return entry.is_dir() or (entry.is_symlink() and not entry.exists())


@dataclass(frozen=True, slots=True)
class _SearchRoot:
    """A directory searched for skills, with the scope its skills belong to."""

    path: Path
    scope: Scope
    base: Path
    bounds: Path
    plugin: str | None = None


# --------------------------------------------------------------------------------------------- collector


class SkillsCollector(BaseCollector):
    """Agent Skills in the project, in Claude Code plugins and (with a home directory) in the user scope."""

    name = "skills"
    version = "0.1.0"
    surfaces = (Surface.INSTRUCTIONS,)
    mode = CollectorMode.DECLARED

    def __init__(
        self,
        *,
        project_roots: Sequence[str] = PROJECT_SKILL_ROOTS,
        user_roots: Sequence[str] = USER_SKILL_ROOTS,
    ) -> None:
        self.project_roots = tuple(project_roots)
        self.user_roots = tuple(user_roots)

    def detect(self, ctx: CollectContext) -> bool:
        del ctx
        return True  # no skills is a fact worth recording (queried, 0 items)

    def collect(self, ctx: CollectContext) -> CollectionResult:
        run = RunState(ctx, self.new_result())
        for found in self._discover(run):
            self._emit_skill(run, found)
        return run.finish(self.ref)

    # ----------------------------------------------------------------------------------------- discovery

    def _discover(self, run: RunState) -> list[FoundSkill]:
        ctx = run.ctx
        root = ctx.root.resolve()
        # plugin roots first: a plugin at the repository root shares ``skills/`` and keeps its plugin tag
        roots = [
            _SearchRoot(plugin_dir / "skills", "project", ctx.root, root, plugin)
            for plugin_dir, plugin in self._plugins(run)
        ]
        roots += [_SearchRoot(ctx.root / rel, "project", ctx.root, root) for rel in self.project_roots]
        if ctx.home is None:
            run.result.add_source(Surface.INSTRUCTIONS, "user-scope", ok=False, error_class="not-attempted")
        else:
            home = ctx.home.resolve()
            roots += [_SearchRoot(ctx.home / rel, "user", ctx.home, home) for rel in self.user_roots]
        found: dict[str, FoundSkill] = {}
        for search in roots:
            if not _searchable(search.path):
                continue
            if os.path.lexists(search.path / SKILL_FILE):
                run.result.warnings.append(
                    f"{ctx.display(search.path / SKILL_FILE)}: SKILL.md directly in a skills root is not a skill"
                )
            # vendor pruning does not apply inside skill roots: a skill may be named build, dist or venv
            dirs, problems = find_skill_dirs(search.path, bounds=search.bounds, exclude=(".git",))
            for path, error_class in problems:
                run.fail(f"skills:{search.scope}", ctx.display(path), error_class)
            for path in dirs:
                skill = FoundSkill(path, search.scope, search.base, search.bounds, search.plugin)
                found.setdefault(os.path.abspath(path), skill)
        rank = {"project": 0, "user": 1}
        return sorted(found.values(), key=lambda f: (rank[f.scope], ctx.display(f.path)))

    @staticmethod
    def _plugins(run: RunState) -> list[tuple[Path, str]]:
        """Claude Code plugin directories (holding ``.claude-plugin/plugin.json``) found by the repository walk."""
        ctx = run.ctx
        plugins: list[tuple[Path, str]] = []
        walked = 0
        for path in ctx.walk():
            walked += 1
            if path.name == _PLUGIN_MANIFEST and path.parent.name == _PLUGIN_DIR:
                plugin_dir = path.parent.parent
                plugins.append((plugin_dir, ctx.display(plugin_dir)))
                run.result.add_source(
                    Surface.INSTRUCTIONS, "claude-plugin:project", locator=ctx.display(path)
                )
        record_walk(run.result, walked, ctx.max_files)
        return sorted(plugins)

    # ----------------------------------------------------------------------------------------- emission

    def _emit_skill(self, run: RunState, found: FoundSkill) -> None:
        ctx = run.ctx
        display = ctx.display(found.path)
        source = f"skills:{found.scope}"
        try:
            manifest = build_dir_manifest(found.path)
        except UndigestableError as exc:
            run.fail(source, display, "undigestable", f"{exc.reason_class}; no Skill emitted (fail closed)")
            return
        except OSError as exc:
            run.fail(source, display, os_error_class(exc), "no Skill emitted")
            return
        except ValueError:  # e.g. UnicodeEncodeError from a file name that is not valid UTF-8
            run.fail(
                source,
                display,
                "non-utf8-name",
                "a file name is not valid UTF-8; no Skill emitted (fail closed)",
            )
            return
        md_path = found.path / SKILL_FILE
        md_display = ctx.display(md_path)
        real, error = resolve_within(md_path, found.bounds)
        facts, error = read_file_facts(real, ctx.max_file_bytes) if real is not None else (None, error)
        if facts is None:
            run.fail(source, md_display, error or "unreadable", "no Skill emitted")
            return
        if any(i.name == SKILL_FILE and i.digest != facts.digest for i in manifest.resources):
            run.result.warnings.append(f"{md_display}: changed while the skill was being digested")
        precedence = PRECEDENCE_USER if found.scope == "user" else PRECEDENCE_PROJECT
        link = symlink_tag(
            found.path, base=found.base, bounds=found.bounds, prefix="~/" if found.scope == "user" else ""
        )
        scope_tags = [
            f"scope:{found.scope}",
            *([f"plugin:{found.plugin}"] if found.plugin else []),
            *([link] if link else []),
        ]
        instruction_id = run.ids.claim("instr", md_display)
        spec = InstructionInput(
            instruction_id,
            SKILL_FILE,
            md_display,
            InstructionKind.SKILL_MD,
            precedence,
            frontmatter="strict",
            tags=tuple(scope_tags),
        )
        built = build_instruction(spec, facts, collector=self.ref, observed_at=ctx.now)
        run.result.entities.append(built.instruction)
        run.redact(instruction_id, built.redacted)

        raw = built.frontmatter
        analysed = built.text is not None
        problems, name_matches = (
            validate_frontmatter(raw, found.path.name, built.frontmatter_problem) if analysed else ([], False)
        )
        sanitizer = FrontmatterSanitizer()
        frontmatter = skill_frontmatter(raw, sanitizer)
        tools = split_tools(raw.get("allowed-tools")) if raw is not None else []
        files = scan_skill_files(found.path, manifest)
        lint = (
            ("hidden-unicode", files.hidden_unicode),
            ("secret-like", files.secret_like),
            ("secret-scan-partial", files.partial),
        )
        tags = {
            *scope_tags,
            *problems,
            *capability_tags(tools),
            *(t for t in built.instruction.tags if t in _PROPAGATED_TAGS),
            *(tag for tag, on in lint if on),
        }
        skill_id = run.ids.claim("skill", display)
        run.result.entities.append(
            Skill(
                id=skill_id,
                name=frontmatter.name or found.path.name,
                description=frontmatter.description,
                provenance=Provenance(
                    method=ClaimMethod.MANIFEST, locator=md_display, collector=self.ref, observed_at=ctx.now
                ),
                tags=sorted(tags),
                path=display,
                digest=manifest.root,
                manifest=manifest,
                skill_md_ref=instruction_id,
                frontmatter=frontmatter,
                scripts=files.scripts,
                referenced_servers=referenced_servers(built.text or ""),
                has_scripts=bool(files.scripts),
                name_matches_directory=name_matches,
            )
        )
        run.redact(skill_id, sanitizer.redacted)
        run.result.add_source(Surface.INSTRUCTIONS, source, locator=display, ok=True, items=1)
        run.link(skill_id, precedence, md_display)
