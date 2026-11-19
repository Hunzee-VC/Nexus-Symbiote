"""Confined CommonMark instruction-tree diff (`R1.1-10`).

Compares two directory trees (``BASE_TREE`` and ``HEAD_TREE``) through confined,
no-symlink regular-file reads and classifies security-relevant instruction changes into
five classes:

- ``tool_grant_changed``
- ``import_added``
- ``url_or_path_added``
- ``hidden_markup_added``
- ``scope_widened``

Prose rewording that introduces none of these five classes raises nothing. By default,
instruction text is withheld; when ``--show-text`` is passed, every line is redacted
and terminal-neutralized before output.
"""

from __future__ import annotations

import difflib
import json
import os
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import click
import yaml

from nexus_symbiote.core.hashing import open_regular_file
from nexus_symbiote.scanners.prompt import INSTRUCTION_FILES, NESTED_INSTRUCTION_NAMES
from nexus_symbiote.utils.markdown import commonmark_blocks, hidden_text
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import echo_line, json_text, neutralize

FORMAT = "nexus-symbiote/instruction-diff/v1"
MAX_FILES = 2000
MAX_DEPTH = 32
MAX_FILE_BYTES = 1024 * 1024

_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", ".tox"})
_FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)", re.DOTALL)
_URL_RE = re.compile(r"(?:https?|wss?|ftp|file)://[^\s<>\"'`\)\]]+", re.IGNORECASE)
_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:~/|/etc/|/var/|/usr/|/root/|/home/|\.\./)[^\s<>\"'`\)\],;]+"
)
_IMPORT_RE = re.compile(r"(?:^|(?<=\s))@((?:~/|\./|\.\./|[A-Za-z0-9_.-]+/)[A-Za-z0-9_./~-]+)")
_INCLUDE_RE = re.compile(r"<!--\s*include\s*:\s*([^\s>]+)\s*-->", re.IGNORECASE)
_TOOL_GRANT_RE = re.compile(
    r"\b(?:Bash|WebFetch|WebSearch|Write|Edit|MultiEdit|NotebookEdit|Task)\([^)]*\)"
    r"|\bmcp__[A-Za-z0-9_.-]+\b"
    r"|^\s*allowed[-_]tools\s*:\s*(.+)$",
    re.MULTILINE,
)
_HIDDEN_UNICODE_RE = re.compile(
    "[\u00ad\u034f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f"
    "\ufeff\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)


class InstructionChangeClass(StrEnum):
    TOOL_GRANT_CHANGED = "tool_grant_changed"
    IMPORT_ADDED = "import_added"
    URL_OR_PATH_ADDED = "url_or_path_added"
    HIDDEN_MARKUP_ADDED = "hidden_markup_added"
    SCOPE_WIDENED = "scope_widened"


@dataclass(frozen=True)
class InstructionChange:
    change_class: InstructionChangeClass
    file: str
    block_index: int | None
    summary: str
    text: str | None = None

    def to_dict(self, *, show_text: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "class": self.change_class.value,
            "file": self.file,
            "block_index": self.block_index,
            "summary": self.summary,
        }
        if show_text and self.text is not None:
            payload["text"] = self.text
        return payload


@dataclass(frozen=True)
class _ParsedInstruction:
    rel_path: str
    globs: frozenset[str]
    always_apply: bool
    tool_grants: frozenset[str]
    blocks: tuple[tuple[str, str], ...]
    hidden_signatures: tuple[str, ...]
    hidden_unicode_count: int


def _is_instruction_file(rel_posix: str, name: str) -> bool:
    if rel_posix in INSTRUCTION_FILES or name in NESTED_INSTRUCTION_NAMES:
        return True
    parts = Path(rel_posix).parts
    if len(parts) >= 3 and parts[0] == ".cursor" and parts[1] == "rules":
        return name.endswith((".mdc", ".md"))
    if len(parts) >= 3 and parts[0] == ".github" and parts[1] == "instructions":
        return name.endswith(".md")
    if len(parts) >= 3 and parts[0] == ".claude" and parts[1] in {"commands", "agents", "rules"}:
        return name.endswith(".md")
    return bool(name == "SKILL.md" and "skills" in parts)


def _sanitize_text(raw: str) -> str:
    return "\n".join(neutralize(redact_text(line)) for line in raw.splitlines())


def _normalize_glob(pattern: str) -> str:
    cleaned = pattern.strip()
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def _glob_list(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        items = [_normalize_glob(part) for part in value.split(",")]
        return frozenset(item for item in items if item)
    if isinstance(value, list):
        items = [_normalize_glob(str(item)) for item in value if isinstance(item, str)]
        return frozenset(item for item in items if item)
    return frozenset()


def _tool_list(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        return frozenset(part.strip() for part in re.split(r"[,\s]+", value) if part.strip())
    if isinstance(value, list):
        return frozenset(str(item).strip() for item in value if str(item).strip())
    return frozenset()


def _parse_frontmatter(content: str) -> tuple[dict[str, Any], str]:
    match = _FRONTMATTER_RE.match(content)
    if match is None:
        return {}, content
    raw_yaml = match.group(1)
    body = content[match.end() :]
    try:
        parsed = yaml.safe_load(raw_yaml)
    except yaml.YAMLError:
        return {}, body
    if not isinstance(parsed, dict):
        return {}, body
    return parsed, body


def _parse_instruction(rel_path: str, content: str) -> _ParsedInstruction:
    meta, body = _parse_frontmatter(content)
    globs: set[str] = set()
    for key in ("globs", "applyTo", "paths"):
        globs.update(_glob_list(meta.get(key)))
    always_apply = bool(meta.get("alwaysApply") is True)
    tool_grants: set[str] = set()
    for key in ("allowed-tools", "allowed_tools", "tools", "disallowedTools"):
        tool_grants.update(_tool_list(meta.get(key)))

    blocks = tuple(commonmark_blocks(body))
    hidden = hidden_text(body)
    comments: list[str] = []
    pos = 0
    while (start := body.find("<!--", pos)) != -1:
        end = body.find("-->", start + 4)
        stop = len(body) if end == -1 else end + 3
        comments.append(body[start:stop])
        pos = stop
    hidden_signatures = tuple(sorted([*comments, *hidden.definitions, *hidden.html]))
    hidden_unicode_count = len(_HIDDEN_UNICODE_RE.findall(content))
    return _ParsedInstruction(
        rel_path=rel_path,
        globs=frozenset(globs),
        always_apply=always_apply,
        tool_grants=frozenset(tool_grants),
        blocks=blocks,
        hidden_signatures=hidden_signatures,
        hidden_unicode_count=hidden_unicode_count,
    )


def _read_confined_tree(root: Path) -> dict[str, _ParsedInstruction]:
    if root.is_symlink() or not root.is_dir():
        raise click.ClickException(
            f"instruction tree '{neutralize(str(root))}' must be a non-symlink directory"
        )
    records: dict[str, _ParsedInstruction] = {}
    file_count = 0
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)
        if len(current.parts) - root_depth >= MAX_DEPTH:
            dirnames[:] = []
            continue
        dirnames[:] = sorted(
            d for d in dirnames if d not in _SKIP_DIRS and not (current / d).is_symlink()
        )
        for filename in sorted(filenames):
            candidate = current / filename
            if candidate.is_symlink():
                continue
            rel = candidate.relative_to(root).as_posix()
            if not _is_instruction_file(rel, filename):
                continue
            file_count += 1
            if file_count > MAX_FILES:
                raise click.ClickException(
                    f"instruction tree exceeds maximum file limit ({MAX_FILES})"
                )
            try:
                with open_regular_file(candidate) as stream:
                    raw_bytes = stream.read(MAX_FILE_BYTES + 1)
            except OSError:
                continue
            if len(raw_bytes) > MAX_FILE_BYTES:
                continue
            text = raw_bytes.decode("utf-8", errors="replace")
            records[rel] = _parse_instruction(rel, text)
    return records


def _glob_covered_by(candidate: str, existing: frozenset[str]) -> bool:
    if candidate in existing:
        return True
    if any(pat in {"*", "**", "**/*"} for pat in existing):
        return True
    for pat in existing:
        for suffix in ("/**/*", "/**"):
            if pat.endswith(suffix):
                prefix = pat[: -len(suffix)]
                if candidate == prefix or candidate.startswith(prefix + "/"):
                    return True
        if "/**/" in pat:
            prefix, tail = pat.split("/**/", 1)
            if (not prefix or candidate.startswith(prefix + "/")) and candidate.endswith(
                tail.lstrip("*")
            ):
                return True
    return False


def _extract_urls_and_paths(blocks: tuple[tuple[str, str], ...]) -> set[str]:
    found: set[str] = set()
    for _, content in blocks:
        found.update(_URL_RE.findall(content))
        found.update(_PATH_RE.findall(content))
    return found


def _extract_imports(blocks: tuple[tuple[str, str], ...]) -> set[str]:
    found: set[str] = set()
    for kind, content in blocks:
        if kind in {"fence", "indented"}:
            continue
        found.update(_IMPORT_RE.findall(content))
        found.update(_INCLUDE_RE.findall(content))
    return found


def _extract_inline_tool_grants(blocks: tuple[tuple[str, str], ...]) -> set[str]:
    found: set[str] = set()
    for _, content in blocks:
        for match in _TOOL_GRANT_RE.finditer(content):
            if match.group(1) is not None:
                found.update(_tool_list(match.group(1)))
            else:
                found.add(match.group(0).strip())
    return found


def _changed_block_indices(
    base_blocks: tuple[tuple[str, str], ...],
    head_blocks: tuple[tuple[str, str], ...],
) -> list[int]:
    base_norm = [re.sub(r"\s+", " ", content).strip() for _, content in base_blocks]
    head_norm = [re.sub(r"\s+", " ", content).strip() for _, content in head_blocks]
    matcher = difflib.SequenceMatcher(None, base_norm, head_norm)
    indices: list[int] = []
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in {"replace", "insert"}:
            indices.extend(range(j1, j2))
    return indices


def _first_matching_block(
    blocks: tuple[tuple[str, str], ...],
    candidate_indices: list[int],
    needle: str,
) -> int | None:
    for idx in candidate_indices:
        if needle in blocks[idx][1]:
            return idx
    for idx, (_, content) in enumerate(blocks):
        if needle in content:
            return idx
    return candidate_indices[0] if candidate_indices else None


def diff_instruction_trees(
    base_tree: Path,
    head_tree: Path,
    *,
    show_text: bool = False,
) -> dict[str, Any]:
    """Compare instruction files across ``base_tree`` and ``head_tree``."""
    base_records = _read_confined_tree(base_tree)
    head_records = _read_confined_tree(head_tree)
    changes: list[InstructionChange] = []

    for rel_path in sorted(head_records):
        head = head_records[rel_path]
        base = base_records.get(rel_path)
        safe_path = neutralize(rel_path)
        base_blocks = base.blocks if base is not None else ()
        changed_indices = _changed_block_indices(base_blocks, head.blocks)

        # 1. scope_widened
        if base is None:
            if head.always_apply or any(g in {"*", "**", "**/*"} for g in head.globs):
                changes.append(
                    InstructionChange(
                        change_class=InstructionChangeClass.SCOPE_WIDENED,
                        file=safe_path,
                        block_index=None,
                        summary=f"new instruction file '{safe_path}' activates broadly",
                    )
                )
        else:
            if not base.always_apply and head.always_apply:
                changes.append(
                    InstructionChange(
                        change_class=InstructionChangeClass.SCOPE_WIDENED,
                        file=safe_path,
                        block_index=None,
                        summary=f"'{safe_path}' changed alwaysApply from false to true",
                    )
                )
            widened_globs = sorted(g for g in head.globs if not _glob_covered_by(g, base.globs))
            if widened_globs:
                changes.append(
                    InstructionChange(
                        change_class=InstructionChangeClass.SCOPE_WIDENED,
                        file=safe_path,
                        block_index=None,
                        summary=(
                            f"'{safe_path}' widened activation globs: "
                            + neutralize(", ".join(widened_globs))
                        ),
                    )
                )

        # 2. tool_grant_changed
        base_fm_tools = base.tool_grants if base is not None else frozenset()
        if base_fm_tools != head.tool_grants:
            changes.append(
                InstructionChange(
                    change_class=InstructionChangeClass.TOOL_GRANT_CHANGED,
                    file=safe_path,
                    block_index=None,
                    summary=f"'{safe_path}' front-matter tool grants changed",
                )
            )
        base_inline_tools = _extract_inline_tool_grants(base_blocks)
        head_inline_tools = _extract_inline_tool_grants(head.blocks)
        if base_inline_tools != head_inline_tools:
            diff_tools = sorted(base_inline_tools ^ head_inline_tools)
            blk = (
                _first_matching_block(head.blocks, changed_indices, diff_tools[0])
                if diff_tools
                else None
            )
            txt = _sanitize_text(head.blocks[blk][1]) if (show_text and blk is not None) else None
            changes.append(
                InstructionChange(
                    change_class=InstructionChangeClass.TOOL_GRANT_CHANGED,
                    file=safe_path,
                    block_index=blk,
                    summary=f"'{safe_path}' inline tool grants changed",
                    text=txt,
                )
            )

        # 3. import_added
        base_imports = _extract_imports(base_blocks)
        head_imports = _extract_imports(head.blocks)
        for imp in sorted(head_imports - base_imports):
            blk = _first_matching_block(head.blocks, changed_indices, imp)
            txt = _sanitize_text(head.blocks[blk][1]) if (show_text and blk is not None) else None
            changes.append(
                InstructionChange(
                    change_class=InstructionChangeClass.IMPORT_ADDED,
                    file=safe_path,
                    block_index=blk,
                    summary=f"'{safe_path}' added import '{neutralize(redact_text(imp))}'",
                    text=txt,
                )
            )

        # 4. url_or_path_added
        base_refs = _extract_urls_and_paths(base_blocks)
        head_refs = _extract_urls_and_paths(head.blocks)
        for ref in sorted(head_refs - base_refs):
            blk = _first_matching_block(head.blocks, changed_indices, ref)
            txt = _sanitize_text(head.blocks[blk][1]) if (show_text and blk is not None) else None
            changes.append(
                InstructionChange(
                    change_class=InstructionChangeClass.URL_OR_PATH_ADDED,
                    file=safe_path,
                    block_index=blk,
                    summary=f"'{safe_path}' added URL or path '{neutralize(redact_text(ref))}'",
                    text=txt,
                )
            )

        # 5. hidden_markup_added
        base_hidden = list(base.hidden_signatures) if base is not None else []
        head_hidden = list(head.hidden_signatures)
        base_uni = base.hidden_unicode_count if base is not None else 0
        new_hidden_markup = len(head_hidden) > len(base_hidden) or any(
            item not in base_hidden for item in head_hidden
        )
        if new_hidden_markup or head.hidden_unicode_count > base_uni:
            blk = changed_indices[0] if changed_indices else None
            txt = _sanitize_text(head.blocks[blk][1]) if (show_text and blk is not None) else None
            changes.append(
                InstructionChange(
                    change_class=InstructionChangeClass.HIDDEN_MARKUP_ADDED,
                    file=safe_path,
                    block_index=blk,
                    summary=f"'{safe_path}' added hidden markup or invisible Unicode",
                    text=txt,
                )
            )

    by_class: dict[str, int] = {}
    for item in changes:
        by_class[item.change_class.value] = by_class.get(item.change_class.value, 0) + 1

    return {
        "format": FORMAT,
        "base_tree": neutralize(base_tree.name or str(base_tree)),
        "head_tree": neutralize(head_tree.name or str(head_tree)),
        "files_scanned": {"base": len(base_records), "head": len(head_records)},
        "changes": [c.to_dict(show_text=show_text) for c in changes],
        "summary": {"total_changes": len(changes), "by_class": by_class},
    }


@click.command("diff-instructions")
@click.argument(
    "base_tree",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.argument(
    "head_tree",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--show-text",
    is_flag=True,
    help="Include redacted, terminal-neutralized changed block text (withheld by default).",
)
@click.option("--json-output", is_flag=True, help="Print the instruction diff as JSON.")
@click.option(
    "--fail-on-change",
    is_flag=True,
    help="Exit with status 1 if any security-relevant instruction change is detected.",
)
def diff_instructions(
    base_tree: Path,
    head_tree: Path,
    show_text: bool,
    json_output: bool,
    fail_on_change: bool,
) -> None:
    """Compare instruction files between BASE_TREE and HEAD_TREE for security-relevant changes."""
    report = diff_instruction_trees(base_tree, head_tree, show_text=show_text)
    if json_output:
        click.echo(json_text(json.dumps(report, indent=2)))
    else:
        total = report["summary"]["total_changes"]
        echo_line(
            "Instruction diff: ",
            f"{total} change(s) across {report['files_scanned']['head']} head file(s).",
        )
        for item in report["changes"]:
            loc = f" [block {item['block_index']}]" if item["block_index"] is not None else ""
            echo_line(f"  [{item['class']}]{loc} ", item["summary"])
            if show_text and item.get("text"):
                for line in str(item["text"]).splitlines():
                    echo_line("    | ", line)
    if fail_on_change and report["summary"]["total_changes"] > 0:
        raise click.exceptions.Exit(1)


def register_instruction_diff_commands(main: click.Group) -> None:
    main.add_command(diff_instructions)
