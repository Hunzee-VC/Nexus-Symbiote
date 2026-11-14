"""IDE coding agent configuration scanner.

Discovers configurations for IDE-integrated AI coding agents:
  - Claude Code (.claude/, CLAUDE.md, .claude/settings.json)
  - Codex (.codex/, codex.md, .codex/config.toml)
  - Cursor (.cursor/, .cursorrules, .cursor/mcp.json, .cursor/hooks.json)
  - Gemini CLI (GEMINI.md, .gemini/settings.json)
  - Antigravity (.antigravity/)
  - XAI IDE agent configs
  - Windsurf (.windsurfrules, .windsurf/)
  - Cline (.clinerules, .cline/)
  - GitHub Copilot (.github/copilot-instructions.md)

Markers and settings are read at fixed paths beneath the project root; the tree is
walked only for the `.claude` settings of subdirectories. Every settings file a record
recognizes, JSON or TOML, is digested whole, so a changed value changes the record,
except, without the operator key, a value the redaction withholds from a file digested
after it; only some values are interpreted. Instruction files and directories among
the markers are inventoried by the `prompt` collector.
"""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import canonical_json, hash_canonical, parse_json_strict
from nexus_symbiote.core.models import IDEAgentComponent, RiskAssessment, VerifiedExtensionComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.scanners.source_binding import BindingError, value_binding
from nexus_symbiote.utils.confined import ConfinedCollection, fold_name
from nexus_symbiote.utils.jsonc import strip_jsonc
from nexus_symbiote.utils.secrets import redact_text

IDE_AGENT_CONFIGS: dict[str, dict[str, Any]] = {
    "claude-code": {
        "markers": [
            ".claude/settings.json",
            ".claude/settings.local.json",
            "CLAUDE.md",
            ".claude/CLAUDE.md",
            "CLAUDE.local.md",
            ".claude/commands",
            ".claude/skills",
            ".claude/agents",
            ".claude/rules",
            ".claude-plugin/plugin.json",
            ".claude-plugin/marketplace.json",
        ],
        "mcp_config": [".claude/mcp.json", ".mcp.json"],
    },
    "codex": {
        "markers": [
            ".codex/config.toml",
            ".codex/config.json",
            "codex.md",
            "CODEX.md",
            ".codex/instructions.md",
        ],
        "mcp_config": [],
    },
    "cursor": {
        "markers": [
            ".cursorrules",
            ".cursor/rules",
            ".cursor/settings.json",
            ".cursor/cli.json",
            ".cursor/hooks.json",
        ],
        "mcp_config": [".cursor/mcp.json"],
    },
    "gemini": {
        "markers": ["GEMINI.md", ".gemini/settings.json"],
        "mcp_config": [],
    },
    "antigravity": {
        "markers": [
            ".antigravity/config.json",
            ".antigravity/settings.json",
        ],
        "mcp_config": [],
    },
    "xai": {
        "markers": [
            ".xai/config.json",
            ".xai/settings.json",
        ],
        "mcp_config": [],
    },
    "windsurf": {
        "markers": [
            ".windsurfrules",
            ".windsurf/settings.json",
            ".windsurf/rules",
        ],
        "mcp_config": [".windsurf/mcp.json"],
    },
    "cline": {
        "markers": [
            ".clinerules",
            ".cline/settings.json",
        ],
        "mcp_config": [".cline/mcp.json"],
    },
    "copilot": {
        "markers": [
            ".github/copilot-instructions.md",
            ".github/copilot-extensions.json",
            ".github/instructions",
        ],
        "mcp_config": [],
    },
}
_CODEX_SPELLINGS = frozenset({"codex.md", "CODEX.md"})
CLAUDE_SETTINGS = [".claude/settings.json", ".claude/settings.local.json"]
_FOLDED_SETTINGS_NAMES = {
    fold_name(name): name for name in ("settings.json", "settings.local.json")
}
# A Claude Code plugin repository's own manifests; its root hooks/hooks.json is the
# plugin's hook configuration only when one of them is present.
CLAUDE_PLUGIN_MANIFESTS = [".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"]
CLAUDE_PLUGIN_HOOKS = "hooks/hooks.json"
# The `agent.permissionMode` key read for these hosts is a project convention that
# vendor documentation does not describe; the files are read for it, and digested.
_AGENT_MODE_SETTINGS = {
    "cursor": [".cursor/settings.json"],
    "windsurf": [".windsurf/settings.json"],
    "cline": [".cline/settings.json"],
    "codex": [".codex/config.json"],
}
# Settings files whose values no record interprets. Each is read as editors read JSON,
# with comments and trailing commas, only to be digested.
_DIGESTED_SETTINGS = {
    "cursor": [".cursor/cli.json"],
    "antigravity": [".antigravity/config.json", ".antigravity/settings.json"],
    "xai": [".xai/config.json", ".xai/settings.json"],
    "copilot": [".github/copilot-extensions.json"],
}
# The keyed binding of every settings file an IDE record digests in `settings_hashes`.
SETTINGS_VALUE_BINDING_PROFILE = "nexus-symbiote/ide-settings-values/v1"
CODEX_CONFIG = ".codex/config.toml"
CURSOR_HOOKS = ".cursor/hooks.json"
GEMINI_SETTINGS = ".gemini/settings.json"
# Digested after the redaction with or without the operator key, so no unkeyed digest
# covers a value it withholds, such as the environment of an MCP server that Codex
# settings declare. The other files keep the digest of the file as read that existing
# baselines record.
_REDACTED_DIGESTS = frozenset(
    {CODEX_CONFIG, *(path for paths in _DIGESTED_SETTINGS.values() for path in paths)}
)
_PERMISSION_MODES = frozenset(
    {
        "default",
        "manual",
        "plan",
        "acceptEdits",
        "bypassPermissions",
        "dontAsk",
        "ask",
        "auto",
        "read-only",
        "workspace-write",
        "full-access",
        "danger-full-access",
        "untrusted",
        "on-failure",
        "on-request",
        "never",
        "always",
    }
)
_MAX_SETTINGS_DEPTH = 64
# Tools whose unscoped grant gives a whole capability class, by Claude Code's names.
_SCOPED_TOOL_CLASSES = {
    "bash": "shell commands",
    "edit": "file edits",
    "write": "file edits",
    "multiedit": "file edits",
    "notebookedit": "file edits",
    "read": "file reads",
    "webfetch": "web fetches",
}
# A specifier made only of these characters names everything: Bash(*), Bash(:*),
# Edit(//**), Read(~/**), Edit(./**).
_WILDCARD_SPECIFIER = re.compile(r"[\s*:/~.]*")
_EXTENSION_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z0-9][a-zA-Z0-9._-]*")


def _broad_grants(allowed: list[str]) -> list[str]:
    """Capability classes that the allow list grants without a narrowing specifier."""
    classes: set[str] = set()
    for value in allowed:
        rule = value.strip()
        if rule == "*":
            classes.add("every tool")
            continue
        tool, opened, rest = rule.partition("(")
        tool = tool.strip()
        specifier = None
        if opened:
            if not rest.endswith(")"):
                continue
            specifier = rest[:-1].strip()
        key = tool.lower()
        if key.startswith("mcp__"):
            server = key.removeprefix("mcp__")
            whole_server = "__" not in server or server.endswith("__*")
            if server in {"", "*"} or (whole_server and specifier in (None, "", "*")):
                classes.add("MCP server tools")
            continue
        broad = specifier is None or bool(_WILDCARD_SPECIFIER.fullmatch(specifier))
        if key == "webfetch" and specifier is not None:
            broad |= specifier.replace(" ", "") in {"domain:*", "domain:"}
        if key == "read" and specifier is None:
            # A bare Read grant covers the working directory, as reading does by default.
            continue
        if broad and key in _SCOPED_TOOL_CLASSES:
            classes.add(_SCOPED_TOOL_CLASSES[key])
    return sorted(classes)


# Text is redacted piece by piece between these shell operators, which are kept, so a
# URL ends at the first of them: a command, a host or an operator glued to a URL or to a
# credential assignment stays covered while the URL's path and the value are withheld.
# A piece is also cut before each URL scheme after its first one, so every URL keeps its
# own host whatever separates it from the text before it.
_SHELL_OPERATORS = re.compile(r"([;|&$`(){}<>\n]+)")
_SCHEME_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")
# A URL authority that URL parsers read differently: urlsplit takes the host after the
# last "@", WHATWG parsers end the authority at a backslash and, for special schemes,
# skip any number of slashes, so the redaction could keep a host the client never uses.
_URL_AUTHORITY = re.compile(r"(?<![a-zA-Z0-9+.-])([a-zA-Z0-9+.-]+)://([^/?#\s\"'<>]*)")
_SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp"})


class AmbiguousURLError(ValueError):
    """A settings URL whose host the redaction cannot keep as clients read it."""


def _ambiguous_authority(text: str) -> bool:
    return any(
        "\\" in authority or (not authority and scheme.lower() in _SPECIAL_SCHEMES)
        for scheme, authority in _URL_AUTHORITY.findall(text)
    )


def _url_pieces(text: str) -> list[str]:
    """``text`` cut before each URL scheme, in linear time.

    Cutting before the first scheme too keeps the host of a URL assigned to a
    credential-named option (``--token-url=URL``) out of the assignment the redaction
    removes whole; userinfo, path and query stay redacted.
    """
    cuts: list[int] = []
    floor = 0
    index = text.find("://")
    while index != -1:
        start = index
        while start > floor and text[start - 1] in _SCHEME_CHARACTERS:
            start -= 1
        while start < index and not ("a" <= text[start].lower() <= "z"):
            start += 1
        if start < index:
            cuts.append(start)
        floor = index + 3
        index = text.find("://", floor)
    bounds = [0, *cuts, len(text)]
    parts = [text[begin:end] for begin, end in zip(bounds, bounds[1:], strict=False)]
    return [part for part in parts if part] or [text]


def _projected_text(value: str, *, unkeyed: bool) -> str:
    pieces = _SHELL_OPERATORS.split(value)
    for index in range(0, len(pieces), 2):
        parts = _url_pieces(pieces[index])
        if unkeyed and any(_ambiguous_authority(part) for part in parts):
            raise AmbiguousURLError("a URL authority is ambiguous")
        # A white space ends a redacted URL, so no host can absorb the next part's text.
        pieces[index] = " ".join(redact_text(part) for part in parts)
    return "".join(pieces)


def _projection(value: Any, depth: int = 0, *, env: bool = False, unkeyed: bool = True) -> Any:
    """Settings as a redacted `settings_hashes` digest covers them.

    The standard redaction is applied to the text between shell operators, cut again
    before each URL scheme, and
    environment variables keep their names only, so the digest cannot confirm a guess
    of a value the redaction removes, and does not change with one; only the keyed
    binding covers those values. ``unkeyed`` raises ``AmbiguousURLError`` for a URL
    whose authority URL parsers read differently, since its redacted origin could hide a
    change of host that no keyed binding covers.
    """
    if depth > _MAX_SETTINGS_DEPTH:
        raise ValueError("settings nested too deeply")
    if isinstance(value, dict):
        if env:
            return sorted(_projected_text(str(key), unkeyed=unkeyed) for key in value)
        projected: dict[str, Any] = {}
        merged: dict[str, list[Any]] = {}
        for key, item in value.items():
            text = _projected_text(str(key), unkeyed=unkeyed)
            entry = _projection(item, depth + 1, env=key == "env", unkeyed=unkeyed)
            merged.setdefault(text, []).append(entry)
            projected[text] = entry
        # Keys the redaction makes equal keep every value, in canonical order, so no
        # value the redaction leaves in place drops out of the digest.
        for text, entries in merged.items():
            if len(entries) > 1:
                projected[text] = sorted(entries, key=canonical_json)
        return projected
    if isinstance(value, list):
        return [_projection(item, depth + 1, unkeyed=unkeyed) for item in value]
    if isinstance(value, str):
        return _projected_text(value, unkeyed=unkeyed)
    return value


_FETCH_EXEC = re.compile(
    r"(?:curl|wget|iwr|invoke-webrequest)\b[^|\n;]*\|\s*(?:ba|z|da)?sh\b"
    r"|base64\s+(?:-d|--decode)\b[^|\n]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
_HOOK_URL = re.compile(r"https?://", re.IGNORECASE)
_SEVERITY_RANK = {severity: index for index, severity in enumerate(RiskSeverity)}


def _command_severity(command: str) -> RiskSeverity:
    """How dangerous a hook command is, without keeping its text."""
    if _FETCH_EXEC.search(command):
        return RiskSeverity.CRITICAL
    if _HOOK_URL.search(command):
        return RiskSeverity.HIGH
    return RiskSeverity.MEDIUM


def _worse(current: RiskSeverity | None, candidate: RiskSeverity | None) -> RiskSeverity | None:
    if candidate is None:
        return current
    if current is None or _SEVERITY_RANK[candidate] < _SEVERITY_RANK[current]:
        return candidate
    return current


def _hook_command_severity(value: Any, depth: int = 0) -> RiskSeverity | None:
    """The strongest severity among hook commands. The commands themselves are not returned."""
    if depth > _MAX_SETTINGS_DEPTH:
        raise ValueError("settings nested too deeply")
    found: RiskSeverity | None = None
    if isinstance(value, dict):
        command = value.get("command")
        if isinstance(command, str):
            found = _command_severity(command)
        for item in value.values():
            found = _worse(found, _hook_command_severity(item, depth + 1))
    elif isinstance(value, list):
        for item in value:
            found = _worse(found, _hook_command_severity(item, depth + 1))
    return found


def _hook_detail(count: int, severity: RiskSeverity, ide: str) -> str:
    base = (
        f"IDE agent '{ide}' declares {count} hook command(s) that run automatically on agent events"
    )
    if severity is RiskSeverity.CRITICAL:
        return base + ", including a command that downloads and executes a script."
    if severity is RiskSeverity.HIGH:
        return base + ", including a command that contacts a network address."
    return base + "."


def _hook_commands(value: Any, depth: int = 0) -> int:
    if depth > _MAX_SETTINGS_DEPTH:
        raise ValueError("settings nested too deeply")
    if isinstance(value, dict):
        own = 1 if isinstance(value.get("command"), str) else 0
        return own + sum(_hook_commands(item, depth + 1) for item in value.values())
    if isinstance(value, list):
        return sum(_hook_commands(item, depth + 1) for item in value)
    return 0


def _declared_hooks(hooks: object) -> dict[str, int]:
    """Count handlers per event for the reader; the settings digest is what binds them.

    Commands may carry secrets and stay unrecorded. A shape this does not know
    is left to the digest rather than guessed at.
    """
    counts: dict[str, int] = {}
    if not isinstance(hooks, dict):
        return counts
    for event, matchers in hooks.items():
        if not isinstance(event, str) or not isinstance(matchers, list):
            continue
        handlers = [matcher.get("hooks") for matcher in matchers if isinstance(matcher, dict)]
        counts[redact_text(event)] = sum(len(h) for h in handlers if isinstance(h, list))
    return counts


def _count(value: Any) -> int:
    return len(value) if isinstance(value, (list, dict)) else 0


def _starting_mode_risk(ide_type: str, mode: str | None) -> RiskAssessment | None:
    """The finding for a declared starting mode that skips approval prompts."""
    if mode == "bypassPermissions":
        return RiskAssessment(
            severity=RiskSeverity.HIGH,
            category="permission_scope",
            detail=(
                f"IDE agent '{ide_type}' declares a starting mode that skips "
                "permission prompts; effective approval remains unverified."
            ),
            recommendation=(
                "Remove the project-level bypass mode, or confine the agent to "
                "an isolated environment with no credentials it should not use."
            ),
        )
    if mode == "acceptEdits":
        return RiskAssessment(
            severity=RiskSeverity.MEDIUM,
            category="permission_scope",
            detail=(
                f"IDE agent '{ide_type}' declares a starting mode that accepts file edits "
                "without a prompt; effective approval remains unverified."
            ),
            recommendation=(
                "Use the default or plan mode in project settings; grant narrow allow "
                "rules instead."
            ),
        )
    return None


class IDEAgentScanner(Scanner):
    name = "ide_agents"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(project_root, result) as files:
            for ide_type, config in IDE_AGENT_CONFIGS.items():
                found: list[str] = []
                for marker in config["markers"]:
                    evidence = self._marker(files, marker)
                    if evidence is not None:
                        found.append(marker)
                        result.surfaces_scanned.append(evidence)
                if found:
                    result.components.append(
                        self._agent(files, result, ide_type, found, config["mcp_config"])
                    )
            # A host started in a subdirectory, such as one package of a monorepo, reads
            # that directory's .claude settings as its project settings, and on a
            # case-insensitive file system those of another spelling of either name.
            nested: dict[str, list[str]] = {}
            links: list[Path] = []
            for path in files.iter_files(directory_links=links):
                if len(path.parts) <= 2 or fold_name(path.parts[-2]) != ".claude":
                    continue
                name = _FOLDED_SETTINGS_NAMES.get(fold_name(path.name))
                if name is None:
                    continue
                if path.parts[-2] != ".claude" or path.name != name:
                    files.report_case_variant(path, Path(*path.parts[:-2], ".claude", name))
                    continue
                nested.setdefault(Path(*path.parts[:-2]).as_posix(), []).append(path.as_posix())
            for link in links:
                self._linked_settings(files, link, nested)
            for base, paths in sorted(nested.items()):
                result.surfaces_scanned.extend(sorted(paths))
                result.components.append(
                    self._agent(files, result, "claude-code", sorted(paths), [], base=base)
                )
            self._scan_extensions(files, result)
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("ide-agents (no IDE agent configs found)")
        return result

    def _agent(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        ide_type: str,
        found: list[str],
        mcp_config: list[str],
        *,
        base: str = "",
    ) -> IDEAgentComponent:
        """One agent's record; ``base`` names the subdirectory of nested settings."""
        risks: list[RiskAssessment] = []
        properties: dict[str, Any] = {"settings_directory": base} if base else {}
        # Every settings file the record reads, as read; each is digested.
        documents: dict[str, dict[str, Any]] = {}
        if ide_type == "claude-code":
            settings = self._claude_settings(result, risks, properties, documents, base=base)
        else:
            settings = self._agent_mode_settings(ide_type, result, documents)
        if ide_type == "codex":
            self._codex_settings(files, result, risks, properties, documents)
        elif ide_type == "gemini":
            self._gemini_settings(files, result, documents)
        elif ide_type == "cursor":
            self._cursor_hooks(files, result, risks, properties, documents)
        for relative in _DIGESTED_SETTINGS.get(ide_type, []):
            data = self._read_jsonc(files, relative, result)
            if data is not None:
                documents[relative] = data
        self._bind_settings(ide_type, documents, result, risks, properties)
        mode = self._extract_permission_mode(settings or {}, ide_type, result)
        if ide_type == "codex" and mode is None:
            mode = properties.get("approval_policy")
        broad = self._broad_permissions(settings or {}, ide_type, result)
        if broad:
            risks.insert(
                0,
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="permission_scope",
                    detail=(
                        f"IDE agent '{ide_type}' declares unscoped tool allowances "
                        f"({', '.join(broad)}); effective approval remains unverified."
                    ),
                    recommendation=(
                        "Review deny/ask rules, workspace trust, user and managed "
                        "settings, and runtime controls; enforce resource-scoped authority."
                    ),
                ),
            )
        starting_mode = _starting_mode_risk(ide_type, mode)
        if starting_mode is not None:
            risks.insert(0, starting_mode)
        layered = (
            ide_type == "claude-code" and {"CLAUDE.md", ".claude/CLAUDE.md"}.issubset(found)
        ) or (ide_type == "cursor" and {".cursorrules", ".cursor/rules"}.issubset(found))
        if layered:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="instruction_layering",
                    detail=f"IDE agent '{ide_type}' has multiple declared instruction locations.",
                    recommendation="Document loading order, modification authority and approved digests.",
                )
            )
        mcp_configs = []
        for config_name in mcp_config:
            data = self._read_mapping(Path(config_name), result)
            if data is not None:
                mcp_configs.append(config_name)
        # Markers and settings read through an in-root symlink, with the file that held them.
        links = {
            path: target
            for path in (*found, *documents)
            if (target := files.link_target(path)) is not None
        }
        if links:
            properties["symlink_targets"] = dict(sorted(links.items()))
        # Configuration locators are not component references. The MCP
        # collector binds actual client/server components separately.
        return IDEAgentComponent(
            bom_ref=f"ide-agent:{ide_type}" + (f"@{base}" if base else ""),
            name=ide_type + (f" ({base})" if base else ""),
            ide_type=ide_type,
            config_files=found,
            mcp_server_refs=[],
            permission_mode=mode,
            source_path=found[0],
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
            properties={
                "collection_mode": "static-project-configuration",
                "mcp_config_paths": mcp_configs,
                "permission_evidence": "declaration-only",
                "effective_authorization_verified": False,
                "permission_policy_limitations": [
                    (
                        "User and managed settings, workspace trust, per-session "
                        "flags and runtime controls were not observed."
                    ),
                    "Deny and ask rules may narrow declared allow rules.",
                    (
                        "Project/local starting-mode declarations may be ignored "
                        "by the host or version."
                    ),
                ],
                **properties,
            },
        )

    @staticmethod
    def _linked_settings(
        files: ConfinedCollection, link: Path, nested: dict[str, list[str]]
    ) -> None:
        """Nested settings below a ``.claude`` directory symlink, which the walk skips.

        The walk covers the target under its own name, where the settings files are not
        recognised, so they are looked up through the link as a host started there would.
        """
        if len(link.parts) < 2 or fold_name(link.name) != ".claude":
            return
        for name in _FOLDED_SETTINGS_NAMES.values():
            path = link / name
            if files.regular_file(path) is None:
                # Records a refused link, or another spelling below the link.
                files.read_bytes(path, missing_ok=True)
            elif link.name != ".claude":
                files.report_case_variant(path, link.with_name(".claude") / name)
            else:
                nested.setdefault(link.parent.as_posix(), []).append(path.as_posix())

    @staticmethod
    def _marker(files: ConfinedCollection, marker: str) -> str | None:
        """The path that shows a marker exists: the file, or a file in the directory."""
        if files.is_directory(marker):
            for path in files.iter_files(marker):
                return path.as_posix()
            return None
        variants = _CODEX_SPELLINGS if marker in _CODEX_SPELLINGS else ()
        if files.read_bytes(marker, missing_ok=True, variants_read=variants) is None:
            return None
        return marker

    def _claude_settings(
        self,
        result: ScanResult,
        risks: list[RiskAssessment],
        properties: dict[str, Any],
        documents: dict[str, dict[str, Any]],
        *,
        base: str = "",
    ) -> dict[str, Any] | None:
        """Merge permission layers and count what the settings and plugin files declare.

        Every file is bound by its digest, so a changed hook, rule, helper, plugin or
        marketplace changes the record. The merged summary does not resolve effective
        permissions across trust, user or managed policy, flags or product versions.
        """
        merged: dict[str, Any] = {}
        for relative in (f"{base}/{name}" if base else name for name in CLAUDE_SETTINGS):
            data = self._read_mapping(Path(relative), result)
            if data is None:
                continue
            documents[relative] = data
            hooks = _declared_hooks(data.get("hooks"))
            if hooks:
                properties.setdefault("declared_hooks", {})[relative] = hooks
            if "permissions" in data:
                permissions = data["permissions"]
                if not isinstance(permissions, dict):
                    result.scan_failures.append(f"{relative}: invalid permission settings object")
                    # The file's other declarations still count.
                    merged.update({key: item for key, item in data.items() if key != "permissions"})
                    continue
                previous = merged.get("permissions", {})
                combined = {**previous, **permissions}
                for key in ("allow", "ask", "deny"):
                    earlier, current = previous.get(key, []), permissions.get(key, [])
                    if not all(
                        isinstance(values, list) and all(isinstance(value, str) for value in values)
                        for values in (earlier, current)
                    ):
                        result.scan_failures.append(
                            f"{relative}: invalid declared permission {key}-list"
                        )
                        combined.pop(key, None)
                    else:
                        combined[key] = list(dict.fromkeys([*earlier, *current]))
                data = {**data, "permissions": combined}
            merged.update(data)
        plugins: dict[str, dict[str, Any]] = {}
        for relative in CLAUDE_PLUGIN_MANIFESTS if not base else ():
            data = self._read_mapping(Path(relative), result)
            if data is not None:
                plugins[relative] = data
        if plugins:
            hooks_file = self._read_mapping(Path(CLAUDE_PLUGIN_HOOKS), result)
            if hooks_file is not None:
                plugins[CLAUDE_PLUGIN_HOOKS] = hooks_file
                hooks = _declared_hooks(hooks_file.get("hooks"))
                if hooks:
                    properties.setdefault("declared_hooks", {})[CLAUDE_PLUGIN_HOOKS] = hooks
            properties["plugin_manifests"] = sorted(plugins)
        # Only settings files merge into the permission summary; every file is bound.
        documents.update(plugins)
        if not documents:
            return None
        declared_permissions = merged.get("permissions")
        rules: dict[str, Any] = (
            declared_permissions if isinstance(declared_permissions, dict) else {}
        )
        counts = {
            key: len(rules[key])
            for key in ("allow", "ask", "deny")
            if isinstance(rules.get(key), list)
        }
        if counts:
            properties["declared_permission_rule_counts"] = counts
        hook_commands = 0
        hook_severity: RiskSeverity | None = None
        for relative, data in documents.items():
            body = data if relative == CLAUDE_PLUGIN_HOOKS else data.get("hooks")
            try:
                hook_commands += _hook_commands(body)
                hook_severity = _worse(hook_severity, _hook_command_severity(body))
            except ValueError:
                result.scan_failures.append(f"{relative}: settings cannot be canonicalized")
        declared = {
            "additional_directories": _count(rules.get("additionalDirectories")),
            "enabled_plugins": _count(merged.get("enabledPlugins")),
            "extra_known_marketplaces": _count(merged.get("extraKnownMarketplaces")),
            "enabled_mcpjson_servers": _count(merged.get("enabledMcpjsonServers")),
            "disabled_mcpjson_servers": _count(merged.get("disabledMcpjsonServers")),
            "env_variables": _count(merged.get("env")),
            "api_key_helper": merged.get("apiKeyHelper") is not None,
            "enable_all_project_mcp_servers": merged.get("enableAllProjectMcpServers") is True,
        }
        properties["settings_declarations"] = declared
        if hook_commands:
            risks.append(
                RiskAssessment(
                    severity=hook_severity or RiskSeverity.MEDIUM,
                    category="hook_commands",
                    detail=_hook_detail(
                        hook_commands, hook_severity or RiskSeverity.MEDIUM, "claude-code"
                    ),
                    recommendation="Review this setting and approve its exact value.",
                )
            )
        for category, severity, present, detail in (
            (
                "mcp_auto_approval",
                RiskSeverity.MEDIUM,
                declared["enable_all_project_mcp_servers"],
                "approves every MCP server in the project's .mcp.json without a prompt",
            ),
            (
                "credential_helper",
                RiskSeverity.MEDIUM,
                declared["api_key_helper"],
                "declares apiKeyHelper, a command that runs to obtain credentials",
            ),
            (
                "plugin_sources",
                RiskSeverity.LOW,
                bool(declared["enabled_plugins"] or declared["extra_known_marketplaces"]),
                "enables plugins or registers plugin marketplaces, which can add commands, "
                "agents, hooks and MCP servers",
            ),
            (
                "additional_directories",
                RiskSeverity.LOW,
                bool(declared["additional_directories"]),
                "grants access to directories outside the project",
            ),
        ):
            if present:
                risks.append(
                    RiskAssessment(
                        severity=severity,
                        category=category,
                        detail=f"IDE agent 'claude-code' {detail}.",
                        recommendation="Review this setting and approve its exact value.",
                    )
                )
        return merged

    @staticmethod
    def _bind_settings(
        ide_type: str,
        documents: dict[str, dict[str, Any]],
        result: ScanResult,
        risks: list[RiskAssessment],
        properties: dict[str, Any],
    ) -> None:
        """Digest each settings file into `settings_hashes`; bind their values with the key.

        Without the operator key each digest covers the file as read, except that the
        files of `_REDACTED_DIGESTS` are digested after the redaction. With it, every
        digest leaves out what the redaction removes and the environment values, and an
        HMAC under the key covers every file as read, so the inventory never carries an
        unkeyed digest of those values. A file that has no RFC 8785 form, such as TOML
        with a date, is a failure that names it, and leaves the record's values unbound.
        Without the key, so is a redacted file that holds a URL whose authority URL parsers
        read differently, and a redacted digest that leaves out a value is a low
        completeness finding.
        """
        if not documents:
            return
        keyed = bool(os.environ.get(SOURCE_BINDING_KEY_ENV))
        hashes: dict[str, str] = {}
        withheld: list[str] = []
        for relative, data in documents.items():
            redacted = keyed or relative in _REDACTED_DIGESTS
            try:
                projected = _projection(data, unkeyed=not keyed) if redacted else data
                digest = hash_canonical(projected)
                if keyed:
                    # The keyed binding covers the file as read, not only its projection.
                    canonical_json(data)
                elif projected != data:
                    withheld.append(relative)
            except AmbiguousURLError:
                result.scan_failures.append(
                    f"{relative}: a URL authority is ambiguous, so its host cannot be bound"
                )
            except (TypeError, ValueError, RecursionError):
                result.scan_failures.append(f"{relative}: settings cannot be canonicalized")
            else:
                hashes[relative] = digest
        if hashes:
            properties["settings_hashes"] = hashes
        if withheld:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=(
                        f"IDE agent '{ide_type}' settings values not bound in this inventory: "
                        f"the redacted values of {', '.join(withheld)}."
                    ),
                    recommendation=(
                        f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes to "
                        "these values."
                    ),
                )
            )
        if len(hashes) < len(documents):
            properties["source_values_bound"] = False
            return
        try:
            binding = value_binding(SETTINGS_VALUE_BINDING_PROFILE, documents)
        except BindingError as exc:
            result.scan_failures.append(f"{next(iter(documents))}: {exc}")
            return
        properties["source_values_bound"] = bool(binding)
        properties.update(binding)

    def _codex_settings(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        risks: list[RiskAssessment],
        properties: dict[str, Any],
        documents: dict[str, dict[str, Any]],
    ) -> None:
        """Read the approval and sandbox modes; the whole file is digested.

        The ``mcp`` collector inventories the MCP servers it declares.
        """
        text = files.read_text(CODEX_CONFIG, missing_ok=True)
        if text is None:
            return
        try:
            config = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError, RecursionError):
            result.scan_failures.append(f"{CODEX_CONFIG}: invalid TOML")
            return
        documents[CODEX_CONFIG] = config
        approval, sandbox = config.get("approval_policy"), config.get("sandbox_mode")
        if approval is not None and (
            not isinstance(approval, str) or approval not in _PERMISSION_MODES
        ):
            result.scan_failures.append(f"{CODEX_CONFIG}: unsupported approval_policy")
            approval = None
        if sandbox is not None and (
            not isinstance(sandbox, str) or sandbox not in _PERMISSION_MODES
        ):
            result.scan_failures.append(f"{CODEX_CONFIG}: unsupported sandbox_mode")
            sandbox = None
        properties["approval_policy"] = approval
        properties["sandbox_mode"] = sandbox
        if sandbox == "danger-full-access" or approval == "never":
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH
                    if sandbox == "danger-full-access"
                    else RiskSeverity.MEDIUM,
                    category="permission_scope",
                    detail=(
                        "IDE agent 'codex' declares "
                        + (
                            "an unsandboxed full-access mode"
                            if sandbox == "danger-full-access"
                            else "that commands never ask for approval"
                        )
                        + "; effective approval remains unverified."
                    ),
                    recommendation="Keep the workspace-write sandbox and on-request approval.",
                )
            )

    def _gemini_settings(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        documents: dict[str, dict[str, Any]],
    ) -> None:
        """Read Gemini CLI project settings for their digest.

        The ``mcp`` collector inventories the MCP servers they declare.
        """
        data = self._read_jsonc(files, GEMINI_SETTINGS, result)
        if data is None:
            return
        documents[GEMINI_SETTINGS] = data

    def _cursor_hooks(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        risks: list[RiskAssessment],
        properties: dict[str, Any],
        documents: dict[str, dict[str, Any]],
    ) -> None:
        """Count the commands that Cursor project hooks run on agent events."""
        data = self._read_jsonc(files, CURSOR_HOOKS, result)
        if data is None:
            return
        documents[CURSOR_HOOKS] = data
        try:
            hooks = _hook_commands(data.get("hooks"))
        except ValueError:
            result.scan_failures.append(f"{CURSOR_HOOKS}: settings cannot be canonicalized")
            return
        properties["hook_commands"] = hooks
        if hooks:
            try:
                severity = _hook_command_severity(data.get("hooks")) or RiskSeverity.MEDIUM
            except ValueError:
                severity = RiskSeverity.MEDIUM
            risks.append(
                RiskAssessment(
                    severity=severity,
                    category="hook_commands",
                    detail=_hook_detail(hooks, severity, "cursor"),
                    recommendation="Review this setting and approve its exact value.",
                )
            )

    @staticmethod
    def _read_jsonc(
        files: ConfinedCollection, relative: str, result: ScanResult
    ) -> dict[str, Any] | None:
        """A JSON object that may hold comments and trailing commas, as editors accept."""
        text = files.read_text(relative, missing_ok=True)
        if text is None:
            return None
        try:
            data = parse_json_strict(strip_jsonc(text))
        except (ValueError, RecursionError):
            result.scan_failures.append(f"{relative}: invalid JSON or duplicate keys")
            return None
        if not isinstance(data, dict):
            result.scan_failures.append(f"{relative}: expected a mapping")
            return None
        return data

    def _agent_mode_settings(
        self, ide_type: str, result: ScanResult, documents: dict[str, dict[str, Any]]
    ) -> dict[str, Any] | None:
        merged: dict[str, Any] = {}
        for relative in _AGENT_MODE_SETTINGS.get(ide_type, []):
            data = self._read_mapping(Path(relative), result)
            if data is not None:
                documents[relative] = data
                merged.update(data)
        return merged or None

    def _extract_permission_mode(
        self, settings: dict[str, Any], ide_type: str, result: ScanResult
    ) -> str | None:
        key = "permissions" if ide_type == "claude-code" else "agent"
        mode_key = "defaultMode" if ide_type == "claude-code" else "permissionMode"
        values = settings.get(key, {})
        if not isinstance(values, dict):
            result.scan_failures.append(f"{ide_type}: invalid permission settings object")
            return None
        mode = values.get(mode_key)
        if mode is None:
            return None
        if not isinstance(mode, str):
            result.scan_failures.append(f"{ide_type}: invalid declared permission mode")
            return None
        if mode not in _PERMISSION_MODES:
            result.scan_failures.append(f"{ide_type}: unsupported declared permission mode")
            return None
        return mode

    def _broad_permissions(
        self, settings: dict[str, Any], ide_type: str, result: ScanResult
    ) -> list[str]:
        if ide_type != "claude-code":
            return []
        permissions = settings.get("permissions", {})
        if not isinstance(permissions, dict):
            return []
        allowed = permissions.get("allow", [])
        if not isinstance(allowed, list) or not all(isinstance(value, str) for value in allowed):
            result.scan_failures.append(f"{ide_type}: invalid declared permission allow-list")
            return []
        return _broad_grants(allowed)

    def _scan_extensions(self, files: ConfinedCollection, result: ScanResult) -> None:
        relative = ".vscode/extensions.json"
        data = self._read_jsonc(files, relative, result)
        if data is None:
            return
        result.surfaces_scanned.append(relative)
        recommendations = data.get("recommendations", [])
        if not isinstance(recommendations, list) or len(recommendations) > 1000:
            result.scan_failures.append("extensions.json: invalid or oversized recommendation list")
            return
        ai_patterns = (
            "anthropic",
            "claude",
            "copilot",
            "codeium",
            "cursor",
            "tabnine",
            "codex",
            "openai",
            "ai-",
            "agent",
        )
        for extension in recommendations:
            if not isinstance(extension, str) or not _EXTENSION_ID.fullmatch(extension):
                result.scan_failures.append("extensions.json: invalid extension identifier")
                continue
            if any(pattern in extension.lower() for pattern in ai_patterns):
                extension = redact_text(extension)
                result.components.append(
                    VerifiedExtensionComponent(
                        bom_ref=f"verified-extension:vscode/{extension}",
                        name=extension,
                        extension_type="ide-extension",
                        publisher=extension.split(".", 1)[0],
                        publisher_verified=False,
                        attestation_status="unverified",
                        source_path=relative,
                        trust_tier=TrustTier.UNKNOWN,
                        properties={
                            "collection_mode": "recommended-extension",
                            "installation_observed": False,
                        },
                        risks=[
                            RiskAssessment(
                                severity=RiskSeverity.LOW,
                                category="attestation",
                                detail=f"Recommended VS Code AI extension '{extension}' has no verified attestation.",
                                recommendation="Verify installed extension identity, publisher and artifact evidence separately.",
                            )
                        ],
                    )
                )
