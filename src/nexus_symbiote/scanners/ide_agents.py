"""IDE coding agent configuration scanner.

Discovers configurations for IDE-integrated AI coding agents:
  - Claude Code (.claude/, CLAUDE.md, .claude/settings.json)
  - Codex (.codex/, codex.md, .codex/config.toml)
  - Cursor (.cursor/, .cursorrules, .cursor/mcp.json)
  - Gemini CLI (GEMINI.md, .gemini/settings.json)
  - Antigravity (.antigravity/)
  - XAI IDE agent configs
  - Windsurf (.windsurfrules, .windsurf/)
  - Cline (.clinerules, .cline/)
  - GitHub Copilot (.github/copilot-instructions.md)

Only fixed paths beneath the project root are read; nothing is walked.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_canonical, parse_json_strict
from nexus_symbiote.core.models import IDEAgentComponent, RiskAssessment, VerifiedExtensionComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.scanners.source_binding import BindingError, value_binding
from nexus_symbiote.utils.confined import ConfinedCollection
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
# A Claude Code plugin repository's own manifests; its root hooks/hooks.json is the
# plugin's hook configuration only when one of them is present.
CLAUDE_PLUGIN_MANIFESTS = [".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"]
CLAUDE_PLUGIN_HOOKS = "hooks/hooks.json"
# The `agent.permissionMode` key read for these hosts is a project convention that
# vendor documentation does not describe; the files are read for it only.
_AGENT_MODE_SETTINGS = {
    "cursor": [".cursor/settings.json"],
    "windsurf": [".windsurf/settings.json"],
    "cline": [".cline/settings.json"],
    "codex": [".codex/config.json"],
}
SETTINGS_STRUCTURE_PROFILE = "nexus-symbiote/claude-settings-structure/v1"
SETTINGS_VALUE_BINDING_PROFILE = "nexus-symbiote/claude-settings-values/v1"
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


def _projection(value: Any, depth: int = 0, *, env: bool = False) -> Any:
    """Settings as an unkeyed digest may cover them: redacted text, no env values."""
    if depth > _MAX_SETTINGS_DEPTH:
        raise ValueError("settings nested too deeply")
    if isinstance(value, dict):
        if env:
            return sorted(redact_text(str(key)) for key in value)
        return {
            redact_text(str(key)): _projection(item, depth + 1, env=key == "env")
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_projection(item, depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _redacts(value: Any) -> bool:
    """Whether the projection changed any key or text value; depth was bounded by it."""
    if isinstance(value, dict):
        return any(
            redact_text(str(key)) != str(key) or _redacts(item) for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_redacts(item) for item in value)
    return isinstance(value, str) and redact_text(value) != value


def _hook_commands(value: Any, depth: int = 0) -> int:
    if depth > _MAX_SETTINGS_DEPTH:
        raise ValueError("settings nested too deeply")
    if isinstance(value, dict):
        own = 1 if isinstance(value.get("command"), str) else 0
        return own + sum(_hook_commands(item, depth + 1) for item in value.values())
    if isinstance(value, list):
        return sum(_hook_commands(item, depth + 1) for item in value)
    return 0


def _count(value: Any) -> int:
    return len(value) if isinstance(value, (list, dict)) else 0


def _strip_jsonc(text: str) -> str:
    """Remove comments and trailing commas outside strings, as VS Code's parser accepts."""
    out: list[str] = []
    index, length = 0, len(text)
    in_string = False
    while index < length:
        char = text[index]
        if in_string:
            out.append(char)
            if char == "\\" and index + 1 < length:
                out.append(text[index + 1])
                index += 2
                continue
            in_string = char != '"'
            index += 1
            continue
        if char == '"':
            in_string = True
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = length if end == -1 else end
            continue
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end == -1:
                raise ValueError("unterminated comment")
            out.append(" ")
            index = end + 2
            continue
        out.append(char)
        index += 1
    stripped = "".join(out)
    cleaned: list[str] = []
    in_string = False
    for position, char in enumerate(stripped):
        if in_string:
            if char == '"' and not _escaped(stripped, position):
                in_string = False
        elif char == '"':
            in_string = True
        elif char == ",":
            following = position + 1
            while following < len(stripped) and stripped[following] in " \t\r\n":
                following += 1
            if following < len(stripped) and stripped[following] in "}]":
                continue
        cleaned.append(char)
    return "".join(cleaned)


def _escaped(text: str, position: int) -> bool:
    backslashes = 0
    while position - backslashes - 1 >= 0 and text[position - backslashes - 1] == "\\":
        backslashes += 1
    return backslashes % 2 == 1


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
            # that directory's .claude settings as its project settings.
            nested: dict[str, list[str]] = {}
            for path in files.iter_files():
                if (
                    len(path.parts) > 2
                    and path.parts[-2] == ".claude"
                    and path.as_posix() not in CLAUDE_SETTINGS
                    and path.name in {"settings.json", "settings.local.json"}
                ):
                    nested.setdefault(Path(*path.parts[:-2]).as_posix(), []).append(path.as_posix())
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
        if ide_type == "claude-code":
            settings = self._claude_settings(files, result, risks, properties, base=base)
        elif ide_type == "codex":
            settings = self._codex_settings(files, result, risks, properties)
        else:
            settings = self._agent_mode_settings(ide_type, result)
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
        if ide_type == "claude-code" and mode in {"bypassPermissions", "acceptEdits"}:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH
                    if mode == "bypassPermissions"
                    else RiskSeverity.MEDIUM,
                    category="permission_mode",
                    detail=(
                        f"IDE agent '{ide_type}' declares the {mode} starting mode, "
                        "which skips approval prompts."
                    ),
                    recommendation=(
                        "Use the default or plan mode in project settings; grant "
                        "narrow allow rules instead."
                    ),
                )
            )
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
        files: ConfinedCollection,
        result: ScanResult,
        risks: list[RiskAssessment],
        properties: dict[str, Any],
        *,
        base: str = "",
    ) -> dict[str, Any] | None:
        """Merge permission layers and bind every setting of each settings file.

        The digest covers every key and redacted value, so a changed hook, rule, helper,
        plugin or marketplace changes the record; environment values are bound only by
        the operator key. The merged summary does not resolve effective permissions
        across trust, user or managed policy, flags or product versions.
        """
        documents: dict[str, dict[str, Any]] = {}
        merged: dict[str, Any] = {}
        plugins: dict[str, dict[str, Any]]
        for relative in (f"{base}/{name}" if base else name for name in CLAUDE_SETTINGS):
            data = self._read_mapping(Path(relative), result)
            if data is None:
                continue
            documents[relative] = data
            if "permissions" in data:
                permissions = data["permissions"]
                if not isinstance(permissions, dict):
                    result.scan_failures.append(f"{relative}: invalid permission settings object")
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
        plugins = {}
        for relative in CLAUDE_PLUGIN_MANIFESTS if not base else ():
            data = self._read_mapping(Path(relative), result)
            if data is not None:
                plugins[relative] = data
        if plugins:
            hooks_file = self._read_mapping(Path(CLAUDE_PLUGIN_HOOKS), result)
            if hooks_file is not None:
                plugins[CLAUDE_PLUGIN_HOOKS] = hooks_file
            properties["plugin_manifests"] = sorted(plugins)
        # Only settings files merge into the permission summary; every file is bound.
        documents.update(plugins)
        if not documents:
            return None
        try:
            projection = {path: _projection(data) for path, data in documents.items()}
            structure = hash_canonical(
                {"profile": SETTINGS_STRUCTURE_PROFILE, "settings": projection}
            )
            binding = value_binding(SETTINGS_VALUE_BINDING_PROFILE, documents)
            hooks = sum(
                _hook_commands(data if path == CLAUDE_PLUGIN_HOOKS else data.get("hooks"))
                for path, data in documents.items()
            )
        except BindingError as exc:
            result.scan_failures.append(f"{next(iter(documents))}: {exc}")
            return merged
        except (TypeError, ValueError, RecursionError):
            result.scan_failures.append(
                f"{next(iter(documents))}: settings cannot be digested (values must be JSON)"
            )
            return merged
        declared_permissions = merged.get("permissions")
        rules: dict[str, Any] = (
            declared_permissions if isinstance(declared_permissions, dict) else {}
        )
        declared = {
            "hook_commands": hooks,
            "allow_rules": _count(rules.get("allow")),
            "ask_rules": _count(rules.get("ask")),
            "deny_rules": _count(rules.get("deny")),
            "additional_directories": _count(rules.get("additionalDirectories")),
            "enabled_plugins": _count(merged.get("enabledPlugins")),
            "extra_known_marketplaces": _count(merged.get("extraKnownMarketplaces")),
            "enabled_mcpjson_servers": _count(merged.get("enabledMcpjsonServers")),
            "disabled_mcpjson_servers": _count(merged.get("disabledMcpjsonServers")),
            "env_variables": _count(merged.get("env")),
            "api_key_helper": merged.get("apiKeyHelper") is not None,
            "enable_all_project_mcp_servers": merged.get("enableAllProjectMcpServers") is True,
        }
        properties.update(
            {
                "settings_files": sorted(set(documents) - set(plugins)),
                "settings_declarations": declared,
                "source_values_bound": bool(binding),
                "static_config_hash": structure,
                "static_config_hash_profile": SETTINGS_STRUCTURE_PROFILE,
                **binding,
            }
        )
        for category, severity, present, detail in (
            (
                "hook_commands",
                RiskSeverity.MEDIUM,
                hooks > 0,
                f"declares {hooks} hook command(s) that run automatically on agent events",
            ),
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
        unbound = [
            label
            for label, gap in (
                (
                    "environment variable values",
                    any(_count(data.get("env")) for data in documents.values()),
                ),
                ("values reduced by redaction", any(_redacts(data) for data in documents.values())),
            )
            if gap
        ]
        if unbound and not binding:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=(
                        "IDE agent 'claude-code' settings values not bound in this inventory: "
                        f"{'; '.join(unbound)}."
                    ),
                    recommendation=(
                        f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes "
                        "to these values."
                    ),
                )
            )
        return merged

    def _codex_settings(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        risks: list[RiskAssessment],
        properties: dict[str, Any],
    ) -> dict[str, Any] | None:
        settings = self._agent_mode_settings("codex", result)
        text = files.read_text(".codex/config.toml", missing_ok=True)
        if text is None:
            return settings
        try:
            config = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError, RecursionError):
            result.scan_failures.append(".codex/config.toml: invalid TOML")
            return settings
        approval, sandbox = config.get("approval_policy"), config.get("sandbox_mode")
        if approval is not None and (
            not isinstance(approval, str) or approval not in _PERMISSION_MODES
        ):
            result.scan_failures.append(".codex/config.toml: unsupported approval_policy")
            approval = None
        if sandbox is not None and (
            not isinstance(sandbox, str) or sandbox not in _PERMISSION_MODES
        ):
            result.scan_failures.append(".codex/config.toml: unsupported sandbox_mode")
            sandbox = None
        properties["approval_policy"] = approval
        properties["sandbox_mode"] = sandbox
        if sandbox == "danger-full-access" or approval == "never":
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH
                    if sandbox == "danger-full-access"
                    else RiskSeverity.MEDIUM,
                    category="permission_mode",
                    detail=(
                        "IDE agent 'codex' declares "
                        + (
                            "an unsandboxed full-access mode"
                            if sandbox == "danger-full-access"
                            else "that commands never ask for approval"
                        )
                        + "."
                    ),
                    recommendation="Keep the workspace-write sandbox and on-request approval.",
                )
            )
        servers = config.get("mcp_servers")
        if isinstance(servers, dict) and servers:
            result.surfaces_excluded.append(
                f".codex/config.toml: {len(servers)} MCP server declaration(s) are not inventoried"
            )
        return settings

    def _agent_mode_settings(self, ide_type: str, result: ScanResult) -> dict[str, Any] | None:
        merged: dict[str, Any] = {}
        for relative in _AGENT_MODE_SETTINGS.get(ide_type, []):
            data = self._read_mapping(Path(relative), result)
            if data is not None:
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
        text = files.read_text(relative, missing_ok=True)
        if text is None:
            return
        try:
            # VS Code reads this file as JSON with comments and trailing commas.
            data = parse_json_strict(_strip_jsonc(text))
        except (ValueError, RecursionError):
            result.scan_failures.append(f"{relative}: invalid JSON or duplicate keys")
            return
        if not isinstance(data, dict):
            result.scan_failures.append(f"{relative}: expected a mapping")
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
