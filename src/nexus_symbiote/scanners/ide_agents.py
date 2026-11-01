"""IDE coding agent configuration scanner.

Discovers configurations for IDE-integrated AI coding agents:
  - Claude Code (.claude/, CLAUDE.md, .claude/settings.json)
  - Codex (.codex/, codex.md)
  - Cursor (.cursor/, .cursorrules, .cursor/mcp.json)
  - Antigravity (.antigravity/)
  - XAI IDE agent configs
  - Windsurf (.windsurfrules, .windsurf/)
  - Cline (.clinerules, .cline/)
  - GitHub Copilot (.github/copilot-instructions.md)
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import (
    IDEAgentComponent,
    RiskAssessment,
    VerifiedExtensionComponent,
)
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.mcp import (
    as_text,
    excluded_before_read,
    make_components_unique,
    parse_json_object,
    read_text_for_scan,
    server_map,
)

IDE_AGENT_CONFIGS: dict[str, dict[str, Any]] = {
    "claude-code": {
        "markers": [
            ".claude/settings.json",
            ".claude/settings.local.json",
            "CLAUDE.md",
            ".claude/CLAUDE.md",
            ".claude/commands",
            ".claude/skills",
        ],
        "mcp_config": [".claude/mcp.json", ".mcp.json"],
    },
    "codex": {
        "markers": [
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
        ],
        "mcp_config": [".cursor/mcp.json"],
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
        ],
        "mcp_config": [],
    },
}

# Settings files whose permissions and hooks are inspected, per IDE.
IDE_SETTINGS_FILES: dict[str, tuple[str, ...]] = {
    "claude-code": (".claude/settings.json", ".claude/settings.local.json"),
    "cursor": (".cursor/settings.json",),
    "windsurf": (".windsurf/settings.json",),
    "cline": (".cline/settings.json",),
    "codex": (".codex/config.json",),
}

# IDE types whose settings declare hooks that run commands.
HOOK_IDE_TYPES = frozenset({"claude-code", "cursor"})

BROAD_PERMISSION_PATTERNS = ("Bash(*)", "Edit(*)", "Write(*)", "*")

AI_EXTENSION_PATTERNS = (
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

_ENV_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


@dataclass(frozen=True)
class _SettingsFacts:
    """What one settings file says about permissions, MCP auto-enablement, and hooks."""

    permission_mode: str | None = None
    broad_permissions: bool = False
    bypass_permissions: bool = False
    auto_enable_mcp: bool = False
    hook_commands: tuple[tuple[str, str], ...] = ()


def command_basename(command: str) -> str:
    """The executable's file name. Environment assignments, directories, and arguments are dropped."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for token in tokens:
        if _ENV_ASSIGNMENT.match(token):
            continue
        return token.replace("\\", "/").rsplit("/", 1)[-1] or "unnamed"
    return "unnamed"


def _object_field(
    document: dict[str, Any], key: str, surface: str, result: ScanResult
) -> dict[str, Any]:
    value = document.get(key)
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    result.record_failure(f"{surface}: {key} is not an object; its checks are skipped")
    return {}


def _hook_handlers(entry: object) -> list[object]:
    """Command handlers of one hooks entry: a matcher group that holds hooks, or a handler."""
    if isinstance(entry, dict) and isinstance(entry.get("hooks"), list):
        return list(entry["hooks"])
    return [entry]


def _hook_commands(
    surface: str, document: dict[str, Any], result: ScanResult
) -> list[tuple[str, str]]:
    """Each hook handler as (event, executable name). Arguments are never kept."""
    hooks = document.get("hooks")
    if hooks is None:
        return []
    if not isinstance(hooks, dict):
        result.record_failure(f"{surface}: hooks is not an object; hook inventory skipped")
        return []
    found: list[tuple[str, str]] = []
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            result.record_failure(f"{surface}: hooks.{event} is not a list; not inventoried")
            continue
        for entry in entries:
            for handler in _hook_handlers(entry):
                command = handler.get("command") if isinstance(handler, dict) else None
                if isinstance(command, str) and command.strip():
                    found.append((str(event), command_basename(command)))
                else:
                    result.record_failure(
                        f"{surface}: a hooks.{event} entry has no command string; not inventoried"
                    )
    return found


class IDEAgentScanner(Scanner):
    name = "ide_agents"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        found_any = False

        for ide_type, config in IDE_AGENT_CONFIGS.items():
            if self._scan_ide_agent(project_root, ide_type, config, result):
                found_any = True

        self._scan_extensions(project_root, result)
        make_components_unique(result)

        if not found_any:
            markers = dict.fromkeys(
                marker for cfg in IDE_AGENT_CONFIGS.values() for marker in cfg["markers"]
            )
            result.record_absent("ide-agent-config", list(markers))

        return result

    def _scan_ide_agent(
        self,
        root: Path,
        ide_type: str,
        config: dict[str, Any],
        result: ScanResult,
    ) -> bool:
        """Scan one IDE agent. Returns True when a marker exists, even one that was excluded."""
        present = False
        found_files: list[str] = []

        for marker in config["markers"]:
            marker_path = root / marker
            if not (marker_path.exists() or marker_path.is_symlink()):
                continue
            present = True
            surface = f"ide-agent-config {marker}"
            if excluded_before_read(marker_path, root, self.exclude_paths, surface, result):
                continue
            found_files.append(marker)
            result.surfaces_scanned.append(surface)

        if not found_files:
            return present

        settings_files = IDE_SETTINGS_FILES.get(ide_type, ())
        facts: list[_SettingsFacts] = []
        for rel in found_files:
            if rel not in settings_files:
                continue
            surface = f"ide-agent-config {rel}"
            text = read_text_for_scan(root / rel, surface, result)
            if text is None:
                continue
            document = parse_json_object(text, surface, result)
            if document is not None:
                facts.append(self._settings_facts(ide_type, rel, document, result))

        risks: list[RiskAssessment] = []
        if any(fact.broad_permissions for fact in facts):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="permission_scope",
                    detail=f"IDE agent '{ide_type}' has broad tool permissions configured.",
                    recommendation="Review and restrict tool permissions to minimum required.",
                )
            )

        if self._has_instruction_override(root, ide_type):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="instruction_layering",
                    detail=f"IDE agent '{ide_type}' has multiple instruction files.",
                    recommendation="Consolidate instructions to avoid conflicting directives.",
                )
            )

        if any(fact.bypass_permissions for fact in facts):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="permission-bypass",
                    detail=(
                        f"IDE agent '{ide_type}' sets permissions.defaultMode to "
                        "bypassPermissions."
                    ),
                    recommendation="Remove bypassPermissions and require approval for tool use.",
                )
            )

        if any(fact.auto_enable_mcp for fact in facts):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="auto-enabled-mcp",
                    detail=(
                        f"IDE agent '{ide_type}' enables every project MCP server without "
                        "per-server approval."
                    ),
                    recommendation="Set enableAllProjectMcpServers to false and approve servers.",
                )
            )

        for fact in facts:
            for event, command_name in fact.hook_commands:
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.MEDIUM,
                        category="agent-hook-command",
                        detail=(
                            f"IDE agent '{ide_type}' runs '{command_name}' on hook event "
                            f"'{event}'."
                        ),
                        recommendation="Review each hook command; hooks run with agent privileges.",
                    )
                )

        mcp_refs: list[str] = []
        for mcp_cfg in config.get("mcp_config", []):
            mcp_refs.extend(self._mcp_server_refs(root, mcp_cfg, result))

        permission_mode = next(
            (fact.permission_mode for fact in facts if fact.permission_mode is not None),
            None,
        )
        result.components.append(
            IDEAgentComponent(
                bom_ref=f"ide-agent:{ide_type}",
                name=ide_type,
                ide_type=ide_type,
                config_files=found_files,
                mcp_server_refs=list(dict.fromkeys(mcp_refs)),
                permission_mode=permission_mode,
                source_path=str(root / found_files[0]),
                trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                risks=risks,
            )
        )
        return True

    def _settings_facts(
        self,
        ide_type: str,
        rel: str,
        document: dict[str, Any],
        result: ScanResult,
    ) -> _SettingsFacts:
        surface = f"ide-agent-config {rel}"
        permission_mode: str | None = None
        broad = False
        bypass = False
        auto_enable = False

        if ide_type == "claude-code":
            perms = _object_field(document, "permissions", surface, result)
            permission_mode = as_text(
                perms.get("defaultMode"), "permissions.defaultMode", surface, result
            ) or as_text(perms.get("mode"), "permissions.mode", surface, result)
            allowed = perms.get("allow")
            if isinstance(allowed, list):
                broad = any(
                    isinstance(pattern, str) and pattern in BROAD_PERMISSION_PATTERNS
                    for pattern in allowed
                )
                skipped = sum(1 for pattern in allowed if not isinstance(pattern, str))
                if skipped:
                    result.record_failure(
                        f"{surface}: permissions.allow has {skipped} non-string entries; ignored"
                    )
            elif allowed is not None:
                result.record_failure(f"{surface}: permissions.allow is not a list; ignored")
            bypass = perms.get("defaultMode") == "bypassPermissions"

            enabled = document.get("enableAllProjectMcpServers")
            if enabled is not None and not isinstance(enabled, bool):
                result.record_failure(
                    f"{surface}: enableAllProjectMcpServers is not a boolean; ignored"
                )
            auto_enable = enabled is True
        elif ide_type == "cursor":
            agent = _object_field(document, "agent", surface, result)
            permission_mode = as_text(
                agent.get("permissionMode"), "agent.permissionMode", surface, result
            )

        hook_commands = (
            _hook_commands(surface, document, result) if ide_type in HOOK_IDE_TYPES else []
        )
        return _SettingsFacts(
            permission_mode=permission_mode,
            broad_permissions=broad,
            bypass_permissions=bypass,
            auto_enable_mcp=auto_enable,
            hook_commands=tuple(hook_commands),
        )

    def _mcp_server_refs(self, root: Path, rel: str, result: ScanResult) -> list[str]:
        """The mcp-server:<name> references for the servers that an MCP config declares."""
        path = root / rel
        if not (path.exists() or path.is_symlink()):
            return []
        surface = f"ide-agent MCP references {rel}"
        if excluded_before_read(path, root, self.exclude_paths, surface, result):
            return []
        text = read_text_for_scan(path, surface, result)
        if text is None:
            return []
        data = parse_json_object(text, surface, result)
        if data is None:
            return []
        servers = server_map(data, surface, result)
        if servers is None:
            return []
        return [
            f"mcp-server:{name}" for name, config in servers.items() if isinstance(config, dict)
        ]

    def _has_instruction_override(self, root: Path, ide_type: str) -> bool:
        if ide_type == "claude-code":
            files = ["CLAUDE.md", ".claude/CLAUDE.md"]
            return sum(1 for f in files if (root / f).exists()) > 1
        if ide_type == "cursor":
            files = [".cursorrules", ".cursor/rules"]
            return sum(1 for f in files if (root / f).exists()) > 1
        return False

    def _scan_extensions(self, root: Path, result: ScanResult) -> None:
        """Scan for verified/marketplace extensions used by IDE agents."""
        extensions_file = root / ".vscode" / "extensions.json"
        surface = "vscode-extensions .vscode/extensions.json"
        if not (extensions_file.exists() or extensions_file.is_symlink()):
            result.record_absent("vscode-extensions", [".vscode/extensions.json"])
            return
        if excluded_before_read(extensions_file, root, self.exclude_paths, surface, result):
            return
        text = read_text_for_scan(extensions_file, surface, result)
        if text is None:
            return
        result.surfaces_scanned.append(surface)
        data = parse_json_object(text, surface, result)
        if data is None:
            return

        recommendations = data.get("recommendations")
        if recommendations is None:
            return
        if not isinstance(recommendations, list):
            result.record_failure(f"{surface}: recommendations is not a list; ignored")
            return

        for ext_id in recommendations:
            if not isinstance(ext_id, str):
                result.record_failure(f"{surface}: a recommendation is not a string; skipped")
                continue
            ext_lower = ext_id.lower()
            if not any(p in ext_lower for p in AI_EXTENSION_PATTERNS):
                continue
            publisher = ext_id.split(".")[0] if "." in ext_id else None
            result.components.append(
                VerifiedExtensionComponent(
                    bom_ref=f"verified-extension:vscode/{ext_id}",
                    name=ext_id,
                    extension_type="ide-extension",
                    publisher=publisher,
                    publisher_verified=False,
                    attestation_status="unverified",
                    source_path=str(extensions_file),
                    trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                    risks=[
                        RiskAssessment(
                            severity=RiskSeverity.LOW,
                            category="attestation",
                            detail=f"VS Code AI extension '{ext_id}' attestation not verified.",
                            recommendation=(
                                "Verify extension publisher and review marketplace attestation."
                            ),
                        )
                    ],
                )
            )
