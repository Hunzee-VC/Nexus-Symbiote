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

from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import IDEAgentComponent, RiskAssessment, VerifiedExtensionComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult

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


class IDEAgentScanner(Scanner):
    name = "ide_agents"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        for ide_type, config in IDE_AGENT_CONFIGS.items():
            self._scan_ide_agent(project_root, ide_type, config, result)

        self._scan_extensions(project_root, result)

        if not result.components and not result.scan_failures:
            result.surfaces_excluded.append("ide-agents (no IDE agent configs found)")

        return result

    def _scan_ide_agent(
        self,
        root: Path,
        ide_type: str,
        config: dict[str, Any],
        result: ScanResult,
    ) -> None:
        found_files: list[str] = []
        config_files: list[str] = []

        for marker in config["markers"]:
            marker_path = root / marker
            if marker_path.exists() and not marker_path.is_symlink():
                found_files.append(marker)
                config_files.append(str(marker_path))

        if not found_files:
            return

        result.surfaces_scanned.extend(config_files)

        mcp_refs: list[str] = []
        for mcp_cfg in config.get("mcp_config", []):
            mcp_path = root / mcp_cfg
            if mcp_path.exists() and not mcp_path.is_symlink():
                mcp_refs.append(f"mcp-config:{mcp_cfg}")

        risks: list[RiskAssessment] = []
        permission_mode = None

        settings_data = self._read_ide_settings(root, ide_type)
        if settings_data:
            permission_mode = self._extract_permission_mode(settings_data, ide_type)

            if self._has_broad_permissions(settings_data, ide_type):
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

        result.components.append(
            IDEAgentComponent(
                bom_ref=f"ide-agent:{ide_type}",
                name=ide_type,
                ide_type=ide_type,
                config_files=found_files,
                mcp_server_refs=mcp_refs,
                permission_mode=permission_mode,
                source_path=config_files[0] if config_files else None,
                trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                risks=risks,
            )
        )

    def _read_ide_settings(self, root: Path, ide_type: str) -> dict[str, Any] | None:
        settings_paths = {
            "claude-code": [".claude/settings.json", ".claude/settings.local.json"],
            "cursor": [".cursor/settings.json"],
            "windsurf": [".windsurf/settings.json"],
            "cline": [".cline/settings.json"],
            "codex": [".codex/config.json"],
        }

        for path in settings_paths.get(ide_type, []):
            full_path = root / path
            if full_path.exists() and not full_path.is_symlink():
                data = self._safe_read_json(full_path)
                if isinstance(data, dict):
                    return data
        return None

    def _extract_permission_mode(
        self, settings: dict[str, Any], ide_type: str
    ) -> str | None:
        if ide_type == "claude-code":
            perms = settings.get("permissions", {})
            mode = perms.get("mode") if isinstance(perms, dict) else None
            return str(mode) if mode is not None else None
        if ide_type == "cursor":
            agent = settings.get("agent", {})
            mode = agent.get("permissionMode") if isinstance(agent, dict) else None
            return str(mode) if mode is not None else None
        return None

    def _has_broad_permissions(self, settings: dict[str, Any], ide_type: str) -> bool:
        if ide_type == "claude-code":
            allowed = settings.get("permissions", {}).get("allow", [])
            if isinstance(allowed, list):
                broad_patterns = ["Bash(*)", "Edit(*)", "Write(*)", "*"]
                return any(p in allowed for p in broad_patterns)
        return False

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
        if not extensions_file.exists() or extensions_file.is_symlink():
            return

        result.surfaces_scanned.append(str(extensions_file))
        data = self._safe_read_json(extensions_file)
        if not isinstance(data, dict):
            return

        ai_extension_patterns = [
            "anthropic", "claude", "copilot", "codeium", "cursor",
            "tabnine", "codex", "openai", "ai-", "agent",
        ]

        recommendations = data.get("recommendations", [])
        if not isinstance(recommendations, list):
            return

        for ext_id in recommendations:
            if not isinstance(ext_id, str):
                continue
            ext_lower = ext_id.lower()
            if any(p in ext_lower for p in ai_extension_patterns):
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
