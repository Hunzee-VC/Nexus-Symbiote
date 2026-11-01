"""A2A (Agent-to-Agent) protocol scanner.

Discovers A2A agent cards, client configurations, and server endpoints from:
  - .well-known/agent.json (standard A2A agent card location)
  - agent.json / agent-card.json in project root
  - A2A client configurations in application code and config files
  - Google A2A SDK usage patterns
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    RiskAssessment,
)
from nexus_symbiote.scanners.base import Scanner, ScanResult, read_regular_text, sanitized_origin

AGENT_CARD_FILES = [
    ".well-known/agent.json",
    "agent.json",
    "agent-card.json",
    "a2a/agent.json",
]

A2A_CONFIG_FILES = [
    "a2a.json",
    "a2a.yaml",
    "a2a.yml",
    "a2a_config.json",
]


class A2AScanner(Scanner):
    name = "a2a"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        self._scan_agent_cards(project_root, result)
        self._scan_a2a_configs(project_root, result)
        self._scan_code_patterns(project_root, result)

        if not result.components and not result.scan_failures:
            result.surfaces_excluded.append("a2a (no A2A configurations found)")

        return result

    def _scan_agent_cards(self, root: Path, result: ScanResult) -> None:
        for rel_path in AGENT_CARD_FILES:
            card_path = root / rel_path
            if not card_path.exists() or card_path.is_symlink():
                continue

            result.surfaces_scanned.append(str(card_path))
            data = self._safe_read_json(card_path)
            if not isinstance(data, dict):
                result.scan_failures.append(f"Failed to parse agent card {card_path}")
                continue

            comp = self._parse_agent_card(data, rel_path, card_path)
            result.components.append(comp)

    def _parse_agent_card(
        self, data: dict[str, Any], rel_path: str, card_path: Path
    ) -> A2AServerComponent:
        name = data.get("name", "unnamed-agent")
        version = data.get("version")
        endpoint = data.get("url") or data.get("endpoint")
        protocols = data.get("protocols", [])
        if isinstance(protocols, str):
            protocols = [protocols]

        skills = []
        for skill in data.get("skills", []):
            if isinstance(skill, dict):
                skills.append(skill.get("name", skill.get("id", "unknown")))
            elif isinstance(skill, str):
                skills.append(skill)

        auth_required = data.get("authentication") is not None

        risks: list[RiskAssessment] = []

        if endpoint and not endpoint.startswith("https://"):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"A2A agent '{name}' exposes endpoint without HTTPS.",
                    recommendation="Use HTTPS for all A2A agent endpoints.",
                )
            )

        if not auth_required:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="authentication",
                    detail=f"A2A agent '{name}' has no authentication configured.",
                    recommendation="Require authentication for agent-to-agent communication.",
                )
            )

        if not skills:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=f"A2A agent '{name}' declares no skills in its agent card.",
                    recommendation="Declare skills so consumers can verify capabilities.",
                )
            )

        return A2AServerComponent(
            bom_ref=f"a2a-server:{name}",
            name=name,
            version=version,
            agent_card_path=rel_path,
            endpoint_url=sanitized_origin(endpoint) if endpoint else None,
            supported_protocols=protocols,
            skills_declared=skills,
            authentication_required=auth_required,
            source_path=str(card_path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
        )

    def _scan_a2a_configs(self, root: Path, result: ScanResult) -> None:
        for config_name in A2A_CONFIG_FILES:
            config_path = root / config_name
            if not config_path.exists() or config_path.is_symlink():
                continue

            result.surfaces_scanned.append(str(config_path))
            data = self._safe_read_json(config_path)
            if not isinstance(data, dict):
                result.scan_failures.append(f"Failed to parse {config_path}")
                continue

            clients = data.get("clients", data.get("remoteAgents", []))
            if isinstance(clients, list):
                for client_cfg in clients:
                    if isinstance(client_cfg, dict):
                        comp = self._parse_a2a_client(client_cfg, config_path)
                        result.components.append(comp)

    def _parse_a2a_client(
        self, config: dict[str, Any], config_path: Path
    ) -> A2AClientComponent:
        name = config.get("name", config.get("agentName", "unnamed-client"))
        card_url = config.get("agentCardUrl", config.get("url", config.get("endpoint")))
        auth_methods = config.get("authMethods", config.get("authentication", []))
        if isinstance(auth_methods, str):
            auth_methods = [auth_methods]
        elif isinstance(auth_methods, dict):
            auth_methods = list(auth_methods.keys())

        risks: list[RiskAssessment] = []

        if card_url and not card_url.startswith("https://"):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"A2A client '{name}' connects to agent over insecure transport.",
                    recommendation="Use HTTPS for all A2A agent card URLs.",
                )
            )

        if not auth_methods:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="authentication",
                    detail=f"A2A client '{name}' has no authentication configured.",
                    recommendation="Configure authentication for remote agent invocation.",
                )
            )

        return A2AClientComponent(
            bom_ref=f"a2a-client:{name}",
            name=name,
            agent_card_url=sanitized_origin(card_url) if card_url else None,
            authentication_methods=auth_methods if isinstance(auth_methods, list) else [],
            source_path=str(config_path),
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
            risks=risks,
        )

    def _scan_code_patterns(self, root: Path, result: ScanResult) -> None:
        """Detect A2A SDK usage in Python files (shallow scan of top-level .py files)."""
        import re

        a2a_patterns = [
            re.compile(r"from\s+a2a\b"),
            re.compile(r"import\s+a2a\b"),
            re.compile(r"A2AClient\s*\("),
            re.compile(r"AgentCard\s*\("),
            re.compile(r"agent_card_url"),
        ]

        py_files = sorted(root.glob("*.py"))
        py_files.extend(sorted((root / "src").glob("*.py")) if (root / "src").is_dir() else [])

        for py_file in py_files[:20]:
            if py_file.is_symlink():
                continue
            try:
                content = read_regular_text(py_file)
            except (OSError, UnicodeError):
                continue

            if any(p.search(content) for p in a2a_patterns):
                result.surfaces_scanned.append(str(py_file))
                if not any(
                    c.bom_ref.startswith("a2a-") for c in result.components
                ):
                    result.components.append(
                        A2AClientComponent(
                            bom_ref="a2a-client:code-detected",
                            name="a2a-client (code-detected)",
                            source_path=str(py_file),
                            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                            risks=[
                                RiskAssessment(
                                    severity=RiskSeverity.INFO,
                                    category="detection_method",
                                    detail="A2A usage detected via code pattern matching.",
                                    recommendation=(
                                        "Add an a2a.json config for explicit agent card references."
                                    ),
                                )
                            ],
                        )
                    )
                break
