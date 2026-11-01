"""A2A (Agent-to-Agent) protocol scanner.

Discovers A2A agent cards, client configurations, and server endpoints from:
  - .well-known/agent.json (standard A2A agent card location)
  - agent.json / agent-card.json in project root
  - A2A client configurations in application code and config files
  - Google A2A SDK usage patterns
"""

from __future__ import annotations

import re
from importlib import import_module
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import A2AClientComponent, A2AServerComponent, RiskAssessment
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    read_regular_text,
    relative_posix,
    sanitized_origin,
)
from nexus_symbiote.scanners.mcp import (
    as_text,
    excluded_before_read,
    make_components_unique,
    parse_json_object,
    read_text_for_scan,
)

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

# Top-level and src/ Python files examined by the code-pattern scan.
CODE_SCAN_LIMIT = 20

# Only plain names are recorded as authentication methods. Anything else may be a credential.
_AUTH_METHOD_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.+-]{0,63}")

# Keys that hold credential material, not the name of a method.
_CREDENTIAL_KEYS = frozenset(
    {"credentials", "credential", "token", "secret", "password", "header", "headers", "value"}
)

_A2A_CODE_PATTERNS = (
    re.compile(r"from\s+a2a\b"),
    re.compile(r"import\s+a2a\b"),
    re.compile(r"A2AClient\s*\("),
    re.compile(r"AgentCard\s*\("),
    re.compile(r"agent_card_url"),
)


class A2AScanner(Scanner):
    name = "a2a"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        found_card = self._scan_agent_cards(project_root, result)
        found_config = self._scan_a2a_configs(project_root, result)
        found_code = self._scan_code_patterns(project_root, result)
        make_components_unique(result)

        if not (found_card or found_config or found_code):
            result.record_absent(
                "a2a-configuration",
                [*AGENT_CARD_FILES, *A2A_CONFIG_FILES, "*.py", "src/*.py"],
            )
        return result

    def _scan_agent_cards(self, root: Path, result: ScanResult) -> bool:
        found = False
        for rel_path in AGENT_CARD_FILES:
            card_path = root / rel_path
            if not (card_path.exists() or card_path.is_symlink()):
                continue
            found = True
            surface = f"a2a-agent-card {rel_path}"
            if excluded_before_read(card_path, root, self.exclude_paths, surface, result):
                continue
            text = read_text_for_scan(card_path, surface, result)
            if text is None:
                continue
            result.surfaces_scanned.append(surface)
            data = parse_json_object(text, surface, result)
            if data is not None:
                result.components.append(
                    self._parse_agent_card(data, rel_path, card_path, surface, result)
                )
        return found

    def _parse_agent_card(
        self,
        data: dict[str, Any],
        rel_path: str,
        card_path: Path,
        surface: str,
        result: ScanResult,
    ) -> A2AServerComponent:
        name = as_text(data.get("name"), "name", surface, result) or "unnamed-agent"
        version = as_text(data.get("version"), "version", surface, result)
        endpoint = as_text(data.get("url") or data.get("endpoint"), "url", surface, result)
        protocols = _string_list(data.get("protocols"), "protocols", surface, result)
        skills = _skill_names(data.get("skills"), surface, result)
        auth_required = data.get("authentication") is not None

        risks: list[RiskAssessment] = []

        if endpoint and not endpoint.lower().startswith("https://"):
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

    def _scan_a2a_configs(self, root: Path, result: ScanResult) -> bool:
        found = False
        for config_name in A2A_CONFIG_FILES:
            config_path = root / config_name
            if not (config_path.exists() or config_path.is_symlink()):
                continue
            found = True
            surface = f"a2a-config {config_name}"
            if excluded_before_read(config_path, root, self.exclude_paths, surface, result):
                continue
            text = read_text_for_scan(config_path, surface, result)
            if text is None:
                continue
            result.surfaces_scanned.append(surface)
            data = _parse_config(config_name, text, surface, result)
            if data is None:
                continue

            clients = data.get("clients", data.get("remoteAgents"))
            if clients is None:
                continue
            if not isinstance(clients, list):
                result.record_failure(f"{surface}: clients is not a list; no clients recorded")
                continue
            for index, client_cfg in enumerate(clients):
                if not isinstance(client_cfg, dict):
                    result.record_failure(
                        f"{surface}: clients[{index}] is not an object; not recorded"
                    )
                    continue
                result.components.append(
                    self._parse_a2a_client(client_cfg, config_path, surface, result)
                )
        return found

    def _parse_a2a_client(
        self,
        config: dict[str, Any],
        config_path: Path,
        surface: str,
        result: ScanResult,
    ) -> A2AClientComponent:
        name = (
            as_text(config.get("name", config.get("agentName")), "name", surface, result)
            or "unnamed-client"
        )
        card_url = as_text(
            config.get("agentCardUrl", config.get("url", config.get("endpoint"))),
            "agentCardUrl",
            surface,
            result,
        )
        auth_methods = _auth_method_names(
            config.get("authMethods", config.get("authentication")), name, surface, result
        )

        risks: list[RiskAssessment] = []

        if card_url and not card_url.lower().startswith("https://"):
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
            authentication_methods=auth_methods,
            source_path=str(config_path),
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
            risks=risks,
        )

    def _scan_code_patterns(self, root: Path, result: ScanResult) -> bool:
        """Detect A2A SDK usage in top-level and src/ Python files."""
        py_files = sorted(root.glob("*.py"))
        src_dir = root / "src"
        if src_dir.is_dir():
            py_files.extend(sorted(src_dir.glob("*.py")))
        if len(py_files) > CODE_SCAN_LIMIT:
            result.record_excluded(
                "a2a-code", f"only the first {CODE_SCAN_LIMIT} Python files are scanned"
            )

        found = False
        for py_file in py_files[:CODE_SCAN_LIMIT]:
            surface = f"a2a-code {relative_posix(py_file, root)}"
            if excluded_before_read(py_file, root, self.exclude_paths, surface, result):
                continue
            if not py_file.is_file():
                continue
            try:
                content = read_regular_text(py_file)
            except OSError:
                result.record_excluded(surface, "unreadable or not a regular file; not followed")
                continue
            except UnicodeError:
                result.record_excluded(surface, "not UTF-8 text; not scanned")
                continue

            if not any(p.search(content) for p in _A2A_CODE_PATTERNS):
                continue
            found = True
            result.surfaces_scanned.append(surface)
            if not any(c.bom_ref.startswith("a2a-") for c in result.components):
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
        return found


def _parse_config(
    config_name: str, text: str, surface: str, result: ScanResult
) -> dict[str, Any] | None:
    if config_name.endswith((".yaml", ".yml")):
        return _parse_yaml_object(text, surface, result)
    return parse_json_object(text, surface, result)


def _parse_yaml_object(text: str, surface: str, result: ScanResult) -> dict[str, Any] | None:
    try:
        yaml = import_module("yaml")
    except ImportError:
        result.record_failure(f"YAML support unavailable for {surface}")
        return None
    try:
        data: object = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError):
        result.record_failure(f"{surface}: malformed YAML")
        return None
    if not isinstance(data, dict):
        result.record_failure(f"{surface}: top-level value is not an object")
        return None
    return data


def _string_list(value: object, label: str, surface: str, result: ScanResult) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        result.record_failure(f"{surface}: {label} is neither a string nor a list; ignored")
        return []
    items = [item for item in value if isinstance(item, str)]
    if len(items) != len(value):
        result.record_failure(f"{surface}: {label} has non-string entries; they are ignored")
    return items


def _skill_names(value: object, surface: str, result: ScanResult) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        result.record_failure(f"{surface}: skills is not a list; ignored")
        return []
    names: list[str] = []
    skipped = 0
    for skill in value:
        if isinstance(skill, str):
            names.append(skill)
        elif isinstance(skill, dict) and isinstance(
            skill.get("name", skill.get("id", "unknown")), str
        ):
            names.append(skill.get("name", skill.get("id", "unknown")))
        else:
            skipped += 1
    if skipped:
        result.record_failure(f"{surface}: {skipped} skill entries have no string name; ignored")
    return names


def _auth_method_names(value: object, owner: str, surface: str, result: ScanResult) -> list[str]:
    """Names of the authentication methods only. Credential and header values are never read."""
    if value is None:
        return []
    candidates: list[object]
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list):
        candidates = list(value)
    elif isinstance(value, dict):
        schemes = value.get("schemes")
        if isinstance(schemes, str):
            candidates = [schemes]
        elif isinstance(schemes, list):
            candidates = list(schemes)
        else:
            candidates = [key for key in value if str(key).lower() not in _CREDENTIAL_KEYS]
    else:
        result.record_failure(
            f"{surface}: authentication for '{owner}' has an unsupported type; ignored"
        )
        return []

    names = [
        item for item in candidates if isinstance(item, str) and _AUTH_METHOD_NAME.fullmatch(item)
    ]
    rejected = len(candidates) - len(names)
    if rejected:
        result.record_failure(
            f"{surface}: {rejected} authentication entries for '{owner}' are not plain "
            "method names; not recorded"
        )
    return names
