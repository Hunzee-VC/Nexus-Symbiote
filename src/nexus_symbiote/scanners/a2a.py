"""Bounded offline A2A card, client configuration and SDK-reference collection."""

from __future__ import annotations

import ast
import hmac
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import canonical_json, hash_canonical
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    CapabilityDeclaration,
    RiskAssessment,
)
from nexus_symbiote.scanners.base import Scanner, ScanResult, parse_python, sanitized_origin
from nexus_symbiote.scanners.mcp import _MIN_SOURCE_BINDING_KEY_LENGTH, SOURCE_BINDING_KEY_ENV
from nexus_symbiote.utils.secrets import redact_text

AGENT_CARD_FILES = [
    ".well-known/agent.json",
    ".well-known/agent-card.json",
    "agent.json",
    "agent-card.json",
    "a2a/agent.json",
]
A2A_CONFIG_FILES = ["a2a.json", "a2a.yaml", "a2a.yml", "a2a_config.json"]

# Exports keep only URL origins, and paths or queries may carry credentials, so no
# unkeyed digest covers them: it would let anyone holding the BOM confirm guesses.
# The structure digests cover names, counts, flags and values exported in clear.
# Other values are bound only by an HMAC under the operator key, as for MCP.
CARD_STRUCTURE_PROFILE = "nexus-symbiote/a2a-card-structure/v1"
CARD_VALUE_BINDING_PROFILE = "nexus-symbiote/a2a-card-values/v1"
CLIENT_STRUCTURE_PROFILE = "nexus-symbiote/a2a-client-structure/v1"
CLIENT_VALUE_BINDING_PROFILE = "nexus-symbiote/a2a-client-values/v1"
SECURITY_SCHEME_TYPES = frozenset({"apiKey", "http", "oauth2", "openIdConnect", "mutualTLS"})
_MAX_ENTRIES = 1000
_ORIGIN_PATHS = frozenset({"", "/"})
_CARD_PATHS = _ORIGIN_PATHS | {"/.well-known/agent.json", "/.well-known/agent-card.json"}


class _BindingKeyError(ValueError):
    pass


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if (
        not isinstance(value, list)
        or len(value) > _MAX_ENTRIES
        or not all(isinstance(item, str) for item in value)
    ):
        raise ValueError("invalid string-list declaration")
    return [redact_text(item) for item in value]


def _fields(declaration: dict[str, Any]) -> list[str]:
    if len(declaration) > _MAX_ENTRIES:
        raise ValueError("oversized declaration")
    return sorted(redact_text(key) for key in declaration)


def _url_shape(url: str | None) -> dict[str, Any] | None:
    """Describe what an origin-only export omits from a URL, without the values."""
    if url is None:
        return None
    try:
        parsed = urlsplit(url)
    except ValueError:
        return {"valid": False}
    return {
        "path_separators": parsed.path.count("/"),
        "query": bool(parsed.query),
        "fragment": bool(parsed.fragment),
        "userinfo": "@" in parsed.netloc,
    }


def _beyond_origin(url: str, plain_paths: frozenset[str]) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return True
    return (
        parsed.path not in plain_paths
        or bool(parsed.query or parsed.fragment)
        or "@" in parsed.netloc
    )


def _value_binding(profile: str, declaration: dict[str, Any]) -> dict[str, str]:
    key = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if not key:
        return {}
    if len(key) < _MIN_SOURCE_BINDING_KEY_LENGTH:
        raise _BindingKeyError(f"{SOURCE_BINDING_KEY_ENV} must contain at least 32 characters")
    material = key.encode()
    message = canonical_json({"profile": profile, "configuration": declaration})
    key_id = hmac.new(material, b"nexus-symbiote/source-binding-key-id", "sha256").hexdigest()
    return {
        "static_value_binding": "hmac-sha256:"
        + hmac.new(material, message.encode(), "sha256").hexdigest(),
        "static_value_binding_key_id": key_id[:32],
        "static_value_binding_profile": profile,
    }


def _security(data: dict[str, Any]) -> tuple[bool, list[str], list[str], dict[str, Any]]:
    """Read declared requirements; a card cannot show that an endpoint enforces them."""
    schemes = data.get("securitySchemes", {})
    if not isinstance(schemes, dict) or len(schemes) > _MAX_ENTRIES:
        raise ValueError("invalid security schemes")
    kinds: dict[str, str] = {}
    for scheme_name, scheme in schemes.items():
        declared = scheme.get("type", "") if isinstance(scheme, dict) else None
        if not isinstance(declared, str):
            raise ValueError("invalid security scheme")
        kinds[scheme_name] = declared if declared in SECURITY_SCHEME_TYPES else "other"
    decisions: list[bool] = []
    scopes: set[str] = set()
    alternatives: list[dict[str, list[str]]] | None = None
    requirements = data.get("security")
    if requirements is not None:
        if not isinstance(requirements, list) or len(requirements) > _MAX_ENTRIES:
            raise ValueError("invalid security requirements")
        alternatives, entries = [], 0
        for requirement in requirements:
            if not isinstance(requirement, dict):
                raise ValueError("invalid security requirement")
            alternative: dict[str, list[str]] = {}
            for scheme_name, required in requirement.items():
                entries += 1 + (len(required) if isinstance(required, list) else 0)
                if not isinstance(required, list) or entries > _MAX_ENTRIES:
                    raise ValueError("invalid or oversized security requirement")
                required_scopes = sorted(set(_strings(required)))
                alternative[redact_text(scheme_name)] = required_scopes
                scopes.update(required_scopes)
            alternatives.append(alternative)
        # An empty alternative ({}) permits anonymous access, as in OpenAPI.
        decisions.append(
            bool(requirements)
            and all(requirement and set(requirement) <= set(kinds) for requirement in requirements)
        )
    legacy = data.get("authentication")
    legacy_count = None
    if legacy is not None:
        if not isinstance(legacy, dict) or not isinstance(legacy.get("schemes", []), list):
            raise ValueError("invalid authentication declaration")
        legacy_count = len(_strings(legacy.get("schemes", [])))
        decisions.append(legacy_count > 0)
    structure = {
        "security_schemes": sorted([redact_text(name), kind] for name, kind in kinds.items()),
        "security": (None if alternatives is None else sorted(alternatives, key=canonical_json)),
        "authentication_schemes": legacy_count,
    }
    required = bool(decisions) and all(decisions)
    return required, sorted(scopes), sorted(set(kinds.values())), structure


class A2AScanner(Scanner):
    name = "a2a"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(project_root, result) as files:
            for relative in AGENT_CARD_FILES:
                path = files.root / relative
                data = self._read_mapping(path, result)
                if data is None:
                    continue
                result.surfaces_scanned.append(str(path))
                try:
                    result.components.append(self._parse_agent_card(data, relative, path))
                except _BindingKeyError as exc:
                    result.scan_failures.append(f"{relative}: {exc}")
                except (TypeError, ValueError, RecursionError):
                    result.scan_failures.append(f"{relative}: invalid A2A card field types")
            for relative in A2A_CONFIG_FILES:
                path = files.root / relative
                data = self._read_mapping(path, result)
                if data is None:
                    continue
                result.surfaces_scanned.append(str(path))
                clients = data.get("clients", data.get("remoteAgents", []))
                if not isinstance(clients, list) or len(clients) > 1000:
                    result.scan_failures.append(f"{relative}: invalid or oversized A2A client list")
                    continue
                for client in clients:
                    try:
                        if not isinstance(client, dict):
                            raise ValueError("invalid client")
                        result.components.append(self._parse_a2a_client(client, path))
                    except _BindingKeyError as exc:
                        result.scan_failures.append(f"{relative}: {exc}")
                    except (TypeError, ValueError, RecursionError):
                        result.scan_failures.append(f"{relative}: invalid A2A client field types")
            self._scan_code_patterns(files.root, result)
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("a2a (no A2A configurations found)")
        return result

    def _parse_agent_card(
        self, data: dict[str, Any], rel_path: str, card_path: Path
    ) -> A2AServerComponent:
        name, version = data.get("name", "unnamed-agent"), data.get("version")
        endpoint = data.get("url") or data.get("endpoint")
        if (
            not isinstance(name, str)
            or (version is not None and not isinstance(version, str))
            or (endpoint is not None and not isinstance(endpoint, str))
        ):
            raise ValueError("invalid card identity")
        name = redact_text(name)
        protocols = _strings(data.get("protocols", []))
        declared_skills = data.get("skills", [])
        if not isinstance(declared_skills, list) or len(declared_skills) > 1000:
            raise ValueError("invalid skills")
        skills = []
        for skill in declared_skills:
            if isinstance(skill, dict):
                skill = skill.get("name", skill.get("id", "unknown"))
            if not isinstance(skill, str):
                raise ValueError("invalid skill name")
            skills.append(redact_text(skill))
        # This records declarations only; neither a card nor this collector proves
        # that an endpoint actually enforces authentication.
        auth_required, scopes, scheme_types, security = _security(data)
        structure_hash = hash_canonical(
            {
                "profile": CARD_STRUCTURE_PROFILE,
                "structure": {
                    "fields": _fields(data),
                    "endpoint": _url_shape(endpoint),
                    **security,
                },
            }
        )
        binding = _value_binding(CARD_VALUE_BINDING_PROFILE, data)
        path_bound = bool(binding) or not (endpoint and _beyond_origin(endpoint, _ORIGIN_PATHS))
        risks: list[RiskAssessment] = []
        if endpoint and not endpoint.lower().startswith("https://"):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"A2A agent '{name}' declares an endpoint without HTTPS.",
                    recommendation="Use authenticated HTTPS transport for agent endpoints.",
                )
            )
        if not auth_required:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="authentication",
                    detail=f"A2A agent '{name}' has no nonempty authentication requirement declared.",
                    recommendation="Declare and independently verify endpoint authentication requirements.",
                )
            )
        if not skills:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=f"A2A agent '{name}' declares no skills in its agent card.",
                    recommendation="Document declared skills and separately verify effective capabilities.",
                )
            )
        if not path_bound:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=f"A2A agent '{name}' endpoint beyond its origin is not bound in this inventory.",
                    recommendation=f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect same-origin endpoint changes.",
                )
            )
        return A2AServerComponent(
            bom_ref=f"a2a-server:{name}",
            name=name,
            version=redact_text(version) if version else None,
            agent_card_path=rel_path,
            endpoint_url=sanitized_origin(endpoint) if endpoint else None,
            supported_protocols=protocols,
            skills_declared=skills,
            authentication_required=auth_required,
            capabilities=CapabilityDeclaration(oauth_scopes=scopes) if scopes else None,
            source_path=str(card_path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
            properties={
                "collection_mode": "static-agent-card",
                "authentication_evidence": "declaration-only",
                "security_scheme_types": scheme_types,
                "source_values_bound": bool(binding),
                "static_card_hash": structure_hash,
                "static_card_hash_profile": CARD_STRUCTURE_PROFILE,
                **binding,
            },
        )

    def _parse_a2a_client(self, config: dict[str, Any], config_path: Path) -> A2AClientComponent:
        name = config.get("name", config.get("agentName", "unnamed-client"))
        card_url = config.get("agentCardUrl", config.get("url", config.get("endpoint")))
        auth_methods = config.get("authMethods", config.get("authentication", []))
        if isinstance(auth_methods, dict):
            auth_methods = list(auth_methods)
        auth_methods = _strings(auth_methods)
        if not isinstance(name, str) or (card_url is not None and not isinstance(card_url, str)):
            raise ValueError("invalid client identity")
        name = redact_text(name)
        structure_hash = hash_canonical(
            {
                "profile": CLIENT_STRUCTURE_PROFILE,
                "structure": {"fields": _fields(config), "card_url": _url_shape(card_url)},
            }
        )
        binding = _value_binding(CLIENT_VALUE_BINDING_PROFILE, config)
        path_bound = bool(binding) or not (card_url and _beyond_origin(card_url, _CARD_PATHS))
        risks = []
        if card_url and not card_url.lower().startswith("https://"):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"A2A client '{name}' declares an insecure endpoint transport.",
                    recommendation="Use authenticated HTTPS for agent card retrieval.",
                )
            )
        if not auth_methods:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="authentication",
                    detail=f"A2A client '{name}' has no authentication method declared.",
                    recommendation="Configure and independently verify remote-agent authentication.",
                )
            )
        if not path_bound:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=f"A2A client '{name}' agent card URL beyond its origin is not bound in this inventory.",
                    recommendation=f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect same-origin card changes.",
                )
            )
        return A2AClientComponent(
            bom_ref=f"a2a-client:{name}",
            name=name,
            agent_card_url=sanitized_origin(card_url) if card_url else None,
            authentication_methods=auth_methods,
            source_path=str(config_path),
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
            properties={
                "collection_mode": "static-config",
                "remote_agent_contacted": False,
                "source_values_bound": bool(binding),
                "static_config_hash": structure_hash,
                "static_config_hash_profile": CLIENT_STRUCTURE_PROFILE,
                **binding,
            },
        )

    def _scan_code_patterns(self, root: Path, result: ScanResult) -> None:
        if self._files is None:
            raise RuntimeError("_scan_code_patterns called outside a _collection context")
        sources = [
            path
            for path in self._files.iter_files()
            if path.suffix == ".py"
            and (len(path.parts) == 1 or (len(path.parts) == 2 and path.parts[0] == "src"))
        ]
        if len(sources) > 20:
            result.scan_failures.append("a2a code references: 20-file collection limit exceeded")
        for path in sources[:20]:
            content = self._files.read_text(path)
            if content is None:
                continue
            result.surfaces_scanned.append(str(root / path))
            if len(content) > 262_144:
                result.scan_failures.append(f"{path}: syntax collection size limit exceeded")
                continue
            try:
                tree = parse_python(content)
            except (SyntaxError, ValueError, RecursionError):
                result.scan_failures.append(f"{path}: invalid Python syntax")
                continue
            detected = any(
                (
                    isinstance(node, ast.ImportFrom)
                    and node.module is not None
                    and node.module.split(".")[0] == "a2a"
                )
                or (
                    isinstance(node, ast.Import)
                    and any(alias.name.split(".")[0] == "a2a" for alias in node.names)
                )
                or (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in {"A2AClient", "AgentCard"}
                )
                for node in ast.walk(tree)
            )
            if detected and not any(
                component.bom_ref.startswith("a2a-") for component in result.components
            ):
                result.components.append(
                    A2AClientComponent(
                        bom_ref="a2a-client:code-detected",
                        name="a2a-client (code-detected)",
                        source_path=str(root / path),
                        trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                        properties={"collection_mode": "static-syntax-reference"},
                        risks=[
                            RiskAssessment(
                                severity=RiskSeverity.INFO,
                                category="detection_method",
                                detail="A2A SDK reference detected in Python syntax; deployment not verified.",
                                recommendation="Add explicit client configuration and deployment evidence.",
                            )
                        ],
                    )
                )
