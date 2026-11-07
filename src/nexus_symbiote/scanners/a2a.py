"""Bounded offline A2A card, client configuration and SDK-reference collection."""

from __future__ import annotations

import ast
import hmac
import os
import re
from pathlib import Path
from typing import Any, NamedTuple
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
from nexus_symbiote.utils.secrets import REDACTED, redact_text

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
# Requirements list scopes for these types and role names for the others, as in OpenAPI.
SCOPED_SCHEME_TYPES = frozenset({"oauth2", "openIdConnect"})
_MAX_ENTRIES = 1000
_MAX_DEPTH = 8
_ORIGIN_PATHS = frozenset({"", "/"})
_CARD_PATHS = _ORIGIN_PATHS | {"/.well-known/agent.json", "/.well-known/agent-card.json"}
_HOSTNAME = re.compile(r"[\w.-]+|[0-9a-f:.]+")
# Credential formats that redact_text leaves intact; no OAuth scope takes these forms.
_TOKEN_SHAPE = re.compile(
    r"eyJ[\w-]{8,}\.[\w-]{8,}"
    r"|(?<![\w-])(?:gh[oprsu]_|github_pat_|glpat-|xox[abeoprs]-|sk-|[rs]k_live_|AKIA|ASIA|AIza)"
    r"[\w-]{12,}"
)


class _BindingError(ValueError):
    pass


class _Security(NamedTuple):
    required: bool
    scopes: list[str]
    scheme_types: list[str]
    scheme_urls: list[str]
    structure: dict[str, Any]
    unbound: list[str]


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if (
        not isinstance(value, list)
        or len(value) > _MAX_ENTRIES
        or not all(isinstance(item, str) for item in value)
    ):
        raise ValueError("invalid string-list declaration")
    return value


def _strings(value: Any) -> list[str]:
    return [redact_text(item) for item in _string_list(value)]


def _fields(declaration: dict[str, Any]) -> list[str]:
    if len(declaration) > _MAX_ENTRIES:
        raise ValueError("oversized declaration")
    return sorted(redact_text(key) for key in declaration)


def _scope(value: str) -> str:
    """Export a scope, a public identifier (RFC 6749 section 3.3), unless it may be a secret."""
    if _TOKEN_SHAPE.search(value):
        return REDACTED
    redacted = redact_text(value)
    if redacted == value:
        return value
    try:
        parsed = urlsplit(value)
    except ValueError:
        return redacted
    # Scope URIs such as https://www.googleapis.com/auth/drive.readonly name the
    # permission in their path, which redact_text would cut down to the origin.
    locator = parsed.netloc + parsed.path
    if (
        parsed.scheme
        and parsed.netloc
        and not any(char in "@?#" or char.isspace() for char in value)
        and redact_text(locator) == locator
    ):
        return value
    return redacted


def _odd_host(url: str) -> bool:
    """urlsplit keeps "host\\path" in the host, where WHATWG parsers read a path."""
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return True
    return hostname is not None and not _HOSTNAME.fullmatch(hostname)


def _origin(url: str) -> str:
    return "[redacted]" if _odd_host(url) else sanitized_origin(url)


def _url_shape(url: str | None, plain_paths: frozenset[str]) -> dict[str, Any] | None:
    """Describe what an origin-only export omits from a URL, without the values."""
    if url is None:
        return None
    try:
        parsed = urlsplit(url)
    except ValueError:
        return {"valid": False}
    return {
        "path_separators": parsed.path.count("/"),
        "plain_path": parsed.path if parsed.path in plain_paths else None,
        "query": bool(parsed.query),
        "fragment": bool(parsed.fragment),
        "userinfo": "@" in parsed.netloc,
    }


def _url_shapes(urls: list[str]) -> list[dict[str, Any] | None]:
    return sorted((_url_shape(url, _ORIGIN_PATHS) for url in urls), key=canonical_json)


def _beyond_origin(url: str, plain_paths: frozenset[str]) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return True
    return (
        parsed.path not in plain_paths
        or bool(parsed.query or parsed.fragment)
        or "@" in parsed.netloc
        or _odd_host(url)
    )


def _declared_urls(value: Any, depth: int = 0) -> list[str]:
    """Collect URL fields, such as tokenUrl, wherever a declaration nests them."""
    if depth > _MAX_DEPTH:
        raise ValueError("declaration nested too deeply")
    if isinstance(value, list):
        if len(value) > _MAX_ENTRIES:
            raise ValueError("oversized declaration")
        urls = [url for item in value for url in _declared_urls(item, depth + 1)]
    elif isinstance(value, dict):
        if len(value) > _MAX_ENTRIES:
            raise ValueError("oversized declaration")
        urls = []
        for key, item in value.items():
            if isinstance(item, str) and key.lower().endswith(("url", "uri")):
                urls.append(item)
            elif key != "scopes":
                urls.extend(_declared_urls(item, depth + 1))
    else:
        return []
    if len(urls) > _MAX_ENTRIES:
        raise ValueError("oversized declaration")
    return urls


def _value_binding(profile: str, declaration: dict[str, Any]) -> dict[str, str]:
    key = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if not key:
        return {}
    if len(key) < _MIN_SOURCE_BINDING_KEY_LENGTH:
        raise _BindingError(
            f"{SOURCE_BINDING_KEY_ENV} must contain at least "
            f"{_MIN_SOURCE_BINDING_KEY_LENGTH} characters"
        )
    try:
        message = canonical_json({"profile": profile, "configuration": declaration})
    except ValueError as exc:
        raise _BindingError(
            f"{SOURCE_BINDING_KEY_ENV} binding needs RFC 8785 JSON values; "
            "quote YAML dates and timestamps"
        ) from exc
    material = key.encode()
    key_id = hmac.new(material, b"nexus-symbiote/source-binding-key-id", "sha256").hexdigest()
    return {
        "static_value_binding": "hmac-sha256:"
        + hmac.new(material, message.encode(), "sha256").hexdigest(),
        "static_value_binding_key_id": key_id[:32],
        "static_value_binding_profile": profile,
    }


def _security(data: dict[str, Any]) -> _Security:
    """Read declared requirements; a card cannot show that an endpoint enforces them."""
    schemes = data.get("securitySchemes")
    schemes = {} if schemes is None else schemes
    if not isinstance(schemes, dict) or len(schemes) > _MAX_ENTRIES:
        raise ValueError("invalid security schemes")
    kinds: dict[str, str] = {}
    typed: set[str] = set()
    for scheme_name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            raise ValueError("invalid security scheme")
        declared = scheme.get("type")
        declared = "" if declared is None else declared
        if not isinstance(declared, str):
            raise ValueError("invalid security scheme type")
        kinds[scheme_name] = declared if declared in SECURITY_SCHEME_TYPES else "other"
        if declared.strip():
            typed.add(scheme_name)
    scheme_urls = _declared_urls(schemes)
    decisions: list[bool] = []
    scopes: set[str] = set()
    redacted_scopes = role_names = False
    alternatives: list[dict[str, list[str] | int]] | None = None
    requirements = data.get("security")
    if requirements is not None:
        if not isinstance(requirements, list) or len(requirements) > _MAX_ENTRIES:
            raise ValueError("invalid security requirements")
        alternatives, entries = [], 0
        for requirement in requirements:
            if not isinstance(requirement, dict):
                raise ValueError("invalid security requirement")
            alternative: dict[str, list[str] | int] = {}
            for scheme_name, required in requirement.items():
                entries += 1 + (len(required) if isinstance(required, list) else 0)
                if not isinstance(required, list) or entries > _MAX_ENTRIES:
                    raise ValueError("invalid or oversized security requirement")
                named = _string_list(required)
                if kinds.get(scheme_name) in SCOPED_SCHEME_TYPES:
                    exported = {scope: _scope(scope) for scope in named}
                    redacted_scopes |= any(scope != kept for scope, kept in exported.items())
                    alternative[redact_text(scheme_name)] = sorted(set(exported.values()))
                    scopes.update(exported.values())
                else:
                    # Role names may be anything, so only the key binds them.
                    role_names |= bool(named)
                    alternative[redact_text(scheme_name)] = len(named)
            alternatives.append(alternative)
        # An empty alternative ({}) permits anonymous access, as in OpenAPI.
        decisions.append(
            bool(requirements)
            and all(requirement and set(requirement) <= typed for requirement in requirements)
        )
    legacy = data.get("authentication")
    legacy_count = None
    if legacy is not None:
        if not isinstance(legacy, dict):
            raise ValueError("invalid authentication declaration")
        named_schemes = legacy.get("schemes")
        named_schemes = [] if named_schemes is None else named_schemes
        if not isinstance(named_schemes, list):
            raise ValueError("invalid authentication schemes")
        legacy_count = sum(1 for scheme in _string_list(named_schemes) if scheme.strip())
        decisions.append(legacy_count > 0)
    structure = {
        "security_schemes": sorted([redact_text(name), kind] for name, kind in kinds.items()),
        "security_scheme_urls": _url_shapes(scheme_urls),
        "security": (None if alternatives is None else sorted(alternatives, key=canonical_json)),
        "authentication_schemes": legacy_count,
    }
    unbound = [
        label
        for label, gap in (
            (
                "security scheme URL paths or queries",
                any(_beyond_origin(url, _ORIGIN_PATHS) for url in scheme_urls),
            ),
            ("redacted OAuth scopes", redacted_scopes),
            ("role names in security requirements", role_names),
        )
        if gap
    ]
    return _Security(
        required=bool(decisions) and all(decisions),
        scopes=sorted(scopes),
        scheme_types=sorted(set(kinds.values())),
        scheme_urls=scheme_urls,
        structure=structure,
        unbound=unbound,
    )


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
                except _BindingError as exc:
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
                    except _BindingError as exc:
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
        security = _security(data)
        # Clients may send credentials to these alternative endpoints too.
        interface_urls = _declared_urls(data.get("additionalInterfaces"))
        structure_hash = hash_canonical(
            {
                "profile": CARD_STRUCTURE_PROFILE,
                "structure": {
                    "fields": _fields(data),
                    "endpoint": _url_shape(endpoint, _ORIGIN_PATHS),
                    "additional_interfaces": _url_shapes(interface_urls),
                    **security.structure,
                },
            }
        )
        binding = _value_binding(CARD_VALUE_BINDING_PROFILE, data)
        unbound = [
            label
            for label, gap in (
                (
                    "endpoint path, query or user information",
                    endpoint is not None and _beyond_origin(endpoint, _ORIGIN_PATHS),
                ),
                (
                    "additional interface URL paths or queries",
                    any(_beyond_origin(url, _ORIGIN_PATHS) for url in interface_urls),
                ),
            )
            if gap
        ] + security.unbound
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
        if not security.required:
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
        if unbound and not binding:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=f"A2A agent '{name}' values not bound in this inventory: {'; '.join(unbound)}.",
                    recommendation=f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes to these values.",
                )
            )
        return A2AServerComponent(
            bom_ref=f"a2a-server:{name}",
            name=name,
            version=redact_text(version) if version else None,
            agent_card_path=rel_path,
            endpoint_url=_origin(endpoint) if endpoint else None,
            supported_protocols=protocols,
            skills_declared=skills,
            authentication_required=security.required,
            capabilities=(
                CapabilityDeclaration(oauth_scopes=security.scopes) if security.scopes else None
            ),
            source_path=str(card_path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
            properties={
                "collection_mode": "static-agent-card",
                "authentication_evidence": "declaration-only",
                "security_scheme_types": security.scheme_types,
                "security_scheme_origins": sorted({_origin(url) for url in security.scheme_urls}),
                "additional_interface_origins": sorted({_origin(url) for url in interface_urls}),
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
                "structure": {
                    "fields": _fields(config),
                    "card_url": _url_shape(card_url, _CARD_PATHS),
                },
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
                    detail=f"A2A client '{name}' agent card URL path, query or user information is not bound in this inventory.",
                    recommendation=f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect same-origin card changes.",
                )
            )
        return A2AClientComponent(
            bom_ref=f"a2a-client:{name}",
            name=name,
            agent_card_url=_origin(card_url) if card_url else None,
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
