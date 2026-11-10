"""MCP server and tool scanner.

Discovers MCP server configurations from:
  - .mcp.json (project-level MCP config)
  - claude_desktop_config.json
  - mcp.json
  - .cursor/mcp.json
  - package.json (mcp-related dependencies)

For each server, extracts tool definitions, computes canonical hashes,
and detects unpinned versions, missing transport security, and rug-pull risk.
"""

from __future__ import annotations

import ast
import hmac
import ipaddress
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from nexus_symbiote.core.enums import (
    CapabilityClass,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    canonical_json,
    extract_version_pin,
    hash_canonical,
    hash_tool_definition,
)
from nexus_symbiote.core.models import (
    CapabilityDeclaration,
    MCPClientComponent,
    MCPServerComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.scanners.base import (
    MAX_SOURCE_BYTES,
    Scanner,
    ScanResult,
    SourceBudget,
    parse_python,
    sanitized_origin,
)
from nexus_symbiote.utils.confined import MAX_TOTAL_BYTES
from nexus_symbiote.utils.secrets import REDACTED, redact_descriptor, redact_text

MCP_CONFIG_FILES = [
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    ".cursor/mcp.json",
    ".claude/mcp.json",
]

# The same names below the root: a package's own configuration, and the files
# other hosts read (.vscode/mcp.json, .windsurf/mcp_config.json, ...).
MCP_CONFIG_NAMES = frozenset(
    {
        ".mcp.json",
        "mcp.json",
        "mcp-config.json",
        "mcp_config.json",
        "mcp-servers.json",
        "claude_desktop_config.json",
        "cline_mcp_settings.json",
    }
)
_HOST_DIRECTORIES = {
    ".claude": "claude-code",
    ".cursor": "cursor",
    ".vscode": "vscode",
    ".windsurf": "windsurf",
    ".roo": "roo",
    ".amazonq": "amazon-q",
    ".kiro": "kiro",
    ".cline": "cline",
}

_SDK_IMPORT = re.compile(
    r"(?:\bfrom\s*[\"']@modelcontextprotocol/sdk(?:/[^\"']*)?[\"']|"
    r"\brequire\s*\(\s*[\"']@modelcontextprotocol/sdk(?:/[^\"']*)?[\"'])"
)
_SPACE = re.compile(r"\s*")
_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
# Fixed width on purpose: "HTTPServer" splits before the capital that starts "Server".
_ACRONYM_BOUNDARY = re.compile(r"([A-Z])([A-Z][a-z])")
_WORD = re.compile(r"[a-z0-9]+")
_WORD_ENDINGS = ("s", "es", "ed", "d", "ing")


def without_js_comments(text: str) -> str:
    """Drop block comments and whole-line ``//`` comments in one linear pass.

    The pattern this replaces rescanned every run of blank lines from each of its
    lines, so a file of newlines within the size limit took minutes.
    """
    kept: list[str] = []
    size = len(text)
    emitted = position = line_from = 0
    block = text.find("/*")
    close = -1
    line: tuple[int, int] | None = None
    while position < size:
        if 0 <= block < position:
            block = text.find("/*", position)
        if block >= 0:
            close = text.find("*/", block + 2)
            if close < 0:
                block = -1
        if line is None or line[0] < position:
            line = None
            start = max(position, line_from)
            if start and text[start - 1] != "\n":
                newline = text.find("\n", start)
                start = size if newline < 0 else newline + 1
            while start < size:
                indent = _SPACE.match(text, start)
                content = indent.end() if indent else start
                newline = text.find("\n", content)
                if text.startswith("//", content):
                    line = (start, size if newline < 0 else newline)
                    break
                start = size if newline < 0 else newline + 1
            line_from = start
        if block >= 0 and (line is None or block <= line[0]):
            begin, end = block, close + 2
        elif line is not None:
            begin, end = line
        else:
            break
        kept.append(text[emitted:begin])
        emitted = position = end
        if end == begin:
            position += 1
    kept.append(text[emitted:])
    return "".join(kept)


_NPM_NAME = r"(?:@[A-Za-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]*"
_OCI_REPOSITORY = (
    r"(?:[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]+)?/)?"
    r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*"
)

# Exported bindings must not be computable from secret values: an unkeyed digest
# over credentials lets anyone holding the BOM confirm guesses offline. The
# structure digest covers only fields the inventory already exports in clear.
# Values are bound by an HMAC under an operator key that never enters the BOM.
STATIC_CONFIG_HASH_PROFILE = "nexus-symbiote/mcp-static-config/v2"
STATIC_VALUE_BINDING_PROFILE = "nexus-symbiote/mcp-static-values/v1"
SOURCE_BINDING_KEY_ENV = "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY"
_MIN_SOURCE_BINDING_KEY_LENGTH = 32


def _value_binding(config: dict[str, Any]) -> tuple[str, str] | None:
    key = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if not key:
        return None
    if len(key) < _MIN_SOURCE_BINDING_KEY_LENGTH:
        raise ValueError(f"{SOURCE_BINDING_KEY_ENV} must contain at least 32 characters")
    material = key.encode()
    message = canonical_json({"profile": STATIC_VALUE_BINDING_PROFILE, "configuration": config})
    mac = hmac.new(material, message.encode(), "sha256").hexdigest()
    key_id = hmac.new(material, b"nexus-symbiote/source-binding-key-id", "sha256").hexdigest()
    return "hmac-sha256:" + mac, key_id[:32]


def _has_userinfo(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    return parsed.username is not None or parsed.password is not None


def _has_path_or_query(url: object) -> bool:
    if not isinstance(url, str):
        return False
    try:
        parsed = urlsplit(url)
    except ValueError:
        return True
    return parsed.path not in {"", "/"} or bool(parsed.query)


# Index, registry and find-links options decide where a launcher fetches its package.
# Without credentials they are not secret, so the unkeyed digest binds them.
_SOURCE_OPTIONS = frozenset(
    {
        "-i",
        "-f",
        "--index",
        "--default-index",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--registry",
    }
)


def _package_sources(args: list[str], secrets: list[str]) -> list[str]:
    sources = []
    for index, arg in enumerate(args):
        name, separator, value = arg.partition("=")
        if name not in _SOURCE_OPTIONS:
            continue
        if not separator:
            value = args[index + 1] if index + 1 < len(args) else ""
        if "://" in value:
            parts = urlsplit(value)
            try:
                port = f":{parts.port}" if parts.port else ""
            except ValueError:
                # Never hash an unparsed authority: it may hold credentials.
                sources.append(f"{name}=[unparsed]")
                continue
            value = f"{parts.scheme}://{parts.hostname or ''}{port}{parts.path}"
        sources.append(f"{name}={redact_text(value, secrets)}")
    return sorted(sources)


# Short environment values are flags such as "1" or "true", not credentials. Matching
# them against package names would silently discard ordinary launcher identities.
_MIN_IDENTITY_SECRET_LENGTH = 8
# npm resolves these specs to a local directory or tarball, not a registry package.
_NPM_LOCAL_SPEC = re.compile(r"(?:^|@)\.|\.(?:tgz|tar|tar\.gz)$", re.IGNORECASE)
# Options that make uvx or pipx resolve the package from somewhere other than PyPI.
_PYTHON_SOURCE_OPTIONS = frozenset(
    {
        "-i",
        "-f",
        "--index",
        "--default-index",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--pip-args",
    }
)


class MCPScanner(Scanner):
    name = "mcp"

    def scan(self, project_root: Path, *, config_only: bool = False) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        found_any = False
        clients: dict[str, MCPClientComponent] = {}

        limits = {"max_total_bytes": MAX_TOTAL_BYTES + MAX_SOURCE_BYTES}
        with self._collection(project_root, result, **limits) as files:
            sources = list(files.iter_files())
            nested = sorted(
                {path.as_posix() for path in sources if path.name in MCP_CONFIG_NAMES}
                - set(MCP_CONFIG_FILES)
            )
            for config_name in (*MCP_CONFIG_FILES, *nested):
                config_path = files.root / config_name
                data = files.read_json(config_name, missing_ok=True)
                if data is None:
                    continue
                found_any = True
                result.surfaces_scanned.append(str(config_path))
                if not isinstance(data, dict):
                    result.scan_failures.append(f"{config_name}: expected a configuration object")
                    continue
                servers = data.get("mcpServers", data.get("servers", {}))
                if not isinstance(servers, dict) or len(servers) > 1000:
                    result.scan_failures.append(f"{config_name}: invalid or oversized server map")
                    continue
                server_refs: list[str] = []
                for server_name, server_config in sorted(servers.items()):
                    if not isinstance(server_config, dict) or not self._valid_server(server_config):
                        result.scan_failures.append(f"{config_name}: invalid server configuration")
                        continue
                    try:
                        mcp_comp, tool_comps = self._parse_server(
                            server_name, server_config, config_path
                        )
                    except (TypeError, ValueError, RecursionError):
                        result.scan_failures.append(f"{config_name}: invalid tool definition")
                        continue
                    result.components.append(mcp_comp)
                    result.components.extend(tool_comps)
                    server_refs.append(mcp_comp.bom_ref)
                host = self._detect_host_from_config(config_name)
                if host:
                    if host not in clients:
                        clients[host] = MCPClientComponent(
                            bom_ref=f"mcp-client:{host}",
                            name=f"{host} MCP client",
                            host_application=host,
                            server_refs=[],
                            config_path=str(config_path),
                            source_path=str(config_path),
                            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                            properties={"collection_mode": "static-config", "config_paths": []},
                        )
                    client = clients[host]
                    client.server_refs = sorted({*client.server_refs, *server_refs})
                    client.properties["config_paths"].append(str(config_path))
            result.components.extend(clients.values())
            if not config_only:
                self._scan_code_mcp_clients(result, sources)

        if not found_any and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("mcp-config (no config files found)")

        return result

    def _valid_server(self, config: dict[str, Any]) -> bool:
        return (
            isinstance(config.get("command", ""), str)
            and isinstance(config.get("args", []), list)
            and all(isinstance(arg, str) for arg in config.get("args", []))
            and isinstance(config.get("env", {}), dict)
            and all(isinstance(value, str) for value in config.get("env", {}).values())
            and all(isinstance(config.get(key, ""), str) for key in ("url", "endpoint"))
            and isinstance(config.get("tools", []), list)
            and len(config.get("tools", [])) <= 1000
            and all(isinstance(tool, dict) for tool in config.get("tools", []))
        )

    def _parse_server(
        self,
        name: str,
        config: dict[str, Any],
        config_path: Path,
    ) -> tuple[MCPServerComponent, list[ToolComponent]]:
        command = config.get("command", "")
        args = config.get("args", [])
        env = config.get("env", {})
        transport = self._detect_transport(config)
        endpoint_url = config.get("url") or config.get("endpoint")
        # Launch arguments are opaque executable inputs. Rather than attempting
        # to enumerate every application's secret flags, retain positions only.
        # Environment names remain credential references; values never leave.
        secrets = [value for value in env.values() if isinstance(value, str) and value]
        if self._files is None:
            raise RuntimeError("_parse_server called outside a _collection context")
        config_scope = config_path.relative_to(self._files.root).as_posix()
        server_ref = (
            "mcp-server:" + hash_canonical({"config": config_scope, "name": name}).split(":", 1)[1]
        )
        name = redact_text(name, secrets)
        safe_endpoint = (
            redact_text(sanitized_origin(endpoint_url), secrets) if endpoint_url else None
        )
        shown_command = (
            command
            if command in {"npx", "bunx", "uvx", "pipx", "docker", "node", "python", "python3"}
            else ("[redacted-command]" if command else None)
        )
        tool_names = sorted(
            redact_text(str(tool.get("name", "")), secrets)
            for tool in config.get("tools", [])
            if isinstance(tool, dict)
        )
        source_config_hash = hash_canonical(
            {
                "profile": STATIC_CONFIG_HASH_PROFILE,
                "structure": {
                    "fields": sorted(config),
                    "command": shown_command,
                    "transport": transport,
                    "endpoint": safe_endpoint,
                    "argument_count": len(args),
                    "environment_names": sorted(env),
                    "tool_names": tool_names,
                    "package_sources": _package_sources(args, secrets),
                },
            }
        )
        value_binding = _value_binding(config)

        package_ref = self._extract_package_ref(command, args)
        launcher_package = self._launcher_package(command, package_ref) if package_ref else None
        if launcher_package and command in {"uvx", "pipx"}:
            if any(arg.split("=", 1)[0] in _PYTHON_SOURCE_OPTIONS for arg in args):
                launcher_package = None
        if launcher_package:
            package_name = launcher_package.split(":", 1)[1]
            if any(
                len(secret) >= _MIN_IDENTITY_SECRET_LENGTH and secret in package_name
                for secret in secrets
            ):
                launcher_package = None
        version_pinned: bool | None = None
        version = None
        if package_ref:
            if command in {"uvx", "pipx"}:
                version = extract_version_pin(package_ref, ecosystem="python")
            elif command == "docker":
                version = extract_version_pin(package_ref, ecosystem="oci")
            else:
                version = extract_version_pin(package_ref, ecosystem="npm")
            version_pinned = version is not None

        risks: list[RiskAssessment] = []

        if not version_pinned and package_ref:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="version_pinning",
                    detail=f"MCP server '{name}' uses an unpinned package reference (arguments omitted).",
                    recommendation="Pin to an exact version and store a hash of the tool schema.",
                )
            )

        if transport == "stdio" and command:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="transport_security",
                    detail=f"MCP server '{name}' uses stdio transport (local process).",
                    recommendation="Ensure the command binary is integrity-checked.",
                )
            )

        if endpoint_url and _has_userinfo(endpoint_url):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"MCP server '{name}' endpoint URL embeds credentials: {safe_endpoint}",
                    recommendation="Supply the credential through a header or environment reference.",
                )
            )
        elif endpoint_url and not self._secure_endpoint(endpoint_url):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"MCP server '{name}' endpoint is not HTTPS: {safe_endpoint}",
                    recommendation="Use HTTPS for all remote MCP server connections.",
                )
            )

        # The launcher package and its version are recorded; every other argument
        # (a served directory, a mount, a flag) is a redacted position.
        recorded_args = {"-y", "--yes", package_ref} if launcher_package else set()
        unrecorded_args = [arg for arg in args if arg not in recorded_args]
        unbound = [
            label
            for label, present in (
                ("launch arguments", bool(unrecorded_args)),
                ("environment values", bool(secrets)),
                ("endpoint path and query", _has_path_or_query(endpoint_url)),
            )
            if present
        ]
        if unbound and not value_binding:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=f"MCP server '{name}' values not bound in this inventory: {'; '.join(unbound)}.",
                    recommendation=f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes to these values.",
                )
            )

        server_comp = MCPServerComponent(
            bom_ref=server_ref,
            name=name,
            version=version,
            transport=transport,
            launcher_package=launcher_package,
            command=(
                command
                if command in {"npx", "bunx", "uvx", "pipx", "docker", "node", "python", "python3"}
                else ("[redacted-command]" if command else None)
            ),
            args=[REDACTED for _ in args],
            env=dict.fromkeys(env, "***"),
            endpoint_url=safe_endpoint,
            version_pinned=version_pinned,
            source_path=str(config_path),
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
            risks=risks,
            properties={
                "collection_mode": "static-config",
                "launch_arguments_redacted": bool(args),
                "endpoint_credentials_omitted": bool(endpoint_url),
                "static_config_hash": source_config_hash,
                "static_config_hash_profile": STATIC_CONFIG_HASH_PROFILE,
                **(
                    {
                        "static_value_binding": value_binding[0],
                        "static_value_binding_key_id": value_binding[1],
                        "static_value_binding_profile": STATIC_VALUE_BINDING_PROFILE,
                    }
                    if value_binding
                    else {}
                ),
            },
        )

        tools = self._extract_tools(
            name, config, secrets, server_ref=server_ref, config_path=config_path
        )
        server_comp.tool_count = len(tools)
        server_comp.tool_refs = [tool.bom_ref for tool in tools]
        return server_comp, tools

    def _detect_transport(self, config: dict[str, Any]) -> str:
        if config.get("url") or config.get("endpoint"):
            url = config.get("url", config.get("endpoint", ""))
            if "/sse" in urlsplit(url).path:
                return "sse"
            return "streamable-http"
        return "stdio"

    def _extract_package_ref(self, command: str, args: list[str]) -> str | None:
        if command in {"uvx", "pipx", "npx", "bunx"}:
            values = args[1:] if command == "pipx" and args[:1] == ["run"] else args
            for index, arg in enumerate(values):
                if arg in {"-y", "--yes", "--no", "-n"}:
                    continue
                if (command == "uvx" and arg == "--from") or (
                    command == "pipx" and arg == "--spec"
                ):
                    return (
                        self._python_package_ref(command, values[index + 1])
                        if index + 1 < len(values)
                        else None
                    )
                # Unknown options may consume a secret in the next position.
                if arg.startswith("-"):
                    return None
                if command in {"uvx", "pipx"}:
                    return self._python_package_ref(command, arg)
                return (
                    arg
                    if len(arg) <= 2048 and re.fullmatch(rf"{_NPM_NAME}(?:@.+)?", arg, re.ASCII)
                    else None
                )
        if command == "docker" and args and args[0] == "run":
            for arg in args[1:]:
                if arg in {"--rm", "-i", "-t", "-it", "-d", "--detach"}:
                    continue
                if arg.startswith("-"):
                    return None
                return (
                    arg
                    if len(arg) <= 2048
                    and re.fullmatch(r"[A-Za-z0-9][\w./:-]*(?:@sha256:[a-fA-F0-9]{64})?", arg)
                    else None
                )
        return None

    @staticmethod
    def _launcher_package(command: str, reference: str) -> str | None:
        """Keep only a declared registry name. Never copy arbitrary launcher arguments."""
        if command in {"uvx", "pipx"}:
            requirement = Requirement(reference)  # Validated by _python_package_ref.
            if requirement.url:
                return None
            return "pypi:" + canonicalize_name(requirement.name)
        if command == "docker":
            image = re.fullmatch(
                rf"({_OCI_REPOSITORY})(?::[A-Za-z0-9_][A-Za-z0-9_.-]{{0,127}})?"
                r"(?:@sha256:[a-fA-F0-9]{64})?",
                reference,
            )
            return "oci:" + image[1].lower() if image else None
        # A tag or range may follow the name. An alias, URL or path can point to
        # a different package, so its nominal name does not identify the target.
        package = re.fullmatch(rf"({_NPM_NAME})(?:@[A-Za-z0-9.*^~<>=|+ -]+)?", reference, re.ASCII)
        if package is None or _NPM_LOCAL_SPEC.search(reference):
            return None
        return "npm:" + package[1]

    @staticmethod
    def _python_package_ref(command: str, value: str) -> str | None:
        if len(value) > 2048 or any(c in value for c in "\r\n\x00"):
            return None
        try:
            requirement = Requirement(value)
        except InvalidRequirement:
            return None
        # uvx supports package@version shorthand; pipx follows PEP 508 URLs.
        if command == "uvx" and requirement.url and not requirement.marker:
            try:
                Version(requirement.url)
            except InvalidVersion:
                pass
            else:
                return requirement.name + "==" + requirement.url
        return value

    def _extract_tools(
        self,
        server_name: str,
        config: dict[str, Any],
        secrets: list[str] | None = None,
        *,
        server_ref: str,
        config_path: Path,
    ) -> list[ToolComponent]:
        tools_config = config.get("tools", [])
        tool_comps = []

        if isinstance(tools_config, list):
            for tool_def in tools_config:
                if isinstance(tool_def, dict):
                    t_name = tool_def.get("name", "unknown")
                    t_desc = tool_def.get("description", "")
                    t_schema = tool_def.get("inputSchema", tool_def.get("input_schema"))
                    t_annotations = tool_def.get("annotations", {})
                    if (
                        not isinstance(t_name, str)
                        or not isinstance(t_desc, str)
                        or not isinstance(t_annotations, dict)
                        or (t_schema is not None and not isinstance(t_schema, dict))
                    ):
                        raise ValueError("invalid tool fields")

                    def_hash = hash_tool_definition(t_name, t_desc, t_schema, t_annotations)
                    tool_ref = (
                        "tool:"
                        + hash_canonical({"server": server_ref, "name": t_name}).split(":", 1)[1]
                    )

                    side_effect = self._classify_side_effects(t_annotations, t_name)
                    caps = self._infer_capabilities(t_name, t_desc, t_annotations)
                    safe = redact_descriptor(
                        {
                            "name": t_name,
                            "description": t_desc,
                            "inputSchema": t_schema,
                            "annotations": t_annotations,
                        },
                        secrets or [],
                    )
                    t_name = safe["name"]
                    display_hash = hash_tool_definition(
                        t_name, safe["description"], safe["inputSchema"], safe["annotations"]
                    )

                    risks: list[RiskAssessment] = []
                    if side_effect in (
                        SideEffectProfile.DESTRUCTIVE,
                        SideEffectProfile.FINANCIAL_TRANSACTION,
                    ):
                        risks.append(
                            RiskAssessment(
                                severity=RiskSeverity.HIGH,
                                category="capability_scope",
                                detail=f"Tool '{t_name}' has {side_effect.value} side effects.",
                                recommendation="Ensure human-in-the-loop approval for destructive operations.",
                            )
                        )

                    tool_comps.append(
                        ToolComponent(
                            bom_ref=tool_ref,
                            name=t_name,
                            mcp_server_ref=server_ref,
                            source_path=str(config_path),
                            description_text=safe["description"],
                            input_schema=safe["inputSchema"],
                            definition_hash=def_hash,
                            redacted_definition_hash=display_hash
                            if display_hash != def_hash
                            else None,
                            definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
                            annotations=safe["annotations"],
                            capabilities=CapabilityDeclaration(
                                capabilities=caps,
                                side_effect_profile=side_effect,
                            ),
                            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                            risks=risks,
                            properties={
                                "collection_mode": "static-config",
                                "capability_evidence": "unverified-declaration-and-name-heuristic",
                                "definition_hash_subject": "original-declared-descriptor",
                                "descriptor_output_may_be_redacted": True,
                            },
                        )
                    )
        return tool_comps

    @staticmethod
    def _secure_endpoint(url: str) -> bool:
        """Classify exact HTTP loopback or HTTPS declarations without connecting."""
        try:
            parsed = urlsplit(url)
            if not parsed.hostname or parsed.username is not None or parsed.password is not None:
                return False
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                return False
            if parsed.scheme == "https":
                return True
            if parsed.scheme != "http":
                return False
            if parsed.hostname.lower() == "localhost":
                return True
            try:
                return ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                return False
        except ValueError:
            return False

    @staticmethod
    def _detect_host_from_config(config_name: str) -> str | None:
        path = Path(config_name)
        by_name = {
            ".mcp.json": "claude-code",
            "claude_desktop_config.json": "claude-desktop",
            "cline_mcp_settings.json": "cline",
        }.get(path.name)
        return by_name or next(
            (host for part in path.parts[:-1] if (host := _HOST_DIRECTORIES.get(part))), None
        )

    def _scan_code_mcp_clients(self, result: ScanResult, sources: list[Path]) -> None:
        if self._files is None:
            raise RuntimeError("_scan_code_mcp_clients called outside a _collection context")
        from nexus_symbiote.scanners.python_tools import PYTHON_TOOL_HINTS, collect_python_tools
        from nexus_symbiote.scanners.ts_tools import collect_typescript

        budget = SourceBudget("MCP source references", result)
        collect_typescript(self._files, result, sources, budget)
        detected: list[str] = []
        excluded_dirs = {"tests", "test", "dist", "build", "docs", "benchmarks", "examples"}
        python_hints = tuple(hint.encode("ascii") for hint in PYTHON_TOOL_HINTS)
        for suffix in (".py", ".ts", ".js"):
            paths = [
                path
                for path in sources
                if path.suffix == suffix
                and not excluded_dirs.intersection(path.parts)
                and not path.name.endswith(
                    (".d.ts", ".spec.ts", ".test.ts", ".spec.js", ".test.js")
                )
            ]
            paths.sort(key=lambda path: len(path.parts) > 1)
            hints = python_hints if suffix == ".py" else (b"@modelcontextprotocol/sdk",)
            for path in paths:
                if budget.exhausted:
                    break
                raw = self._files.read_bytes(path)
                if raw is None or not budget.admit(len(raw)):
                    continue
                # Nested modules are decoded only when they can name a supported SDK, so
                # an unrelated module is neither parsed nor a decoding failure.
                if len(path.parts) > 1 and not any(hint in raw for hint in hints):
                    continue
                try:
                    content = raw.decode("utf-8")
                except UnicodeDecodeError:
                    result.scan_failures.append(f"{path}: invalid UTF-8")
                    continue
                result.surfaces_scanned.append(str(self._files.root / path))
                if len(raw) > 262_144:
                    result.scan_failures.append(f"{path}: syntax collection size limit exceeded")
                    continue
                if suffix == ".py":
                    try:
                        tree = parse_python(content)
                    except (SyntaxError, ValueError, RecursionError):
                        result.scan_failures.append(f"{path}: invalid Python syntax")
                        continue
                    collect_python_tools(tree, content, path, result)
                    found = any(
                        isinstance(node, ast.ImportFrom)
                        and node.module is not None
                        and node.module.split(".")[0] == "mcp"
                        and any("Client" in alias.name for alias in node.names)
                        for node in ast.walk(tree)
                    ) or any(
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "MCPClient"
                        for node in ast.walk(tree)
                    )
                else:
                    # A bounded syntax hint, never a claim that an SDK is installed
                    # or deployed. Strip comments and require the SDK import path.
                    found = bool(_SDK_IMPORT.search(without_js_comments(content)))
                if found:
                    detected.append(str(self._files.root / path))
        if detected:
            result.components.append(
                MCPClientComponent(
                    bom_ref="mcp-client:sdk",
                    name="MCP SDK client (code-detected)",
                    host_application="sdk",
                    source_path=detected[0],
                    trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                    properties={
                        "collection_mode": "static-source-reference",
                        "source_paths": detected,
                    },
                )
            )

    @staticmethod
    def _tokenize_identifier(text: str) -> set[str]:
        """Words of a tool name or description, each also without a plural or verb ending.

        Descriptions come from the checkout and may be megabytes long, so every
        pattern here is linear: a repeated capital class before the acronym
        boundary rescanned each run of capitals from every position in it.
        """
        expanded = _ACRONYM_BOUNDARY.sub(r"\1 \2", _CAMEL_BOUNDARY.sub(r"\1 \2", text))
        words = set(_WORD.findall(expanded.lower()))
        forms = set(words)
        for word in words:
            for ending in _WORD_ENDINGS:
                if len(word) <= len(ending) + 1 or not word.endswith(ending):
                    continue
                stem = word[: -len(ending)]
                forms.add(stem)
                if ending in {"ed", "ing"}:
                    forms.add(stem + "e")
                    if stem[-1] == stem[-2]:
                        forms.add(stem[:-1])
                elif ending == "es" and stem.endswith("i"):
                    forms.add(stem[:-1] + "y")
        return forms

    def _classify_side_effects(
        self, annotations: dict[str, Any], tool_name: str
    ) -> SideEffectProfile:
        if annotations.get("destructiveHint"):
            return SideEffectProfile.DESTRUCTIVE
        if annotations.get("readOnlyHint"):
            return SideEffectProfile.READ_ONLY
        tokens = self._tokenize_identifier(tool_name)
        if tokens & {"delete", "remove", "drop", "destroy", "purge"}:
            return SideEffectProfile.DESTRUCTIVE
        if tokens & {"create", "update", "write", "send", "post", "put"}:
            return SideEffectProfile.STATE_MODIFYING
        if tokens & {"get", "list", "read", "search", "query", "fetch"}:
            return SideEffectProfile.READ_ONLY
        return SideEffectProfile.UNKNOWN

    def _infer_capabilities(
        self, tool_name: str, description: str, annotations: dict[str, Any]
    ) -> list[CapabilityClass]:
        caps = []
        tokens = self._tokenize_identifier(f"{tool_name} {description}")
        if tokens & {
            "file",
            "filename",
            "filepath",
            "filesystem",
            "directory",
            "path",
            "fs",
            "disk",
        }:
            caps.append(CapabilityClass.FILESYSTEM)
        if tokens & {"http", "https", "url", "fetch", "request", "api", "endpoint"}:
            caps.append(CapabilityClass.NETWORK)
        if tokens & {
            "exec",
            "execute",
            "executable",
            "run",
            "shell",
            "command",
            "bash",
            "terminal",
        }:
            caps.append(CapabilityClass.EXECUTE)
        if tokens & {"pay", "payment", "transfer", "invoice", "charge", "billing"}:
            caps.append(CapabilityClass.PAYMENT)
        if tokens & {
            "credential",
            "secret",
            "token",
            "password",
            "passwd",
            "passphrase",
            "key",
            "apikey",
            "auth",
            "oauth",
            "authenticate",
            "authentication",
            "authorize",
            "authorization",
        }:
            caps.append(CapabilityClass.CREDENTIALS)
        if tokens & {"write", "create", "update", "delete", "send", "post", "put"}:
            caps.append(CapabilityClass.WRITE)
        elif tokens & {"read", "get", "list", "search", "query", "fetch"}:
            caps.append(CapabilityClass.READ)
        return caps
