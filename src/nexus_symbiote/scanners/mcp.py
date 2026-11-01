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
import ipaddress
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from nexus_symbiote.core.enums import (
    CapabilityClass,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    extract_version_pin,
    hash_tool_definition,
)
from nexus_symbiote.core.models import (
    CapabilityDeclaration,
    MCPClientComponent,
    MCPServerComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.scanners.base import Scanner, ScanResult, sanitized_origin
from nexus_symbiote.utils.secrets import REDACTED, redact_metadata, redact_text

MCP_CONFIG_FILES = [
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    ".cursor/mcp.json",
    ".claude/mcp.json",
]


class MCPScanner(Scanner):
    name = "mcp"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        found_any = False
        clients: dict[str, MCPClientComponent] = {}

        with self._collection(project_root, result) as files:
            for config_name in MCP_CONFIG_FILES:
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
            self._scan_code_mcp_clients(files.root, result)

        if not found_any and not result.scan_failures:
            result.surfaces_excluded.append("mcp-config (no config files found)")

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
        name = redact_text(name, secrets)
        safe_endpoint = (
            redact_text(sanitized_origin(endpoint_url), secrets) if endpoint_url else None
        )

        package_ref = self._extract_package_ref(command, args)
        version = None
        version_pinned: bool | None = None
        if package_ref:
            version = extract_version_pin(package_ref)
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

        if endpoint_url and not self._secure_endpoint(endpoint_url):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"MCP server '{name}' endpoint is not HTTPS: {safe_endpoint}",
                    recommendation="Use HTTPS for all remote MCP server connections.",
                )
            )

        server_comp = MCPServerComponent(
            bom_ref=f"mcp-server:{name}",
            name=name,
            version=version,
            transport=transport,
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
            },
        )

        tools = self._extract_tools(name, config, secrets)
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
        if command in ("npx", "bunx", "uvx", "pipx"):
            for arg in args:
                if arg in {"-y", "--yes", "--no", "-n"}:
                    continue
                # Unknown flag grammars may consume a credential as their next
                # argument. Do not infer a package/version from that position.
                if arg.startswith("-"):
                    return None
                pattern = r"(?:@[A-Za-z][\w.-]*/[A-Za-z][\w.-]*|[A-Za-z][\w.-]*)(?:@[\w.+-]+)?"
                return arg if re.fullmatch(pattern, arg) else None
        if command == "docker" and args and args[0] == "run":
            for arg in args[1:]:
                if arg in {"--rm", "-i", "-t", "-it", "-d", "--detach"}:
                    continue
                if arg.startswith("-"):
                    return None
                return (
                    arg
                    if re.fullmatch(r"[A-Za-z][\w./:-]*(?:@sha256:[a-fA-F0-9]{64})?", arg)
                    else None
                )
        return None

    def _extract_tools(
        self, server_name: str, config: dict[str, Any], secrets: list[str] | None = None
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

                    side_effect = self._classify_side_effects(t_annotations, t_name)
                    caps = self._infer_capabilities(t_name, t_desc, t_annotations)
                    t_name = redact_text(t_name, secrets or [])

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
                            bom_ref=f"tool:{server_name}/{t_name}",
                            name=t_name,
                            mcp_server_ref=f"mcp-server:{server_name}",
                            description_text=redact_text(t_desc, secrets or []),
                            input_schema=redact_metadata(t_schema, secrets or []),
                            definition_hash=def_hash,
                            definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
                            annotations=redact_metadata(t_annotations, secrets or []),
                            capabilities=CapabilityDeclaration(
                                capabilities=caps,
                                side_effect_profile=side_effect,
                            ),
                            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                            risks=risks,
                            properties={
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
        return {
            ".mcp.json": "claude-code",
            ".claude/mcp.json": "claude-code",
            "claude_desktop_config.json": "claude-desktop",
            ".cursor/mcp.json": "cursor",
        }.get(config_name)

    def _scan_code_mcp_clients(self, root: Path, result: ScanResult) -> None:
        assert self._files is not None
        sources = list(self._files.iter_files())
        detected: list[str] = []
        for suffix in (".py", ".ts", ".js"):
            paths = [path for path in sources if len(path.parts) == 1 and path.suffix == suffix]
            if len(paths) > 10:
                result.scan_failures.append(
                    f"MCP {suffix} references: 10-file collection limit exceeded"
                )
            for path in paths[:10]:
                content = self._files.read_text(path)
                if content is None:
                    continue
                result.surfaces_scanned.append(str(root / path))
                if len(content) > 262_144:
                    result.scan_failures.append(f"{path}: syntax collection size limit exceeded")
                    continue
                if suffix == ".py":
                    try:
                        tree = ast.parse(content)
                    except (SyntaxError, ValueError, RecursionError):
                        result.scan_failures.append(f"{path}: invalid Python syntax")
                        continue
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
                    content = re.sub(r"/\*.*?\*/|(?m:^\s*//[^\n]*$)", "", content, flags=re.S)
                    found = bool(
                        re.search(
                            r"(?:\bfrom\s*[\"']@modelcontextprotocol/sdk(?:/[^\"']*)?[\"']|"
                            r"\brequire\s*\(\s*[\"']@modelcontextprotocol/sdk(?:/[^\"']*)?[\"'])",
                            content,
                        )
                    )
                if found:
                    detected.append(str(root / path))
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

    def _classify_side_effects(
        self, annotations: dict[str, Any], tool_name: str
    ) -> SideEffectProfile:
        if annotations.get("destructiveHint"):
            return SideEffectProfile.DESTRUCTIVE
        if annotations.get("readOnlyHint"):
            return SideEffectProfile.READ_ONLY
        name_lower = tool_name.lower()
        if any(w in name_lower for w in ("delete", "remove", "drop", "destroy", "purge")):
            return SideEffectProfile.DESTRUCTIVE
        if any(w in name_lower for w in ("create", "update", "write", "send", "post", "put")):
            return SideEffectProfile.STATE_MODIFYING
        if any(w in name_lower for w in ("get", "list", "read", "search", "query", "fetch")):
            return SideEffectProfile.READ_ONLY
        return SideEffectProfile.UNKNOWN

    def _infer_capabilities(
        self, tool_name: str, description: str, annotations: dict[str, Any]
    ) -> list[CapabilityClass]:
        caps = []
        combined = f"{tool_name} {description}".lower()
        if any(w in combined for w in ("file", "directory", "path", "fs", "disk")):
            caps.append(CapabilityClass.FILESYSTEM)
        if any(w in combined for w in ("http", "url", "fetch", "request", "api", "endpoint")):
            caps.append(CapabilityClass.NETWORK)
        if any(w in combined for w in ("exec", "run", "shell", "command", "bash", "terminal")):
            caps.append(CapabilityClass.EXECUTE)
        if any(w in combined for w in ("pay", "transfer", "invoice", "charge", "billing")):
            caps.append(CapabilityClass.PAYMENT)
        if any(w in combined for w in ("credential", "secret", "token", "password", "key", "auth")):
            caps.append(CapabilityClass.CREDENTIALS)
        if any(w in combined for w in ("write", "create", "update", "delete", "send", "post")):
            caps.append(CapabilityClass.WRITE)
        elif any(w in combined for w in ("read", "get", "list", "search", "query")):
            caps.append(CapabilityClass.READ)
        return caps
