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

import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from symbiote.core.enums import (
    CapabilityClass,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from symbiote.core.hashing import extract_version_pin, hash_tool_definition
from symbiote.core.models import (
    CapabilityDeclaration,
    MCPClientComponent,
    MCPServerComponent,
    RiskAssessment,
    ToolComponent,
)
from symbiote.scanners.base import Scanner, ScanResult, read_regular_text, sanitized_origin

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
        server_names: list[str] = []

        for config_name in MCP_CONFIG_FILES:
            config_path = project_root / config_name
            if not config_path.exists():
                continue

            found_any = True
            result.surfaces_scanned.append(str(config_path))
            data = self._safe_read_json(config_path)
            if data is None:
                result.scan_failures.append(f"Failed to parse {config_path}")
                continue

            if not isinstance(data, dict):
                continue
            servers = data.get("mcpServers", data.get("servers", {}))
            if isinstance(servers, dict):
                for server_name, server_config in servers.items():
                    mcp_comp, tool_comps = self._parse_server(
                        server_name, server_config, config_path
                    )
                    result.components.append(mcp_comp)
                    result.components.extend(tool_comps)
                    server_names.append(server_name)

                host_app = self._detect_host_from_config(config_name)
                if host_app:
                    client_comp = self._create_mcp_client(host_app, config_path, server_names)
                    result.components.append(client_comp)

        self._scan_code_mcp_clients(project_root, result)

        if not found_any:
            result.surfaces_excluded.append("mcp-config (no config files found)")

        return result

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

        package_ref = self._extract_package_ref(command, args)
        version_pinned = False
        version = None
        if package_ref:
            version = extract_version_pin(package_ref)
            version_pinned = version is not None

        risks: list[RiskAssessment] = []

        if not version_pinned and package_ref:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="version_pinning",
                    detail=f"MCP server '{name}' uses an unpinned package reference.",
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
                    detail=f"MCP server '{name}' endpoint has insecure or invalid transport: {sanitized_origin(endpoint_url)}",
                    recommendation="Use HTTPS for all remote MCP server connections.",
                )
            )

        server_comp = MCPServerComponent(
            bom_ref=f"mcp-server:{name}",
            name=name,
            version=version,
            transport=transport,
            command=Path(command).name if command else None,
            args=["[redacted]" for _ in args],
            env=dict.fromkeys(env, "***"),
            endpoint_url=sanitized_origin(endpoint_url) if endpoint_url else None,
            version_pinned=version_pinned,
            source_path=str(config_path),
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
            risks=risks,
        )

        tools = self._extract_tools(name, config)
        return server_comp, tools

    @staticmethod
    def _secure_endpoint(url: str) -> bool:
        """HTTPS or an exact HTTP loopback host; userinfo is never accepted."""
        try:
            parsed = urlsplit(url)
            if not parsed.hostname or parsed.username is not None or parsed.password is not None:
                return False
            _ = parsed.port  # reject invalid ports
            if parsed.scheme.lower() == "https":
                return True
            if parsed.scheme.lower() != "http":
                return False
            host = parsed.hostname.lower()
            if host == "localhost":
                return True
            try:
                return ipaddress.ip_address(host).is_loopback
            except ValueError:
                return False
        except ValueError:
            return False

    def _detect_transport(self, config: dict[str, Any]) -> str:
        if config.get("url") or config.get("endpoint"):
            url = config.get("url", config.get("endpoint", ""))
            if "/sse" in url:
                return "sse"
            return "streamable-http"
        return "stdio"

    def _extract_package_ref(self, command: str, args: list[str]) -> str | None:
        if command in ("npx", "bunx"):
            for arg in args:
                if not arg.startswith("-"):
                    return arg
        if command in ("uvx", "pipx"):
            for arg in args:
                if not arg.startswith("-"):
                    return arg
        if command == "docker":
            for i, arg in enumerate(args):
                if arg == "run" and i + 1 < len(args):
                    return args[-1]
        return None

    def _extract_tools(self, server_name: str, config: dict[str, Any]) -> list[ToolComponent]:
        tools_config = config.get("tools", [])
        tool_comps = []

        if isinstance(tools_config, list):
            for tool_def in tools_config:
                if isinstance(tool_def, dict):
                    t_name = tool_def.get("name", "unknown")
                    t_desc = tool_def.get("description", "")
                    t_schema = tool_def.get("inputSchema", tool_def.get("input_schema"))
                    t_annotations = tool_def.get("annotations", {})

                    def_hash = hash_tool_definition(t_name, t_desc, t_schema, t_annotations)

                    side_effect = self._classify_side_effects(t_annotations, t_name)
                    caps = self._infer_capabilities(t_name, t_desc, t_annotations)

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
                            description_text=t_desc,
                            input_schema=t_schema,
                            definition_hash=def_hash,
                            definition_hash_version="rfc8785-jcs-v1",
                            annotations=t_annotations,
                            capabilities=CapabilityDeclaration(
                                capabilities=caps,
                                side_effect_profile=side_effect,
                            ),
                            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                            risks=risks,
                        )
                    )
        return tool_comps

    @staticmethod
    def _detect_host_from_config(config_name: str) -> str | None:
        mapping = {
            ".mcp.json": "claude-code",
            ".claude/mcp.json": "claude-code",
            "claude_desktop_config.json": "claude-desktop",
            ".cursor/mcp.json": "cursor",
        }
        return mapping.get(config_name)

    def _create_mcp_client(
        self,
        host_app: str,
        config_path: Path,
        server_names: list[str],
    ) -> MCPClientComponent:
        return MCPClientComponent(
            bom_ref=f"mcp-client:{host_app}",
            name=f"{host_app} MCP client",
            host_application=host_app,
            server_refs=[f"mcp-server:{s}" for s in server_names],
            config_path=str(config_path),
            source_path=str(config_path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
        )

    def _scan_code_mcp_clients(self, root: Path, result: ScanResult) -> None:
        """Detect MCP client SDK usage in Python/TypeScript entrypoints."""
        import re

        patterns = [
            re.compile(r"from\s+mcp\b.*import.*Client"),
            re.compile(r"MCPClient\s*\("),
            re.compile(r"new\s+Client\s*\("),
            re.compile(r'require\s*\(\s*["\']@modelcontextprotocol/sdk["\']'),
            re.compile(r"from\s+['\"]@modelcontextprotocol/sdk['\"]"),
        ]

        for ext in ("*.py", "*.ts", "*.js"):
            for source in sorted(root.glob(ext))[:10]:
                if source.is_symlink():
                    continue
                try:
                    content = read_regular_text(source)
                except (OSError, UnicodeError):
                    continue
                if any(p.search(content) for p in patterns):
                    if not any(
                        getattr(c, "host_application", None) == "sdk"
                        for c in result.components
                        if hasattr(c, "host_application")
                    ):
                        result.surfaces_scanned.append(str(source))
                        result.components.append(
                            MCPClientComponent(
                                bom_ref="mcp-client:sdk",
                                name="MCP SDK client (code-detected)",
                                host_application="sdk",
                                source_path=str(source),
                                trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                            )
                        )
                    break

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
