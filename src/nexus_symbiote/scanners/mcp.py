"""MCP server and tool scanner.

Discovers MCP server configurations from:
  - .mcp.json (project-level MCP config)
  - claude_desktop_config.json
  - mcp.json
  - .cursor/mcp.json
  - .claude/mcp.json
  - .windsurf/mcp.json and .cline/mcp.json (the IDE scanner references these servers)

For each server, extracts tool definitions, computes canonical hashes,
and detects unpinned versions, missing transport security, and rug-pull risk.

The helpers at module level are shared by the other scanners in this package.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.enums import (
    CapabilityClass,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.hashing import extract_version_pin, hash_tool_definition
from nexus_symbiote.core.models import (
    AnyComponent,
    CapabilityDeclaration,
    MCPClientComponent,
    MCPServerComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.core.textsafety import find_hidden_characters
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    matched_exclusion,
    read_regular_text,
    relative_posix,
    sanitized_origin,
)

MCP_CONFIG_FILES = [
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    ".cursor/mcp.json",
    ".claude/mcp.json",
    ".windsurf/mcp.json",
    ".cline/mcp.json",
]

# Launchers whose package argument can carry an exact version pin.
LAUNCHERS = frozenset({"npx", "bunx", "uvx", "pipx", "pnpm", "yarn", "docker", "podman"})

# Top-level code files examined per pattern by the client code scan.
CODE_SCAN_LIMIT = 10

_MCP_CLIENT_CODE_PATTERNS = (
    re.compile(r"from\s+mcp\b[^\n]{0,200}?import[^\n]{0,200}?Client"),
    re.compile(r"MCPClient\s*\("),
    re.compile(r"new\s+Client\s*\("),
    re.compile(r'require\s*\(\s*["\']@modelcontextprotocol/sdk["\']'),
    re.compile(r"from\s+['\"]@modelcontextprotocol/sdk['\"]"),
)

_SIDE_EFFECT_RANK = {
    SideEffectProfile.READ_ONLY: 0,
    SideEffectProfile.STATE_MODIFYING: 1,
    SideEffectProfile.DESTRUCTIVE: 2,
}


def read_text_for_scan(path: Path, surface: str, result: ScanResult) -> str | None:
    """Read a bounded UTF-8 file. An unreadable or unsafe file is recorded as excluded."""
    try:
        return read_regular_text(path)
    except OSError:
        result.record_excluded(surface, "unreadable or not a regular file; not followed")
    except UnicodeError:
        result.record_failure(f"{surface}: not valid UTF-8 text")
    return None


def excluded_before_read(
    path: Path, root: Path, patterns: Iterable[str], surface: str, result: ScanResult
) -> bool:
    """True when the file must not be read: it is a symbolic link or matches a policy pattern."""
    if path.is_symlink():
        result.record_excluded(surface, "symbolic link, not followed")
        return True
    if matched_exclusion(path, root, patterns) is not None:
        result.record_excluded(surface, "excluded by policy")
        return True
    return False


def parse_json_object(text: str, surface: str, result: ScanResult) -> dict[str, Any] | None:
    """Parse text that must be a JSON object. Malformed content is recorded as a failure."""
    try:
        data: object = json.loads(text)
    except (ValueError, RecursionError) as exc:
        result.record_failure(f"{surface}: malformed JSON ({exc})")
        return None
    if not isinstance(data, dict):
        result.record_failure(f"{surface}: top-level value is not an object")
        return None
    return data


def server_map(data: dict[str, Any], surface: str, result: ScanResult) -> dict[str, Any] | None:
    """The mcpServers (or servers) object of an MCP config. None when it has the wrong type."""
    raw: object = data.get("mcpServers", data.get("servers"))
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    result.record_failure(f"{surface}: server map is not an object; no servers recorded")
    return None


def as_text(value: object, label: str, surface: str, result: ScanResult) -> str | None:
    """A text field, or None when absent. A field of another type is recorded and ignored."""
    if value is None or isinstance(value, str):
        return value
    result.record_failure(f"{surface}: {label} is not a string; ignored")
    return None


def pinned_version(spec: str) -> str | None:
    """The exact version that a package reference or version specifier pins, or None.

    Every pinning decision goes through extract_version_pin. A PEP 508 name such as
    "pkg[extra]==1.2.3" is reduced to its specifier first, and a wildcard is never exact.
    """
    compact = "".join(spec.split())
    if "*" in compact:
        return None
    if "==" in compact:
        compact = compact[compact.index("==") :]
    return extract_version_pin(compact)


def make_components_unique(result: ScanResult) -> None:
    """Make bom_refs unique in one pass. A repeated ref gets a numbered suffix.

    An identical repeat is dropped, because it describes the same component.
    """
    seen: dict[str, AnyComponent] = {}
    kept: list[AnyComponent] = []
    for component in result.components:
        base = component.bom_ref
        ref = base
        suffix = 2
        is_duplicate = False
        while ref in seen:
            if seen[ref].model_dump(exclude={"bom_ref"}) == component.model_dump(
                exclude={"bom_ref"}
            ):
                is_duplicate = True
                break
            ref = f"{base}#{suffix}"
            suffix += 1
        if is_duplicate:
            continue
        component.bom_ref = ref
        seen[ref] = component
        kept.append(component)
    result.components = kept


def _basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def _launcher_name(command: str) -> str:
    name = _basename(command).lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _first_positional(args: list[str]) -> str | None:
    return next((arg for arg in args if not arg.startswith("-")), None)


def _string_args(value: object, label: str, surface: str, result: ScanResult) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        result.record_failure(f"{surface}: {label} args is not a list; ignored")
        return []
    args = [item for item in value if isinstance(item, str)]
    if len(args) != len(value):
        result.record_failure(f"{surface}: {label} has non-string args; they are ignored")
    return args


def _env_map(value: object, label: str, surface: str, result: ScanResult) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    result.record_failure(f"{surface}: {label} env is not an object; ignored")
    return {}


def _declared_profile(annotations: dict[str, Any]) -> SideEffectProfile | None:
    if annotations.get("destructiveHint") is True:
        return SideEffectProfile.DESTRUCTIVE
    if annotations.get("readOnlyHint") is True:
        return SideEffectProfile.READ_ONLY
    return None


def _hidden_character_risks(name: str, description: str) -> list[RiskAssessment]:
    hits = [("name", hit) for hit in find_hidden_characters(name)]
    hits += [("description", hit) for hit in find_hidden_characters(description)]
    strong = [(where, hit) for where, hit in hits if hit.kind != "invisible"]
    invisible = [(where, hit) for where, hit in hits if hit.kind == "invisible"]
    risks: list[RiskAssessment] = []
    recommendation = "Remove hidden or reordering characters before approving this tool."
    if strong:
        where, first = strong[0]
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="hidden-characters",
                detail=(
                    f"Tool {where} contains {len(strong)} bidirectional or tag character(s); "
                    f"the first is {first.codepoint} at index {first.index}."
                ),
                recommendation=recommendation,
            )
        )
    if invisible:
        where, first = invisible[0]
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category="hidden-characters",
                detail=(
                    f"Tool {where} contains {len(invisible)} invisible character(s); "
                    f"the first is {first.codepoint} at index {first.index}."
                ),
                recommendation=recommendation,
            )
        )
    return risks


class MCPScanner(Scanner):
    name = "mcp"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        found_any = False
        declared: dict[str, dict[str, Any]] = {}

        for config_name in MCP_CONFIG_FILES:
            config_path = project_root / config_name
            if not (config_path.exists() or config_path.is_symlink()):
                continue
            found_any = True
            surface = f"mcp-config {config_name}"
            if excluded_before_read(
                config_path, project_root, self.exclude_paths, surface, result
            ):
                continue
            text = read_text_for_scan(config_path, surface, result)
            if text is None:
                continue
            result.surfaces_scanned.append(surface)
            data = parse_json_object(text, surface, result)
            if data is not None:
                self._scan_config(data, config_name, config_path, surface, declared, result)

        self._scan_code_mcp_clients(project_root, result)
        make_components_unique(result)

        if not found_any:
            result.record_absent("mcp-config", MCP_CONFIG_FILES)
        return result

    def _scan_config(
        self,
        data: dict[str, Any],
        config_name: str,
        config_path: Path,
        surface: str,
        declared: dict[str, dict[str, Any]],
        result: ScanResult,
    ) -> None:
        servers = server_map(data, surface, result)
        if servers is None:
            return

        # References are built per file, so a client never claims another file's servers.
        server_refs: list[str] = []
        for server_name, server_config in servers.items():
            if not isinstance(server_config, dict):
                result.record_failure(
                    f"{surface}: server '{server_name}' is not an object; not recorded"
                )
                continue
            server_refs.append(f"mcp-server:{server_name}")
            earlier = declared.get(server_name)
            if earlier is not None:
                if earlier != server_config:
                    result.record_failure(
                        f"{surface}: server '{server_name}' conflicts with an earlier "
                        "declaration; this declaration is not recorded"
                    )
                continue
            declared[server_name] = server_config
            mcp_comp, tool_comps = self._parse_server(
                server_name, server_config, config_path, surface, result
            )
            result.components.append(mcp_comp)
            result.components.extend(tool_comps)

        host_app = self._detect_host_from_config(config_name)
        if host_app:
            result.components.append(self._create_mcp_client(host_app, config_path, server_refs))

    def _parse_server(
        self,
        name: str,
        config: dict[str, Any],
        config_path: Path,
        surface: str,
        result: ScanResult,
    ) -> tuple[MCPServerComponent, list[ToolComponent]]:
        label = f"server '{name}'"
        command = as_text(config.get("command"), f"{label} command", surface, result) or ""
        args = _string_args(config.get("args"), label, surface, result)
        env = _env_map(config.get("env"), label, surface, result)
        endpoint = as_text(
            config.get("url") or config.get("endpoint"), f"{label} url", surface, result
        )
        transport = self._detect_transport(endpoint)

        package_ref = self._extract_package_ref(command, args) if command else None
        version = pinned_version(package_ref) if package_ref else None
        version_pinned = version is not None

        risks: list[RiskAssessment] = []
        if package_ref and not version_pinned:
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

        if endpoint and not self._secure_endpoint(endpoint):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=(
                        f"MCP server '{name}' endpoint has insecure or invalid transport: "
                        f"{sanitized_origin(endpoint)}"
                    ),
                    recommendation="Use HTTPS for all remote MCP server connections.",
                )
            )

        server_comp = MCPServerComponent(
            bom_ref=f"mcp-server:{name}",
            name=name,
            version=version,
            transport=transport,
            command=_basename(command) if command else None,
            args=["[redacted]" for _ in args],
            env=dict.fromkeys(env, "***"),
            endpoint_url=sanitized_origin(endpoint) if endpoint else None,
            version_pinned=version_pinned,
            source_path=str(config_path),
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
            risks=risks,
        )
        return server_comp, self._extract_tools(name, config, surface, result)

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

    @staticmethod
    def _detect_transport(endpoint: str | None) -> str:
        if endpoint:
            return "sse" if "/sse" in endpoint else "streamable-http"
        return "stdio"

    def _extract_package_ref(self, command: str, args: list[str]) -> str | None:
        launcher = _launcher_name(command)
        if launcher not in LAUNCHERS:
            return None
        if launcher in ("npx", "bunx", "uvx"):
            return _first_positional(args)
        if launcher == "pipx":
            return _first_positional(args[args.index("run") + 1 :]) if "run" in args else None
        if launcher in ("pnpm", "yarn"):
            return _first_positional(args[args.index("dlx") + 1 :]) if "dlx" in args else None
        # docker and podman: the image is the last argument of "run".
        if "run" in args[:-1]:
            return args[-1]
        return None

    def _extract_tools(
        self, server_name: str, config: dict[str, Any], surface: str, result: ScanResult
    ) -> list[ToolComponent]:
        tools_config = config.get("tools")
        if tools_config is None:
            return []
        if not isinstance(tools_config, list):
            result.record_failure(
                f"{surface}: server '{server_name}' tools is not a list; no tools recorded"
            )
            return []

        tool_comps: list[ToolComponent] = []
        seen_names: set[str] = set()
        for index, tool_def in enumerate(tools_config):
            where = f"{surface}: server '{server_name}' tools[{index}]"
            if not isinstance(tool_def, dict):
                result.record_failure(f"{where} is not an object; not recorded")
                continue
            t_name = tool_def.get("name", "unknown")
            t_desc = tool_def.get("description", "")
            t_schema = tool_def.get("inputSchema", tool_def.get("input_schema"))
            t_annotations = tool_def.get("annotations", {})
            if t_desc is None:
                t_desc = ""
            if t_annotations is None:
                t_annotations = {}
            if not isinstance(t_name, str) or not isinstance(t_desc, str):
                result.record_failure(f"{where}: name and description must be strings; skipped")
                continue
            if t_schema is not None and not isinstance(t_schema, dict):
                result.record_failure(f"{where}: inputSchema is not an object; skipped")
                continue
            if not isinstance(t_annotations, dict):
                result.record_failure(f"{where}: annotations is not an object; skipped")
                continue
            if t_name in seen_names:
                result.record_failure(f"{where}: repeats tool name '{t_name}'; skipped")
                continue
            seen_names.add(t_name)
            try:
                def_hash = hash_tool_definition(t_name, t_desc, t_schema, t_annotations)
            except (TypeError, ValueError):
                result.record_failure(
                    f"{where}: definition cannot be canonicalized (non-finite number or "
                    "unsupported value); skipped"
                )
                continue

            side_effect = self._classify_side_effects(t_annotations, t_name)
            caps = self._infer_capabilities(t_name, t_desc, t_annotations)
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
                    risks=self._tool_risks(t_name, t_desc, t_annotations, side_effect),
                )
            )
        return tool_comps

    def _tool_risks(
        self,
        tool_name: str,
        description: str,
        annotations: dict[str, Any],
        side_effect: SideEffectProfile,
    ) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []
        if side_effect in (
            SideEffectProfile.DESTRUCTIVE,
            SideEffectProfile.FINANCIAL_TRANSACTION,
        ):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="capability_scope",
                    detail=f"Tool '{tool_name}' has {side_effect.value} side effects.",
                    recommendation="Ensure human-in-the-loop approval for destructive operations.",
                )
            )
        if annotations.get("readOnlyHint") is True and (
            self._name_profile(tool_name) == SideEffectProfile.DESTRUCTIVE
        ):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="annotation-mismatch",
                    detail=(
                        f"Tool '{tool_name}' declares readOnlyHint but its name indicates a "
                        "destructive action."
                    ),
                    recommendation=(
                        "Correct the annotation or the tool name; do not rely on readOnlyHint "
                        "to skip approval."
                    ),
                )
            )
        risks.extend(_hidden_character_risks(tool_name, description))
        return risks

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
        server_refs: list[str],
    ) -> MCPClientComponent:
        return MCPClientComponent(
            bom_ref=f"mcp-client:{host_app}",
            name=f"{host_app} MCP client",
            host_application=host_app,
            server_refs=list(server_refs),
            config_path=str(config_path),
            source_path=str(config_path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
        )

    def _scan_code_mcp_clients(self, root: Path, result: ScanResult) -> None:
        """Detect MCP client SDK usage in top-level Python and JavaScript/TypeScript files."""
        for suffix in ("*.py", "*.ts", "*.js"):
            candidates = sorted(root.glob(suffix))
            if len(candidates) > CODE_SCAN_LIMIT:
                result.record_excluded(
                    f"mcp-code {suffix}", f"only the first {CODE_SCAN_LIMIT} files are scanned"
                )
            for source in candidates[:CODE_SCAN_LIMIT]:
                surface = f"mcp-code {relative_posix(source, root)}"
                if excluded_before_read(source, root, self.exclude_paths, surface, result):
                    continue
                if not source.is_file():
                    continue
                try:
                    content = read_regular_text(source)
                except OSError:
                    result.record_excluded(surface, "unreadable or not a regular file; not followed")
                    continue
                except UnicodeError:
                    result.record_excluded(surface, "not UTF-8 text; not scanned")
                    continue
                if not any(p.search(content) for p in _MCP_CLIENT_CODE_PATTERNS):
                    continue
                result.surfaces_scanned.append(surface)
                if not any(getattr(c, "host_application", None) == "sdk" for c in result.components):
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
        """The more severe of the declared hint and the name-based inference.

        A declared annotation can raise the profile but never lower it.
        """
        candidates = [
            profile
            for profile in (_declared_profile(annotations), self._name_profile(tool_name))
            if profile is not None
        ]
        if not candidates:
            return SideEffectProfile.UNKNOWN
        return max(candidates, key=_SIDE_EFFECT_RANK.__getitem__)

    @staticmethod
    def _name_profile(tool_name: str) -> SideEffectProfile | None:
        name_lower = tool_name.lower()
        if any(w in name_lower for w in ("delete", "remove", "drop", "destroy", "purge")):
            return SideEffectProfile.DESTRUCTIVE
        if any(w in name_lower for w in ("create", "update", "write", "send", "post", "put")):
            return SideEffectProfile.STATE_MODIFYING
        if any(w in name_lower for w in ("get", "list", "read", "search", "query", "fetch")):
            return SideEffectProfile.READ_ONLY
        return None

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
