"""``mcp-config`` collector: MCP servers declared in agent-client configuration files (``spec/collectors.md``).

Produces one ``ToolServer`` per configured server with transport, endpoint or package identity (pinning
facts from :mod:`symbiote.collect.launchers`), the *names* of credentials it is given, the client's
auto-approval settings, and credential bindings for every credential-bearing variable or header. Values are
never read into entities: an inline secret becomes a ``static-long-lived`` binding stored in a file, plus a
redaction record.

Client formats are data (:data:`CLIENTS`), so supporting a new client is a table entry plus a fixture.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

from symbiote.collect._common import (
    as_str_list,
    classify_env_value,
    locator,
    names_from_mapping,
    parse_structured,
    redact_args,
    secretish_name,
    url_facts,
)
from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult, Platform
from symbiote.collect.launchers import LaunchFacts, parse_launch
from symbiote.digest import canonical_bytes, server_identity_digest
from symbiote.digest.jcs import UndigestableError
from symbiote.model.common import Claim, DigestResult, Provenance
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    Authentication,
    CredentialBinding,
    CredentialStorage,
    Identity,
    PackageRef,
    Redaction,
    ToolDefinition,
    ToolServer,
)
from symbiote.model.enums import (
    ApprovalGate,
    AuthMode,
    ClaimMethod,
    CollectorMode,
    CredentialKind,
    CredentialStorageKind,
    DigestStatus,
    EdgeScope,
    EdgeType,
    IdentityKind,
    Surface,
    ToolServerKind,
    ToolSource,
    Transport,
    TrustZone,
    UnknownReason,
)
from symbiote.model.ids import make_id, tool_id

__all__ = [
    "CLIENTS",
    "ClientSpec",
    "ConfigLocation",
    "McpConfigCollector",
    "ServerDecl",
    "parse_client_config",
]

Fmt = Literal["json", "jsonc", "toml", "yaml"]
Base = Literal["root", "home", "appconfig"]
Scope = Literal["project", "user"]


@dataclass(frozen=True, slots=True)
class ConfigLocation:
    """Where one client keeps MCP servers, and how to find them inside the file.

    ``relpath`` may contain ``*`` glob segments (profile folders, per-server fragment files, plugin folders).
    """

    scope: Scope
    base: Base
    relpath: str
    fmt: Fmt
    servers_path: tuple[str, ...]
    platforms: frozenset[Platform] | None = None
    #: ``~/.claude.json`` also nests per-project servers under ``projects[<abs path>].mcpServers``.
    claude_projects: bool = False
    #: ``map`` (name -> entry) or ``list`` (entries carrying a ``name``)
    shape: Literal["map", "list"] = "map"
    #: dotted paths in the same file whose values are client-wide trust settings
    global_keys: tuple[tuple[str, ...], ...] = ()
    #: entry ``type`` values that are not external servers (for example Goose ``builtin`` extensions)
    skip_types: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class ClientSpec:
    client: str
    locations: tuple[ConfigLocation, ...]
    #: per-server keys copied (stringified) into ``client_trust_flags``
    trust_keys: tuple[str, ...] = ()
    #: keys that carry a remote URL, in precedence order
    url_keys: tuple[str, ...] = ("url",)
    #: per-server keys listing tools the client restricts or auto-approves (become declared tool records)
    tool_list_keys: tuple[str, ...] = ()
    #: client-specific field names mapped to the canonical ones (``cmd`` -> ``command``, ``envs`` -> ``env``)
    field_aliases: tuple[tuple[str, str], ...] = ()


_ALL: Final[frozenset[Platform]] = frozenset({"linux", "macos", "windows"})

_WIN: Final[frozenset[Platform]] = frozenset({"windows"})
_UNIX: Final[frozenset[Platform]] = frozenset({"linux", "macos"})

#: Verified client formats (``spec/collectors.md``; adoption-first proposal Appendix B; WP9 format research
#: 2026-11-01 against each client's official docs or source). ``.mcp.json`` is also read by GitHub Copilot CLI;
#: it is attributed to Claude Code here.
CLIENTS: Final[tuple[ClientSpec, ...]] = (
    ClientSpec(
        client="claude-code",
        locations=(
            ConfigLocation("project", "root", ".mcp.json", "json", ("mcpServers",)),
            ConfigLocation("user", "home", ".claude.json", "json", ("mcpServers",), claude_projects=True),
        ),
    ),
    ClientSpec(
        client="claude-desktop",
        locations=(
            ConfigLocation("user", "appconfig", "Claude/claude_desktop_config.json", "json", ("mcpServers",)),
        ),
    ),
    ClientSpec(
        client="cursor",
        locations=(
            ConfigLocation("project", "root", ".cursor/mcp.json", "json", ("mcpServers",)),
            ConfigLocation("user", "home", ".cursor/mcp.json", "json", ("mcpServers",)),
            ConfigLocation("user", "home", ".cursor/plugins/local/*/mcp.json", "json", ("mcpServers",)),
        ),
    ),
    ClientSpec(
        client="vscode",
        locations=(
            ConfigLocation("project", "root", ".vscode/mcp.json", "jsonc", ("servers",)),
            ConfigLocation(
                "project",
                "root",
                ".devcontainer/devcontainer.json",
                "jsonc",
                ("customizations", "vscode", "mcp", "servers"),
            ),
            ConfigLocation("user", "appconfig", "Code/User/mcp.json", "jsonc", ("servers",)),
            ConfigLocation("user", "appconfig", "Code/User/profiles/*/mcp.json", "jsonc", ("servers",)),
            ConfigLocation("user", "appconfig", "Code - Insiders/User/mcp.json", "jsonc", ("servers",)),
        ),
    ),
    ClientSpec(
        client="windsurf",
        locations=(
            ConfigLocation("user", "home", ".codeium/windsurf/mcp_config.json", "json", ("mcpServers",)),
            ConfigLocation("user", "home", ".codeium/mcp_config.json", "json", ("mcpServers",)),
        ),
        url_keys=("serverUrl", "url"),
        trust_keys=("disabledTools",),
    ),
    ClientSpec(
        client="codex",
        locations=(
            ConfigLocation("project", "root", ".codex/config.toml", "toml", ("mcp_servers",)),
            ConfigLocation("user", "home", ".codex/config.toml", "toml", ("mcp_servers",)),
        ),
        trust_keys=(
            "enabled_tools",
            "disabled_tools",
            "bearer_token_env_var",
            "startup_timeout_sec",
            "tool_timeout_sec",
        ),
        tool_list_keys=("enabled_tools",),
    ),
    ClientSpec(
        client="gemini-cli",
        locations=(
            ConfigLocation("project", "root", ".gemini/settings.json", "jsonc", ("mcpServers",)),
            ConfigLocation("user", "home", ".gemini/settings.json", "jsonc", ("mcpServers",)),
            ConfigLocation(
                "user", "home", ".gemini/extensions/*/gemini-extension.json", "json", ("mcpServers",)
            ),
        ),
        url_keys=("httpUrl", "url"),
        trust_keys=("trust", "includeTools", "excludeTools", "timeout"),
        tool_list_keys=("includeTools",),
    ),
    ClientSpec(
        client="github-copilot-cli",
        locations=(
            ConfigLocation("project", "root", ".github/mcp.json", "json", ("mcpServers",)),
            ConfigLocation("user", "home", ".copilot/mcp-config.json", "json", ("mcpServers",)),
        ),
        trust_keys=("tools",),
    ),
    ClientSpec(
        client="cline",
        locations=(
            ConfigLocation(
                "user", "home", ".cline/data/settings/cline_mcp_settings.json", "json", ("mcpServers",)
            ),
            ConfigLocation(
                "user",
                "appconfig",
                "Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
                "json",
                ("mcpServers",),
            ),
            ConfigLocation(
                "user", "home", "Documents/Cline/MCP/cline_mcp_settings.json", "json", ("mcpServers",)
            ),
        ),
        trust_keys=("autoApprove", "alwaysAllow", "timeout"),
        tool_list_keys=("autoApprove",),
    ),
    ClientSpec(
        client="roo",
        locations=(
            ConfigLocation("project", "root", ".roo/mcp.json", "json", ("mcpServers",)),
            ConfigLocation(
                "user",
                "appconfig",
                "Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
                "json",
                ("mcpServers",),
            ),
        ),
        trust_keys=("alwaysAllow",),
        tool_list_keys=("alwaysAllow",),
    ),
    ClientSpec(
        client="kiro",
        locations=(
            ConfigLocation("project", "root", ".kiro/settings/mcp.json", "json", ("mcpServers",)),
            ConfigLocation("user", "home", ".kiro/settings/mcp.json", "json", ("mcpServers",)),
        ),
        trust_keys=("autoApprove", "disabledTools"),
        tool_list_keys=("autoApprove",),
    ),
    ClientSpec(
        client="continue",
        locations=(
            ConfigLocation("user", "home", ".continue/config.yaml", "yaml", ("mcpServers",), shape="list"),
            ConfigLocation(
                "project", "root", ".continue/mcpServers/*.yaml", "yaml", ("mcpServers",), shape="list"
            ),
            ConfigLocation("project", "root", ".continue/mcpServers/*.json", "json", ("mcpServers",)),
            ConfigLocation("user", "home", ".continue/mcpServers/*.json", "json", ("mcpServers",)),
        ),
    ),
    ClientSpec(
        client="zed",
        locations=(
            ConfigLocation("project", "root", ".zed/settings.json", "jsonc", ("context_servers",)),
            ConfigLocation(
                "user",
                "home",
                ".config/zed/settings.json",
                "jsonc",
                ("context_servers",),
                platforms=_UNIX,
                global_keys=(
                    ("agent", "tool_permissions", "default"),
                    ("agent", "always_allow_tool_actions"),
                ),
            ),
            ConfigLocation(
                "user",
                "appconfig",
                "Zed/settings.json",
                "jsonc",
                ("context_servers",),
                platforms=_WIN,
                global_keys=(
                    ("agent", "tool_permissions", "default"),
                    ("agent", "always_allow_tool_actions"),
                ),
            ),
        ),
    ),
    ClientSpec(
        client="junie",
        locations=(
            ConfigLocation("project", "root", ".junie/mcp/mcp.json", "json", ("mcpServers",)),
            ConfigLocation("user", "home", ".junie/mcp/mcp.json", "json", ("mcpServers",)),
        ),
    ),
    ClientSpec(
        client="amazon-q",
        locations=(
            ConfigLocation("project", "root", ".amazonq/mcp.json", "json", ("mcpServers",)),
            ConfigLocation(
                "project",
                "root",
                ".amazonq/cli-agents/*.json",
                "json",
                ("mcpServers",),
                global_keys=(("allowedTools",),),
            ),
            ConfigLocation("user", "home", ".aws/amazonq/mcp.json", "json", ("mcpServers",)),
            ConfigLocation(
                "user",
                "home",
                ".aws/amazonq/cli-agents/*.json",
                "json",
                ("mcpServers",),
                global_keys=(("allowedTools",),),
            ),
        ),
    ),
    ClientSpec(
        client="opencode",
        locations=(
            ConfigLocation(
                "project", "root", "opencode.json", "jsonc", ("mcp",), global_keys=(("permission",),)
            ),
            ConfigLocation(
                "project", "root", "opencode.jsonc", "jsonc", ("mcp",), global_keys=(("permission",),)
            ),
            ConfigLocation(
                "user",
                "home",
                ".config/opencode/opencode.json",
                "jsonc",
                ("mcp",),
                global_keys=(("permission",),),
            ),
            ConfigLocation(
                "user",
                "home",
                ".config/opencode/opencode.jsonc",
                "jsonc",
                ("mcp",),
                global_keys=(("permission",),),
            ),
        ),
        field_aliases=(("environment", "env"),),
    ),
    ClientSpec(
        client="goose",
        locations=(
            ConfigLocation(
                "user",
                "home",
                ".config/goose/config.yaml",
                "yaml",
                ("extensions",),
                platforms=_UNIX,
                global_keys=(("GOOSE_MODE",),),
                skip_types=frozenset({"builtin", "platform", "frontend"}),
            ),
            ConfigLocation(
                "user",
                "appconfig",
                "Block/goose/config/config.yaml",
                "yaml",
                ("extensions",),
                platforms=_WIN,
                global_keys=(("GOOSE_MODE",),),
                skip_types=frozenset({"builtin", "platform", "frontend"}),
            ),
        ),
        field_aliases=(("cmd", "command"), ("envs", "env"), ("uri", "url")),
        trust_keys=("available_tools",),
    ),
    ClientSpec(
        client="lm-studio",
        locations=(ConfigLocation("user", "home", ".lmstudio/mcp.json", "json", ("mcpServers",)),),
    ),
    ClientSpec(
        client="openclaw",
        locations=(ConfigLocation("user", "home", ".openclaw/openclaw.json", "jsonc", ("mcp", "servers")),),
    ),
)

_AUTH_HEADERS: Final = frozenset(
    {"authorization", "x-api-key", "api-key", "x-auth-token", "proxy-authorization"}
)


@dataclass(slots=True)
class ServerDecl:
    """One server entry as parsed from a client config (values already reduced to names / redacted)."""

    client: str
    scope: Scope
    config_display: str
    name: str
    locator: str
    transport: Transport
    transport_source: str
    command: str | None
    redacted_args: list[str]
    url_display: str | None
    url_zone: TrustZone | None
    url_crosses: bool | None
    url_query_names: tuple[str, ...]
    launch: LaunchFacts | None
    env: dict[str, str] = field(default_factory=dict)  # name -> value kind (never the value)
    headers: dict[str, str] = field(default_factory=dict)
    trust_flags: dict[str, str] = field(default_factory=dict)
    declared_tools: list[str] = field(default_factory=list)
    disabled: bool = False
    redactions: int = 0
    warnings: list[str] = field(default_factory=list)
    oauth_configured: bool = False


def _dig(data: object, path: Iterable[str]) -> object:
    cur = data
    for key in path:
        if not isinstance(cur, Mapping):
            return None
        cur = cur.get(key)
    return cur


_TYPE_TRANSPORT: Final[dict[str, Transport]] = {
    "stdio": Transport.STDIO,
    "local": Transport.STDIO,
    "http": Transport.STREAMABLE_HTTP,
    "streamable-http": Transport.STREAMABLE_HTTP,
    "streamablehttp": Transport.STREAMABLE_HTTP,
    "remote": Transport.STREAMABLE_HTTP,
    "sse": Transport.SSE,
    "ws": Transport.WEBSOCKET,
    "websocket": Transport.WEBSOCKET,
}


def _transport(entry: Mapping[str, Any], url_keys: tuple[str, ...]) -> tuple[Transport, str, str | None]:
    """Apply the spec's transport rule; returns (transport, which rule fired, url)."""
    url = next((str(entry[k]) for k in url_keys if isinstance(entry.get(k), str) and entry.get(k)), None)
    if entry.get("command"):
        return Transport.STDIO, "command", url
    declared = str(entry.get("type", "")).lower().replace("_", "-")
    if declared in _TYPE_TRANSPORT:
        return _TYPE_TRANSPORT[declared], "type", url
    if isinstance(entry.get("httpUrl"), str):
        return Transport.STREAMABLE_HTTP, "httpUrl", str(entry["httpUrl"])
    is_sse = bool(url and url.rstrip("/").endswith("/sse"))
    return (Transport.SSE, "url-suffix", url) if is_sse else (Transport.STREAMABLE_HTTP, "default", url)


def _server_entries(
    data: object, loc: ConfigLocation, root: Path
) -> list[tuple[tuple[str | int, ...], str, Mapping[str, Any]]]:
    out: list[tuple[tuple[str | int, ...], str, Mapping[str, Any]]] = []
    servers = _dig(data, loc.servers_path)
    if isinstance(servers, Mapping):
        out.extend(
            ((*loc.servers_path, name), str(name), entry)
            for name, entry in servers.items()
            if isinstance(entry, Mapping)
        )
    elif isinstance(servers, list):
        for i, entry in enumerate(servers):
            if isinstance(entry, Mapping):
                out.append(((*loc.servers_path, i), str(entry.get("name") or f"server-{i}"), entry))
    if loc.claude_projects:
        projects = _dig(data, ("projects",))
        if isinstance(projects, Mapping):
            for project_path, project in projects.items():
                # only the project being scanned: other projects' configs are private and out of scope
                if not isinstance(project, Mapping) or Path(str(project_path)).resolve() != root.resolve():
                    continue
                nested = project.get("mcpServers")
                if isinstance(nested, Mapping):
                    out.extend(
                        (("projects", str(project_path), "mcpServers", name), str(name), entry)
                        for name, entry in nested.items()
                        if isinstance(entry, Mapping)
                    )
    return out


def _normalize_entry(entry: Mapping[str, Any], aliases: tuple[tuple[str, str], ...]) -> dict[str, Any]:
    """Map client-specific field names to canonical ones and unnest Zed's ``command: {path, args, env}``."""
    out = dict(entry)
    for alias, canonical in aliases:
        if alias in out and canonical not in out:
            out[canonical] = out[alias]
    command = out.get("command")
    if isinstance(command, Mapping):
        out["command"] = command.get("path") or command.get("command")
        if "args" in command and "args" not in entry:
            out["args"] = command["args"]
        if "env" in command and "env" not in entry:
            out["env"] = command["env"]
    return out


def parse_client_config(
    spec: ClientSpec, loc: ConfigLocation, data: object, display: str, root: Path
) -> list[ServerDecl]:
    """Turn one parsed client config into server declarations (pure function; no filesystem access)."""
    decls: list[ServerDecl] = []
    for pointer, name, raw_entry in _server_entries(data, loc, root):
        if str(raw_entry.get("type", "")).lower() in loc.skip_types:
            continue
        entry = _normalize_entry(raw_entry, spec.field_aliases)
        transport, rule, url = _transport(entry, spec.url_keys)
        command = entry.get("command")
        args_raw = entry.get("args", [])
        if isinstance(command, list):  # some clients store argv as a single list
            args_raw = [*command[1:], *(args_raw if isinstance(args_raw, list) else [])]
            command = command[0] if command else None
        command_s = str(command) if command else None
        redacted, n_redacted = redact_args(as_str_list(args_raw))
        launch = parse_launch(command_s, redacted) if transport is Transport.STDIO else None
        facts = url_facts(url) if url else None
        decl = ServerDecl(
            client=spec.client,
            scope=loc.scope,
            config_display=display,
            name=name,
            locator=locator(display, *pointer),
            transport=transport,
            transport_source=rule,
            command=command_s,
            redacted_args=redacted,
            url_display=facts.display if facts else None,
            url_zone=facts.trust_zone if facts else None,
            url_crosses=facts.crosses_trust_boundary if facts else None,
            url_query_names=facts.query_param_names if facts else (),
            launch=launch,
            redactions=n_redacted,
        )
        if facts and (facts.had_userinfo or facts.secret_in_query):
            decl.redactions += 1
            decl.warnings.append("credential material in server URL (userinfo or query) was dropped")
        for env_name in names_from_mapping(entry.get("env")):
            decl.env[env_name] = classify_env_value(env_name, _dig(entry, ("env", env_name)))
        for header in names_from_mapping(entry.get("headers")):
            decl.headers[header] = classify_env_value(header, _dig(entry, ("headers", header)))
        for key in spec.trust_keys:
            if key in entry:
                value = entry[key]
                decl.trust_flags[f"{spec.client}.{key}"] = (
                    ",".join(as_str_list(value))
                    if isinstance(value, list)
                    else str(value).lower()
                    if isinstance(value, bool)
                    else str(value)
                )
        for key in spec.tool_list_keys:
            decl.declared_tools.extend(as_str_list(entry.get(key)))
        if spec.client == "codex" and isinstance(entry.get("bearer_token_env_var"), str):
            decl.env.setdefault(str(entry["bearer_token_env_var"]), "placeholder")
        if entry.get("disabled") is True or entry.get("enabled") is False:
            decl.disabled = True
        decl.oauth_configured = isinstance(entry.get("oauth"), Mapping) or "authProviderType" in entry
        if launch is not None and launch.risky_flags:
            decl.trust_flags[f"{spec.client}.container-risks"] = ",".join(launch.risky_flags)
        if launch is not None:
            decl.trust_flags["launcher"] = launch.launcher_detail
        decls.append(decl)
    return decls


# --------------------------------------------------------------------------------------------- client-level trust settings


def _claude_code_settings(
    paths: Iterable[tuple[Path, str]], ctx: CollectContext
) -> dict[str, dict[str, str]]:
    """Per-server Claude Code trust flags from ``permissions.allow`` / ``defaultMode`` / project-server opt-ins."""
    per_server: dict[str, dict[str, str]] = {}
    global_flags: dict[str, str] = {}
    for path, scope in paths:
        outcome = ctx.read_config(path)
        if not outcome.ok or outcome.data is None:
            continue
        try:
            data = parse_structured(outcome.data, "json")
        except (ValueError, UnicodeDecodeError):
            continue
        perms = data.get("permissions") if isinstance(data, Mapping) else None
        if isinstance(perms, Mapping):
            mode = perms.get("defaultMode")
            if isinstance(mode, str):
                global_flags[f"claude-code.defaultMode.{scope}"] = mode
            for rule in as_str_list(perms.get("allow")):
                if not rule.startswith("mcp__"):
                    continue
                parts = rule.split("__", 2)
                server = parts[1] if len(parts) > 1 else "*"
                tool = parts[2] if len(parts) > 2 else "*"
                flags = per_server.setdefault(server, {})
                current = flags.get("claude-code.permissions.allow")
                flags["claude-code.permissions.allow"] = ",".join(
                    sorted({*(current.split(",") if current else []), tool})
                )
        if isinstance(data, Mapping) and data.get("enableAllProjectMcpServers") is True:
            global_flags["claude-code.enableAllProjectMcpServers"] = "true"
    if global_flags:
        per_server.setdefault("*", {}).update(global_flags)
    return per_server


def _vscode_settings(paths: Iterable[Path], ctx: CollectContext) -> dict[str, str]:
    flags: dict[str, str] = {}
    for path in paths:
        outcome = ctx.read_config(path)
        if not outcome.ok or outcome.data is None:
            continue
        try:
            data = parse_structured(outcome.data, "jsonc")
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(data, Mapping):
            for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove", "chat.agent.enabled"):
                if key in data:
                    flags[f"vscode.{key}"] = str(data[key]).lower()
    return flags


def _global_flags(client: str, loc: ConfigLocation, data: object) -> dict[str, str]:
    """Client-wide trust settings declared in the same file (``loc.global_keys``)."""
    flags: dict[str, str] = {}
    for path in loc.global_keys:
        value = _dig(data, path)
        if value is None:
            continue
        rendered = (
            str(value).lower()
            if isinstance(value, bool)
            else ",".join(as_str_list(value))
            if isinstance(value, list)
            else json.dumps(value, sort_keys=True)
            if isinstance(value, Mapping)
            else str(value)
        )
        flags[f"{client}.{'.'.join(path)}"] = rendered
    return flags


def _codex_globals(data: object) -> dict[str, str]:
    if not isinstance(data, Mapping):
        return {}
    flags = {
        f"codex.{k}": str(data[k])
        for k in ("approval_policy", "sandbox_mode")
        if isinstance(data.get(k), str)
    }
    sandbox = data.get("sandbox_workspace_write")
    if isinstance(sandbox, Mapping) and "network_access" in sandbox:
        flags["codex.sandbox_workspace_write.network_access"] = str(sandbox["network_access"]).lower()
    return flags


def _gemini_globals(data: object) -> dict[str, str]:
    if not isinstance(data, Mapping):
        return {}
    flags: dict[str, str] = {}
    if "autoAccept" in data:
        flags["gemini-cli.autoAccept"] = str(data["autoAccept"]).lower()
    tools = data.get("tools")
    if isinstance(tools, Mapping) and "autoAccept" in tools:
        flags["gemini-cli.tools.autoAccept"] = str(tools["autoAccept"]).lower()
    return flags


# --------------------------------------------------------------------------------------------- collector


class McpConfigCollector(BaseCollector):
    """Declared MCP servers from every supported client configuration."""

    name = "mcp-config"
    version = "0.1.0"
    surfaces = (Surface.TOOLS,)
    mode = CollectorMode.DECLARED

    def __init__(self, clients: tuple[ClientSpec, ...] = CLIENTS) -> None:
        self.clients = clients

    def detect(self, ctx: CollectContext) -> bool:
        del ctx
        return True  # absence of every config is itself a fact worth recording (queried, 0 items)

    def _location_paths(self, ctx: CollectContext, loc: ConfigLocation) -> list[Path] | None:
        """Concrete files for a location (glob segments expanded); ``None`` when the scope is not in reach."""
        if loc.platforms is not None and ctx.platform not in loc.platforms:
            return None
        if loc.base == "root":
            base: Path | None = ctx.root
        elif loc.base == "home":
            base = ctx.home
        else:
            base = ctx.user_config_dir()
        if base is None:
            return None
        if "*" in loc.relpath:
            return sorted(p for p in base.glob(loc.relpath) if p.is_file() and not p.is_symlink())
        return [base / loc.relpath]

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        decls: list[ServerDecl] = []
        client_globals: dict[str, dict[str, str]] = {}
        checked = 0
        for spec in self.clients:
            for loc in spec.locations:
                paths = self._location_paths(ctx, loc)
                if paths is None:
                    continue
                checked += 1
                for path in paths:
                    if not path.is_file():
                        continue
                    data = self._read(ctx, result, spec, loc, path)
                    if data is None:
                        continue
                    display = ctx.display(path)
                    found = parse_client_config(spec, loc, data, display, ctx.root)
                    decls.extend(found)
                    result.add_source(
                        Surface.TOOLS,
                        f"{spec.client}:{loc.scope}",
                        locator=display,
                        ok=True,
                        items=len(found),
                    )
                    flags = client_globals.setdefault(spec.client, {})
                    flags.update(_global_flags(spec.client, loc, data))
                    if spec.client == "codex":
                        flags.update(_codex_globals(data))
                    if spec.client == "gemini-cli":
                        flags.update(_gemini_globals(data))
        if ctx.home is None:
            result.add_source(Surface.TOOLS, "user-scope", ok=False, error_class="not-attempted")
        result.add_source(Surface.TOOLS, "locations-checked", ok=True, items=0, locator=str(checked))

        claude_flags = _claude_code_settings(self._claude_settings_paths(ctx), ctx)
        vscode_flags = _vscode_settings(self._vscode_settings_paths(ctx), ctx)
        client_globals.setdefault("vscode", {}).update(vscode_flags)

        used_ids: set[str] = set()
        total_redactions = 0
        for decl in decls:
            flags = dict(client_globals.get(decl.client, {}))
            if decl.client == "claude-code":
                flags.update(claude_flags.get("*", {}))
                flags.update(claude_flags.get(decl.name, {}))
            flags.update(decl.trust_flags)
            decl.trust_flags = dict(sorted(flags.items()))
            total_redactions += decl.redactions + sum(
                1 for kind in (*decl.env.values(), *decl.headers.values()) if kind == "literal-secret"
            )
            result.warnings.extend(f"{decl.locator}: {w}" for w in decl.warnings)
            self._emit(ctx, result, decl, used_ids)
        if total_redactions:
            result.redactions.append(
                Redaction(
                    redaction_class="credential-shaped-token",
                    count=total_redactions,
                    applied_by=self.ref,
                    applied_at=ctx.now,
                )
            )
        return result

    @staticmethod
    def _read(
        ctx: CollectContext, result: CollectionResult, spec: ClientSpec, loc: ConfigLocation, path: Path
    ) -> object | None:
        display = ctx.display(path)
        outcome = ctx.read_config(path)  # confined beneath the scan root, home or user config dir
        if not outcome.ok or outcome.data is None:
            result.add_source(
                Surface.TOOLS,
                f"{spec.client}:{loc.scope}",
                locator=display,
                ok=False,
                error_class=outcome.error_class,
            )
            return None
        try:
            parsed: object = parse_structured(outcome.data, loc.fmt)
        except (ValueError, UnicodeDecodeError) as exc:
            result.add_source(
                Surface.TOOLS,
                f"{spec.client}:{loc.scope}",
                locator=display,
                ok=False,
                error_class="parse-error",
            )
            result.warnings.append(f"{display}: {type(exc).__name__}: {str(exc)[:120]}")
            return None
        return parsed

    @staticmethod
    def _claude_settings_paths(ctx: CollectContext) -> list[tuple[Path, str]]:
        paths = [
            (ctx.root / ".claude" / "settings.json", "project"),
            (ctx.root / ".claude" / "settings.local.json", "local"),
        ]
        if ctx.home is not None:
            paths.append((ctx.home / ".claude" / "settings.json", "user"))
        return paths

    @staticmethod
    def _vscode_settings_paths(ctx: CollectContext) -> list[Path]:
        paths = [ctx.root / ".vscode" / "settings.json"]
        app = ctx.user_config_dir()
        if app is not None:
            paths.append(app / "Code" / "User" / "settings.json")
        return paths

    def _emit(
        self, ctx: CollectContext, result: CollectionResult, decl: ServerDecl, used_ids: set[str]
    ) -> None:
        server_id = make_id("server", f"{decl.client}-{decl.name}")
        if server_id in used_ids:
            server_id = make_id("server", f"{decl.client}-{decl.name}", collision_seed=decl.locator)
        used_ids.add(server_id)
        prov = Provenance(
            method=ClaimMethod.CONFIG, locator=decl.locator, collector=self.ref, observed_at=ctx.now
        )

        def declared(value: Any) -> Claim[Any]:
            return Claim.declared(value, locator=decl.locator, collector=self.ref, observed_at=ctx.now)

        package_claim: Claim[PackageRef] | None = None
        package_ident: dict[str, str | None] | None = None
        launch = decl.launch
        if launch is not None and launch.package_name is not None:
            pkg = PackageRef(
                purl=launch.purl,
                digest=launch.digest if launch.digest else None,
                floating=not launch.pinned,
                launcher=launch.launcher,
            )
            package_claim = declared(pkg)
            package_ident = {"purl": launch.purl or launch.package_name, "digest": launch.digest}

        if decl.transport is Transport.STDIO:
            zone, crosses = TrustZone.LOCAL_PROCESS, False
        else:
            zone, crosses = decl.url_zone or TrustZone.UNKNOWN, bool(decl.url_crosses)
        auth = self._authentication(decl)
        identity_digest = server_identity_digest(
            kind=ToolServerKind.MCP.value,
            transport=decl.transport.value,
            endpoint=decl.url_display if decl.transport is not Transport.STDIO else None,
            package=package_ident,
        )
        args_digest: str | None = None
        if decl.redacted_args:
            try:
                args_digest = "sha256:" + hashlib.sha256(canonical_bytes(decl.redacted_args)).hexdigest()
            except UndigestableError:
                args_digest = None
        tags = [f"scope:{decl.scope}"]
        if decl.disabled:
            tags.append("disabled")
        if launch is not None and launch.local_path is not None:
            tags.append("local-command")
        if launch is not None and launch.float_reason:
            tags.append(f"float:{launch.float_reason}")
        server = ToolServer(
            id=server_id,
            name=decl.name,
            provenance=prov,
            tags=tags,
            server_kind=ToolServerKind.MCP,
            digest=identity_digest.value if identity_digest.ok else None,
            client=decl.client,
            transport=Claim.declared(
                decl.transport, locator=decl.locator, collector=self.ref, observed_at=ctx.now
            ),
            endpoint=declared(decl.url_display)
            if decl.url_display and decl.transport is not Transport.STDIO
            else None,
            package=package_claim,
            command=self._command_display(ctx, decl.command),
            args_digest=args_digest,
            env_var_names=sorted(decl.env),
            header_names=sorted(decl.headers),
            authentication=auth,
            trust_zone=zone,
            crosses_trust_boundary=declared(crosses),
            client_trust_flags=decl.trust_flags,
        )
        result.entities.append(server)
        result.edges.append(
            Edge.model_validate(
                {
                    "type": EdgeType.DEPENDS_ON,
                    "from": ctx.agent_id,
                    "to": server_id,
                    "scope": EdgeScope.RUNTIME,
                    "qualifiers": {
                        "relation": "mcp-server",
                        "client": decl.client,
                        "configScope": decl.scope,
                    },
                    "declaredBy": decl.locator,
                }
            )
        )
        self._emit_credentials(result, decl, server_id, prov)
        self._emit_declared_tools(ctx, result, decl, server_id, prov)

    @staticmethod
    def _command_display(ctx: CollectContext, command: str | None) -> str | None:
        if command is None:
            return None
        path = Path(command)
        return ctx.display(path) if path.is_absolute() else command

    def _authentication(self, decl: ServerDecl) -> Claim[Authentication]:
        loc = decl.locator
        if decl.transport is Transport.STDIO:
            return Claim.declared(Authentication(mode=AuthMode.NONE), locator=loc, collector=self.ref)
        if decl.oauth_configured:
            return Claim.declared(Authentication(mode=AuthMode.OAUTH2), locator=loc, collector=self.ref)
        auth_headers = [h for h in decl.headers if h.lower() in _AUTH_HEADERS or secretish_name(h)]
        if auth_headers or any(k.startswith("codex.bearer_token_env_var") for k in decl.trust_flags):
            return Claim.declared(Authentication(mode=AuthMode.API_KEY), locator=loc, collector=self.ref)
        # remote servers usually negotiate OAuth at connect time (MCP authorization); config alone cannot tell
        return Claim.unknown(UnknownReason.NOT_COLLECTED, locator=loc, collector=self.ref)

    def _emit_credentials(
        self, result: CollectionResult, decl: ServerDecl, server_id: str, prov: Provenance
    ) -> None:
        server_slug = server_id.split(":", 1)[1]
        entries = [("env", name, kind) for name, kind in decl.env.items()] + [
            ("header", name, kind) for name, kind in decl.headers.items()
        ]
        for channel, name, kind in entries:
            if kind not in {"literal-secret", "placeholder"} and not secretish_name(name):
                continue
            ident_id = make_id("ident", f"{server_slug}-{channel}-{name}")
            cred_id = make_id("cred", f"{server_slug}-{channel}-{name}")
            storage = (
                CredentialStorage(kind=CredentialStorageKind.FILE, locator=f"{decl.locator}/{channel}/{name}")
                if kind == "literal-secret"
                else CredentialStorage(
                    kind=CredentialStorageKind.KEYCHAIN
                    if decl.client == "vscode" and "input:" in name
                    else CredentialStorageKind.ENV,
                    locator=f"{channel}:{name}",
                )
            )
            result.entities.append(
                Identity(
                    id=ident_id,
                    name=name,
                    provenance=prov,
                    identity_kind=IdentityKind.API_KEY_REF,
                    ref=f"{channel}:{name}",
                )
            )
            result.entities.append(
                CredentialBinding(
                    id=cred_id,
                    name=f"{decl.name} {channel} {name}",
                    provenance=prov,
                    subject_ref=server_id,
                    identity_ref=ident_id,
                    credential_kind=CredentialKind.STATIC_LONG_LIVED
                    if kind == "literal-secret"
                    else CredentialKind.UNKNOWN,
                    storage=storage,
                    tags=["inline-secret-in-config"] if kind == "literal-secret" else [],
                )
            )
            result.edges.append(
                Edge.model_validate(
                    {
                        "type": EdgeType.HOLDS_CREDENTIAL,
                        "from": server_id,
                        "to": cred_id,
                        "qualifiers": {"channel": channel},
                        "declaredBy": decl.locator,
                    }
                )
            )

    def _emit_declared_tools(
        self,
        ctx: CollectContext,
        result: CollectionResult,
        decl: ServerDecl,
        server_id: str,
        prov: Provenance,
    ) -> None:
        gate = ApprovalGate.UNKNOWN
        if decl.trust_flags.get(f"{decl.client}.trust") == "true":
            gate = ApprovalGate.NONE
        for tool_name in dict.fromkeys(decl.declared_tools):
            if not tool_name or tool_name == "*":
                continue
            tid = tool_id(server_id, tool_name)
            result.entities.append(
                ToolDefinition(
                    id=tid,
                    name=tool_name,
                    provenance=prov,
                    server_ref=server_id,
                    tool_name=tool_name,
                    input_schema={},
                    digest=DigestResult(
                        algorithm="tooldef/v1",
                        status=DigestStatus.UNDIGESTABLE,
                        reason="declared-without-definition: only the name is configured; observe it live to pin",
                    ),
                    source=ToolSource.DECLARED_CONFIG,
                    approval_gate=gate,
                )
            )
            result.edges.append(
                Edge.model_validate(
                    {"type": EdgeType.PROVIDES_TOOL, "from": server_id, "to": tid, "declaredBy": decl.locator}
                )
            )
            result.edges.append(
                Edge.model_validate(
                    {
                        "type": EdgeType.INVOKES_TOOL,
                        "from": ctx.agent_id,
                        "to": tid,
                        "qualifiers": {"mode": "declared"},
                        "declaredBy": decl.locator,
                    }
                )
            )
