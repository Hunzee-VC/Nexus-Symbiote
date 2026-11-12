"""MCP server and tool scanner.

Discovers MCP server configurations in the project-level client files listed in
``MCP_DIALECTS`` (Claude Code, Claude Desktop, Cursor, VS Code, Gemini CLI, Roo Code,
Kiro, Amazon Q, Windsurf, Cline and Codex), in the configuration names of
``MCP_CONFIG_NAMES`` anywhere below the root, and MCP server source written in the
supported SDK forms. Each launch command is classified without being executed
(``scanners/mcp_launch.py``); declared tools are fingerprinted; unpinned packages,
redirected package sources, launch context and endpoint transport are reported.
Client files that are recognised but not parsed, and launchers or endpoints that
cannot be classified, are coverage gaps rather than silence.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import posixpath
import re
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from packaging.utils import canonicalize_name

from nexus_symbiote.core.enums import (
    CapabilityClass,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    canonical_json,
    hash_canonical,
    hash_tool_definition,
    tool_definition_extensions,
)
from nexus_symbiote.core.models import (
    CapabilityDeclaration,
    MCPClientComponent,
    MCPServerComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    SourceBudget,
    sanitized_origin,
    source_collection_bytes,
)
from nexus_symbiote.scanners.mcp_launch import (
    NPM_CONFIG_FLAGS,
    NPM_CONFIG_VALUES,
    Launch,
    Package,
    analyze,
    expands,
    known_executable,
    origin,
)
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.jsonc import strip_jsonc
from nexus_symbiote.utils.secrets import (
    REDACTED,
    TOKEN_SHAPE,
    SecretScrubber,
    redact_descriptor,
    redact_text,
    secret_values,
)


@dataclass(frozen=True)
class McpDialect:
    """An MCP client file: where it is, how it is written and how it nests servers.

    The client that reads it is named from its path by ``_detect_host_from_config``.
    """

    path: str
    syntax: str
    maps: tuple[str, ...]
    url_transport: str | None = None


# Every MCP configuration file is read for both server maps, whichever its client
# reads; a server named in both is a failure. Gemini CLI settings and Codex
# configuration hold other settings too, so only their own map is read there.
_SERVER_MAPS = ("mcpServers", "servers")
MCP_DIALECTS = (
    McpDialect(".mcp.json", "json", _SERVER_MAPS),
    McpDialect("mcp.json", "json", _SERVER_MAPS),
    McpDialect("claude_desktop_config.json", "json", _SERVER_MAPS),
    McpDialect(".cursor/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".claude/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".vscode/mcp.json", "jsonc", _SERVER_MAPS),
    McpDialect(".gemini/settings.json", "jsonc", ("mcpServers",), "sse"),
    McpDialect(".roo/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".kiro/settings/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".amazonq/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".windsurf/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".cline/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".codex/config.toml", "toml", ("mcp_servers",)),
)
MCP_CONFIG_FILES = [dialect.path for dialect in MCP_DIALECTS]

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
    ".gemini": "gemini-cli",
    ".codex": "codex",
}


def _template(path: str) -> McpDialect | None:
    """The dialect whose file ``path`` is, at the root or below it; the longest match wins."""
    matches = [
        dialect
        for dialect in MCP_DIALECTS
        if path == dialect.path or path.endswith("/" + dialect.path)
    ]
    return max(matches, key=lambda dialect: len(dialect.path)) if matches else None


def _dialect(path: str) -> McpDialect:
    """How to read the client file at ``path``, a root dialect or one of its nested copies.

    A nested copy of a dialect's file (``packages/api/.vscode/mcp.json``) is read as
    that dialect; any other configuration name is a generic server map.
    """
    template = _template(path)
    return (
        McpDialect(path, "json", _SERVER_MAPS) if template is None else replace(template, path=path)
    )


def _launch_directory(path: str) -> str:
    """The directory, relative to the root, that a client starts the file's servers in.

    A root dialect file's servers start at the root; a nested copy's start where it
    is, as Claude Code and VS Code start them in the directory they were opened in.
    A client directory such as ``.windsurf`` names no project directory of its own.
    """
    template = _template(path)
    if template is not None:
        return path[: -len(template.path)].rstrip("/")
    parts = path.split("/")[:-1]
    while parts and parts[-1] in _HOST_DIRECTORIES:
        parts.pop()
    return "/".join(parts)


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


# Client files whose MCP declarations are recognised but not parsed: a gap when present.
UNPARSED_CLIENT_FILES = (
    (".zed/settings.json", "context_servers"),
    ("opencode.json", "mcp"),
    ("opencode.jsonc", "mcp"),
    (".junie/mcp/mcp.json", None),
)
UNPARSED_CLIENT_DIRECTORIES = (".continue/mcpServers",)

MAX_SERVERS_PER_FILE = 1000
MAX_TOOLS_PER_SERVER = 1000
MAX_TOOLS_PER_FILE = 5000
MAX_ARGUMENTS = 1024
MAX_ENVIRONMENT = 256
MAX_HEADERS = 64
MAX_LIST_ENTRIES = 1000
MAX_TOOL_NODES = 20_000
MAX_TOOL_DEPTH = 64
MAX_FILE_NODES = 200_000

# Exported bindings must not be computable from secret values: an unkeyed digest
# over credentials lets anyone holding the BOM confirm guesses offline. The
# structure digest covers only fields the inventory already exports in clear.
# Values are bound by an HMAC under an operator key that never enters the BOM.
# A change to either preimage requires a new profile and new test vectors.
STATIC_CONFIG_HASH_PROFILE = "nexus-symbiote/mcp-static-config/v3"
STATIC_VALUE_BINDING_PROFILE = "nexus-symbiote/mcp-static-values/v2"
SOURCE_BINDING_KEY_ENV = "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY"
_MIN_SOURCE_BINDING_KEY_LENGTH = 32


def _names(words: str) -> frozenset[str]:
    return frozenset(words.split())


class SourceBindingKeyError(ValueError):
    """The operator's source binding key cannot be used; the message names the variable."""


def source_binding_key() -> bytes | None:
    """The operator key from the environment, validated once per collection."""
    key = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if not key:
        return None
    if len(key) < _MIN_SOURCE_BINDING_KEY_LENGTH:
        raise SourceBindingKeyError(
            f"{SOURCE_BINDING_KEY_ENV} must contain at least "
            f"{_MIN_SOURCE_BINDING_KEY_LENGTH} characters"
        )
    return key.encode()


def _value_binding(
    config: dict[str, Any], resolver: list[list[str]] | None = None
) -> tuple[str, str] | None:
    """The keyed binding of one server object and its key identifier, or None without a key."""
    key = source_binding_key()
    if key is None:
        return None
    binding = _keyed_binding(key, config, resolver or [])
    return binding["static_value_binding"], binding["static_value_binding_key_id"]


def _keyed_binding(key: bytes, config: dict[str, Any], resolver: list[list[str]]) -> dict[str, str]:
    try:
        message = canonical_json(
            {"profile": STATIC_VALUE_BINDING_PROFILE, "configuration": config, "resolver": resolver}
        )
    except (TypeError, ValueError) as exc:
        raise SourceBindingKeyError(
            f"{SOURCE_BINDING_KEY_ENV} binding needs RFC 8785 JSON values"
        ) from exc
    key_id = hmac.new(key, b"nexus-symbiote/source-binding-key-id", "sha256").hexdigest()
    return {
        "static_value_binding": "hmac-sha256:"
        + hmac.new(key, message.encode(), "sha256").hexdigest(),
        "static_value_binding_key_id": key_id[:32],
        "static_value_binding_profile": STATIC_VALUE_BINDING_PROFILE,
    }


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


_STRING_FIELDS = _names(
    "command url endpoint serverUrl httpUrl type transport transportType cwd envFile "
    "description name version bearer_token_env_var"
)
_LIST_FIELDS = _names(
    "args alwaysAllow autoApprove includeTools excludeTools enabled_tools disabled_tools "
    "disabledTools env_vars watchPaths"
)
_MAP_FIELDS = frozenset({"env", "headers", "http_headers", "env_http_headers"})
_BOOL_FIELDS = frozenset({"disabled", "trust", "enabled"})
_NUMBER_FIELDS = _names("timeout startup_timeout_sec startup_timeout_ms tool_timeout_sec")
_OBJECT_FIELDS = frozenset({"oauth", "auth", "dev"})
_KNOWN_FIELDS = (
    _STRING_FIELDS
    | _LIST_FIELDS
    | _MAP_FIELDS
    | _BOOL_FIELDS
    | _NUMBER_FIELDS
    | _OBJECT_FIELDS
    | {"tools", "gallery"}
)
_ENDPOINT_FIELDS = ("url", "endpoint", "serverUrl", "httpUrl")
# A field such as Claude Code's headersHelper names a command the client runs.
_COMMAND_FIELD = re.compile(r"(?i).*(?:helper|command|cmd|script|hooks?)")
_FIELD_NAME = re.compile(r"[A-Za-z0-9_.$-]{1,64}")
_SAFE_NAME = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}")
_TRANSPORT_TYPES = {
    "stdio": "stdio",
    "local": "stdio",
    "http": "streamable-http",
    "streamable-http": "streamable-http",
    "streamablehttp": "streamable-http",
    "sse": "sse",
    "ws": "websocket",
    "websocket": "websocket",
}
# Login shells, zsh, fish and Python's user site also load code from HOME, ZDOTDIR,
# XDG_CONFIG_HOME and PYTHONUSERBASE.
_CODE_LOADING_ENVIRONMENT = _names(
    "LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH "
    "DYLD_FRAMEWORK_PATH NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONSTARTUP PYTHONHOME "
    "PERL5OPT PERL5LIB RUBYOPT RUBYLIB JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS "
    "BASH_ENV ENV NPM_CONFIG_NODE_OPTIONS NPM_CONFIG_SCRIPT_SHELL SHELLOPTS BASHOPTS PS4 "
    "HOME ZDOTDIR XDG_CONFIG_HOME PYTHONUSERBASE"
)
# Environment names that make a package runner resolve from another registry, index,
# cache, proxy, trust store or engine. npm reads npm_config_<key> for every .npmrc key.
_NPM_REDIRECT = (
    r"(?:npm|pnpm)_config_(?:(?:@[^:]+:)?registry|userconfig|globalconfig|prefix|cache"
    r"|offline|prefer[-_]offline|proxy|https[-_]proxy|strict[-_]ssl|ca|cafile"
    r"|replace[-_]registry[-_]host|store[-_]dir)"
)
# Caches and tool directories count too: a prepared one in the checkout is used as is.
_UV_REDIRECT = (
    r"uv_(?:index|index_url|default_index|extra_index_url|find_links|config_file"
    r"|insecure_host|python_install_mirror|pypy_install_mirror|cache_dir|tool_dir)"
)
_REDIRECT_ENVIRONMENT = {
    "npm": _NPM_REDIRECT,
    "bun": rf"bun_config_registry|bun_install_cache_dir|bun_install|{_NPM_REDIRECT}",
    "yarn": (
        r"yarn_(?:npm_registry_server|registry|rc_filename|cache_folder|enable_strict_ssl"
        r"|https_proxy|http_proxy|ca_file_path|global_folder|npm_scopes)"
    ),
    "deno": rf"jsr_url|deno_cert|deno_dir|{_NPM_REDIRECT}",
    "uv-tool": _UV_REDIRECT,
    "uv-project": _UV_REDIRECT,
    "pip": (
        r"pip_(?:index|index_url|extra_index_url|find_links|config_file|trusted_host|proxy|cert"
        r"|cache_dir)|pipx_home|pipx_shared_libs"
    ),
    "go": (
        r"goproxy|goflags|gonosumdb|gonosumcheck|gosumdb|goprivate|gonoproxy|goinsecure"
        r"|gomodcache|gopath"
    ),
    "oci": (
        r"docker_(?:host|context|config|cert_path|tls_verify)|container_(?:host|connection)"
        r"|containers_(?:conf|registries_conf|storage_conf)|containerd_address"
    ),
}
_NODE_TRUST = r"node_extra_ca_certs|node_tls_reject_unauthorized"
_PYTHON_TRUST = r"ssl_cert_file|ssl_cert_dir|requests_ca_bundle|curl_ca_bundle"
# Environment names that add a trusted CA or disable TLS verification for a runner.
_TRUST_ENVIRONMENT = {
    "npm": _NODE_TRUST,
    "bun": _NODE_TRUST,
    "yarn": _NODE_TRUST,
    "deno": r"deno_tls_ca_store|ssl_cert_file",
    "uv-tool": _PYTHON_TRUST,
    "uv-project": _PYTHON_TRUST,
    "pip": _PYTHON_TRUST,
    "go": r"ssl_cert_file|ssl_cert_dir",
}
_PROXY_ENVIRONMENT = r"https?_proxy|all_proxy"
# Where a runner finds its user and global configuration, caches and programs: npm
# reads ~/.npmrc and <prefix>/etc/npmrc, uv and pip ~/.config, go $GOENV and
# ~/.config/go/env, docker ~/.docker, shells their profiles. No file there is read.
_LOCATION_ENVIRONMENT = _names(
    "HOME XDG_CONFIG_HOME XDG_CONFIG_DIRS XDG_CACHE_HOME XDG_DATA_HOME ZDOTDIR PYTHONUSERBASE"
)
# Read only on Windows, where a drive, UNC or rooted path is absolute.
_WINDOWS_LOCATION_ENVIRONMENT = _names("USERPROFILE APPDATA LOCALAPPDATA")
_LOCATION_LISTS = frozenset({"PATH", "XDG_CONFIG_DIRS"})
_NPM_LOCATION_ENVIRONMENT = _names("PREFIX DESTDIR")
_RUNNER_LOCATION_ENVIRONMENT = {
    "npm": _NPM_LOCATION_ENVIRONMENT,
    "bun": _NPM_LOCATION_ENVIRONMENT,
    "yarn": _NPM_LOCATION_ENVIRONMENT,
    "deno": _NPM_LOCATION_ENVIRONMENT,
    "go": _names("GOENV"),
}
# The environment forms of --overrides, --constraints and -r replace or add packages.
_UV_REPLACEMENT_ENVIRONMENT = _names("UV_OVERRIDE UV_CONSTRAINT UV_BUILD_CONSTRAINT")
_REPLACEMENT_ENVIRONMENT = {
    "uv-tool": _UV_REPLACEMENT_ENVIRONMENT,
    "uv-project": _UV_REPLACEMENT_ENVIRONMENT,
    "pip": _names("PIP_CONSTRAINT PIP_REQUIREMENT PIP_BUILD_CONSTRAINT"),
}


def _prefixes(*prefixes: str) -> tuple[tuple[re.Pattern[str], str], ...]:
    return tuple((re.compile(re.escape(prefix) + ".+", re.DOTALL), prefix) for prefix in prefixes)


# Each runner reads every setting from its own namespace, matched upper-cased as
# Windows reads names. go's settings have no underscore, so GOOGLE_API_KEY is not one.
_COREPACK_NAMESPACE = _prefixes("COREPACK_")
_UV_NAMESPACE = _prefixes("UV_")
_NAMESPACE_ENVIRONMENT = {
    "npm": _COREPACK_NAMESPACE,
    "yarn": _prefixes("YARN_") + _COREPACK_NAMESPACE,
    "bun": _prefixes("BUN_"),
    "deno": _prefixes("DENO_"),
    "uv-tool": _UV_NAMESPACE,
    "uv-project": _UV_NAMESPACE,
    "pip": _prefixes("PIP_", "PIPX_"),
    "go": ((re.compile(r"GO[A-Z0-9]+"), "GO"),),
    "oci": _prefixes("DOCKER_", "CONTAINER_", "CONTAINERS_", "CONTAINERD_", "PODMAN_", "NERDCTL_"),
}
# Settings in those namespaces that change only what the runner displays.
_DISPLAY_ENVIRONMENT = _names(
    "UV_NO_PROGRESS PIP_QUIET PIP_VERBOSE PIP_PROGRESS_BAR PIP_NO_COLOR PIPX_USE_EMOJI"
    " YARN_SILENT YARN_ENABLE_PROGRESS_BARS YARN_PROGRESS_BAR_STYLE YARN_ENABLE_COLORS"
    " BUN_CONFIG_VERBOSE_FETCH DOCKER_CLI_HINTS COREPACK_ENABLE_DOWNLOAD_PROMPT"
)
_RELOCATED = "environment relocates resolver configuration into the project"
_SEARCHED = "PATH may search the project for the runner"
_REPLACED = "environment replaces or constrains the launched package"
# bash imports BASH_FUNC_<name>%% (BASH_FUNC_<name>() on some distributions, and
# __BASH_FUNC<name>() in Apple's bash) as a function that replaces the program <name> in
# every bash the launch starts, the package runner included. bash from before 2014 did
# so for any variable whose value starts with "() {".
_EXPORTED_FUNCTION = "BASH_FUNC"
_FUNCTION_REPLACED = "environment defines a shell function that can replace the launched program"
# A non-interactive bash sources BASH_ENV before its script, and an interactive POSIX
# shell sources ENV; a file that may lie in the project can replace the runner.
_STARTUP_ENVIRONMENT = "BASH_ENV"
_INTERACTIVE_STARTUP_ENVIRONMENT = "ENV"
_STARTUP_IN_PROJECT = "environment names a shell startup file that may lie in the project"
# /proc/self/cwd and its kin resolve to the working directory: the project.
_PROC = re.compile(r"/+proc(?:/|$)")
_WINDOWS_ROOT = re.compile(r"[A-Za-z]:[\\/]|[\\/]")
_LOCATOR = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s,;\"']+")
_NPM_PURL_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")
_CONTEXT_HIGH = {
    "privileged": "privileged mode",
    "runtime_socket_mount": "a container runtime socket mount",
    "host_root_mount": "a host root mount",
    "security_options_disabled": "disabled confinement",
    "dangerous_capabilities": "a host-level capability",
}
_CONTEXT_MEDIUM = {
    "host_namespaces": "a host namespace",
    "added_capabilities": "added capabilities",
    "devices": "host devices",
    "broad_host_mount": "a broad host directory mount",
    "preload_module": "a preloaded module",
    "code_loading_option": "an option that loads local code",
    "code_loading_environment": "environment that changes code loading",
    "code_loading_setting": "a package manager setting that loads local code",
}


def _declared_type(config: dict[str, Any]) -> Any:
    return config.get("type", config.get("transport", config.get("transportType")))


def _declared_transport(config: dict[str, Any]) -> str | None:
    """The transport a server declares, normalised; None when it declares none it names."""
    declared = _declared_type(config)
    if not isinstance(declared, str):
        return None
    return _TRANSPORT_TYPES.get(declared.strip().lower().replace("_", "-"))


def _origin_label(value: str) -> list[str]:
    """Exported locations of a package source value: origins, never paths or credentials."""
    if expands(value):
        return ["[unresolved]"]
    found = [origin(match) or "[redacted]" for match in _LOCATOR.findall(value)]
    if found:
        return sorted(set(found))
    return ["[local]"] if value.strip() else []


_TOKEN_RUN = re.compile(r"[A-Za-z0-9]{24,}")


def _exportable_name(name: str) -> bool:
    """Whether a configuration name may be exported: a plain field name, not token-shaped.

    A secret pasted as a key ("ghp_..." as a field, header or environment name) must not
    reach the inventory, so a name that matches a known token shape, or holds a run of 24
    or more letters and digits that mixes both, is withheld.
    """
    if not _FIELD_NAME.fullmatch(name) or TOKEN_SHAPE.search(name):
        return False
    return not any(
        any(c.isdigit() for c in run) and any(c.isalpha() for c in run)
        for run in _TOKEN_RUN.findall(name)
    )


def _exported_names(names: Iterable[str]) -> list[str]:
    """Sorted names with every withheld one as "[redacted]", one marker per name."""
    return sorted(
        redact_text(name, identifier=True) if _exportable_name(name) else "[redacted]"
        for name in names
    )


def _exported_environment(env: dict[str, Any]) -> dict[str, str]:
    """The environment's names with masked values; withheld names get numbered markers."""
    shown: dict[str, str] = {}
    withheld = 0
    for name in sorted(env):
        if _exportable_name(name):
            shown[name] = "***"
        else:
            withheld += 1
            shown[f"[redacted-{withheld}]"] = "***"
    return shown


def _field_names(config: dict[str, Any]) -> list[str]:
    return _exported_names(config)


def _json_shape(value: Any, budget: int) -> tuple[int, int]:
    """Count nodes, keys included, and depth iteratively, stopping past ``budget``."""
    nodes = depth = 0
    pending = [(value, 1)]
    while pending and nodes <= budget and depth <= MAX_TOOL_DEPTH:
        item, level = pending.pop()
        nodes += 1
        depth = max(depth, level)
        if isinstance(item, dict):
            nodes += len(item)
            pending.extend((child, level + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, level + 1) for child in item)
    return nodes, depth


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError("nonfinite JSON")


def _load_jsonc(text: str) -> Any:
    return json.loads(
        strip_jsonc(text), object_pairs_hook=_unique_pairs, parse_constant=_reject_constant
    )


def _purl(package: Package) -> str | None:
    """An exact npm or PyPI package URL, the form advisory lookups accept."""
    if not package.pinned or package.name is None or package.version is None:
        return None
    if package.ecosystem == "npm" and _NPM_PURL_NAME.fullmatch(package.name):
        return f"pkg:npm/{quote(package.name, safe='/')}@{quote(package.version, safe='')}"
    if package.ecosystem == "pypi":
        return f"pkg:pypi/{quote(package.name, safe='')}@{quote(package.version, safe='')}"
    return None


# String.prototype.trim whitespace: npm's ini reader trims keys and values with it.
_JS_SPACE = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
    "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)
_INI_COMMENT = re.compile(f"[{_JS_SPACE}]*[;#]")
_INI_SECTION = re.compile(f"\\[[^\\]]*\\][{_JS_SPACE}]*")
_NPMRC_AUTH = re.compile(
    r"//.*|_auth|_authToken|_password|username|password|email|certfile|keyfile"
    r"|always-auth|otp",
    re.S,
)
# Keys that change where package bytes come from or how their transport is trusted.
_NPMRC_SOURCES = frozenset(
    {
        "cache",
        "proxy",
        "https-proxy",
        "http-proxy",
        "ca",
        "cafile",
        "userconfig",
        "globalconfig",
        "replace-registry-host",
        "prefix",
        "store-dir",
        "cache-dir",
        "workspace",
    }
)
# npm configuration that decides what npm exec runs: `call` runs a shell command and
# `package` installs another package; either way the declared package does not
# establish what runs (npm reads both from every configuration layer).
_NPM_IDENTITY_SETTINGS = frozenset({"call", "package"})
# Configuration that names local code npm, pnpm or a lifecycle script runs.
_NPM_CODE_SETTINGS = _names(
    "script-shell node-options shell git node-gyp editor browser viewer init-module init.module"
    " onload-script pnpmfile global-pnpmfile npm-path"
)
# Settings known to change neither what runs nor where package bytes come from. npm
# passes every other setting to lifecycle scripts, whose installers read binary
# mirrors and hosts from them, so an unknown setting is a package source.
_NPM_INERT_SETTINGS = (
    (NPM_CONFIG_FLAGS | NPM_CONFIG_VALUES | {"color", "always-auth", "certfile", "keyfile"})
    - _NPM_IDENTITY_SETTINGS
    - _NPM_CODE_SETTINGS
    - _NPMRC_SOURCES
) | _names(
    "auto-install-peers shamefully-hoist strict-peer-dependencies node-linker"
    " link-workspace-packages prefer-workspace-packages public-hoist-pattern hoist-pattern hoist"
    " hoist-workspace-packages enable-pre-post-scripts resolution-mode dedupe-peer-dependents"
    " side-effects-cache side-effects-cache-readonly lockfile prefer-frozen-lockfile"
    " frozen-lockfile use-lockfile-v6 git-checks publish-branch recursive-install"
    " child-concurrency network-concurrency package-import-method symlink enable-modules-dir"
    " shared-workspace-lockfile save-workspace-protocol ignore-workspace-root-check"
    " disallow-workspace-cycles dedupe-direct-deps dedupe-injected-deps"
    " exclude-links-from-lockfile resolve-peers-from-workspace-root peers-suffix-max-length"
    " optimistic-repeat-install package-manager-strict package-manager-strict-version use-stderr"
    " reporter strict-dep-builds ignore-compatibility-db deploy-all-files extend-node-path"
    " ignore-pnpmfile ignore-dep-scripts only-built-dependencies never-built-dependencies"
    " minimum-release-age use-node-version node-version manage-package-manager-versions"
    " unsafe-perm"
)
_SCOPED_REGISTRY = re.compile(r"@[^:]+:(?:registry|npmRegistryServer)", re.DOTALL)
_NPM_SCOPE = re.compile(r"@[a-z0-9][a-z0-9._-]{0,63}")
_NPM_ENVIRONMENT = re.compile(r"(?:npm|pnpm)_config_(.+)", re.IGNORECASE | re.DOTALL)
_UV_SETTINGS = (
    "index-url",
    "extra-index-url",
    "find-links",
    "index",
    "allow-insecure-host",
    "python-install-mirror",
    "pypy-install-mirror",
)
# Yarn settings that replace or extend yarn with local code, and that redirect or
# relax where packages come from (.yarnrc.yml for Yarn 2+, .yarnrc for Yarn 1).
_YARN_CODE_SETTINGS = frozenset({"yarnPath", "plugins", "yarn-path"})
_YARN_CODE_ENVIRONMENT = {"YARN_YARN_PATH": "yarnPath", "YARN_PLUGINS": "plugins"}
_YARN_SOURCE_SETTINGS = _names(
    "httpProxy httpsProxy caFilePath enableStrictSsl cacheFolder globalFolder networkSettings"
    " unsafeHttpWhitelist checksumBehavior enableOfflineMode injectEnvironmentFiles"
    " packageExtensions"
)
_RESOLVER_FILES = {
    "npm": (".npmrc",),
    "deno": (".npmrc",),
    "bun": (".npmrc", "bunfig.toml"),
    "yarn": (".yarnrc.yml", ".yarnrc", ".env.yarn"),
    "uv-project": ("uv.toml", "pyproject.toml"),
}
# Setting names exported in clear: fixed vocabularies, never a name taken from input.
_KNOWN_SETTINGS = (
    _NPM_INERT_SETTINGS
    | _NPMRC_SOURCES
    | _NPM_IDENTITY_SETTINGS
    | _NPM_CODE_SETTINGS
    | _YARN_CODE_SETTINGS
    | _YARN_SOURCE_SETTINGS
    | frozenset(_UV_SETTINGS)
    | {"registry", "npmRegistryServer", "offline", "prefer-offline", "strict-ssl", "environment"}
)


def _environment_label(variable: str) -> str:
    """A package source label for an environment variable, never a token-shaped name."""
    return "env:[redacted]" if TOKEN_SHAPE.search(variable) else f"env:{variable}"


def _absolute(value: str, *, windows: bool = False) -> bool:
    """Whether a location names an absolute directory; any other may lie in the project.

    An empty, relative or ``~`` value is relative to the working directory, and an
    expansion such as ``${workspaceFolder}`` or ``%USERPROFILE%`` may name the project.
    """
    if not value or expands(value):
        return False
    if windows:
        return bool(_WINDOWS_ROOT.match(value))
    return value.startswith("/") and _PROC.match(posixpath.normpath(value)) is None


def _exported_function(variable: str, value: object) -> bool:
    """Whether bash imports the variable as a function that replaces a program."""
    return _EXPORTED_FUNCTION in variable.upper() or (
        isinstance(value, str) and value.startswith("() {")
    )


def _absolute_list(value: str) -> bool:
    """Whether every entry of a directory list is absolute however it is split.

    POSIX splits at ``:`` and searches the working directory for an empty entry, so a
    Windows list such as ``C:\\bin`` names relative directories there; Windows splits
    at ``;``.
    """
    return all(_absolute(entry) for entry in value.split(":")) and all(
        _absolute(entry, windows=True) for entry in value.split(";") if entry
    )


def _runner_environment(
    family: str, environment: list[tuple[str, str]], *, interactive: bool = False
) -> tuple[list[tuple[str, str]], list[str]]:
    """Package sources a runner's environment adds, and why it leaves the identity unknown.

    A location the runner reads its configuration, caches or programs from, a
    replacement of the package and any non-display setting of the runner's own
    namespace are sources. A location that may lie in the project, or a replacement,
    also makes the identity unknown: no file there is read, so a change would go
    unseen. A PATH of absolute directories is the operator's own and adds nothing.
    """
    sources: list[tuple[str, str]] = []
    reasons: list[str] = []
    explicit = _REDIRECT_ENVIRONMENT.get(family)
    for variable, value in environment if family else ():
        name = variable.upper()
        windows = name in _WINDOWS_LOCATION_ENVIRONMENT
        if _exported_function(variable, value):
            reasons.append(_FUNCTION_REPLACED)
        elif name == _STARTUP_ENVIRONMENT or (
            interactive and name == _INTERACTIVE_STARTUP_ENVIRONMENT
        ):
            if not _absolute(value):
                reasons.append(_STARTUP_IN_PROJECT)
        elif name == "PATH":
            if not _absolute_list(value):
                sources.append((_environment_label(variable), value))
                reasons.append(_SEARCHED)
        elif (
            windows
            or name in _LOCATION_ENVIRONMENT
            or name in _RUNNER_LOCATION_ENVIRONMENT.get(family, ())
        ):
            sources.append((_environment_label(variable), value))
            inside = (
                not _absolute_list(value)
                if name in _LOCATION_LISTS
                else not _absolute(value, windows=windows)
            )
            if inside:
                reasons.append(_RELOCATED)
        elif name in _REPLACEMENT_ENVIRONMENT.get(family, ()):
            sources.append((_environment_label(variable), value))
            reasons.append(_REPLACED)
        elif name not in _DISPLAY_ENVIRONMENT and not (
            explicit is not None and re.fullmatch(explicit, variable, re.IGNORECASE)
        ):
            prefix = next(
                (
                    label
                    for pattern, label in _NAMESPACE_ENVIRONMENT.get(family, ())
                    if pattern.fullmatch(name)
                ),
                None,
            )
            if prefix is not None:
                # A name taken from input is never exported: only its namespace is.
                sources.append((f"env:{prefix}[other]", value))
    return sources, reasons


def _setting_name(key: str, launched: set[str]) -> str:
    """A resolver setting name safe to export; a name from no vocabulary is ``[other]``.

    A token pasted on its own .npmrc line is read by npm as ``<token>=true``, so
    a key name is input and may be a secret.
    """
    if key in _KNOWN_SETTINGS:
        return key
    scope, _, rest = key.partition(":")
    if (
        _SCOPED_REGISTRY.fullmatch(key)
        and _NPM_SCOPE.fullmatch(scope)
        and not TOKEN_SHAPE.search(scope)
    ):
        return f"{scope}:{rest}"
    if key.startswith("sources.") and key[8:] in launched:
        return key
    return "[other]"


def _npm_key(variable: str) -> str | None:
    """The npm configuration key an environment variable sets, as npm reads it."""
    match = _NPM_ENVIRONMENT.fullmatch(variable)
    if match is None:
        return None
    key = match.group(1)
    return key if key.startswith("//") else (key[:1] + key[1:].replace("_", "-")).lower()


def _npm_setting(key: str, value: str) -> str:
    """What an npm setting does to an npm exec launch: identity, code, registry, source or inert."""
    if key in _NPM_IDENTITY_SETTINGS:
        return "identity"
    if key in _NPM_CODE_SETTINGS:
        return "code"
    if key == "registry" or _SCOPED_REGISTRY.fullmatch(key):
        return "registry"
    if key in {"offline", "prefer-offline"}:
        return "inert" if value == "false" else "source"
    if key == "strict-ssl":
        return "inert" if value == "true" else "source"
    if key in _NPMRC_SOURCES:
        return "source"
    if key in _NPM_INERT_SETTINGS or key.startswith("//") or _NPMRC_AUTH.fullmatch(key):
        return "inert"
    return "source"


_YARNRC_LINE = re.compile(r'(?:"((?:[^"\\]|\\.)*)"|([^\s"]+))\s*(.*)', re.DOTALL)


def _yarnrc(text: str) -> tuple[tuple[str, str], ...]:
    """Top-level ``key value`` lines of a Yarn 1 .yarnrc, keys without leading dashes."""
    settings: dict[str, str] = {}
    for line in re.split(r"[\r\n]+", text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _YARNRC_LINE.fullmatch(stripped)
        if match is None:
            continue
        key = (match.group(1) if match.group(1) is not None else match.group(2)).lstrip("-")
        value = match.group(3).strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        settings[key] = value
    return tuple(settings.items())


def _file_setting(path: str, family: str, key: str, value: str, launched: set[str]) -> str:
    """What a project resolver file setting does: identity, code, source or inert.

    Registry entries are inert here; they apply per package scope.
    """
    if path == ".npmrc":
        if family != "npm":
            return "source" if _npmrc_source(key, value) else "inert"
        kind = _npm_setting(key, value)
        return "inert" if kind == "registry" else kind
    if path in {".yarnrc.yml", ".yarnrc"}:
        if key in _YARN_CODE_SETTINGS:
            return "identity"
        if path != ".yarnrc.yml" or key not in _YARN_SOURCE_SETTINGS:
            return "inert"
        relaxed = {
            "enableStrictSsl": "true",
            "checksumBehavior": "throw",
            "enableOfflineMode": "false",
        }
        return "inert" if relaxed.get(key) == value else "source"
    if path in {"uv.toml", "pyproject.toml"}:
        return "source" if not key.startswith("sources.") or key[8:] in launched else "inert"
    return "unresolved" if path == ".env.yarn" else "inert"


# Working directories that are the scan root; any other one may hold other resolver files.
_ROOT_DIRECTORIES = frozenset({"", ".", "./", "${workspaceFolder}", "${workspaceFolder}/"})


def _ini_text(raw: str) -> str:
    """npm's ini ``unsafe``: trim, decode quoted text as JSON, else cut at ``;`` or ``#``."""
    text = raw.strip(_JS_SPACE)
    if text[:1] in {'"', "'"} and text.endswith(text[0]):
        inner = text[1:-1] if text[0] == "'" else text
        try:
            decoded = json.loads(inner)
        except ValueError:
            return inner if text[0] == "'" else text
        return decoded if isinstance(decoded, str) else json.dumps(decoded)
    kept: list[str] = []
    escaped = False
    for char in text:
        if escaped:
            kept.append(char if char in ";#\\" else "\\" + char)
            escaped = False
        elif char in ";#":
            break
        elif char == "\\":
            escaped = True
        else:
            kept.append(char)
    if escaped:
        kept.append("\\")
    return "".join(kept).strip(_JS_SPACE)


@dataclass(frozen=True)
class _ResolverFile:
    """Effective settings of one project resolver file; auth settings are left out."""

    settings: tuple[tuple[str, str], ...] = ()
    unresolved: bool = False


def _npmrc(text: str) -> _ResolverFile:
    """Top-level .npmrc settings exactly as npm's ini reader and config loader see them.

    Keys are trimmed, JSON-decoded when quoted and cut at ``;`` or ``#`` otherwise;
    a key that holds ``${...}`` depends on the environment and is unresolved. Keys
    after the first section header are not top-level settings and npm ignores them.
    """
    settings: dict[str, str] = {}
    unresolved = False
    for line in re.split(r"[\r\n]+", text):
        if not line.strip(_JS_SPACE) or _INI_COMMENT.match(line):
            continue
        if _INI_SECTION.fullmatch(line):
            break
        raw_key, equals, raw_value = line.partition("=")
        if not raw_key or (equals and ("\u2028" in raw_value or "\u2029" in raw_value)):
            continue
        key = _ini_text(raw_key)
        if len(key) > 2 and key.endswith("[]"):
            key = key[:-2]
        if "${" in key:
            unresolved = True
        elif key != "__proto__" and not _NPMRC_AUTH.fullmatch(key):
            settings[key] = _ini_text(raw_value) if equals else "true"
    return _ResolverFile(tuple(settings.items()), unresolved)


def _npmrc_source(key: str, value: str) -> bool:
    """A setting other than a registry that changes where packages come from."""
    if key in {"offline", "prefer-offline"}:
        return value != "false"
    if key == "strict-ssl":
        return value != "true"
    return key in _NPMRC_SOURCES


def _uv_settings(settings: dict[str, Any]) -> _ResolverFile:
    found: list[tuple[str, str]] = []
    for key in _UV_SETTINGS:
        values = settings.get(key)
        for item in values if isinstance(values, list) else [values]:
            url = item.get("url") if isinstance(item, dict) else item
            if isinstance(url, str):
                found.append((key, url))
    sources = settings.get("sources")
    if isinstance(sources, dict):
        for name, source in sources.items():
            locations = source if isinstance(source, list) else [source]
            for location in locations:
                if isinstance(location, dict):
                    value = next(
                        (
                            str(location[field])
                            for field in ("git", "url", "path", "index", "workspace")
                            if field in location
                        ),
                        "",
                    )
                    found.append((f"sources.{canonicalize_name(str(name))}", value))
    return _ResolverFile(tuple(found))


class _Resolvers:
    """Project-root package resolver settings, read once per collection when needed."""

    def __init__(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        read_mapping: Callable[[Path, ScanResult], dict[str, Any] | None],
    ) -> None:
        self._files = files
        self._result = result
        self._read_mapping = read_mapping
        self._loaded: dict[str, _ResolverFile] = {}

    def entries(self, path: str) -> _ResolverFile:
        if path not in self._loaded:
            self._loaded[path] = self._read(path)
        return self._loaded[path]

    def _text(self, path: str) -> str | None:
        text = self._files.read_text(path, missing_ok=True)
        if text is not None:
            self._result.surfaces_scanned.append(path)
        return text

    def _toml(self, path: str) -> dict[str, Any]:
        text = self._text(path)
        if text is None:
            return {}
        try:
            return tomllib.loads(text)
        except (tomllib.TOMLDecodeError, RecursionError):
            self._result.scan_failures.append(f"{path}: invalid TOML")
            return {}

    def _read(self, path: str) -> _ResolverFile:
        if path == ".npmrc":
            return _npmrc(self._text(path) or "")
        if path == ".yarnrc":
            return _ResolverFile(_yarnrc(self._text(path) or ""))
        if path == ".env.yarn":
            # Yarn 4 loads .env.yarn into its environment by default (injectEnvironmentFiles).
            text = self._text(path)
            return _ResolverFile((("environment", text),) if text is not None else ())
        if path == ".yarnrc.yml":
            settings = self._read_mapping(Path(path), self._result) or {}
            if settings:
                self._result.surfaces_scanned.append(path)
            entries = _registries(settings, "npmRegistryServer", "npmScopes")
            entries += [
                (str(key), value if isinstance(value, str) else json.dumps(value, default=str))
                for key, value in settings.items()
                if key in _YARN_CODE_SETTINGS or key in _YARN_SOURCE_SETTINGS
            ]
            return _ResolverFile(tuple(entries))
        settings = self._toml(path)
        if path == "bunfig.toml":
            install = settings.get("install")
            return _ResolverFile(
                tuple(
                    _registries(install if isinstance(install, dict) else {}, "registry", "scopes")
                )
            )
        if path == "pyproject.toml":
            tool = settings.get("tool")
            uv = tool.get("uv") if isinstance(tool, dict) else None
            settings = uv if isinstance(uv, dict) else {}
        return _uv_settings(settings)


class _ResolverView:
    """What project resolver files and package manager environment mean for one launcher."""

    __slots__ = ("binding", "code", "environment", "identity", "names", "sources", "unresolved")

    def __init__(self) -> None:
        self.sources: list[tuple[str, str]] = []
        self.unresolved: list[str] = []
        self.binding: list[list[str]] = []
        self.names: list[str] = []
        # Settings that change what runs (fixed-vocabulary reasons) or load local code.
        self.identity: list[str] = []
        self.code = 0
        # The package manager's own environment settings were read here.
        self.environment = False


def _registry_url(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("url", value.get("npmRegistryServer"))
    return value if isinstance(value, str) else None


def _registries(settings: dict[str, Any], default: str, scopes_key: str) -> list[tuple[str, str]]:
    """The default and per-scope registry URLs of a bunfig or yarnrc mapping."""
    pairs: list[tuple[str, str | None]] = [(default, _registry_url(settings.get(default)))]
    scopes = settings.get(scopes_key)
    if isinstance(scopes, dict):
        pairs += [
            (f"@{str(scope).lstrip('@')}:{default}", _registry_url(value))
            for scope, value in scopes.items()
        ]
    return [(key, value) for key, value in pairs if value is not None]


@dataclass
class _Identity:
    """Identity fields computed from raw configuration before any scrubbing."""

    name: str
    command: str | None
    executable: str | None
    endpoint: str | None
    endpoint_gap: str | None
    packages: list[dict[str, Any]]
    package_identities: list[str]
    sources: list[str]
    withheld: list[str]


class MCPScanner(Scanner):
    name = "mcp"
    _resolvers: _Resolvers | None = None

    def scan(self, project_root: Path, *, config_only: bool = False) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        found_any = False
        clients: dict[str, MCPClientComponent] = {}

        # Source text read while looking for SDK references is charged to this
        # collection too, so its byte limit leaves room for the source budget.
        with self._collection(
            project_root, result, max_total_bytes=source_collection_bytes()
        ) as files:
            sources = list(files.iter_files())
            nested = sorted(
                {path.as_posix() for path in sources if path.name in MCP_CONFIG_NAMES}
                - set(MCP_CONFIG_FILES)
            )
            try:
                key, key_error = source_binding_key(), None
            except SourceBindingKeyError as exc:
                key, key_error = None, str(exc)
            self._resolvers = _Resolvers(files, result, self._read_mapping)
            try:
                found_any = self._scan_dialects(
                    files, result, (*MCP_CONFIG_FILES, *nested), key, key_error, clients
                )
            finally:
                self._resolvers = None
            result.components.extend(clients.values())
            self._report_unparsed_clients(files, result)
            if not config_only:
                self._scan_code_mcp_clients(result, sources)

        if not found_any and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("mcp-config (no config files found)")

        return result

    def _scan_dialects(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        paths: tuple[str, ...],
        key: bytes | None,
        key_error: str | None,
        clients: dict[str, MCPClientComponent],
    ) -> bool:
        """Read each client file in ``paths``; whether any of them was present."""
        found_any = False
        for path in paths:
            dialect = _dialect(path)
            data = self._read_dialect(files, dialect, result)
            if data is None:
                continue
            found_any = True
            result.surfaces_scanned.append(dialect.path)
            if not isinstance(data, dict):
                result.scan_failures.append(f"{dialect.path}: expected a configuration object")
                continue
            entries = self._server_entries(dialect, data, result)
            if entries is None:
                continue
            if key_error is not None and entries:
                result.scan_failures.append(f"{dialect.path}: {key_error}")
                continue
            server_refs: list[str] = []
            for server_name, server_config in entries:
                problem = (
                    self._server_problem(server_config)
                    if isinstance(server_config, dict)
                    else "invalid server configuration"
                )
                if problem is not None:
                    result.scan_failures.append(f"{dialect.path}: {problem}")
                    continue
                try:
                    mcp_comp, tool_comps = self._parse_server(
                        server_name, server_config, dialect, key, result
                    )
                except SourceBindingKeyError as exc:
                    result.scan_failures.append(f"{dialect.path}: {exc}")
                    continue
                except (TypeError, ValueError, RecursionError):
                    result.scan_failures.append(f"{dialect.path}: invalid tool definition")
                    continue
                result.components.append(mcp_comp)
                result.components.extend(tool_comps)
                server_refs.append(mcp_comp.bom_ref)
            host = self._detect_host_from_config(dialect.path)
            if host and any(key in data for key in dialect.maps):
                if host not in clients:
                    clients[host] = MCPClientComponent(
                        bom_ref=f"mcp-client:{host}",
                        name=f"{host} MCP client",
                        host_application=host,
                        server_refs=[],
                        config_path=dialect.path,
                        source_path=dialect.path,
                        trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                        properties={"collection_mode": "static-config", "config_paths": []},
                    )
                client = clients[host]
                client.server_refs = sorted({*client.server_refs, *server_refs})
                client.properties["config_paths"].append(dialect.path)
        return found_any

    @staticmethod
    def _read_dialect(files: ConfinedCollection, dialect: McpDialect, result: ScanResult) -> Any:
        if dialect.syntax == "json":
            return files.read_json(dialect.path, missing_ok=True)
        text = files.read_text(dialect.path, missing_ok=True)
        if text is None:
            return None
        try:
            return tomllib.loads(text) if dialect.syntax == "toml" else _load_jsonc(text)
        except (ValueError, RecursionError):
            syntax = "TOML" if dialect.syntax == "toml" else "JSON or duplicate keys"
            result.scan_failures.append(f"{dialect.path}: invalid {syntax}")
            return None

    @staticmethod
    def _server_entries(
        dialect: McpDialect, data: dict[str, Any], result: ScanResult
    ) -> list[tuple[str, Any]] | None:
        entries: dict[str, Any] = {}
        for key in dialect.maps:
            servers = data.get(key)
            if servers is None:
                continue
            if not isinstance(servers, dict) or len(servers) + len(entries) > MAX_SERVERS_PER_FILE:
                result.scan_failures.append(
                    f"{dialect.path}: invalid server map or MCP server limit "
                    f"({MAX_SERVERS_PER_FILE} per file) exceeded"
                )
                return None
            for name, config in servers.items():
                if name in entries:
                    result.scan_failures.append(
                        f"{dialect.path}: MCP server declared under more than one server map"
                    )
                    continue
                entries[name] = config
        tools = [
            tool
            for config in entries.values()
            if isinstance(config, dict) and isinstance(config.get("tools"), list)
            for tool in config["tools"]
        ]
        if len(tools) > MAX_TOOLS_PER_FILE:
            result.scan_failures.append(
                f"{dialect.path}: MCP tool limit ({MAX_TOOLS_PER_FILE} per file) exceeded"
            )
            return None
        nodes = 0
        for tool in tools:
            nodes += _json_shape(tool, MAX_FILE_NODES)[0]
            if nodes > MAX_FILE_NODES:
                result.scan_failures.append(
                    f"{dialect.path}: MCP tool definition limit ({MAX_FILE_NODES} nodes per file) "
                    "exceeded"
                )
                return None
        return sorted(entries.items())

    @staticmethod
    def _server_problem(config: dict[str, Any]) -> str | None:
        """A type or size problem in a server entry; unknown fields are gaps, not failures."""
        for field, value in config.items():
            if field in _STRING_FIELDS:
                valid = isinstance(value, str)
            elif field in _LIST_FIELDS:
                valid = isinstance(value, list) and all(isinstance(item, str) for item in value)
            elif field in _MAP_FIELDS:
                valid = isinstance(value, dict) and all(
                    isinstance(item, str) for item in value.values()
                )
            elif field in _BOOL_FIELDS:
                valid = isinstance(value, bool)
            elif field in _NUMBER_FIELDS:
                valid = isinstance(value, (int, float)) and not isinstance(value, bool)
            elif field in _OBJECT_FIELDS:
                valid = isinstance(value, dict)
            elif field == "gallery":
                valid = isinstance(value, (str, bool))
            elif field == "tools":
                valid = isinstance(value, list) and all(isinstance(tool, dict) for tool in value)
            else:
                continue
            if not valid:
                return "invalid server configuration"
        limits = (
            ("args", MAX_ARGUMENTS, "argument"),
            ("env", MAX_ENVIRONMENT, "environment variable"),
            ("headers", MAX_HEADERS, "header"),
            ("http_headers", MAX_HEADERS, "header"),
            ("tools", MAX_TOOLS_PER_SERVER, "tool"),
        )
        for field, limit, label in limits:
            if len(config.get(field, ())) > limit:
                return f"MCP server {label} limit ({limit}) exceeded"
        if any(len(config.get(field, ())) > MAX_LIST_ENTRIES for field in _LIST_FIELDS):
            return f"MCP server list limit ({MAX_LIST_ENTRIES} entries) exceeded"
        for tool in config.get("tools", ()):
            nodes, depth = _json_shape(tool, MAX_TOOL_NODES)
            if nodes > MAX_TOOL_NODES or depth > MAX_TOOL_DEPTH:
                return (
                    f"MCP tool definition limit ({MAX_TOOL_NODES} nodes, "
                    f"{MAX_TOOL_DEPTH} levels) exceeded"
                )
        return None

    def _parse_server(
        self,
        name: str,
        config: dict[str, Any],
        dialect: McpDialect,
        key: bytes | None,
        result: ScanResult,
    ) -> tuple[MCPServerComponent, list[ToolComponent]]:
        config_scope = dialect.path
        command = config.get("command", "")
        args = config.get("args", [])
        env = config.get("env", {})
        headers = {**config.get("headers", {}), **config.get("http_headers", {})}
        header_names = sorted({*headers, *config.get("env_http_headers", {})})
        endpoints = [config[field] for field in _ENDPOINT_FIELDS if config.get(field)]
        endpoint_url = endpoints[0] if endpoints else None
        launch = analyze(command, args) if command else Launch()
        transport, transport_gap = self._transport(config, dialect, bool(command))
        server_ref = (
            "mcp-server:" + hash_canonical({"config": config_scope, "name": name}).split(":", 1)[1]
        )
        # Launch arguments are opaque executable inputs. Only the launcher's own
        # grammar is read; argument and environment values never leave.
        scrubber = SecretScrubber(
            [*secret_values(env), *secret_values(headers), *secret_values(dict(launch.environment))]
        )
        cwd = config.get("cwd")
        relocated = (
            launch.relocated
            or (isinstance(cwd, str) and cwd.strip() not in _ROOT_DIRECTORIES)
            or _launch_directory(dialect.path) != ""
        )
        environment = [*env.items(), *launch.environment]
        runner_sources, runner_reasons = _runner_environment(
            launch.family or "", environment, interactive=launch.interactive
        )
        environment_file = "envFile" in config or launch.injected_environment
        view = self._resolver_view(launch, relocated, environment, environment_file)
        identity = self._identity(
            name, config, launch, endpoint_url, env, scrubber, view, runner_sources
        )
        gaps: list[str] = []
        for gap in (identity.endpoint_gap, transport_gap):
            if gap:
                gaps.append(gap)
        if len(set(endpoints)) > 1:
            gaps.append("declares more than one endpoint field")
        unknown_fields = [field for field in config if field not in _KNOWN_FIELDS]
        command_fields = [field for field in unknown_fields if _COMMAND_FIELD.fullmatch(field)]
        if unknown_fields:
            count = len(unknown_fields)
            gaps.append(
                f"declares {count} field{'s' if count > 1 else ''} the collector does not interpret"
            )
        identity_unknown = self._identity_unknown(launch) or next(
            iter([*view.identity, *runner_reasons]), None
        )
        if identity_unknown:
            gaps.append(f"launcher identity unknown ({identity_unknown})")
        if identity.withheld:
            gaps.append("identity withheld by environment-value redaction")
        name = identity.name
        tool_names = sorted(
            self._tool_name(str(tool.get("name", "")), scrubber)
            for tool in config.get("tools", [])
            if isinstance(tool, dict)
        )
        packages = launch.packages
        # uv tool run and pipx name one tool package; --with adds dependencies to it.
        primary = (
            packages[0]
            if len(packages) == 1 or (packages and launch.family in {"uv-tool", "pip"})
            else None
        )
        launcher_package = (
            identity.package_identities[0]
            if primary is not None and primary.registry and not identity.sources
            else None
        )
        if launcher_package == "[withheld]":
            launcher_package = None
        version = (
            primary.version
            if primary is not None and identity.packages[0]["identity"] != "[withheld]"
            else None
        )
        version_pinned: bool | None = None
        if identity_unknown:
            version_pinned = False
        elif packages:
            version_pinned = all(package.pinned for package in packages)
        # An exact package URL claims what the server is; not while its launch is unknown.
        package_url = (
            _purl(primary)
            if primary is not None and launcher_package is not None and not identity_unknown
            else None
        )
        settings = self._client_settings(config)
        context = dict(launch.context)
        loading = [
            variable
            for variable, value in environment
            if variable.upper() in _CODE_LOADING_ENVIRONMENT
            or _exported_function(variable, value)
            or _npm_key(variable) in _NPM_CODE_SETTINGS
        ]
        if loading:
            context["code_loading_environment"] = len(loading)
        if command_fields:
            context["command_fields"] = len(command_fields)
        if view.code:
            context["code_loading_setting"] = view.code

        risks = self._server_risks(
            name,
            launch=launch,
            transport=transport,
            command=command,
            endpoint_url=endpoint_url,
            safe_endpoint=identity.endpoint,
            endpoint_gap=identity.endpoint_gap,
            identity_unknown=identity_unknown,
            sources=identity.sources,
            context=context,
            settings=settings,
            withheld=identity.withheld,
            endpoints=endpoints,
            remote_type=_declared_transport(config) not in (None, "stdio"),
        )
        resolver = sorted(view.binding)
        # The launcher package and its version are recorded; every other argument
        # (a served directory, a mount, a flag) is a redacted position.
        recorded = (
            {"-y", "--yes", *(package.spec for package in packages)} if launcher_package else set()
        )
        unbound = self._unbound_values(args, env, headers, endpoint_url, command, launch, recorded)
        if resolver:
            unbound.append("project resolver settings")
        if unbound and key is None:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=(
                        f"MCP server '{name}' values not bound in this inventory: "
                        f"{'; '.join(unbound)}."
                    ),
                    recommendation=(
                        f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes to "
                        "these values."
                    ),
                )
            )
        fields = _field_names(config)
        launcher_properties: dict[str, Any] = {}
        if launch.launcher:
            launcher_properties["launcher"] = launch.launcher
        if launch.wrappers:
            launcher_properties["launcher_wrappers"] = list(launch.wrappers)
        if identity.executable and identity.executable != identity.command:
            launcher_properties["launcher_command"] = identity.executable
        if identity.packages:
            launcher_properties["packages"] = identity.packages
        if identity.sources:
            launcher_properties["package_sources"] = identity.sources
        # Repeated "[other]" names stay, so adding an unnamed setting changes the digest.
        resolver_names = sorted(view.names)
        if resolver_names:
            launcher_properties["resolver_settings"] = resolver_names
        if context:
            launcher_properties["launch_context"] = context
        if header_names:
            launcher_properties["header_names"] = _exported_names(header_names)
        if settings:
            launcher_properties["client_settings"] = settings
        source_config_hash = hash_canonical(
            {
                "profile": STATIC_CONFIG_HASH_PROFILE,
                "structure": {
                    "fields": fields,
                    "command": identity.command,
                    "launcher": launch.launcher,
                    "launcher_wrappers": launch.wrappers,
                    "launcher_command": identity.executable,
                    "packages": identity.packages,
                    "package_sources": identity.sources,
                    "resolver_settings": resolver_names,
                    "launch_context": context,
                    "transport": transport,
                    "endpoint": identity.endpoint,
                    "argument_count": len(args),
                    "environment_names": _exported_names(env),
                    "header_names": launcher_properties.get("header_names", []),
                    "client_settings": settings,
                    "tool_names": tool_names,
                },
            }
        )
        binding = _keyed_binding(key, config, resolver) if key is not None else {}

        server_comp = MCPServerComponent(
            bom_ref=server_ref,
            name=name,
            version=version,
            transport=transport,
            launcher_package=launcher_package,
            package_url=package_url,
            command=identity.command,
            args=[REDACTED for _ in args],
            env=_exported_environment(env),
            endpoint_url=identity.endpoint,
            version_pinned=version_pinned,
            source_path=config_scope,
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
            risks=risks,
            properties={
                "collection_mode": "static-config",
                "launch_arguments_redacted": bool(args),
                "endpoint_credentials_omitted": bool(endpoint_url),
                "declared_fields": fields,
                **launcher_properties,
                "source_values_bound": key is not None,
                "static_config_hash": source_config_hash,
                "static_config_hash_profile": STATIC_CONFIG_HASH_PROFILE,
                **binding,
            },
        )

        tools = self._extract_tools(
            name, config, scrubber, server_ref=server_ref, config_path=config_scope
        )
        server_comp.tool_count = len(tools)
        server_comp.tool_refs = [tool.bom_ref for tool in tools]
        result.surfaces_excluded.extend(
            f"{config_scope}: MCP server '{name}' {gap}" for gap in gaps
        )
        return server_comp, tools

    def _identity(
        self,
        name: str,
        config: dict[str, Any],
        launch: Launch,
        endpoint_url: str | None,
        env: dict[str, str],
        scrubber: SecretScrubber,
        view: _ResolverView,
        runner_sources: list[tuple[str, str]],
    ) -> _Identity:
        """Compute identity fields from raw values; withhold one that holds a secret value."""
        withheld: list[str] = []
        shown_name = redact_text(name, identifier=True)
        if scrubber.contains(name):
            shown_name = scrubber.scrub(shown_name)
            withheld.append("name")
        command = self._safe_name(launch.command)
        if launch.command and scrubber.contains(launch.command):
            command = "[redacted-command]"
            withheld.append("command")
        # The effective command can come from the arguments, whose values never
        # leave; only a recognised runner, wrapper or interpreter name is exported.
        executable = launch.executable if known_executable(launch.executable) else None
        endpoint, endpoint_gap = (None, None)
        if endpoint_url:
            endpoint, endpoint_gap = self._endpoint(endpoint_url)
            if scrubber.contains(endpoint):
                endpoint = "[redacted]"
                withheld.append("endpoint")
        packages: list[dict[str, Any]] = []
        identities: list[str] = []
        for package in launch.packages:
            hidden = scrubber.contains(package.spec)
            if hidden:
                withheld.append("launcher package")
            entry_identity = "[withheld]" if hidden else package.identity
            identities.append(entry_identity)
            packages.append(
                {
                    "identity": entry_identity,
                    "version": None if hidden else package.version,
                    "pinned": package.pinned,
                    "pin": package.pin,
                }
            )
        sources = self._package_sources(launch, env, scrubber, withheld, view, runner_sources)
        return _Identity(
            name=shown_name,
            command=command,
            executable=executable,
            endpoint=endpoint,
            endpoint_gap=endpoint_gap,
            packages=packages,
            package_identities=identities,
            sources=sources,
            withheld=sorted(set(withheld)),
        )

    @staticmethod
    def _safe_name(value: str | None) -> str | None:
        if value is None:
            return None
        if _SAFE_NAME.fullmatch(value) and not TOKEN_SHAPE.search(value):
            return value
        return "[redacted-command]"

    def _package_sources(
        self,
        launch: Launch,
        env: dict[str, str],
        scrubber: SecretScrubber,
        withheld: list[str],
        view: _ResolverView,
        runner_sources: list[tuple[str, str]],
    ) -> list[str]:
        """Exported sources that redirect package resolution: label and origin only."""
        found: list[tuple[str, str]] = [*launch.sources, *runner_sources]
        family = launch.family or ""
        environment = [*env.items(), *launch.environment]
        pattern = _REDIRECT_ENVIRONMENT.get(family)
        if pattern is not None and not view.environment:
            for variable, value in environment:
                if re.fullmatch(pattern, variable, re.IGNORECASE):
                    found.append((_environment_label(variable), value))
        trust_pattern = _TRUST_ENVIRONMENT.get(family)
        if trust_pattern is not None:
            # An added CA or disabled TLS verification lets a proxy or another
            # host serve registry content; a proxy alone cannot.
            trust = [
                (variable, value)
                for variable, value in environment
                if re.fullmatch(trust_pattern, variable, re.IGNORECASE)
                and (variable.upper() != "NODE_TLS_REJECT_UNAUTHORIZED" or value.strip() == "0")
            ]
            if trust:
                trust += [
                    (variable, value)
                    for variable, value in environment
                    if re.fullmatch(_PROXY_ENVIRONMENT, variable, re.IGNORECASE)
                ]
            found.extend((_environment_label(variable), value) for variable, value in trust)
        found.extend(view.sources)
        sources: set[str] = {f"{label}=[unresolved]" for label in view.unresolved}
        for label, value in found:
            for location in _origin_label(value) or ["[set]"]:
                if scrubber.contains(location):
                    location = "[redacted]"
                    withheld.append("package source")
                sources.add(f"{label}={location}")
        return sorted(sources)

    def _resolver_view(
        self,
        launch: Launch,
        relocated: bool,
        environment: list[tuple[str, str]],
        environment_file: bool,
    ) -> _ResolverView:
        """Project resolver settings and package manager environment for registry packages."""
        view = _ResolverView()
        packages = [package for package in launch.packages if package.registry]
        if not packages:
            return view
        family = launch.family or ""
        if environment_file:
            # Variables from an environment file or secret store may redirect or
            # replace what the runner fetches; their names are not visible here.
            view.unresolved.append("environment-file")
        launched = {str(package.name) for package in packages}
        npm_environment: dict[str, str] = {}
        if family == "npm":
            view.environment = True
            for variable, value in environment:
                key = _npm_key(variable)
                if key is None or value == "":
                    continue
                npm_environment[key] = value
                kind = _npm_setting(key, value)
                if kind == "identity":
                    view.identity.append(f"npm {key} setting from the environment")
                elif kind in {"source", "registry"}:
                    known = _setting_name(key, launched) != "[other]"
                    view.sources.append(
                        (_environment_label(variable) if known else "env:npm_config_[other]", value)
                    )
        if family == "yarn":
            # Yarn reads every setting from YARN_<NAME> variables, yarnPath included.
            for variable, value in environment:
                setting = _YARN_CODE_ENVIRONMENT.get(variable.upper())
                if setting is not None and value:
                    view.identity.append(f"yarn {setting} setting from the environment")
        files = _RESOLVER_FILES.get(family, ())
        if self._resolvers is None or not files:
            return view
        if relocated:
            # Another working directory may hold its own resolver files.
            view.unresolved.append("working-directory")
        for path in files:
            file = self._resolvers.entries(path)
            if file.unresolved:
                view.unresolved.append(f"{path}:key")
            settings = dict(file.settings)
            for key, value in file.settings:
                view.binding.append([f"{path}:{key}", value])
                label = f"{path}:{_setting_name(key, launched)}"
                view.names.append(label)
                kind = _file_setting(path, family, key, value, launched)
                if kind == "identity":
                    view.identity.append(
                        f"npm {key} setting from {path}"
                        if path == ".npmrc"
                        else f"{path} {key} replaces or extends yarn"
                    )
                elif kind == "code":
                    view.code += 1
                elif kind == "source":
                    view.sources.append((label, value))
                elif kind == "unresolved":
                    view.unresolved.append(label)
            if path in {"uv.toml", "pyproject.toml", ".env.yarn"}:
                continue
            default = "npmRegistryServer" if path == ".yarnrc.yml" else "registry"
            # npm uses the registry of a configured `scope` for a package whose own
            # scope has none, unscoped packages included (npm-registry-fetch).
            selected_scope = (
                npm_environment.get("scope") or settings.get("scope") if path == ".npmrc" else None
            )
            fallback = (
                f"{selected_scope if selected_scope.startswith('@') else '@' + selected_scope}"
                ":registry"
                if selected_scope
                else None
            )
            for package in packages:
                name = package.name or ""
                scope = name.split("/", 1)[0] if name.startswith("@") else None
                scoped = f"{scope}:{default}" if scope else None
                if scoped in settings:
                    selected = scoped
                elif fallback in settings:
                    selected = fallback
                else:
                    selected = default
                if selected in settings:
                    view.sources.append(
                        (f"{path}:{_setting_name(selected, launched)}", settings[selected])
                    )
        return view

    @staticmethod
    def _identity_unknown(launch: Launch) -> str | None:
        """Why a launcher's identity or pin cannot be established, from a fixed vocabulary."""
        if launch.unknown is not None:
            return launch.unknown
        reasons = {
            "git": "git source without a full commit",
            "url": "URL source",
            "path": "local path or archive source",
            "unknown": "unparsed package reference",
        }
        for package in launch.packages:
            if package.ecosystem == "git" and package.pinned:
                continue
            if package.ecosystem in reasons:
                return reasons[package.ecosystem]
        return None

    @staticmethod
    def _tool_name(name: str, scrubber: SecretScrubber) -> str:
        shown = redact_text(name, identifier=True)
        return scrubber.scrub(shown) if scrubber.contains(name) else shown

    def _transport(
        self, config: dict[str, Any], dialect: McpDialect, has_command: bool
    ) -> tuple[str, str | None]:
        declared = _declared_transport(config)
        gap = (
            "declares an unrecognised transport type"
            if declared is None and isinstance(_declared_type(config), str)
            else None
        )
        # Gemini CLI chooses the transport from command, url and httpUrl, not a type.
        if declared is not None and not (has_command and dialect.url_transport):
            return declared, None
        if has_command:
            return "stdio", gap
        if config.get("httpUrl"):
            return "streamable-http", gap
        url = next((config[field] for field in _ENDPOINT_FIELDS if config.get(field)), None)
        if url is None:
            return "stdio", gap
        if dialect.url_transport and config.get("url"):
            return dialect.url_transport, gap
        try:
            parsed = urlsplit(url)
        except ValueError:
            return "streamable-http", gap
        if parsed.scheme.lower() in {"ws", "wss"}:
            return "websocket", gap
        return ("sse" if "sse" in parsed.path.split("/") else "streamable-http"), gap

    @staticmethod
    def _endpoint(url: str) -> tuple[str, str | None]:
        """Export an origin only for an authority every URL parser reads the same way."""
        if expands(url):
            return "[redacted]", "endpoint depends on environment expansion"
        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError:
            return "[redacted]", "endpoint URL cannot be parsed"
        if (
            not parsed.scheme
            or not hostname
            or "\\" in parsed.netloc
            or origin(url) is None
            or any(char.isspace() or ord(char) < 32 for char in parsed.netloc)
        ):
            return "[redacted]", "endpoint authority is ambiguous"
        return sanitized_origin(url), None

    @staticmethod
    def _client_settings(config: dict[str, Any]) -> dict[str, Any]:
        """Client behaviour switches as booleans and counts, never values."""
        settings: dict[str, Any] = {}
        approved = len(config.get("alwaysAllow", [])) + len(config.get("autoApprove", []))
        if config.get("trust") is True:
            settings["auto_approve"] = "all"
        elif approved:
            settings["auto_approve"] = approved
        if config.get("disabled") is True or config.get("enabled") is False:
            settings["disabled"] = True
        for field, label in (
            ("cwd", "working_directory"),
            ("envFile", "environment_file"),
            ("oauth", "oauth"),
            ("auth", "authentication"),
            ("watchPaths", "watch_paths"),
            ("bearer_token_env_var", "bearer_token_variable"),
            ("dev", "development_mode"),
        ):
            if field in config:
                settings[label] = True
        filters = sum(
            len(config.get(field, []))
            for field in (
                "includeTools",
                "excludeTools",
                "enabled_tools",
                "disabled_tools",
                "disabledTools",
            )
        )
        if filters:
            settings["tool_filters"] = filters
        return settings

    @staticmethod
    def _unbound_values(
        args: list[str],
        env: dict[str, str],
        headers: dict[str, str],
        endpoint_url: str | None,
        command: str,
        launch: Launch,
        recorded: set[str],
    ) -> list[str]:
        """Values only the keyed binding covers, named by kind."""
        unbound = []
        if command and (re.search(r"[\\/]", command) or launch.wrappers):
            unbound.append("command path")
        if any(arg not in recorded for arg in args):
            unbound.append("launch arguments")
        if any(env.values()):
            unbound.append("environment values")
        if headers:
            unbound.append("header values")
        if endpoint_url and (
            _has_path_or_query(endpoint_url) or "#" in endpoint_url or _has_userinfo(endpoint_url)
        ):
            unbound.append("endpoint path and query")
        return unbound

    def _server_risks(
        self,
        name: str,
        *,
        launch: Launch,
        transport: str,
        command: str,
        endpoint_url: str | None,
        safe_endpoint: str | None,
        endpoint_gap: str | None,
        identity_unknown: str | None,
        sources: list[str],
        context: dict[str, int],
        settings: dict[str, Any],
        withheld: list[str],
        endpoints: list[str],
        remote_type: bool,
    ) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []

        def add(severity: RiskSeverity, category: str, detail: str, advice: str) -> None:
            risks.append(
                RiskAssessment(
                    severity=severity, category=category, detail=detail, recommendation=advice
                )
            )

        floating = [p for p in launch.packages if p.registry and not p.pinned]
        if any(p.ecosystem != "oci" for p in floating):
            add(
                RiskSeverity.HIGH,
                "version_pinning",
                f"MCP server '{name}' uses an unpinned package reference (arguments omitted).",
                "Pin to an exact version and store a hash of the tool schema.",
            )
        if any(p.ecosystem == "oci" and p.pin != "tag" for p in floating):
            add(
                RiskSeverity.HIGH,
                "version_pinning",
                f"MCP server '{name}' container image has neither a digest nor a release tag.",
                "Pin to a SHA256 artifact digest and verify its provenance.",
            )
        if any(p.ecosystem == "oci" and p.pin == "tag" for p in floating):
            add(
                RiskSeverity.MEDIUM,
                "mutable_image_tag",
                f"MCP server '{name}' container image lacks an immutable digest pin.",
                "Pin to a SHA256 artifact digest and verify its provenance.",
            )
        if identity_unknown:
            add(
                RiskSeverity.HIGH,
                "launcher_identity",
                f"MCP server '{name}' launcher identity and pin are unknown: {identity_unknown}.",
                "Launch a registry package pinned to an exact version, or an image pinned by "
                "digest, in a form the inventory classifies.",
            )
        if sources:
            labels = sorted({source.split("=", 1)[0] for source in sources})
            add(
                RiskSeverity.MEDIUM,
                "package_source",
                f"MCP server '{name}' resolves packages through a non-default source "
                f"({', '.join(labels)}); package name and version do not establish identity.",
                "Review that registry or index, and pin an artifact digest or integrity hash.",
            )
        # A client may start the command whatever transport the server declares.
        if command:
            add(
                RiskSeverity.MEDIUM,
                "local_process",
                f"MCP server '{name}' uses stdio transport (local process)."
                if transport == "stdio"
                else f"MCP server '{name}' declares a launch command (local process) and a "
                "remote transport.",
                "Ensure the command binary is integrity-checked.",
            )
        if endpoint_url and _has_userinfo(endpoint_url):
            add(
                RiskSeverity.HIGH,
                "transport_security",
                f"MCP server '{name}' endpoint URL embeds credentials: {safe_endpoint}",
                "Supply the credential through a header or environment reference.",
            )
        elif (
            endpoint_url
            and safe_endpoint != "[redacted]"
            and not self._secure_endpoint(endpoint_url)
        ):
            add(
                RiskSeverity.HIGH,
                "transport_security",
                f"MCP server '{name}' endpoint is not HTTPS: {safe_endpoint}",
                "Use HTTPS for all remote MCP server connections.",
            )
        if endpoint_url and endpoint_gap:
            dynamic = expands(endpoint_url)
            add(
                RiskSeverity.MEDIUM if dynamic else RiskSeverity.HIGH,
                "endpoint_identity",
                f"MCP server '{name}' endpoint depends on the environment."
                if dynamic
                else f"MCP server '{name}' endpoint host cannot be established from its URL.",
                "Declare a literal https:// URL whose host every URL parser reads the same way.",
            )
        if command and (endpoints or remote_type):
            add(
                RiskSeverity.LOW,
                "transport_ambiguity",
                f"MCP server '{name}' declares both a launch command and an endpoint."
                if endpoints
                else f"MCP server '{name}' declares a launch command and a remote transport type.",
                "Declare either a command or an endpoint, and an explicit transport type.",
            )
        high = [label for flag, label in _CONTEXT_HIGH.items() if context.get(flag)]
        if context.get("command_fields"):
            high.append("a command-valued field")
        if high:
            add(
                RiskSeverity.HIGH,
                "launch_context",
                f"MCP server '{name}' has high-risk launch settings: {', '.join(high)}.",
                "Remove host-level privileges and command-valued fields, or isolate the server.",
            )
        medium = [label for flag, label in _CONTEXT_MEDIUM.items() if context.get(flag)]
        if medium:
            add(
                RiskSeverity.MEDIUM,
                "launch_context",
                f"MCP server '{name}' launch widens its execution context: {', '.join(medium)}.",
                "Review the launch options and environment before approving this server.",
            )
        if context.get("shell_wrapper") and not identity_unknown:
            add(
                RiskSeverity.LOW,
                "launch_context",
                f"MCP server '{name}' is launched through a shell or wrapper.",
                "Launch the server executable directly.",
            )
        approve = settings.get("auto_approve")
        if approve:
            scope = (
                "all tools are trusted" if approve == "all" else f"{approve} tools auto-approved"
            )
            add(
                RiskSeverity.MEDIUM,
                "auto_approval",
                f"MCP server '{name}' tools run without per-call approval: {scope}.",
                "Require human approval for tool calls with side effects.",
            )
        if withheld:
            add(
                RiskSeverity.MEDIUM,
                "completeness",
                f"MCP server '{name}' identity fields are withheld because environment or header "
                f"values occur in them: {', '.join(withheld)}.",
                f"Keep credentials out of names, hosts and package references, and set "
                f"{SOURCE_BINDING_KEY_ENV} during collection.",
            )
        return risks

    def _report_unparsed_clients(self, files: ConfinedCollection, result: ScanResult) -> None:
        """Recognised client files whose MCP declarations this collector does not parse."""
        for path, member in UNPARSED_CLIENT_FILES:
            text = files.read_text(path, missing_ok=True)
            if text is None:
                continue
            if member is not None:
                try:
                    data = _load_jsonc(text)
                except (ValueError, RecursionError):
                    data = {member: True}
                if not isinstance(data, dict) or not data.get(member):
                    continue
            result.surfaces_excluded.append(f"{path}: MCP client configuration not inventoried")
        for directory in UNPARSED_CLIENT_DIRECTORIES:
            if next(iter(files.iter_files(directory)), None) is not None:
                result.surfaces_excluded.append(
                    f"{directory}: MCP client configuration not inventoried"
                )

    def _extract_tools(
        self,
        server_name: str,
        config: dict[str, Any],
        secrets: SecretScrubber | None = None,
        *,
        server_ref: str,
        config_path: str,
    ) -> list[ToolComponent]:
        tools_config = config.get("tools", [])
        tool_comps = []
        scrubber = secrets or SecretScrubber()

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

                    def_hash = hash_tool_definition(
                        t_name,
                        t_desc,
                        t_schema,
                        t_annotations,
                        **tool_definition_extensions(tool_def),
                    )
                    tool_ref = (
                        "tool:"
                        + hash_canonical({"server": server_ref, "name": t_name}).split(":", 1)[1]
                    )

                    side_effect = self._classify_side_effects(t_annotations, t_name)
                    conflict = self._read_only_conflict(t_annotations, side_effect)
                    caps = self._infer_capabilities(t_name, t_desc, t_annotations)
                    safe = redact_descriptor(
                        {
                            "name": t_name,
                            "description": t_desc,
                            "inputSchema": t_schema,
                            "annotations": t_annotations,
                        },
                        scrubber,
                    )
                    t_name = self._tool_name(t_name, scrubber)
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
                    if conflict:
                        risks.append(
                            RiskAssessment(
                                severity=RiskSeverity.MEDIUM,
                                category="capability_scope",
                                detail=f"Tool '{t_name}' is declared read-only but named for a destructive operation.",
                                recommendation="Verify the tool's effects before relying on its readOnlyHint.",
                            )
                        )

                    tool_comps.append(
                        ToolComponent(
                            bom_ref=tool_ref,
                            name=t_name,
                            mcp_server_ref=server_ref,
                            source_path=config_path,
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
        """Classify HTTPS or WSS, or exact loopback HTTP or WS, without connecting."""
        try:
            parsed = urlsplit(url)
            if not parsed.hostname or parsed.username is not None or parsed.password is not None:
                return False
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                return False
            if parsed.scheme in {"https", "wss"}:
                return True
            if parsed.scheme not in {"http", "ws"}:
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
        from nexus_symbiote.scanners.mcp_sources import collect_source_references

        budget = SourceBudget("MCP source references", result)
        collect_source_references(self._files, result, sources, budget)

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
        """Profile from boolean hints and name words; a read-only hint never hides harm."""
        tokens = self._tokenize_identifier(tool_name)
        money = bool(tokens & _MONEY_VERBS) or (
            bool(tokens & {"transfer", "send"}) and bool(tokens & _MONEY_NOUNS)
        )
        harmful = (
            SideEffectProfile.FINANCIAL_TRANSACTION
            if money
            else SideEffectProfile.DESTRUCTIVE
            if tokens & _DESTRUCTIVE
            else None
        )
        if annotations.get("destructiveHint") is True:
            return SideEffectProfile.DESTRUCTIVE
        if annotations.get("readOnlyHint") is True:
            return harmful or SideEffectProfile.READ_ONLY
        if harmful:
            return harmful
        if tokens & _STATE_CHANGING:
            return SideEffectProfile.STATE_MODIFYING
        if tokens & _READING:
            return SideEffectProfile.READ_ONLY
        return SideEffectProfile.UNKNOWN

    @staticmethod
    def _read_only_conflict(annotations: dict[str, Any], side_effect: SideEffectProfile) -> bool:
        """A read-only hint on a tool whose name reads destructive or financial."""
        return (
            annotations.get("readOnlyHint") is True
            and annotations.get("destructiveHint") is not True
            and side_effect in _HARMFUL
        )

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
            "folder",
            "path",
            "fs",
            "disk",
        }:
            caps.append(CapabilityClass.FILESYSTEM)
        if tokens & {"http", "https", "url", "fetch", "request", "api", "endpoint", "web"}:
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
            "script",
        }:
            caps.append(CapabilityClass.EXECUTE)
        if tokens & (_MONEY_VERBS | _MONEY_NOUNS | {"billing", "transfer"}):
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
        if tokens & (_STATE_CHANGING | _DESTRUCTIVE):
            caps.append(CapabilityClass.WRITE)
        elif tokens & _READING:
            caps.append(CapabilityClass.READ)
        return caps


# Whole words of _tokenize_identifier, each also matched without a plural or verb
# ending: "compute_stats" does not read as "put", nor "dropdown" as "drop". "patch"
# and "upload" are left out: the stem rule makes "monkey patch" and "the uploaded
# executable" in a description read as writes.
_DESTRUCTIVE = _names(
    "delete remove drop destroy purge truncate wipe erase kill terminate uninstall revoke "
    "unlink rmdir"
)
_MONEY_VERBS = _names("pay payout refund charge purchase checkout withdraw withdrawal deposit wire")
_MONEY_NOUNS = _names("funds fund money payment balance cash invoice crypto coins usd eur")
_STATE_CHANGING = _names(
    "create update write send post put insert modify edit set add append move rename commit "
    "push publish deploy merge approve"
)
_READING = _names("get list read search query fetch find lookup describe show view count inspect")
_HARMFUL = frozenset({SideEffectProfile.DESTRUCTIVE, SideEffectProfile.FINANCIAL_TRANSACTION})
