"""MCP client dialects, endpoints, transports and launch context are read or reported."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest
from packageurl import PackageURL

from nexus_symbiote.core.models import MCPClientComponent, MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner, _load_jsonc


def scan(root: Path, files: dict[str, str]):
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return MCPScanner().scan(root, config_only=True)


def servers(result) -> dict[str, MCPServerComponent]:
    return {c.name: c for c in result.components if isinstance(c, MCPServerComponent)}


def single(tmp_path: Path, server: dict) -> tuple[MCPServerComponent, list[str]]:
    result = scan(tmp_path, {".mcp.json": json.dumps({"mcpServers": {"s": server}})})
    assert not result.scan_failures, result.scan_failures
    return servers(result)["s"], result.surfaces_excluded


VSCODE = """{
  // Workspace servers; comments and trailing commas are allowed here.
  "inputs": [{"type": "promptString", "id": "token", "description": "Token", "password": true}],
  "servers": {
    "fetch": {"type": "stdio", "command": "uvx", "args": ["mcp-server-fetch@0.6.2"],},
    /* A remote server with a prompted credential. */
    "github": {
      "type": "http",
      "url": "https://api.githubcopilot.com/mcp/",
      "headers": {"Authorization": "Bearer ${input:token}"},
    },
    "events": {"type": "sse", "url": "https://events.example.test/mcp"},
  },
}
"""


def test_vscode_workspace_servers_are_inventoried(tmp_path):
    result = scan(tmp_path, {".vscode/mcp.json": VSCODE})
    assert not result.scan_failures and not result.surfaces_excluded
    found = servers(result)
    assert found["fetch"].launcher_package == "pypi:mcp-server-fetch"
    assert found["fetch"].transport == "stdio"
    assert found["github"].transport == "streamable-http"
    assert found["github"].endpoint_url == "https://api.githubcopilot.com"
    assert found["github"].properties["header_names"] == ["Authorization"]
    assert found["events"].transport == "sse"
    client = next(c for c in result.components if isinstance(c, MCPClientComponent))
    assert client.host_application == "vscode"
    assert client.server_refs == sorted(s.bom_ref for s in found.values())
    assert ".vscode/mcp.json" in result.surfaces_scanned


def test_vscode_input_placeholder_in_endpoint_is_a_gap(tmp_path):
    config = {"servers": {"remote": {"type": "http", "url": "https://${input:host}/mcp"}}}
    result = scan(tmp_path, {".vscode/mcp.json": json.dumps(config)})
    assert servers(result)["remote"].endpoint_url == "[redacted]"
    assert result.surfaces_excluded == [
        ".vscode/mcp.json: MCP server 'remote' endpoint depends on environment expansion"
    ]


@pytest.mark.parametrize(
    "text",
    [
        '{"servers": {"a": {"command": "node", "args": ["x"]}} /* unterminated',
        '{"servers": {"a": {}}, "servers": {"b": {}}}',
        '{"servers": "unterminated}',
    ],
)
def test_malformed_jsonc_is_a_failure(tmp_path, text):
    result = scan(tmp_path, {".vscode/mcp.json": text})
    assert result.scan_failures == [".vscode/mcp.json: invalid JSON or duplicate keys"]
    assert not servers(result)


def test_jsonc_keeps_comment_markers_inside_strings():
    data = _load_jsonc('{"url": "https://x.test/a//b", "d": "/* not a comment */",}')
    assert data == {"url": "https://x.test/a//b", "d": "/* not a comment */"}
    assert _load_jsonc("[1, 2, /* c */ ]") == [1, 2]
    assert _load_jsonc('{"a": "\\\\"} // tail') == {"a": "\\"}


# A reader that ends the comment only at the line feed sees just "safe"; VS Code,
# which also ends it at the separator, starts "evil" as well.
HIDDEN = (
    '{"servers": {"safe": {"type": "stdio", "command": "node", "args": ["a.js"]} // note%s'
    ' , "evil": {"type": "stdio", "command": "npx", "args": ["-y", "evil-mcp@latest"]}\n}}'
)


@pytest.mark.parametrize("separator", ["\r", "\u2028", "\u2029"])
def test_jsonc_line_ends_that_readers_disagree_on_are_a_failure(tmp_path, separator):
    result = scan(tmp_path, {".vscode/mcp.json": HIDDEN % separator})
    assert result.scan_failures == [".vscode/mcp.json: invalid JSON or duplicate keys"]
    assert not servers(result)


def test_jsonc_crlf_line_comments_are_read(tmp_path):
    text = '{"servers": {"safe": {"type": "stdio", "command": "node"}} // note\r\n}'
    result = scan(tmp_path, {".vscode/mcp.json": text})
    assert not result.scan_failures and set(servers(result)) == {"safe"}


def test_unparsed_client_with_ambiguous_line_ends_is_still_a_gap(tmp_path):
    text = '{"theme": "x" // c\r, "context_servers": {"evil": {}}\n}'
    result = scan(tmp_path, {".zed/settings.json": text})
    assert result.surfaces_excluded == [
        ".zed/settings.json: MCP client configuration not inventoried"
    ]


@pytest.mark.parametrize("payload", ["/*" * 200_000, "//\n" * 200_000, '"a",' * 200_000])
def test_jsonc_preprocessing_is_linear(payload):
    started = time.monotonic()
    with pytest.raises(ValueError):
        _load_jsonc(payload)
    assert time.monotonic() - started < 5


def test_gemini_settings_use_gemini_url_semantics_and_trust(tmp_path):
    settings = {
        "theme": "Default",
        "mcpServers": {
            "events": {"url": "https://events.example.test/mcp"},
            "api": {"httpUrl": "https://api.example.test/mcp", "trust": True},
        },
    }
    result = scan(tmp_path, {".gemini/settings.json": json.dumps(settings)})
    found = servers(result)
    assert found["events"].transport == "sse"
    assert found["api"].transport == "streamable-http"
    assert found["api"].endpoint_url == "https://api.example.test"
    assert found["api"].properties["client_settings"] == {"auto_approve": "all"}
    assert any(
        r.category == "auto_approval" and "all tools are trusted" in r.detail
        for r in found["api"].risks
    )
    assert {c.host_application for c in result.components if isinstance(c, MCPClientComponent)} == {
        "gemini-cli"
    }


def test_codex_project_config_toml_is_inventoried(tmp_path):
    toml = (
        '[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp@1.2.3"]\n'
        'env = { DOCS_TOKEN = "secret-docs-token-1" }\nenabled_tools = ["search"]\n\n'
        '[mcp_servers.remote]\nurl = "https://mcp.example.test/mcp"\n'
        'bearer_token_env_var = "REMOTE_TOKEN"\n'
    )
    result = scan(tmp_path, {".codex/config.toml": toml})
    assert not result.scan_failures and not result.surfaces_excluded
    found = servers(result)
    assert found["docs"].launcher_package == "npm:docs-mcp"
    assert found["docs"].properties["client_settings"] == {"tool_filters": 1}
    assert found["remote"].transport == "streamable-http"
    assert found["remote"].properties["client_settings"] == {"bearer_token_variable": True}
    assert "secret-docs-token-1" not in json.dumps(
        [c.model_dump(mode="json") for c in result.components]
    )


def test_invalid_codex_toml_is_a_failure(tmp_path):
    result = scan(tmp_path, {".codex/config.toml": "[mcp_servers.docs\ncommand = 1"})
    assert result.scan_failures == [".codex/config.toml: invalid TOML"]


@pytest.mark.parametrize(
    "path,host",
    [
        (".roo/mcp.json", "roo-code"),
        (".kiro/settings/mcp.json", "kiro"),
        (".amazonq/mcp.json", "amazon-q"),
        (".windsurf/mcp.json", "windsurf"),
        (".cline/mcp.json", "cline"),
    ],
)
def test_other_project_client_files_are_inventoried(tmp_path, path, host):
    config = {
        "mcpServers": {
            "docs": {
                "command": "npx",
                "args": ["-y", "docs@latest"],
                "disabled": True,
                "autoApprove": ["search"],
            }
        }
    }
    result = scan(tmp_path, {path: json.dumps(config)})
    server = servers(result)["docs"]
    assert server.source_path == path
    assert server.properties["client_settings"] == {"auto_approve": 1, "disabled": True}
    assert any(r.category == "version_pinning" for r in server.risks)
    assert any(
        c.host_application == host for c in result.components if isinstance(c, MCPClientComponent)
    )


@pytest.mark.parametrize(
    "files,expected",
    [
        ({".zed/settings.json": '{"context_servers": {"x": {}}}'}, ".zed/settings.json"),
        ({"opencode.json": '{"mcp": {"x": {"type": "local"}}}'}, "opencode.json"),
        ({".continue/mcpServers/server.yaml": "name: x"}, ".continue/mcpServers"),
        ({".junie/mcp/mcp.json": "{}"}, ".junie/mcp/mcp.json"),
        ({".zed/settings.json": "{not json"}, ".zed/settings.json"),
    ],
)
def test_recognised_client_files_that_are_not_parsed_are_gaps(tmp_path, files, expected):
    result = scan(tmp_path, files)
    assert result.surfaces_excluded == [f"{expected}: MCP client configuration not inventoried"]


def test_unrelated_editor_settings_are_not_gaps(tmp_path):
    result = scan(tmp_path, {".zed/settings.json": '{"tab_size": 2}', "opencode.json": "{}"})
    assert not result.surfaces_excluded


def test_both_server_maps_are_read_and_duplicate_names_fail(tmp_path):
    config = {"mcpServers": {"a": {"command": "node"}}, "servers": {"b": {"command": "node"}}}
    assert set(servers(scan(tmp_path / "x", {"mcp.json": json.dumps(config)}))) == {"a", "b"}
    config["servers"]["a"] = {"command": "python"}
    result = scan(tmp_path / "y", {"mcp.json": json.dumps(config)})
    assert "mcp.json: MCP server declared under more than one server map" in result.scan_failures


def test_unknown_and_command_valued_fields_fail_closed(tmp_path):
    server, gaps = single(
        tmp_path,
        {"type": "http", "url": "https://x.test/mcp", "headersHelper": "/bin/token", "tags": ["a"]},
    )
    assert gaps == [".mcp.json: MCP server 's' declares 2 fields the collector does not interpret"]
    finding = next(r for r in server.risks if r.category == "launch_context")
    assert finding.severity.value == "high" and "command-valued field" in finding.detail
    assert "/bin/token" not in server.model_dump_json()
    assert server.properties["declared_fields"] == ["headersHelper", "tags", "type", "url"]


@pytest.mark.parametrize(
    "server,transport",
    [
        ({"type": "sse", "url": "https://x.test/mcp"}, "sse"),
        ({"url": "https://x.test/ssexy/mcp"}, "streamable-http"),
        ({"url": "https://x.test/v1/sse"}, "sse"),
        ({"url": "wss://x.test/socket"}, "websocket"),
        ({"serverUrl": "https://x.test/mcp"}, "streamable-http"),
        ({"type": "stdio", "command": "node", "url": "https://localhost"}, "stdio"),
    ],
)
def test_declared_transport_is_honoured(tmp_path, server, transport):
    record, gaps = single(tmp_path, server)
    assert record.transport == transport
    assert not gaps
    assert not any(r.category == "transport_security" for r in record.risks)


def test_command_with_endpoint_keeps_the_local_process_finding(tmp_path):
    record, _ = single(tmp_path, {"command": "npx", "args": ["x@1.0.0"], "url": "https://x.test"})
    categories = {(r.severity.value, r.category) for r in record.risks}
    assert {("medium", "local_process"), ("low", "transport_ambiguity")} <= categories


def test_unrecognised_transport_type_is_a_gap(tmp_path):
    _, gaps = single(tmp_path, {"type": "carrier-pigeon", "url": "https://x.test/mcp"})
    assert gaps == [".mcp.json: MCP server 's' declares an unrecognised transport type"]


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example\\@good.example/mcp",
        "https://evil.example\\.good.example/mcp",
        "https:\\\\evil.example/mcp",
        "https:///evil.example/mcp",
        "https:evil.example/mcp",
        "https://%65vil.example/mcp",
    ],
)
def test_ambiguous_endpoint_authority_is_never_exported_as_a_host(tmp_path, url):
    record, gaps = single(tmp_path, {"url": url})
    assert record.endpoint_url == "[redacted]"
    assert gaps == [".mcp.json: MCP server 's' endpoint authority is ambiguous"]
    finding = next(r for r in record.risks if r.category == "endpoint_identity")
    assert finding.severity.value == "high"
    assert "good.example" not in record.model_dump_json()


@pytest.mark.parametrize(
    "url", ["${API_BASE_URL:-https://api.example.test}/mcp", "https://${MCP_HOST}/mcp"]
)
def test_environment_expanded_endpoint_is_a_gap_not_a_value(tmp_path, url):
    record, gaps = single(tmp_path, {"url": url})
    assert record.endpoint_url == "[redacted]"
    assert gaps == [".mcp.json: MCP server 's' endpoint depends on environment expansion"]
    assert any(
        r.category == "endpoint_identity" and r.severity.value == "medium" for r in record.risks
    )


def test_endpoint_with_user_information_is_named_accurately(tmp_path):
    record, _ = single(tmp_path, {"url": "https://user:pw@x.test/mcp"})
    finding = next(r for r in record.risks if r.category == "transport_security")
    assert "embeds user information" in finding.detail and "pw" not in finding.detail


@pytest.mark.parametrize(
    "args,high,medium",
    [
        (["run", "--privileged", "img@sha256:" + "a" * 64], ["privileged mode"], []),
        (
            ["run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img"],
            ["container runtime socket"],
            [],
        ),
        (["run", "--mount", "type=bind,source=/,target=/host", "img"], ["host root mount"], []),
        (["run", "--security-opt", "seccomp=unconfined", "img"], ["disabled confinement"], []),
        (["run", "--network", "host", "--pid=host", "img"], [], ["a host namespace"]),
        (
            ["run", "--cap-add", "NET_BIND_SERVICE", "--device", "/dev/kvm", "img"],
            [],
            ["added capabilities", "host devices"],
        ),
        (["run", "-v", "/home/alice:/data", "img"], [], ["broad host directory mount"]),
        (["run", "-v", "data:/data", "-v", "/srv/app/cache:/cache", "img"], [], []),
    ],
)
def test_container_launch_context_is_rated_without_values(tmp_path, args, high, medium):
    record, _ = single(tmp_path, {"command": "docker", "args": args})
    details = {r.severity.value: r.detail for r in record.risks if r.category == "launch_context"}
    for label in high:
        assert label in details["high"]
    for label in medium:
        assert label in details["medium"]
    if not high and not medium:
        assert not details
    exported = record.model_dump_json()
    assert "/home/alice" not in exported and "docker.sock" not in exported


@pytest.mark.parametrize(
    "server,reason",
    [
        ({"command": "node", "args": ["-e", "require('x')"]}, "inline node code"),
        ({"command": "node", "args": ["--eval=require('x')"]}, "inline node code"),
        ({"command": "node", "args": ["-pe", "require('x')"]}, "inline node code"),
        ({"command": "node", "args": ["--import", "data:text/javascript,x"]}, "inline node code"),
        ({"command": "node", "args": ["--title", "t", "-e", "x"]}, "inline node code"),
        ({"command": "python3", "args": ["-c", "import x"]}, "inline python code"),
        ({"command": "python3", "args": ["-Ic", "import x"]}, "inline python code"),
        ({"command": "python3", "args": ["-W", "ignore", "-c", "x"]}, "inline python code"),
        ({"command": "ruby", "args": ["-I", "lib", "-e", "x"]}, "inline ruby code"),
        ({"command": "uv", "args": ["run", "python", "-c", "x"]}, "inline python code"),
        ({"command": "npx", "args": ["-p", "pkg@1.2.3", "node", "-e", "x"]}, "inline node code"),
        ({"command": "deno", "args": ["eval", "import('npm:x')"]}, "inline deno code"),
        ({"command": "deno", "args": ["run", "data:application/javascript,x"]}, "inline deno"),
    ],
)
def test_inline_interpreter_code_is_an_unknown_launcher(tmp_path, server, reason):
    record, gaps = single(tmp_path, server)
    finding = next(r for r in record.risks if r.category == "launcher_identity")
    assert finding.severity.value == "high" and reason in finding.detail
    assert gaps and "launcher identity unknown" in gaps[0]
    assert record.version_pinned is False


@pytest.mark.parametrize(
    "server",
    [
        {"command": "node", "args": ["server.js", "-e", "production", "-p", "8080"]},
        {"command": "node", "args": ["--inspect", "dist/index.js"]},
        {"command": "python3", "args": ["-u", "-m", "my_server", "-c", "config.toml"]},
        {"command": "python3", "args": ["-X", "dev", "server.py"]},
    ],
)
def test_script_arguments_are_not_interpreter_options(tmp_path, server):
    record, gaps = single(tmp_path, server)
    assert not gaps
    assert not any(r.category == "launcher_identity" for r in record.risks)


@pytest.mark.parametrize(
    "server,label",
    [
        (
            {"command": "node", "args": ["--require", "/srv/hook/x.js", "s.js"]},
            "a preloaded module",
        ),
        (
            {"command": "npx", "args": ["--node-options=--require /srv/hook/x.js", "pkg@1.2.3"]},
            "an option that loads local code",
        ),
        (
            {"command": "npm", "args": ["--script-shell", "/srv/hook/x.sh", "exec", "pkg@1.2.3"]},
            "an option that loads local code",
        ),
        (
            {
                "command": "node",
                "args": ["s.js"],
                "env": {"NODE_OPTIONS": "--require=/srv/hook/x.js"},
            },
            "environment that changes code loading",
        ),
        (
            {"command": "env", "args": ["LD_PRELOAD=/srv/hook/x.so", "node", "s.js"]},
            "environment that changes code loading",
        ),
    ],
)
def test_interpreter_and_loader_context_is_rated(tmp_path, server, label):
    record, gaps = single(tmp_path, server)
    assert not gaps
    assert any(r.category == "launch_context" and label in r.detail for r in record.risks)
    assert "/srv/hook/x" not in record.model_dump_json()


def test_simple_shell_wrapper_is_a_low_finding(tmp_path):
    record, gaps = single(tmp_path, {"command": "sh", "args": ["-c", "node server.js"]})
    assert not gaps and record.properties["launcher_wrappers"] == ["sh -c"]
    assert ("low", "launch_context") in {(r.severity.value, r.category) for r in record.risks}


@pytest.mark.parametrize(
    "server,purl",
    [
        (
            {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21"]},
            "pkg:npm/%40modelcontextprotocol/server-filesystem@2025.8.21",
        ),
        (
            {"command": "npx", "args": ["-y", "mcp-remote@0.1.15", "https://x.test/sse"]},
            "pkg:npm/mcp-remote@0.1.15",
        ),
        (
            {"command": "uvx", "args": ["mcp-server-git==1!2.3rc1+local.1"]},
            "pkg:pypi/mcp-server-git@1%212.3rc1%2Blocal.1",
        ),
        ({"command": "npx", "args": ["-y", "mcp-remote@^0.1.15"]}, None),
        ({"command": "npx", "args": ["-y", "Legacy-Name@1.2.3"]}, None),
        ({"command": "docker", "args": ["run", "img@sha256:" + "a" * 64]}, None),
        (
            {
                "command": "npx",
                "args": ["-y", "a@1.0.0"],
                "env": {"npm_config_registry": "https://r.test"},
            },
            None,
        ),
    ],
)
def test_exact_npm_and_pypi_launchers_get_a_package_url(tmp_path, server, purl):
    record, _ = single(tmp_path, server)
    assert record.package_url == purl
    if purl is not None:
        parsed = PackageURL.from_string(purl)
        assert parsed.type in {"npm", "pypi"} and parsed.version == record.version


def test_config_records_use_root_relative_paths_and_survive_a_move(tmp_path):
    config = {
        "mcpServers": {
            "docs": {
                "command": "npx",
                "args": ["-y", "docs@1.2.3"],
                "tools": [{"name": "search", "description": "Search docs"}],
            }
        }
    }
    first = tmp_path / "checkout-a" / "agent"
    result = scan(first, {".mcp.json": json.dumps(config), ".cursor/mcp.json": json.dumps(config)})
    second = tmp_path / "elsewhere" / "agent"
    shutil.copytree(first, second)
    moved = MCPScanner().scan(second, config_only=True)

    def dump(scanned) -> str:
        return json.dumps(
            {
                "components": [c.model_dump(mode="json") for c in scanned.components],
                "scanned": scanned.surfaces_scanned,
                "excluded": scanned.surfaces_excluded,
                "failures": scanned.scan_failures,
            },
            sort_keys=True,
        )

    assert dump(result) == dump(moved)
    assert str(tmp_path) not in dump(result)
    assert result.surfaces_scanned == [".mcp.json", ".cursor/mcp.json"]
    client = next(c for c in result.components if c.bom_ref == "mcp-client:cursor")
    assert client.config_path == ".cursor/mcp.json" and client.properties["config_paths"] == [
        ".cursor/mcp.json"
    ]


def test_settings_without_mcp_servers_create_no_client(tmp_path):
    result = scan(
        tmp_path,
        {".gemini/settings.json": '{"theme": "Default"}', ".codex/config.toml": 'model = "x"\n'},
    )
    assert not result.components and not result.scan_failures and not result.surfaces_excluded
    assert result.surfaces_scanned == [".gemini/settings.json", ".codex/config.toml"]


def test_client_fields_of_other_dialects_are_interpreted(tmp_path):
    record, gaps = single(
        tmp_path,
        {
            "url": "https://x.test/v1/events",
            "transportType": "sse",
            "disabledTools": ["delete"],
            "watchPaths": ["src"],
            "auth": {"CLIENT_SECRET": "cursor-oauth-secret-1"},
        },
    )
    assert not gaps and record.transport == "sse"
    assert record.properties["client_settings"] == {
        "authentication": True,
        "watch_paths": True,
        "tool_filters": 1,
    }
    assert "cursor-oauth-secret-1" not in record.model_dump_json()
