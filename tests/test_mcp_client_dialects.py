"""Zed, opencode, Continue and Junie client files are parsed as dialects, not left as gaps.

Each client's own server shape is read into the common form, so every launch goes
through the launcher classification and every environment value is redacted as for
the other dialects; a shape the collector cannot confirm stays a gap with its reason.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPClientComponent, MCPServerComponent
from nexus_symbiote.scanners.mcp import MCP_CONFIG_DIRECTORIES, MCP_DIALECTS, MCPScanner

ZED_ENV_SENTINEL = "zed-env-sentinel-token-value-0001"
ZED_SETTINGS_SENTINEL = "ghp_ZEDSETTINGSSENTINEL00000000000000000000"
OPENCODE_SENTINEL = "opencode-env-sentinel-token-value-0002"
CONTINUE_SENTINEL = "xoxb-CONTINUE-SENTINEL-0003"
JUNIE_SENTINEL = "junie-env-sentinel-token-value-0004"

ZED = f"""{{
  // Editor settings; comments and trailing commas are allowed here.
  "theme": "One Dark",
  "context_servers": {{
    "fetch": {{
      "command": {{
        "path": "uvx",
        "args": ["mcp-server-fetch==2025.4.7"],
        "env": {{"FETCH_TOKEN": "{ZED_ENV_SENTINEL}"}},
      }},
    }},
    "docs": {{"source": "custom", "command": "npx", "args": ["-y", "docs-mcp@1.2.3"]}},
    "mcp-server-github": {{
      "source": "extension",
      "settings": {{"github_personal_access_token": "{ZED_SETTINGS_SENTINEL}"}},
    }},
    "remote": {{"url": "https://mcp.example.test/mcp"}},
  }},
}}
"""
OPENCODE = {
    "$schema": "https://opencode.ai/config.json",
    "mcp": {
        "local": {
            "type": "local",
            "command": ["npx", "-y", "oc-mcp@2.0.0"],
            "environment": {"OC_TOKEN": OPENCODE_SENTINEL},
            "enabled": False,
        },
        "remote": {
            "type": "remote",
            "url": "https://mcp.example.test/sse",
            "headers": {"Authorization": "Bearer " + OPENCODE_SENTINEL},
        },
    },
}
CONTINUE_CONFIG = (
    "name: analytics\n"
    "models: []\n"
    "mcpServers:\n"
    "  - name: slack\n"
    "    command: docker\n"
    "    args: [run, -i, --rm, -e, SLACK_BOT_TOKEN, mcp/slack:latest]\n"
    "    env:\n"
    f"      SLACK_BOT_TOKEN: {CONTINUE_SENTINEL}\n"
    "  - name: events\n"
    "    type: sse\n"
    "    url: https://events.example.test/sse\n"
)
CONTINUE_BLOCK = (
    "name: Playwright\n"
    "version: 0.0.1\n"
    "schema: v1\n"
    "mcpServers:\n"
    "  - name: browser\n"
    "    command: npx\n"
    "    args:\n"
    '      - "@playwright/mcp@1.0.0"\n'
)
JUNIE = {
    "mcpServers": {
        "fs": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/data"],
            "env": {"FS_SECRET": JUNIE_SENTINEL},
        }
    }
}
SECRETS = (
    ZED_ENV_SENTINEL,
    ZED_SETTINGS_SENTINEL,
    OPENCODE_SENTINEL,
    CONTINUE_SENTINEL,
    JUNIE_SENTINEL,
)
EXTENSION_GAP = (
    ".zed/settings.json: MCP server 'mcp-server-github' launcher identity unknown "
    "(provided by a Zed extension; the client file holds no launch)"
)
DIRECTORY_GAP = "file below an MCP server directory that the collector does not read there"


def write(root: Path, files: dict[str, str | bytes]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    return root


def scan(root: Path, files: dict[str, str | bytes]):
    return MCPScanner().scan(write(root, files), config_only=True)


def servers(result) -> dict[str, MCPServerComponent]:
    return {c.name: c for c in result.components if isinstance(c, MCPServerComponent)}


def clients(result) -> dict[str, MCPClientComponent]:
    return {c.host_application: c for c in result.components if isinstance(c, MCPClientComponent)}


def dump(result) -> str:
    return json.dumps(
        {
            "components": [c.model_dump(mode="json") for c in result.components],
            "scanned": result.surfaces_scanned,
            "excluded": result.surfaces_excluded,
            "failures": result.scan_failures,
        },
        sort_keys=True,
    )


def test_zed_context_servers_are_inventoried_in_both_command_shapes(tmp_path):
    result = scan(tmp_path, {".zed/settings.json": ZED})
    assert not result.scan_failures
    found = servers(result)
    assert set(found) == {"fetch", "docs", "mcp-server-github", "remote"}
    assert found["fetch"].command == "uvx"
    assert found["fetch"].launcher_package == "pypi:mcp-server-fetch"
    assert found["fetch"].version == "2025.4.7" and found["fetch"].version_pinned is True
    assert found["fetch"].env == {"FETCH_TOKEN": "***"}
    assert found["fetch"].args == ["***"]
    assert found["docs"].launcher_package == "npm:docs-mcp" and found["docs"].version == "1.2.3"
    assert found["docs"].properties["declared_fields"] == ["args", "command"]
    assert not any(r.category == "launcher_identity" for r in found["docs"].risks)
    assert found["remote"].transport == "streamable-http"
    assert found["remote"].endpoint_url == "https://mcp.example.test"
    client = clients(result)["zed"]
    assert client.config_path == ".zed/settings.json"
    assert client.server_refs == sorted(s.bom_ref for s in found.values())
    assert result.surfaces_scanned == [".zed/settings.json"]
    assert result.surfaces_excluded == [EXTENSION_GAP]


def test_zed_extension_server_has_an_unknown_launcher_and_scrubbed_settings(tmp_path):
    result = scan(tmp_path, {".zed/settings.json": ZED})
    server = servers(result)["mcp-server-github"]
    assert server.command is None and server.launcher_package is None
    assert server.version_pinned is False
    finding = next(r for r in server.risks if r.category == "launcher_identity")
    assert finding.severity.value == "high"
    assert "provided by a Zed extension" in finding.detail
    assert server.properties["client_settings"] == {"extension_settings": True}
    assert server.properties["declared_fields"] == ["settings"]
    assert ZED_SETTINGS_SENTINEL not in dump(result)


@pytest.mark.parametrize("entry", [{}, {"settings": {}}])
def test_zed_entry_without_a_launch_is_never_a_gap_free_local_launch(tmp_path, entry):
    config = {"context_servers": {"ext": entry}}
    result = scan(tmp_path, {".zed/settings.json": json.dumps(config)})
    server = servers(result)["ext"]
    assert any(r.category == "launcher_identity" for r in server.risks)
    assert result.surfaces_excluded == [
        ".zed/settings.json: MCP server 'ext' launcher identity unknown "
        "(provided by a Zed extension; the client file holds no launch)"
    ]


def test_zed_command_object_fields_the_collector_does_not_read_are_a_gap(tmp_path):
    config = {
        "context_servers": {
            "s": {"command": {"path": "npx", "args": ["x@1.0.0"], "cwd": "/srv/private"}}
        }
    }
    result = scan(tmp_path, {".zed/settings.json": json.dumps(config)})
    server = servers(result)["s"]
    assert server.properties["declared_fields"] == ["args", "command", "command.cwd"]
    assert result.surfaces_excluded == [
        ".zed/settings.json: MCP server 's' declares 1 field the collector does not interpret"
    ]
    assert "/srv/private" not in dump(result)


def test_zed_unknown_source_is_kept_as_a_field_the_collector_does_not_interpret(tmp_path):
    config = {"context_servers": {"s": {"source": "weird", "command": "npx", "args": ["x@1.0.0"]}}}
    result = scan(tmp_path, {".zed/settings.json": json.dumps(config)})
    assert servers(result)["s"].properties["declared_fields"] == ["args", "command", "source"]
    assert result.surfaces_excluded == [
        ".zed/settings.json: MCP server 's' declares 1 field the collector does not interpret"
    ]


@pytest.mark.parametrize("name", ["opencode.json", "opencode.jsonc"])
def test_opencode_servers_are_inventoried(tmp_path, name):
    text = json.dumps(OPENCODE, indent=2)
    if name.endswith(".jsonc"):
        text = "// opencode configuration\n" + text.replace('"mcp": {', '"mcp": { /* servers */')
    result = scan(tmp_path, {name: text})
    assert not result.scan_failures and not result.surfaces_excluded
    found = servers(result)
    assert found["local"].command == "npx" and found["local"].transport == "stdio"
    assert found["local"].launcher_package == "npm:oc-mcp" and found["local"].version == "2.0.0"
    assert found["local"].env == {"OC_TOKEN": "***"}
    assert found["local"].properties["client_settings"] == {"disabled": True}
    assert found["local"].properties["declared_fields"] == [
        "args",
        "command",
        "enabled",
        "env",
        "type",
    ]
    assert found["remote"].transport == "sse"
    assert found["remote"].endpoint_url == "https://mcp.example.test"
    assert found["remote"].properties["header_names"] == ["Authorization"]
    assert found["remote"].properties["declared_fields"] == ["headers", "url"]
    assert clients(result)["opencode"].config_path == name
    assert OPENCODE_SENTINEL not in dump(result)


def test_opencode_enabled_server_has_no_disabled_setting(tmp_path):
    config = {"mcp": {"s": {"type": "local", "command": ["uvx", "x==1.0.0"], "enabled": True}}}
    result = scan(tmp_path, {"opencode.json": json.dumps(config)})
    assert "disabled" not in servers(result)["s"].properties.get("client_settings", {})


def test_opencode_remote_without_sse_path_is_streamable_http(tmp_path):
    config = {"mcp": {"s": {"type": "remote", "url": "https://mcp.example.test/mcp"}}}
    result = scan(tmp_path, {"opencode.json": json.dumps(config)})
    assert servers(result)["s"].transport == "streamable-http"
    assert not result.surfaces_excluded


def test_continue_config_and_server_directory_are_inventoried(tmp_path):
    result = scan(
        tmp_path,
        {
            ".continue/config.yaml": CONTINUE_CONFIG,
            ".continue/mcpServers/playwright.yaml": CONTINUE_BLOCK,
        },
    )
    assert not result.scan_failures
    found = servers(result)
    assert set(found) == {"slack", "events", "browser"}
    assert found["slack"].source_path == ".continue/config.yaml"
    assert found["slack"].command == "docker"
    assert found["slack"].launcher_package == "oci:mcp/slack"
    assert found["slack"].env == {"SLACK_BOT_TOKEN": "***"}
    assert found["slack"].version_pinned is False
    assert any(r.category == "version_pinning" for r in found["slack"].risks)
    assert found["events"].transport == "sse"
    assert found["events"].endpoint_url == "https://events.example.test"
    assert found["browser"].source_path == ".continue/mcpServers/playwright.yaml"
    assert found["browser"].launcher_package == "npm:@playwright/mcp"
    assert found["browser"].version == "1.0.0"
    client = clients(result)["continue"]
    assert client.properties["config_paths"] == [
        ".continue/config.yaml",
        ".continue/mcpServers/playwright.yaml",
    ]
    assert client.server_refs == sorted(s.bom_ref for s in found.values())
    assert result.surfaces_scanned == [
        ".continue/config.yaml",
        ".continue/mcpServers/playwright.yaml",
    ]
    assert CONTINUE_SENTINEL not in dump(result)
    assert "/data" not in dump(result)


def test_continue_settings_without_servers_create_no_client_or_gap(tmp_path):
    result = scan(
        tmp_path,
        {
            ".continue/config.yaml": "name: x\nmodels:\n  - name: m\n    provider: p\n",
            ".continue/mcpServers/notes.md": "# notes\n",
            ".continue/rules/style.md": "Prefer pnpm.\n",
        },
    )
    assert not result.components and not result.scan_failures and not result.surfaces_excluded
    assert result.surfaces_scanned == [".continue/config.yaml"]


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (".continue/mcpServers/bare.yaml", "MCP server file of unconfirmed shape; not inventoried"),
        (".continue/mcpServers/x.json", DIRECTORY_GAP),
        (".continue/mcpServers/nested/x.yaml", DIRECTORY_GAP),
        (".continue/mcpServers/nested/x.yml", DIRECTORY_GAP),
    ],
)
def test_continue_server_files_of_unconfirmed_shape_are_gaps(tmp_path, path, expected):
    content = "name: bare\ncommand: npx\nargs: [x@1.0.0]\n"
    if path.endswith(".json"):
        content = json.dumps({"mcpServers": [{"name": "x", "command": "npx"}]})
    result = scan(tmp_path, {path: content})
    assert not result.components and not result.scan_failures
    assert result.surfaces_excluded == [f"{path}: {expected}"]


def test_continue_yml_member_is_read_and_json_member_is_a_gap(tmp_path):
    result = scan(
        tmp_path,
        {
            ".continue/mcpServers/a.yml": "mcpServers:\n  - name: a\n    command: npx\n"
            "    args: [a@1.0.0]\n",
            ".continue/mcpServers/b.json": '{"mcpServers": []}',
        },
    )
    assert set(servers(result)) == {"a"} and not result.scan_failures
    assert result.surfaces_excluded == [f".continue/mcpServers/b.json: {DIRECTORY_GAP}"]


def test_junie_server_map_is_inventoried(tmp_path):
    result = scan(tmp_path, {".junie/mcp/mcp.json": json.dumps(JUNIE)})
    assert not result.scan_failures and not result.surfaces_excluded
    server = servers(result)["fs"]
    assert server.launcher_package == "npm:@modelcontextprotocol/server-filesystem"
    assert server.version == "1.0.0" and server.env == {"FS_SECRET": "***"}
    assert clients(result)["junie"].config_path == ".junie/mcp/mcp.json"
    assert JUNIE_SENTINEL not in dump(result) and "/data" not in dump(result)


def test_every_new_dialect_names_its_host_and_is_listed_for_the_reference():
    hosts = {
        path: MCPScanner._detect_host_from_config(path)
        for path in [*(dialect.path for dialect in MCP_DIALECTS), ".continue/mcpServers/x.yml"]
    }
    assert hosts[".zed/settings.json"] == "zed"
    assert hosts["opencode.json"] == hosts["opencode.jsonc"] == "opencode"
    assert hosts[".continue/config.yaml"] == hosts[".continue/mcpServers/x.yml"] == "continue"
    assert hosts[".junie/mcp/mcp.json"] == "junie"
    assert MCP_CONFIG_DIRECTORIES == [".continue/mcpServers"]
    assert MCPScanner._detect_host_from_config("pkg/.continue/mcpServers/x.yaml") == "continue"


@pytest.mark.parametrize(
    ("files", "failure"),
    [
        (
            {"opencode.json": '{"mcp": {"s": {"type": "local", "command": []}}}'},
            "opencode.json: invalid server configuration",
        ),
        (
            {"opencode.json": '{"mcp": {"s": {"type": "local", "command": ["npx", 1]}}}'},
            "opencode.json: invalid server configuration",
        ),
        (
            {"opencode.json": '{"mcp": {"s": {"command": ["npx", "x@1.0.0"], "args": ["y"]}}}'},
            "opencode.json: MCP server declares args beside a command list",
        ),
        (
            {
                "opencode.json": json.dumps(
                    {
                        "mcp": {
                            "s": {
                                "command": ["npx", "x@1.0.0"],
                                "environment": {"A": "b"},
                                "env": {"A": "c"},
                            }
                        }
                    }
                )
            },
            "opencode.json: MCP server declares both environment and env",
        ),
        (
            {".zed/settings.json": '{"context_servers": {"s": {"command": {"args": ["x"]}}}}'},
            ".zed/settings.json: invalid server configuration",
        ),
        (
            {".zed/settings.json": '{"context_servers": {"s": {"command": {"path": 1}}}}'},
            ".zed/settings.json: invalid server configuration",
        ),
        (
            {
                ".zed/settings.json": json.dumps(
                    {
                        "context_servers": {
                            "s": {"command": {"path": "npx", "args": ["x"]}, "args": ["y"]}
                        }
                    }
                )
            },
            ".zed/settings.json: MCP server declares args both in and beside its command object",
        ),
        (
            {
                ".zed/settings.json": json.dumps(
                    {
                        "context_servers": {
                            "s": {"command": {"path": "npx", "env": {"A": "x"}}, "env": {"A": "y"}}
                        }
                    }
                )
            },
            ".zed/settings.json: MCP server declares env both in and beside its command object",
        ),
        (
            {
                ".zed/settings.json": json.dumps(
                    {"context_servers": {"s": {"source": "extension", "command": "npx"}}}
                )
            },
            ".zed/settings.json: MCP server declares a launch beside an extension source",
        ),
        (
            {
                ".zed/settings.json": '{"context_servers": {"s": {"source": "extension", "settings": 1}}}'
            },
            ".zed/settings.json: invalid server configuration",
        ),
        (
            {".zed/settings.json": '{"context_servers": []}'},
            ".zed/settings.json: invalid server map or MCP server limit (1000 per file) exceeded",
        ),
        (
            {".continue/config.yaml": "mcpServers:\n  x:\n    command: npx\n"},
            ".continue/config.yaml: invalid server list or MCP server limit (1000 per file) "
            "exceeded",
        ),
        (
            {".continue/config.yaml": "mcpServers:\n  - command: npx\n"},
            ".continue/config.yaml: MCP server entry 1 declares no name and is not inventoried",
        ),
        (
            {".continue/config.yaml": "mcpServers:\n  - name: a\n    command: npx\n  - name: 3\n"},
            ".continue/config.yaml: MCP server entry 2 declares no name and is not inventoried",
        ),
        (
            {".continue/config.yaml": "mcpServers:\n  - name: a\n    command: npx\n  - name: a\n"},
            ".continue/config.yaml: MCP server declared more than once; not inventoried",
        ),
        (
            {".continue/config.yaml": "mcpServers:\n  - name: a\n    command: 1\n"},
            ".continue/config.yaml: invalid server configuration",
        ),
        (
            {".continue/mcpServers/x.yaml": "mcpServers:\n  - npx\n"},
            ".continue/mcpServers/x.yaml: MCP server entry 1 declares no name and is not "
            "inventoried",
        ),
    ],
)
def test_server_shapes_the_client_would_not_start_are_failures(tmp_path, files, failure):
    result = scan(tmp_path, files)
    assert failure in result.scan_failures, result.scan_failures
    assert not servers(result) or failure.endswith(("more than once", "not inventoried"))


DEEP = "[" * 2000 + "]" * 2000


@pytest.mark.parametrize(
    ("files", "failure"),
    [
        ({".zed/settings.json": "{not json"}, ".zed/settings.json: invalid JSON or duplicate keys"),
        (
            {".zed/settings.json": '{"context_servers": {"s": {"command": ' + DEEP + "}}}"},
            ".zed/settings.json: invalid JSON or duplicate keys",
        ),
        (
            {".zed/settings.json": '{"context_servers": {"a": {}}, "context_servers": {}}'},
            ".zed/settings.json: invalid JSON or duplicate keys",
        ),
        (
            {".zed/settings.json": b'{"context_servers": {"\xff": {}}}'},
            ".zed/settings.json: invalid UTF-8",
        ),
        (
            {"opencode.json": '{"mcp": {"s": {"command": ' + DEEP + "}}}"},
            "opencode.json: invalid JSON or duplicate keys",
        ),
        ({"opencode.jsonc": "{"}, "opencode.jsonc: invalid JSON or duplicate keys"),
        (
            {".junie/mcp/mcp.json": '{"mcpServers": {"s": {"tools": ' + DEEP + "}}}"},
            ".junie/mcp/mcp.json: invalid JSON or duplicate keys",
        ),
        ({".junie/mcp/mcp.json": b"\xff"}, ".junie/mcp/mcp.json: invalid UTF-8"),
        (
            {
                ".continue/config.yaml": "base: &b\n  command: npx\nmcpServers:\n  - name: x\n    <<: *b\n"
            },
            ".continue/config.yaml: YAML mapping parse failed or unsupported",
        ),
        (
            {".continue/config.yaml": "mcpServers: !!python/object:os.system []\n"},
            ".continue/config.yaml: YAML mapping parse failed or unsupported",
        ),
        (
            {".continue/config.yaml": "mcpServers: [\n  - name: x\n"},
            ".continue/config.yaml: YAML mapping parse failed or unsupported",
        ),
        (
            {".continue/config.yaml": "mcpServers: " + "[" * 5000 + "]" * 5000 + "\n"},
            ".continue/config.yaml: YAML mapping parse failed or unsupported",
        ),
        (
            {".continue/config.yaml": "- a\n- b\n"},
            ".continue/config.yaml: YAML mapping parse failed or unsupported",
        ),
        (
            {".continue/config.yaml": b"mcpServers: \xff\xfe\n"},
            ".continue/config.yaml: invalid UTF-8",
        ),
        (
            {
                ".continue/mcpServers/x.yaml": "x: &a npx\nmcpServers:\n  - name: s\n    command: *a\n"
            },
            ".continue/mcpServers/x.yaml: YAML mapping parse failed or unsupported",
        ),
        (
            {
                ".continue/mcpServers/x.yml": "mcpServers: ["
                + "{a: " * 3000
                + "1"
                + "}" * 3000
                + "]\n"
            },
            ".continue/mcpServers/x.yml: YAML mapping parse failed or unsupported",
        ),
    ],
)
def test_malformed_deep_mistagged_and_misencoded_files_are_failures(tmp_path, files, failure):
    result = scan(tmp_path, files)
    assert result.scan_failures == [failure]
    assert not result.components and not result.surfaces_excluded


@pytest.mark.parametrize(
    "path", [".zed/settings.json", "opencode.json", ".continue/config.yaml", ".junie/mcp/mcp.json"]
)
def test_an_oversized_client_file_names_the_limit(tmp_path, path):
    content = ("mcpServers: []\n#" if path.endswith(".yaml") else "{}  ") + " " * (4 * 1024 * 1024)
    result = scan(tmp_path, {path: content})
    assert result.scan_failures == [
        f"{path}: file-bytes limit of 4 MiB exceeded; raise it with --limit file-bytes=N"
    ]
    assert not result.components


def test_a_symlink_out_of_the_root_is_a_failure_and_one_inside_is_read(tmp_path):
    outside = tmp_path / "outside" / "config.yaml"
    outside.parent.mkdir()
    outside.write_text(CONTINUE_CONFIG, encoding="utf-8")
    root = write(tmp_path / "root", {"shared/servers/s.yaml": CONTINUE_BLOCK})
    (root / ".continue").mkdir()
    os.symlink(outside, root / ".continue" / "config.yaml")
    os.symlink("../shared/servers", root / ".continue" / "mcpServers")
    result = MCPScanner().scan(root, config_only=True)
    assert result.scan_failures == [".continue/config.yaml: symlink target is absolute"]
    assert set(servers(result)) == {"browser"}
    assert servers(result)["browser"].source_path == ".continue/mcpServers/s.yaml"
    assert result.surfaces_scanned == [".continue/mcpServers/s.yaml"]


def test_an_oversized_extension_settings_object_is_refused_whole(tmp_path):
    settings = {f"k{i}": i for i in range(25_000)}
    config = {"context_servers": {"s": {"source": "extension", "settings": settings}}}
    result = scan(tmp_path, {".zed/settings.json": json.dumps(config)})
    assert result.scan_failures == [
        ".zed/settings.json: MCP server extension settings limit (20000 nodes, 64 levels) exceeded"
    ]
    assert not servers(result)


def test_env_and_settings_secrets_of_every_dialect_are_redacted_and_never_written(tmp_path):
    project = write(
        tmp_path / "project",
        {
            ".zed/settings.json": ZED,
            "opencode.json": json.dumps(OPENCODE),
            ".continue/config.yaml": CONTINUE_CONFIG,
            ".continue/mcpServers/playwright.yaml": CONTINUE_BLOCK,
            ".junie/mcp/mcp.json": json.dumps(JUNIE),
        },
    )
    result = MCPScanner().scan(project, config_only=True)
    assert {s.name for s in servers(result).values()} == {
        "fetch",
        "docs",
        "mcp-server-github",
        "remote",
        "local",
        "slack",
        "events",
        "browser",
        "fs",
    }
    text = dump(result)
    for secret in SECRETS:
        assert secret not in text
    outputs = []
    for name in ("first", "second"):
        out = tmp_path / f"{name}.json"
        run = CliRunner().invoke(
            main, ["scan", "--report-only", str(project), "-f", "json", "-o", str(out)]
        )
        assert run.exit_code == 0, run.output
        outputs.append(out.read_bytes())
        for secret in SECRETS:
            assert secret.encode() not in outputs[-1]
            assert secret not in run.output
    assert outputs[0] == outputs[1]
    inventory = json.loads(outputs[0])
    names = {c["name"] for c in inventory["components"] if c.get("component_type") == "mcp-server"}
    assert {"fetch", "local", "slack", "browser", "fs"} <= names


def test_two_scans_of_every_dialect_are_identical_and_root_relative(tmp_path):
    files = {
        ".zed/settings.json": ZED,
        "opencode.jsonc": json.dumps(OPENCODE),
        ".continue/config.yaml": CONTINUE_CONFIG,
        ".continue/mcpServers/b.yaml": CONTINUE_BLOCK,
        ".continue/mcpServers/a.yaml": CONTINUE_BLOCK.replace("browser", "another"),
        ".junie/mcp/mcp.json": json.dumps(JUNIE),
    }
    first = dump(scan(tmp_path / "one", files))
    second = dump(scan(tmp_path / "two", files))
    assert first == second
    assert str(tmp_path) not in first
    scanned = json.loads(first)["scanned"]
    assert scanned.index(".continue/mcpServers/a.yaml") < scanned.index(
        ".continue/mcpServers/b.yaml"
    )


@pytest.mark.parametrize("name", ["mcp.json", "mcp-config.json"])
def test_generic_config_name_in_the_continue_directory_keeps_its_own_reading(tmp_path, name):
    config = {"mcpServers": {"a": {"command": "npx", "args": ["-y", "a-mcp@1.0.0"]}}}
    result = scan(tmp_path, {f".continue/mcpServers/{name}": json.dumps(config)})
    assert not result.scan_failures and not result.surfaces_excluded
    assert servers(result)["a"].command == "npx"
    assert result.surfaces_scanned == [f".continue/mcpServers/{name}"]
    assert not clients(result)


def test_opencode_file_in_the_continue_directory_is_read_as_opencode(tmp_path):
    config = {"mcp": {"o": {"type": "local", "command": ["npx", "-y", "o-mcp@1.0.0"]}}}
    result = scan(tmp_path, {".continue/mcpServers/opencode.json": json.dumps(config)})
    assert not result.scan_failures and not result.surfaces_excluded
    assert servers(result)["o"].command == "npx"
    assert result.surfaces_scanned == [".continue/mcpServers/opencode.json"]
    assert set(clients(result)) == {"opencode"}


@pytest.mark.parametrize("field", ["settings", "settings (zed extension)", "oauth (disabled)"])
def test_client_shape_fields_stay_uninterpreted_in_another_clients_file(tmp_path, field):
    config = {"mcpServers": {"s": {"command": "npx", "args": ["x@1.0.0"], field: {"k": "v"}}}}
    result = scan(tmp_path, {".mcp.json": json.dumps(config)})
    assert result.surfaces_excluded == [
        ".mcp.json: MCP server 's' declares 1 field the collector does not interpret"
    ]
    assert "client_settings" not in servers(result)["s"].properties


def test_zed_settings_are_interpreted_only_in_the_zed_file(tmp_path):
    config = {"context_servers": {"s": {"source": "extension", "settings": {"k": "v"}}}}
    result = scan(tmp_path, {".zed/settings.json": json.dumps(config)})
    assert not any("does not interpret" in gap for gap in result.surfaces_excluded)
    assert servers(result)["s"].properties["client_settings"] == {"extension_settings": True}


@pytest.mark.parametrize(
    "path", [".zed/mcp.json", "pkg/.continue/mcp.json", ".junie/mcp.json", "pkg/.Zed/mcp.json"]
)
def test_generic_names_below_new_client_directories_keep_their_attribution(tmp_path, path):
    config = {"mcpServers": {"a": {"command": "npx", "args": ["-y", "a-mcp@1.0.0"]}}}
    result = scan(tmp_path, {path: json.dumps(config)})
    assert not result.scan_failures
    assert set(servers(result)) == {"a"}
    assert not clients(result)


def test_opencode_remote_with_oauth_disabled_is_inventoried(tmp_path):
    remote = {"type": "remote", "url": "https://mcp.example.test/mcp"}
    config = {"mcp": {"off": {**remote, "oauth": False}, "on": remote}}
    result = scan(tmp_path, {"opencode.json": json.dumps(config)})
    assert not result.scan_failures and not result.surfaces_excluded
    found = servers(result)
    assert found["off"].properties["client_settings"] == {"oauth_disabled": True}
    assert found["off"].properties["declared_fields"] == ["oauth", "url"]
    assert "client_settings" not in found["on"].properties


def test_opencode_oauth_object_is_still_an_authentication_setting(tmp_path):
    config = {"mcp": {"s": {"type": "remote", "url": "https://x.example.test/mcp", "oauth": {}}}}
    result = scan(tmp_path, {"opencode.json": json.dumps(config)})
    assert servers(result)["s"].properties["client_settings"] == {"oauth": True}


def test_continue_hub_block_reference_is_a_named_gap_not_a_failure(tmp_path):
    text = "mcpServers:\n  - uses: someone/private-slug\n  - name: b\n    command: npx\n"
    result = scan(tmp_path, {".continue/config.yaml": text})
    assert not result.scan_failures
    assert (
        ".continue/config.yaml: MCP server entry 1 references a hub block whose launch is "
        "not resolved offline; not inventoried" in result.surfaces_excluded
    )
    assert set(servers(result)) == {"b"}
    assert "private-slug" not in dump(result)


def test_continue_duplicate_name_refuses_every_entry_of_that_name(tmp_path):
    text = (
        "mcpServers:\n  - name: a\n    command: npx\n  - name: b\n    command: uvx\n"
        "  - name: a\n    command: docker\n"
    )
    result = scan(tmp_path, {".continue/config.yaml": text})
    assert result.scan_failures == [
        ".continue/config.yaml: MCP server declared more than once; not inventoried"
    ]
    assert set(servers(result)) == {"b"}


def test_a_relative_symlink_escaping_the_root_is_a_failure(tmp_path):
    outside = tmp_path / "outside" / "config.yaml"
    outside.parent.mkdir()
    outside.write_text(CONTINUE_CONFIG, encoding="utf-8")
    root = tmp_path / "root"
    (root / ".continue").mkdir(parents=True)
    os.symlink("../../outside/config.yaml", root / ".continue" / "config.yaml")
    result = MCPScanner().scan(root, config_only=True)
    assert len(result.scan_failures) == 1
    assert result.scan_failures[0].startswith(".continue/config.yaml: ")
    assert "absolute" not in result.scan_failures[0]
    assert not result.components
    assert CONTINUE_SENTINEL not in dump(result)
