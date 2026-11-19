"""The Zed, opencode, Continue and Junie dialects never rate a server lower than a gap.

A server whose launch the client file does not hold, or whose launch opencode fills in
from the environment or a file, is an unknown launcher as it is in every other client
file; a file without servers is complete however it is written; and a credential in a
field of the client's own shape is scrubbed from every server of the file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPClientComponent, MCPServerComponent
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.mcp import MCPScanner, _opencode_text
from tests.support import scaling_ratio

NO_LAUNCH = "declares neither a command nor an endpoint; the client file holds no launch"
DIRECTORY_GAP = "file below an MCP server directory that the collector does not read there"
YAML_FAILURE = "YAML mapping parse failed or unsupported"
SENTINEL = "sk-live-GATESENTINEL000000000000abcd"
PINNED = json.dumps(
    {
        "mcpServers": {
            "pinned": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-everything@2025.1.1"],
            }
        }
    }
)


def write(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def scan(root: Path, files: dict[str, str]) -> ScanResult:
    return MCPScanner().scan(write(root, files), config_only=True)


def servers(result: ScanResult) -> dict[str, MCPServerComponent]:
    return {c.name: c for c in result.components if isinstance(c, MCPServerComponent)}


def clients(result: ScanResult) -> dict[str, MCPClientComponent]:
    return {c.host_application: c for c in result.components if isinstance(c, MCPClientComponent)}


def text(result: ScanResult) -> str:
    return json.dumps(
        [
            [c.model_dump(mode="json") for c in result.components],
            result.surfaces_excluded,
            result.scan_failures,
        ]
    )


def high(server: MCPServerComponent) -> set[str]:
    return {r.category for r in server.risks if r.severity.value in ("high", "critical")}


def continue_entry(entry: str) -> str:
    return f"name: block\nversion: 0.0.1\nschema: v1\nmcpServers:\n  - name: x\n{entry}"


WITHOUT_LAUNCH = [
    ("opencode.json", json.dumps({"mcp": {"x": {"enabled": True}}})),
    ("opencode.json", json.dumps({"mcp": {"x": {}}})),
    ("opencode.jsonc", json.dumps({"mcp": {"x": {"type": "local"}}})),
    ("opencode.json", json.dumps({"mcp": {"x": {"type": "remote"}}})),
    ("opencode.json", json.dumps({"mcp": {"x": {"type": "remote", "url": ""}}})),
    (".junie/mcp/mcp.json", json.dumps({"mcpServers": {"x": {}}})),
    (".continue/config.yaml", "mcpServers:\n  - name: x\n"),
    (".continue/mcpServers/x.yaml", continue_entry("    type: sse\n")),
    (".continue/agents/a.yaml", continue_entry("")),
    (".mcp.json", json.dumps({"mcpServers": {"x": {"disabled": True}}})),
    (".cursor/mcp.json", json.dumps({"mcpServers": {"x": {"type": "stdio"}}})),
    ("pkg/opencode.json", json.dumps({"mcp": {"x": {}}})),
    (".zed/settings.json", json.dumps({"context_servers": {"x": {"source": "custom"}}})),
    (".codex/config.toml", "[mcp_servers.x]\nenabled = true\n"),
    (".gemini/settings.json", json.dumps({"mcpServers": {"x": {"trust": True}}})),
    (".vscode/mcp.json", json.dumps({"servers": {"x": {"type": "stdio"}}})),
]
WITH_LAUNCH = [
    ("opencode.json", json.dumps({"mcp": {"x": {"command": ["npx", "-y", "x-mcp@1.0.0"]}}})),
    ("opencode.json", json.dumps({"mcp": {"x": {"type": "remote", "url": "https://x.test/m"}}})),
    (
        ".junie/mcp/mcp.json",
        json.dumps({"mcpServers": {"x": {"command": "uvx", "args": ["x==1"]}}}),
    ),
    (".continue/config.yaml", "mcpServers:\n  - name: x\n    command: uvx\n    args: [x==1.0]\n"),
    (".continue/mcpServers/x.yaml", continue_entry("    type: sse\n    url: https://x.test/sse\n")),
    (".mcp.json", json.dumps({"mcpServers": {"x": {"url": "https://x.test/mcp"}}})),
]


@pytest.mark.parametrize(("path", "content"), WITHOUT_LAUNCH)
def test_a_server_without_a_launch_has_an_unknown_launcher_in_every_dialect(
    tmp_path, path, content
):
    result = scan(tmp_path, {path: content})
    assert not result.scan_failures
    server = servers(result)["x"]
    assert server.command is None and server.endpoint_url is None
    assert "launcher_identity" in high(server)
    assert server.version_pinned is False
    assert f"{path}: MCP server 'x' launcher identity unknown ({NO_LAUNCH})" in (
        result.surfaces_excluded
    )


@pytest.mark.parametrize(("path", "content"), WITH_LAUNCH)
def test_a_server_with_a_command_or_an_endpoint_has_no_launch_gap(tmp_path, path, content):
    result = scan(tmp_path, {path: content})
    assert not result.scan_failures
    assert not any(NO_LAUNCH in gap for gap in result.surfaces_excluded)
    assert not any(
        r.category == "launcher_identity" and NO_LAUNCH in r.detail
        for r in servers(result)["x"].risks
    )


def test_the_zed_extension_reason_is_kept_for_a_zed_entry_without_a_launch(tmp_path):
    result = scan(tmp_path, {".zed/settings.json": '{"context_servers": {"x": {}}}'})
    (gap,) = result.surfaces_excluded
    assert "provided by a Zed extension" in gap and NO_LAUNCH not in gap


def gates(tmp_path: Path, files: dict[str, str]) -> tuple[int, int]:
    project = write(tmp_path / "project", {".mcp.json": PINNED, **files})
    out = tmp_path / "inventory.json"
    collected = CliRunner().invoke(main, ["scan", str(project), "-o", str(out)])
    assert out.exists(), collected.output
    scored = CliRunner().invoke(main, ["risk", str(out), "--fail-on-severity", "high"])
    return collected.exit_code, scored.exit_code


@pytest.mark.parametrize(
    "files",
    [
        {"opencode.json": json.dumps({"mcp": {"jira": {"enabled": True}}})},
        {"opencode.json": json.dumps({"mcp": {"x": {"command": ["{env:MCP_SERVER_BIN}"]}}})},
        {".junie/mcp/mcp.json": json.dumps({"mcpServers": {"x": {}}})},
        {".continue/mcpServers/x.yaml": "mcpServers:\n  - name: x\n"},
    ],
)
def test_both_gates_fail_on_a_server_whose_launch_is_unknown(tmp_path, files):
    assert gates(tmp_path, files) == (1, 1)


def test_both_gates_pass_a_pinned_opencode_server(tmp_path):
    config = {"mcp": {"x": {"type": "local", "command": ["npx", "-y", "oc-mcp@2.0.0"]}}}
    assert gates(tmp_path, {"opencode.json": json.dumps(config)}) == (0, 0)


LONG_SUBSTITUTIONS = [
    "{file:" + "./" * 510 + "bin/server}",
    "{env:" + "A" * 1100 + "}",
    "{env:A{B}",
]


@pytest.mark.parametrize("word", LONG_SUBSTITUTIONS)
def test_both_gates_fail_on_a_long_or_braced_opencode_substitution(tmp_path, word):
    config = {"mcp": {"x": {"type": "local", "command": [word, "--stdio"]}}}
    assert gates(tmp_path, {"opencode.json": json.dumps(config)}) == (1, 1)


@pytest.mark.parametrize(
    "word", ["{env:MCP_SERVER_BIN}", "{file:./bin/server}", "{env:SHELL}", *LONG_SUBSTITUTIONS]
)
def test_an_opencode_substitution_in_the_command_is_an_environment_dependent_launcher(
    tmp_path, word
):
    config = {"mcp": {"x": {"type": "local", "command": [word, "--stdio"]}}}
    result = scan(tmp_path / "opencode", {"opencode.json": json.dumps(config)})
    reference = {"mcpServers": {"x": {"command": "${MCP_SERVER_BIN}", "args": ["--stdio"]}}}
    cursor = scan(tmp_path / "cursor", {".cursor/mcp.json": json.dumps(reference)})
    server = servers(result)["x"]
    assert "launcher_identity" in high(server)
    assert result.surfaces_excluded == [
        "opencode.json: MCP server 'x' launcher identity unknown "
        "(command depends on the environment)"
    ]
    assert [gap.split(": ", 1)[1] for gap in result.surfaces_excluded] == [
        gap.split(": ", 1)[1] for gap in cursor.surfaces_excluded
    ]
    assert word not in text(result)


def test_an_opencode_substitution_in_a_package_version_leaves_it_unpinned(tmp_path):
    config = {"mcp": {"x": {"command": ["npx", "-y", "@acme/mcp-db@{env:MCP_VERSION}"]}}}
    result = scan(tmp_path, {"opencode.json": json.dumps(config)})
    server = servers(result)["x"]
    assert server.version_pinned is False and server.package_url is None
    assert "launcher_identity" in high(server)
    assert any("launcher identity unknown" in gap for gap in result.surfaces_excluded)


def test_an_opencode_substitution_in_an_endpoint_leaves_it_unresolved(tmp_path):
    config = {"mcp": {"x": {"type": "remote", "url": "https://mcp.example.test/{env:T}/mcp"}}}
    result = scan(tmp_path, {"opencode.json": json.dumps(config)})
    assert result.surfaces_excluded == [
        "opencode.json: MCP server 'x' endpoint depends on environment expansion"
    ]


def test_an_opencode_substitution_in_a_header_or_environment_is_a_reference(tmp_path):
    config = {
        "mcp": {
            "x": {
                "command": ["npx", "-y", "oc-mcp@2.0.0"],
                "environment": {"TOKEN": "{env:OC_TOKEN}", "KEY": "{file:~/.oc/key}"},
            },
            "y": {
                "type": "remote",
                "url": "https://mcp.example.test/mcp",
                "headers": {"Authorization": "Bearer {env:OC_TOKEN}"},
            },
        }
    }
    result = scan(tmp_path, {"opencode.json": json.dumps(config)})
    assert not result.scan_failures and not result.surfaces_excluded
    assert servers(result)["x"].env == {"KEY": "***", "TOKEN": "***"}
    assert servers(result)["x"].version_pinned is True


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("{env:A}", "${env:A}"),
        ("pre-{file:./k}-post", "pre-${file:./k}-post"),
        ("{env:A}{env:B}", "${env:A}${env:B}"),
        ("${env:A}", "${env:A}"),
        ("{env:}", "{env:}"),
        ("{envx:A}", "{envx:A}"),
        ("{team}", "{team}"),
        ("{env:A", "{env:A"),
        ("{env:A{B}", "${env:A{B}"),
        ("{env:{env:A}", "${env:{env:A}"),
        ("{env:A}-{env:B", "${env:A}-{env:B"),
        (3, 3),
    ],
)
def test_only_an_opencode_substitution_is_spelled_as_a_reference(value, expected):
    assert _opencode_text(value) == expected


def test_braces_that_are_not_an_opencode_substitution_stay_literal(tmp_path):
    config = {"mcp": {"x": {"command": ["npx", "-y", "oc-mcp@2.0.0", "--label={team}"]}}}
    result = scan(tmp_path, {"opencode.json": json.dumps(config)})
    assert not result.surfaces_excluded and not result.scan_failures
    server = servers(result)["x"]
    assert server.version_pinned is True and "launcher_identity" not in high(server)


def test_an_opencode_substitution_in_a_nested_object_is_not_rewritten(tmp_path):
    word = "{env:NOT_A_SERVER_FIELD}"
    config = {"mcp": {"x": {"command": ["npx", "-y", "oc-mcp@2.0.0"], "oauth": {"a": {"b": word}}}}}
    result = scan(tmp_path, {"opencode.json": json.dumps(config)})
    assert servers(result)["x"].properties["client_settings"] == {"oauth": True}


COMMENTED = '{\n  // theme only\n  "theme": "opencode", /* trailing comma */\n}\n'


@pytest.mark.parametrize("name", ["opencode.json", "opencode.jsonc", "pkg/opencode.json"])
def test_opencode_files_may_hold_comments_and_trailing_commas(tmp_path, name):
    result = scan(tmp_path, {name: COMMENTED})
    assert not result.scan_failures and not result.surfaces_excluded and not result.components
    assert result.surfaces_scanned == [name]


def test_a_commented_opencode_json_with_servers_is_read(tmp_path):
    content = '{\n  // servers\n  "mcp": {"x": {"command": ["npx", "-y", "oc-mcp@2.0.0"],},},\n}\n'
    result = scan(tmp_path, {"opencode.json": content})
    assert not result.scan_failures and servers(result)["x"].version_pinned is True


@pytest.mark.parametrize("content", ["{", '{"mcp": {}, "mcp": {}}', "// only a comment\n"])
def test_invalid_opencode_json_is_still_a_failure(tmp_path, content):
    result = scan(tmp_path, {"opencode.json": content})
    assert result.scan_failures == ["opencode.json: invalid JSON or duplicate keys"]


ANCHORED = "name: a\ndefaults: &d\n  provider: p\nmodels:\n  - <<: *d\n    name: m\n"


@pytest.mark.parametrize(
    "content",
    ["", "\n\n", "# nothing yet\n", "---\n", "---\n...\n", ANCHORED, "name: !custom a\n"],
)
@pytest.mark.parametrize(
    "path", [".continue/config.yaml", ".continue/mcpServers/x.yaml", ".continue/agents/a.yaml"]
)
def test_a_continue_file_that_cannot_declare_a_server_is_complete(tmp_path, path, content):
    result = scan(tmp_path, {path: content})
    assert not result.scan_failures and not result.surfaces_excluded and not result.components
    assert result.surfaces_scanned == [path]


@pytest.mark.parametrize(
    ("path", "content"),
    [
        (
            ".continue/config.yaml",
            "base: &b\n  command: npx\nmcpServers:\n  - name: x\n    <<: *b\n",
        ),
        (".continue/config.yaml", "mcpServers: !!seq []\n"),
        (".continue/config.yaml", "&a mcpServers: []\n"),
        (".continue/config.yaml", '"mcp\\u0053ervers": &l []\n'),
        (".continue/config.yaml", "~\n"),
        (".continue/config.yaml", "- a\n"),
        (".continue/mcpServers/x.yaml", "base: &b npx\ncommand: *b\n"),
        (".continue/mcpServers/x.yaml", "type: !t stdio\n"),
        (".continue/agents/a.yaml", "x: &a 1\nmcpServers:\n  - name: s\n    command: npx\n"),
    ],
)
def test_a_continue_file_that_could_declare_a_server_with_a_graph_is_a_failure(
    tmp_path, path, content
):
    result = scan(tmp_path, {path: content})
    assert result.scan_failures == [f"{path}: {YAML_FAILURE}"]
    assert not result.components


def test_the_shared_yaml_reader_still_refuses_every_anchor(tmp_path):
    result = ScanResult(scanner_name="mcp")
    parsed = MCPScanner._parse_yaml_mapping(Path("x.yaml"), ANCHORED, result)
    assert parsed is None and result.scan_failures == [f"x.yaml: {YAML_FAILURE}"]
    empty = ScanResult(scanner_name="mcp")
    assert MCPScanner._parse_yaml_mapping(Path("e.yaml"), "", empty) is None
    assert empty.scan_failures == [f"e.yaml: {YAML_FAILURE}"]


def test_the_yaml_token_bound_holds_for_a_file_without_servers(tmp_path):
    content = "models:\n" + "".join(f"  - m{i}\n" for i in range(10_001))
    result = scan(tmp_path, {".continue/config.yaml": content})
    assert result.scan_failures == [f".continue/config.yaml: {YAML_FAILURE}"]


@pytest.mark.parametrize(
    "command",
    [
        {"path": "npx", "args": ["-y", "z-mcp@1.0.0"], "env": None},
        {"path": "npx", "args": ["-y", "z-mcp@1.0.0"]},
    ],
)
def test_a_null_zed_env_is_absent(tmp_path, command):
    config = {"context_servers": {"x": {"command": command}}}
    result = scan(tmp_path, {".zed/settings.json": json.dumps(config)})
    assert not result.scan_failures and not result.surfaces_excluded
    server = servers(result)["x"]
    assert server.env == {} and server.version_pinned is True
    assert server.properties["declared_fields"] == ["args", "command"]


def test_a_null_env_beside_a_flat_zed_command_is_absent(tmp_path):
    entry = {"source": "custom", "command": "npx", "args": ["-y", "z-mcp@1.0.0"], "env": None}
    result = scan(tmp_path, {".zed/settings.json": json.dumps({"context_servers": {"x": entry}})})
    assert not result.scan_failures and servers(result)["x"].env == {}


def test_a_zed_env_map_is_still_redacted_and_a_null_args_is_still_refused(tmp_path):
    config = {
        "context_servers": {
            "x": {"command": {"path": "npx", "args": ["z-mcp@1.0.0"], "env": {"T": SENTINEL}}},
            "y": {"command": {"path": "npx", "args": None}},
        }
    }
    result = scan(tmp_path, {".zed/settings.json": json.dumps(config)})
    assert servers(result)["x"].env == {"T": "***"}
    assert result.scan_failures == [".zed/settings.json: invalid server configuration"]
    assert SENTINEL not in text(result)


AGENT = (
    "name: Local Agent\nversion: 1.0.0\nschema: v1\nmodels: []\nmcpServers:\n"
    "  - name: browser\n    command: npx\n    args: ['@playwright/mcp@1.0.0']\n"
)


@pytest.mark.parametrize(
    "path",
    [
        ".continue/agents/local.yaml",
        ".continue/assistants/local.yml",
        ".continue/configs/local.yaml",
        "pkg/.continue/agents/local.yaml",
    ],
)
def test_continue_local_agent_files_are_parsed_as_continue(tmp_path, path):
    result = scan(tmp_path, {path: AGENT})
    assert not result.scan_failures and not result.surfaces_excluded
    server = servers(result)["browser"]
    assert server.source_path == path and server.version == "1.0.0"
    assert server.command == "npx"
    assert clients(result)["continue"].properties["config_paths"] == [path]
    assert result.surfaces_scanned == [path]


def test_continue_local_agent_files_without_servers_create_no_client_or_gap(tmp_path):
    result = scan(
        tmp_path,
        {
            ".continue/agents/a.yaml": "name: a\nversion: 1.0.0\nschema: v1\nmodels: []\n",
            ".continue/agents/notes.md": "# notes\n",
            ".continue/agents/b.json": json.dumps({"mcpServers": [{"name": "x"}]}),
        },
    )
    assert not result.components and not result.scan_failures and not result.surfaces_excluded
    assert result.surfaces_scanned == [".continue/agents/a.yaml"]


def test_a_continue_agent_file_in_a_deeper_directory_is_a_gap(tmp_path):
    result = scan(tmp_path, {".continue/agents/team/local.yaml": AGENT})
    assert not result.components and not result.scan_failures
    assert result.surfaces_excluded == [f".continue/agents/team/local.yaml: {DIRECTORY_GAP}"]


def test_another_spelling_of_a_continue_agent_directory_is_a_case_variant_failure(tmp_path):
    result = scan(tmp_path, {".continue/Agents/local.yaml": AGENT})
    assert not servers(result)
    assert len(result.scan_failures) == 1
    assert result.scan_failures[0].startswith(".continue/Agents/local.yaml: case variant")


def test_a_linked_continue_agent_directory_is_read_through_the_link(tmp_path):
    root = write(tmp_path / "root", {"shared/agents/local.yaml": AGENT})
    (root / ".continue").mkdir()
    os.symlink("../shared/agents", root / ".continue" / "agents")
    result = MCPScanner().scan(root, config_only=True)
    assert not result.scan_failures
    assert servers(result)["browser"].source_path == ".continue/agents/local.yaml"


REFUSED_ENVIRONMENT = json.dumps(
    {
        "mcp": {
            "bad": {
                "command": ["npx", "x@1.0.0"],
                "environment": {"TOKEN": SENTINEL},
                "env": {"A": "b"},
            },
            f"good-{SENTINEL}": {"command": ["npx", "y@1.0.0"]},
        }
    }
)


@pytest.mark.parametrize(
    ("path", "content"),
    [
        ("opencode.json", REFUSED_ENVIRONMENT),
        (
            ".continue/config.yaml",
            "mcpServers:\n  - name: bad\n    type: sse\n    url: https://a.test/sse\n"
            f"    apiKey: {SENTINEL}\n  - name: good-{SENTINEL}\n    command: npx\n",
        ),
        (
            ".continue/config.yaml",
            "mcpServers:\n  - name: bad\n    type: sse\n    url: https://a.test/sse\n"
            "    requestOptions:\n      headers:\n"
            f"        Authorization: Bearer {SENTINEL}\n"
            f"  - name: good-{SENTINEL}\n    command: npx\n",
        ),
    ],
)
def test_a_credential_in_a_shape_field_is_scrubbed_from_every_server(tmp_path, path, content):
    result = scan(tmp_path, {path: content})
    assert "good-***" in servers(result)
    assert SENTINEL not in text(result)


def test_a_value_in_a_shape_field_that_is_not_a_credential_is_kept(tmp_path):
    content = (
        "mcpServers:\n  - name: bad\n    type: sse\n    url: https://a.test/sse\n"
        "    requestOptions:\n      headers:\n        X-Team: blue\n"
        "  - name: blue\n    command: npx\n"
    )
    result = scan(tmp_path, {".continue/config.yaml": content})
    assert "blue" in servers(result)


def test_the_root_junie_file_names_its_package_without_the_nested_launch_finding(tmp_path):
    config = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "fs-mcp@1.0.0"]}}}
    result = scan(tmp_path, {".junie/mcp/mcp.json": json.dumps(config)})
    server = servers(result)["fs"]
    assert server.package_url == "pkg:npm/fs-mcp@1.0.0"
    assert not any(r.category == "package_source" for r in server.risks)
    assert clients(result)["junie"].config_path == ".junie/mcp/mcp.json"


def test_a_zed_entry_that_spells_the_internal_settings_name_is_refused(tmp_path):
    config = {"context_servers": {"x": {"command": "npx", "settings (zed extension)": {}}}}
    result = scan(tmp_path, {".zed/settings.json": json.dumps(config)})
    assert result.scan_failures == [".zed/settings.json: invalid server configuration"]
    assert not servers(result)


def test_an_opencode_substitution_in_a_header_is_a_reference_not_a_credential(tmp_path):
    config = {
        "mcp": {
            "x": {
                "type": "remote",
                "url": "https://mcp.example.test/mcp",
                "headers": {"X-Api-Key": "{env:OC_KEY}"},
            },
            "named-{env:OC_KEY}": {"command": ["npx", "-y", "oc-mcp@2.0.0"]},
        }
    }
    result = scan(tmp_path, {"opencode.json": json.dumps(config)})
    assert "named-{env:OC_KEY}" in servers(result)


def test_a_continue_entry_with_a_name_beside_uses_is_inventoried_with_a_field_gap(tmp_path):
    content = "mcpServers:\n  - name: a\n    uses: someone/block\n"
    result = scan(tmp_path, {".continue/config.yaml": content})
    assert set(servers(result)) == {"a"}
    gap = ".continue/config.yaml: MCP server 'a' declares 1 field the collector does not interpret"
    assert gap in result.surfaces_excluded
    assert not any("hub block" in gap for gap in result.surfaces_excluded)


@pytest.mark.parametrize("field", ["type", "command", "url"])
def test_a_server_field_at_the_top_of_a_continue_config_is_not_a_shape_gap(tmp_path, field):
    result = scan(tmp_path, {".continue/config.yaml": f"name: x\n{field}: y\n"})
    assert not result.surfaces_excluded and not result.scan_failures


def test_a_deeper_file_below_a_linked_continue_server_directory_is_a_gap(tmp_path):
    block = "mcpServers:\n  - name: s\n    command: npx\n    args: [s-mcp@1.0.0]\n"
    root = write(tmp_path / "root", {"shared/servers/deeper/x.yaml": block})
    (root / ".continue").mkdir()
    os.symlink("../shared/servers", root / ".continue" / "mcpServers")
    result = MCPScanner().scan(root, config_only=True)
    assert not servers(result) and not result.scan_failures
    assert result.surfaces_excluded == [f".continue/mcpServers/deeper/x.yaml: {DIRECTORY_GAP}"]


def test_a_scheme_credential_in_continue_request_options_is_scrubbed_bare(tmp_path):
    word = "opensesameopensesame"
    content = (
        "mcpServers:\n  - name: bad\n    type: sse\n    url: https://a.test/sse\n"
        f"    requestOptions:\n      headers:\n        Authorization: Bearer {word}\n"
        f"  - name: good-{word}\n    command: npx\n"
    )
    result = scan(tmp_path, {".continue/config.yaml": content})
    assert "good-***" in servers(result)
    assert word not in text(result)


def test_shape_settings_in_another_clients_file_set_no_client_setting_or_unbound_value(
    tmp_path,
):
    entry = {
        "command": "npx",
        "args": ["-y", "a-mcp@1.0.0"],
        "oauth (disabled)": True,
        "settings (zed extension)": {"k": "v"},
    }
    result = scan(tmp_path, {".mcp.json": json.dumps({"mcpServers": {"x": entry}})})
    server = servers(result)["x"]
    assert "client_settings" not in server.properties
    assert not any(r.category == "completeness" for r in server.risks)


DROPPED_VALUE = "horsebattery013staplecorrectqz"
REPEATS_DROPPED = (
    f"  - name: {DROPPED_VALUE}\n    command: npx\n    args: [-y, a-mcp@1.0.0]\n"
    f"  - name: remote\n    url: https://{DROPPED_VALUE}.example.test/mcp\n"
)


@pytest.mark.parametrize(
    "dropped",
    [
        f"  - uses: acme/mcp\n    with:\n      API_KEY: {DROPPED_VALUE}\n",
        f"  - command: npx\n    env:\n      API_KEY: {DROPPED_VALUE}\n",
        f"  - name: twice\n    command: npx\n    env:\n      API_KEY: {DROPPED_VALUE}\n"
        "  - name: twice\n    command: npx\n",
        "  - name: twice\n    command: npx\n"
        f"  - name: twice\n    command: npx\n    env:\n      API_KEY: {DROPPED_VALUE}\n",
        f"  - name: x\n    apiKey: {DROPPED_VALUE}\n    with:\n      TOKEN: {DROPPED_VALUE}\n",
    ],
)
def test_a_credential_of_a_continue_entry_that_is_not_inventoried_is_scrubbed(tmp_path, dropped):
    result = scan(tmp_path, {".continue/config.yaml": f"mcpServers:\n{dropped}{REPEATS_DROPPED}"})
    assert {"***", "remote"} <= servers(result).keys()
    assert DROPPED_VALUE not in text(result)


@pytest.mark.parametrize("output", ["json", "cyclonedx", "spdx", "sarif"])
def test_a_dropped_continue_entry_scrubs_its_value_from_every_export(tmp_path, output):
    project = write(
        tmp_path / "project",
        {
            ".continue/config.yaml": "mcpServers:\n"
            f"  - uses: acme/mcp\n    with:\n      API_KEY: {DROPPED_VALUE}\n{REPEATS_DROPPED}"
        },
    )
    out = tmp_path / "inventory.json"
    exported = tmp_path / "export"
    CliRunner().invoke(main, ["scan", str(project), "-o", str(out)])
    CliRunner().invoke(main, ["scan", str(project), "-o", str(exported), "-f", output])
    scored = CliRunner().invoke(main, ["risk", str(out)])
    assert "***" in scored.output
    for content in (out.read_text("utf-8"), exported.read_text("utf-8"), scored.output):
        assert DROPPED_VALUE not in content


def test_a_null_env_is_refused_in_mcp_json_and_absent_in_zed_by_design(tmp_path):
    server = {"command": "npx", "args": ["-y", "server-x@1.0.0"], "env": None}
    mcp_json = json.dumps({"mcpServers": {"x": server}})
    refused = scan(tmp_path / "map", {".mcp.json": mcp_json})
    assert refused.scan_failures == [".mcp.json: invalid server configuration"]
    assert gates(tmp_path / "map", {".mcp.json": mcp_json}) == (1, 1)
    zed = json.dumps({"context_servers": {"x": server}})
    read = scan(tmp_path / "zed", {".zed/settings.json": zed})
    assert not read.scan_failures and not read.surfaces_excluded
    assert servers(read)["x"].launcher_package == "npm:server-x"
    assert servers(read)["x"].version_pinned is True
    assert gates(tmp_path / "zed", {".zed/settings.json": zed}) == (0, 0)


def test_an_opencode_remote_server_with_a_command_is_a_transport_ambiguity(tmp_path):
    config = {"mcp": {"x": {"type": "remote", "command": ["npx", "-y", "evil"]}}}
    server = servers(scan(tmp_path, {"opencode.json": json.dumps(config)}))["x"]
    assert server.transport == "streamable-http"
    assert "transport_ambiguity" in {r.category for r in server.risks}


def test_an_opencode_remote_server_with_an_endpoint_keeps_the_endpoint_transport(tmp_path):
    config = {"mcp": {"x": {"type": "remote", "url": "https://x.test/sse"}}}
    server = servers(scan(tmp_path, {"opencode.json": json.dumps(config)}))["x"]
    assert server.transport == "sse"
    assert "transport_ambiguity" not in {r.category for r in server.risks}


@pytest.mark.parametrize("entry", [{"source": "custom"}, {"source": "custom", "command": ""}])
def test_a_custom_zed_entry_without_a_launch_is_not_called_an_extension(tmp_path, entry):
    result = scan(tmp_path, {".zed/settings.json": json.dumps({"context_servers": {"x": entry}})})
    (gap,) = result.surfaces_excluded
    assert NO_LAUNCH in gap and "Zed extension" not in gap


CONTINUERC_GAP = (
    "Continue workspace MCP servers (experimental.modelContextProtocolServers) not inventoried"
)


@pytest.mark.parametrize("name", [".continuerc.json", "pkg/.continuerc.json"])
def test_continue_workspace_mcp_servers_in_continuerc_are_a_gap(tmp_path, name):
    content = (
        '{\n  // workspace overrides\n  "experimental": {"modelContextProtocolServers": '
        '[{"transport": {"type": "stdio", "command": "bash"}}]},\n}\n'
    )
    result = scan(tmp_path, {name: content})
    assert not result.scan_failures and not servers(result) and not clients(result)
    assert result.surfaces_excluded == [f"{name}: {CONTINUERC_GAP}"]


@pytest.mark.parametrize(
    "content",
    ['{"models": []}', '{"experimental": {"modelContextProtocolServers": []}}', "{}"],
)
def test_a_continuerc_without_mcp_servers_is_complete(tmp_path, content):
    result = scan(tmp_path, {".continuerc.json": content})
    assert not result.scan_failures and not result.surfaces_excluded and not clients(result)


@pytest.mark.parametrize(
    "unit",
    ["{env:", "{env:{env:A}", "{env:A}{env:", "{env:A{B}{env:", "${env:{file:"],
)
@pytest.mark.parametrize("closed", [False, True])
def test_an_unclosed_opencode_substitution_run_is_read_in_linear_time(tmp_path, unit, closed):
    def run(scale: int) -> None:
        project = tmp_path / f"run{scale}"
        project.mkdir(exist_ok=True)
        word = unit * (20_000 * scale // len(unit)) + ("}" if closed else "")
        (project / "opencode.json").write_text(
            json.dumps({"mcp": {"x": {"type": "local", "command": [word]}}})
        )
        MCPScanner().scan(project)

    assert scaling_ratio(run) < 10
