"""Malformed tool diagnostics retain coverage gaps without publishing credentials."""

from __future__ import annotations

import json

import pytest

from nexus_symbiote.cli import main
from nexus_symbiote.scanners import mcp
from nexus_symbiote.scanners.mcp import MCPScanner

TOKEN = "ghp_" + "A" * 36
SECRET = "KnownOnlyFromSource42"  # noqa: S105 - synthetic fixture
SHADOWED = "ShadowedKnownSource42"  # noqa: S105 - synthetic fixture


def _failure(tmp_path, name, config, other=None):
    servers = {} if other is None else {"other": other}
    servers[name] = {
        "command": "node",
        **config,
        "tools": [{"name": "read", "inputSchema": []}],
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(tmp_path, config_only=True)
    (failure,) = result.scan_failures
    assert "invalid tool definition for server '" in failure
    assert failure.endswith("'; the server and its risks are not inventoried")
    return failure


def test_token_shaped_server_names_are_redacted_from_failure_details(tmp_path):
    failure = _failure(tmp_path, f"agent-{TOKEN}", {})
    assert TOKEN not in failure
    assert "server 'agent-***'" in failure


def test_generic_api_token_name_uses_free_text_redaction(tmp_path):
    token = "sk-" + "A1" * 24
    failure = _failure(tmp_path, token, {})
    assert token not in failure
    assert "server '***'" in failure


@pytest.mark.parametrize("field", ["env", "headers", "http_headers"])
def test_known_source_secret_values_are_redacted_from_failure_names(tmp_path, field):
    key = "API_TOKEN" if field == "env" else "Authorization"
    failure = _failure(tmp_path, f"agent-{SECRET}", {field: {key: SECRET}})
    assert SECRET not in failure
    assert "server 'agent-***'" in failure


@pytest.mark.parametrize("field", ["env", "headers", "http_headers"])
def test_another_servers_known_file_secret_is_redacted_from_failure_names(tmp_path, field):
    key = "API_TOKEN" if field == "env" else "Authorization"
    other = {"command": "node", field: {key: SECRET}}
    failure = _failure(tmp_path, f"agent-{SECRET}", {}, other)
    assert SECRET not in failure
    assert "server 'agent-***'" in failure


def test_inline_launch_environment_secret_is_redacted_from_failure_names(tmp_path):
    failure = _failure(
        tmp_path,
        f"agent-{SECRET}",
        {"command": "env", "args": [f"API_TOKEN={SECRET}", "node", "server.js"]},
    )
    assert SECRET not in failure
    assert "server 'agent-***'" in failure


def test_another_servers_inline_environment_secret_is_redacted_from_failure_names(tmp_path):
    other = {"command": "env", "args": [f"API_TOKEN={SECRET}", "node", "server.js"]}
    failure = _failure(tmp_path, f"agent-{SECRET}", {}, other)
    assert SECRET not in failure
    assert "server 'agent-***'" in failure


def test_shadowed_inline_secret_is_redacted_from_a_sibling_failure(tmp_path):
    other = {
        "command": "env",
        "args": [f"API_TOKEN={SHADOWED}", f"API_TOKEN={SECRET}", "node", "server.js"],
    }
    failure = _failure(tmp_path, f"agent-{SHADOWED}-{SECRET}", {}, other)
    assert SHADOWED not in failure and SECRET not in failure
    assert "server 'agent-***-***'" in failure


def test_diagnostic_scrubs_all_own_inline_values_without_file_context():
    config = {"command": "env", "args": [f"API_TOKEN={SHADOWED}", f"API_TOKEN={SECRET}", "node"]}
    assert MCPScanner._diagnostic_server_name(f"agent-{SHADOWED}-{SECRET}", config, []) == (
        "agent-***-***"
    )


def test_shadowed_ordinary_inline_values_are_not_treated_as_credentials(tmp_path):
    config = {"command": "env", "args": ["MODE=development", "MODE=production", "node"]}
    assert "server 'development-production'" in _failure(tmp_path, "development-production", config)


@pytest.mark.parametrize("output_format", ["json", "cyclonedx", "spdx", "sarif"])
@pytest.mark.parametrize(
    "source", ["generic-token", "vendor-token", "inline-environment", "shadowed-inline-environment"]
)
def test_malformed_names_reach_no_cli_export(tmp_path, runner, output_format, source):
    project = tmp_path / "project"
    project.mkdir()
    secret = {"generic-token": "sk-" + "A1" * 24, "vendor-token": "gsk_" + "B2" * 24}.get(
        source, SECRET
    )
    servers = {secret: {"command": "node", "tools": [{"name": "read", "inputSchema": []}]}}
    if source.endswith("inline-environment"):
        servers["other"] = {"command": "env", "args": [f"API_TOKEN={secret}", "node", "server.js"]}
    if source == "shadowed-inline-environment":
        servers["other"]["args"].insert(0, f"API_TOKEN={SHADOWED}")
        servers[SHADOWED] = servers.pop(secret)
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    output = tmp_path / "inventory.json"
    result = runner.invoke(
        main,
        ["scan", str(project), "--no-project-policy", "-f", output_format, "-o", str(output)],
    )
    assert result.exit_code == 1, result.output
    assert "invalid tool definition" in result.output
    assert secret not in result.output + output.read_text()
    assert SHADOWED not in result.output + output.read_text()


def test_secret_recognition_precedes_name_clipping(tmp_path):
    prefix = "a" * 239 + "_"
    failure = _failure(tmp_path, prefix + TOKEN, {})
    assert "ghp_" not in failure
    assert "server '" + prefix + "***'" in failure


def test_ordinary_server_name_diagnostic_is_preserved(tmp_path):
    assert _failure(tmp_path, "weather", {}) == (
        ".mcp.json: invalid tool definition for server 'weather'; "
        "the server and its risks are not inventoried"
    )


def test_failure_names_are_terminal_neutralized_after_redaction(tmp_path):
    failure = _failure(tmp_path, f"weather-{TOKEN}\n\x1b[31m##vso[task]", {})
    assert TOKEN not in failure
    assert "\n" not in failure and "\x1b" not in failure and "##vso[" not in failure
    assert "weather-***" in failure


def test_failing_launcher_analysis_withholds_the_name_without_losing_the_gap(tmp_path, monkeypatch):
    def broken(*args, **kwargs):
        raise ValueError("unusable launch")

    monkeypatch.setattr(mcp, "analyze", broken)
    assert "server '[withheld]'" in _failure(tmp_path, f"agent-{SECRET}", {})
