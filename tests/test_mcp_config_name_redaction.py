"""A secret pasted as a configuration name never reaches an inventory or an export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.mcp import MCPScanner

# Token-shaped names are assembled at run time so the source holds no token-shaped literal.
TOKENS = {
    "github": "".join(("gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0")),
    "gitlab": "".join(("gl", "pat-", "Xy9fakeFAKEfake12345")),
    "aws": "".join(("AK", "IA", "ABCDEFGHIJKLMNOP")),
    "mixed-run": "".join(("A1b2C3d4E5f6", "G7h8I9j0K1l2M3")),
}


def _write(project: Path, server: dict[str, object]) -> None:
    project.mkdir(parents=True, exist_ok=True)
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))


def _server(tmp_path: Path, server: dict[str, object]):
    _write(tmp_path / "p", server)
    result = MCPScanner().scan(tmp_path / "p")
    return next(c for c in result.components if c.component_type.value == "mcp-server")


@pytest.mark.parametrize("token", sorted(TOKENS))
def test_a_token_shaped_field_name_is_withheld(tmp_path, token):
    name = TOKENS[token]
    record = _server(tmp_path, {"command": "node", "args": ["server.js"], name: True})
    text = record.model_dump_json()
    assert name not in text
    assert record.properties["declared_fields"] == ["[redacted]", "args", "command"]


@pytest.mark.parametrize("token", sorted(TOKENS))
def test_token_shaped_header_and_environment_names_are_withheld(tmp_path, token):
    name = TOKENS[token]
    record = _server(
        tmp_path,
        {
            "type": "http",
            "url": "https://mcp.example.com/mcp",
            "headers": {name: "1", "X-Client": "1"},
            "env": {name: "1", "LOG_LEVEL": "info"},
        },
    )
    text = record.model_dump_json()
    assert name not in text
    assert record.properties["header_names"] == ["X-Client", "[redacted]"]


def test_withheld_environment_names_stay_distinct(tmp_path):
    env = {TOKENS["github"]: "1", TOKENS["gitlab"]: "2", "NODE_ENV": "production"}
    record = _server(tmp_path, {"command": "node", "args": ["server.js"], "env": env})
    assert set(record.env) == {"NODE_ENV", "[redacted-1]", "[redacted-2]"}
    assert set(record.env.values()) == {"***"}


def test_ordinary_names_are_kept(tmp_path):
    record = _server(
        tmp_path,
        {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}", "NODE_ENV": "production"},
            "timeout": 30,
        },
    )
    assert record.properties["declared_fields"] == ["args", "command", "env", "timeout"]
    assert set(record.env) == {"GITHUB_PERSONAL_ACCESS_TOKEN", "NODE_ENV"}


def test_a_withheld_name_still_changes_the_static_configuration_digest(tmp_path):
    base = {"command": "node", "args": ["server.js"]}
    plain = _server(tmp_path / "a", base).properties["static_config_hash"]
    added = _server(tmp_path / "b", {**base, TOKENS["github"]: True}).properties[
        "static_config_hash"
    ]
    assert plain != added


# A credential pasted after a prefix is still a credential.
PREFIXED = {"AWS_" + TOKENS["aws"], "UV_" + TOKENS["aws"], "X_" + TOKENS["gitlab"]}


def test_a_token_inside_an_environment_or_header_name_is_withheld(tmp_path):
    env = {**dict.fromkeys(PREFIXED, "1"), "OPENAI_API_KEY": "${OPENAI_API_KEY}"}
    record = _server(
        tmp_path,
        {
            "command": "node",
            "args": ["server.js"],
            "env": env,
            "headers": {"X_" + TOKENS["aws"]: "1"},
        },
    )
    text = record.model_dump_json()
    assert not any(token in text for token in (TOKENS["aws"], TOKENS["gitlab"]))
    assert "OPENAI_API_KEY" in record.env


@pytest.mark.parametrize("fmt", ["json", "cyclonedx", "spdx"])
def test_no_export_carries_a_token_in_a_server_tool_or_environment_name(tmp_path, fmt):
    project = tmp_path / "p"
    project.mkdir()
    server = {
        "command": "node",
        "args": ["server.js"],
        "env": dict.fromkeys(PREFIXED, "1"),
        "tools": [{"name": TOKENS["github"], "description": "Lists issues"}],
    }
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {TOKENS["github"]: server}}))
    output = tmp_path / f"out.{fmt}.json"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "-f",
            fmt,
            "-o",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    text = output.read_text()
    assert all(token not in text for token in (TOKENS["github"], TOKENS["aws"], TOKENS["gitlab"]))


@pytest.mark.parametrize("fmt", ["json", "cyclonedx", "spdx"])
def test_no_export_carries_a_token_shaped_name(tmp_path, fmt):
    project = tmp_path / "p"
    _write(
        project,
        {
            "command": "node",
            "args": ["server.js"],
            TOKENS["github"]: True,
            "env": {TOKENS["aws"]: "1"},
            "headers": {TOKENS["gitlab"]: "1"},
        },
    )
    codex = project / ".codex"
    codex.mkdir()
    (codex / "config.toml").write_text(
        f'[mcp_servers.c]\ncommand = "node"\nargs = ["server.js"]\n"{TOKENS["mixed-run"]}" = true\n'
    )
    output = tmp_path / f"out.{fmt}.json"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "-f",
            fmt,
            "-o",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    text = output.read_text()
    assert all(token not in text for token in TOKENS.values())
