"""Gemini CLI starts a server named ``mcp`` from ``mcpServerCommand`` (``mcp.serverCommand``
in its current settings layout), which must be inventoried like a server in
``mcpServers`` (Audit 2026-11-16, S2-02).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.mcp import MCPScanner

COMMAND = "npx -y unpinned-mcp-server --port 3000"
FORMS = {
    "mcpServerCommand": {"mcpServerCommand": COMMAND},
    "mcp.serverCommand": {"mcp": {"serverCommand": COMMAND}},
}


def _servers(result: ScanResult) -> list[MCPServerComponent]:
    return [c for c in result.components if isinstance(c, MCPServerComponent)]


def _write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.mark.parametrize("base", ["", "pkg/"])
@pytest.mark.parametrize("form", sorted(FORMS))
def test_server_command_is_inventoried_as_server_mcp(tmp_path: Path, form: str, base: str) -> None:
    _write(tmp_path / f"{base}.gemini" / "settings.json", FORMS[form])
    result = MCPScanner().scan(tmp_path, config_only=True)
    [server] = _servers(result)
    assert server.name == "mcp"
    assert server.source_path == f"{base}.gemini/settings.json"
    assert server.command == "npx"
    assert server.properties["packages"][0]["identity"] == "npm:unpinned-mcp-server"
    assert len(server.args) == 4
    assert any(
        r.category == "version_pinning" and r.severity == RiskSeverity.HIGH for r in server.risks
    )
    assert any(c.bom_ref == "mcp-client:gemini-cli" for c in result.components)
    assert not result.scan_failures


def test_server_command_replaces_a_server_map_entry_named_mcp(tmp_path: Path) -> None:
    _write(
        tmp_path / ".gemini" / "settings.json",
        {
            "mcpServers": {
                "mcp": {"command": "node", "args": ["local.js"]},
                "other": {"command": "node", "args": ["other.js"]},
            },
            "mcpServerCommand": COMMAND,
        },
    )
    servers = {s.name: s for s in _servers(MCPScanner().scan(tmp_path, config_only=True))}
    assert sorted(servers) == ["mcp", "other"]
    assert servers["mcp"].command == "npx"


@pytest.mark.parametrize(
    "value",
    [
        "npx -y $PKG",
        "npx -y 'quoted pkg'",
        'npx -y "pkg"',
        "npx -y pkg && curl x",
        "npx -y pkg | sh",
        "npx -y pkg; rm x",
        "npx -y pkg*",
        "npx -y pkg\nnext",
        "npx -y pkg\\ x",
        "npx -y `id`",
        "   ",
    ],
)
def test_shell_syntax_in_server_command_is_a_failure(tmp_path: Path, value: str) -> None:
    _write(tmp_path / ".gemini" / "settings.json", {"mcpServerCommand": value})
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert _servers(result) == []
    assert result.scan_failures == [
        ".gemini/settings.json: MCP server command 'mcp' is not plain words and is not inventoried"
    ]


@pytest.mark.parametrize("value", [42, ["npx", "x"], {"a": 1}, True])
def test_non_string_server_command_is_a_failure(tmp_path: Path, value: object) -> None:
    _write(tmp_path / ".gemini" / "settings.json", {"mcp": {"serverCommand": value}})
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert _servers(result) == []
    assert result.scan_failures == [".gemini/settings.json: invalid MCP server command"]


def test_both_server_command_settings_are_a_failure(tmp_path: Path) -> None:
    _write(
        tmp_path / ".gemini" / "settings.json",
        {"mcpServerCommand": COMMAND, "mcp": {"serverCommand": "node server.js"}},
    )
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert _servers(result) == []
    assert result.scan_failures == [
        ".gemini/settings.json: MCP server command declared under more than one setting"
    ]


def test_empty_server_command_and_other_mcp_settings_add_nothing(tmp_path: Path) -> None:
    _write(
        tmp_path / ".gemini" / "settings.json",
        {"mcpServerCommand": "", "mcp": {"allowed": ["x"]}},
    )
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert _servers(result) == []
    assert not result.scan_failures


def test_other_dialects_do_not_read_server_command(tmp_path: Path) -> None:
    _write(tmp_path / ".mcp.json", {"mcpServerCommand": COMMAND})
    assert _servers(MCPScanner().scan(tmp_path, config_only=True)) == []


def test_unpinned_server_command_fails_the_risk_gate(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "pkg" / ".gemini" / "settings.json", FORMS["mcp.serverCommand"])
    _write(project / ".mcp.json", {"mcpServers": {"files": {"command": "node", "args": ["s.js"]}}})
    (project / "CLAUDE.md").write_text("# Project\n", encoding="utf-8")
    output = str(tmp_path / "bom.json")
    runner = CliRunner()
    run = runner.invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", output]
    )
    assert run.exit_code == 0, run.output
    risk = runner.invoke(
        main,
        [
            "risk",
            output,
            "--no-project-policy",
            "--project",
            str(project),
            "--fail-on-severity",
            "high",
        ],
    )
    assert risk.exit_code == 1, risk.output
    assert "version_pinning" in risk.output
