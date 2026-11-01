"""Tests for live MCP verification — runtime rug-pull detection."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import TrustTier
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.live import verify_mcp_servers

FAKE_SERVER_SCRIPT = """
import json
import sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0", "id": msg["id"],
            "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fake", "version": "1.0"}},
        }), flush=True)
    elif msg.get("method") == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0", "id": msg["id"],
            "result": {"tools": [
                {"name": "get_weather", "description": "Get current weather",
                 "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}}},
                {"name": "delete_file", "description": "Delete a file",
                 "inputSchema": {"type": "object"}, "annotations": {"destructiveHint": True}},
            ]},
        }), flush=True)
"""


def _approved_launcher(root: Path, source: str = FAKE_SERVER_SCRIPT) -> dict[str, dict[str, str]]:
    script = root / "fake_server.py"
    script.write_text("#!" + sys.executable + "\n" + source, encoding="utf-8")
    return {
        "mcp-server:weather": {
            "command": str(script),
            "sha256": "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest(),
        }
    }


def _bom_with_server(server_name: str, tools: list[ToolComponent]) -> AIBOM:
    bom = AIBOM()
    bom.add_component(
        MCPServerComponent(
            bom_ref=f"mcp-server:{server_name}",
            name=server_name,
            transport="stdio",
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
        )
    )
    for tool in tools:
        bom.add_component(tool)
    return bom


GET_WEATHER_SCHEMA = {"type": "object", "properties": {"city": {"type": "string"}}}


def _tool(
    server_name: str,
    name: str,
    description: str,
    input_schema: dict | None = None,
    annotations: dict | None = None,
) -> ToolComponent:
    return ToolComponent(
        bom_ref=f"tool:{server_name}/{name}",
        name=name,
        mcp_server_ref=f"mcp-server:{server_name}",
        description_text=description,
        input_schema=input_schema,
        definition_hash=hash_tool_definition(name, description, input_schema, annotations),
        definition_hash_version="rfc8785-jcs-v1",
    )


def test_live_match_reports_no_drift(tmp_path: Path) -> None:
    policy = _approved_launcher(tmp_path)
    tools = [
        _tool("weather", "get_weather", "Get current weather", GET_WEATHER_SCHEMA),
        _tool(
            "weather",
            "delete_file",
            "Delete a file",
            {"type": "object"},
            {"destructiveHint": True},
        ),
    ]
    bom = _bom_with_server("weather", tools)

    report = verify_mcp_servers(bom, trusted_launchers=policy)

    assert report.servers_checked == 1
    assert report.servers_reachable == 1
    assert not report.has_drift
    assert all(f.status == "match" for f in report.results[0].tool_findings)
    assert report.results[0].live_schema_hash is not None


def test_live_changed_description_is_rug_pull(tmp_path: Path) -> None:
    """A server that rewrites its tool description post-approval is a rug-pull."""
    policy = _approved_launcher(tmp_path)
    # BOM was approved when the description was benign; the live server now
    # serves a different description for the same tool name.
    tools = [_tool("weather", "get_weather", "Get current weather (approved)")]
    bom = _bom_with_server("weather", tools)

    report = verify_mcp_servers(bom, trusted_launchers=policy)

    assert report.has_drift
    changed = [f for f in report.results[0].tool_findings if f.status == "changed"]
    assert len(changed) == 1
    assert changed[0].name == "get_weather"


def test_live_new_tool_is_drift(tmp_path: Path) -> None:
    """A tool added after approval is drift even if existing tools are unchanged."""
    policy = _approved_launcher(tmp_path)
    tools = [_tool("weather", "get_weather", "Get current weather")]
    bom = _bom_with_server("weather", tools)

    report = verify_mcp_servers(bom, trusted_launchers=policy)

    assert report.has_drift
    new = [f for f in report.results[0].tool_findings if f.status == "new"]
    assert any(f.name == "delete_file" for f in new)


def test_live_unreachable_server_reported_not_skipped(tmp_path: Path) -> None:
    bom = _bom_with_server("ghost", [])
    report = verify_mcp_servers(bom, {})

    assert report.servers_checked == 1
    assert report.servers_reachable == 0
    result = report.results[0]
    assert not result.reachable
    assert result.error is not None
    assert not report.has_drift


def test_live_report_json_roundtrip(tmp_path: Path) -> None:
    policy = _approved_launcher(tmp_path)
    tools = [_tool("weather", "get_weather", "Get current weather")]
    bom = _bom_with_server("weather", tools)

    report = verify_mcp_servers(bom, trusted_launchers=policy)
    data = json.loads(json.dumps(report.to_dict()))
    assert data["servers_checked"] == 1
    assert "has_drift" in data


def test_checkout_cannot_start_a_process_and_unreachable_fails_cli(tmp_path):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    root = tmp_path / "repo"
    root.mkdir()
    target = root / "bom.json"
    bom = _bom_with_server("weather", [])
    bom.save(target)
    marker = tmp_path / "unexpected-launch"
    config = {"command": sys.executable, "args": ["-c", f"open({str(marker)!r}, 'w').close()"]}
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"weather": config}}))
    runner = CliRunner()
    command = ["verify-live", str(target), "--project", str(root)]
    assert runner.invoke(main, command).exit_code != 0
    forged = root / "policy.json"
    forged.write_text(json.dumps(_approved_launcher(root)))
    assert runner.invoke(main, command + ["--launch-policy", str(forged)]).exit_code != 0
    policy = tmp_path / "operator.json"
    policy.write_text("{}")
    legacy = verify_mcp_servers(bom, {"weather": config})
    assert not legacy.complete and not legacy.results[0].reachable
    result = runner.invoke(main, command + ["--launch-policy", str(policy), "--json-output"])
    assert result.exit_code != 0 and not json.loads(result.stdout)["complete"]
    assert not marker.exists()


def test_candidate_requires_complete_observation_and_keeps_original(tmp_path):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    project = tmp_path / "project"
    project.mkdir()
    target = project / "bom.json"
    bom = _bom_with_server("weather", [])
    bom.save(target)
    original = target.read_bytes()
    policy = tmp_path / "approved.json"
    record = _approved_launcher(tmp_path)
    policy.write_text(json.dumps(record))
    cmd = ["verify-live", str(target), "--project", str(project), "--launch-policy", str(policy)]
    runner = CliRunner()
    assert runner.invoke(main, cmd).exit_code != 0  # newly observed tools
    result = runner.invoke(main, cmd + ["--record"])
    assert result.exit_code == 0, result.output
    candidate = AIBOM.model_validate_json(result.stdout)
    assert verify_mcp_servers(candidate, trusted_launchers=record).complete
    assert not verify_mcp_servers(candidate, trusted_launchers=record).has_drift
    assert target.read_bytes() == original
    policy.write_text("{}")
    incomplete = runner.invoke(main, cmd + ["--record"])
    assert incomplete.exit_code != 0 and not incomplete.stdout.strip()
    assert target.read_bytes() == original


def test_substitution_legacy_identity_and_environment_isolation(tmp_path, monkeypatch):
    script = (
        """import os
assert "CHECKOUT_TEST_SECRET" not in os.environ
assert not os.path.exists(".mcp.json")
"""
        + FAKE_SERVER_SCRIPT
    )
    monkeypatch.setenv("CHECKOUT_TEST_SECRET", "canary")
    (tmp_path / ".mcp.json").write_text("{}")
    monkeypatch.chdir(tmp_path)
    policy = _approved_launcher(tmp_path, script)
    bom = _bom_with_server("weather", [])
    assert verify_mcp_servers(bom, trusted_launchers=policy).complete
    assert not verify_mcp_servers(
        bom, trusted_launchers={"weather": next(iter(policy.values()))}
    ).complete
    server = tmp_path / "fake_server.py"
    server.write_text(server.read_text() + "\n# substituted\n")
    assert not verify_mcp_servers(bom, trusted_launchers=policy).complete


def test_silent_process_is_bounded_and_missing_tools_are_drift(tmp_path, monkeypatch):
    import time

    from nexus_symbiote.live import stdio

    policy = _approved_launcher(tmp_path, "import time; time.sleep(30)")
    bom = _bom_with_server("weather", [_tool("weather", "removed", "approved")])
    monkeypatch.setattr(stdio, "DEADLINE_SECONDS", 0.3)
    start = time.monotonic()
    assert not verify_mcp_servers(bom, trusted_launchers=policy).complete
    assert time.monotonic() - start < 5
    report = verify_mcp_servers(bom, trusted_launchers=_approved_launcher(tmp_path))
    assert report.has_drift and any(f.status == "missing" for f in report.results[0].tool_findings)


def test_incomplete_pages_and_duplicate_names_fail_closed(tmp_path):
    bom = _bom_with_server("weather", [])
    for original, replacement in [
        ('"tools": [', '"nextCursor": "loop", "tools": ['),
        ('"name": "get_weather"', '"outputSchema": {}, "name": "get_weather"'),
        ('"name": "delete_file"', '"name": "get_weather"'),
        ('"inputSchema": {"type": "object"}, "annotations"', '"inputSchema": [], "annotations"'),
    ]:
        policy = _approved_launcher(tmp_path, FAKE_SERVER_SCRIPT.replace(original, replacement))
        result = verify_mcp_servers(bom, trusted_launchers=policy)
        assert not result.complete and not result.results[0].tool_findings
