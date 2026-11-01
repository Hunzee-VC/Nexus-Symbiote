"""Tests for live MCP verification — runtime rug-pull detection."""

from __future__ import annotations

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


def _write_fake_server(tmp_path: Path) -> tuple[str, list[str]]:
    script = tmp_path / "fake_server.py"
    script.write_text(FAKE_SERVER_SCRIPT, encoding="utf-8")
    return sys.executable, [str(script)]


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
    command, args = _write_fake_server(tmp_path)
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

    report = verify_mcp_servers(bom, {"weather": {"command": command, "args": args}})

    assert report.servers_checked == 1
    assert report.servers_reachable == 1
    assert not report.has_drift
    assert all(f.status == "match" for f in report.results[0].tool_findings)
    assert report.results[0].live_schema_hash is not None


def test_live_changed_description_is_rug_pull(tmp_path: Path) -> None:
    """A server that rewrites its tool description post-approval is a rug-pull."""
    command, args = _write_fake_server(tmp_path)
    # BOM was approved when the description was benign; the live server now
    # serves a different description for the same tool name.
    tools = [_tool("weather", "get_weather", "Get current weather (approved)")]
    bom = _bom_with_server("weather", tools)

    report = verify_mcp_servers(bom, {"weather": {"command": command, "args": args}})

    assert report.has_drift
    changed = [f for f in report.results[0].tool_findings if f.status == "changed"]
    assert len(changed) == 1
    assert changed[0].name == "get_weather"


def test_live_new_tool_is_drift(tmp_path: Path) -> None:
    """A tool added after approval is drift even if existing tools are unchanged."""
    command, args = _write_fake_server(tmp_path)
    tools = [_tool("weather", "get_weather", "Get current weather")]
    bom = _bom_with_server("weather", tools)

    report = verify_mcp_servers(bom, {"weather": {"command": command, "args": args}})

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
    command, args = _write_fake_server(tmp_path)
    tools = [_tool("weather", "get_weather", "Get current weather")]
    bom = _bom_with_server("weather", tools)

    report = verify_mcp_servers(bom, {"weather": {"command": command, "args": args}})
    data = json.loads(json.dumps(report.to_dict()))
    assert data["servers_checked"] == 1
    assert "has_drift" in data
