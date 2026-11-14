"""A declared endpoint counts for trace evidence only when every URL parser reads it alike.

`trace_evidence` took a declared server's host and port from `urlsplit` alone. For
`https://approved.internal\\@attacker.example/mcp` that is `attacker.example`, while a
WHATWG parser connects to `approved.internal`, so an inventory could declare a host it
never names and spans to that host stopped being undeclared. A URL that states no port
and has no default one still declares its host only, and its matches say so.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.risk_classes import plain_authority
from nexus_symbiote.trace_evidence import collect
from tests.support import otlp_export, otlp_span

CLIENT = 3


def _call(address: str, port: int) -> dict[str, Any]:
    attributes = {
        "mcp.method.name": "tools/call",
        "gen_ai.tool.name": "lookup",
        "network.transport": "tcp",
        "server.address": address,
        "server.port": port,
    }
    return otlp_span(attributes, kind=CLIENT)


def _undeclared_endpoints(tmp_path: Path, url: str, address: str, port: int) -> list[dict]:
    server = MCPServerComponent(bom_ref="mcp:approved", name="approved", endpoint_url=url)
    inventory = tmp_path / "bom.json"
    inventory.write_text(AIBOM(components=[server]).to_native_json(), encoding="utf-8")
    trace = tmp_path / "trace.json"
    trace.write_text(json.dumps(otlp_export(_call(address, port))), encoding="utf-8")
    evidence = collect(inventory, [trace])
    return [entry for entry in evidence["reconciliation"]["undeclared"] if entry["kind"] != "tool"]


@pytest.mark.parametrize(
    ("url", "address", "port"),
    [
        ("https://approved.internal\\@attacker.example/mcp", "attacker.example", 443),
        ("https://approved.internal@attacker.example/mcp", "attacker.example", 443),
        ("https://attacker%2eexample/mcp", "attacker.example", 443),
        ("https://attacker.example:0/mcp", "attacker.example", 443),
        ("tcp://approved.internal\\@attacker.example", "attacker.example", 7000),
    ],
    ids=["backslash", "userinfo", "escaped-host", "port-zero", "portless-backslash"],
)
def test_an_endpoint_parsers_read_differently_declares_no_host(tmp_path, url, address, port):
    undeclared = _undeclared_endpoints(tmp_path, url, address, port)
    assert [entry["kind"] for entry in undeclared] == ["mcp-endpoint"]


@pytest.mark.parametrize(
    ("url", "address", "port"),
    [
        ("https://mcp.example/sse", "mcp.example", 443),
        ("http://mcp.example/sse", "mcp.example", 80),
        ("wss://MCP.example:8443/ws", "mcp.example", 8443),
        ("https://[2001:db8::1]:8443/mcp", "2001:db8::1", 8443),
    ],
    ids=["https", "http", "wss-port-and-case", "ipv6"],
)
def test_a_plain_endpoint_still_declares_its_host_and_port(tmp_path, url, address, port):
    assert _undeclared_endpoints(tmp_path, url, address, port) == []


def test_a_declared_port_does_not_cover_another_port_of_the_host(tmp_path):
    undeclared = _undeclared_endpoints(tmp_path, "https://mcp.example/sse", "mcp.example", 8443)
    assert [entry["kind"] for entry in undeclared] == ["mcp-endpoint"]


def test_a_url_without_a_port_or_a_default_one_still_declares_its_host_only(tmp_path):
    assert _undeclared_endpoints(tmp_path, "tcp://mcp.example", "mcp.example", 7000) == []
    undeclared = _undeclared_endpoints(tmp_path, "tcp://mcp.example", "other.example", 7000)
    assert [entry["kind"] for entry in undeclared] == ["mcp-endpoint"]


@pytest.mark.parametrize(
    ("netloc", "plain"),
    [
        ("example.com", True),
        ("example.com:8443", True),
        ("[2001:db8::1]:8443", True),
        ("a\\@b.example", False),
        ("user:pw@b.example", False),
        ("b%2eexample", False),
        ("b.example:", False),
        ("b.example:123456", False),
        ("", False),
    ],
)
def test_an_authority_is_plain_only_as_a_host_and_an_optional_port(netloc, plain):
    assert plain_authority(netloc) is plain
