"""File-wide redaction preparation must not grow with every server in that file."""

from __future__ import annotations

import json

import pytest

from nexus_symbiote.scanners import mcp
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.utils.secrets import SecretScrubber


def _record_preparation(monkeypatch):
    prepared = []

    class RecordingScrubber(SecretScrubber):
        def __init__(self, values=()):
            values = tuple(values)
            prepared.append(values)
            super().__init__(values)

    monkeypatch.setattr(mcp, "SecretScrubber", RecordingScrubber)
    return prepared


@pytest.mark.parametrize("count", [32, 128])
@pytest.mark.parametrize("malformed", [False, True])
@pytest.mark.parametrize("credentials", [False, True])
def test_file_redaction_preparation_is_linear_in_source_values(
    tmp_path, monkeypatch, count, malformed, credentials
):
    servers = {}
    for index in range(count):
        config = {"command": "node"}
        if credentials:
            config["env"] = {
                f"TOKEN_{field}": f"KnownSourceValue{index:04d}{field:04d}Only"
                for field in range(8)
            }
        if malformed:
            config["tools"] = [{"name": "read", "inputSchema": []}]
        servers[f"s{index}"] = config
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    prepared = _record_preparation(monkeypatch)

    result = mcp.MCPScanner().scan(tmp_path, config_only=True)

    assert len(result.scan_failures) == (count if malformed else 0)
    assert sum(c.component_type.value == "mcp-server" for c in result.components) == (
        0 if malformed else count
    )
    # Count actual preparation work instead of relying on a noisy wall-clock limit.
    assert len(prepared) == 1
    assert len(prepared[0]) == (8 * count if credentials else 0)


def test_file_scrubbers_do_not_cross_source_boundaries_or_scans(tmp_path, monkeypatch):
    alpha = "KnownSourceValueAlpha"
    beta = "KnownSourceValueBeta"
    first, second = tmp_path / ".mcp.json", tmp_path / "nested" / ".mcp.json"
    second.parent.mkdir()
    for path, local, other in ((first, alpha, beta), (second, beta, alpha)):
        path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "holder": {"command": "node", "env": {"API_TOKEN": local}},
                        f"agent-{local}": {"command": "node"},
                        f"other-{other}": {"command": "node"},
                    }
                }
            )
        )
    prepared = _record_preparation(monkeypatch)
    scanner = mcp.MCPScanner()

    result = scanner.scan(tmp_path, config_only=True)

    assert not result.scan_failures
    assert len(prepared) == 2
    assert set(prepared) == {(alpha,), (beta,)}
    names = [c.name for c in result.components if c.component_type.value == "mcp-server"]
    assert names.count("agent-***") == 2
    assert f"other-{alpha}" in names and f"other-{beta}" in names

    second.unlink()
    first.write_text(json.dumps({"mcpServers": {f"ordinary-{alpha}": {"command": "node"}}}))
    again = scanner.scan(tmp_path, config_only=True)
    assert any(c.name == f"ordinary-{alpha}" for c in again.components)
    assert prepared[-1] == ()


@pytest.mark.parametrize("field", ["env", "headers", "http_headers", "inline"])
def test_standalone_parsing_still_prepares_its_own_secret_values(field):
    secret = "KnownSourceValueStandalone"  # noqa: S105 - synthetic fixture
    shadowed = "EarlierSourceValueStandalone"
    config = {"command": "node", "tools": [{"name": f"read-{secret}"}]}
    if field == "inline":
        config.update(
            command="env",
            args=[f"API_TOKEN={shadowed}", f"API_TOKEN={secret}", "node"],
        )
    else:
        config[field] = {"API_TOKEN" if field == "env" else "Authorization": secret}

    server, tools = mcp.MCPScanner()._parse_server(
        f"agent-{secret}" + (f"-{shadowed}" if field == "inline" else ""),
        config,
        mcp._dialect(".mcp.json"),
        None,
        ScanResult(scanner_name="mcp"),
    )

    exported = server.model_dump_json() + "".join(tool.model_dump_json() for tool in tools)
    assert secret not in exported and shadowed not in exported
    assert server.name == ("agent-***-***" if field == "inline" else "agent-***")
    assert tools[0].name == "read-***"
