from __future__ import annotations

import json

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners import live_mcp


def test_live_discovery_requires_explicit_origin_and_refuses_private_targets():
    runner = CliRunner()
    missing = runner.invoke(main, ["--live", "discover-mcp", "https://127.0.0.1/mcp"])
    assert missing.exit_code == 2 and "Missing option '--allowed-origin'" in missing.output
    private = runner.invoke(
        main,
        [
            "--live",
            "discover-mcp",
            "https://127.0.0.1/mcp",
            "--allowed-origin",
            "https://127.0.0.1",
        ],
    )
    assert private.exit_code == 1
    payload = json.loads(private.stdout)
    assert payload["complete"] is False
    assert payload["failures"] == ["nonpublic destination refused"]


def test_static_scan_never_calls_live_discovery(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("static scan attempted network discovery")

    monkeypatch.setattr(live_mcp, "discover_tools", forbidden)
    monkeypatch.setattr(live_mcp.PinnedHTTPTransport, "request", forbidden)
    monkeypatch.setattr(live_mcp, "_resolve_public", forbidden)
    monkeypatch.setattr("nexus_symbiote.live_cli.discover_tools", forbidden)
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--report-only"])
    assert result.exit_code == 0
