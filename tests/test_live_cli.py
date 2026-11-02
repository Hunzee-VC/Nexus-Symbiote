from __future__ import annotations

import json

from click.testing import CliRunner

from nexus_symbiote.cli import main


def test_live_discovery_requires_explicit_origin_and_refuses_private_targets():
    runner = CliRunner()
    missing = runner.invoke(main, ["--live", "discover-mcp", "https://127.0.0.1/mcp"])
    assert missing.exit_code == 1 and "--allowed-origin" in missing.output
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
    assert private.exit_code == 3
    assert json.loads(private.stdout)["complete"] is False


def test_static_scan_never_calls_live_discovery(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("static scan attempted network discovery")

    monkeypatch.setattr("nexus_symbiote.live_cli.discover_tools", forbidden)
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--report-only"])
    assert result.exit_code == 0
