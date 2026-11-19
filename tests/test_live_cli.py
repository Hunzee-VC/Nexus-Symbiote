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


def test_report_shows_origin_and_path_digest_never_the_endpoint_path(monkeypatch, tmp_path):
    from nexus_symbiote.core.hashing import hash_canonical
    from tests.test_live_inventory import REAL_DISCOVER, server
    from tests.test_live_mcp import ORIGIN, FixtureTransport

    sentinel = "path-credential-sentinel-0123456789"
    endpoint = f"{ORIGIN}/api/mcp/s/{sentinel}/mcp"

    def fixture(url: str, **kwargs):
        return REAL_DISCOVER(url, transport=FixtureTransport(server()), **kwargs)

    monkeypatch.setattr("nexus_symbiote.live_cli.discover_tools", fixture)
    report, review = tmp_path / "observed.json", tmp_path / "review.json"
    args = ["--live", "discover-mcp", endpoint, "--allowed-origin", ORIGIN]
    written = CliRunner().invoke(main, [*args, "-o", str(report), "--raw-descriptors", str(review)])
    assert written.exit_code == 0, written.output
    assert sentinel not in written.output and sentinel not in report.read_text()
    observed = json.loads(report.read_text())
    assert observed["endpoint"] == ORIGIN
    assert observed["observed_endpoint_hash"] == hash_canonical({"observed_endpoint": endpoint})
    assert json.loads(review.read_text())["endpoint"] == endpoint
    printed = CliRunner().invoke(main, args)
    assert printed.exit_code == 0, printed.output
    assert sentinel not in printed.output
    assert json.loads(printed.stdout)["endpoint"] == ORIGIN
