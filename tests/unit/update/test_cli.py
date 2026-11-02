"""``symbiote update`` exit codes and outputs, with the advisors monkeypatched (no network)."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from symbiote.advisories import engine, inventory
from symbiote.advisories.types import (
    Advisory,
    DependencyIntel,
    DependencyKind,
    DependencyRef,
    ReleaseInfo,
    Signal,
    SignalKind,
)
from symbiote.cli.update_cmd import register

NOW = datetime(2026, 11, 1, tzinfo=UTC)
CONFIG = '{\n  "mcpServers": {\n    "s": {"command": "npx", "args": ["-y", "server-pkg@1.2.0"]}\n  }\n}\n'
REF = DependencyRef(
    kind=DependencyKind.MCP_SERVER_PACKAGE,
    ecosystem="npm",
    name="server-pkg",
    version="1.2.0",
    locators=(".mcp.json#/mcpServers/s/args/1",),
)


def _app() -> typer.Typer:
    app = typer.Typer()

    @app.callback()
    def _root() -> None:  # a group, so the command is invoked as `update`
        """test app"""

    register(app)
    return app


def _releases() -> list[ReleaseInfo]:
    return [
        ReleaseInfo("1.2.0", NOW - timedelta(days=90), has_provenance=True),
        ReleaseInfo("1.2.5", NOW - timedelta(days=30), has_provenance=True),
    ]


def _queried(**kw: Any) -> DependencyIntel:
    return DependencyIntel(ref=REF, checked_at=NOW, coverage="queried", releases=_releases(), **kw)


@pytest.fixture
def agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / ".mcp.json").write_text(CONFIG)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(inventory, "dependencies_from_bom", lambda bom: [REF])
    return tmp_path


def _advise(monkeypatch: pytest.MonkeyPatch, make: Callable[[], list[DependencyIntel]]) -> list[Any]:
    calls: list[Any] = []

    def fake(refs: Sequence[DependencyRef], **kw: Any) -> list[DependencyIntel]:
        calls.append((list(refs), kw))
        return make()

    monkeypatch.setattr(engine, "check_dependencies", fake)
    return calls


def _run(*args: str) -> Any:
    return CliRunner().invoke(_app(), ["update", *args])


def test_nothing_pending_exits_zero(agent: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _advise(
        monkeypatch,
        lambda: [DependencyIntel(ref=REF, checked_at=NOW, coverage="queried", releases=_releases()[:1])],
    )
    result = _run(str(agent), "--json", "--offline")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["proposals"] == [] and data["dependencies"] == 1
    assert calls[0][1]["client"].offline is True
    assert calls[0][1]["policy"].cooldown_days == 7


def test_low_version_update_exits_zero_and_writes(agent: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _advise(monkeypatch, lambda: [_queried()])
    result = _run(str(agent), "--write", "--json")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert [p["kind"] for p in data["proposals"]] == ["version"]
    assert data["written"] == [".mcp.json"]
    assert (agent / ".mcp.json").read_text() == CONFIG.replace("server-pkg@1.2.0", "server-pkg@1.2.5")


def test_security_proposal_exits_one_with_diff(agent: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    adv = Advisory("GHSA-aaaa-bbbb-cccc", "RCE", severity="high", fixed_in=("1.2.5",))
    sig = Signal(SignalKind.VULNERABLE, "high", "RCE", reference="GHSA-aaaa-bbbb-cccc")
    _advise(monkeypatch, lambda: [_queried(advisories=[adv], signals=[sig])])
    result = _run(str(agent), "--diff", "--json")
    assert result.exit_code == 1, result.output
    data = json.loads(result.stdout)
    assert data["proposals"][0]["kind"] == "security"
    assert '-    "s": {"command": "npx", "args": ["-y", "server-pkg@1.2.0"]}' in data["diff"]
    assert data["diff"].startswith("--- a/.mcp.json\n+++ b/.mcp.json\n")
    assert (agent / ".mcp.json").read_text() == CONFIG  # --diff alone writes nothing


def test_unreachable_lookups_exit_six(agent: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def make() -> list[DependencyIntel]:
        intel = DependencyIntel(ref=REF, checked_at=NOW, coverage="unreachable")
        intel.errors.append("offline mode and no fresh cache entry")
        return [intel]

    _advise(monkeypatch, make)
    result = _run(str(agent), "--json", "--offline")
    assert result.exit_code == 6, result.output
    data = json.loads(result.stdout)
    assert data["proposals"] == [] and data["unreachable"][0]["name"] == "server-pkg"


def test_lookup_io_error_exits_six(agent: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> list[DependencyIntel]:
        raise OSError("disk full")

    _advise(monkeypatch, boom)
    assert _run(str(agent)).exit_code == 6


def test_options_reach_the_policy(agent: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _advise(monkeypatch, lambda: [_queried()])
    result = _run(str(agent), "--cooldown-days", "45", "--allow-major")
    # 1.2.5 is 30 days old, inside a 45-day cooldown: nothing proposed.
    assert result.exit_code == 0, result.output
    policy = calls[0][1]["policy"]
    assert policy.cooldown_days == 45 and policy.allow_major is True


def test_open_pr_is_called_with_edited_proposals(agent: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import symbiote.update as update_pkg

    seen: list[Any] = []

    def fake_pr(root: Path, proposals: Sequence[Any], **kw: Any) -> str:
        seen.append([p.edits for p in proposals])
        return "https://github.example/acme/agent/pull/7"

    monkeypatch.setattr(update_pkg, "open_pull_request", fake_pr)
    _advise(monkeypatch, lambda: [_queried()])
    result = _run(str(agent), "--open-pr", "--json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["pullRequest"] == "https://github.example/acme/agent/pull/7"
    assert seen and seen[0][0][0].after == "server-pkg@1.2.5"


def test_open_pr_failure_exits_six(agent: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import symbiote.update as update_pkg

    def fail(root: Path, proposals: Sequence[Any], **kw: Any) -> str:
        raise update_pkg.PullRequestError("the working tree has uncommitted changes")

    monkeypatch.setattr(update_pkg, "open_pull_request", fail)
    _advise(monkeypatch, lambda: [_queried()])
    assert _run(str(agent), "--open-pr").exit_code == 6
