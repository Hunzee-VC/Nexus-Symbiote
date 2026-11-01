"""mcp-live collector against the drift-mode fixture server (offline: our own subprocess)."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from symbiote.collect.base import CollectContext
from symbiote.collect.mcp_live import (
    LiveServerSpec,
    McpLiveCollector,
    capture_to_entities,
    introspect_stdio,
)
from symbiote.model.enums import CoverageStatus, Surface, ToolSource, ToolState

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "mcp_fixture_server.py"
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def spec(drift: str = "none", **env: str) -> LiveServerSpec:
    return LiveServerSpec(
        id="server:fixture",
        name="fixture",
        transport="stdio",
        command=sys.executable,
        args=["-I", str(FIXTURE), "--drift", drift],
        env=env,
    )


def ctx(**options) -> CollectContext:
    return CollectContext(root=FIXTURE.parent, now=NOW, deterministic=True, options=options)


def capture(drift: str = "none", **env: str):
    return introspect_stdio(spec(drift, **env), deadline_seconds=10)


def test_introspects_baseline_server() -> None:
    cap = capture()
    assert cap.protocol_version == "2025-06-18"
    assert cap.server_info and cap.server_info["name"] == "symbiote-fixture"
    assert [t["name"] for t in cap.raw_tools] == ["get_issue", "add_label"]
    assert cap.instructions and "Fixture server" in cap.instructions


def test_log_noise_on_stdout_is_skipped() -> None:
    cap = capture(SYMBIOTE_FIXTURE_LOG_NOISE="1")
    assert len(cap.raw_tools) == 2


def test_entities_carry_wire_exact_digests() -> None:
    server, tools, evidence, edges = capture_to_entities(
        spec(), capture(), collector_ref="collector:mcp-live@0.1.0", ctx=ctx()
    )
    get_issue = next(t for t in tools if t.tool_name == "get_issue")
    assert get_issue.source is ToolSource.SERVED_LIVE and get_issue.state is ToolState.SERVED
    assert get_issue.digest.ok and get_issue.description_digest and get_issue.input_schema_digest
    assert get_issue.annotations is not None and get_issue.annotations.value.read_only_hint is True
    assert server.toolset_digest_result is not None and server.toolset_digest_result.ok
    assert evidence.evidence_kind.value == "tools-list-capture"
    assert len(edges) == 2 and all(e.type.value == "providesTool" for e in edges)


@pytest.mark.parametrize(
    ("drift", "changed"),
    [("description", True), ("schema", True), ("annotations", True), ("order", False), ("pagination", False)],
)
def test_drift_modes_change_exactly_the_right_digests(drift: str, changed: bool) -> None:
    base_server, base_tools, *_ = capture_to_entities(spec(), capture(), collector_ref="collector:mcp-live@0.1.0", ctx=ctx())
    drift_server, drift_tools, *_ = capture_to_entities(
        spec(drift), capture(drift), collector_ref="collector:mcp-live@0.1.0", ctx=ctx()
    )
    base_set = base_server.toolset_digest_result
    drift_set = drift_server.toolset_digest_result
    assert base_set is not None and drift_set is not None
    assert (base_set.value != drift_set.value) is changed
    base_tool = {t.tool_name: t for t in base_tools}["get_issue"]
    drift_tool = {t.tool_name: t for t in drift_tools}["get_issue"]
    if drift == "description":
        assert base_tool.description_digest != drift_tool.description_digest
        assert base_tool.input_schema_digest == drift_tool.input_schema_digest
    if drift == "schema":
        assert base_tool.description_digest == drift_tool.description_digest
        assert base_tool.input_schema_digest != drift_tool.input_schema_digest
    if drift == "annotations":
        # hint removal changes the tooldef digest though description and schema are unchanged
        assert base_tool.digest.value != drift_tool.digest.value
        assert base_tool.description_digest == drift_tool.description_digest
        assert base_tool.input_schema_digest == drift_tool.input_schema_digest


def test_unicode_drift_sets_text_flags() -> None:
    _, tools, *_ = capture_to_entities(spec("unicode"), capture("unicode"), collector_ref="collector:mcp-live@0.1.0", ctx=ctx())
    get_issue = {t.tool_name: t for t in tools}["get_issue"]
    assert any(f.value == "hidden-unicode" for f in get_issue.text_flags)


def test_collector_enforces_allowlist_and_records_coverage() -> None:
    collector = McpLiveCollector()
    live = {
        "id": "server:fixture",
        "name": "fixture",
        "transport": "stdio",
        "command": sys.executable,
        "args": ["-I", str(FIXTURE)],
    }
    denied = collector.collect(ctx(live=True, live_servers=[live], live_allow=[]))
    assert denied.entities == []
    tools_cov = denied.coverage[Surface.TOOLS]
    assert tools_cov.sources and tools_cov.sources[0].error_class == "not-allowlisted"
    allowed = collector.collect(
        ctx(live=True, live_servers=[live], live_allow=["server:fixture"], live_deadline_seconds=10)
    )
    allowed.finalize_coverage(collector.surfaces)
    assert allowed.coverage[Surface.TOOLS].status is CoverageStatus.QUERIED
    assert {e.id for e in allowed.entities} >= {"server:fixture", "tool:fixture/get_issue"}


def test_remote_transport_is_an_honest_gap() -> None:
    collector = McpLiveCollector()
    result = collector.collect(
        ctx(
            live=True,
            live_servers=[{"id": "server:remote", "name": "remote", "transport": "sse", "url": "https://x"}],
            live_allow=["server:remote"],
        )
    )
    cov = result.coverage[Surface.TOOLS]
    assert cov.sources[0].error_class == "unsupported-source"
    assert result.entities == []
