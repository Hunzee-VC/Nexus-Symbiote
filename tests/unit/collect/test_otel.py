"""otel-traces collector: GenAI semconv spans → observed entities, edges, trace summary."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from symbiote.collect.base import CollectContext
from symbiote.collect.otel import OtelTracesCollector
from symbiote.model.enums import CoverageStatus, Surface, ToolSource, ToolState

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
NS = 1_000_000_000
T0 = 1_767_000_000 * NS


def spans_jsonl(path, *, with_definitions: bool = True) -> None:
    definitions = json.dumps(
        [{"name": "get_issue", "description": "Fetch an issue.", "inputSchema": {"type": "object"}}]
    )
    rows = [
        {
            "name": "execute_tool get_issue",
            "startTimeUnixNano": str(T0),
            "endTimeUnixNano": str(T0 + NS),
            "attributes": {
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": "get_issue",
                **({"gen_ai.tool.definitions": definitions} if with_definitions else {}),
            },
            "resource": {"agentbom.snapshot.digest": "sha256:" + "ab" * 32},
        },
        {
            "name": "execute_tool get_issue",
            "startTimeUnixNano": str(T0 + 2 * NS),
            "endTimeUnixNano": str(T0 + 3 * NS),
            "attributes": {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "get_issue"},
        },
        {
            "name": "chat claude",
            "attributes": {
                "gen_ai.operation.name": "chat",
                "gen_ai.provider.name": "anthropic",
                "gen_ai.request.model": "claude-sonnet-4-5",
                "gen_ai.response.model": "claude-sonnet-4-5-20250929",
            },
        },
        {
            "name": "invoke_agent helper",
            "attributes": {
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.agent.id": "helper-1",
                "gen_ai.agent.name": "helper",
            },
        },
        {
            "name": "retrieval",
            "attributes": {"gen_ai.operation.name": "retrieval", "gen_ai.data_source.id": "kb-prod"},
        },
        {
            "name": "chat with memory",
            "attributes": {
                "gen_ai.operation.name": "chat",
                "gen_ai.request.model": "claude-sonnet-4-5",
                "gen_ai.memory.store.id": "mem-1",
                "gen_ai.system_instructions": "You are a triager.",
            },
        },
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def collect(tmp_path, **kw):
    trace = tmp_path / "spans.jsonl"
    spans_jsonl(trace, **kw)
    ctx = CollectContext(
        root=tmp_path, agent_id="agent:triager", now=NOW, options={"otel_files": [str(trace)]}
    )
    collector = OtelTracesCollector()
    result = collector.collect(ctx)
    result.finalize_coverage(collector.surfaces)
    return result


def test_tool_invocations_aggregate_with_counts_and_window(tmp_path) -> None:
    result = collect(tmp_path)
    tool = next(e for e in result.entities if e.id == "tool:observed/get_issue")
    assert tool.state is ToolState.INVOKED and tool.source is ToolSource.TRACE
    assert tool.invocation_count == 2
    assert tool.digest.ok  # the captured definition yields a real tooldef digest
    edge = next(e for e in result.edges if e.type.value == "invokesTool")
    assert edge.observed_count == 2
    assert edge.first_seen is not None and edge.last_seen is not None and edge.first_seen < edge.last_seen


def test_trace_only_tool_without_definition_fails_closed(tmp_path) -> None:
    result = collect(tmp_path, with_definitions=False)
    tool = next(e for e in result.entities if e.id == "tool:observed/get_issue")
    assert not tool.digest.ok and tool.digest.reason and "no tool definition" in tool.digest.reason


def test_alias_routing_models_and_satellite_entities(tmp_path) -> None:
    result = collect(tmp_path)
    ids = {e.id for e in result.entities}
    assert "server:observed" in ids  # stub server for trace-only tools
    model = next(e for e in result.entities if e.id.startswith("model:anthropic"))
    assert model.hosted is not None and model.hosted.value.resolved_ref.value == "claude-sonnet-4-5-20250929"
    assert any(e.id.startswith("agent:helper") for e in result.entities)
    assert any(e.id == "data:kb-prod" for e in result.entities)
    assert any(e.id.startswith("data:memory-") for e in result.entities)
    instr = next(e for e in result.entities if e.id.startswith("instr:otel-"))
    assert instr.size > 0  # hashed and sized, never stored
    assert result.coverage[Surface.RUNTIME].status is CoverageStatus.QUERIED
    assert result.evidence and result.evidence[0].evidence_kind.value == "trace-summary"


def test_unreadable_file_is_a_coverage_fact(tmp_path) -> None:
    bad = tmp_path / "broken.jsonl"
    bad.write_text("{not json", encoding="utf-8")
    ctx = CollectContext(root=tmp_path, now=NOW, options={"otel_files": [str(bad)]})
    collector = OtelTracesCollector()
    result = collector.collect(ctx)
    result.finalize_coverage(collector.surfaces)
    cov = result.coverage[Surface.RUNTIME]
    assert cov.sources[0].ok is False and cov.status is not CoverageStatus.QUERIED
