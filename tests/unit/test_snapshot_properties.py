"""Property tests for the snapshot engine (WP16 will generalise these strategies)."""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st

from symbiote.model import AgentBOM, Producer, Snapshot
from symbiote.model import enums as E
from symbiote.model.common import DigestResult
from symbiote.model.entities import Agent, ToolDefinition
from symbiote.snapshot import diff

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)

hex_digest = st.sampled_from("0123456789abcdef").flatmap(lambda c: st.just("sha256:" + c * 64))
tool_name = st.from_regex(r"[a-z][a-z0-9_]{0,10}", fullmatch=True)


@st.composite
def tools(draw: st.DrawFn) -> list[ToolDefinition]:
    names = draw(st.lists(tool_name, min_size=0, max_size=6, unique=True))
    return [
        ToolDefinition(
            id=f"tool:srv/{name}",
            server_ref="server:srv",
            tool_name=name,
            input_schema={"type": "object"},
            digest=DigestResult(algorithm="tooldef/v1", value=draw(hex_digest)),
            description_digest=draw(st.none() | hex_digest),
            input_schema_digest=draw(st.none() | hex_digest),
            source=E.ToolSource("declared-config"),
        )
        for name in names
    ]


def doc(tool_list: list[ToolDefinition], serial: int = 1) -> AgentBOM:
    digest = "sha256:" + "a" * 64
    return AgentBOM(
        snapshot=Snapshot(
            id=f"snap:{serial}:{digest[7:19]}",
            kind=E.SnapshotKind.DECLARED,
            digest=digest,
            serial=serial,
            agent_ref="agent:x",
            produced_at=NOW,
        ),
        subject="agent:x",
        producer=Producer(version="0"),
        agents=[Agent(id="agent:x", version="1", role=E.AgentRole.ROOT)],
        tools=tool_list,
    )


@settings(max_examples=50, deadline=None)
@given(tools())
def test_diff_of_identical_documents_is_empty(tool_list: list[ToolDefinition]) -> None:
    a, b = doc(tool_list), doc(tool_list, serial=2)
    assert diff(a, b).events == []


@settings(max_examples=50, deadline=None)
@given(tools(), tools())
def test_diff_events_are_deterministic_and_bounded(
    a_tools: list[ToolDefinition], b_tools: list[ToolDefinition]
) -> None:
    a, b = doc(a_tools), doc(b_tools, serial=2)
    first, second = diff(a, b), diff(a, b)
    assert first.model_dump_json() == second.model_dump_json()
    # one event per added/removed/changed tool at most
    ids_a = {t.id for t in a_tools}
    ids_b = {t.id for t in b_tools}
    assert len(first.events) <= len(ids_a | ids_b)
