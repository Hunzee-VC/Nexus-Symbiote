"""Digest-based diff semantics (spec/agentbom-profile.md §2.2, I8): the diff is the alarm."""

from __future__ import annotations

from datetime import UTC, datetime

from symbiote.model import AgentBOM, Claim, DigestResult, Edge, Producer, Snapshot
from symbiote.model import enums as E
from symbiote.model.common import Provenance
from symbiote.model.entities import (
    Agent,
    Authentication,
    DataSource,
    Evaluation,
    Grant,
    Harness,
    HostedIdentity,
    Instruction,
    Model,
    SubjectConfig,
    ToolDefinition,
    ToolServer,
    TrustStatus,
)
from symbiote.model.enums import DeltaEventType as T
from symbiote.snapshot import diff, stale_evaluation_ids

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
LATER = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)


def hx(c: str) -> str:
    return "sha256:" + c * 64


def mk_tool(
    *,
    digest: str = hx("1"),
    desc: str = hx("2"),
    schema: str = hx("3"),
    full: str | None = None,
    side: E.SideEffectClass = E.SideEffectClass.READ_ONLY,
    provenance: Provenance | None = None,
) -> ToolDefinition:
    return ToolDefinition(
        id="tool:github/get_issue",
        server_ref="server:github",
        tool_name="get_issue",
        input_schema={"type": "object"},
        digest=DigestResult(algorithm="tooldef/v1", value=digest),
        full_digest=DigestResult(algorithm="tooldef-full/v1", value=full) if full else None,
        description_digest=desc,
        input_schema_digest=schema,
        source=E.ToolSource("declared-config"),
        side_effect_class=side,
        provenance=provenance or Provenance(),
    )


def mk_server(
    *, digest: str = hx("4"), env: list[str] | None = None, claim_noise: bool = False
) -> ToolServer:
    transport = (
        Claim(
            value=E.Transport.STDIO,
            assurance=E.AssuranceLevel.OBSERVED,
            method=E.ClaimMethod.LIVE_QUERY,
            locator="live:initialize",
            observed_at=LATER,
        )
        if claim_noise
        else Claim.declared(E.Transport.STDIO)
    )
    return ToolServer(
        id="server:github",
        kind=E.ToolServerKind.MCP,
        digest=digest,
        transport=transport,
        authentication=Claim.declared(Authentication(mode=E.AuthMode.API_KEY)),
        crosses_trust_boundary=Claim.declared(True),
        env_var_names=env or ["GITHUB_TOKEN"],
    )


def mk_doc(
    *,
    serial: int = 1,
    digest: str = hx("a"),
    kind: E.SnapshotKind = E.SnapshotKind.DECLARED,
    tools: list[ToolDefinition] | None = None,
    servers: list[ToolServer] | None = None,
    window: dict | None = None,
    **collections,
) -> AgentBOM:
    agent = Agent(id="agent:triager", version="1.0.0", role=E.AgentRole.ROOT)
    return AgentBOM(
        snapshot=Snapshot(
            id=f"snap:{serial}:{digest[7:19]}",
            kind=kind,
            digest=digest,
            serial=serial,
            agent_ref="agent:triager",
            produced_at=NOW if serial == 1 else LATER,
            observation_window=window,
        ),
        subject="agent:triager",
        producer=Producer(version="0.1.0"),
        agents=[agent],
        tools=tools or [],
        tool_servers=servers if servers is not None else ([mk_server()] if tools else []),
        **collections,
    )


def events_of(a: AgentBOM, b: AgentBOM) -> list:
    return diff(a, b).events


# ------------------------------------------------------------------------------------ tools


def test_rug_pull_description_change_is_critical() -> None:
    a = mk_doc(tools=[mk_tool()])
    b = mk_doc(serial=2, digest=hx("b"), tools=[mk_tool(digest=hx("9"), desc=hx("8"))])
    (ev,) = events_of(a, b)
    assert ev.type is T.TOOL_DEFINITION_CHANGED
    assert ev.severity_hint is E.Severity.CRITICAL
    assert "description" in (ev.detail or "")
    assert ev.before == hx("1") and ev.after == hx("9")


def test_schema_only_change_is_high() -> None:
    a = mk_doc(tools=[mk_tool()])
    b = mk_doc(serial=2, digest=hx("b"), tools=[mk_tool(digest=hx("9"), schema=hx("7"))])
    (ev,) = events_of(a, b)
    assert ev.type is T.TOOL_DEFINITION_CHANGED and ev.severity_hint is E.Severity.HIGH
    assert "schema" in (ev.detail or "")


def test_annotation_only_change_is_medium() -> None:
    a = mk_doc(tools=[mk_tool()])
    b = mk_doc(serial=2, digest=hx("b"), tools=[mk_tool(digest=hx("9"))])  # same desc+schema digests
    (ev,) = events_of(a, b)
    assert ev.type is T.TOOL_ANNOTATIONS_CHANGED and ev.severity_hint is E.Severity.MEDIUM


def test_non_model_visible_change_is_low() -> None:
    a = mk_doc(tools=[mk_tool(full=hx("5"))])
    b = mk_doc(serial=2, digest=hx("b"), tools=[mk_tool(full=hx("6"))])
    (ev,) = events_of(a, b)
    assert ev.type is T.TOOL_ANNOTATIONS_CHANGED and ev.severity_hint is E.Severity.LOW


def test_tool_added_and_removed() -> None:
    a = mk_doc(tools=[mk_tool()])
    b = mk_doc(serial=2, digest=hx("b"), tools=[])
    b = b.model_copy(update={"tool_servers": [mk_server()]})
    (removed,) = events_of(a, b)
    assert removed.type is T.TOOL_REMOVED and removed.severity_hint is E.Severity.LOW
    unknown_tool = mk_tool(side=E.SideEffectClass.UNKNOWN)
    (added,) = events_of(b, mk_doc(serial=3, digest=hx("c"), tools=[unknown_tool]))
    assert added.type is T.TOOL_REGISTERED and added.severity_hint is E.Severity.HIGH


# ------------------------------------------------------------------------------------ noise immunity


def test_reobservation_and_assurance_upgrade_produce_no_events() -> None:
    """Same facts, different collection metadata: provenance, claim noise, assurance upgrades."""
    a = mk_doc(tools=[mk_tool()], servers=[mk_server()])
    noisy_provenance = Provenance(
        assurance=E.AssuranceLevel.OBSERVED,
        method=E.ClaimMethod.LIVE_QUERY,
        locator="live:tools/list",
        observed_at=LATER,
    )
    b = mk_doc(
        serial=2,
        digest=hx("b"),
        kind=E.SnapshotKind.OBSERVED,
        tools=[mk_tool(provenance=noisy_provenance)],
        servers=[mk_server(claim_noise=True)],
        window={"start": NOW, "end": LATER},
    )
    assert events_of(a, b) == []


# ------------------------------------------------------------------------------------ servers


def test_server_identity_change_is_critical() -> None:
    a = mk_doc(servers=[mk_server()], tools=[])
    b = mk_doc(serial=2, digest=hx("b"), servers=[mk_server(digest=hx("f"))], tools=[])
    (ev,) = events_of(a, b)
    assert ev.type is T.SERVER_IDENTITY_CHANGED and ev.severity_hint is E.Severity.CRITICAL


def test_server_fact_change_outside_identity_digest_is_high() -> None:
    a = mk_doc(servers=[mk_server()], tools=[])
    b = mk_doc(serial=2, digest=hx("b"), servers=[mk_server(env=["GITHUB_TOKEN", "EXTRA"])], tools=[])
    (ev,) = events_of(a, b)
    assert ev.type is T.SERVER_IDENTITY_CHANGED and ev.severity_hint is E.Severity.HIGH
    assert "env" in (ev.detail or "")


# ------------------------------------------------------------------------------------ instructions, grants, trust


def test_instruction_change_is_critical() -> None:
    instr_a = Instruction(
        id="instr:agents-md", kind=E.InstructionKind("agents-md"), path="AGENTS.md", size=10, digest=hx("1")
    )
    instr_b = instr_a.replace(digest=hx("2"))
    a = mk_doc(instructions=[instr_a])
    b = mk_doc(serial=2, digest=hx("b"), instructions=[instr_b])
    (ev,) = events_of(a, b)
    assert ev.type is T.INSTRUCTION_CHANGED and ev.severity_hint is E.Severity.CRITICAL
    assert ev.before == hx("1") and ev.after == hx("2")


def test_grant_added_privileged_is_high() -> None:
    grant = Grant(
        id="grant:egress",
        layer=E.GrantLayer.DECLARED,
        subject_ref="agent:triager",
        capability=E.CapabilityClass.NETWORK_EGRESS,
    )
    a = mk_doc()
    b = mk_doc(serial=2, digest=hx("b"), grants=[grant])
    (ev,) = events_of(a, b)
    assert ev.type is T.GRANT_ADDED and ev.severity_hint is E.Severity.HIGH


def test_trust_revocation_is_critical() -> None:
    ts = TrustStatus(
        id="trust:tool-1",
        subject_kind=E.TrustSubjectKind.TOOL_DIGEST,
        subject_key=hx("1"),
        status=E.TrustState.REVOKED,
        reason="rug pull",
        decided_by_ref="party:security",
        decided_at=LATER,
        serial=1,
    )
    (ev,) = events_of(mk_doc(), mk_doc(serial=2, digest=hx("b"), trust_status=[ts]))
    assert ev.type is T.TRUST_STATUS_CHANGED and ev.severity_hint is E.Severity.CRITICAL


# ------------------------------------------------------------------------------------ models & edges


def test_hosted_alias_resolution_change() -> None:
    def model(resolved: str) -> Model:
        return Model(
            id="model:primary",
            kind=E.ModelKind.HOSTED,
            hosted=Claim.declared(
                HostedIdentity(
                    provider="anthropic",
                    requested_ref="claude-sonnet-4-5",
                    resolved_ref=Claim.declared(resolved),
                    alias_pinning=E.AliasPinning.FLOATING,
                )
            ),
        )

    a = mk_doc(models=[model("claude-sonnet-4-5-20250929")])
    b = mk_doc(serial=2, digest=hx("b"), models=[model("claude-sonnet-4-5-20261101")])
    (ev,) = events_of(a, b)
    assert ev.type is T.MODEL_ALIAS_RESOLVED
    assert "20261101" in (ev.detail or "")


def test_new_spawn_edge_is_sub_agent_spawned() -> None:
    sub = Agent(id="agent:helper", version="0.1", role=E.AgentRole.SUB_AGENT)
    a = mk_doc()
    b = mk_doc(serial=2, digest=hx("b"))
    b = b.model_copy(
        update={
            "agents": [*b.agents, sub],
            "edges": [Edge(type=E.EdgeType.SPAWNS, **{"from": "agent:triager", "to": "agent:helper"})],
        }
    )
    events = events_of(a, b)
    assert any(e.type is T.SUB_AGENT_SPAWNED and e.subject_ref == "agent:helper" for e in events)


def test_memory_writer_added() -> None:
    def mem(writers: list[str]) -> DataSource:
        return DataSource(
            id="data:memory",
            kind=E.DataSourceKind.MEMORY_STORE,
            instruction_bearing=Claim.declared(True),
            writers=Claim.declared(writers),
        )

    a = mk_doc(data_sources=[mem(["agent:triager"])])
    b = mk_doc(serial=2, digest=hx("b"), data_sources=[mem(["agent:triager", "agent:helper"])])
    (ev,) = events_of(a, b)
    assert ev.type is T.MEMORY_WRITER_ADDED and "agent:helper" in (ev.detail or "")


# ------------------------------------------------------------------------------------ determinism & staleness


def test_delta_is_deterministic_and_dated_from_b() -> None:
    a = mk_doc(tools=[mk_tool()])
    b = mk_doc(serial=2, digest=hx("b"), tools=[mk_tool(digest=hx("9"), desc=hx("8"))])
    d1, d2 = diff(a, b), diff(a, b)
    assert d1.model_dump_json() == d2.model_dump_json()
    assert d1.produced_at == b.snapshot.produced_at
    assert d1.id == f"delta:{a.snapshot.digest[7:19]}:{b.snapshot.digest[7:19]}"


def test_stale_evaluation_detection() -> None:
    toolset = hx("5")
    server = mk_server().replace(toolset_digest=Claim.declared(toolset))
    evaluation = Evaluation(
        id="eval:injection-1",
        subject_config=SubjectConfig(toolset_digests=[toolset]),
        harness=Harness(name="symbench", version="1.0"),
        assessor_ref="party:sec",
        performed_at=NOW,
    )
    fresh = mk_doc(servers=[server], tools=[], evaluations=[evaluation])
    assert stale_evaluation_ids(fresh) == {}
    drifted_server = mk_server(digest=hx("f")).replace(toolset_digest=Claim.declared(hx("6")))
    stale = mk_doc(serial=2, digest=hx("b"), servers=[drifted_server], tools=[], evaluations=[evaluation])
    assert stale_evaluation_ids(stale) == {"eval:injection-1": [toolset]}
