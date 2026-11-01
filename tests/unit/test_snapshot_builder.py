"""SnapshotBuilder: sealing, determinism (I7), chain integration (spec/agentbom-profile.md §2.1)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from symbiote.digest import verify_commitment
from symbiote.model import Claim, DigestResult, Edge, Producer
from symbiote.model import enums as E
from symbiote.model.entities import Agent, Authentication, ToolDefinition, ToolServer
from symbiote.snapshot import ChainStore, SnapshotBuilder, edge_leaf_id, leaf_body

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
NONCE = bytes.fromhex("11" * 32)
D = "sha256:" + "ab" * 32


def _entities() -> tuple[Agent, ToolServer, ToolDefinition]:
    agent = Agent(id="agent:triager", name="triager", version="1.0.0", role=E.AgentRole.ROOT)
    server = ToolServer(
        id="server:github",
        kind=E.ToolServerKind.MCP,
        transport=Claim.declared(E.Transport.STDIO),
        authentication=Claim.declared(Authentication(mode=E.AuthMode.API_KEY)),
        crosses_trust_boundary=Claim.declared(True),
    )
    tool = ToolDefinition(
        id="tool:github/get_issue",
        server_ref="server:github",
        tool_name="get_issue",
        input_schema={"type": "object"},
        digest=DigestResult(algorithm="tooldef/v1", value=D),
        source=E.ToolSource("declared-config"),
    )
    return agent, server, tool


def _builder(store: ChainStore | None = None) -> SnapshotBuilder:
    agent, server, tool = _entities()
    b = SnapshotBuilder(
        kind=E.SnapshotKind.DECLARED,
        subject="agent:triager",
        producer=Producer(version="0.1.0"),
        nonce=NONCE,
        store=store,
    )
    b.add(agent, server, tool)
    b.add_edges(
        Edge(type=E.EdgeType.PROVIDES_TOOL, **{"from": "server:github", "to": "tool:github/get_issue"})
    )
    return b


def test_build_seals_a_valid_document() -> None:
    bom = _builder().build(produced_at=NOW)
    assert bom.snapshot.serial == 1 and bom.snapshot.prev is None
    assert bom.merkle is not None
    assert bom.snapshot.digest == bom.merkle.root
    assert bom.snapshot.id == f"snap:1:{bom.merkle.root[7:19]}"
    # leaves: 3 entities + 1 edge + coverage
    assert bom.merkle.leaf_count == 5
    bodies = {("agent", "agent:triager"): leaf_body(bom.root_agent)}
    for server in bom.tool_servers:
        bodies[("server", server.id)] = leaf_body(server)
    for tool in bom.tools:
        bodies[("tool", tool.id)] = leaf_body(tool)
    for edge in bom.edges:
        bodies[("edge", edge_leaf_id(edge))] = edge.to_json_dict()
    bodies[("coverage", "coverage")] = bom.coverage.to_json_dict()
    assert verify_commitment(bom.merkle, bodies)


def test_deterministic_under_fixed_nonce_and_time() -> None:
    one = _builder().build(produced_at=NOW).model_dump_json(by_alias=True)
    two = _builder().build(produced_at=NOW).model_dump_json(by_alias=True)
    assert one == two
    other = SnapshotBuilder(
        kind=E.SnapshotKind.DECLARED,
        subject="agent:triager",
        producer=Producer(version="0.1.0"),
        nonce=bytes.fromhex("22" * 32),
    )
    agent, server, tool = _entities()
    other.add(agent, server, tool)
    assert other.build(produced_at=NOW).snapshot.digest != _builder().build(produced_at=NOW).snapshot.digest


def test_leaf_body_strips_only_id() -> None:
    agent, _, _ = _entities()
    body = leaf_body(agent)
    assert "id" not in body
    assert body["version"] == "1.0.0"
    assert "provenance" in body  # leaves keep full fidelity


def test_chain_store_allocates_and_chains(tmp_path) -> None:
    store = ChainStore(tmp_path)
    first = _builder(store).build(produced_at=NOW)
    assert (first.snapshot.serial, first.snapshot.prev) == (1, None)
    b2 = _builder(store)
    second = b2.build(produced_at=NOW)
    assert second.snapshot.serial == 2
    assert second.snapshot.prev == first.snapshot.digest
    assert b2.chain_issues == []


def test_unroutable_entity_raises() -> None:
    with pytest.raises(TypeError):
        SnapshotBuilder(kind=E.SnapshotKind.DECLARED, subject="agent:x", producer=Producer(version="0")).add(
            object()
        )  # type: ignore[arg-type]
