"""Hypothesis strategies for AgentBOM model types (WP16).

Every strategy produces objects that pass the frozen model's validators, and the document
strategies produce *referentially consistent* documents (tool ``server_ref``s resolve, edges point
at existing entities, the subject is among the agents), so any property test can seal, verify,
redact or diff what it draws. Sizes are deliberately small — properties should be fast.
"""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import strategies as st

from symbiote.model import Claim, DigestResult, Edge, Producer
from symbiote.model import enums as E
from symbiote.model.document import AgentBOM
from symbiote.model.entities import (
    Agent,
    Authentication,
    Instruction,
    ToolDefinition,
    ToolServer,
)
from symbiote.snapshot import finalize, new_document

FIXED_NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)

# ----------------------------------------------------------------------------- scalars

hex64 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
digests = hex64.map(lambda h: f"sha256:{h}")
nonces = st.binary(min_size=32, max_size=32)
slugs = st.from_regex(r"[a-z][a-z0-9-]{0,11}", fullmatch=True)
tool_names = st.from_regex(r"[a-z][a-z0-9_]{0,14}", fullmatch=True)

#: JSON values that survive JCS (finite doubles, |int| < 2^53, no lone surrogates).
json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
    # |float| is kept below 2**53: an integral double of exactly ±2**53 canonicalises to an
    # integer numeral that the strict parser then rejects as out-of-range, so canonical output
    # is not re-ingestible at that single boundary (fail-closed; noted in the WP16 PR).
    st.floats(
        allow_nan=False,
        allow_infinity=False,
        width=64,
        min_value=-(2.0**53) + 1,
        max_value=2.0**53 - 1,
    ),
    st.text(max_size=20),
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=8), children, max_size=3),
    ),
    max_leaves=10,
)

# ----------------------------------------------------------------------------- entities


@st.composite
def tool_definitions(draw: st.DrawFn, server_slug: str, name: str | None = None) -> ToolDefinition:
    tool = name or draw(tool_names)
    return ToolDefinition(
        id=f"tool:{server_slug}/{tool}",
        server_ref=f"server:{server_slug}",
        tool_name=tool,
        description=draw(st.none() | st.text(max_size=40)),
        input_schema={"type": "object"},
        digest=DigestResult(algorithm="tooldef/v1", value=draw(digests)),
        description_digest=draw(st.none() | digests),
        input_schema_digest=draw(st.none() | digests),
        source=E.ToolSource("declared-config"),
        side_effect_class=draw(st.sampled_from(E.SideEffectClass)),
    )


@st.composite
def tool_servers(draw: st.DrawFn, slug: str | None = None) -> ToolServer:
    server_slug = slug or draw(slugs)
    return ToolServer(
        id=f"server:{server_slug}",
        kind=E.ToolServerKind.MCP,
        digest=draw(st.none() | digests),
        transport=Claim.declared(draw(st.sampled_from([E.Transport.STDIO, E.Transport.STREAMABLE_HTTP]))),
        authentication=Claim.declared(Authentication(mode=draw(st.sampled_from(E.AuthMode)))),
        crosses_trust_boundary=Claim.declared(draw(st.booleans())),
        env_var_names=draw(
            st.lists(st.from_regex(r"[A-Z][A-Z0-9_]{0,10}", fullmatch=True), max_size=2, unique=True)
        ),
    )


@st.composite
def instructions(draw: st.DrawFn) -> Instruction:
    return Instruction(
        id=f"instr:{draw(slugs)}",
        kind=E.InstructionKind("agents-md"),
        path="AGENTS.md",
        size=draw(st.integers(min_value=0, max_value=1 << 20)),
        digest=draw(digests),
        precedence=draw(st.integers(min_value=0, max_value=9)),
    )


# ----------------------------------------------------------------------------- documents


@st.composite
def draft_documents(draw: st.DrawFn) -> AgentBOM:
    """An unfinalised, referentially consistent document (placeholder snapshot digest)."""
    agent = Agent(id="agent:root", version="1.0.0", role=E.AgentRole.ROOT)
    server_slugs = draw(st.lists(slugs, min_size=0, max_size=3, unique=True))
    servers = [draw(tool_servers(slug=s)) for s in server_slugs]
    tools: list[ToolDefinition] = []
    for s in server_slugs:
        names = draw(st.lists(tool_names, min_size=0, max_size=3, unique=True))
        tools.extend(draw(tool_definitions(s, name=n)) for n in names)
    instrs = draw(st.lists(instructions(), min_size=0, max_size=2, unique_by=lambda i: i.id))
    edges = [Edge(type=E.EdgeType.PROVIDES_TOOL, **{"from": t.server_ref, "to": t.id}) for t in tools] + [
        Edge(type=E.EdgeType.INVOKES_TOOL, **{"from": "agent:root", "to": t.id}) for t in tools
    ]
    return new_document(
        subject="agent:root",
        producer=Producer(version="0.0.0-test"),
        kind=E.SnapshotKind.DECLARED,
        produced_at=FIXED_NOW,
        agents=[agent],
        tool_servers=servers,
        tools=tools,
        instructions=instrs,
        edges=edges,
    )


@st.composite
def sealed_documents(draw: st.DrawFn) -> AgentBOM:
    """A finalised document: Merkle-committed, chain-serial 1, deterministic nonce."""
    return finalize(draw(draft_documents()), nonce=draw(nonces))


__all__ = [
    "FIXED_NOW",
    "digests",
    "draft_documents",
    "instructions",
    "json_values",
    "nonces",
    "sealed_documents",
    "slugs",
    "tool_definitions",
    "tool_names",
    "tool_servers",
]
