"""Golden locks for the sealed companion document and a canonical rug-pull delta (WP16, I7).

These goldens pin the byte-exact output of the whole model → digest → snapshot stack. Exporters
(WP6/WP7) add their own goldens next to these with the same tooling. Regenerate intentionally with
``UPDATE_GOLDENS=1`` and review the diff — a surprise change here is a determinism regression or
an unreviewed emitted-field change (``spec/versioning.md``).
"""

from __future__ import annotations

from datetime import UTC, datetime

from symbiote.model import Claim, DigestResult, Edge, Producer
from symbiote.model import enums as E
from symbiote.model.entities import Agent, Authentication, ToolDefinition, ToolServer
from symbiote.snapshot import diff, finalize, new_document
from tests.support import assert_golden

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
NONCE = bytes.fromhex("11" * 32)
D_TOOL = "sha256:" + "ab" * 32
D_TOOL2 = "sha256:" + "cd" * 32
D_DESC = "sha256:" + "0f" * 32
D_DESC2 = "sha256:" + "1f" * 32
D_SCHEMA = "sha256:" + "2f" * 32


def _doc(tool_digest: str, desc_digest: str):
    agent = Agent(id="agent:triager", name="triager", version="1.0.0", role=E.AgentRole.ROOT)
    server = ToolServer(
        id="server:github",
        kind=E.ToolServerKind.MCP,
        transport=Claim.declared(E.Transport.STDIO, locator=".mcp.json#/mcpServers/github/command"),
        authentication=Claim.declared(Authentication(mode=E.AuthMode.API_KEY)),
        crosses_trust_boundary=Claim.declared(True),
        env_var_names=["GITHUB_TOKEN"],
    )
    tool = ToolDefinition(
        id="tool:github/get_issue",
        server_ref="server:github",
        tool_name="get_issue",
        input_schema={"type": "object"},
        digest=DigestResult(algorithm="tooldef/v1", value=tool_digest),
        description_digest=desc_digest,
        input_schema_digest=D_SCHEMA,
        source=E.ToolSource("declared-config"),
        side_effect_class=E.SideEffectClass.READ_ONLY,
    )
    return new_document(
        subject="agent:triager",
        producer=Producer(version="0.1.0"),
        kind=E.SnapshotKind.DECLARED,
        produced_at=NOW,
        agents=[agent],
        tool_servers=[server],
        tools=[tool],
        edges=[
            Edge(type=E.EdgeType.PROVIDES_TOOL, **{"from": "server:github", "to": "tool:github/get_issue"}),
            Edge(type=E.EdgeType.INVOKES_TOOL, **{"from": "agent:triager", "to": "tool:github/get_issue"}),
        ],
    )


def test_golden_sealed_companion_document() -> None:
    sealed = finalize(_doc(D_TOOL, D_DESC), nonce=NONCE)
    assert_golden("companion/minimal.agentbom.json", sealed.model_dump_json(by_alias=True, indent=2))


def test_golden_rug_pull_delta() -> None:
    approved = finalize(_doc(D_TOOL, D_DESC), nonce=NONCE)
    observed = finalize(_doc(D_TOOL2, D_DESC2), nonce=NONCE)
    delta = diff(approved, observed)
    assert len(delta.events) == 1 and delta.events[0].severity_hint is E.Severity.CRITICAL
    assert_golden("delta/rug-pull.delta.json", delta.model_dump_json(by_alias=True, indent=2))
