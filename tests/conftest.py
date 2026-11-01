from __future__ import annotations

from datetime import UTC, datetime

import pytest

from symbiote.model import AgentBOM, Claim, DigestResult, Edge, Producer, Snapshot
from symbiote.model import enums as E
from symbiote.model.entities import Agent, Authentication, ToolDefinition, ToolServer

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
D = "sha256:" + "ab" * 32


@pytest.fixture
def minimal_bom() -> AgentBOM:
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
        digest=DigestResult(algorithm="tooldef/v1", value=D),
        source=E.ToolSource.DECLARED_CONFIG,
    )
    snap = Snapshot(
        id=f"snap:1:{D[7:19]}",
        kind=E.SnapshotKind.DECLARED,
        digest=D,
        serial=1,
        agent_ref="agent:triager",
        produced_at=NOW,
    )
    return AgentBOM(
        snapshot=snap,
        subject="agent:triager",
        producer=Producer(version="0.1.0"),
        agents=[agent],
        tool_servers=[server],
        tools=[tool],
        edges=[
            Edge(type=E.EdgeType.INVOKES_TOOL, **{"from": "agent:triager", "to": "tool:github/get_issue"}),
            Edge(type=E.EdgeType.PROVIDES_TOOL, **{"from": "server:github", "to": "tool:github/get_issue"}),
        ],
    )
