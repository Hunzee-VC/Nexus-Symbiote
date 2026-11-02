"""dependencies_from_bom on a scanned project plus hand-built entities."""

from __future__ import annotations

import json
from pathlib import Path

from symbiote.advisories import DependencyKind, DependencyRef, dependencies_from_bom
from symbiote.model import AgentBOM, Claim
from symbiote.model.common import Provenance
from symbiote.model.entities import (
    A2ACard,
    Agent,
    Authentication,
    DirManifest,
    HostedIdentity,
    ManifestItem,
    Model,
    PackageRef,
    Skill,
    SoftwareComponent,
    ToolServer,
    WeightsIdentity,
)
from symbiote.model.enums import (
    AgentRole,
    AliasPinning,
    AuthMode,
    Launcher,
    ModelKind,
    ToolServerKind,
    Transport,
    UnknownReason,
)
from symbiote.scan import scan

from ._support import NOW

D = "sha256:" + "ab" * 32
D2 = "sha256:" + "cd" * 32


def _scanned(tmp_path: Path) -> AgentBOM:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "cli": {"command": "npx", "args": ["-y", "agent-cli-demo@2.2.3"]},
                    "files": {"command": "npx", "args": ["-y", "@demo/mcp-server-files"]},
                    "py": {"command": "uvx", "args": ["demo-mcp-server==1.0.1"]},
                    "remote": {"type": "http", "url": "https://mcp.example.com/mcp"},
                }
            }
        )
    )
    return scan(tmp_path, deterministic=True, now=NOW, policy=False).bom


def _by_name(refs: list[DependencyRef]) -> dict[str, DependencyRef]:
    return {r.name: r for r in refs}


def test_scanned_mcp_servers(tmp_path: Path) -> None:
    refs = _by_name(dependencies_from_bom(_scanned(tmp_path)))
    cli = refs["agent-cli-demo"]
    assert cli.kind is DependencyKind.MCP_SERVER_PACKAGE and cli.ecosystem == "npm"
    assert cli.version == "2.2.3" and cli.purl == "pkg:npm/agent-cli-demo@2.2.3"
    assert cli.locators == (".mcp.json#/mcpServers/cli",)
    assert cli.subjects and cli.subjects[0].startswith("server:")
    files = refs["@demo/mcp-server-files"]
    assert files.version is None  # npx -y without a version floats
    assert files.locators == (".mcp.json#/mcpServers/files",)
    py = refs["demo-mcp-server"]
    assert py.ecosystem == "pypi" and py.version == "1.0.1"
    remote = refs["https://mcp.example.com/mcp"]
    assert remote.kind is DependencyKind.MCP_SERVER_REMOTE
    assert remote.locators == (".mcp.json#/mcpServers/remote",)


def _server(sid: str, purl: str, locator: str, *, floating: bool = False) -> ToolServer:
    return ToolServer(  # type: ignore[call-arg]
        id=sid,
        kind=ToolServerKind.MCP,  # pydantic alias of server_kind/model_kind
        transport=Claim.declared(Transport.STDIO),
        authentication=Claim.declared(Authentication(mode=AuthMode.NONE)),
        crosses_trust_boundary=Claim.declared(False),
        package=Claim.declared(
            PackageRef(purl=purl, floating=floating, launcher=Launcher.NPX), locator=locator
        ),
        provenance=Provenance(locator=locator.split("/args")[0]),
    )


def test_hand_built_entities_and_dedup(tmp_path: Path) -> None:
    bom = _scanned(tmp_path)
    peer = ToolServer(  # type: ignore[call-arg]
        id="server:peer",
        kind=ToolServerKind.A2A,  # pydantic alias of server_kind/model_kind
        digest=D2,
        transport=Claim.declared(Transport.STREAMABLE_HTTP),
        authentication=Claim.declared(Authentication(mode=AuthMode.NONE)),
        crosses_trust_boundary=Claim.declared(True),
        endpoint=Claim.declared("https://peer.example.com/a2a", locator="agent.yaml#/peers/0/url"),
    )
    dup1 = _server("server:dup-a", "pkg:npm/shared-tool@1.0.0", "a/.mcp.json#/mcpServers/x/args/1")
    dup2 = _server("server:dup-b", "pkg:npm/shared-tool@1.0.0", "b/.mcp.json#/mcpServers/y/args/1")
    sub = Agent(
        id="agent:helper",
        name="helper",
        version="1",
        role=AgentRole.SUB_AGENT,
        a2a_card=A2ACard(url="https://helper.example.com/.well-known/agent-card.json", digest=D),
        provenance=Provenance(locator="agents/helper.json"),
    )
    skill = Skill(
        id="skill:triage",
        name="triage",
        path=".claude/skills/triage",
        digest=D,
        manifest=DirManifest(resources=[ManifestItem(name="SKILL.md", digest=D)], root=D),
        provenance=Provenance(locator=".claude/skills/triage/SKILL.md"),
    )
    sw = SoftwareComponent(
        id="sw:lodash", purl="pkg:npm/lodash@4.17.21", provenance=Provenance(locator="sbom.json")
    )
    sw_go = SoftwareComponent(id="sw:go", purl="pkg:golang/example.com/x@v1.0.0")
    hosted = Model(  # type: ignore[call-arg]
        id="model:sonnet",
        kind=ModelKind.HOSTED,  # pydantic alias of server_kind/model_kind
        hosted=Claim.declared(
            HostedIdentity(
                provider="anthropic",
                requested_ref="claude-sonnet-4-5",
                resolved_ref=Claim.unknown(UnknownReason.NOT_COLLECTED),
                alias_pinning=AliasPinning.FLOATING,
            ),
            locator="agent.yaml#/model",
        ),
    )
    local = Model(  # type: ignore[call-arg]
        id="model:local",
        kind=ModelKind.WEIGHTS,  # pydantic alias of server_kind/model_kind
        weights=Claim.declared(
            WeightsIdentity(purl="pkg:huggingface/org/model@abc123", manifest_root=D, file_count=1),
            locator="models/model.json",
        ),
    )
    bom = bom.model_copy(
        update={
            "tool_servers": [*bom.tool_servers, peer, dup1, dup2],
            "agents": [*bom.agents, sub],
            "skills": [skill],
            "software": [sw, sw_go],
            "models": [hosted, local],
        }
    )
    refs = dependencies_from_bom(bom)
    by = _by_name(refs)

    shared = by["shared-tool"]
    assert shared.subjects == ("server:dup-a", "server:dup-b")
    # The package claim's locator (the exact argument) and the declaring entry, from both declarations.
    assert shared.locators == (
        "a/.mcp.json#/mcpServers/x",
        "a/.mcp.json#/mcpServers/x/args/1",
        "b/.mcp.json#/mcpServers/y",
        "b/.mcp.json#/mcpServers/y/args/1",
    )
    assert [r.name for r in refs].count("shared-tool") == 1

    p = by["https://peer.example.com/a2a"]
    assert p.kind is DependencyKind.A2A_PEER and p.ecosystem == "a2a" and p.version == D2
    assert p.locators == ("agent.yaml#/peers/0/url",)
    h = by["https://helper.example.com/.well-known/agent-card.json"]
    assert h.kind is DependencyKind.A2A_PEER and h.version == D

    s = by["triage"]
    assert s.kind is DependencyKind.SKILL and s.version == D
    assert ".claude/skills/triage/SKILL.md" in s.locators

    assert by["lodash"].kind is DependencyKind.SOFTWARE_COMPONENT and by["lodash"].version == "4.17.21"
    assert "example.com/x" not in by  # no advisor for Go: not inventoried

    m = by["claude-sonnet-4-5"]
    assert m.kind is DependencyKind.HOSTED_MODEL and m.ecosystem == "hosted-model" and m.version is None
    assert m.locators == ("agent.yaml#/model",)
    assert m.purl is not None and "provider=anthropic" in m.purl

    w = by["org/model"]
    assert w.kind is DependencyKind.LOCAL_MODEL and w.ecosystem == "huggingface" and w.version == "abc123"

    # Deterministic order.
    assert refs == dependencies_from_bom(bom)
    assert refs == sorted(refs, key=lambda r: (r.ecosystem, r.name, r.version or "", r.kind.value))


def test_purl_less_launcher_packages_are_inventoried(tmp_path: Path) -> None:
    """``npx -y github:owner/repo`` and tarball URLs have no package URL; they must not vanish."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "git": {"command": "npx", "args": ["-y", "github:evil/mcp-server"]},
                    "tar": {"command": "npx", "args": ["-y", "https://example.com/srv.tgz"]},
                    "ok": {"command": "npx", "args": ["-y", "some-server@1.0.0"]},
                }
            }
        )
    )
    bom = scan(tmp_path, deterministic=True, now=NOW, policy=False).bom
    refs = _by_name(dependencies_from_bom(bom))
    assert set(refs) == {"npx:git", "npx:tar", "some-server"}
    for name in ("npx:git", "npx:tar"):
        ref = refs[name]
        assert ref.ecosystem == "mcp-registry" and ref.purl is None and ref.version is None
        assert ref.kind is DependencyKind.MCP_SERVER_PACKAGE
        assert ref.locators and ref.locators[0].startswith(".mcp.json#/mcpServers/")
