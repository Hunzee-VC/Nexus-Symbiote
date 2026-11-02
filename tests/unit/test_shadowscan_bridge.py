"""The ShadowScan bridge: capability-card/inventory export and JSON-report import."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from symbiote.export.shadowscan import (
    declared_level,
    discovery_resources,
    to_capability_card,
    to_simple_inventory,
)
from symbiote.imp.shadowscan import ShadowScanImportError, import_shadowscan
from symbiote.model import Claim, DigestResult, Edge, Producer
from symbiote.model import enums as E
from symbiote.model.common import Party
from symbiote.model.entities import (
    Agent,
    Authentication,
    DataSource,
    Deployment,
    Environment,
    Instruction,
    PackageRef,
    ToolDefinition,
    ToolServer,
    WorkloadRef,
)
from symbiote.model.enums import Surface
from symbiote.snapshot import finalize, new_document

FIXTURE = Path(__file__).parent.parent / "fixtures" / "shadowscan" / "report.min.json"
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
NONCE = bytes.fromhex("42" * 32)
TOOL_DIGEST = "sha256:" + "ab" * 32


def sealed_bom():
    party = Party(id="party:claims-it", kind=E.PartyKind.ORGANIZATION, name="Claims IT")
    agent = Agent(
        id="agent:claims-assistant",
        name="Claims Assistant",
        version="2.4.1",
        role=E.AgentRole.ROOT,
        owner_ref="party:claims-it",
        automation_level=Claim.declared(E.IsoAutomationLevel.CONDITIONAL_AUTOMATION),
    )
    deploy = Deployment(
        id="deploy:prod",
        agent_ref="agent:claims-assistant",
        environment=Environment(kind=E.EnvironmentKind.K8S, cluster="prod-eu", namespace="claims-prod"),
        workload_ref=WorkloadRef(
            kind="Deployment", namespace="claims-prod", name="claims-assistant", uid="uid-claims-1"
        ),
    )
    server = ToolServer(
        id="server:github",
        name="github",
        kind=E.ToolServerKind.MCP,
        transport=Claim.declared(E.Transport.STDIO),
        package=Claim.declared(PackageRef(purl="pkg:npm/%40acme/github-tools@1.4.2")),
        authentication=Claim.declared(Authentication(mode=E.AuthMode.API_KEY)),
        crosses_trust_boundary=Claim.declared(True),
    )
    remote = ToolServer(
        id="server:kb",
        name="kb",
        kind=E.ToolServerKind.MCP,
        transport=Claim.declared(E.Transport.STREAMABLE_HTTP),
        endpoint=Claim.declared("https://mcp.claims.example.com/kb"),
        authentication=Claim.declared(Authentication(mode=E.AuthMode.OAUTH2)),
        crosses_trust_boundary=Claim.declared(True),
    )
    tool = ToolDefinition(
        id="tool:github/get_issue",
        server_ref="server:github",
        tool_name="get_issue",
        input_schema={"type": "object"},
        digest=DigestResult(algorithm="tooldef/v1", value=TOOL_DIGEST),
        source=E.ToolSource("declared-config"),
    )
    web = DataSource(
        id="data:public-kb",
        kind=E.DataSourceKind.RAG_INDEX,
        trust_tier=E.TrustTier.UNTRUSTED_PUBLIC,
        instruction_bearing=Claim.declared(True),
    )
    instr = Instruction(
        id="instr:agents-md",
        kind=E.InstructionKind("agents-md"),
        path="AGENTS.md",
        size=64,
        digest="sha256:" + "cd" * 32,
    )
    draft = new_document(
        subject="agent:claims-assistant",
        producer=Producer(version="0.1.0"),
        kind=E.SnapshotKind.DECLARED,
        produced_at=NOW,
        agents=[agent],
        parties=[party],
        deployments=[deploy],
        tool_servers=[server, remote],
        tools=[tool],
        data_sources=[web],
        instructions=[instr],
        edges=[
            Edge(type=E.EdgeType.PROVIDES_TOOL, **{"from": "server:github", "to": "tool:github/get_issue"}),
            Edge(
                type=E.EdgeType.READS_CONTEXT_FROM,
                **{"from": "agent:claims-assistant", "to": "data:public-kb"},
            ),
        ],
    )
    return finalize(draft, nonce=NONCE)


# --------------------------------------------------------------------------- export


def test_capability_card_carries_identity_autonomy_and_tool_digests() -> None:
    card = to_capability_card(sealed_bom())
    assert card["schema_version"] == 2
    assert card["metadata"]["agent_id"] == "agent:claims-assistant"
    assert card["metadata"]["owner_team"] == "Claims IT"
    assert card["autonomy_profile"] == {"level": 3}  # conditionalAutomation -> L3
    (tool,) = card["capability_surface"]["authorized_tools"]
    assert tool["name"] == "get_issue" and tool["provider"] == "github"
    assert tool["sha256"] == "ab" * 32  # tooldef/v1 digest, bare hex per card convention
    assert card["data_trust_zones"]["read_access"] == [{"zone": 3}]
    assert card["provenance"]["snapshot_digest"].startswith("sha256:")


def test_discovery_resources_match_the_shadowscan_loader_derivation() -> None:
    """Bindings follow ShadowScan's AgentBOM loader (PR #335): complete k8s identities approve; endpoints,
    purls and bare workload UIDs are descriptive ``component_resources`` and never approve."""
    bom = sealed_bom()
    resources = discovery_resources(bom)
    assert resources == ["k8s:prod-eu/claims-prod/Deployment/claims-assistant"]
    card = to_capability_card(bom)
    assert "https://mcp.claims.example.com/kb" in card["provenance"]["component_resources"]
    assert "pkg:npm/%40acme/github-tools@1.4.2" in card["provenance"]["component_resources"]
    assert "uid-claims-1" not in resources


def test_unknown_automation_level_exports_no_level() -> None:
    bom = sealed_bom()
    agent = bom.root_agent.replace(automation_level=Claim.unknown(E.UnknownReason.NOT_COLLECTED))
    bom = bom.model_copy(update={"agents": [agent]})
    assert declared_level(bom) is None
    assert "autonomy_profile" not in to_capability_card(bom)


def test_simple_inventory_shape() -> None:
    doc = to_simple_inventory(sealed_bom())
    (entry,) = doc["agents"]
    assert entry["id"] == "agent:claims-assistant"
    assert entry["owner"] == "Claims IT"
    assert entry["autonomy_level"] == 3
    assert entry["resources"] == ["k8s:prod-eu/claims-prod/Deployment/claims-assistant"]


# --------------------------------------------------------------------------- import


def _report() -> dict:
    return json.loads(FIXTURE.read_text())


def test_import_maps_mcp_findings_autonomy_and_coverage() -> None:
    result = import_shadowscan(_report(), agent_id="agent:claims-assistant", now=NOW)
    assert result.tool_servers, "mcp-server finding becomes an observed ToolServer stub"
    server = next(s for s in result.tool_servers if s.name == "github")
    assert server.id == "server:claude-code-github"  # same id scheme as the mcp-config collector
    assert (
        server.transport.value is E.Transport.STDIO
    )  # derived from the server's command, declared assurance
    assert server.provenance.assurance is E.AssuranceLevel.DECLARED
    assert result.automation_level is not None
    assert result.automation_level.value is E.IsoAutomationLevel.HIGH_AUTOMATION  # floor L4
    assert result.automation_level.assurance is E.AssuranceLevel.OBSERVED
    assert result.autonomy_interval is not None and result.autonomy_interval.ceiling == 5
    assert any("ceiling L5" in w for w in result.warnings)  # the interval is never dropped
    # the fixture carries no connector stats, so no surface can be called queried: unknown ≠ absent (I2)
    assert (
        Surface.CODE not in result.coverage
        or result.coverage[Surface.CODE].status is not E.CoverageStatus.QUERIED
    )
    lowcode = next(a for a in result.detail.agents if a.foreign.get("shadowscan:surface") == "lowcode")
    assert lowcode.role is E.AgentRole.EXTERNAL_AGENT  # a lowcode agent is an estate agent, not force-fitted
    assert result.evidence and result.evidence[0].evidence_kind is E.EvidenceKind.SCAN_REPORT
    assert any(p.name == "shadow" for p in result.foreign_properties)


def test_import_models_become_unpinned_hosted_stubs() -> None:
    report = _report()
    report["findings"][0]["models"] = ["gpt-4o"]
    report["findings"][0]["model_providers"] = ["provider.openai"]
    result = import_shadowscan(report, now=NOW)
    model = next(m for m in result.models if m.name == "gpt-4o")
    assert model.hosted is not None
    hosted = model.hosted.value
    assert hosted.requested_ref == "gpt-4o" and hosted.provider == "openai"
    assert hosted.resolved_ref.is_unknown  # a scan sees names, never snapshots


def test_malformed_model_providers_fail_closed_with_a_typed_error() -> None:
    """Hostile shapes must neither corrupt provider identity (string indexing
    yielded 'o') nor escape as KeyError: the strict reader rejects them."""
    report = _report()
    report["findings"][0]["models"] = ["gpt-4o"]
    for bad in ("openai", {"a": 1}, [None, ""], 7):
        report["findings"][0]["model_providers"] = bad
        with pytest.raises(ShadowScanImportError, match="model_providers"):
            import_shadowscan(report, now=NOW)


def test_inverted_autonomy_interval_is_rejected_not_exported() -> None:
    """ceiling < floor is contradictory evidence: it must never be stored or
    exported as an observed L5 — the interval is dropped."""
    report = _report()
    for finding in report["findings"]:
        finding.get("metadata", {}).pop("autonomy", None)
    report["findings"][0].setdefault("metadata", {})["autonomy"] = {"floor": 5, "ceiling": 0}
    result = import_shadowscan(report, now=NOW)
    assert result.autonomy_interval is None
    assert result.automation_level is None


def test_selector_filters_findings() -> None:
    result = import_shadowscan(_report(), selector=lambda f: f.get("kind") == "mcp-server", now=NOW)
    assert result.tool_servers
    # The excluded agent finding carried the L4 interval; only the mcp-server
    # finding's own, lower floor remains.
    assert result.automation_level is not None
    assert result.automation_level.value is E.IsoAutomationLevel.PARTIAL_AUTOMATION
    assert result.autonomy_interval is not None and result.autonomy_interval.floor == 2


def test_non_report_input_fails_closed() -> None:
    with pytest.raises(ShadowScanImportError):
        import_shadowscan({"hello": "world"})
