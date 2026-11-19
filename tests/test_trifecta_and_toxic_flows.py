"""Tests for lethal-trifecta, chained toxic-flow, and tool-shadowing analysis (Items 15 & 24)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    CapabilityClass,
    HumanInTheLoop,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.models import (
    AgentComponent,
    AuthorizationRecord,
    CapabilityDeclaration,
    IDEAgentComponent,
    MCPServerComponent,
    ToolComponent,
)
from nexus_symbiote.trifecta import analyze_trifecta


def _trifecta_bom(*, gated: bool = False, partial_gate: bool = False) -> AIBOM:
    """Build an agent with untrusted input, private data, and egress (plus gated twin)."""
    hitl_egress = HumanInTheLoop.REQUIRED if gated else HumanInTheLoop.NONE
    fetch_tool = ToolComponent(
        bom_ref="tool:web-fetch",
        name="web_fetch",
        mcp_server_ref="mcp:browser",
        description="Fetch arbitrary external web pages",
        source_path="mcp.json",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.READ],
            human_in_the_loop=HumanInTheLoop.NONE,
        ),
    )
    secret_tool = ToolComponent(
        bom_ref="tool:read-secrets",
        name="read_secret",
        mcp_server_ref="mcp:vault",
        description="Read local credentials and private files",
        source_path="mcp.json",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.FILESYSTEM, CapabilityClass.CREDENTIALS],
            filesystem_paths=["/etc/app/secrets"],
            human_in_the_loop=HumanInTheLoop.NONE,
        ),
    )
    egress_tool = ToolComponent(
        bom_ref="tool:send-webhook",
        name="send_webhook",
        mcp_server_ref="mcp:notify",
        description="Send outbound HTTP notifications",
        source_path="mcp.json",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.WRITE],
            egress_domains=["hooks.example.com"],
            side_effect_profile=SideEffectProfile.STATE_MODIFYING,
            human_in_the_loop=hitl_egress,
        ),
    )
    components = [fetch_tool, secret_tool, egress_tool]
    tool_refs = [fetch_tool.bom_ref, secret_tool.bom_ref, egress_tool.bom_ref]
    if partial_gate:
        second_egress = ToolComponent(
            bom_ref="tool:post-slack",
            name="post_slack",
            mcp_server_ref="mcp:notify",
            source_path="mcp.json",
            capabilities=CapabilityDeclaration(
                capabilities=[CapabilityClass.NETWORK],
                egress_domains=["slack.example.com"],
                human_in_the_loop=None,  # unknown -> fail closed
            ),
        )
        components.append(second_egress)
        tool_refs.append(second_egress.bom_ref)

    agent = AgentComponent(
        bom_ref="agent:support",
        name="support-agent",
        tool_refs=tool_refs,
        capabilities=CapabilityDeclaration(
            human_in_the_loop=HumanInTheLoop.REQUIRED if (gated and not partial_gate) else None,
        ),
    )
    return AIBOM(components=[agent, *components])


def test_lethal_trifecta_ungated_is_critical():
    report = analyze_trifecta(_trifecta_bom(gated=False))
    assert report.has_critical
    trifecta = [f for f in report.findings if f.kind == "lethal_trifecta"]
    assert len(trifecta) == 1
    assert trifecta[0].severity is RiskSeverity.CRITICAL
    assert set(trifecta[0].component_refs) == {
        "tool:web-fetch",
        "tool:read-secrets",
        "tool:send-webhook",
    }
    legs = {e["leg"] for e in trifecta[0].evidence}
    assert legs == {"untrusted_input", "private_data", "egress"}


def test_lethal_trifecta_gated_twin_stays_clean():
    report = analyze_trifecta(_trifecta_bom(gated=True))
    assert not report.has_critical
    assert [f for f in report.findings if f.kind == "lethal_trifecta"] == []
    assert [f for f in report.findings if f.kind == "toxic_flow"] == []


def test_lethal_trifecta_partial_gate_still_fails_closed():
    report = analyze_trifecta(_trifecta_bom(gated=True, partial_gate=True))
    assert report.has_critical
    trifecta = [f for f in report.findings if f.kind == "lethal_trifecta"]
    assert len(trifecta) == 1
    assert "tool:post-slack" in trifecta[0].component_refs


def test_authorization_record_approval_gates_agent():
    bom = _trifecta_bom(gated=False)
    agent = next(c for c in bom.components if isinstance(c, AgentComponent))
    agent.authorizations = [
        AuthorizationRecord(principal="user:alice", action="egress", approval_required=True)
    ]
    report = analyze_trifecta(bom)
    assert not report.has_critical


def test_ide_agent_bypass_permissions_triggers_trifecta_while_default_mode_gates():
    server = MCPServerComponent(
        bom_ref="mcp:remote",
        name="remote-mcp",
        endpoint_url="https://remote.example.com/mcp",
        env={"API_TOKEN": "[redacted]"},
    )
    ungated_ide = IDEAgentComponent(
        bom_ref="ide:claude-ungated",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="bypassPermissions",
    )
    gated_ide = IDEAgentComponent(
        bom_ref="ide:claude-gated",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="default",
    )
    assert analyze_trifecta(AIBOM(components=[ungated_ide, server])).has_critical
    assert not analyze_trifecta(AIBOM(components=[gated_ide, server])).has_critical


def test_chained_toxic_flow_two_tools_is_one_finding():
    # Tool A only reads private files (not exfil-capable alone).
    reader = ToolComponent(
        bom_ref="tool:read-customer-db",
        name="query_db",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.FILESYSTEM],
            filesystem_paths=["/var/data/customers.sqlite"],
        ),
    )
    # Tool B only sends network egress (not exfil-capable alone).
    sender = ToolComponent(
        bom_ref="tool:send-report",
        name="send_report",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK],
            egress_domains=["reports.example.org"],
        ),
    )
    bom = AIBOM(components=[reader, sender])
    report = analyze_trifecta(bom)
    toxic = [f for f in report.findings if f.kind == "toxic_flow"]
    assert len(toxic) == 1
    assert toxic[0].severity is RiskSeverity.HIGH
    assert set(toxic[0].component_refs) == {"tool:read-customer-db", "tool:send-report"}

    # Gated twin: adding approval gate on the sink tool clears the toxic flow.
    sender.capabilities = CapabilityDeclaration(
        capabilities=[CapabilityClass.NETWORK],
        egress_domains=["reports.example.org"],
        human_in_the_loop=HumanInTheLoop.REQUIRED,
    )
    clean_report = analyze_trifecta(bom)
    assert [f for f in clean_report.findings if f.kind == "toxic_flow"] == []


def test_tool_shadowing_detects_lookalike_and_trust_escalation():
    trusted = ToolComponent(
        bom_ref="tool:internal-lookup",
        name="lookup_ticket",
        mcp_server_ref="mcp:internal",
        source_path="internal/mcp.json",
        trust_tier=TrustTier.INTERNAL_VERIFIED,
        assurance_level=AssuranceLevel.OBSERVED,
    )
    # Zero-width space + hyphen lookalike from an untrusted third-party server.
    shadow = ToolComponent(
        bom_ref="tool:thirdparty-lookup",
        name="lookup\u200b-ticket",
        mcp_server_ref="mcp:thirdparty",
        source_path="thirdparty/mcp.json",
        trust_tier=TrustTier.UNTRUSTED_PUBLIC,
        assurance_level=AssuranceLevel.DECLARED,
    )
    report = analyze_trifecta(AIBOM(components=[trusted, shadow]))
    shadow_findings = [f for f in report.findings if f.kind == "tool_shadowing"]
    assert len(shadow_findings) == 1
    assert shadow_findings[0].severity is RiskSeverity.HIGH
    assert set(report.shadowed_refs) == {"tool:internal-lookup", "tool:thirdparty-lookup"}


def test_trifecta_cli_gate_and_determinism(tmp_path):
    ungated_path = tmp_path / "ungated.json"
    gated_path = tmp_path / "gated.json"
    bom_ungated = _trifecta_bom(gated=False)
    bom_ungated.save(ungated_path)
    _trifecta_bom(gated=True).save(gated_path)

    runner = CliRunner()
    res_fail = runner.invoke(main, ["trifecta", str(ungated_path)])
    assert res_fail.exit_code == 1
    payload_1 = json.loads(res_fail.output)
    assert payload_1["severity_counts"]["critical"] == 1

    # Reversed component order must produce byte-identical JSON.
    reversed_path = tmp_path / "ungated_rev.json"
    AIBOM(components=list(reversed(bom_ungated.components))).save(reversed_path)
    res_rev = runner.invoke(main, ["trifecta", str(reversed_path)])
    assert res_rev.exit_code == 1
    assert res_rev.output == res_fail.output

    res_pass = runner.invoke(main, ["trifecta", str(gated_path)])
    assert res_pass.exit_code == 0
    assert json.loads(res_pass.output)["finding_count"] == 0
