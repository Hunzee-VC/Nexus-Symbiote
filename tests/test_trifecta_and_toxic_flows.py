"""Tests for lethal-trifecta, chained toxic-flow, and tool-shadowing analysis (Items 15 & 24)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
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
    PromptComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.trifecta import analyze_trifecta, canonical_tool_name


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
            side_effect_profile=SideEffectProfile.READ_ONLY,
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


def test_lethal_trifecta_ungated_is_critical() -> None:
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


def test_lethal_trifecta_gated_twin_stays_clean() -> None:
    report = analyze_trifecta(_trifecta_bom(gated=True))
    assert not report.has_critical
    assert [f for f in report.findings if f.kind == "lethal_trifecta"] == []
    assert [f for f in report.findings if f.kind == "toxic_flow"] == []


def test_lethal_trifecta_partial_gate_still_fails_closed() -> None:
    report = analyze_trifecta(_trifecta_bom(gated=True, partial_gate=True))
    assert report.has_critical
    trifecta = [f for f in report.findings if f.kind == "lethal_trifecta"]
    assert len(trifecta) == 1
    assert "tool:post-slack" in trifecta[0].component_refs


def test_explicit_none_on_egress_tool_overrides_agent_gate() -> None:
    bom = _trifecta_bom(gated=True)
    egress = next(c for c in bom.components if c.bom_ref == "tool:send-webhook")
    assert isinstance(egress, ToolComponent) and egress.capabilities is not None
    egress.capabilities.human_in_the_loop = HumanInTheLoop.NONE
    report = analyze_trifecta(bom)
    assert report.has_critical


def test_authorization_record_approval_gates_agent() -> None:
    bom = _trifecta_bom(gated=False)
    # Remove explicit NONE override on the egress tool so agent-level authorization governs it.
    egress = next(c for c in bom.components if c.bom_ref == "tool:send-webhook")
    assert isinstance(egress, ToolComponent) and egress.capabilities is not None
    egress.capabilities.human_in_the_loop = None
    agent = next(c for c in bom.components if isinstance(c, AgentComponent))
    agent.authorizations = [
        AuthorizationRecord(principal="user:alice", action="egress", approval_required=True)
    ]
    report = analyze_trifecta(bom)
    assert not report.has_critical


def test_real_scan_output_triggers_critical_trifecta(tmp_path: Path) -> None:
    """End-to-end: real `scan` on .mcp.json + .claude/settings.json fires critical trifecta."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fetch": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-fetch"],
                    },
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                    },
                    "slack": {"url": "https://mcp.slack.example.com/sse"},
                }
            }
        ),
        encoding="utf-8",
    )
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(
        json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}),
        encoding="utf-8",
    )

    bom_path = tmp_path / "bom.json"
    runner = CliRunner()
    scan_res = runner.invoke(main, ["scan", str(tmp_path), "-o", str(bom_path)])
    assert scan_res.exit_code == 0

    res = runner.invoke(main, ["trifecta", str(bom_path)])
    assert res.exit_code == 1
    payload = json.loads(res.output)
    assert payload["severity_counts"]["critical"] >= 1
    trifecta_findings = [f for f in payload["findings"] if f["kind"] == "lethal_trifecta"]
    assert len(trifecta_findings) == 1
    legs = {e["leg"] for e in trifecta_findings[0]["evidence"]}
    assert legs == {"untrusted_input", "private_data", "egress"}


def test_real_scan_default_mode_with_allow_rules_does_not_clear_trifecta(tmp_path: Path) -> None:
    """Static defaultMode: default with allow rules must not silence a trifecta."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fetch": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-fetch"],
                    },
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                    },
                    "slack": {"url": "https://mcp.slack.example.com/sse"},
                }
            }
        ),
        encoding="utf-8",
    )
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(
        json.dumps(
            {
                "permissions": {
                    "defaultMode": "default",
                    "allow": ["Bash(*)", "WebFetch(*)"],
                }
            }
        ),
        encoding="utf-8",
    )

    bom_path = tmp_path / "bom.json"
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(tmp_path), "-o", str(bom_path)]).exit_code == 0
    res = runner.invoke(main, ["trifecta", str(bom_path)])
    assert res.exit_code == 1
    assert json.loads(res.output)["severity_counts"]["critical"] >= 1


def test_real_scan_benign_http_docs_and_time_server_with_tz_env_is_clean(tmp_path: Path) -> None:
    """Benign MCP env (TZ=UTC) beside an HTTP docs server must NOT trigger a false critical."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "docs": {"url": "https://docs.example.com/mcp"},
                    "time": {
                        "command": "npx",
                        "args": ["-y", "mcp-server-time"],
                        "env": {"TZ": "UTC", "LANG": "C.UTF-8"},
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    bom_path = tmp_path / "bom.json"
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(tmp_path), "-o", str(bom_path)]).exit_code == 0
    res = runner.invoke(main, ["trifecta", str(bom_path)])
    assert res.exit_code == 0
    assert json.loads(res.output)["finding_count"] == 0


def test_real_scan_secret_env_beside_http_server_is_critical(tmp_path: Path) -> None:
    """Credential-named MCP env var beside a remote HTTP server fires critical."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "docs": {"url": "https://docs.example.com/mcp"},
                    "helper": {
                        "command": "npx",
                        "args": ["-y", "mcp-server-time"],
                        "env": {"OPENAI_API_KEY": "placeholder-value"},
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    bom_path = tmp_path / "bom.json"
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(tmp_path), "-o", str(bom_path)]).exit_code == 0
    res = runner.invoke(main, ["trifecta", str(bom_path)])
    assert res.exit_code == 1
    assert json.loads(res.output)["severity_counts"]["critical"] == 1


def test_readonly_web_search_and_read_file_is_not_critical() -> None:
    """An agent with only web_search and read-only read_file has no egress/mutation leg."""
    web_search = ToolComponent(
        bom_ref="tool:web-search",
        name="web_search",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.READ],
            side_effect_profile=SideEffectProfile.READ_ONLY,
        ),
    )
    read_file = ToolComponent(
        bom_ref="tool:read-file",
        name="read_file",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.FILESYSTEM, CapabilityClass.READ],
            side_effect_profile=SideEffectProfile.READ_ONLY,
        ),
    )
    agent = AgentComponent(
        bom_ref="agent:researcher",
        name="researcher",
        tool_refs=["tool:web-search", "tool:read-file"],
    )
    report = analyze_trifecta(AIBOM(components=[agent, web_search, read_file]))
    assert not report.has_critical
    assert report.findings == ()


def test_hostile_inventory_properties_cannot_clear_trifecta() -> None:
    """Ad-hoc untrusted properties (requires_approval, approval_gate) cannot clear the gate."""
    bom = _trifecta_bom(gated=False)
    for comp in bom.components:
        comp.properties["requires_approval"] = True
        comp.properties["approval_gate"] = True
        comp.properties["human_in_the_loop"] = "required"
    report = analyze_trifecta(bom)
    assert report.has_critical


def test_ide_agent_gating_requires_verified_authorization_without_allow_rules() -> None:
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
    unverified_default = IDEAgentComponent(
        bom_ref="ide:claude-default-static",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="default",
        assurance_level=AssuranceLevel.DECLARED,
        properties={"effective_authorization_verified": False},
    )
    default_with_allow = IDEAgentComponent(
        bom_ref="ide:claude-default-allow",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="default",
        assurance_level=AssuranceLevel.VERIFIED,
        properties={
            "effective_authorization_verified": True,
            "declared_permission_rule_counts": {"allow": 1, "ask": 0, "deny": 0},
        },
    )
    default_with_risk = IDEAgentComponent(
        bom_ref="ide:claude-default-risk",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="default",
        assurance_level=AssuranceLevel.VERIFIED,
        properties={
            "effective_authorization_verified": True,
            "declared_permission_rule_counts": {"allow": 0, "ask": 0, "deny": 0},
        },
        risks=[
            RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category="permission_scope",
                detail="Unscoped tool allowance",
            )
        ],
    )
    verified_gated = IDEAgentComponent(
        bom_ref="ide:claude-verified",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="default",
        assurance_level=AssuranceLevel.VERIFIED,
        properties={
            "effective_authorization_verified": True,
            "declared_permission_rule_counts": {"allow": 0, "ask": 0, "deny": 0},
        },
    )

    assert analyze_trifecta(AIBOM(components=[ungated_ide, server])).has_critical
    assert analyze_trifecta(AIBOM(components=[unverified_default, server])).has_critical
    assert analyze_trifecta(AIBOM(components=[default_with_allow, server])).has_critical
    assert analyze_trifecta(AIBOM(components=[default_with_risk, server])).has_critical
    assert not analyze_trifecta(AIBOM(components=[verified_gated, server])).has_critical


def test_ide_agent_with_prompt_edge_still_covers_workspace_mcp_servers() -> None:
    """An IDE agent in bypassPermissions with a single edge to a prompt still catches MCP risks."""
    ide = IDEAgentComponent(
        bom_ref="ide:claude",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="bypassPermissions",
    )
    prompt = PromptComponent(bom_ref="prompt:claude-md", name="CLAUDE.md")
    server = MCPServerComponent(
        bom_ref="mcp:remote",
        name="remote-mcp",
        endpoint_url="https://remote.example.com/mcp",
        env={"API_TOKEN": "***"},
    )
    bom = AIBOM(
        components=[ide, prompt, server],
        dependencies=[
            DependencyEdge(
                source_ref="ide:claude",
                target_ref="prompt:claude-md",
                relationship="reads-instructions",
            )
        ],
    )
    report = analyze_trifecta(bom)
    assert report.has_critical


def test_empty_agent_cannot_hide_unlinked_tools() -> None:
    """An AgentComponent with no tool_refs must not drop unlinked tools from evaluation."""
    dummy = AgentComponent(bom_ref="agent:empty", name="empty", tool_refs=[])
    t_in = ToolComponent(bom_ref="tool:in", name="fetch_url")
    t_priv = ToolComponent(bom_ref="tool:priv", name="read_secret")
    t_out = ToolComponent(
        bom_ref="tool:out",
        name="post_slack",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.WRITE]
        ),
    )
    report = analyze_trifecta(AIBOM(components=[dummy, t_in, t_priv, t_out]))
    assert report.has_critical
    assert any(f.scope_ref == "inventory:unscoped" for f in report.findings)


@pytest.mark.parametrize(
    ("input_name", "private_name"),
    [
        ("fetch_url", "read_secret"),
        ("fetchUrl", "readSecrets"),
        ("WebFetch", "FileRead"),
        ("get_url", "cat_file"),
        ("f\u0435tch", "read_secret"),  # Cyrillic small letter ie
        ("f\u0435tchUrl", "r\u0435adSecrets"),
    ],
)
def test_naming_evasion_variants_are_caught_without_capabilities(
    input_name: str,
    private_name: str,
) -> None:
    t_in = ToolComponent(bom_ref="tool:in", name=input_name)
    t_priv = ToolComponent(bom_ref="tool:priv", name=private_name)
    t_out = ToolComponent(
        bom_ref="tool:out",
        name="post_slack",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.WRITE]
        ),
    )
    report = analyze_trifecta(AIBOM(components=[t_in, t_priv, t_out]))
    assert report.has_critical
    trifecta = [f for f in report.findings if f.kind == "lethal_trifecta"]
    assert len(trifecta) == 1
    assert set(trifecta[0].component_refs) == {"tool:in", "tool:priv", "tool:out"}


def test_chained_toxic_flow_two_tools_is_one_finding() -> None:
    reader = ToolComponent(
        bom_ref="tool:read-customer-db",
        name="query_db",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.FILESYSTEM],
            filesystem_paths=["/var/data/customers.sqlite"],
        ),
    )
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

    sender.capabilities = CapabilityDeclaration(
        capabilities=[CapabilityClass.NETWORK],
        egress_domains=["reports.example.org"],
        human_in_the_loop=HumanInTheLoop.REQUIRED,
    )
    clean_report = analyze_trifecta(bom)
    assert [f for f in clean_report.findings if f.kind == "toxic_flow"] == []


def test_tool_shadowing_detects_camelcase_zwsp_and_homoglyphs() -> None:
    trusted = ToolComponent(
        bom_ref="tool:internal-lookup",
        name="lookup_ticket",
        mcp_server_ref="mcp:internal",
        source_path="internal/mcp.json",
        trust_tier=TrustTier.INTERNAL_VERIFIED,
        assurance_level=AssuranceLevel.OBSERVED,
    )
    shadow_zwsp = ToolComponent(
        bom_ref="tool:thirdparty-zwsp",
        name="lookup\u200b-ticket",
        mcp_server_ref="mcp:thirdparty-1",
        source_path="thirdparty/mcp1.json",
        trust_tier=TrustTier.UNTRUSTED_PUBLIC,
    )
    shadow_camel = ToolComponent(
        bom_ref="tool:thirdparty-camel",
        name="lookupTicket",
        mcp_server_ref="mcp:thirdparty-2",
        source_path="thirdparty/mcp2.json",
        trust_tier=TrustTier.UNTRUSTED_PUBLIC,
    )
    shadow_cyrillic = ToolComponent(
        bom_ref="tool:thirdparty-cyrillic",
        name="l\u043e\u043ekup_ticket",  # Cyrillic small letter o
        mcp_server_ref="mcp:thirdparty-3",
        source_path="thirdparty/mcp3.json",
        trust_tier=TrustTier.UNTRUSTED_PUBLIC,
    )
    assert canonical_tool_name("lookupTicket") == "lookup_ticket"
    assert canonical_tool_name("l\u043e\u043ekup_ticket") == "lookup_ticket"

    report = analyze_trifecta(
        AIBOM(components=[trusted, shadow_zwsp, shadow_camel, shadow_cyrillic])
    )
    shadow_findings = [f for f in report.findings if f.kind == "tool_shadowing"]
    assert len(shadow_findings) == 1
    assert shadow_findings[0].severity is RiskSeverity.HIGH
    assert set(report.shadowed_refs) == {
        "tool:internal-lookup",
        "tool:thirdparty-zwsp",
        "tool:thirdparty-camel",
        "tool:thirdparty-cyrillic",
    }


def test_trifecta_linear_time_on_large_tool_set_and_agent_graphs() -> None:
    """2,000+2,000 tools, a 2,000-agent cycle, and an alternating-gate chain stay linear."""
    tools = [
        ToolComponent(bom_ref=f"tool:priv-{i}", name=f"read_secret_{i}") for i in range(2000)
    ] + [
        ToolComponent(
            bom_ref=f"tool:sink-{i}",
            name=f"send_report_{i}",
            capabilities=CapabilityDeclaration(
                capabilities=[CapabilityClass.NETWORK],
                egress_domains=["reports.example.org"],
            ),
        )
        for i in range(2000)
    ]
    t0 = time.perf_counter()
    report_tools = analyze_trifecta(AIBOM(components=tools))
    assert time.perf_counter() - t0 < 2.0
    assert any(f.kind == "toxic_flow" for f in report_tools.findings)

    t_in = ToolComponent(bom_ref="tool:in", name="fetch_url")
    t_priv = ToolComponent(bom_ref="tool:priv", name="read_secret")
    t_out = ToolComponent(
        bom_ref="tool:out",
        name="post_slack",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.NETWORK, CapabilityClass.WRITE]
        ),
    )
    cycle_agents = [
        AgentComponent(
            bom_ref=f"agent:c{i}",
            name=f"c{i}",
            sub_agent_refs=[f"agent:c{(i + 1) % 2000}"],
        )
        for i in range(2000)
    ]
    cycle_agents[0].tool_refs = ["tool:in", "tool:priv", "tool:out"]
    t1 = time.perf_counter()
    report_cycle = analyze_trifecta(AIBOM(components=[*cycle_agents, t_in, t_priv, t_out]))
    assert time.perf_counter() - t1 < 1.5
    assert report_cycle.has_critical

    chain_agents = [
        AgentComponent(
            bom_ref=f"agent:k{i}",
            name=f"k{i}",
            sub_agent_refs=[f"agent:k{i + 1}"] if i < 1999 else [],
            capabilities=CapabilityDeclaration(
                human_in_the_loop=HumanInTheLoop.REQUIRED if i % 2 == 0 else None
            ),
        )
        for i in range(2000)
    ]
    chain_agents[-1].tool_refs = ["tool:in", "tool:priv", "tool:out"]
    t2 = time.perf_counter()
    report_chain = analyze_trifecta(AIBOM(components=[*chain_agents, t_in, t_priv, t_out]))
    assert time.perf_counter() - t2 < 1.5
    assert report_chain.has_critical


def test_trifecta_cli_gate_and_determinism(tmp_path: Path) -> None:
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
