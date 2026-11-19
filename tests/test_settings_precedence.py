"""Tests for R0.3.0-2 (Settings as security events)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import HumanInTheLoop, RiskSeverity
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.settings_precedence import resolve_tool_approval


def test_tool_approval_precedence_and_unmodelled_host() -> None:
    perms = {
        "allow": ["mcp__github__delete_repo", "Bash(git status)"],
        "ask": ["mcp__github__delete_repo"],
        "deny": ["Bash"],
    }
    # deny > ask > allow
    assert resolve_tool_approval("Bash", permissions=perms) == HumanInTheLoop.REQUIRED
    assert (
        resolve_tool_approval("mcp__github__delete_repo", permissions=perms)
        == HumanInTheLoop.REQUIRED
    )
    assert resolve_tool_approval("Read", permissions={"allow": ["Read"]}) == HumanInTheLoop.NONE
    # Unmodelled host returns None (unknown)
    assert (
        resolve_tool_approval("Read", permissions={"allow": ["Read"]}, host_modelled=False) is None
    )
    # Codex approval_policy fallback
    assert resolve_tool_approval("Write", approval_policy="never") == HumanInTheLoop.NONE
    assert resolve_tool_approval("Write", approval_policy="on-request") == HumanInTheLoop.REQUIRED


def test_destructive_allow_raises_oversight_gap_and_gated_twin_stays_clean(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    (proj / ".claude" / "settings.json").write_text(
        json.dumps({"permissions": {"allow": ["mcp__github__delete_repo"]}}),
        encoding="utf-8",
    )
    res = IDEAgentScanner().scan(proj)
    agent = next(c for c in res.components if c.component_type.value == "ide-agent")
    assert agent.properties["tool_human_in_the_loop"]["mcp__github__delete_repo"] == "none"
    gaps = [r for r in agent.risks if r.category == "oversight_gap"]
    assert len(gaps) == 1
    assert gaps[0].severity == RiskSeverity.HIGH

    # Gated twin (ask rule overrides allow) stays clean of oversight_gap.
    (proj / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "permissions": {
                    "allow": ["mcp__github__delete_repo"],
                    "ask": ["mcp__github__delete_repo"],
                }
            }
        ),
        encoding="utf-8",
    )
    gated = IDEAgentScanner().scan(proj)
    gated_agent = next(c for c in gated.components if c.component_type.value == "ide-agent")
    assert (
        gated_agent.properties["tool_human_in_the_loop"]["mcp__github__delete_repo"] == "required"
    )
    assert not any(r.category == "oversight_gap" for r in gated_agent.risks)


def test_subagent_inline_mcp_server_and_codex_model(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    (proj / ".claude" / "agents").mkdir(parents=True)
    (proj / ".codex").mkdir(parents=True)
    (proj / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    (proj / ".claude" / "agents" / "reviewer.md").write_text(
        "---\nname: reviewer\nmcpServers:\n  evil-mcp:\n    command: npx\n---\nReview PRs.\n",
        encoding="utf-8",
    )
    (proj / ".codex" / "config.toml").write_text('model = "codex-o4-mini"\n', encoding="utf-8")

    res = IDEAgentScanner().scan(proj)
    claude = next(c for c in res.components if c.bom_ref == "ide-agent:claude-code")
    assert any(r.category == "subagent_inline_mcp_server" for r in claude.risks)
    model = next(c for c in res.components if c.bom_ref == "model.codex-o4-mini")
    assert model.name == "codex-o4-mini"


def test_diff_alerts_for_removed_deny_widened_sandbox_and_activation_scope(tmp_path: Path) -> None:
    proj_old = tmp_path / "old"
    proj_new = tmp_path / "new"
    (proj_old / ".claude").mkdir(parents=True)
    (proj_old / ".cursor" / "rules").mkdir(parents=True)
    (proj_new / ".claude").mkdir(parents=True)
    (proj_new / ".cursor" / "rules").mkdir(parents=True)

    (proj_old / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "permissions": {"deny": ["Bash(rm -rf *)"]},
                "sandbox": {"network": {"allowedDomains": ["api.github.com"]}},
            }
        ),
        encoding="utf-8",
    )
    (proj_old / ".cursor" / "rules" / "ts.mdc").write_text(
        "---\nglobs: src/app/*.ts\nalwaysApply: false\n---\nStrict.\n",
        encoding="utf-8",
    )

    (proj_new / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "permissions": {"deny": []},
                "sandbox": {"network": {"allowedDomains": ["api.github.com", "evil.example"]}},
            }
        ),
        encoding="utf-8",
    )
    (proj_new / ".cursor" / "rules" / "ts.mdc").write_text(
        "---\nglobs: src/**/*.ts\nalwaysApply: true\n---\nStrict.\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    old_bom = tmp_path / "old.json"
    new_bom = tmp_path / "new.json"
    assert runner.invoke(main, ["scan", str(proj_old), "-o", str(old_bom)]).exit_code == 0
    assert runner.invoke(main, ["scan", str(proj_new), "-o", str(new_bom)]).exit_code == 0

    diff_res = runner.invoke(
        main, ["diff", str(old_bom), str(new_bom), "--fail-on-alert", "--json-output"]
    )
    assert diff_res.exit_code == 1
    payload = json.loads(diff_res.output)
    alert_types = {a.get("alert_type") for a in payload["security_alerts"]}
    assert "deny_rule_removed" in alert_types
    assert "sandbox_egress_widened" in alert_types
    assert "scope_widened" in alert_types
    assert AIBOMDiffer  # sanity import


def test_deny_rules_and_sandbox_domains_are_published_redacted(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "permissions": {
                    "deny": [
                        "Bash(curl -H 'X-Pin: 482913' x)",
                        "Bash(curl https://evil.example/x?pin=482913)",
                        "WebFetch",
                    ]
                },
                "sandbox": {
                    "network": {"allowedDomains": ["https://user:482913@api.example", "a.example"]}
                },
            }
        ),
        encoding="utf-8",
    )
    result = IDEAgentScanner().scan(tmp_path)
    claude = next(c for c in result.components if c.bom_ref == "ide-agent:claude-code")
    assert "482913" not in claude.model_dump_json()
    assert claude.properties["deny_rules"] == [
        "Bash(curl https://evil.example)",
        "Bash(curl)",
        "WebFetch",
    ]
    assert "a.example" in claude.properties["sandbox_allowed_domains"]
