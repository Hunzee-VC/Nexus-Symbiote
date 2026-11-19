"""Tests for execution-bound VEX, operator VEX decisions with expiry, and advisory linkage (Item 23 & N5)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RegistryEntryComponent, RiskAssessment, ToolComponent
from nexus_symbiote.generators.vex import VEXGenerator, finding_id
from nexus_symbiote.vex_decisions import (
    VEXDecisionError,
    load_execution_evidence,
    load_vex_decisions,
)


def _three_component_bom() -> AIBOM:
    risk = RiskAssessment(
        severity=RiskSeverity.HIGH,
        category="unpinned_tool",
        detail="Tool definition is unpinned",
        recommendation="Pin the tool definition digest.",
    )
    return AIBOM(
        components=[
            ToolComponent(bom_ref="tool:never-loaded", name="never_loaded", risks=[risk]),
            ToolComponent(bom_ref="tool:invoked", name="invoked_tool", risks=[risk]),
            ToolComponent(bom_ref="tool:shadowed", name="shadowed_tool", risks=[risk]),
        ]
    )


def test_execution_bound_vex_yields_three_distinct_outcomes(tmp_path):
    bom = _three_component_bom()
    trace_file = tmp_path / "trace-evidence.json"
    trace_file.write_text(
        json.dumps(
            {
                "matched": [{"bom_ref": "tool:invoked"}],
                "unobserved": [{"bom_ref": "tool:never-loaded"}],
                "shadowed": [{"bom_ref": "tool:shadowed"}],
            }
        ),
        encoding="utf-8",
    )
    evidence = load_execution_evidence(trace_file)
    doc = VEXGenerator(execution_evidence=evidence).generate(bom)

    by_comp = {v["affects"][0]["ref"]: v for v in doc["vulnerabilities"]}
    assert set(by_comp.keys()) == {"tool:never-loaded", "tool:invoked", "tool:shadowed"}

    # 1. Declared-never-loaded -> not_affected + code_not_reachable
    never = by_comp["tool:never-loaded"]["analysis"]
    assert never["state"] == "not_affected"
    assert never["justification"] == "code_not_reachable"
    assert "never observed" in never["detail"]

    # 2. Invoked -> exploitable + update response
    invoked = by_comp["tool:invoked"]["analysis"]
    assert invoked["state"] == "exploitable"
    assert invoked["response"] == ["update"]
    assert "invoked" in invoked["detail"]

    # 3. Shadowed -> in_triage + explicit shadowing reason
    shadowed = by_comp["tool:shadowed"]["analysis"]
    assert shadowed["state"] == "in_triage"
    assert "shadowed" in shadowed["detail"]


def test_operator_vex_decisions_active_and_expired_reverts_to_in_triage(tmp_path):
    bom = _three_component_bom()
    fid_active = finding_id("tool:never-loaded", "unpinned_tool", "Tool definition is unpinned")
    fid_expired = finding_id("tool:invoked", "unpinned_tool", "Tool definition is unpinned")

    decisions_file = tmp_path / "vex-decisions.yaml"
    decisions_file.write_text(
        f"""version: 1
decisions:
  - id: "{fid_active}"
    component_ref: "tool:never-loaded"
    state: "not_affected"
    justification: "protected_at_runtime"
    detail: "Blocked by gateway policy"
    owner: "secops@example.com"
    expires_at: "2027-01-01T00:00:00Z"
  - id: "{fid_expired}"
    component_ref: "tool:invoked"
    state: "resolved"
    detail: "Previously patched in staging"
    owner: "secops@example.com"
    expires_at: "2026-01-01T00:00:00Z"
""",
        encoding="utf-8",
    )
    loaded = load_vex_decisions(decisions_file)
    ref_time = datetime(2026, 11, 19, 0, 0, tzinfo=UTC)
    doc = VEXGenerator(decisions=loaded, reference_time=ref_time).generate(bom)

    by_comp = {v["affects"][0]["ref"]: v for v in doc["vulnerabilities"]}
    active_analysis = by_comp["tool:never-loaded"]["analysis"]
    assert active_analysis["state"] == "not_affected"
    assert active_analysis["justification"] == "protected_at_runtime"
    assert "secops@example.com" in active_analysis["detail"]

    expired_analysis = by_comp["tool:invoked"]["analysis"]
    assert expired_analysis["state"] == "in_triage"
    assert "Expired operator VEX decision" in expired_analysis["detail"]
    assert "justification" not in expired_analysis

    meta_props = {p["name"]: p["value"] for p in doc["metadata"].get("properties", [])}
    assert meta_props["nexus-symbiote:expiredVexDecisions"] == "1"


def test_vex_decisions_refuses_file_inside_project_root_and_symlinks(tmp_path):
    project_dir = tmp_path / "repo"
    project_dir.mkdir()
    inside_file = project_dir / "decisions.yaml"
    inside_file.write_text("version: 1\ndecisions: []\n", encoding="utf-8")

    with pytest.raises(VEXDecisionError, match="outside the scanned project"):
        load_vex_decisions(inside_file, project_root=project_dir)

    outside_file = tmp_path / "outside.yaml"
    outside_file.write_text("version: 1\ndecisions: []\n", encoding="utf-8")
    symlink = tmp_path / "link.yaml"
    symlink.symlink_to(outside_file)
    with pytest.raises(VEXDecisionError):
        load_vex_decisions(symlink)


def test_vex_cli_links_advisories_and_validates_cyclonedx(tmp_path):
    pkg = RegistryEntryComponent(
        bom_ref="pkg:pypi:transformers@4.35.0",
        name="transformers",
        version="4.35.0",
        registry_type="pypi",
        package_url="pkg:pypi/transformers@4.35.0",
    )
    bom_path = tmp_path / "aibom.json"
    AIBOM(components=[pkg]).save(bom_path)

    adv_report = tmp_path / "advisories.json"
    adv_report.write_text(
        json.dumps(
            {
                "advisories": [
                    {
                        "id": "CVE-2024-99999",
                        "aliases": ["GHSA-aaaa-bbbb-cccc"],
                        "bom_ref": "pkg:pypi:transformers@4.35.0",
                        "severity": "critical",
                        "summary": "Planted transformers CVE",
                        "offline": True,
                        "in_kev": True,
                        "kev_sources": ["cisa-kev"],
                        "epss_score": 0.91,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    trace_file = tmp_path / "trace.json"
    trace_file.write_text(
        json.dumps({"invoked": ["pkg:pypi:transformers@4.35.0"]}),
        encoding="utf-8",
    )

    runner = CliRunner()
    res = runner.invoke(
        main,
        [
            "vex",
            str(bom_path),
            "--advisories",
            str(adv_report),
            "--trace-evidence",
            str(trace_file),
        ],
    )
    assert res.exit_code == 0, res.output
    doc = json.loads(res.output)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.7"
    assert len(doc["vulnerabilities"]) == 1
    vuln = doc["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2024-99999"
    assert vuln["ratings"] == [{"severity": "critical"}]
    assert vuln["analysis"]["state"] == "exploitable"
    props = {p["name"]: p["value"] for p in vuln["properties"]}
    assert props["nexus-symbiote:inKev"] == "true"
    assert props["nexus-symbiote:kevSources"] == "cisa-kev"
    assert props["nexus-symbiote:executionOutcome"] == "invoked"
