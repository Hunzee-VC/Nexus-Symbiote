"""What the drift gate must flag, what it must not, and how it says which is which."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import (
    A2AClientComponent,
    AgentComponent,
    CompletenessClaim,
    DataSourceComponent,
    GuardrailComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    ModelComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.graph import INFERRED_AGENT_REF
from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

REPORT = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
CYCLONEDX = Path(__file__).parent / "fixtures/shadowscan-producer/cyclonedx-agent-model.json"


def _scan(project: Path, output: Path, *extra: str) -> None:
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    result = CliRunner().invoke(main, [*args, *extra])
    assert result.exit_code == 0, result.output


def _gate(before: Path, after: Path) -> tuple[int, dict]:
    result = CliRunner().invoke(
        main, ["diff", str(before), str(after), "--json-output", "--fail-on-alert"]
    )
    return result.exit_code, json.loads(result.stdout)


def _alerts(report: dict) -> list[str]:
    return [alert["alert"] for alert in report["security_alerts"]]


@pytest.mark.parametrize(
    ("relative", "before", "after", "removed"),
    [
        (
            "requirements.txt",
            "openai==1.30.0\nlangchain==0.2.0\n",
            "open-ai==1.30.0\nlangchain==0.2.0\n",
            "registry:pypi/openai",
        ),
        (
            "requirements.txt",
            "guardrails-ai==0.5.0\nopenai==1.30.0\n",
            "openai==1.30.0\n",
            "registry:pypi/guardrails-ai",
        ),
        (
            "Dockerfile.agent",
            "FROM ollama/ollama@sha256:" + "a" * 64 + "\nFROM vllm/vllm-openai:v0.6.0\n",
            "FROM ghcr.io/attacker/serve:latest\nFROM vllm/vllm-openai:v0.6.0\n",
            "registry:docker/ollama/ollama@sha256:" + "a" * 64,
        ),
    ],
    ids=["typosquat-swap", "guardrail-removed", "base-image-swap"],
)
def test_removed_registry_entry_fails_the_drift_gate(tmp_path, relative, before, after, removed):
    project = tmp_path / "project"
    project.mkdir()
    (project / relative).write_text(before)
    _scan(project, tmp_path / "before.json")
    (project / relative).write_text(after)
    _scan(project, tmp_path / "after.json")
    status, report = _gate(tmp_path / "before.json", tmp_path / "after.json")
    assert status == 1, report
    gone = [c for c in report["components_removed"] if c["bom_ref"] == removed]
    assert gone and gone[0]["severity"] in {"medium", "high"}
    assert any(
        alert["component"] == removed and "no longer in the inventory" in alert["alert"]
        for alert in report["security_alerts"]
    )


def test_removed_tool_with_dangling_reference_fails_the_gate_in_a_supplied_bom(tmp_path):
    agent = AgentComponent(bom_ref="agent:a", name="a", tool_refs=["tool:t"])
    tool = ToolComponent(bom_ref="tool:t", name="t", definition_hash="sha256:" + "a" * 64)
    before, after = tmp_path / "v1.json", tmp_path / "v2.json"
    AIBOM(components=[agent, tool]).save(before)
    AIBOM(components=[agent]).save(after)
    status, report = _gate(before, after)
    assert status == 1
    assert report["components_removed"][0]["severity"] == "high"
    assert any("graph consistency" in alert for alert in _alerts(report))


@pytest.mark.parametrize(
    ("component", "severity"),
    [
        (MCPServerComponent(bom_ref="x", name="x"), "high"),
        (ToolComponent(bom_ref="x", name="x"), "high"),
        (ModelComponent(bom_ref="x", name="x"), "high"),
        (GuardrailComponent(bom_ref="x", name="x"), "high"),
        (A2AClientComponent(bom_ref="x", name="x"), "high"),
        (RegistryEntryComponent(bom_ref="x", name="x"), "medium"),
        (RegistryEntryComponent(bom_ref="x", name="x", package_url="pkg:pypi/x@1.0.0"), "high"),
        (MemoryStoreComponent(bom_ref="x", name="x"), "medium"),
        (DataSourceComponent(bom_ref="x", name="x", content_hash="sha256:" + "b" * 64), "high"),
    ],
)
def test_removal_rating_follows_type_and_integrity_evidence(component, severity):
    report = AIBOMDiffer().diff(AIBOM(components=[component]), AIBOM())
    assert report.components_removed[0].severity == severity
    assert report.security_alerts == [
        {
            "severity": severity,
            "component": "x",
            "alert": f"Component 'x' ({component.component_type.value}) is no longer in the "
            "inventory: confirm it was deleted, not moved out of collector scope.",
        }
    ]


def _project(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("Use read-only tools.\n")
    (root / "requirements.txt").write_text("openai==1.30.0\n")
    (root / "src/app.py").write_text("print('hello')\n")


def test_an_unrelated_source_file_is_not_drift(tmp_path):
    project = tmp_path / "project"
    _project(project)
    _scan(project, tmp_path / "before.json")
    (project / "src/helpers.py").write_text("def helper():\n    return 1\n")
    (project / "tests").mkdir()
    (project / "tests/test_helpers.py").write_text("def test_helper():\n    pass\n")
    _scan(project, tmp_path / "after.json")
    status, report = _gate(tmp_path / "before.json", tmp_path / "after.json")
    assert status == 0, report["security_alerts"]
    assert report["security_alerts"] == []
    assert all(change["severity"] == "info" for change in report["metadata_changes"])


def test_the_same_tree_in_another_directory_keeps_its_repository_agent(tmp_path):
    first, second = tmp_path / "one" / "checkout", tmp_path / "two" / "elsewhere"
    _project(first)
    shutil.copytree(first, second)
    _scan(first, tmp_path / "first.json")
    _scan(second, tmp_path / "second.json")
    agents = [
        [c for c in json.loads((tmp_path / name).read_text())["components"] if c["bom_ref"]]
        for name in ("first.json", "second.json")
    ]
    refs = [
        {(c["bom_ref"], c["name"]) for c in found if c["component_type"] == "agent"}
        for found in agents
    ]
    assert refs[0] == refs[1] == {(INFERRED_AGENT_REF, "repository")}


def _baseline(project: Path, output: Path, *extra: str):
    return CliRunner().invoke(main, ["baseline", str(project), "-o", str(output), *extra])


def test_a_baseline_can_ignore_the_checkout_policy_like_the_candidate_scan(tmp_path):
    project = tmp_path / "project"
    _project(project)
    (project / ".nexus-symbiote.yaml").write_text("scan: {exclude_paths: [vendor]}\n")
    assert _baseline(project, tmp_path / "operator.json", "--no-project-policy").exit_code == 0
    assert _baseline(project, tmp_path / "checkout.json").exit_code == 0
    _scan(project, tmp_path / "candidate.json")
    exclusions = {
        name: json.loads((tmp_path / f"{name}.json").read_text())["metadata"]["completeness"][
            "exclusions"
        ]
        for name in ("operator", "checkout", "candidate")
    }
    assert exclusions["operator"] == exclusions["candidate"]
    assert "vendor" in exclusions["checkout"] and "vendor" not in exclusions["operator"]
    assert _gate(tmp_path / "operator.json", tmp_path / "candidate.json")[0] == 0


def test_a_baseline_applies_the_operator_signature_policy(tmp_path):
    project = tmp_path / "project"
    _project(project)
    policy = tmp_path / "signers.json"
    policy.write_text('{"version": 1, "artifacts": []}')
    refused = _baseline(project, tmp_path / "reviewed.json", "--signature-policy", str(policy))
    # The scan rejects the policy (exit 1); an unknown option would be a usage error (2).
    assert refused.exit_code == 1, refused.output
    assert not (tmp_path / "reviewed.json").exists()
    assert _baseline(project, tmp_path / "reviewed.json").exit_code == 0


def _claim(**fields) -> CompletenessClaim:
    base = {
        "scope": "repository",
        "scanner_status": {"mcp": "complete", "model": "complete"},
        "collectors_requested": ["mcp", "model"],
        "collectors_completed": ["mcp", "model"],
        "surfaces_scanned": ["a.json"],
    }
    return CompletenessClaim(**{**base, **fields})


def _compare(old: CompletenessClaim | None, new: CompletenessClaim | None):
    before, after = AIBOM(), AIBOM()
    before.metadata.completeness, after.metadata.completeness = old, new
    return AIBOMDiffer().diff(before, after)


@pytest.mark.parametrize(
    ("change", "field", "text"),
    [
        ({"scan_failures": ["mcp.json: invalid JSON"]}, "scan_failures", "mcp.json: invalid JSON"),
        ({"surfaces_excluded": ["models: excluded"]}, "surfaces_excluded", "models: excluded"),
        ({"exclusions": ["vendor"]}, "exclusions", "vendor"),
        (
            {"scanner_status": {"mcp": "partial", "model": "complete"}},
            "scanner_status.mcp",
            "'mcp' coverage changed from complete to partial",
        ),
        ({"scanner_status": {"mcp": "complete"}}, "scanner_status.model", "'model' is no longer"),
        ({"collectors_requested": ["mcp"]}, "collectors_requested", "model"),
        ({"collectors_completed": ["mcp"]}, "collectors_completed", "model"),
        ({"scope": "repository+shadowscan"}, "scope", "repository+shadowscan"),
        ({"unobserved_surfaces": ["network"]}, "unobserved_surfaces", "network"),
    ],
)
def test_each_coverage_regression_alerts_high_and_names_itself(change, field, text):
    report = _compare(_claim(), _claim(**change))
    alerts = [a for a in report.security_alerts if a["component"] == "metadata"]
    assert len(alerts) == 1 and alerts[0]["severity"] == "high"
    assert text in alerts[0]["alert"]
    assert report.metadata_changes[0]["field"] == f"completeness.{field}"
    reverse = _compare(_claim(**change), _claim())
    if field == "scope":
        # A different scope is a different claim, so it alerts in either direction.
        assert [a["severity"] for a in reverse.security_alerts] == ["high"]
        return
    # The reverse direction is an improvement: recorded, never an alert.
    assert reverse.security_alerts == []
    assert reverse.has_changes and {c["severity"] for c in reverse.metadata_changes} == {"info"}


def test_a_second_identical_gap_is_a_new_gap():
    failure = "requirements.txt: URL, VCS or path requirement not followed"
    report = _compare(_claim(scan_failures=[failure]), _claim(scan_failures=[failure, failure]))
    assert [a["severity"] for a in report.security_alerts] == ["high"]


def test_scanned_surfaces_alone_are_an_info_note():
    report = _compare(_claim(), _claim(surfaces_scanned=["a.json", "src/new.py"]))
    assert report.security_alerts == []
    assert report.metadata_changes == [
        {
            "field": "completeness.surfaces_scanned",
            "severity": "info",
            "detail": "Scanned surfaces changed: 1 added (src/new.py). "
            "Components found there are compared separately.",
        }
    ]


def test_shared_gaps_are_noted_without_counting_as_change(tmp_path):
    claim = _claim(
        scanner_status={"mcp": "partial", "model": "complete"},
        surfaces_excluded=["mcp.json: unsupported declaration"],
    )
    report = _compare(claim, claim.model_copy(deep=True))
    assert not report.has_changes and report.security_alerts == []
    assert len(report.notes) == 1
    assert "Both snapshots are incomplete" in report.notes[0]["detail"]
    assert "mcp (partial)" in report.notes[0]["detail"]
    bom = AIBOM()
    bom.metadata.completeness = claim
    bom.save(tmp_path / "bom.json")
    text = CliRunner().invoke(
        main, ["diff", str(tmp_path / "bom.json"), str(tmp_path / "bom.json")]
    )
    assert text.exit_code == 0
    assert "No changes detected." in text.output
    assert "Both snapshots are incomplete" in text.output


def test_missing_completeness_claims_are_never_silently_equal():
    assert (
        "Neither snapshot carries a completeness claim" in _compare(None, None).notes[0]["detail"]
    )
    dropped = _compare(_claim(), None)
    assert [a["severity"] for a in dropped.security_alerts] == ["high"]


@pytest.mark.parametrize(
    ("gap", "named"),
    [
        ({"scan_failures": ["mcp.json: invalid JSON"]}, "mcp.json: invalid JSON"),
        ({"surfaces_excluded": ["models: excluded"]}, "models: excluded"),
        ({"scanner_status": {"mcp": "partial", "model": "complete"}}, "mcp (partial)"),
        ({"collectors_completed": ["mcp"]}, "model (not completed)"),
        ({"source_report_status": "incomplete"}, "ShadowScan source status: incomplete"),
        ({"source_unmapped_count": 3}, "ShadowScan entries left unmapped: 3"),
        (
            {"scanner_status": {}, "collectors_requested": [], "collectors_completed": []},
            "No collector is recorded",
        ),
    ],
)
def test_a_baseline_without_a_claim_cannot_hide_gaps_in_the_new_snapshot(gap, named):
    report = _compare(None, _claim(**gap))
    assert [(a["severity"], a["component"]) for a in report.security_alerts] == [
        ("high", "metadata")
    ]
    assert "cannot be shown to predate this change" in report.security_alerts[0]["alert"]
    assert named in report.security_alerts[0]["alert"]
    assert [c["field"] for c in report.metadata_changes] == ["completeness.claim"]


def test_a_baseline_without_a_claim_against_complete_coverage_is_a_note():
    report = _compare(None, _claim())
    assert report.security_alerts == []
    assert [(c["field"], c["severity"]) for c in report.metadata_changes] == [
        ("completeness.claim", "info")
    ]


def test_a_supplied_baseline_without_a_claim_still_gates_a_failed_collector(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Use read-only tools.\n")
    _scan(project, tmp_path / "clean.json")
    supplied = json.loads((tmp_path / "clean.json").read_text())
    supplied["metadata"].pop("completeness")
    (tmp_path / "supplied.json").write_text(json.dumps(supplied))
    assert _gate(tmp_path / "supplied.json", tmp_path / "clean.json")[0] == 0
    # A malformed configuration hides whatever it declares without removing a component.
    (project / ".mcp.json").write_text('{"mcpServers": {')
    _scan(project, tmp_path / "broken.json")
    status, report = _gate(tmp_path / "supplied.json", tmp_path / "broken.json")
    assert status == 1
    (alert,) = _alerts(report)
    assert "no completeness claim" in alert and "invalid JSON" in alert


def test_a_different_producer_is_not_a_release_note():
    old, new = AIBOM(), AIBOM()
    new.metadata.tool_name, new.metadata.tool_vendor = "other-generator", "someone-else"
    report = AIBOMDiffer().diff(old, new)
    assert sorted((a["severity"], a["alert"]) for a in report.security_alerts) == [
        ("medium", "Snapshot metadata tool_name changed."),
        ("medium", "Snapshot metadata tool_vendor changed."),
    ]
    assert all("releases" not in c["detail"] for c in report.metadata_changes)


def test_shadowscan_content_change_and_coverage_regression_read_differently():
    digest = "sha256:" + "1" * 64
    common = {
        "source_report_digest": digest,
        "source_report_content_digest": "sha256:" + "2" * 64,
        "source_report_content_profile": "nexus-symbiote/shadowscan-content/v1",
    }
    content = _compare(
        _claim(**common),
        _claim(
            **{
                **common,
                "source_report_digest": "sha256:" + "3" * 64,
                "source_report_content_digest": "sha256:" + "4" * 64,
            }
        ),
    )
    failed = _compare(_claim(**common), _claim(**common, scanner_status={"mcp": "failed"}))
    assert [a["alert"] for a in content.security_alerts] == [
        "ShadowScan report content changed; review the report and the imported components."
    ]
    assert all("ShadowScan" not in a["alert"] for a in failed.security_alerts)
    unmapped = _compare(_claim(**common), _claim(**common, source_unmapped_count=2))
    assert "unmapped rose from 0 to 2" in unmapped.security_alerts[0]["alert"]


def test_relationship_between_existing_components_is_rated_and_printed(tmp_path):
    agent = AgentComponent(bom_ref="agent:a", name="a")
    tool = ToolComponent(bom_ref="tool:t", name="t")
    guard = GuardrailComponent(bom_ref="guard:g", name="g")
    guarded = DependencyEdge(
        source_ref="agent:a", target_ref="guard:g", relationship="uses-guardrail"
    )
    before = AIBOM(components=[agent, tool, guard], dependencies=[guarded])
    after = AIBOM(
        components=[agent, tool, guard],
        dependencies=[
            DependencyEdge(source_ref="agent:a", target_ref="tool:t", relationship="invokes")
        ],
    )
    report = AIBOMDiffer().diff(before, after)
    assert [(d.relationship, d.severity) for d in report.dependencies_added] == [
        ("invokes", "high")
    ]
    assert [(d.relationship, d.severity) for d in report.dependencies_removed] == [
        ("uses-guardrail", "high")
    ]
    assert [a["alert"] for a in report.security_alerts] == [
        "Relationship added: 'agent:a' invokes 'tool:t'.",
        "Relationship removed: 'agent:a' uses-guardrail 'guard:g'.",
    ]
    before.save(tmp_path / "before.json")
    after.save(tmp_path / "after.json")
    args = ["diff", str(tmp_path / "before.json"), str(tmp_path / "after.json")]
    text = CliRunner().invoke(main, [*args, "--fail-on-alert"])
    assert text.exit_code == 1
    assert "+1 relationships added" in text.output
    assert "+ [HIGH] agent:a invokes tool:t" in text.output
    assert "- [HIGH] agent:a uses-guardrail guard:g" in text.output


def test_an_edge_to_a_new_component_is_listed_but_alerts_once_through_the_component():
    agent = AgentComponent(bom_ref="agent:a", name="a")
    server = MCPServerComponent(bom_ref="server:s", name="s")
    edge = DependencyEdge(
        source_ref="agent:a", target_ref="server:s", relationship="configured-with"
    )
    report = AIBOMDiffer().diff(
        AIBOM(components=[agent]), AIBOM(components=[agent, server], dependencies=[edge])
    )
    assert len(report.dependencies_added) == 1
    assert [a["component"] for a in report.security_alerts] == ["server:s"]


def test_changed_edge_conditions_alert_once():
    agent = AgentComponent(bom_ref="agent:a", name="a")
    tool = ToolComponent(bom_ref="tool:t", name="t")
    edge = DependencyEdge(
        source_ref="agent:a", target_ref="tool:t", relationship="invokes", conditions="approved"
    )
    report = AIBOMDiffer().diff(
        AIBOM(components=[agent, tool], dependencies=[edge]),
        AIBOM(
            components=[agent, tool], dependencies=[edge.model_copy(update={"conditions": None})]
        ),
    )
    assert [a["severity"] for a in report.security_alerts] == ["high"]
    assert "assurance or conditions changed" in report.security_alerts[0]["alert"]


@pytest.mark.parametrize(
    ("old", "new", "severity", "detail"),
    [
        (
            MCPServerComponent(bom_ref="x", name="x", trust_tier=TrustTier.UNTRUSTED_PUBLIC),
            MCPServerComponent(bom_ref="x", name="x", trust_tier=TrustTier.INTERNAL_VERIFIED),
            "medium",
            "Trust tier upgraded",
        ),
        (
            ModelComponent(bom_ref="x", name="x", signing_status="signature-not-found"),
            ModelComponent(bom_ref="x", name="x", signing_status="sigstore-signed"),
            "medium",
            "Signing status changed",
        ),
        (
            A2AClientComponent(bom_ref="x", name="x", agent_card_url="https://a.example"),
            A2AClientComponent(bom_ref="x", name="x", agent_card_url="https://b.example"),
            "high",
            "agent_card_url changed.",
        ),
        (
            ModelComponent(bom_ref="x", name="x", provider="one"),
            ModelComponent(bom_ref="x", name="x", provider="two"),
            "high",
            "provider changed.",
        ),
        (
            DataSourceComponent(bom_ref="x", name="x", source_uri="https://a.example/d"),
            DataSourceComponent(bom_ref="x", name="x", source_uri="https://b.example/d"),
            "high",
            "source_uri changed.",
        ),
        (
            RegistryEntryComponent(bom_ref="x", name="x", signing_key_reference="k1"),
            RegistryEntryComponent(bom_ref="x", name="x", signing_key_reference="k2"),
            "high",
            "signing_key_reference changed.",
        ),
        (
            AgentComponent(bom_ref="x", name="x", properties={"declared_autonomy_level": "L1"}),
            AgentComponent(bom_ref="x", name="x", properties={"declared_autonomy_level": "L4"}),
            "high",
            "Declared autonomy level changed.",
        ),
        (
            ToolComponent(bom_ref="x", name="x", annotations={"readOnlyHint": 1}),
            ToolComponent(bom_ref="x", name="x", annotations={"readOnlyHint": True}),
            "critical",
            "annotations changed.",
        ),
    ],
)
def test_security_relevant_transitions_are_rated_like_their_peers(old, new, severity, detail):
    report = AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[new]))
    assert report.components_modified[0].severity == severity
    assert any(detail in d for d in report.components_modified[0].details)


def test_risk_changes_carry_the_severity_of_what_was_added():
    finding = RiskAssessment(severity=RiskSeverity.LOW, category="note", detail="minor")
    critical = RiskAssessment(severity=RiskSeverity.CRITICAL, category="unsafe", detail="loader")
    model = ModelComponent(bom_ref="m", name="m", risks=[finding])
    added = AIBOMDiffer().diff(
        AIBOM(components=[model]),
        AIBOM(components=[model.model_copy(update={"risks": [finding, critical]})]),
    )
    assert added.components_modified[0].severity == "critical"
    assert added.components_modified[0].details == ["Risk findings added: 1 critical (unsafe)."]
    removed = AIBOMDiffer().diff(
        AIBOM(components=[model]), AIBOM(components=[model.model_copy(update={"risks": []})])
    )
    assert removed.components_modified[0].details == ["Risk findings removed: 1 low (note)."]
    assert removed.components_modified[0].severity == "medium"


def test_a_tool_upgrade_is_a_note_not_an_alert():
    old, new = AIBOM(), AIBOM()
    old.metadata.tool_version, new.metadata.tool_version = "0.1.0", "0.2.0"
    report = AIBOMDiffer().diff(old, new)
    assert report.security_alerts == []
    assert [c["field"] for c in report.metadata_changes] == ["tool_version"]


def test_unsupported_spec_version_and_reversed_arguments_are_reported():
    old, new = AIBOM(), AIBOM()
    new.metadata.spec_version = "9.0.0"
    old.metadata.timestamp = datetime.now(UTC)
    new.metadata.timestamp = old.metadata.timestamp - timedelta(days=1)
    report = AIBOMDiffer().diff(old, new)
    assert any(
        "spec_version this release does not support" in a["alert"] for a in report.security_alerts
    )
    assert any("check the argument order" in note["detail"] for note in report.notes)


def test_legacy_absolute_paths_are_explained():
    old = AIBOM(components=[ModelComponent(bom_ref="m", name="m", source_path="/home/a/m.bin")])
    new = AIBOM(components=[ModelComponent(bom_ref="m", name="m", source_path="m.bin")])
    report = AIBOMDiffer().diff(old, new)
    assert any(note["field"] == "paths" for note in report.notes)
    assert report.components_modified, "a location change is still reported"


def _with_finding_first(data: dict) -> dict:
    data = json.loads(json.dumps(data))
    extra = json.loads(json.dumps(data["findings"][1]))
    extra["id"] = "ss-inserted-first"
    data["findings"].insert(0, extra)
    data["summary"]["total"] += 1
    data["summary"]["by_kind"][extra["kind"]] += 1
    data["summary"]["by_surface"][extra["surface"]] += 1
    data["summary"]["by_risk_level"][extra["risk"]["level"]] += 1
    return data


def test_an_inserted_finding_alerts_only_for_itself():
    before = ShadowScanImporter().parse_report(REPORT.read_bytes()).to_native_bom()
    after = (
        ShadowScanImporter()
        .parse_report(json.dumps(_with_finding_first(json.loads(REPORT.read_text()))))
        .to_native_bom()
    )
    report = AIBOMDiffer().diff(before, after)
    assert not report.components_modified
    assert len(report.components_added) == 1
    components = {a["component"] for a in report.security_alerts} - {"metadata"}
    assert components == {report.components_added[0].bom_ref}


def test_reordered_cyclonedx_dependencies_are_not_a_changed_relationship():
    data = json.loads(CYCLONEDX.read_text())
    data["dependencies"].insert(0, {"ref": "unmapped-source", "dependsOn": []})
    before = ShadowScanImporter().parse_report(CYCLONEDX.read_bytes()).to_native_bom()
    after = ShadowScanImporter().parse_report(json.dumps(data)).to_native_bom()
    assert before.dependencies[0].conditions != after.dependencies[0].conditions
    report = AIBOMDiffer().diff(before, after)
    assert not report.dependencies_added and not report.dependencies_removed


def _mutations(value):
    """Changes and removals of recorded values; adding evidence where there was none is not drift."""
    if isinstance(value, bool):
        yield not value
    elif isinstance(value, int):
        yield value + 1
    elif isinstance(value, str):
        yield value + "-changed"
    elif isinstance(value, list) and value:
        yield value[:-1]
    elif isinstance(value, dict) and value:
        dropped = sorted(value)[0]
        yield {key: item for key, item in value.items() if key != dropped}


def test_every_single_field_change_of_a_scanned_inventory_alerts(tmp_path):
    from pydantic import ValidationError

    project = tmp_path / "project"
    (project / ".claude").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("Use read-only tools.\n")
    (project / "requirements.txt").write_text("openai==1.30.0\nlangchain\n")
    (project / ".claude/settings.json").write_text(
        json.dumps({"permissions": {"defaultMode": "default", "allow": ["Bash(*)"]}})
    )
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "files": {
                        "command": "npx",
                        "args": ["-y", "@scope/files-mcp@1.0.0"],
                        "tools": [{"name": "read", "description": "Read", "inputSchema": {}}],
                    },
                    "remote": {"url": "https://mcp.example.com/mcp"},
                }
            }
        )
    )
    _scan(project, tmp_path / "bom.json")
    bom = AIBOM.load(tmp_path / "bom.json")
    checked = 0
    for index, component in enumerate(bom.components):
        original = component.model_dump(mode="json")
        for name, value in original.items():
            if name in {"bom_ref", "component_type"}:
                continue
            for mutated in _mutations(value):
                try:
                    candidate = type(component).model_validate({**original, name: mutated})
                except ValidationError:
                    continue
                if candidate.model_dump(mode="json") == original:
                    continue
                changed = bom.model_copy(deep=True)
                changed.components[index] = candidate
                report = AIBOMDiffer().diff(bom, changed)
                assert any(
                    alert["component"] == component.bom_ref
                    and alert["severity"] in {"medium", "high", "critical"}
                    for alert in report.security_alerts
                ), (component.bom_ref, name, report.to_dict())
                checked += 1
    assert checked > 50
