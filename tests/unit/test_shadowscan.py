"""Nexus ShadowScan integration: report reader, autonomy scale, importer, inventory, reconcile, collector, CLI."""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from symbiote.cli.app import app
from symbiote.export.cdx import export_cyclonedx, validate_cyclonedx
from symbiote.export.companion import companion_bytes, load_companion
from symbiote.export.spdx import export_spdx, validate_spdx
from symbiote.model import enums as E
from symbiote.model.entities import AutonomyAssessment
from symbiote.policy import run_policy
from symbiote.scan import scan
from symbiote.shadowscan import (
    LEVELS,
    ReportError,
    assessment_from_metadata,
    export_inventory,
    from_iso,
    import_report,
    map_report,
    read_report,
    reconcile,
    to_iso,
    widen,
)
from symbiote.shadowscan.inventory import literal_pattern
from symbiote.shadowscan.report import detect_cyclonedx, finding_from_dict

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "shadowscan"
EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "triage-agent"
TRIAGE = FIXTURES / "triage-agent.report.json"
TRIAGE_CDX = FIXTURES / "triage-agent.cdx.json"
OFFLINE = FIXTURES / "offline-demo.report.json"
runner = CliRunner()


# ------------------------------------------------------------------------------------------ autonomy scale


def test_scale_is_strictly_increasing_and_round_trips() -> None:
    order = [lv.iso for lv in LEVELS]
    ranks = [list(E.IsoAutomationLevel).index(x) for x in order]
    assert ranks == sorted(ranks) and len(set(ranks)) == 6
    for lv in LEVELS:
        assert from_iso(to_iso(lv.number)) == (lv.number, True)
    assert from_iso(E.IsoAutomationLevel.AUTONOMOUS) == (5, False)
    assert to_iso(0) is E.IsoAutomationLevel.NOT_AUTOMATED
    assert to_iso(5) is E.IsoAutomationLevel.FULL_AUTOMATION
    with pytest.raises(ValueError):
        to_iso(6)


def test_assessment_parses_and_rejects_malformed_blocks() -> None:
    block = {
        "schema": "shadowscan.autonomy/v1",
        "floor": 3,
        "ceiling": 5,
        "oversight": "unknown",
        "initiation": "schedule",
        "basis": [{"bound": "floor", "rule": "agentic-execution", "value": 3}],
        "declared": 2,
        "declared_source": "lead-qualifier",
    }
    a = assessment_from_metadata(block, assessor="shadowscan@0.1.4")
    assert a is not None
    assert (a.floor, a.ceiling, a.initiation) == (3, 5, E.AutonomyInitiation.SCHEDULE)
    assert a.floor_level is E.IsoAutomationLevel.CONDITIONAL_AUTOMATION
    assert a.understated and not a.above_ceiling
    assert a.basis[0].value == "3"
    assert assessment_from_metadata({**block, "schema": "other"}) is None
    assert assessment_from_metadata({**block, "floor": 9}) is None
    assert assessment_from_metadata({**block, "floor": 4, "ceiling": 2}) is None
    assert assessment_from_metadata({**block, "oversight": "maybe"}) is None
    assert assessment_from_metadata({**block, "floor": True}) is None
    with pytest.raises(ValueError):
        AutonomyAssessment(scale="x", floor=4, ceiling=2, floor_level=to_iso(4), ceiling_level=to_iso(2))


def test_widen_follows_shadowscan_merge_semantics() -> None:
    def mk(
        floor: int, ceiling: int, oversight: str, initiation: str, declared: int | None = None
    ) -> AutonomyAssessment:
        return assessment_from_metadata(  # type: ignore[return-value]
            {
                "schema": "shadowscan.autonomy/v1",
                "floor": floor,
                "ceiling": ceiling,
                "oversight": oversight,
                "initiation": initiation,
                "basis": [{"bound": "floor", "rule": "ai-system", "value": 0}],
                **({"declared": declared, "declared_source": "s"} if declared is not None else {}),
            }
        )

    a, b = mk(1, 2, "gated", "human", 3), mk(4, 5, "bypassed", "schedule", 1)
    w = widen([a, b])
    assert w is not None
    assert (w.floor, w.ceiling) == (4, 5)
    assert w.oversight is E.AutonomyOversight.BYPASSED
    assert w.initiation is E.AutonomyInitiation.SCHEDULE
    assert w.declared == 1  # the lowest declaration is kept
    assert widen([b, a]).model_dump() == w.model_dump()  # order independent
    assert widen([]) is None
    assert widen([a]) is a


# ------------------------------------------------------------------------------------------ report reader


def test_read_json_report_fixture() -> None:
    r = read_report(TRIAGE)
    assert r.source_format == "json" and r.version == "0.1.4" and r.complete
    assert r.by_kind() == {"agent": 1, "agent-config": 6, "mcp-server": 5}
    assert r.scan_roots == ["/work/triage-agent"]
    assert r.source_digest and r.source_digest.startswith("sha256:")
    mcp = next(f for f in r.findings if f.resource.endswith(".mcp.json"))
    assert [s["name"] for s in mcp.servers] == ["github", "filesystem", "triage-tools"]
    assert mcp.autonomy and mcp.autonomy["floor"] == 1
    assert mcp.digest().startswith("sha256:")


def test_read_cyclonedx_dialect_infers_scan_roots() -> None:
    doc = json.loads(TRIAGE_CDX.read_text())
    assert detect_cyclonedx(doc)
    r = read_report(TRIAGE_CDX)
    assert r.source_format == "cyclonedx" and len(r.findings) == 12
    assert r.scan_roots == ["/work/triage-agent"]
    assert any("autonomy" in loss for loss in r.losses)
    mcp = next(f for f in r.findings if f.title.endswith(".mcp.json"))
    assert {s["name"] for s in mcp.servers} == {"github", "filesystem", "triage-tools"}


def test_reader_rejects_bad_input(tmp_path: Path) -> None:
    with pytest.raises(ReportError):
        read_report(b'{"findings": [], "finding_identity_schema": "nope"}')
    with pytest.raises(ReportError):
        read_report(
            b'{"findings": [{"confidence": NaN}], "finding_identity_schema": "shadowscan.finding-identity/v2"}'
        )
    with pytest.raises(ReportError):
        read_report(b"not json")
    with pytest.raises(ReportError):
        finding_from_dict(
            {"surface": "code", "connector": "c", "kind": "agent", "title": "t", "resource": "r"}
        )
    with pytest.raises(ReportError):
        finding_from_dict(
            {
                "id": "ss-1",
                "surface": "code",
                "connector": "c",
                "kind": "agent",
                "title": "t",
                "resource": "r",
                "resource_type": "x",
                "confidence": 7,
            }
        )
    with pytest.raises(ReportError):
        read_report(tmp_path.read_bytes() if False else b'{"bomFormat": "CycloneDX", "specVersion": "1.6"}')


# ------------------------------------------------------------------------------------------ importer


def test_import_triage_report_builds_observed_snapshot() -> None:
    bom = import_report(read_report(TRIAGE), deterministic=True)
    assert bom.snapshot.kind is E.SnapshotKind.OBSERVED
    assert bom.subject == "agent:triage-agent"
    assert {s.id for s in bom.tool_servers} == {
        "server:claude-code-filesystem",
        "server:claude-code-github",
        "server:claude-code-triage-tools",
        "server:codex-github",
        "server:codex-triage-tools",
        "server:cursor-github",
        "server:gemini-cli-filesystem",
        "server:vscode-filesystem",
        "server:vscode-github",
    }
    root = bom.root_agent
    assert root.autonomy_assessment is not None
    assert (root.autonomy_assessment.floor, root.autonomy_assessment.ceiling) == (3, 5)
    assert root.automation_level is not None
    assert root.automation_level.value is E.IsoAutomationLevel.CONDITIONAL_AUTOMATION
    assert root.automation_level.assurance is E.AssuranceLevel.OBSERVED
    assert "harness:claude-code" in root.tags
    assert root.foreign["shadowscan:agent-config:openai-codex:approval-gate"] == "some-actions"
    # code-surface findings are declared facts about configuration
    gh = next(s for s in bom.tool_servers if s.id == "server:claude-code-github")
    assert gh.provenance.assurance is E.AssuranceLevel.DECLARED
    assert gh.provenance.evidence and gh.provenance.evidence[0].media_type.endswith("finding+json")
    assert gh.endpoint is not None and gh.endpoint.value == "https://api.githubcopilot.com/mcp/"
    fs = next(s for s in bom.tool_servers if s.id == "server:claude-code-filesystem")
    assert fs.package is not None and fs.package.value is not None and fs.package.value.floating
    assert "inline-secret-in-config" in fs.tags
    flags = {(f.flag, f.subject_ref): f.value for f in bom.derived.flags}
    assert flags[(E.FlagName.UNPINNED_TOOL, "server:claude-code-filesystem")] is E.TriState.TRUE
    assert (
        flags[(E.FlagName.STATIC_LONG_LIVED_CREDENTIAL, "server:claude-code-filesystem")] is E.TriState.TRUE
    )
    # no inventory was supplied: shadow is unknown, never false
    assert (
        flags[(E.FlagName.UNDECLARED_COMPONENT_OBSERVED, "server:claude-code-github")] is E.TriState.UNKNOWN
    )
    # the A2A card found in the repository is a peer the agent delegates to
    peer = next(a for a in bom.agents if a.id != bom.subject)
    assert peer.role is E.AgentRole.EXTERNAL_AGENT and peer.name == "release-notes-writer"
    assert any(e.type is E.EdgeType.DELEGATES_TO and e.to_ref == peer.id for e in bom.edges)
    # every finding is evidence
    assert len(bom.evidence) == 13  # 12 findings + the report itself
    assert bom.coverage.surfaces[E.Surface.CODE].status is E.CoverageStatus.QUERIED
    assert bom.coverage.surfaces[E.Surface.IDENTITY].status is E.CoverageStatus.NOT_ATTEMPTED
    assert bom.snapshot.observation_window is not None
    companion_bytes(bom)  # validates against the companion schema


def test_import_is_deterministic() -> None:
    a = import_report(read_report(TRIAGE), deterministic=True)
    b = import_report(read_report(TRIAGE), deterministic=True)
    assert companion_bytes(a) == companion_bytes(b)


def test_import_estate_report_exports_valid_cyclonedx_and_spdx() -> None:
    bom = import_report(read_report(OFFLINE), deterministic=True)
    kinds = {a.foreign.get("shadowscan:kind") for a in bom.agents}
    assert {"agent", "workflow", "bot-app", "cloud-resource", "gateway-caller"} <= kinds
    assert bom.identities and bom.grants and bom.deployments and bom.models
    root = bom.root_agent
    assert (
        root.autonomy_assessment is not None
        and root.autonomy_assessment.oversight is E.AutonomyOversight.BYPASSED
    )
    # shadow findings are tagged and flagged
    shadow = [a for a in bom.agents if "shadow" in a.tags]
    assert shadow
    assert any(f.check_id == "SYM-SS-001" for f in bom.derived.findings)
    assert any(f.check_id == "SYM-SS-006" for f in bom.derived.findings)
    # observation-only kinds stay as evidence + foreign properties, never fabricated agents
    assert any(p.name == "shadowscan:kind" and p.value == "network-contact" for p in bom.foreign_properties)
    assert not any(a.foreign.get("shadowscan:kind") == "network-contact" for a in bom.agents)
    doc, _ = export_cyclonedx(bom)
    assert validate_cyclonedx(doc) == []
    props = {p["name"]: p["value"] for p in doc["metadata"]["component"]["properties"]}
    assert props["agentbom:agent:autonomy-assessment:floor"] == "4"
    assert props["agentbom:agent:autonomy-assessment:oversight"] == "bypassed"
    sdoc, _ = export_spdx(bom)
    assert validate_spdx(sdoc, schema=False) == []


def test_import_cyclonedx_dialect() -> None:
    bom = import_report(read_report(TRIAGE_CDX), deterministic=True)
    assert bom.subject == "agent:triage-agent"
    assert len(bom.tool_servers) == 9
    assert bom.root_agent.autonomy_assessment is None  # the dialect carries no interval; never invented
    assert bom.loss_report is not None and not bom.loss_report.lossless
    assert bom.coverage.surfaces[E.Surface.CODE].status is E.CoverageStatus.QUERIED


def test_scope_root_keeps_only_repository_findings() -> None:
    mapped = map_report(read_report(OFFLINE), scope="root")
    assert mapped.root.id == "agent:sample_repo"
    assert all(s.foreign.get("shadowscan:surface") == "code" for s in mapped.tool_servers)
    assert not mapped.deployments


# ------------------------------------------------------------------------------------------ inventory


@pytest.fixture(scope="module")
def declared_bom():
    return scan(EXAMPLE, deterministic=True).bom


def test_inventory_cards(declared_bom) -> None:
    files = export_inventory(
        declared_bom, "cards", scan_root="/work/triage-agent", resources=["github:acme/widgets"]
    )
    assert list(files) == ["triage-agent.card.yaml"]
    card = yaml.safe_load(files["triage-agent.card.yaml"])
    assert card["schema_version"] == 2
    assert (
        card["metadata"]["agent_id"] == "agent:triage-agent"
    )  # the id ShadowScan's own AgentBOM loader binds
    assert card["metadata"]["owner_team"] == "Acme Platform Security"
    assert card["discovery"]["resources"] == [
        "github:acme/widgets",
        "/work/triage-agent",
        "/work/triage-agent/*",
    ]
    assert card["discovery"]["names"] == ["triage-agent"]
    assert card["governance"]["intended_purpose"].startswith("Label and acknowledge")
    assert "level" not in card.get("autonomy_profile", {})  # nothing declared → undeclared, never invented
    assert {s["name"] for s in card["capability_surface"]["tool_servers"]} == {
        "filesystem",
        "github",
        "release-notes-writer",  # the A2A peer card found by the a2a-cards collector
        "triage-tools",
    }
    assert card["provenance"]["snapshot_digest"] == declared_bom.snapshot.digest
    assert card["provenance"]["verification"] == "not-verified"
    assert "https://api.githubcopilot.com/mcp/" in card["provenance"]["component_resources"]
    assert set(card["discovery"]) <= {"resources", "names", "frameworks"}


def test_inventory_simple_and_csv(declared_bom) -> None:
    agents = yaml.safe_load(export_inventory(declared_bom, "agents")["agents.yaml"])
    assert agents["agents"][0]["id"] == "agent:triage-agent"
    text = export_inventory(declared_bom, "csv", scan_root="/r")["agents.csv"]
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]["agent_id"] == "agent:triage-agent" and rows[0]["resources"] == "/r|/r/*"
    assert rows[0]["autonomy_level"] == ""


def test_inventory_declares_level_from_iso() -> None:
    bom = import_report(read_report(TRIAGE), deterministic=True)
    card = yaml.safe_load(export_inventory(bom, "cards")["triage-agent.card.yaml"])
    assert card["autonomy_profile"]["level"] == 3
    assert card["provenance"]["autonomy_level_source"] == "observed"
    assert literal_pattern("agent-*[x]?") == "agent-[*][[]x[]][?]"


@pytest.mark.skipif(
    not os.environ.get("SYMBIOTE_SHADOWSCAN_BIN"),
    reason="set SYMBIOTE_SHADOWSCAN_BIN to a shadowscan executable",
)
def test_interop_shadowscan_accepts_generated_inventory(declared_bom, tmp_path: Path) -> None:
    binary = os.environ["SYMBIOTE_SHADOWSCAN_BIN"]
    out = tmp_path / "inv"
    out.mkdir()
    for name, text in export_inventory(declared_bom, "cards", scan_root=str(EXAMPLE.resolve())).items():
        (out / name).write_text(text)
    subprocess.run([binary, "inventory", "check", str(out)], check=True, capture_output=True)
    report = tmp_path / "report.json"
    subprocess.run(
        [binary, "code", str(EXAMPLE), "--inventory", str(out), "--format", "json", "-o", str(report)],
        check=True,
        capture_output=True,
    )
    data = json.loads(report.read_text())
    assert data["inventory_present"] and data["summary"]["shadow"] == 0
    assert all(f["registry_match"] == "agent:triage-agent" for f in data["findings"])


# ------------------------------------------------------------------------------------------ reconcile & checks


def test_reconcile_matches_all_servers(declared_bom) -> None:
    rec = reconcile(declared_bom, read_report(TRIAGE), scan_root="/work/triage-agent", deterministic=True)
    assert len(rec.matched) == 9 and all(m.how == "id" for m in rec.matched)
    assert rec.observed_not_declared == [] and rec.declared_not_observed == []
    assert rec.autonomy is not None and rec.autonomy.verdict == "undeclared"
    assert rec.findings == []
    assert rec.summary()["toolServers"]["matched"][0]["how"] == "id"


def test_reconcile_detects_shadow_and_stale_servers(declared_bom) -> None:
    report = read_report(TRIAGE)
    # drop one declared server from the observation and add an unknown one
    mcp = next(f for f in report.findings if f.resource.endswith(".mcp.json"))
    mcp.metadata["servers"] = [s for s in mcp.servers if s["name"] != "github"] + [
        {
            "name": "rogue",
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "rogue@latest"],
            "env_names": [],
            "headers": [],
            "disabled": False,
            "risks": [],
        }
    ]
    rec = reconcile(declared_bom, report, scan_root="/work/triage-agent", deterministic=True)
    assert "server:claude-code-rogue" in rec.observed_not_declared
    assert "server:claude-code-github" in rec.declared_not_observed
    assert rec.declared_not_observed_state == "fail"
    ids = {f.check_id: f for f in rec.findings}
    assert ids["SYM-SS-002"].state is E.FindingState.FAIL and ids["SYM-SS-003"].state is E.FindingState.FAIL
    assert rec.failing(E.Severity.HIGH)
    # an incomplete report turns absence into an unknown
    report.complete = False
    rec2 = reconcile(declared_bom, report, scan_root="/work/triage-agent", deterministic=True)
    states = {f.check_id: f.state for f in rec2.findings}
    assert states["SYM-SS-003"] is E.FindingState.INDETERMINATE
    assert states["SYM-SS-007"] is E.FindingState.INDETERMINATE


def test_reconcile_autonomy_verdicts(declared_bom) -> None:
    from symbiote.model.common import Claim

    root = declared_bom.root_agent.replace(
        automation_level=Claim.declared(E.IsoAutomationLevel.ASSISTIVE_AUTOMATION)
    )
    low = declared_bom.replace(agents=[root, *(a for a in declared_bom.agents if a.id != root.id)])
    rec = reconcile(low, read_report(TRIAGE), scan_root="/work/triage-agent", deterministic=True)
    assert rec.autonomy is not None and rec.autonomy.verdict == "understated"
    assert any(f.check_id == "SYM-SS-004" for f in rec.findings)
    root = declared_bom.root_agent.replace(
        automation_level=Claim.declared(E.IsoAutomationLevel.HIGH_AUTOMATION)
    )
    rec = reconcile(
        declared_bom.replace(agents=[root, *(a for a in declared_bom.agents if a.id != root.id)]),
        read_report(TRIAGE),
        scan_root="/work/triage-agent",
        deterministic=True,
    )
    assert rec.autonomy is not None and rec.autonomy.verdict == "consistent"


def test_policy_checks_on_imported_bom_with_baseline(declared_bom) -> None:
    observed = import_report(read_report(TRIAGE), deterministic=True, scope="root", policy=False)
    result = run_policy(observed, select=["SYM-SS-*"], baseline=declared_bom)
    assert "SYM-SS-002" in result.checks_run
    assert not [f for f in result.findings if f.check_id in ("SYM-SS-002", "SYM-SS-003")]


# ------------------------------------------------------------------------------------------ collector


def test_collector_folds_report_into_scan(tmp_path: Path) -> None:
    outcome = scan(EXAMPLE, deterministic=True, options={"shadowscan_report": str(TRIAGE)})
    bom = outcome.bom
    names = {c.name: c.status for c in bom.coverage.collectors}
    assert names["shadowscan-report"] is E.CollectorStatus.OK
    assert not [w for w in outcome.warnings if "duplicate entity" in w]
    root = bom.root_agent
    assert root.autonomy_assessment is not None and root.autonomy_assessment.floor == 3
    assert "harness:cursor" in root.tags
    gh = next(s for s in bom.tool_servers if s.id == "server:claude-code-github")
    assert gh.provenance.assurance is E.AssuranceLevel.DECLARED  # declared by mcp-config, corroborated
    assert any("ss:" in t for t in gh.tags)
    assert bom.coverage.surfaces[E.Surface.CODE].status is E.CoverageStatus.QUERIED
    producer_modes = {c.name: c.mode for c in bom.producer.collectors}
    assert producer_modes["shadowscan-report"] is E.CollectorMode.OBSERVED
    assert len(bom.evidence) >= 13
    # a broken report is a failed collector with partial coverage, never silence
    bad = tmp_path / "shadowscan.json"
    bad.write_text("{not json")
    outcome = scan(EXAMPLE, deterministic=True, options={"shadowscan_report": str(bad)})
    run = next(c for c in outcome.bom.coverage.collectors if c.name == "shadowscan-report")
    assert run.status is E.CollectorStatus.FAILED and run.reason and "ReportError" in run.reason


def test_collector_detects_conventional_file(tmp_path: Path) -> None:
    shutil.copytree(EXAMPLE, tmp_path / "repo")
    shutil.copy(TRIAGE, tmp_path / "repo" / "shadowscan.report.json")
    outcome = scan(tmp_path / "repo", deterministic=True)
    assert any(
        c.name == "shadowscan-report" and c.status is E.CollectorStatus.OK
        for c in outcome.bom.coverage.collectors
    )


# ------------------------------------------------------------------------------------------ CLI


def test_cli_levels_import_inventory_reconcile(tmp_path: Path) -> None:
    res = runner.invoke(app, ["shadowscan", "levels", "--json"])
    assert res.exit_code == 0 and json.loads(res.stdout)[5]["iso22989"] == "fullAutomation"
    out = tmp_path / "imp"
    res = runner.invoke(
        app, ["shadowscan", "import", str(TRIAGE), "-o", str(out), "--deterministic", "--json"]
    )
    assert res.exit_code == 0, res.output
    summary = json.loads(res.stdout)
    assert summary["cyclonedxValid"] and summary["spdxValid"] and summary["kind"] == "observed"
    observed = load_companion(out / "agentbom.observed.json")
    assert observed.snapshot.kind is E.SnapshotKind.OBSERVED
    bom_dir = tmp_path / "declared"
    res = runner.invoke(
        app, ["scan", str(EXAMPLE), "-o", str(bom_dir), "--format", "companion", "--deterministic", "--json"]
    )
    assert res.exit_code == 0, res.output
    inv = tmp_path / "inv"
    res = runner.invoke(
        app,
        [
            "shadowscan",
            "inventory",
            str(bom_dir / "agentbom.json"),
            "-o",
            str(inv),
            "--scan-root",
            "/work/triage-agent",
            "--json",
        ],
    )
    assert res.exit_code == 0, res.output
    assert (inv / "triage-agent.card.yaml").exists()
    res = runner.invoke(
        app,
        [
            "shadowscan",
            "inventory",
            str(bom_dir / "agentbom.json"),
            "-o",
            str(tmp_path / "agents.csv"),
            "--format",
            "csv",
            "--json",
        ],
    )
    assert res.exit_code == 0 and (tmp_path / "agents.csv").read_text().startswith("agent_id,")
    res = runner.invoke(
        app,
        [
            "shadowscan",
            "reconcile",
            str(bom_dir / "agentbom.json"),
            str(TRIAGE),
            "--scan-root",
            "/work/triage-agent",
            "--json",
            "-o",
            str(tmp_path / "rec.json"),
            "--sarif",
            str(tmp_path / "rec.sarif"),
        ],
    )
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    assert len(data["toolServers"]["matched"]) == 9
    assert json.loads((tmp_path / "rec.sarif").read_text())["version"] == "2.1.0"
    res = runner.invoke(
        app,
        [
            "scan",
            str(EXAMPLE),
            "-o",
            str(tmp_path / "s2"),
            "--format",
            "companion",
            "--deterministic",
            "--shadowscan-report",
            str(TRIAGE),
            "--json",
        ],
    )
    assert res.exit_code == 0, res.output
    assert any(c["name"] == "shadowscan-report" for c in json.loads(res.stdout)["collectors"])
    res = runner.invoke(app, ["shadowscan", "import", str(tmp_path / "missing.json"), "-o", str(out)])
    assert res.exit_code == 6


def test_a2a_peers_are_outside_shadowscan_reconciliation(declared_bom) -> None:
    # the example's A2A peer card is declared (a2a-cards collector) but ShadowScan never inventories A2A peers
    peers = [s for s in declared_bom.tool_servers if s.server_kind is E.ToolServerKind.A2A]
    assert peers, "the example agent ships an A2A peer card"
    rec = reconcile(declared_bom, read_report(TRIAGE), scan_root="/work/triage-agent", deterministic=True)
    assert not {p.id for p in peers} & set(rec.declared_not_observed)
    observed = import_report(read_report(TRIAGE), deterministic=True, scope="root", policy=False)
    result = run_policy(observed, select=["SYM-SS-003"], baseline=declared_bom)
    assert not [f for f in result.findings if set(f.subject_refs) & {p.id for p in peers}]
