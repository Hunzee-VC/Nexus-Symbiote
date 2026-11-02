"""Contract and hostile-input tests for ShadowScan CycloneDX associations."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.scanners.shadowscan import PROJECTION_PROFILE, ShadowScanImporter
from nexus_symbiote.validators.completeness import CompletenessValidator

FIXTURE = Path(__file__).parent / "fixtures/shadowscan-producer/cyclonedx-agent-model.json"


def test_actual_producer_projection_preserves_declared_edge_and_omits_raw_names():
    report = ShadowScanImporter().read_report(FIXTURE)
    assert len(report.components) == 2
    assert len(report.dependencies) == 1
    by_ref = {c.bom_ref: c for c in report.components}
    edge = report.dependencies[0]
    assert by_ref[edge.source_ref].component_type == ComponentType.AGENT
    assert by_ref[edge.target_ref].component_type == ComponentType.MODEL
    assert edge.relationship == "depends-on" and edge.assurance_level == "declared"
    assert report.digest in edge.conditions
    assert "dependencies index 0" in edge.conditions
    assert all(
        c.properties["shadowscan:projection-profile"] == PROJECTION_PROFILE
        for c in report.components
    )
    assert "synthetic-agent" not in repr(report)
    assert "example/model:1" not in repr(report)
    assert report.to_native_bom().dependencies == report.dependencies


def test_unmapped_endpoints_are_accounted_for_without_exposing_identifiers():
    data = json.loads(FIXTURE.read_text())
    data["dependencies"][0]["dependsOn"].append("unmapped-secret-CANARY")
    report = ShadowScanImporter().parse_report(json.dumps(data))
    assert len(report.dependencies) == 1
    assert any("1 source dependency edges" in item for item in report.limitations)
    assert "CANARY" not in repr(report)


@pytest.mark.parametrize("generator", [CycloneDXGenerator, SPDXGenerator])
def test_portable_round_trip_retains_source_edge_assurance(generator):
    report = ShadowScanImporter().read_report(FIXTURE)
    exporter = generator()
    recovered = exporter.recover(exporter.generate(report.to_native_bom()))
    assert recovered.dependencies == report.dependencies
    assert recovered.metadata.completeness.source_report_digest == report.digest


@pytest.mark.parametrize(
    "dependencies",
    [
        {},
        [None],
        [{"ref": "a", "dependsOn": "b"}],
        [{"ref": "a", "dependsOn": ["b", "b"]}],
        [{"ref": "a"}, {"ref": "a"}],
        [{"ref": "a", "dependsOn": ["b"] * 10_001}],
    ],
)
def test_malformed_or_oversized_edges_fail_closed(dependencies):
    data = json.loads(FIXTURE.read_text())
    data["dependencies"] = dependencies
    with pytest.raises(ValueError):
        ShadowScanImporter().parse_report(json.dumps(data))


def test_direct_import_scan_and_projection_verification_preserve_edges(tmp_path):
    report = tmp_path / "shadowscan.json"
    report.write_bytes(FIXTURE.read_bytes())
    direct, scanned = tmp_path / "direct.json", tmp_path / "scanned.json"
    runner = CliRunner()
    imported = runner.invoke(
        main, ["import-shadowscan", str(report), "-o", str(direct), "--report-only"]
    )
    assert imported.exit_code == 0, imported.output
    checked = runner.invoke(main, ["verify-discovery", str(direct), str(report), "--projection"])
    assert checked.exit_code == 0, checked.output
    scan = runner.invoke(
        main,
        ["scan", str(tmp_path), "--scanner", "shadowscan", "-o", str(scanned), "--report-only"],
    )
    assert scan.exit_code == 0, scan.output
    for path in (direct, scanned):
        bom = AIBOM.load(path)
        edges = [edge for edge in bom.dependencies if edge.assurance_level == "declared"]
        assert len(edges) == 1 and edges[0].relationship == "depends-on"
        assert "example/model:1" not in path.read_text()


@pytest.mark.parametrize(
    "edit", ["omitted", "assurance", "conditions", "reversed", "duplicate", "added"]
)
def test_project_reconciliation_binds_imported_dependency_claims(tmp_path, edit):
    project = tmp_path / "project"
    project.mkdir()
    (project / "shadowscan.json").write_bytes(FIXTURE.read_bytes())
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(main, ["scan", str(project), "-o", str(output), "--report-only"])
    assert result.exit_code == 0, result.output
    bom = AIBOM.load(output)
    validator = CompletenessValidator()
    message = "Discovery report dependency claims differ from the source projection."
    # CycloneDX coverage is still partial; check the specific reconciliation finding.
    assert not any(
        issue.description == message
        for issue in validator.validate_against_project(bom, project).issues
    )
    edge = next(e for e in bom.dependencies if e.source_ref.startswith("shadowscan:"))
    if edit == "omitted":
        bom.dependencies.remove(edge)
    elif edit == "assurance":
        edge.assurance_level = "verified"
    elif edit == "conditions":
        edge.conditions = "fabricated provenance"
    elif edit == "reversed":
        edge.source_ref, edge.target_ref = edge.target_ref, edge.source_ref
    elif edit == "duplicate":
        bom.dependencies.append(edge.model_copy())
    else:
        bom.dependencies.append(edge.model_copy(update={"relationship": "uses-model"}))
    assert any(
        issue.description == message
        for issue in validator.validate_against_project(bom, project).issues
    )
