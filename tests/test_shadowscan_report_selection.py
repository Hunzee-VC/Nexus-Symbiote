"""Which ShadowScan report is read, what it may not drop, and where its findings may appear."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.vex import VEXGenerator
from nexus_symbiote.scanners.shadowscan import (
    MAX_DEPENDENCIES,
    MAX_FINDINGS,
    MAX_REPORT_BYTES,
    REPORT_PATHS,
    UNRECOGNIZED_VALUES_GAP,
    ShadowScanImporter,
)

REPORT = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"


def _report(**finding_fields) -> dict:
    finding = {"id": "f-1", "kind": "agent", "surface": "code", **finding_fields}
    return {
        "version": "0.1.4",
        "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
        "stats": [{"errors": [], "skipped": False, "incomplete": False}],
        "findings": [finding],
    }


def _place(root: Path, relative: str, content: bytes) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)


def test_reports_at_two_supported_paths_are_a_failure_and_neither_is_imported(tmp_path):
    fresh = REPORT.read_bytes()
    stale = json.dumps(_report()).encode()
    _place(tmp_path, "shadowscan.json", fresh)
    _place(tmp_path, ".shadowscan/report.json", stale)
    result = ShadowScanImporter().scan(tmp_path)
    assert result.scan_failures == [
        "ShadowScan reports found at more than one supported path "
        "(.shadowscan/report.json, shadowscan.json); keep exactly one"
    ]
    assert not result.components and result.source_report_digest is None


def test_one_report_under_two_names_is_one_report(tmp_path):
    _place(tmp_path, "shadowscan.json", REPORT.read_bytes())
    os.link(tmp_path / "shadowscan.json", tmp_path / "shadowscan-report.json")
    result = ShadowScanImporter().scan(tmp_path)
    assert not result.scan_failures
    assert result.source_report_path == "shadowscan-report.json"


@pytest.mark.parametrize("relative", REPORT_PATHS)
def test_the_inventory_records_which_report_was_read(tmp_path, relative):
    project = tmp_path / "project"
    _place(project, relative, REPORT.read_bytes())
    output = tmp_path / "bom.json"
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    assert CliRunner().invoke(main, args).exit_code == 0
    surfaces = json.loads(output.read_text())["metadata"]["completeness"]["surfaces_scanned"]
    assert relative in surfaces and "shadowscan:report" in surfaces


@pytest.mark.parametrize(
    ("fields", "value"),
    [
        ({"risk": {"level": "Critical"}}, "a risk level"),
        ({"risk": "high"}, "a risk level"),
        ({"risk": {"score": 90, "factors": []}}, "a risk level"),
        ({"risk": {"level": None, "score": 90}}, "a risk level"),
        ({"shadow": "true"}, "a shadow flag"),
        ({"surface": "satellite"}, "a surface"),
    ],
)
def test_unrecognized_values_are_projection_gaps_not_silence(tmp_path, fields, value):
    report = _report(**fields)
    imported = ShadowScanImporter().parse_report(json.dumps(report))
    assert imported.components and not imported.components[0].risks
    assert (
        f"1 source entries carry {value} the projection does not recognize; it is not represented"
        in imported.limitations
    )
    _place(tmp_path, "shadowscan.json", json.dumps(report).encode())
    assert UNRECOGNIZED_VALUES_GAP in ShadowScanImporter().scan(tmp_path).surfaces_excluded


def test_recognized_values_record_no_gap(tmp_path):
    _place(tmp_path, "shadowscan.json", REPORT.read_bytes())
    result = ShadowScanImporter().scan(tmp_path)
    assert UNRECOGNIZED_VALUES_GAP not in result.surfaces_excluded


@pytest.mark.parametrize("fields", [{}, {"risk": None}, {"risk": {}}])
def test_an_absent_rating_is_not_an_unrecognized_value(fields):
    imported = ShadowScanImporter().parse_report(json.dumps(_report(**fields)))
    assert not imported.unrecognized


def _cyclonedx(entry_type: str, group: str | None, kind: str | None) -> dict:
    properties = [{"name": "shadowscan:kind", "value": kind}] if kind else []
    entry = {"bom-ref": "e-1", "type": entry_type, "properties": properties}
    if group:
        entry["group"] = group
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"properties": [{"name": "shadowscan:scan:status", "value": "complete"}]},
        "components": [entry],
    }


@pytest.mark.parametrize(
    ("entry_type", "group", "kind", "mapped"),
    [
        ("machine-learning-model", None, "agent", None),
        ("application", "mcp-server", "agent", None),
        ("machine-learning-model", "mcp-server", None, None),
        ("machine-learning-model", None, None, "model"),
        ("machine-learning-model", None, "model", "model"),
        ("application", "mcp-server", "mcp-server", "mcp-server"),
    ],
)
def test_contradictory_cyclonedx_classification_stays_unmapped(entry_type, group, kind, mapped):
    imported = ShadowScanImporter().parse_report(json.dumps(_cyclonedx(entry_type, group, kind)))
    if mapped is None:
        assert imported.components == [] and imported.unmapped_indexes == [0]
    else:
        assert imported.components[0].component_type.value == mapped


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32", "utf-16-le"])
def test_reports_other_than_utf8_are_refused(encoding):
    text = json.dumps(_report(title="café"))
    with pytest.raises(ValueError):
        ShadowScanImporter().parse_report(text.encode(encoding))


def test_a_utf8_byte_order_mark_is_accepted_by_import_and_verification(tmp_path):
    report, bom = tmp_path / "report.json", tmp_path / "bom.json"
    report.write_bytes(b"\xef\xbb\xbf" + REPORT.read_bytes())
    runner = CliRunner()
    imported = runner.invoke(
        main, ["import-shadowscan", str(report), "-o", str(bom), "--report-only"]
    )
    assert imported.exit_code == 0, imported.output
    verified = runner.invoke(main, ["verify-discovery", str(bom), str(report), "--projection"])
    assert verified.exit_code == 0, verified.output


@pytest.mark.parametrize(
    "summary",
    [{"by_risk_level": {"high": 1}}, {"by_risk_level": {"medium": True}}, {"shadow": 1}],
)
def test_contradictory_risk_and_shadow_counts_are_invalid(summary):
    report = _report(risk={"level": "medium"})
    report["summary"].update(summary)
    with pytest.raises(ValueError, match="summary"):
        ShadowScanImporter().parse_report(json.dumps(report))


def test_matching_risk_and_shadow_counts_are_accepted():
    report = _report(risk={"level": "medium"}, shadow=True)
    report["summary"].update({"by_risk_level": {"medium": 1, "high": 0}, "shadow": 1})
    assert ShadowScanImporter().parse_report(json.dumps(report)).components


def test_finding_count_bound():
    report = _report()
    report["findings"] = [
        {"id": f"f-{i}", "kind": "agent", "surface": "code"} for i in range(MAX_FINDINGS + 1)
    ]
    with pytest.raises(ValueError, match="envelope"):
        ShadowScanImporter().parse_report(json.dumps(report))


def test_identifier_length_bound():
    with pytest.raises(ValueError, match="identifier"):
        ShadowScanImporter().parse_report(json.dumps(_report(id="x" * 4097)))


def test_dependency_edge_total_bound_fails_for_its_own_reason():
    document = _cyclonedx("application", None, "agent")
    per_source = MAX_DEPENDENCIES // 4 + 1
    document["dependencies"] = [
        {"ref": f"s{n}", "dependsOn": [f"t{n}-{i}" for i in range(per_source)]} for n in range(4)
    ]
    with pytest.raises(ValueError, match="too many CycloneDX dependency edges"):
        ShadowScanImporter().parse_report(json.dumps(document))


def test_report_byte_bound(tmp_path):
    report = tmp_path / "report.json"
    report.write_bytes(b" " * MAX_REPORT_BYTES)
    with pytest.raises(ValueError) as within:
        ShadowScanImporter().read_report(report)
    assert "outside safe read limits" not in str(within.value)
    report.write_bytes(b" " * (MAX_REPORT_BYTES + 1))
    with pytest.raises(ValueError, match="outside safe read limits"):
        ShadowScanImporter().read_report(report)


def test_report_only_import_of_an_incomplete_source_records_its_status(tmp_path):
    source = _report()
    source["stats"][0]["incomplete"] = True
    path, out = tmp_path / "report.json", tmp_path / "bom.json"
    path.write_text(json.dumps(source))
    result = CliRunner().invoke(
        main, ["import-shadowscan", str(path), "-o", str(out), "--report-only"]
    )
    assert result.exit_code == 0, result.output
    claim = AIBOM.load(out).metadata.completeness
    assert claim.source_report_status == "incomplete"
    assert "ShadowScan source report is incomplete or has unknown status" in claim.scan_failures


def _merged(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    shutil.copyfile(REPORT, project / "shadowscan.json")
    (project / "requirements.txt").write_text("openai\n")
    output = tmp_path / "bom.json"
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    assert CliRunner().invoke(main, args).exit_code == 0
    return output


def test_finding_only_exports_omit_imported_heuristics(tmp_path):
    bom = AIBOM.load(_merged(tmp_path))
    imported = sum(len(c.risks) for c in bom.components if c.bom_ref.startswith("shadowscan:"))
    assert imported
    sarif = SARIFGenerator().generate(bom)["runs"][0]
    assert not any("shadowscan" in r["ruleId"] for r in sarif["results"])
    assert sarif["results"], "local findings are still exported"
    assert sarif["properties"]["nexus-symbiote:omittedImportedFindings"] == imported
    vex = VEXGenerator().generate(bom)
    assert not any(v["affects"][0]["ref"].startswith("shadowscan:") for v in vex["vulnerabilities"])
    assert vex["metadata"]["properties"] == [
        {"name": "nexus-symbiote:omittedImportedFindings", "value": str(imported)}
    ]


def test_scan_still_refuses_sarif_for_imported_discovery(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    shutil.copyfile(REPORT, project / "shadowscan.json")
    args = ["scan", str(project), "--no-project-policy", "-f", "sarif", "-o", str(tmp_path / "s")]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1 and "SARIF cannot preserve" in result.output
