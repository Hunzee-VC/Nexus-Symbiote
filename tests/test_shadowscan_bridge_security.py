"""ShadowScan import: source claims remain untrusted and loss is visible."""

import hashlib
import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, AutonomyLevel, ComponentType, TrustTier
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
from nexus_symbiote.validators.completeness import CompletenessValidator
from nexus_symbiote.validators.risk import RiskScorer


def _report():
    return {
        "version": "0.1.4",
        "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
        "stats": [
            {
                "connector": "code.filesystem",
                "errors": [],
                "skipped": False,
                "incomplete": False,
                "declared_omissions": 0,
            }
        ],
        "findings": [
            {
                "id": "agent-CANARY",
                "kind": "agent",
                "surface": "code",
                "title": "CANARY",
                "resource": "CANARY",
                "evidence": [{"snippet": "CANARY"}],
                "risk": {"level": "high"},
                "shadow": True,
            },
            {
                "id": "server",
                "kind": "mcp-server",
                "surface": "endpoint",
                "metadata": {"url": "https://x/CANARY"},
                "risk": {"level": "critical"},
            },
            {"id": "process", "kind": "runtime-process", "surface": "runtime", "title": "CANARY"},
        ],
    }


def test_native_import_has_source_digest_loss_and_no_raw_secrets(tmp_path):
    path = tmp_path / "report.json"
    raw = json.dumps(_report()).encode()
    path.write_bytes(raw)
    imported = ShadowScanImporter().read_report(path)
    assert imported.digest == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert imported.source_status == "complete"
    assert imported.unmapped_count == 1 and imported.unmapped_indexes == [2]
    assert len(imported.components) == 2
    assert "CANARY" not in repr(imported)
    agent = next(c for c in imported.components if c.component_type == ComponentType.AGENT)
    assert agent.autonomy_level == AutonomyLevel.UNKNOWN
    assert (
        agent.assurance_level == AssuranceLevel.DECLARED and agent.trust_tier == TrustTier.UNKNOWN
    )
    assert not agent.source_path


def test_cli_bom_preserves_uncertainty_and_confines_sensitive_data(tmp_path):
    path, out = tmp_path / "report.json", tmp_path / "bom.json"
    path.write_text(json.dumps(_report()))
    result = CliRunner().invoke(main, ["import-shadowscan", str(path), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "CANARY" not in out.read_text()
    bom = AIBOM.load(out)
    claim = bom.metadata.completeness
    assert claim.source_unmapped_indexes == [2]
    assert claim.scanner_status == {"shadowscan": "partial"}
    assert not CompletenessValidator().validate(bom).is_complete
    assert not RiskScorer().passes_gate(bom)[0]
    cdx = CycloneDXGenerator().generate(bom)
    assert cdx["compositions"][0]["aggregate"] == "incomplete"
    assert any(
        p["name"] == "nexus-symbiote:discovery:reportSha256" for p in cdx["metadata"]["properties"]
    )
    assert "CANARY" not in json.dumps(cdx)


def test_incomplete_source_writes_partial_bom_and_fails(tmp_path):
    report = _report()
    report["stats"][0]["incomplete"] = True
    path, out = tmp_path / "report.json", tmp_path / "bom.json"
    path.write_text(json.dumps(report))
    result = CliRunner().invoke(main, ["import-shadowscan", str(path), "-o", str(out)])
    assert result.exit_code != 0 and out.exists()
    claim = AIBOM.load(out).metadata.completeness
    assert claim.source_report_status == "incomplete" and claim.scan_failures


def test_source_cannot_be_overwritten(tmp_path):
    path = tmp_path / "report.json"
    original = json.dumps(_report())
    path.write_text(original)
    result = CliRunner().invoke(main, ["import-shadowscan", str(path), "-o", str(path)])
    assert result.exit_code != 0 and path.read_text() == original


def test_verify_discovery_checks_exact_bytes_without_claiming_authenticity(tmp_path):
    report, bom = tmp_path / "report.json", tmp_path / "bom.json"
    report.write_text(json.dumps(_report()))
    runner = CliRunner()
    assert runner.invoke(main, ["import-shadowscan", str(report), "-o", str(bom)]).exit_code == 0
    result = runner.invoke(main, ["verify-discovery", str(bom), str(report)])
    assert result.exit_code == 0
    assert "Source identity, signature, and truth were not verified" in result.output
    report.write_text(report.read_text() + " ")
    result = runner.invoke(main, ["verify-discovery", str(bom), str(report)])
    assert result.exit_code != 0 and "digest mismatch" in result.output


def test_verify_discovery_rejects_missing_digest(tmp_path):
    report, bom = tmp_path / "report.json", tmp_path / "bom.json"
    report.write_text(json.dumps(_report()))
    bom.write_text(AIBOM().to_json())
    result = CliRunner().invoke(main, ["verify-discovery", str(bom), str(report)])
    assert result.exit_code != 0 and "valid ShadowScan report digest" in result.output


@pytest.mark.parametrize("fmt", ["spdx", "sarif"])
def test_lossy_outputs_fail_closed(tmp_path, fmt):
    path, out = tmp_path / "report.json", tmp_path / "bom.json"
    path.write_text(json.dumps(_report()))
    result = CliRunner().invoke(main, ["import-shadowscan", str(path), "-f", fmt, "-o", str(out)])
    assert result.exit_code != 0 and not out.exists()
    assert "cannot yet preserve discovery coverage" in result.output


@pytest.mark.parametrize("content", ['{"version":"a","version":"b"}', '{"x":NaN}', "[]"])
def test_bad_or_duplicate_json_is_rejected(tmp_path, content):
    path = tmp_path / "report.json"
    path.write_text(content)
    with pytest.raises(ValueError):
        ShadowScanImporter().read_report(path)


def test_duplicate_ids_rejected(tmp_path):
    report = _report()
    report["findings"][1]["id"] = report["findings"][0]["id"]
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="duplicate"):
        ShadowScanImporter().read_report(path)


def test_cyclonedx_services_and_unknown_composition_are_not_ignored(tmp_path):
    report = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"properties": [{"name": "shadowscan:scan:status", "value": "complete"}]},
        "components": [],
        "services": [{"bom-ref": "ss-service", "group": "mcp-server", "name": "CANARY"}],
        "compositions": [{"aggregate": "unknown"}, {"aggregate": "incomplete"}],
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    imported = ShadowScanImporter().read_report(path)
    assert imported.source_status == "complete"
    assert any("incomplete composition" in item for item in imported.limitations)
    assert imported.components[0].component_type == ComponentType.MCP_SERVER
    assert "CANARY" not in repr(imported)


def test_conventional_scan_carries_source_fingerprint(tmp_path):
    directory = tmp_path / ".shadowscan"
    directory.mkdir()
    path, out = directory / "report.json", tmp_path / "bom.json"
    path.write_text(json.dumps(_report()))
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--scanner", "shadowscan", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    claim = AIBOM.load(out).metadata.completeness
    assert claim.source_report_digest == "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    assert claim.scanner_status["shadowscan"] == "partial"
