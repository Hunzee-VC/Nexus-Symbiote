"""A ShadowScan rerun that only records new run times is not drift.

The exact-byte digest still authenticates the report; a normalized content
digest under a versioned profile is what diff compares.
"""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners.shadowscan import (
    CONTENT_PROFILE,
    ShadowScanImporter,
    report_content_digest,
)

FIXTURES = Path(__file__).parent / "fixtures"
REPORT = FIXTURES / "shadowscan/code-report-0.1.4.json"
CYCLONEDX = FIXTURES / "shadowscan-producer/cyclonedx-agent-model.json"
SCHEMA = Path(__file__).parents[1] / "schemas/nexus-symbiote-aibom-1.0.schema.json"
SERVER = "shadowscan:6a6016901367"
AGENT = "shadowscan:bbc418bfbfea"

MINIMAL = {
    "version": "0.1.4",
    "started_at": "2026-01-01T00:00:00Z",
    "finished_at": "2026-01-01T00:00:01Z",
    "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
    "stats": [
        {
            "connector": "code.filesystem",
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "errors": [],
            "skipped": False,
            "incomplete": False,
        }
    ],
    "findings": [
        {
            "id": "ss-1",
            "kind": "agent",
            "surface": "code",
            "confidence": 0.5,
            "first_seen": None,
            "last_seen": "2026-01-01T00:00:01Z",
        }
    ],
}


def _rerun(data: dict) -> dict:
    """The same findings, collected again: only run-event fields change."""
    data = json.loads(json.dumps(data))
    data["started_at"], data["finished_at"] = (
        "2026-11-02T00:10:00+00:00",
        "2026-11-02T00:10:05+00:00",
    )
    for stat in data["stats"]:
        stat["started_at"], stat["finished_at"] = data["started_at"], data["finished_at"]
    for finding in data["findings"]:
        finding["last_seen"] = data["finished_at"]
    return data


def _scan(tmp_path: Path, name: str, report: bytes) -> Path:
    project, out = tmp_path / "proj", tmp_path / f"{name}.json"
    (project / ".shadowscan").mkdir(parents=True, exist_ok=True)
    (project / ".shadowscan/report.json").write_bytes(report)
    CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(out)])
    assert out.is_file()
    return out


def _load(path: Path) -> AIBOM:
    return AIBOM.model_validate(json.loads(path.read_text()))


def test_content_digest_vectors():
    # Independent derivation: the RFC 8785 bytes of the report without run-event fields.
    canonical = (
        b'{"findings":[{"confidence":0.5,"first_seen":null,"id":"ss-1","kind":"agent",'
        b'"surface":"code"}],"stats":[{"connector":"code.filesystem","errors":[],'
        b'"incomplete":false,"skipped":false}],"summary":{"complete":true,'
        b'"declared_omissions":0,"tolerated_gaps":0},"version":"0.1.4"}'
    )
    expected = "sha256:" + hashlib.sha256(canonical).hexdigest()
    assert expected == "sha256:4ac4e303546a3beb416d33455f0a4cc32a1a85da0da7f7e5d3651772b8232e6e"
    assert report_content_digest(MINIMAL) == expected
    finding = b'{"confidence":0.5,"first_seen":null,"id":"ss-1","kind":"agent","surface":"code"}'
    imported = ShadowScanImporter().parse_report(json.dumps(MINIMAL))
    assert imported.components[0].properties["shadowscan:finding-sha256"] == (
        "sha256:" + hashlib.sha256(finding).hexdigest()
    )
    assert CONTENT_PROFILE == "nexus-symbiote/shadowscan-content/v1"

    bundled = ShadowScanImporter().parse_report(REPORT.read_bytes())
    assert bundled.digest == (
        "sha256:09ee8e976318815bf9beaac994af0457d8c75574a0122610223bbe0cbc16ad48"
    )
    assert bundled.content_digest == (
        "sha256:eec0919b1ee517aaf6a267b578145f775a79735796bda48e65615900d44e9532"
    )
    findings = {
        c.bom_ref[:23]: c.properties["shadowscan:finding-sha256"] for c in bundled.components
    }
    assert findings == {
        SERVER: "sha256:c83f0e61de716710b20bbc35df1ff96b1623f43b86caf077b379afe953081025",
        AGENT: "sha256:e839814738a8a2e337cde0a9c25d66fd12a62e00b6013be20ab46d9335a8fc14",
    }
    cyclonedx = ShadowScanImporter().parse_report(CYCLONEDX.read_bytes())
    assert cyclonedx.content_digest == (
        "sha256:f87e13565a540ba18d08f8229df966e85518410b960df9ccc1c212919813c01b"
    )


def test_content_digest_ignores_layout_and_run_times_but_not_content():
    data = json.loads(REPORT.read_text())
    baseline = ShadowScanImporter().parse_report(REPORT.read_bytes())
    for variant in (
        json.dumps(data, sort_keys=True),
        json.dumps(data, separators=(",", ":")),
        json.dumps(_rerun(data), indent=4),
    ):
        imported = ShadowScanImporter().parse_report(variant)
        assert imported.digest != baseline.digest
        assert imported.content_digest == baseline.content_digest
    for edit in (
        lambda d: d["findings"][0]["permissions"].append("filesystem:write:/"),
        lambda d: d["findings"][0].update(first_seen="2026-11-02T00:10:00+00:00"),
        lambda d: d["stats"][0].update(objects_examined=3),
        lambda d: d.update(future_field=True),
        lambda d: d.update(started_at={"hidden": "content"}),
        lambda d: d["findings"][1].update(last_seen="not a timestamp"),
    ):
        changed = json.loads(REPORT.read_text())
        edit(changed)
        assert ShadowScanImporter().parse_report(json.dumps(changed)).content_digest != (
            baseline.content_digest
        )


def test_rerun_with_only_new_run_times_raises_no_drift_alert(tmp_path):
    first = _scan(tmp_path, "s0", REPORT.read_bytes())
    second = _scan(tmp_path, "s1", json.dumps(_rerun(json.loads(REPORT.read_text()))).encode())
    result = CliRunner().invoke(main, ["diff", "--fail-on-alert", str(first), str(second)])
    assert result.exit_code == 0, result.output
    report = AIBOMDiffer().diff(_load(first), _load(second))
    assert report.security_alerts == []
    assert report.metadata_changes == [
        {
            "field": "completeness.source_report_digest",
            "severity": "info",
            "detail": "ShadowScan report regenerated; normalized content unchanged.",
        }
    ]
    # Authentication still binds the exact bytes: the first BOM does not verify the rerun.
    verified = CliRunner().invoke(
        main, ["verify-discovery", str(first), str(tmp_path / "proj/.shadowscan/report.json")]
    )
    assert verified.exit_code != 0 and "Discovery report digest mismatch" in verified.output


def test_changed_finding_alerts_on_that_component_only(tmp_path):
    first = _scan(tmp_path, "s0", REPORT.read_bytes())
    changed = _rerun(json.loads(REPORT.read_text()))
    changed["findings"][0]["permissions"].append("filesystem:write:/")
    second = _scan(tmp_path, "s1", json.dumps(changed).encode())
    result = CliRunner().invoke(main, ["diff", "--fail-on-alert", str(first), str(second)])
    assert result.exit_code == 1
    report = AIBOMDiffer().diff(_load(first), _load(second))
    components = {alert["component"] for alert in report.security_alerts}
    assert {ref[:23] for ref in components - {"metadata"}} == {SERVER}
    assert any(
        "ShadowScan finding content changed" in alert["alert"] for alert in report.security_alerts
    )
    assert {"severity": "high", "component": "metadata"}.items() <= report.security_alerts[
        0
    ].items()


def test_inventories_without_content_digests_keep_the_strict_comparison(tmp_path):
    first = _scan(tmp_path, "s0", REPORT.read_bytes())
    second = _scan(tmp_path, "s1", json.dumps(_rerun(json.loads(REPORT.read_text()))).encode())
    legacy = []
    for path in (first, second):
        doc = json.loads(path.read_text())
        claim = doc["metadata"]["completeness"]
        claim["source_report_content_digest"] = claim["source_report_content_profile"] = None
        for component in doc["components"]:
            component["properties"].pop("shadowscan:finding-sha256", None)
        legacy.append(AIBOM.model_validate(doc))
    report = AIBOMDiffer().diff(*legacy)
    assert {"severity": "high", "component": "metadata"}.items() <= report.security_alerts[
        0
    ].items()
    assert len([a for a in report.security_alerts if a["component"] != "metadata"]) == 2


def test_cyclonedx_rerun_keeps_projected_dependencies(tmp_path):
    data = json.loads(CYCLONEDX.read_text())
    first = ShadowScanImporter().parse_report(json.dumps(data)).to_native_bom()
    data["metadata"]["timestamp"] = "2026-11-02T00:10:00Z"
    data["serialNumber"] = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
    second = ShadowScanImporter().parse_report(json.dumps(data)).to_native_bom()
    assert first.dependencies and first.dependencies == second.dependencies
    report = AIBOMDiffer().diff(first, second)
    assert report.security_alerts == []
    assert not report.dependencies_added and not report.dependencies_removed


def test_project_reconciliation_rejects_an_edited_content_digest(tmp_path):
    bom = _scan(tmp_path, "s0", REPORT.read_bytes())
    doc = json.loads(bom.read_text())
    doc["metadata"]["completeness"]["source_report_content_digest"] = "sha256:" + "0" * 64
    bom.write_text(json.dumps(doc))
    result = CliRunner().invoke(
        main, ["validate", str(bom), "--project", str(tmp_path / "proj"), "--no-project-policy"]
    )
    assert result.exit_code != 0
    assert "Local discovery report differs from the recorded digest." in result.output


@pytest.mark.parametrize(
    ("field", "value", "valid"),
    [
        ("source_report_content_digest", "sha256:" + "a" * 64, True),
        ("source_report_content_profile", CONTENT_PROFILE, True),
        ("source_report_content_digest", "sha256:" + "A" * 64, False),
        ("source_report_content_digest", "a" * 64, False),
        ("source_report_content_profile", "nexus-symbiote/shadowscan-content/v0", False),
    ],
)
def test_schema_describes_the_content_digest_fields(tmp_path, field, value, valid):
    doc = json.loads(_scan(tmp_path, "s0", REPORT.read_bytes()).read_text())
    doc["metadata"]["completeness"][field] = value
    errors = list(Draft202012Validator(json.loads(SCHEMA.read_text())).iter_errors(doc))
    assert not errors if valid else errors


def test_import_records_the_content_digest_and_profile(tmp_path):
    shutil.copy(REPORT, tmp_path / "report.json")
    out = tmp_path / "bom.json"
    CliRunner().invoke(main, ["import-shadowscan", str(tmp_path / "report.json"), "-o", str(out)])
    claim = json.loads(out.read_text())["metadata"]["completeness"]
    assert claim["source_report_content_profile"] == CONTENT_PROFILE
    assert claim["source_report_content_digest"] == (
        "sha256:eec0919b1ee517aaf6a267b578145f775a79735796bda48e65615900d44e9532"
    )
