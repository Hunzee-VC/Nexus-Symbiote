"""``symbiote import`` and ``symbiote convert``: formats, loss reports, exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from symbiote.cli import app
from symbiote.export.cdx import export_cyclonedx
from symbiote.export.companion import companion_bytes, load_companion
from symbiote.model import AgentBOM

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "triage-agent"


def _write(tmp_path: Path, name: str, data: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("fixture", "fmt", "dialect", "kind"),
    [
        ("k8s_aibom.cdx.json", "auto", "k8s-aibom", "deployed"),
        ("k8s_aibom.cdx.json", "k8s-aibom", "k8s-aibom", "deployed"),
        ("cdxgen_aibom.cdx.json", "cdxgen", "cdxgen", "declared"),
        ("harness_aibom.cdx.json", "harness-aibom", "harness-aibom", "declared"),
    ],
)
def test_import_fixtures(tmp_path: Path, fixture: str, fmt: str, dialect: str, kind: str) -> None:
    runner = CliRunner()
    out = tmp_path / "agentbom.json"
    r = runner.invoke(
        app,
        ["import", str(FIXTURES / fixture), "--format", fmt, "-o", str(out), "--loss-report", "--json"],
    )
    assert r.exit_code == 0, r.output
    summary = json.loads(r.stdout)
    assert summary["dialect"] == dialect and summary["kind"] == kind
    assert summary["loss"]["rows"] is not None and (tmp_path / "agentbom.json.loss.json").exists()
    bom = load_companion(out)
    assert bom.subject == summary["agent"] and bom.loss_report is not None


def test_import_as_override_and_strict(tmp_path: Path, minimal_bom: AgentBOM) -> None:
    runner = CliRunner()
    doc, _ = export_cyclonedx(minimal_bom)
    src = _write(tmp_path, "native.cdx.json", doc)
    r = runner.invoke(app, ["import", str(src), "--as", "observed", "-o", str(tmp_path / "a.json"), "--json"])
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)["kind"] == "observed"
    # a verified assurance the projection cannot substantiate is dropped: --strict exits 8
    for p in doc["services"][0]["properties"]:
        if p["name"] == "agentbom:assurance":
            p["value"] = "verified"
    src = _write(tmp_path, "verified.cdx.json", doc)
    r = runner.invoke(app, ["import", str(src), "-o", str(tmp_path / "b.json"), "--json"])
    assert r.exit_code == 0 and json.loads(r.stdout)["loss"]["securityRelevantDropped"] == 1
    r = runner.invoke(app, ["import", str(src), "-o", str(tmp_path / "c.json"), "--strict", "--json"])
    assert r.exit_code == 8, r.output


def test_import_rejects_bad_input(tmp_path: Path) -> None:
    runner = CliRunner()
    src = _write(
        tmp_path, "bad.json", {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [{"name": "x"}]}
    )
    r = runner.invoke(app, ["import", str(src), "--json"])
    assert r.exit_code == 3, r.output
    r = runner.invoke(app, ["import", str(tmp_path / "missing.json"), "--json"])
    assert r.exit_code == 6
    r = runner.invoke(app, ["import", str(src), "--format", "syft"])
    assert r.exit_code == 2


@pytest.mark.skipif(not EXAMPLE.exists(), reason="example fixture missing")
def test_convert_round_trips_through_every_format(tmp_path: Path) -> None:
    from symbiote.scan import scan

    runner = CliRunner()
    bom = scan(EXAMPLE, deterministic=True).bom
    companion = tmp_path / "agentbom.json"
    companion.write_bytes(companion_bytes(bom))
    cdx = tmp_path / "out.cdx.json"
    r = runner.invoke(
        app, ["convert", str(companion), "-o", str(cdx), "--to", "cyclonedx", "--loss-report", "--json"]
    )
    assert r.exit_code == 0, r.output
    summary = json.loads(r.stdout)
    assert (
        summary["valid"] and summary["sourceFormat"] == "agentbom-companion" and "export" in summary["loss"]
    )
    assert (tmp_path / "out.cdx.json.loss.json").exists()
    spdx = tmp_path / "out.spdx.json"
    r = runner.invoke(app, ["convert", str(cdx), "-o", str(spdx), "--to", "spdx", "--json"])
    assert r.exit_code == 0, r.output
    summary = json.loads(r.stdout)
    assert (
        summary["valid"]
        and summary["sourceFormat"] == "cyclonedx-1.7"
        and set(summary["loss"]) == {"import", "export"}
    )
    back = tmp_path / "back.json"
    r = runner.invoke(app, ["convert", str(spdx), "-o", str(back), "--to", "companion", "--json"])
    assert r.exit_code == 0, r.output
    imported = load_companion(back)
    assert {e.id for _, e in imported.iter_entities()} == {e.id for _, e in bom.iter_entities()}
    assert {e.key for e in imported.edges} == {e.key for e in bom.edges}
    r = runner.invoke(app, ["validate", str(cdx), str(spdx), str(back), "--json"])
    assert r.exit_code == 0 and all(x["ok"] for x in json.loads(r.stdout))


def test_convert_strict_exits_8_on_security_relevant_loss(tmp_path: Path, minimal_bom: AgentBOM) -> None:
    runner = CliRunner()
    doc, _ = export_cyclonedx(minimal_bom)
    for p in doc["services"][0]["properties"]:
        if p["name"] == "agentbom:assurance":
            p["value"] = "verified"
    src = _write(tmp_path, "verified.cdx.json", doc)
    r = runner.invoke(
        app, ["convert", str(src), "-o", str(tmp_path / "out.spdx.json"), "--to", "spdx", "--json"]
    )
    assert r.exit_code == 0, r.output
    r = runner.invoke(
        app, ["convert", str(src), "-o", str(tmp_path / "out2.spdx.json"), "--to", "spdx", "--strict"]
    )
    assert r.exit_code == 8, r.output
    r = runner.invoke(app, ["convert", str(src), "-o", str(tmp_path / "x"), "--to", "xml"])
    assert r.exit_code == 2
