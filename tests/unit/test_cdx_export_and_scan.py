from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from symbiote.cli import app
from symbiote.export.cdx import export_cyclonedx, validate_cyclonedx
from symbiote.model import AgentBOM
from symbiote.model import enums as E
from symbiote.scan import scan

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "triage-agent"


def _props(obj: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in obj.get("properties", []) or []:
        out.setdefault(p["name"], []).append(p["value"])
    return out


def test_minimal_export_validates_and_maps(minimal_bom: AgentBOM) -> None:
    doc, loss = export_cyclonedx(
        minimal_bom, companion_digest="sha256:" + "11" * 32, companion_ref="agentbom.json"
    )
    assert validate_cyclonedx(doc) == []
    assert doc["specVersion"] == "1.7" and doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["component"]["bom-ref"] == "agent:triager"
    assert {lc.get("phase") or lc.get("name") for lc in doc["metadata"]["lifecycles"]} == {
        "design",
        "agentbom:snapshot:declared",
    }
    mp = _props(doc["metadata"])
    assert mp["agentbom:snapshot:kind"] == ["declared"] and mp["agentbom:companion:digest"] == [
        "sha256:" + "11" * 32
    ]
    svc = doc["services"][0]
    assert (
        svc["bom-ref"] == "server:github" and svc["authenticated"] is True and svc["x-trust-boundary"] is True
    )
    sp = _props(svc)
    assert (
        sp["agentbom:kind"] == ["mcp-server"]
        and sp["agentbom:mcp:env-var-name"] == ["GITHUB_TOKEN"]
        and sp["agentbom:mcp:transport"] == ["stdio"]
    )
    tool = next(c for c in doc["components"] if c["bom-ref"] == "tool:github/get_issue")
    assert (
        tool["type"] == "data"
        and tool["data"][0]["type"] == "definition"
        and tool["hashes"][0]["alg"] == "SHA-256"
    )
    assert "contents" not in tool["data"][0]  # digests only by default
    deps = {d["ref"]: d for d in doc["dependencies"]}
    assert deps["server:github"]["provides"] == ["tool:github/get_issue"]
    assert deps["agent:triager"]["dependsOn"] == ["tool:github/get_issue"]
    assert {c["bom-ref"] for c in doc["compositions"]} >= {"composition:tools", "composition:document"}
    assert all(c["aggregate"] == "unknown" for c in doc["compositions"])  # nothing was queried in the fixture
    assert loss.lossless and loss.model_digest == minimal_bom.snapshot.digest
    # never modelCard.properties, never secrets
    text = json.dumps(doc)
    assert '"modelCard": {"properties"' not in text and "sk-" not in text


def test_export_is_deterministic(minimal_bom: AgentBOM) -> None:
    a, _ = export_cyclonedx(minimal_bom)
    b, _ = export_cyclonedx(minimal_bom)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_include_text_embeds_definition(minimal_bom: AgentBOM) -> None:
    doc, _ = export_cyclonedx(minimal_bom, include_text=True)
    tool = next(c for c in doc["components"] if c["bom-ref"] == "tool:github/get_issue")
    att = tool["data"][0]["contents"]["attachment"]
    assert att["encoding"] == "base64" and att["contentType"] == "application/json"
    assert validate_cyclonedx(doc) == []


@pytest.mark.skipif(not EXAMPLE.exists(), reason="example fixture missing")
def test_scan_example_and_export() -> None:
    outcome = scan(EXAMPLE, deterministic=True)
    bom = outcome.bom
    assert bom.subject == "agent:triage-agent"
    assert len(bom.tool_servers) >= 5 and any("filesystem" in s.id for s in bom.tool_servers)
    assert bom.identities and all("sk-" not in i.ref for i in bom.identities)
    assert bom.coverage.surfaces[E.Surface.TOOLS].status in (
        E.CoverageStatus.QUERIED,
        E.CoverageStatus.PARTIAL,
    )
    assert bom.coverage.surfaces[E.Surface.RUNTIME].status is E.CoverageStatus.NOT_ATTEMPTED
    again = scan(EXAMPLE, deterministic=True)
    assert again.bom.snapshot.digest == bom.snapshot.digest  # deterministic
    doc, loss = export_cyclonedx(bom)
    assert validate_cyclonedx(doc) == []
    floating = [s for s in doc["services"] if "filesystem" in s["bom-ref"]]
    assert floating and any(
        p["name"] == "agentbom:mcp:pinned" and p["value"] in ("false", "unknown")
        for s in floating
        for p in s["properties"]
    )
    assert all(
        i.severity is not E.LossSeverity.SECURITY_RELEVANT or i.preserved_in is not E.LossPreservedIn.DROPPED
        for i in loss.items
    )


@pytest.mark.skipif(not EXAMPLE.exists(), reason="example fixture missing")
def test_cli_scan(tmp_path: Path) -> None:
    runner = CliRunner()
    r = runner.invoke(app, ["scan", str(EXAMPLE), "-o", str(tmp_path), "--deterministic", "--json"])
    assert r.exit_code == 0, r.output
    summary = json.loads(r.stdout)
    assert (
        summary["cyclonedxValid"] is True
        and (tmp_path / "agentbom.cdx.json").exists()
        and (tmp_path / "agentbom.json").exists()
    )
    r = runner.invoke(
        app, ["validate", str(tmp_path / "agentbom.cdx.json"), str(tmp_path / "agentbom.json"), "--json"]
    )
    assert r.exit_code == 0, r.output
    assert all(x["ok"] for x in json.loads(r.stdout))
