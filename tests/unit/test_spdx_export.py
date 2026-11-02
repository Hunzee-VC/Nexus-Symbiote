from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from symbiote.export.spdx import TERMS, export_spdx, validate_spdx
from symbiote.model import AgentBOM
from symbiote.model import enums as E
from symbiote.scan import scan

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "triage-agent"


def _nodes(doc: dict, typ: str) -> list[dict]:
    return [n for n in doc["@graph"] if n.get("type") == typ]


def test_minimal_spdx_validates_and_maps(minimal_bom: AgentBOM) -> None:
    doc, loss = export_spdx(
        minimal_bom, companion_digest="sha256:" + "11" * 32, companion_ref="agentbom.json"
    )
    assert validate_spdx(doc) == []
    assert doc["@context"].startswith("https://spdx.org/rdf/3.0.1/")
    sdoc = _nodes(doc, "SpdxDocument")[0]
    assert set(sdoc["profileConformance"]) >= {"core", "software", "ai", "dataset", "extension"}
    agent = _nodes(doc, "ai_AIPackage")[0]
    assert agent["spdxId"].endswith("/agent:triager") and agent["software_primaryPurpose"] == "application"
    ext_types = {e["type"] for e in agent["extension"]}
    assert TERMS + "AgentProfile" in ext_types and "extension_CdxPropertiesExtension" in ext_types
    mirror = next(e for e in agent["extension"] if e["type"] == "extension_CdxPropertiesExtension")
    names = {p["extension_cdxPropName"] for p in mirror["extension_cdxProperty"]}
    assert "agentbom:kind" in names
    tool = next(n for n in _nodes(doc, "software_Package") if n["spdxId"].endswith("tool:github/get_issue"))
    assert tool["software_primaryPurpose"] == "specification"
    assert tool["verifiedUsing"][0]["hashValue"] == "ab" * 32
    rels = _nodes(doc, "LifecycleScopedRelationship") + _nodes(doc, "Relationship")
    kinds = {(r["relationshipType"], r["from"].rsplit("/", 1)[-1]) for r in rels}
    assert ("contains", "server:github") in kinds
    # unknown surfaces are NoAssertion, never silently absent
    noassert = [
        r
        for r in rels
        if r.get("to") == ["NoAssertionElement"]
        or any("NoAssertionElement" in str(t) for t in r.get("to", []))
    ]
    assert noassert, "expected NoAssertionElement relationships for unqueried surfaces"
    sbom = _nodes(doc, "software_Sbom")[0]
    assert (
        sbom["software_sbomType"] == ["design"]
        and sbom["verifiedUsing"][0]["hashValue"] == minimal_bom.snapshot.digest[7:]
    )
    assert loss.lossless and loss.model_digest == minimal_bom.snapshot.digest


def test_spdx_export_is_deterministic(minimal_bom: AgentBOM) -> None:
    a, _ = export_spdx(minimal_bom)
    b, _ = export_spdx(minimal_bom)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


@pytest.mark.skipif(not EXAMPLE.exists(), reason="example fixture missing")
def test_spdx_example() -> None:
    bom = scan(EXAMPLE, deterministic=True).bom
    doc, loss = export_spdx(bom)
    assert validate_spdx(doc) == []
    assert len(_nodes(doc, "software_Package")) >= 5
    assert not loss.security_relevant_dropped
    text = json.dumps(doc)
    assert not re.search(r"\bsk-[A-Za-z0-9_-]{16,}", text) and "${" not in text.replace(
        "${GITHUB_PAT}", ""
    ).replace("${SLACK_WEBHOOK_URL}", "").replace("${input:github-pat}", "")


def test_empty_scoped_query_cannot_prove_runtime_absence(minimal_bom: AgentBOM) -> None:
    from symbiote.model.entities import SurfaceCoverage

    coverage = minimal_bom.coverage.replace(
        surfaces={E.Surface.DATA: SurfaceCoverage(status=E.CoverageStatus.QUERIED)}
    )
    doc, _ = export_spdx(minimal_bom.replace(coverage=coverage))
    rel = next(n for n in doc["@graph"] if n.get("spdxId", "").endswith("/rel:surface:data"))
    assert rel["scope"] == "runtime"
    assert rel["completeness"] == "noAssertion"
    assert all("NoAssertionElement" in target for target in rel["to"])
