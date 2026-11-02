"""Exact round trips of the entity kinds the WP9 static collectors produce (instructions, prompts, skills,
A2A cards, identity config, merged SBOMs, local models) through CycloneDX 1.7 and SPDX 3.0.1.

Every field compared by :func:`symbiote.snapshot.diff_body` must survive ``export → import`` with nothing
ignored; the evidence digest and its uri, and an identity bound only by an ``actsAs`` edge, are checked
explicitly because the importers used to drop them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from symbiote.export.cdx import export_cyclonedx, validate_cyclonedx
from symbiote.export.spdx import export_spdx
from symbiote.imp import import_cyclonedx, import_spdx
from symbiote.model import AgentBOM
from symbiote.model import enums as E
from symbiote.scan import scan
from symbiote.snapshot import diff_body

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "triage-agent"
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
WP9_KINDS = ("agent", "instr", "prompt", "skill", "model", "ident", "cred", "ev", "sw")


@pytest.fixture(scope="module")
def example_bom() -> AgentBOM:
    if not EXAMPLE.exists():
        pytest.skip("example fixture missing")
    return scan(EXAMPLE, deterministic=True).bom


@pytest.fixture(scope="module")
def cdx_doc(example_bom: AgentBOM) -> dict[str, Any]:
    doc, _ = export_cyclonedx(example_bom, include_text=True)
    return doc


@pytest.fixture(scope="module")
def round_trips(example_bom: AgentBOM, cdx_doc: dict[str, Any]) -> dict[str, AgentBOM]:
    sdoc, _ = export_spdx(example_bom, include_text=True)
    return {
        "cyclonedx": import_cyclonedx(cdx_doc, now=NOW)[0],
        "spdx": import_spdx(sdoc, now=NOW)[0],
    }


def _by_id(bom: AgentBOM) -> dict[str, Any]:
    return {e.id: e for _, e in bom.iter_entities()}


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
@pytest.mark.parametrize("kind", WP9_KINDS)
def test_every_wp9_entity_round_trips_exactly(
    example_bom: AgentBOM, round_trips: dict[str, AgentBOM], fmt: str, kind: str
) -> None:
    orig = {i: e for i, e in _by_id(example_bom).items() if i.split(":", 1)[0] == kind}
    assert orig, f"the example has no {kind} entities"
    new = _by_id(round_trips[fmt])
    for eid, ent in orig.items():
        assert eid in new, f"{eid} missing after the {fmt} round trip"
        a, b = diff_body(ent), diff_body(new[eid])
        assert a == b, (eid, {k: (a.get(k), b.get(k)) for k in set(a) | set(b) if a.get(k) != b.get(k)})


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
def test_evidence_digest_and_uri_survive(
    example_bom: AgentBOM, round_trips: dict[str, AgentBOM], fmt: str
) -> None:
    with_uri = [ev for ev in example_bom.evidence if ev.uri]
    assert with_uri
    new = {ev.id: ev for ev in round_trips[fmt].evidence}
    for ev in with_uri:
        got = new[ev.id]
        assert (got.digest, got.uri, got.media_type) == (ev.digest, ev.uri, ev.media_type)


def test_cyclonedx_evidence_keeps_the_digest_first(example_bom: AgentBOM, cdx_doc: dict[str, Any]) -> None:
    by_ref = {ev["bom-ref"]: ev for ev in cdx_doc["declarations"]["evidence"]}
    for ev in example_bom.evidence:
        data = by_ref[ev.id]["data"]
        assert data[0]["contents"]["url"] == ev.digest
        if ev.uri:
            assert {"name": "uri", "contents": {"url": ev.uri}} in data


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
def test_acts_as_identity_survives(example_bom: AgentBOM, round_trips: dict[str, AgentBOM], fmt: str) -> None:
    acting = [e for e in example_bom.edges if e.type is E.EdgeType.ACTS_AS]
    assert acting
    imported = round_trips[fmt]
    idents = {i.id: i for i in imported.identities}
    keys = {e.key for e in imported.edges}
    for edge in acting:
        orig = next(i for i in example_bom.identities if i.id == edge.to_ref)
        assert edge.key in keys
        assert diff_body(idents[orig.id]) == diff_body(orig)


def test_cyclonedx_acts_as_identity_block_is_indexed_after_credentials(
    example_bom: AgentBOM, cdx_doc: dict[str, Any]
) -> None:
    edge = next(e for e in example_bom.edges if e.type is E.EdgeType.ACTS_AS)
    comp = cdx_doc["metadata"]["component"]
    assert comp["bom-ref"] == edge.from_ref
    props = {p["name"]: p["value"] for p in comp["properties"]}
    creds = {n.split(":")[2] for n in props if n.startswith("agentbom:credential:")}
    index = next(n.split(":")[2] for n, v in props.items() if n.endswith(":id") and v == edge.to_ref)
    assert index not in creds
    assert props[f"agentbom:identity:{index}:ref"].startswith("spiffe://")
    assert validate_cyclonedx(cdx_doc) == []


def test_software_keeps_its_source_bom_ref(example_bom: AgentBOM, cdx_doc: dict[str, Any]) -> None:
    sw = next(s for s in example_bom.software if s.cyclonedx and s.cyclonedx.get("bom-ref"))
    comp = next(c for c in cdx_doc["components"] if c["bom-ref"] == sw.id)
    assert {"name": "agentbom:import:source-bom-ref", "value": sw.cyclonedx["bom-ref"]} in comp["properties"]


def test_digests_only_export_reports_prompt_schema_as_redacted(example_bom: AgentBOM) -> None:
    prompt = next(p for p in example_bom.prompts if p.variables_schema)
    doc, loss = export_cyclonedx(example_bom)
    item = next(i for i in loss.items if i.path == f"/prompts/{prompt.id}/variablesSchema")
    # no companion is referenced, so the companion-preserved schema is reported as dropped
    assert item.reason is E.LossReason.REDACTED and item.preserved_in is E.LossPreservedIn.DROPPED
    comp = next(c for c in doc["components"] if c["bom-ref"] == prompt.id)
    assert not any(p["name"] == "agentbom:prompt:variables-schema:json" for p in comp["properties"])
    # SPDX reports the same omission (it used to drop the schema silently)
    _, sloss = export_spdx(example_bom)
    sitem = next(i for i in sloss.items if i.path == f"/prompts/{prompt.id}/variablesSchema")
    assert sitem.reason is E.LossReason.REDACTED


def test_spdx_tool_text_round_trips_or_is_reported(minimal_bom: AgentBOM) -> None:
    tool = minimal_bom.tools[0]
    _, sloss = export_spdx(minimal_bom)
    item = next(i for i in sloss.items if i.path == f"/tools/{tool.id}/inputSchema")
    assert item.reason is E.LossReason.REDACTED
    sdoc, _ = export_spdx(minimal_bom, include_text=True)
    imported, _ = import_spdx(sdoc, now=NOW)
    got = imported.tools[0]
    assert (got.input_schema, got.output_schema, got.title) == (
        tool.input_schema,
        tool.output_schema,
        tool.title,
    )


def test_empty_list_claims_stay_present(example_bom: AgentBOM, round_trips: dict[str, AgentBOM]) -> None:
    instr = next(
        i for i in example_bom.instructions if i.loads_remote is not None and not i.loads_remote.value
    )
    got = next(i for i in round_trips["cyclonedx"].instructions if i.id == instr.id)
    assert got.loads_remote is not None and got.loads_remote.value == []
