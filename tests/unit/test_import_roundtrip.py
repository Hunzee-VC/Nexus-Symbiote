"""Round trips: model → CycloneDX/SPDX → model must reproduce ids, digests, edges, grants and coverage.

Comparison is on :func:`symbiote.snapshot.diff_body` (what drift detection compares — claim values and
states, never per-claim collection noise) because the projections do not carry a claim's ``method``,
``collector``, ``observed_at`` or evidence verification, nor the salted Merkle nonce; the fields that are
intentionally not reproduced are listed in :data:`NOT_PROJECTED` and must appear in the loss report or be
documented differences (see the module summary in the work-package commit).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from symbiote.export.cdx import export_cyclonedx, validate_cyclonedx
from symbiote.export.companion import companion_bytes, load_companion
from symbiote.export.spdx import export_spdx, validate_spdx
from symbiote.imp import CycloneDXImportError, SpdxImportError, detect_dialect, import_cyclonedx, import_spdx
from symbiote.model import AgentBOM, Claim, DigestResult, Edge, Producer
from symbiote.model import enums as E
from symbiote.model.entities import Agent, ToolDefinition, ToolServer
from symbiote.scan import scan
from symbiote.snapshot import collect_leaves, diff_body, finalize, new_document, verify_document

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "triage-agent"
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)

#: Entity fields the projections do not carry. ``name`` of identities/credential bindings is not an exporter
#: property (SPDX recovers identity names from the ``SoftwareAgent`` element, CycloneDX cannot); the CycloneDX
#: model component has no ``description`` field in the exporter; the SPDX
#: projection has no home for the tool definition text (``--include-text`` attachments are CycloneDX-only), so
#: the schema/title come back empty while the digests survive.
NOT_PROJECTED = {
    "cyclonedx": {"ident": {"name"}, "cred": {"name"}, "model": {"description"}},
    "spdx": {"cred": {"name"}, "tool": {"inputSchema", "outputSchema", "title"}},
}

#: Derived leaves are recomputed by ``symbiote policy check``; findings are not projected at all and flags
#: lose their subject when it is not a CycloneDX element (reported as ``cardinality-collapsed``).
DERIVED_LEAVES = {"flag", "finding"}


def _compare(original: AgentBOM, imported: AgentBOM, *, fmt: str) -> None:
    ignored = NOT_PROJECTED[fmt]
    orig = {e.id: e for _, e in original.iter_entities()}
    new = {e.id: e for _, e in imported.iter_entities()}
    assert set(orig) == set(new), (sorted(set(orig) - set(new)), sorted(set(new) - set(orig)))
    for eid, ent in orig.items():
        a, b = diff_body(ent), diff_body(new[eid])
        for field in ignored.get(eid.split(":", 1)[0], set()):
            a.pop(field, None)
            b.pop(field, None)
        assert a == b, (eid, {k: (a.get(k), b.get(k)) for k in set(a) | set(b) if a.get(k) != b.get(k)})
    assert {e.key for e in original.edges} == {e.key for e in imported.edges}
    assert {g.id: diff_body(g) for g in original.grants} == {g.id: diff_body(g) for g in imported.grants}
    assert {s: c.status for s, c in original.coverage.surfaces.items()} == {
        s: c.status for s, c in imported.coverage.surfaces.items()
    }
    assert [(c.name, c.status) for c in original.coverage.collectors] == [
        (c.name, c.status) for c in imported.coverage.collectors
    ]
    assert imported.snapshot.kind is original.snapshot.kind
    assert imported.snapshot.serial == original.snapshot.serial
    assert verify_document(imported)
    # leaf kinds/ids (the Merkle tree shape) match; the root differs because the nonce is not projected
    assert {(k, i) for k, i, _ in collect_leaves(original) if k not in DERIVED_LEAVES} == {
        (k, i) for k, i, _ in collect_leaves(imported) if k not in DERIVED_LEAVES
    }
    assert imported.snapshot.digest != original.snapshot.digest or original.merkle is None
    assert imported.loss_report is not None and not imported.loss_report.security_relevant_dropped
    assert json.loads(companion_bytes(imported))  # the imported document is a valid companion


@pytest.fixture(scope="module")
def example_bom() -> AgentBOM:
    if not EXAMPLE.exists():
        pytest.skip("example fixture missing")
    return scan(EXAMPLE, deterministic=True).bom


def test_cyclonedx_round_trip_minimal(minimal_bom: AgentBOM) -> None:
    doc, _ = export_cyclonedx(minimal_bom, include_text=True)
    assert detect_dialect(doc) == "symbiote"
    imported, loss = import_cyclonedx(doc, now=NOW)
    _compare(minimal_bom, imported, fmt="cyclonedx")
    assert loss.direction == "cdx→model" and loss.source_format == "cyclonedx-1.7"
    assert loss.model_digest == imported.snapshot.digest
    tool = imported.tools[0]
    assert tool.input_schema == {"type": "object"} and tool.digest.value == minimal_bom.tools[0].digest.value
    assert (
        imported.links.cyclonedx is not None and imported.links.cyclonedx.serial_number == doc["serialNumber"]
    )
    names = {f.name for f in imported.foreign_properties}
    assert {"agentbom:import:dialect", "agentbom:import:source-digest", "agentbom:snapshot:digest"} <= names


def test_spdx_round_trip_minimal(minimal_bom: AgentBOM) -> None:
    doc, _ = export_spdx(minimal_bom, include_text=True)
    imported, loss = import_spdx(doc, now=NOW)
    _compare(minimal_bom, imported, fmt="spdx")
    assert loss.direction == "spdx→model" and loss.source_format == "spdx-3.0.1"
    assert imported.links.spdx is not None and imported.links.spdx.document_iri.endswith("/document")


def test_cyclonedx_round_trip_example(example_bom: AgentBOM) -> None:
    doc, _ = export_cyclonedx(example_bom, include_text=True)
    imported, loss = import_cyclonedx(doc, now=NOW)
    _compare(example_bom, imported, fmt="cyclonedx")
    # identities and credential bindings come back from the indexed subject properties
    assert {c.identity_ref for c in imported.credential_bindings} == {i.id for i in imported.identities}
    # flags on components/services come back from declarations.claims with their inputs
    orig_flags = {
        (f.flag, f.subject_ref, f.value)
        for f in example_bom.derived.flags
        if not f.subject_ref.startswith("cred:")
    }
    new_flags = {(f.flag, f.subject_ref, f.value) for f in imported.derived.flags}
    assert orig_flags <= new_flags
    # flags whose subject is not a CycloneDX element are collapsed onto the root and reported
    assert any(
        i.path.startswith("/derived/flags/") and i.reason is E.LossReason.CARDINALITY_COLLAPSED
        for i in loss.items
    )
    assert imported.parties[0].name == example_bom.parties[0].name
    assert (
        imported.root_agent.framework is not None
        and imported.root_agent.framework.value == example_bom.root_agent.framework.value
    )


def test_spdx_round_trip_example(example_bom: AgentBOM) -> None:
    doc, _ = export_spdx(example_bom, include_text=True)
    imported, _ = import_spdx(doc, now=NOW)
    _compare(example_bom, imported, fmt="spdx")
    assert {i.name for i in imported.identities} == {i.name for i in example_bom.identities}
    assert {(f.flag, f.subject_ref, f.value) for f in imported.derived.flags} == {
        (f.flag, f.subject_ref, f.value) for f in example_bom.derived.flags
    }


def test_digests_only_export_reports_the_schema_as_lost(minimal_bom: AgentBOM) -> None:
    doc, _ = export_cyclonedx(minimal_bom)  # no --include-text
    imported, loss = import_cyclonedx(doc, now=NOW)
    tool = imported.tools[0]
    assert tool.input_schema == {} and tool.digest.value == minimal_bom.tools[0].digest.value
    item = next(i for i in loss.items if i.path == f"/tools/{tool.id}/inputSchema")
    assert item.reason is E.LossReason.REDACTED and item.preserved_in is E.LossPreservedIn.DROPPED
    assert item.severity is E.LossSeverity.INFO and imported.coverage.text_included is False


def test_round_trip_is_deterministic(minimal_bom: AgentBOM) -> None:
    doc, _ = export_cyclonedx(minimal_bom, include_text=True)
    a, _ = import_cyclonedx(doc, now=NOW, nonce=bytes(32))
    b, _ = import_cyclonedx(doc, now=NOW, nonce=bytes(32))
    assert companion_bytes(a) == companion_bytes(b)
    assert load_companion(companion_bytes(a)) == a


def test_native_header_fields_survive() -> None:
    agent = Agent(id="agent:obs", version="1.0.0", role=E.AgentRole.ROOT)
    draft = new_document(
        subject="agent:obs",
        producer=Producer(version="0.1.0"),
        kind=E.SnapshotKind.OBSERVED,
        serial=7,
        produced_at=NOW,
        agents=[agent],
    )
    prev = "sha256:" + "11" * 32
    sealed = finalize(draft, nonce=bytes(32), prev=prev)
    doc, _ = export_cyclonedx(sealed)
    imported, _ = import_cyclonedx(doc, now=NOW)
    assert imported.snapshot.kind is E.SnapshotKind.OBSERVED and imported.snapshot.serial == 7
    assert imported.snapshot.prev == prev
    assert imported.snapshot.observation_window == sealed.snapshot.observation_window
    forced, _ = import_cyclonedx(doc, now=NOW, as_kind=E.SnapshotKind.DECLARED)
    assert forced.snapshot.kind is E.SnapshotKind.DECLARED


def test_verified_assurance_is_downgraded_and_reported(minimal_bom: AgentBOM) -> None:
    doc, _ = export_cyclonedx(minimal_bom, include_text=True)
    svc = doc["services"][0]
    for p in svc["properties"]:
        if p["name"] == "agentbom:assurance":
            p["value"] = "verified"
    imported, loss = import_cyclonedx(doc, now=NOW)
    server = imported.tool_servers[0]
    assert server.provenance.assurance is E.AssuranceLevel.OBSERVED  # never laundered (I3)
    assert "imported-verified-without-constraint" in server.tags
    dropped = loss.security_relevant_dropped
    assert dropped and dropped[0].field == "assurance" and dropped[0].reason is E.LossReason.ENUM_NARROWED
    assert not loss.lossless


def test_foreign_properties_survive_a_re_export(minimal_bom: AgentBOM) -> None:
    doc, _ = export_cyclonedx(minimal_bom, include_text=True)
    doc["services"][0]["properties"].append({"name": "vendor:custom:flag", "value": "yes"})
    doc["metadata"]["properties"].append({"name": "vendor:document:note", "value": "kept"})
    imported, loss = import_cyclonedx(doc, now=NOW)
    server = imported.tool_servers[0]
    assert server.foreign == {"vendor:custom:flag": "yes"}
    assert any(
        f.element_id == "metadata" and f.name == "vendor:document:note" for f in imported.foreign_properties
    )
    assert any(
        i.reason is E.LossReason.FOREIGN_UNMAPPED and i.preserved_in is E.LossPreservedIn.PROPERTY
        for i in loss.items
    )
    again, _ = export_cyclonedx(imported)
    props = {(p["name"], p["value"]) for p in again["services"][0]["properties"]}
    assert ("vendor:custom:flag", "yes") in props and validate_cyclonedx(again) == []
    sdoc, _ = export_spdx(imported)
    assert validate_spdx(sdoc) == [] and "vendor:custom:flag" in json.dumps(sdoc)


def test_secret_shaped_foreign_values_are_redacted(minimal_bom: AgentBOM) -> None:
    doc, _ = export_cyclonedx(minimal_bom)
    doc["services"][0]["properties"].append({"name": "vendor:token", "value": "sk-" + "A" * 40})
    imported, _ = import_cyclonedx(doc, now=NOW)
    assert "sk-" not in json.dumps(imported.to_json_dict())
    assert any(r.redaction_class == "credential-shaped-token" for r in imported.redactions)


def test_cyclonedx_15_is_checked_structurally() -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"type": "application", "name": "legacy-agent", "version": "1.0"}},
        "components": [
            {"type": "library", "name": "requests", "version": "2.32.0", "purl": "pkg:pypi/requests@2.32.0"}
        ],
    }
    imported, loss = import_cyclonedx(doc, now=NOW)
    assert imported.subject == "agent:legacy-agent" and imported.software[0].id == "sw:pypi/requests@2.32.0"
    assert any(
        i.path == "/specVersion" and i.reason is E.LossReason.UNSUPPORTED_IN_TARGET_VERSION
        for i in loss.items
    )
    assert imported.edges[0].key == ("dependsOn", "agent:legacy-agent", "sw:pypi/requests@2.32.0")


def test_invalid_documents_are_rejected() -> None:
    with pytest.raises(CycloneDXImportError):
        import_cyclonedx(
            {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [{"name": "no-type"}]}
        )
    with pytest.raises(CycloneDXImportError):
        import_cyclonedx({"bomFormat": "SPDX", "specVersion": "1.7"})
    with pytest.raises(CycloneDXImportError):
        import_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "1.2"})
    with pytest.raises(SpdxImportError):
        import_spdx({"hello": "world"})
    with pytest.raises(SpdxImportError):
        import_spdx(
            {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [{"type": "Nonsense"}]}
        )


def test_generic_software_sbom_imports_as_software_layer() -> None:
    doc = json.loads((EXAMPLE / "sbom.cdx.json").read_text()) if EXAMPLE.exists() else None
    if doc is None:
        pytest.skip("example fixture missing")
    assert detect_dialect(doc) == "generic"
    imported, loss = import_cyclonedx(doc, now=NOW)
    assert imported.subject == "agent:triage-agent" and imported.root_agent.version == "2.3.1"
    assert {s.purl for s in imported.software} == {"pkg:pypi/claude-agent-sdk@0.9.4", "pkg:pypi/mcp@1.9.0"}
    assert all(s.cyclonedx["purl"] == s.purl for s in imported.software)
    assert {e.key for e in imported.edges} == {
        ("dependsOn", "agent:triage-agent", "sw:pypi/claude-agent-sdk@0.9.4"),
        ("dependsOn", "agent:triage-agent", "sw:pypi/mcp@1.9.0"),
    }
    assert imported.snapshot.kind is E.SnapshotKind.DECLARED and not loss.security_relevant_dropped
    again, _ = export_cyclonedx(imported)
    assert validate_cyclonedx(again) == []


def _bom_with_server_claims() -> AgentBOM:
    agent = Agent(id="agent:a", name="a", version="1.0.0", role=E.AgentRole.ROOT)
    server = ToolServer(
        id="server:remote",
        kind=E.ToolServerKind.MCP,
        transport=Claim.declared(E.Transport.STREAMABLE_HTTP),
        endpoint=Claim.declared("https://mcp.example.com/mcp"),
        authentication=Claim.unknown(E.UnknownReason.NOT_COLLECTED, locator=".mcp.json#/mcpServers/remote"),
        crosses_trust_boundary=Claim.declared(True),
        trust_zone=E.TrustZone.EXTERNAL,
        header_names=["Authorization"],
    )
    tool = ToolDefinition(
        id="tool:remote/run",
        server_ref="server:remote",
        tool_name="run",
        input_schema={"type": "object", "properties": {"cmd": {"type": "string"}}},
        digest=DigestResult(
            algorithm="tooldef/v1", status=E.DigestStatus.UNDIGESTABLE, reason="duplicate-key: cmd"
        ),
        source=E.ToolSource.SERVED_LIVE,
        state=E.ToolState.SERVED,
        side_effect_class=E.SideEffectClass.DESTRUCTIVE,
        capabilities=[E.CapabilityClass.EXECUTE],
        approval_gate=E.ApprovalGate.REQUIRED,
    )
    draft = new_document(
        subject="agent:a",
        producer=Producer(version="0.1.0"),
        kind=E.SnapshotKind.DECLARED,
        produced_at=NOW,
        agents=[agent],
        tool_servers=[server],
        tools=[tool],
        edges=[Edge(type=E.EdgeType.PROVIDES_TOOL, **{"from": "server:remote", "to": "tool:remote/run"})],
    )
    return finalize(draft, nonce=bytes(32))


def test_unknown_claims_and_undigestable_digests_round_trip() -> None:
    bom = _bom_with_server_claims()
    for exporter, importer, fmt in (
        (export_cyclonedx, import_cyclonedx, "cyclonedx"),
        (export_spdx, import_spdx, "spdx"),
    ):
        doc, _ = exporter(bom, include_text=True)
        imported, _ = importer(doc, now=NOW)
        _compare(bom, imported, fmt=fmt)
        server = imported.tool_servers[0]
        assert (
            server.authentication.is_unknown
            and server.authentication.unknown_reason is E.UnknownReason.NOT_COLLECTED
        )
        assert server.authentication.locator == ".mcp.json#/mcpServers/remote"
        tool = imported.tools[0]
        assert (
            tool.digest.status is E.DigestStatus.UNDIGESTABLE and tool.digest.reason == "duplicate-key: cmd"
        )
        assert tool.approval_gate is E.ApprovalGate.REQUIRED and tool.capabilities == [
            E.CapabilityClass.EXECUTE
        ]
