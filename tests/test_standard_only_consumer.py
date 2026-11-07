"""What a consumer that ignores the SymBiote extension reads from the standard exports.

Such a consumer must never see a conditional native edge as an unconditional typed
relationship, and must see that a scoped, failed or imported inventory is incomplete.
"""

from __future__ import annotations

import io
import json
import shutil
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote import modes
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.models import CompletenessClaim
from nexus_symbiote.generators._common import NAMESPACE
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import validate_cyclonedx, validate_spdx
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from tests.test_export_conformance import fixture_bom

DEMO = Path(__file__).resolve().parents[1] / "examples" / "demo-agent"
EXTENSION_PREFIXES = ("nexus-symbiote:", "agentbom:")
LICENSE_RELATIONSHIPS = {"hasDeclaredLicense", "hasConcludedLicense"}
TYPED = {"usesTool", "dependsOn", "trainedOn", "descendantOf"}
SCAN_CONDITION = "runtime use and authority unobserved"
APPROVAL = "only after a human approves the call"


def standard_only(document: dict[str, Any], fmt: str) -> dict[str, Any]:
    """Drop every SymBiote extension carrier and keep only standard fields."""
    if fmt == "spdx":
        return _without_extension(document)
    view = deepcopy(document)
    for holder in (view.get("metadata", {}), *view.get("components", [])):
        kept = [
            prop
            for prop in holder.get("properties", [])
            if not prop["name"].startswith(EXTENSION_PREFIXES)
        ]
        if kept:
            holder["properties"] = kept
        else:
            holder.pop("properties", None)
    return view


def _without_extension(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_extension(item) for key, item in value.items() if key != "extension"}
    if isinstance(value, list):
        return [_without_extension(item) for item in value]
    return value


def _spdx_id(view: dict[str, Any], bom_ref: str) -> str:
    suffix = f"#component-{uuid.uuid5(NAMESPACE, bom_ref)}"
    return next(n["spdxId"] for n in view["@graph"] if n.get("spdxId", "").endswith(suffix))


def _spdx_document(view: dict[str, Any]) -> dict[str, Any]:
    return next(n for n in view["@graph"] if n["type"] == "SpdxDocument")


def _edges(view: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        n
        for n in view["@graph"]
        if n["type"] == "Relationship" and n["relationshipType"] not in LICENSE_RELATIONSHIPS
    ]


def _between(view: dict[str, Any], source: str, target: str) -> list[dict[str, Any]]:
    source_id, target_id = _spdx_id(view, source), _spdx_id(view, target)
    return [e for e in _edges(view) if e["from"] == source_id and e["to"] == [target_id]]


def _conditional(relationship: str) -> AIBOM:
    bom = fixture_bom()
    bom.dependencies = [
        DependencyEdge(
            source_ref="agent:main",
            target_ref="tool:send",
            relationship=relationship,
            conditions=APPROVAL,
        )
    ]
    return bom


def _spdx_round_trip(document: dict[str, Any]) -> dict[str, Any]:
    from spdx_python_model.bindings import v3_0_1 as spdx

    objects = spdx.SHACLObjectSet()
    spdx.JSONLDDeserializer().read(io.BytesIO(json.dumps(document).encode()), objects)
    output = io.BytesIO()
    spdx.JSONLDSerializer().write(objects, output)
    consumed: dict[str, Any] = json.loads(output.getvalue())
    assert validate_spdx(consumed) == []
    return consumed


def _cyclonedx_strict(document: dict[str, Any]) -> None:
    assert validate_cyclonedx(document) == []
    pytest.importorskip("cyclonedx.validation.json")
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    if not hasattr(SchemaVersion, "V1_7"):
        pytest.skip("installed cyclonedx library does not support 1.7")
    assert JsonStrictValidator(SchemaVersion.V1_7).validate_str(json.dumps(document)) is None


@pytest.mark.parametrize(
    ("relationship", "typed"),
    [
        ("invokes", "usesTool"),
        ("depends-on", "dependsOn"),
        ("trained-on", "trainedOn"),
        ("fine-tuned-from", "descendantOf"),
    ],
)
def test_spdx_conditional_edge_is_never_a_public_typed_relationship(relationship, typed):
    view = standard_only(SPDXGenerator().generate(_conditional(relationship)), "spdx")
    assert not any(e["relationshipType"] in TYPED for e in _edges(view))
    (edge,) = _between(view, "agent:main", "tool:send")
    assert edge["relationshipType"] == "other"
    assert APPROVAL in edge.get("comment", "")
    assert f"'{relationship}'" in edge.get("comment", "")
    assert f"Not an unconditional {typed} assertion" in edge.get("comment", "")
    consumed = _spdx_round_trip(view)
    (kept,) = [n for n in consumed["@graph"] if n.get("comment", "").find(APPROVAL) >= 0]
    assert kept["relationshipType"] == "other"


def test_spdx_unconditional_edges_keep_their_typed_mapping():
    view = standard_only(SPDXGenerator().generate(fixture_bom()), "spdx")
    (uses,) = _between(view, "agent:main", "tool:send")
    (depends,) = _between(view, "agent:main", "model:one")
    assert (uses["relationshipType"], depends["relationshipType"]) == ("usesTool", "dependsOn")
    assert "comment" not in uses and "comment" not in depends


def test_spdx_conditional_comment_is_bounded():
    bom = _conditional("invokes")
    bom.dependencies[0].conditions = "x" * 5000
    view = standard_only(SPDXGenerator().generate(bom), "spdx")
    (edge,) = _between(view, "agent:main", "tool:send")
    assert len(edge["comment"]) < 1200 and "[truncated]" in edge.get("comment", "")
    assert SPDXGenerator.recover(SPDXGenerator().generate(bom)).dependencies[0].conditions == (
        "x" * 5000
    )


def test_imported_conditional_dependency_matches_the_cyclonedx_public_graph():
    from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
    from tests.test_shadowscan_relationships import FIXTURE

    bom = ShadowScanImporter().read_report(FIXTURE).to_native_bom()
    assert any(e.relationship == "depends-on" and e.conditions for e in bom.dependencies)
    spdx_view = standard_only(SPDXGenerator().generate(bom), "spdx")
    cdx_view = standard_only(CycloneDXGenerator().generate(bom), "cyclonedx")
    assert not any(e["relationshipType"] == "dependsOn" for e in _edges(spdx_view))
    assert cdx_view.get("dependencies", []) == []
    # Imported discovery is never complete, in either format.
    assert cdx_view["compositions"] == [{"aggregate": "incomplete"}]
    assert {e.get("completeness") for e in _edges(spdx_view)} == {"incomplete"}
    _cyclonedx_strict(cdx_view)
    _spdx_round_trip(spdx_view)


@pytest.mark.parametrize("change", ["remove", "alter", "retype", "complete"])
def test_spdx_recovery_rejects_a_changed_public_condition(change):
    document = SPDXGenerator().generate(_conditional("invokes"))
    edge = next(n for n in document["@graph"] if APPROVAL in n.get("comment", ""))
    if change == "remove":
        del edge["comment"]
    elif change == "alter":
        edge["comment"] = "Unconditional."
    elif change == "retype":
        edge["relationshipType"] = "usesTool"
    else:
        edge["completeness"] = "complete"
    with pytest.raises(ValueError, match="projection conflicts"):
        SPDXGenerator.recover(document)


def _claim(**changes: Any) -> CompletenessClaim:
    names = sorted(BUILTIN_SCANNER_NAMES)
    fields: dict[str, Any] = {
        "scope": "repository",
        "collectors_requested": names,
        "collectors_completed": names,
        "scanner_status": dict.fromkeys(names, "complete"),
        "exclusions": ["**/.git", "**/node_modules", ".venv", "__pycache__"],
        "unobserved_surfaces": ["runtime", "network"],
    }
    return CompletenessClaim(**{**fields, **changes})


@pytest.mark.parametrize(
    ("changes", "aggregate"),
    [
        (None, "unknown"),
        ({}, "unknown"),
        ({"unobserved_surfaces": []}, "unknown"),
        ({"collectors_requested": ["mcp"], "collectors_completed": ["mcp"]}, "incomplete"),
        ({"collectors_requested": [], "collectors_completed": []}, "incomplete"),
        ({"collectors_completed": ["mcp"]}, "incomplete"),
        ({"scanner_status": {"mcp": "partial"}}, "incomplete"),
        ({"scan_failures": [".mcp.json: invalid JSON or duplicate keys"]}, "incomplete"),
        ({"surfaces_excluded": ["tools.py: unresolved Python MCP tool name"]}, "incomplete"),
        ({"exclusions": ["**/.git", "src"]}, "incomplete"),
        ({"source_report_digest": "sha256:" + "0" * 64}, "incomplete"),
    ],
)
def test_public_coverage_is_derived_from_the_native_claim(changes, aggregate):
    bom = fixture_bom()
    bom.metadata.completeness = None if changes is None else _claim(**changes)
    cdx = standard_only(CycloneDXGenerator().generate(bom), "cyclonedx")
    assert cdx.get("compositions") == [{"aggregate": aggregate}]
    spdx_view = standard_only(SPDXGenerator().generate(bom), "spdx")
    expected = "incomplete" if aggregate == "incomplete" else "noAssertion"
    assert {e.get("completeness") for e in _edges(spdx_view)} == {expected}
    assert (
        _spdx_document(spdx_view)
        .get("comment", "")
        .startswith(f"Collection coverage is {aggregate}")
    )
    from nexus_symbiote.generators._common import coverage_aggregate

    assert coverage_aggregate(bom.metadata.completeness) == aggregate


@pytest.fixture(scope="module")
def scans(tmp_path_factory) -> dict[str, dict[str, dict[str, Any]]]:
    if not DEMO.is_dir():
        pytest.skip("the demo project ships in the repository, not in the wheel")
    base = tmp_path_factory.mktemp("consumer")
    full = base / "demo-agent"
    shutil.copytree(DEMO, full)
    gap = base / "gap-agent"
    shutil.copytree(DEMO, gap)
    (gap / ".mcp.json").write_text('{"mcpServers": {"x": ', encoding="utf-8")
    runs = {"full": (full, []), "subset": (full, ["--scanner", "mcp"]), "failed": (gap, [])}
    documents: dict[str, dict[str, dict[str, Any]]] = {}
    for name, (root, extra) in runs.items():
        documents[name] = {}
        for fmt in ("cyclonedx", "spdx"):
            output = base / f"{name}.{fmt}.json"
            result = CliRunner().invoke(
                main,
                ["scan", str(root), "-f", fmt, "-o", str(output), "--report-only", *extra],
                env={modes.ENV_VAR: None},
            )
            assert result.exit_code == 0, result.output
            documents[name][fmt] = json.loads(output.read_text(encoding="utf-8"))
    return documents


def test_scan_edges_carry_their_public_condition_in_spdx(scans):
    view = standard_only(scans["full"]["spdx"], "spdx")
    edges = _edges(view)
    assert edges
    for edge in edges:
        assert edge["relationshipType"] == "other"
        assert SCAN_CONDITION in edge.get("comment", "")
        assert "Not an unconditional" in edge.get("comment", "")


def test_full_static_scan_is_public_unknown_and_never_complete(scans):
    cdx = standard_only(scans["full"]["cyclonedx"], "cyclonedx")
    spdx_view = standard_only(scans["full"]["spdx"], "spdx")
    assert cdx.get("compositions") == [{"aggregate": "unknown"}]
    assert {e.get("completeness") for e in _edges(spdx_view)} == {"noAssertion"}
    assert _spdx_document(spdx_view).get("comment", "").startswith("Collection coverage is unknown")
    _cyclonedx_strict(cdx)
    _spdx_round_trip(spdx_view)
    document = scans["full"]["cyclonedx"]
    # An SDK that drops the composition removes no assertion; a complete claim conflicts.
    assert CycloneDXGenerator.recover({k: v for k, v in document.items() if k != "compositions"})
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover({**document, "compositions": [{"aggregate": "complete"}]})


@pytest.mark.parametrize("scan", ["subset", "failed"])
def test_scoped_or_failed_scan_is_publicly_incomplete(scans, scan):
    cdx = standard_only(scans[scan]["cyclonedx"], "cyclonedx")
    spdx_view = standard_only(scans[scan]["spdx"], "spdx")
    assert cdx.get("compositions") == [{"aggregate": "incomplete"}]
    assert cdx.get("dependencies", []) == []
    edges = _edges(spdx_view)
    assert edges and {e.get("completeness") for e in edges} == {"incomplete"}
    assert not any(e["relationshipType"] in TYPED for e in edges)
    assert (
        _spdx_document(spdx_view).get("comment", "").startswith("Collection coverage is incomplete")
    )
    _cyclonedx_strict(cdx)
    consumed = _spdx_round_trip(spdx_view)
    assert {
        n.get("completeness") for n in consumed["@graph"] if n.get("relationshipType") == "other"
    } == {"incomplete"}


@pytest.mark.parametrize("scan", ["subset", "failed"])
@pytest.mark.parametrize("composition", [None, "unknown", "complete"])
def test_cyclonedx_recovery_rejects_a_weakened_partial_composition(scans, scan, composition):
    document = deepcopy(scans[scan]["cyclonedx"])
    assert CycloneDXGenerator.recover(document).metadata.completeness is not None
    if composition is None:
        del document["compositions"]
    else:
        document["compositions"] = [{"aggregate": composition}]
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover(document)


def test_no_export_claims_complete_coverage(scans):
    for documents in scans.values():
        cdx, spdx_document = documents["cyclonedx"], documents["spdx"]
        assert all(c["aggregate"] != "complete" for c in cdx["compositions"])
        assert all(e.get("completeness") != "complete" for e in _edges(spdx_document))
