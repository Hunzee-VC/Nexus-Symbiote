"""Exports declare their projection version, and every released projection stays recoverable."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.generators import _common
from nexus_symbiote.generators._common import PROJECTION_PROPERTY, PROJECTION_SCANNERS
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import validate_spdx
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from tests.test_export_conformance import fixture_bom

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "export-projection-0.1.0"
FIXTURE_NAMES = sorted(path.name for path in FIXTURES.glob("*.json"))


def _load(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return document


def _generator(name: str) -> type[CycloneDXGenerator] | type[SPDXGenerator]:
    return CycloneDXGenerator if ".cyclonedx." in name else SPDXGenerator


def _properties(document: dict[str, Any]) -> list[dict[str, Any]]:
    """The document-level extension properties, as name/value records."""
    if "metadata" in document:
        properties: list[dict[str, Any]] = document["metadata"]["properties"]
        return properties
    doc = next(n for n in document["@graph"] if n["type"] == "SpdxDocument")
    return [
        {"name": p["extension_cdxPropName"], "value": p["extension_cdxPropValue"]}
        for p in doc["extension"][0]["extension_cdxProperty"]
    ]


def _set_marker(document: dict[str, Any], value: str | None) -> None:
    if "metadata" in document:
        properties = document["metadata"]["properties"]
        properties[:] = [p for p in properties if p["name"] != PROJECTION_PROPERTY]
        if value is not None:
            properties.append({"name": PROJECTION_PROPERTY, "value": value})
        return
    doc = next(n for n in document["@graph"] if n["type"] == "SpdxDocument")
    entries = doc["extension"][0]["extension_cdxProperty"]
    entries[:] = [p for p in entries if p["extension_cdxPropName"] != PROJECTION_PROPERTY]
    if value is not None:
        entries.append(
            {
                "type": "extension_CdxPropertyEntry",
                "extension_cdxPropName": PROJECTION_PROPERTY,
                "extension_cdxPropValue": value,
            }
        )


def test_the_0_1_0_fixtures_cover_both_formats_and_a_scan():
    assert FIXTURE_NAMES == [
        "api-inventory.cyclonedx.json",
        "api-inventory.spdx.json",
        "demo-agent-scan.cyclonedx.json",
        "demo-agent-scan.spdx.json",
    ]


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_exports_written_by_0_1_0_still_recover(name):
    document = _load(name)
    generator = _generator(name)
    properties = _properties(document)
    assert all(p["name"] != PROJECTION_PROPERTY for p in properties)
    embedded = json.loads(
        next(p["value"] for p in properties if p["name"] == "nexus-symbiote:document")
    )
    recovered = generator.recover(deepcopy(document))
    assert recovered == AIBOM.model_validate(embedded)
    # Re-exported, the same inventory declares the current projection and recovers.
    current = generator().generate(recovered.model_copy(deep=True))
    assert any(p["name"] == PROJECTION_PROPERTY for p in _properties(current))
    assert generator.recover(current) == recovered


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_a_0_1_0_export_with_a_changed_public_field_is_rejected(name):
    document = _load(name)
    if "metadata" in document:
        document["components"][0]["name"] = "renamed"
    else:
        node = next(n for n in document["@graph"] if n["type"] == "Relationship")
        node["relationshipType"] = (
            "dependsOn" if node["relationshipType"] != "dependsOn" else "other"
        )
    with pytest.raises(ValueError):
        _generator(name).recover(document)


@pytest.mark.parametrize("generator", [CycloneDXGenerator, SPDXGenerator])
def test_current_exports_declare_their_projection(generator):
    document = generator().generate(fixture_bom())
    (marker,) = [p["value"] for p in _properties(document) if p["name"] == PROJECTION_PROPERTY]
    assert marker == ("cyclonedx-1.7/2" if generator is CycloneDXGenerator else "spdx-3.0.1/2")


@pytest.mark.parametrize("change", ["unknown", "removed", "duplicated"])
def test_a_changed_projection_marker_is_rejected(change):
    document = CycloneDXGenerator().generate(fixture_bom())
    if change == "unknown":
        _set_marker(document, "cyclonedx-1.7/99")
    elif change == "removed":
        # Without the marker the document must match the 0.1.0 projection, and does not.
        _set_marker(document, None)
    else:
        document["metadata"]["properties"].append(
            {"name": PROJECTION_PROPERTY, "value": "cyclonedx-1.7/2"}
        )
    with pytest.raises(ValueError):
        CycloneDXGenerator.recover(document)


@pytest.mark.parametrize("name", ["api-inventory.cyclonedx.json", "api-inventory.spdx.json"])
def test_a_0_1_0_export_cannot_claim_the_current_projection(name):
    document = _load(name)
    _set_marker(document, "cyclonedx-1.7/2" if "metadata" in document else "spdx-3.0.1/2")
    with pytest.raises(ValueError):
        _generator(name).recover(document)


def test_the_0_1_0_license_iri_is_accepted_only_when_recovering_0_1_0_exports():
    legacy = _load("api-inventory.spdx.json")
    assert any("Licensing/NoAssertion" in error for error in validate_spdx(legacy))
    assert SPDXGenerator.recover(deepcopy(legacy))
    current = SPDXGenerator().generate(fixture_bom())
    for node in current["@graph"]:
        if node.get("relationshipType") == "hasDeclaredLicense":
            node["to"] = ["https://spdx.org/rdf/3.0.1/terms/Licensing/NoAssertion"]
    with pytest.raises(ValueError, match="unresolved"):
        SPDXGenerator.recover(current)


def _replace_document(document: dict[str, Any], text: str) -> None:
    prop = next(
        p for p in document["metadata"]["properties"] if p["name"] == "nexus-symbiote:document"
    )
    prop["value"] = text


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("duplicate-key", "Duplicate JSON object key"),
        ("non-finite", "Nonfinite JSON number"),
        ("deep", None),
        ("oversized", None),
        ("not-an-object", None),
        ("digest", None),
    ],
)
def test_malformed_embedded_documents_fail_with_value_errors(monkeypatch, case, message):
    document = CycloneDXGenerator().generate(fixture_bom())
    prop = next(
        p for p in document["metadata"]["properties"] if p["name"] == "nexus-symbiote:document"
    )
    native = json.loads(prop["value"])
    # A last-key-wins parser reads both texts as the original document, digest included;
    # the strict parser rejects them before the projection comparison.
    if case == "duplicate-key":
        _replace_document(
            document, prop["value"][:-1] + ',"metadata":' + json.dumps(native["metadata"]) + "}"
        )
    elif case == "non-finite":
        _replace_document(document, '{"metadata":NaN,' + prop["value"][1:])
    elif case == "deep":
        _replace_document(document, "[" * 200_000 + "]" * 200_000)
    elif case == "oversized":
        monkeypatch.setattr(_common, "NATIVE_DOCUMENT_LIMIT", 64)
    elif case == "not-an-object":
        _replace_document(document, "[]")
    else:
        _replace_document(document, prop["value"].replace('"main"', '"other"', 1))
    with pytest.raises(ValueError, match=message):
        CycloneDXGenerator.recover(document)


@pytest.mark.parametrize("generator", [CycloneDXGenerator, SPDXGenerator])
def test_deeply_nested_public_documents_fail_with_value_errors(generator):
    nested: dict[str, Any] = {"type": "library", "bom-ref": "leaf", "name": "leaf"}
    for index in range(5000):
        nested = {"type": "library", "bom-ref": f"n{index}", "name": "n", "components": [nested]}
    document: dict[str, Any] = (
        {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": [nested]}
        if generator is CycloneDXGenerator
        else {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [nested]}
    )
    with pytest.raises(ValueError):
        generator.recover(document)


def test_the_projection_collector_universe_is_a_subset_of_the_catalog():
    # Collectors added later are judged by scanner_status, so the projection set is frozen.
    assert PROJECTION_SCANNERS <= BUILTIN_SCANNER_NAMES


def test_exported_files_recover_through_the_bounded_loader(monkeypatch):
    from nexus_symbiote.generators import recovery

    cyclonedx = FIXTURES / "api-inventory.cyclonedx.json"
    spdx = FIXTURES / "api-inventory.spdx.json"
    expected = CycloneDXGenerator.recover(_load(cyclonedx.name))
    assert recovery.load_export(cyclonedx) == expected
    assert recovery.recover_export(spdx.read_text(encoding="utf-8")) == expected
    text = cyclonedx.read_text(encoding="utf-8")
    for malformed in (
        text.replace('"specVersion": "1.7",', '"specVersion": "1.7", "specVersion": "1.7",', 1),
        '{"bomFormat": "CycloneDX", "version": NaN}',
        "[" * 200_000,
        '{"unrelated": true}',
        b"\xff\xfe",
    ):
        with pytest.raises(ValueError):
            recovery.recover_export(malformed)
    with pytest.raises(ValueError, match="CycloneDX only"):
        recovery.recover_export(spdx.read_bytes(), allow_legacy_relationships=True)
    monkeypatch.setattr(recovery, "MAX_EXPORT_BYTES", 1024)
    with pytest.raises(ValueError):
        recovery.load_export(cyclonedx)
