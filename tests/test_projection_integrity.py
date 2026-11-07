"""Standard consumers and native recovery must agree on the exported public view."""

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.aibom import DependencyEdge
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from tests.test_export_conformance import fixture_bom

LEGACY_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cyclonedx-legacy"


def test_cyclonedx_projects_only_unconditional_dependencies():
    bom = fixture_bom()
    bom.dependencies.extend(
        [
            DependencyEdge(
                source_ref="server:one", target_ref="tool:send", relationship="provides-tool"
            ),
            DependencyEdge(
                source_ref="agent:main",
                target_ref="prompt:one",
                relationship="depends-on",
                conditions="only when enabled",
            ),
        ]
    )
    document = CycloneDXGenerator().generate(bom)
    assert document["dependencies"] == [{"ref": "agent:main", "dependsOn": ["model:one"]}]
    recovered = CycloneDXGenerator.recover(document)
    assert sorted(recovered.dependencies, key=str) == sorted(bom.dependencies, key=str)
    assert any(
        json.loads(prop["value"])["type"] == "provides-tool"
        for prop in document["metadata"]["properties"]
        if prop["name"] == "nexus-symbiote:dependency:relationship"
    )


@pytest.mark.parametrize(
    "field", ["name", "hashes", "properties", "dependencies", "extra", "missing"]
)
def test_cyclonedx_recovery_rejects_conflicting_public_view(field):
    document = CycloneDXGenerator().generate(fixture_bom())
    component = next(c for c in document["components"] if c["bom-ref"] == "tool:send")
    if field == "name":
        component["name"] = "weather"
    elif field == "hashes":
        component["hashes"][0]["content"] = "ff" * 32
    elif field == "properties":
        prop = next(
            p for p in component["properties"] if p["name"] == "agentbom:claimsVerifiedByExporter"
        )
        prop["value"] = "true"
    elif field == "dependencies":
        document["dependencies"][0]["dependsOn"] = ["tool:send"]
    elif field == "extra":
        component["scope"] = "excluded"
    else:
        del component["hashes"]
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover(document)


@pytest.mark.parametrize("field", ["name", "hash", "relationship", "extra", "context"])
def test_spdx_recovery_rejects_conflicting_public_view(field):
    document = SPDXGenerator("https://example.test/custom-namespace").generate(fixture_bom())
    component = next(c for c in document["@graph"] if c.get("name") == "send")
    if field == "name":
        component["name"] = "weather"
    elif field == "hash":
        component["verifiedUsing"][0]["hashValue"] = "ff" * 32
    elif field == "relationship":
        edge = next(c for c in document["@graph"] if c.get("relationshipType") == "usesTool")
        edge["relationshipType"] = "dependsOn"
    elif field == "extra":
        component["summary"] = "externally reviewed"
    else:
        # The JSON-LD context determines how each term is interpreted.
        document["@context"] = "https://example.test/context"
    with pytest.raises(ValueError):
        SPDXGenerator.recover(document)


def test_legacy_cyclonedx_recovery_accepts_only_the_unchanged_historical_projection():
    bom = fixture_bom()
    document = CycloneDXGenerator().generate(bom)
    historical = deepcopy(document)
    historical["dependencies"] = [{"ref": "agent:main", "dependsOn": ["tool:send", "model:one"]}]
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover(historical)
    assert (
        CycloneDXGenerator.recover(historical, allow_legacy_relationships=True)
        .get_component("tool:send")
        .name
        == "send"
    )
    for graph in (
        [{"ref": "agent:main", "dependsOn": ["tool:send"]}],
        [{"ref": "agent:main", "dependsOn": ["tool:send", "model:one", "server:one"]}],
    ):
        with pytest.raises(ValueError, match="projection conflicts"):
            CycloneDXGenerator.recover(
                {**historical, "dependencies": graph}, allow_legacy_relationships=True
            )
    historical["components"][0]["name"] = "unexpected"
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover(historical, allow_legacy_relationships=True)


def _historical_export() -> dict[str, Any]:
    """Written by the exporter at 6edf849, before the standard graph was typed.

    Every native edge is in ``dependsOn`` and no relationship property has the
    conditional flag. The edges to prompt, server and tool are conditional.
    """
    return json.loads((LEGACY_FIXTURES / "flattened-6edf849.json").read_text(encoding="utf-8"))


def _relationship_values(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        value["to"]: value
        for value in (
            json.loads(prop["value"])
            for prop in document["metadata"]["properties"]
            if prop["name"] == "nexus-symbiote:dependency:relationship"
        )
    }


def _set_relationship_values(document: dict[str, Any], values: dict[str, dict[str, Any]]) -> None:
    for prop in document["metadata"]["properties"]:
        if prop["name"] == "nexus-symbiote:dependency:relationship":
            value = values[json.loads(prop["value"])["to"]]
            prop["value"] = json.dumps(value, sort_keys=True, separators=(",", ":"))


def test_legacy_cyclonedx_recovery_accepts_a_real_historical_export():
    document = _historical_export()
    assert document["dependencies"] == [
        {
            "ref": "agent:main",
            "dependsOn": ["memory:one", "model:one", "prompt:one", "server:one", "tool:send"],
        }
    ]
    assert not any("conditional" in value for value in _relationship_values(document).values())
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover(deepcopy(document))
    recovered = CycloneDXGenerator.recover(document, allow_legacy_relationships=True)
    assert sorted((e.target_ref, e.conditions is not None) for e in recovered.dependencies) == [
        ("memory:one", False),
        ("model:one", False),
        ("prompt:one", True),
        ("server:one", True),
        ("tool:send", True),
    ]
    current = CycloneDXGenerator().generate(recovered)
    assert current["dependencies"] == [{"ref": "agent:main", "dependsOn": ["model:one"]}]
    assert {
        to for to, value in _relationship_values(current).items() if value.get("conditional")
    } == {
        "prompt:one",
        "server:one",
        "tool:send",
    }
    assert sorted(CycloneDXGenerator.recover(current).dependencies, key=str) == sorted(
        recovered.dependencies, key=str
    )


@pytest.mark.parametrize(
    "change",
    [
        "flag-every-conditional",
        "flag-one-conditional",
        "flag-unconditional",
        "typed-graph",
        "drop-target",
        "retype",
    ],
)
def test_legacy_cyclonedx_recovery_rejects_a_mixed_or_changed_historical_projection(change):
    document = _historical_export()
    values = _relationship_values(document)
    if change == "flag-every-conditional":
        # The current flags with the flattened graph match no exporter's output.
        for target in ("prompt:one", "server:one", "tool:send"):
            values[target]["conditional"] = True
    elif change == "flag-one-conditional":
        values["tool:send"]["conditional"] = True
    elif change == "flag-unconditional":
        values["model:one"]["conditional"] = True
    elif change == "typed-graph":
        document["dependencies"] = [{"ref": "agent:main", "dependsOn": ["model:one"]}]
    elif change == "drop-target":
        document["dependencies"][0]["dependsOn"].remove("tool:send")
    else:
        values["tool:send"]["type"] = "depends-on"
    _set_relationship_values(document, values)
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover(document, allow_legacy_relationships=True)


@pytest.mark.parametrize("composition", [None, [{"aggregate": "complete"}]])
def test_cyclonedx_recovery_requires_preserved_public_incomplete_claim(composition):
    from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
    from tests.test_shadowscan_relationships import FIXTURE

    bom = ShadowScanImporter().read_report(FIXTURE).to_native_bom()
    document = CycloneDXGenerator().generate(bom)
    # Some standard readers omit compositions on reserialization. Losing the public
    # coverage warning is substantive even when the native extension survives.
    removed = document.pop("compositions")
    assert removed == [{"aggregate": "incomplete"}]
    if composition:
        document["compositions"] = composition
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover(document, allow_legacy_relationships=True)
