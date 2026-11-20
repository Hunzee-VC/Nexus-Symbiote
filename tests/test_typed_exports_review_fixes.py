"""Regressions for the #279 review of cdf955ba: projection pins, SDK round trip, declarations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from cyclonedx.model.bom import Bom
from cyclonedx.output.json import JsonV1Dot6, JsonV1Dot7

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, native_document
from nexus_symbiote.core.enums import AssuranceLevel, AutonomyLevel
from nexus_symbiote.core.models import AgentComponent, DataSourceComponent, ModelComponent
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.spdx_profiles import apply_agent_yaml_declarations, spdx_license_expression
from tests.test_export_conformance import fixture_bom
from tests.test_typed_exports_and_spdx_ai import _rich_aibom

FROZEN_V3 = Path(__file__).parent / "fixtures/export-projection-3/fixture.spdx.json"
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"


def _observed() -> AIBOM:
    bom = AIBOM()
    bom.components = [
        AgentComponent(
            bom_ref="agent:a",
            name="a",
            autonomy_level=AutonomyLevel.L2_AGENT,
            assurance_level=AssuranceLevel.OBSERVED,
        ),
        ModelComponent(
            bom_ref="model:m",
            name="models/clf.safetensors",
            model_type="classifier",
            assurance_level=AssuranceLevel.OBSERVED,
        ),
        DataSourceComponent(
            bom_ref="dataset:d",
            name="tickets",
            source_uri="https://data.example.com/tickets.parquet",
            license="CC-BY-4.0",
            assurance_level=AssuranceLevel.OBSERVED,
        ),
    ]
    return bom


def _declare(tmp_path: Path, text: str) -> tuple[AIBOM, list[str]]:
    (tmp_path / "agent.yaml").write_text(text, encoding="utf-8")
    bom = _observed()
    return bom, apply_agent_yaml_declarations(bom, tmp_path, relative_path="agent.yaml")


def _graph_node(document: dict, **match: str) -> dict:
    return next(n for n in document["@graph"] if all(n.get(k) == v for k, v in match.items()))


def test_spdx_projection_3_reprojects_a_frozen_export_byte_for_byte() -> None:
    text = FROZEN_V3.read_text(encoding="utf-8")
    recovered = SPDXGenerator.recover(json.loads(text))
    assert SPDXGenerator().generate_json(recovered) + "\n" == text


@pytest.mark.parametrize("spec, writer", [("1.7", JsonV1Dot7), ("1.6", JsonV1Dot6)])
def test_cdx_projection_3_survives_cyclonedx_python_lib(spec, writer) -> None:
    original = fixture_bom()
    document = CycloneDXGenerator(projection_version=3, spec_version=spec).generate(original)
    assert any("modelCard" in c for c in document["components"])
    output = json.loads(writer(Bom.from_json(document)).output_as_string())
    assert native_document(CycloneDXGenerator.recover(output)) == native_document(original)


def test_cdx_projection_3_rejects_a_partly_removed_or_edited_model_card() -> None:
    document = CycloneDXGenerator(projection_version=3).generate(_rich_aibom())
    cards = [c for c in document["components"] if "modelCard" in c]
    assert len(cards) >= 2
    del cards[0]["modelCard"]
    with pytest.raises(ValueError, match="conflicts"):
        CycloneDXGenerator.recover(document)
    edited = CycloneDXGenerator(projection_version=3).generate(_rich_aibom())
    next(c for c in edited["components"] if "modelCard" in c)["modelCard"] = {
        "modelParameters": {"task": "edited"}
    }
    with pytest.raises(ValueError, match="conflicts"):
        CycloneDXGenerator.recover(edited)


def test_declarations_never_replace_observed_dataset_location_or_license(tmp_path: Path) -> None:
    bom, notices = _declare(
        tmp_path,
        'schema_version: "1.1"\ndatasets:\n  - name: tickets\n    license: MIT\n'
        "    download_location: https://attacker.example.net/tickets.parquet\n"
        "models:\n  - name: models/clf.safetensors\n"
        "    download_location: https://models.example.com/clf.safetensors\n"
        "    training:\n      datasets: [tickets]\n",
    )
    assert notices == [
        "dataset:d: license conflict with agent.yaml",
        "dataset:d: source_uri conflict with agent.yaml",
    ]
    dataset = bom.get_component("dataset:d")
    assert "declared_license" not in dataset.properties
    assert "declared_download_location" not in dataset.properties
    # A declared training edge is exported as a typed edge but keeps its provenance.
    assert [e.model_dump(exclude_none=True) for e in bom.dependencies] == [
        {
            "source_ref": "model:m",
            "target_ref": "dataset:d",
            "relationship": "trained-on",
            "assurance_level": "declared",
        }
    ]

    cdx = CycloneDXGenerator(projection_version=3).generate(bom)
    by_ref = {c["bom-ref"]: c for c in cdx["components"]}
    assert by_ref["dataset:d"]["externalReferences"] == [
        {"type": "distribution", "url": "https://data.example.com/tickets.parquet"}
    ]
    assert by_ref["dataset:d"]["licenses"] == [{"license": {"id": "CC-BY-4.0"}}]
    assert by_ref["model:m"]["externalReferences"] == [
        {
            "type": "distribution",
            "url": "https://models.example.com/clf.safetensors",
            "comment": "declared by producer",
        }
    ]

    spdx_doc = SPDXGenerator(projection_version=4).generate(bom)
    ds = _graph_node(spdx_doc, name="tickets")
    assert ds["software_downloadLocation"] == "https://data.example.com/tickets.parquet"
    licence = _graph_node(spdx_doc, relationshipType="hasDeclaredLicense", **{"from": ds["spdxId"]})
    expression = _graph_node(spdx_doc, spdxId=licence["to"][0])
    assert expression["simplelicensing_licenseExpression"] == "CC-BY-4.0"
    trained = _graph_node(spdx_doc, relationshipType="trainedOn")
    (native_edge,) = trained["extension"][0]["extension_cdxProperty"]
    assert json.loads(native_edge["extension_cdxPropValue"])["assurance_level"] == "declared"


def test_declared_dataset_without_observed_location_is_marked_declared(tmp_path: Path) -> None:
    bom = _observed()
    bom.get_component("dataset:d").source_uri = None
    (tmp_path / "agent.yaml").write_text(
        "datasets:\n  - name: tickets\n    download_location: https://d.example.com/t.parquet\n",
        encoding="utf-8",
    )
    apply_agent_yaml_declarations(bom, tmp_path, relative_path="agent.yaml")
    ds = _graph_node(SPDXGenerator(projection_version=4).generate(bom), name="tickets")
    assert ds["software_downloadLocation"] == "https://d.example.com/t.parquet"
    declared = [
        p["extension_cdxPropValue"]
        for p in ds["extension"][0]["extension_cdxProperty"]
        if p["extension_cdxPropName"] == "nexus-symbiote:declaredField"
    ]
    assert "software_downloadLocation" in declared


@pytest.mark.parametrize("token", [AWS_KEY, GH_TOKEN])
def test_token_shaped_url_host_never_reaches_exports(tmp_path: Path, token: str) -> None:
    bom, _ = _declare(tmp_path, f"download_location: https://{token}.example.com/agent.tgz\n")
    assert "declared_download_location" not in bom.get_component("agent:a").properties
    for generator in (
        CycloneDXGenerator(projection_version=3),
        SPDXGenerator(projection_version=4),
    ):
        assert token not in generator.generate_json(bom)


def test_declared_free_text_secrets_are_redacted(tmp_path: Path) -> None:
    bom, _ = _declare(
        tmp_path,
        f'owner: "{GH_TOKEN}"\ndata_usage: "password=hunter2hunter2 {AWS_KEY}"\n'
        f'compliance: ["{GH_TOKEN}"]\n',
    )
    for generator in (
        CycloneDXGenerator(projection_version=3),
        SPDXGenerator(projection_version=4),
    ):
        rendered = generator.generate_json(bom)
        assert GH_TOKEN not in rendered
        assert AWS_KEY not in rendered
        assert "hunter2hunter2" not in rendered


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
def test_author_option_is_redacted(tmp_path: Path, fmt: str) -> None:
    bom_path = tmp_path / "inv.json"
    _observed().save(bom_path)
    result = CliRunner().invoke(
        main, ["export-standard", str(bom_path), "-f", fmt, "--author", f"ops {AWS_KEY}"]
    )
    assert result.exit_code == 0, result.output
    assert AWS_KEY not in result.output
    assert "ops ***" in result.output
    assert AWS_KEY not in SPDXGenerator(
        projection_version=4, author=f"ops {AWS_KEY}"
    ).generate_json(_observed())


@pytest.mark.parametrize(
    "value, valid",
    [
        ("Apache-2.0", True),
        ("MIT OR Apache-2.0", True),
        ("(MIT AND BSD-3-Clause) OR Apache-2.0", True),
        ("GPL-2.0-or-later WITH Classpath-exception-2.0", True),
        ("LicenseRef-acme-1", True),
        ("Apache License 2.0", False),
        ("Proprietary", False),
        ("MIT OR", False),
        ("(MIT", False),
        ("MIT)", False),
        ("AND MIT", False),
        ("MIT Apache-2.0", False),
    ],
)
def test_spdx_license_expression_grammar(value: str, valid: bool) -> None:
    assert spdx_license_expression(value) == (value if valid else None)


def test_invalid_license_text_is_no_assertion_in_spdx_and_name_in_cdx(tmp_path: Path) -> None:
    bom, _ = _declare(
        tmp_path,
        'licenses: ["Apache License 2.0"]\nmodels:\n  - name: models/clf.safetensors\n'
        "    license: Proprietary\n",
    )
    bom.get_component("dataset:d").license = None
    spdx_doc = SPDXGenerator(projection_version=4).generate(bom)
    expressions = [
        n["simplelicensing_licenseExpression"]
        for n in spdx_doc["@graph"]
        if n["type"] == "simplelicensing_LicenseExpression"
    ]
    assert expressions == []
    assert "simpleLicensing" not in _graph_node(spdx_doc, type="SpdxDocument")["profileConformance"]
    assert "Proprietary" in json.dumps(spdx_doc)  # kept in the native extension

    cdx = {
        c["bom-ref"]: c
        for c in CycloneDXGenerator(projection_version=3).generate(bom)["components"]
    }
    assert cdx["model:m"]["licenses"] == [
        {"license": {"name": "Proprietary", "acknowledgement": "declared"}}
    ]
    bom.get_component("dataset:d").license = "MIT OR Apache-2.0"
    cdx = {
        c["bom-ref"]: c
        for c in CycloneDXGenerator(projection_version=3).generate(bom)["components"]
    }
    assert cdx["dataset:d"]["licenses"] == [{"expression": "MIT OR Apache-2.0"}]
