"""Neutralized projection-3 comments preserve recovery of projection-2 exports."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from nexus_symbiote.generators import spdx
from nexus_symbiote.generators.recovery import recover_export
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import validate_spdx
from nexus_symbiote.utils.terminal import neutralize


def legacy_document():
    path = Path(__file__).parent / "fixtures/export-projection-2/conditional.spdx.json"
    return json.loads(path.read_text(encoding="utf-8"))


def marker(document):
    node = next(node for node in document["@graph"] if node["type"] == "SpdxDocument")
    return next(
        prop
        for extension in node["extension"]
        for prop in extension["extension_cdxProperty"]
        if prop["extension_cdxPropName"] == "nexus-symbiote:projection"
    )


def conditional(document):
    return next(node for node in document["@graph"] if "conditions:" in node.get("comment", ""))


def test_frozen_projection_two_recovers_with_its_original_comment():
    document = legacy_document()
    assert validate_spdx(document) == []
    original_comment = conditional(document)["comment"]
    assert "\n" in original_comment and "\t" in original_comment and "\u202e" in original_comment
    bom = SPDXGenerator.recover(document)
    assert recover_export(json.dumps(document)) == bom
    assert "\n" in bom.dependencies[0].conditions

    current = SPDXGenerator().generate(bom)
    assert marker(current)["extension_cdxPropValue"] == "spdx-3.0.1/3"
    assert conditional(current)["comment"] == neutralize(original_comment)
    assert SPDXGenerator.recover(current) == bom
    assert document == legacy_document()


@pytest.mark.parametrize("edit", ["comment", "marker", "inline-reference"])
def test_projection_two_still_rejects_a_changed_standard_view(edit, monkeypatch):
    document = legacy_document()
    if edit == "comment":
        conditional(document)["comment"] = neutralize(conditional(document)["comment"])
    elif edit == "marker":
        marker(document)["extension_cdxPropValue"] = "spdx-3.0.1/3"
    else:
        document["@graph"].append(
            {"type": "Tool", "spdxId": "urn:test:extra", "creationInfo": {"type": "CreationInfo"}}
        )

    def refuse_schema(*args, **kwargs):
        pytest.fail("conflicting legacy projection reached general schema validation")

    monkeypatch.setattr(spdx, "spdx_errors", refuse_schema)
    with pytest.raises(ValueError, match="projection conflicts"):
        SPDXGenerator.recover(document)


def test_projection_three_cannot_be_relabelled_as_two():
    bom = SPDXGenerator.recover(legacy_document())
    document = deepcopy(SPDXGenerator().generate(bom))
    marker(document)["extension_cdxPropValue"] = "spdx-3.0.1/2"
    with pytest.raises(ValueError, match="projection conflicts"):
        SPDXGenerator.recover(document)
