"""Unrecoverable reference topologies never reach the general SPDX validator."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.aibom import AIBOM, native_document
from nexus_symbiote.generators import spdx
from nexus_symbiote.generators.recovery import recover_export
from nexus_symbiote.generators.spdx import SPDXGenerator


def _with_inline_references(document: dict[str, Any], depth: int) -> dict[str, Any]:
    creation: dict[str, Any] = {
        "type": "CreationInfo",
        "created": "2026-11-14T00:00:00Z",
        "createdBy": ["urn:test:actor"],
        "specVersion": "3.0.1",
    }
    for index in range(depth):
        creation = {
            "type": "CreationInfo",
            "created": "2026-11-14T00:00:00Z",
            "createdBy": [
                {
                    "type": "SoftwareAgent",
                    "spdxId": f"urn:test:actor:{index}",
                    "creationInfo": creation,
                }
            ],
            "specVersion": "3.0.1",
        }
    document["@graph"].append(
        {"type": "Tool", "spdxId": "urn:test:extra", "creationInfo": creation}
    )
    return document


@pytest.mark.parametrize("depth", [0, 1, 2, 3, 8])
@pytest.mark.parametrize("text_api", [False, True])
def test_inline_references_are_rejected_before_schema_validation(monkeypatch, depth, text_api):
    document = _with_inline_references(SPDXGenerator().generate(AIBOM()), depth)

    def refuse_schema(*args, **kwargs):
        pytest.fail("unrecoverable nested references reached the general schema validator")

    monkeypatch.setattr(spdx, "spdx_errors", refuse_schema)
    with pytest.raises(ValueError, match="projection conflicts"):
        if text_api:
            recover_export(json.dumps(document))
        else:
            SPDXGenerator.recover(document)


def test_timestamp_normalization_does_not_skip_schema_validation():
    document = SPDXGenerator().generate(AIBOM())
    creation = next(node for node in document["@graph"] if node["type"] == "CreationInfo")
    creation["created"] = "not-a-date-time"
    with pytest.raises(ValueError, match="invalid spdx export"):
        SPDXGenerator.recover(document)


def test_current_and_legacy_exports_still_pass_the_official_schema_check(monkeypatch):
    current_bom = AIBOM()
    current = SPDXGenerator().generate(current_bom)
    fixtures = Path(__file__).parent / "fixtures" / "export-projection-0.1.0"
    documents = [current, *[json.loads(path.read_text()) for path in fixtures.glob("*.spdx.json")]]
    checked: list[str | None] = []
    schema_errors = spdx.spdx_errors

    def record_schema(document, *, legacy_license=None):
        checked.append(legacy_license)
        return schema_errors(document, legacy_license=legacy_license)

    monkeypatch.setattr(spdx, "spdx_errors", record_schema)
    for document in documents:
        recovered = SPDXGenerator.recover(deepcopy(document))
        assert recover_export(json.dumps(document)) == recovered
    assert native_document(SPDXGenerator.recover(current)) == native_document(current_bom)
    assert len(checked) == len(documents) * 2 + 1
    assert None in checked
    assert spdx._legacy.NO_ASSERTION_LICENSE in checked
