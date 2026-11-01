"""Regression tests for canonical fingerprints and CycloneDX projections."""

import json

import pytest

from symbote.core.hashing import canonical_json
from symbote.generators.cyclonedx import CycloneDXGenerator
from tests.test_generators import _sample_aibom


def test_jcs_numbers_and_unicode_order():
    assert canonical_json(1e-7) == "1e-7"
    assert canonical_json(1e20) == "100000000000000000000"
    assert canonical_json({"\ue000": 1, "\U00010000": 2}) == '{"\U00010000":2,"\ue000":1}'
    with pytest.raises(ValueError):
        canonical_json(float("nan"))


def test_cyclonedx_preserves_edge_semantics_without_invalid_fields():
    bom = _sample_aibom()
    exported = CycloneDXGenerator().generate(bom)
    assert all(set(edge) == {"ref", "dependsOn"} for edge in exported["dependencies"])
    relationship = json.loads(exported["metadata"]["properties"][0]["value"])
    assert relationship["type"] == "invokes"
    agent = next(c for c in exported["components"] if c["bom-ref"] == "agent:main")
    assert agent["type"] == "application"


def test_cyclonedx_strict_validator():
    # Optional dependency; CI should install a CycloneDX 1.7-capable version.
    pytest.importorskip("cyclonedx.validation.json")
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    if not hasattr(SchemaVersion, "V1_7"):
        pytest.skip("installed cyclonedx library does not support 1.7")
    data = CycloneDXGenerator().generate_json(_sample_aibom())
    assert JsonStrictValidator(SchemaVersion.V1_7).validate_str(data) is None
