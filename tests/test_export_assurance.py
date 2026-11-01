"""Regression tests for canonical fingerprints and CycloneDX projections."""

import json

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.hashing import canonical_json
from nexus_symbiote.core.models import (
    AIBOMMetadata,
    CompletenessClaim,
    ModelComponent,
    RiskAssessment,
)
from nexus_symbiote.core.vocab import REQUIRED_SCANNERS
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.sarif import SARIFGenerator
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


def test_legacy_tool_fingerprint_requires_migration():
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.core.models import ToolComponent
    from nexus_symbiote.validators.integrity import IntegrityValidator

    bom = AIBOM()
    bom.add_component(
        ToolComponent(
            bom_ref="tool:legacy",
            name="legacy",
            description_text="legacy tool",
            definition_hash="sha256:old",
        )
    )
    report = IntegrityValidator().validate(bom)
    assert not report.is_valid
    assert report.hashes_verified == 0
    assert any(i.category == "fingerprint_version_unknown" for i in report.issues)


def test_diff_does_not_compare_legacy_and_new_fingerprints():
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.core.models import ToolComponent
    from nexus_symbiote.diff.differ import AIBOMDiffer

    old = AIBOM()
    new = AIBOM()
    old.add_component(ToolComponent(bom_ref="tool:t", name="t", definition_hash="sha256:old"))
    new.add_component(
        ToolComponent(
            bom_ref="tool:t",
            name="t",
            definition_hash="sha256:new",
            definition_hash_version="rfc8785-jcs-v1",
        )
    )
    result = AIBOMDiffer().diff(old, new)
    assert result.has_changes
    assert any(
        "unknown or incompatible" in item for c in result.components_modified for item in c.details
    )


def _sarif_bom(scan_failures: list[str], scanner_status: dict[str, str]) -> AIBOM:
    bom = AIBOM(
        metadata=AIBOMMetadata(
            completeness=CompletenessClaim(
                scope="test",
                scan_failures=scan_failures,
                scanner_status=scanner_status,
            )
        )
    )
    bom.add_component(
        ModelComponent(
            bom_ref="model:m",
            name="m",
            risks=[
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="signing_status",
                    detail="Model is unsigned.",
                )
            ],
        )
    )
    return bom


def test_sarif_execution_successful_when_no_failures():
    bom = _sarif_bom([], dict.fromkeys(REQUIRED_SCANNERS, "complete"))
    run = SARIFGenerator().generate(bom)["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is True


def test_sarif_execution_unsuccessful_when_scan_failure_recorded():
    bom = _sarif_bom(["mcp: could not read .mcp.json"], dict.fromkeys(REQUIRED_SCANNERS, "complete"))
    run = SARIFGenerator().generate(bom)["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is False


def test_sarif_execution_unsuccessful_when_scanner_failed():
    status = dict.fromkeys(REQUIRED_SCANNERS, "complete")
    status["rag"] = "failed"
    bom = _sarif_bom([], status)
    run = SARIFGenerator().generate(bom)["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is False
