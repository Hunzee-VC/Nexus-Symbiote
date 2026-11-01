"""Fingerprint migrations must preserve both drift detection and honest unknowns."""

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import TOOL_DEFINITION_HASH_VERSION
from nexus_symbiote.core.models import ToolComponent
from nexus_symbiote.diff.differ import AIBOMDiffer


def document(digest, version):
    return AIBOM(
        components=[
            ToolComponent(
                bom_ref="tool:t", name="t", definition_hash=digest, definition_hash_version=version
            )
        ]
    )


def test_current_fingerprint_identical_is_not_drift():
    first = document("sha256:" + "a" * 64, TOOL_DEFINITION_HASH_VERSION)
    second = document("sha256:" + "a" * 64, TOOL_DEFINITION_HASH_VERSION)
    assert not AIBOMDiffer().diff(first, second).has_changes


def test_current_fingerprint_mutation_is_critical():
    result = AIBOMDiffer().diff(
        document("sha256:" + "a" * 64, TOOL_DEFINITION_HASH_VERSION),
        document("sha256:" + "b" * 64, TOOL_DEFINITION_HASH_VERSION),
    )
    assert result.security_alerts[0]["severity"] == "critical"
    assert result.components_modified[0].severity == "critical"


def test_legacy_profile_requires_reapproval_even_when_digest_looks_equal():
    for legacy in [None, "rfc8785-jcs-v1"]:
        result = AIBOMDiffer().diff(
            document("sha256:" + "a" * 64, legacy),
            document("sha256:" + "a" * 64, TOOL_DEFINITION_HASH_VERSION),
        )
        assert result.has_changes
        assert result.components_modified[0].severity == "high"
        assert "re-approve" in result.components_modified[0].details[0]
