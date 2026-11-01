"""k8s-aibom importer: CR unwrapping, confidence mapping (§5), no signature laundering (I3)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import pytest

from symbiote.imp.k8s_aibom import (
    VERIFIED_WITHOUT_CONSTRAINT,
    K8sAibomError,
    extract_bom_document,
    import_k8s_aibom,
)
from symbiote.model.enums import AssuranceLevel, ValueState

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
DIGEST_HEX = "ab" * 32


def bom(confidence: str = "inferred", signature: dict | None = None, hosted: bool = False) -> dict:
    properties = [
        {"name": "aibom.confidence", "value": confidence},
        {"name": "aibom.workload.kind", "value": "Deployment"},
        {"name": "aibom.workload.name", "value": "triager"},
        {"name": "aibom.workload.namespace", "value": "prod"},
        {"name": "aibom.workload.uid", "value": "uid-123"},
        {"name": "aibom.redaction.applied", "value": "endpoint-internal-host"},
        {"name": "aibom.extraction.path", "value": "spec.containers[0].args"},
    ]
    for key, value in (signature or {}).items():
        properties.append({"name": f"signature.{key}", "value": value})
    component = {
        "type": "machine-learning-model",
        "bom-ref": "model-1",
        "name": "reranker-mini",
        "version": "main",
        "properties": properties,
    }
    if not hosted:
        component["hashes"] = [{"alg": "SHA-256", "content": DIGEST_HEX}]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "components": [component],
    }


def as_cr(document: dict) -> dict:
    return {
        "apiVersion": "aibom.k8saibom.dev/v1alpha1",
        "kind": "AIBOM",
        "metadata": {"name": "apps-deployment-triager", "namespace": "prod"},
        "status": {
            "bomDocument": {"inline": {"data": base64.b64encode(json.dumps(document).encode()).decode()}}
        },
    }


def test_cr_unwrapping_and_basic_mapping() -> None:
    result = import_k8s_aibom(as_cr(bom()), agent_id="agent:triager", now=NOW)
    assert result.source_serial_number and result.source_serial_number.startswith("urn:uuid:")
    (model,) = result.models
    assert model.weights is not None
    claim = model.weights
    assert claim.assurance is AssuranceLevel.OBSERVED  # inferred → observed
    assert claim.method is not None and claim.method.value == "heuristic" and claim.confidence == 0.5
    assert claim.value.manifest_root == f"sha256:{DIGEST_HEX}"
    (deployment,) = result.deployments
    assert deployment.workload_ref is not None and deployment.workload_ref.uid == "uid-123"
    assert deployment.environment.kind.value == "k8s" and deployment.environment.namespace == "prod"
    assert result.redactions and result.redactions[0].redaction_class == "endpoint-internal-host"
    assert any(f.name == "aibom.extraction.path" for f in result.foreign_properties)


def test_unresolved_maps_to_unknown_state() -> None:
    result = import_k8s_aibom(bom(confidence="unresolved"), now=NOW)
    claim = result.models[0].weights
    assert claim is not None and claim.state is ValueState.UNKNOWN and claim.value is None


def test_verified_without_constraint_downgrades_and_records_the_fact() -> None:
    result = import_k8s_aibom(
        bom(confidence="verified", signature={"status": "verified", "outcome": "verified"}),
        now=NOW,
    )
    claim = result.models[0].weights
    assert claim is not None and claim.assurance is AssuranceLevel.DECLARED  # unauthenticated producer claim
    assert VERIFIED_WITHOUT_CONSTRAINT in result.facts
    # a "verified" signature with no identity is downgraded to claimed (I3)
    assert result.models[0].signature is not None and result.models[0].signature.status.value == "claimed"


def test_self_asserted_signer_and_bundle_digest_do_not_verify() -> None:
    result = import_k8s_aibom(
        bom(
            confidence="verified",
            signature={
                "status": "verified",
                "outcome": "verified",
                "identity": "https://github.com/acme/models/.github/workflows/release.yml@refs/tags/v1",
                "issuer": "https://token.actions.githubusercontent.com",
                "bundleDigest": "sha256:" + "cd" * 32,
            },
        ),
        now=NOW,
    )
    claim = result.models[0].weights
    assert claim is not None and claim.assurance is AssuranceLevel.DECLARED
    assert not claim.evidence
    assert result.models[0].signature.status.value == "claimed"
    assert result.models[0].signature.outcome.value == "none"


def test_hosted_component_without_hash_becomes_hosted_model() -> None:
    result = import_k8s_aibom(bom(hosted=True), now=NOW)
    model = result.models[0]
    assert model.hosted is not None and model.weights is None


def test_url_referenced_bom_is_rejected_with_guidance() -> None:
    cr = as_cr(bom())
    cr["status"]["bomDocument"] = {"url": "https://bucket/bom.json"}
    with pytest.raises(K8sAibomError, match="references its BOM by URL"):
        extract_bom_document(cr)


def test_non_aibom_input_is_rejected() -> None:
    with pytest.raises(K8sAibomError):
        extract_bom_document({"hello": "world"})


def test_model_identity_survives_same_name_and_duplicate_components() -> None:
    payload = bom()
    base = payload["components"][0]
    payload["components"] += [
        base.copy(),
        {**base, "bom-ref": "model-2", "hashes": [{"alg": "SHA-256", "content": "cd" * 32}]},
    ]
    left = import_k8s_aibom(payload, now=NOW)
    payload["components"].reverse()
    right = import_k8s_aibom(payload, now=NOW)
    assert len({model.id for model in left.models}) == len(left.models) == 2
    assert {model.id for model in left.models} == {model.id for model in right.models}


def test_conflicting_subjects_at_duplicate_bom_ref_rejected():
    payload = bom()
    payload["components"].append({**payload["components"][0], "version": "new"})
    with pytest.raises(K8sAibomError, match="conflicting components"):
        import_k8s_aibom(payload, now=NOW)
