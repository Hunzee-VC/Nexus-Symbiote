"""Tests for deployment-scoped authority and evidence claims."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.evidence import AuthorityClaim, DeploymentProfile, EvidenceRecord
from nexus_symbiote.core.models import AgentComponent

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def evidence(**changes):
    data = {"source": "iam:policy:42", "collector": "iam-reader", "collected_at": NOW}
    data.update(changes)
    return EvidenceRecord(**data)


def test_existing_agent_round_trips_without_profile():
    original = AIBOM(components=[AgentComponent(bom_ref="agent:a", name="a")])
    restored = AIBOM.model_validate_json(original.model_dump_json(exclude_none=True))
    assert restored.components[0].deployment_profile is None


def test_deployment_authority_and_evidence_round_trip():
    claim = AuthorityClaim(
        kind="effective",
        state="observed",
        principal="workload:agent-a",
        action="s3:GetObject",
        resource="arn:example:bucket/docs/*",
        observed_at=NOW,
        evidence=[evidence()],
    )
    profile = DeploymentProfile(
        deployment_id="prod:agent-a:v3",
        environment="production",
        tenant="tenant-1",
        workload_identity="workload:agent-a",
        authority=[claim],
    )
    agent = AgentComponent(bom_ref="agent:a", name="a", deployment_profile=profile)
    restored = AIBOM.model_validate_json(AIBOM(components=[agent]).model_dump_json())
    result = restored.components[0].deployment_profile
    assert result is not None
    assert result.authority[0].kind.value == "effective"
    assert result.authority[0].evidence[0].verification_status.value == "unverified"


def test_unknown_is_not_an_empty_permission_set():
    claim = AuthorityClaim(kind="effective", state="unknown", unknown_reason="access denied")
    assert claim.principal is None and claim.resource is None
    with pytest.raises(ValidationError):
        AuthorityClaim(kind="effective", state="unknown")
    with pytest.raises(ValidationError):
        AuthorityClaim(kind="effective", state="unknown", unknown_reason="denied", action="read")
    na = AuthorityClaim(kind="observed", state="not-applicable")
    assert na.action is None


def test_known_claim_requires_scoped_authority_and_evidence():
    with pytest.raises(ValidationError):
        AuthorityClaim(kind="declared", state="declared", principal="alice", action="read")
    with pytest.raises(ValidationError):
        AuthorityClaim(
            kind="declared", state="declared", principal="alice", action="read", resource="*"
        )
    with pytest.raises(ValidationError):
        AuthorityClaim(
            kind="observed",
            state="observed",
            principal="alice",
            action="read",
            resource="*",
            evidence=[evidence()],
        )


def test_verified_is_only_a_well_formed_producer_claim():
    with pytest.raises(ValidationError):
        evidence(verification_status="verified")
    with pytest.raises(ValidationError):
        AuthorityClaim(
            kind="effective",
            state="verified",
            principal="alice",
            action="read",
            resource="*",
            evidence=[evidence()],
        )
    item = evidence(
        verification_status="verified",
        subject_digest="sha256:" + "a" * 64,
        verifier="verifier:v1",
        verification_policy="policy:v1",
        verified_at=NOW,
    )
    claim = AuthorityClaim(
        kind="effective",
        state="verified",
        principal="alice",
        action="read",
        resource="*",
        evidence=[item],
    )
    assert claim.evidence[0].verification_policy == "policy:v1"


def test_timestamps_must_have_timezone():
    with pytest.raises(ValidationError):
        evidence(collected_at=datetime(2026, 1, 1))
    with pytest.raises(ValidationError):
        AuthorityClaim(
            kind="observed",
            state="observed",
            principal="alice",
            action="read",
            resource="*",
            observed_at=datetime(2026, 1, 1),
            evidence=[evidence()],
        )


def test_native_schema_checks_deployment_profile_shape():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "nexus-symbiote-aibom-1.0.schema.json").read_text()
    )
    profile = DeploymentProfile(deployment_id="prod:a:v1", environment="production")
    agent = AgentComponent(bom_ref="agent:a", name="a", deployment_profile=profile)
    bom = AIBOM(components=[agent]).model_dump(mode="json", exclude_none=True)
    jsonschema.validate(bom, schema)
    bom["components"][0]["deployment_profile"]["environment"] = ""
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bom, schema)
