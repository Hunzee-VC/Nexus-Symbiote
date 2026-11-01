from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from symbiote.model import AgentBOM, Claim, Edge, companion_json_schema
from symbiote.model import enums as E
from symbiote.model.common import EvidenceRef, Validity
from symbiote.model.entities import Identity, SignatureFacts, ToolServer
from symbiote.model.ids import make_id, slugify, tool_id, uuid5_for_digest
from tests.conftest import D


def test_round_trip_json(minimal_bom: AgentBOM) -> None:
    js = minimal_bom.to_json_dict()
    assert js["toolServers"][0]["kind"] == "mcp"
    assert js["edges"][0]["from"] == "agent:triager"
    assert AgentBOM.model_validate(js) == minimal_bom
    assert AgentBOM.model_validate_json(json.dumps(js)) == minimal_bom


def test_i2_unknown_claims_need_reason() -> None:
    with pytest.raises(ValidationError):
        Claim(state=E.ValueState.UNKNOWN)
    c: Claim[str] = Claim.unknown(E.UnknownReason.PERMISSION_DENIED)
    assert c.is_unknown and c.value is None
    with pytest.raises(ValidationError):
        Claim(value="x", state=E.ValueState.UNKNOWN, unknown_reason=E.UnknownReason.TIMEOUT)


def test_i3_verified_requires_constrained_evidence() -> None:
    with pytest.raises(ValidationError):
        Claim(value=1, assurance=E.AssuranceLevel.VERIFIED)
    ok = Claim(
        value=1,
        assurance=E.AssuranceLevel.VERIFIED,
        evidence=[EvidenceRef(digest=D, verification=E.EvidenceVerification.VERIFIED_CONSTRAINED)],
    )
    assert ok.assurance is E.AssuranceLevel.VERIFIED
    with pytest.raises(ValidationError):
        Claim(
            value=1,
            assurance=E.AssuranceLevel.VERIFIED,
            evidence=[
                EvidenceRef(digest=D, verification=E.EvidenceVerification.SIGNATURE_VALID_UNCONSTRAINED)
            ],
        )


def test_signature_facts_never_launder() -> None:
    with pytest.raises(ValidationError):
        SignatureFacts(
            status=E.SignatureStatus.VERIFIED,
            outcome=E.SignatureOutcome.SIGNATURE_VALID_UNCONSTRAINED,
            identity="x",
        )
    with pytest.raises(ValidationError):
        SignatureFacts(status=E.SignatureStatus.VERIFIED, outcome=E.SignatureOutcome.VERIFIED)
    SignatureFacts(status=E.SignatureStatus.CLAIMED, outcome=E.SignatureOutcome.SIGNATURE_VALID_UNCONSTRAINED)


@pytest.mark.parametrize(
    "secret",
    [
        "sk-abcdefghijklmnopqrstuvwxyz1234",
        "AKIAABCDEFGHIJKLMNOP",
        "-----BEGIN RSA PRIVATE KEY-----",
        "ghp_" + "a" * 36,
    ],
)
def test_identity_rejects_secret_shapes(secret: str) -> None:
    with pytest.raises(ValidationError):
        Identity(id="ident:x", identity_kind=E.IdentityKind.API_KEY_REF, ref=secret)


def test_tool_server_names_only() -> None:
    with pytest.raises(ValidationError):
        ToolServer(
            id="server:x",
            kind=E.ToolServerKind.MCP,
            transport=Claim.declared(E.Transport.STDIO),
            authentication=Claim.declared({"mode": "none"}),
            crosses_trust_boundary=Claim.declared(False),
            env_var_names=["TOKEN=sk-abcdefghijklmnopqrstuvwxyz1234"],
        )


def test_document_integrity(minimal_bom: AgentBOM) -> None:
    with pytest.raises(ValidationError):
        minimal_bom.replace(subject="agent:other")
    with pytest.raises(ValidationError):
        minimal_bom.replace(
            edges=[
                *minimal_bom.edges,
                Edge(type=E.EdgeType.USES_MODEL, **{"from": "agent:triager", "to": "model:missing"}),
            ]
        )
    with pytest.raises(ValidationError):
        minimal_bom.replace(agents=[*minimal_bom.agents, minimal_bom.agents[0]])


def test_coverage_defaults_to_unknown(minimal_bom: AgentBOM) -> None:
    assert len(minimal_bom.coverage.surfaces) == len(E.Surface)
    assert minimal_bom.coverage.completeness is E.Completeness.UNKNOWN


def test_validity_ordering() -> None:
    from datetime import UTC, datetime

    with pytest.raises(ValidationError):
        Validity(not_before=datetime(2026, 1, 2, tzinfo=UTC), not_after=datetime(2026, 1, 1, tzinfo=UTC))


def test_ids() -> None:
    assert slugify("GitHub MCP Server!") == "github-mcp-server"
    assert slugify("Ünïcödé") == "unicode"
    assert make_id("server", "GitHub") == "server:github"
    assert tool_id("server:github", "get_issue") == "tool:github/get_issue"
    assert str(uuid5_for_digest(D)) == str(uuid5_for_digest(D))


def test_companion_schema_is_strict_and_stable() -> None:
    s1 = companion_json_schema()
    s2 = companion_json_schema()
    assert s1 == s2
    assert s1["$id"].endswith("/schemas/agentbom/0.1/agentbom.schema.json")
    assert s1["additionalProperties"] is False
    assert "AgentBOM" in s1.get("title", "") or s1["title"]
