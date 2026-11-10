"""Envelope encodings, endpoint identities, descriptor digests and the argument domain."""

from __future__ import annotations

import base64
import inspect
import json
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import nexus_symbiote.runtime as runtime
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.runtime import (
    MAX_STATEMENT_BYTES,
    PREDICATES,
    STATEMENT_TYPE,
    AuthorizationError,
    Envelope,
    EnvelopeSignature,
    ServedTool,
    ToolCall,
    ToolGrant,
    TrustStatus,
    _pae,
    canonical_bytes,
    digest,
    key_id,
    request_digest,
    sign_contract,
    tool_definition_digest,
    verify_contract,
)
from tests.test_runtime_authorization import DEFINITION, NOW, autonomous, fixture, invoke


def ring(*keys):
    return {key_id(key.public_key()): key.public_key() for key in keys}


def test_url_safe_base64_is_accepted_and_normalized(tmp_path):
    values = fixture(tmp_path)
    key = values[6]
    envelope = sign_contract(values[3], "snapshot", (key,))
    wire = envelope.model_dump(mode="json", by_alias=True)
    payload = base64.b64decode(wire["payload"])
    raw = base64.b64decode(wire["signatures"][0]["sig"])
    wire["payload"] = base64.urlsafe_b64encode(payload).decode()
    wire["signatures"][0]["sig"] = base64.urlsafe_b64encode(raw).decode()
    parsed = Envelope.model_validate(wire)
    assert parsed == envelope
    contract, accepted = verify_contract(parsed, "snapshot", ring(key))
    assert contract == values[3] and accepted == {key_id(key.public_key())}


@pytest.mark.parametrize("payload", ["QR==", "QQ", "QQ=", "Q+-=", "Q Q=", "QQ==\n"])
def test_noncanonical_or_mixed_base64_is_rejected(payload):
    with pytest.raises(ValidationError, match="payload"):
        Envelope(payload=payload, signatures=())
    assert Envelope(payload="QQ==", signatures=()).payload == "QQ=="


@pytest.mark.parametrize("hint", [None, "", "kms-key-7", "a" * 64])
def test_signature_without_a_matching_key_id_is_tried_against_each_ring_key(tmp_path, hint):
    values = fixture(tmp_path)
    key, other = values[6], Ed25519PrivateKey.generate()
    envelope = sign_contract(values[3], "snapshot", (key,))
    foreign = envelope.signatures[0].model_copy(update={"key_id": hint})
    envelope = envelope.model_copy(update={"signatures": (foreign,)})
    contract, accepted = verify_contract(envelope, "snapshot", ring(other, key))
    assert contract == values[3] and accepted == {key_id(key.public_key())}


def test_verification_work_per_envelope_is_capped(tmp_path):
    values = fixture(tmp_path)
    key = values[6]
    keys = ring(key, Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())
    valid = sign_contract(values[3], "snapshot", (key,))
    bogus = EnvelopeSignature(key_id=None, signature=base64.b64encode(bytes(64)).decode())
    padded = valid.model_copy(update={"signatures": (bogus,) * 31 + valid.signatures})
    with pytest.raises(AuthorizationError) as capped:
        verify_contract(padded, "snapshot", keys)
    assert capped.value.reason == "signers-insufficient"
    first = valid.model_copy(update={"signatures": valid.signatures + (bogus,) * 31})
    assert verify_contract(first, "snapshot", keys)[1] == {key_id(key.public_key())}


def statement_envelope(key, predicate, kind="snapshot", subject=None, raw=None):
    statement = {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATES[kind],
        "subject": subject or [],
        "predicate": predicate,
    }
    payload = raw if raw is not None else canonical_bytes(statement)
    signature = EnvelopeSignature(
        key_id=key_id(key.public_key()),
        signature=base64.b64encode(key.sign(_pae(payload))).decode(),
    )
    return Envelope(payload=base64.b64encode(payload).decode(), signatures=(signature,))


def test_deeply_nested_signed_payload_is_an_authorization_error():
    key = Ed25519PrivateKey.generate()
    envelope = statement_envelope(key, None, raw=b"[" * 100_000 + b"]" * 100_000)
    with pytest.raises(AuthorizationError) as invalid:
        verify_contract(envelope, "snapshot", ring(key))
    assert invalid.value.reason == "statement-invalid"


def test_statement_size_is_limited_when_signing_and_verifying(tmp_path):
    values = fixture(tmp_path)
    key = values[8]
    big = values[4].model_copy(
        update={"revoked_tools": tuple(f"sha256:{n:064x}" for n in range(16_000))}
    )
    with pytest.raises(AuthorizationError) as refused:
        sign_contract(big, "trust", (key,))
    assert refused.value.reason == "statement-too-large"
    oversized = statement_envelope(key, None, raw=b" " * (MAX_STATEMENT_BYTES + 1))
    with pytest.raises(AuthorizationError) as too_large:
        verify_contract(oversized, "trust", ring(key))
    assert too_large.value.reason == "statement-too-large"


class ExternalSigner:
    """A signer whose private key never enters this process's key objects, like a KMS."""

    def __init__(self, broken=False):
        self._key = Ed25519PrivateKey.generate()
        self.broken = broken

    def sign(self, data: bytes) -> bytes:
        return bytes(64) if self.broken else self._key.sign(data)

    def public_key(self):
        return self._key.public_key()


def test_external_signers_can_sign_and_broken_ones_are_refused(tmp_path):
    values = fixture(tmp_path)
    signer = ExternalSigner()
    envelope = sign_contract(values[4], "trust", (signer,))
    assert verify_contract(envelope, "trust", ring(signer))[0] == values[4]
    with pytest.raises(AuthorizationError) as refused:
        sign_contract(values[4], "trust", (ExternalSigner(broken=True),))
    assert refused.value.reason == "configuration-invalid"


@pytest.mark.parametrize(
    ("kind", "index", "lifetime"),
    [
        ("snapshot", 3, timedelta(hours=25)),
        ("trust", 4, timedelta(hours=2)),
        ("approval", 5, timedelta(minutes=6)),
    ],
)
def test_contract_that_can_never_verify_is_not_signed(tmp_path, kind, index, lifetime):
    values = fixture(tmp_path)
    contract = values[index]
    longer = contract.model_copy(update={"not_after": contract.not_before + lifetime})
    with pytest.raises(AuthorizationError, match="can never verify") as refused:
        sign_contract(longer, kind, (values[6],))
    assert refused.value.reason == f"{kind}-lifetime-exceeds-policy"


@pytest.mark.parametrize(
    "identity",
    [
        "https://mail.example.test/mcp",
        "https://mail.example.test",
        "https://mail.example.test:8443/mcp/",
        "http://127.0.0.1:8080/mcp",
        "https://[::1]/mcp",
        "https://[fe80::1]/mcp",
        "https://mcp.0xample/mcp",
        "spiffe://acme.example/ns/prod/sa/mail",
        "stdio+launcher:sha256:" + "0" * 64,
    ],
)
def test_canonical_endpoint_identities_are_accepted(identity):
    assert ToolGrant(
        server_id="s",
        endpoint_identity=identity,
        tool_name="t",
        definition_digest="sha256:" + "0" * 64,
        actions=("a",),
        resources=("r",),
    )
    window = {"not_before": NOW, "not_after": NOW + timedelta(minutes=5)}
    assert TrustStatus(tenant="acme", serial=1, revoked_endpoints=(identity,), **window)


@pytest.mark.parametrize(
    "identity",
    [
        "https://mail.example.test/",
        "https://Mail.example.test/mcp",
        "HTTPS://mail.example.test/mcp",
        "https://mail.example.test:443/mcp",
        "https://user@mail.example.test/mcp",
        "https://mail.example.test/mcp?x=1",
        "https://mail.example.test/mcp#top",
        "https://mail.example.test/a/../mcp",
        "https://mail.example.test/%6Dcp",
        "mail.example.test/mcp",
        " https://mail.example.test/mcp",
        "stdio+launcher:SHA256:" + "0" * 64,
        "stdio+launcher:sha256:" + "A" * 64,
        "",
        # An IP address has one accepted spelling, the one ipaddress prints.
        "https://[0:0:0:0:0:0:0:1]/mcp",
        "https://[::0001]/mcp",
        "https://[::ffff:127.0.0.1]/mcp",
        "https://[127.0.0.1]/mcp",
        "https://127.000.000.001/mcp",
        "https://2130706433/mcp",
        "https://127.1/mcp",
        "https://0x7f.0.0.1/mcp",
        "https://mcp.example.0x1f/mcp",
    ],
)
def test_noncanonical_endpoint_identities_are_rejected_where_they_are_signed(identity):
    with pytest.raises(ValidationError, match="endpoint_identity"):
        ToolGrant(
            server_id="s",
            endpoint_identity=identity,
            tool_name="t",
            definition_digest="sha256:" + "0" * 64,
            actions=("a",),
            resources=("r",),
        )
    window = {"not_before": NOW, "not_after": NOW + timedelta(minutes=5)}
    with pytest.raises(ValidationError, match="revoked_endpoints"):
        TrustStatus(tenant="acme", serial=1, revoked_endpoints=(identity,), **window)


EXTENDED = {
    **DEFINITION,
    "title": "Send mail",
    "outputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
    "_meta": {"vendor": {"tier": 1}},
}


def grant_for(values, definition):
    values[3] = values[3].model_copy(
        update={
            "tools": (
                values[3]
                .tools[0]
                .model_copy(update={"definition_digest": tool_definition_digest(definition)}),
            )
        }
    )
    values[5] = values[5].model_copy(
        update={"snapshot_digest": digest(values[3].model_dump(mode="json"))}
    )


def serve(values, definition):
    endpoint = values[3].tools[0].endpoint_identity
    values[0].describe = lambda *_: ServedTool(endpoint_identity=endpoint, definition=definition)


def test_descriptor_with_title_output_schema_and_meta_is_admitted_when_bound(tmp_path):
    values = list(fixture(tmp_path))
    grant_for(values, EXTENDED)
    serve(values, EXTENDED)
    assert invoke(values) == "executed"


@pytest.mark.parametrize(
    "change",
    [
        {"title": "Send mail to anyone"},
        {"outputSchema": {"type": "object"}},
        {"_meta": {"vendor": {"tier": 2}}},
    ],
)
def test_changing_an_extended_descriptor_field_is_denied(tmp_path, change):
    values = list(fixture(tmp_path))
    grant_for(values, EXTENDED)
    serve(values, {**EXTENDED, **change})
    with pytest.raises(AuthorizationError) as denied:
        invoke(values)
    assert denied.value.reason == "descriptor-changed"
    assert values[-1] == []


def test_null_extended_fields_are_absent_and_base_fields_match_the_inventory_fingerprint():
    assert tool_definition_digest({**DEFINITION, "title": None}) == tool_definition_digest(
        DEFINITION
    )
    assert tool_definition_digest(DEFINITION) == hash_tool_definition(
        DEFINITION["name"], DEFINITION["description"], DEFINITION["inputSchema"]
    )
    annotated = {**DEFINITION, "annotations": {"readOnlyHint": True}}
    assert tool_definition_digest(annotated) == hash_tool_definition(
        "send", DEFINITION["description"], DEFINITION["inputSchema"], {"readOnlyHint": True}
    )
    # Once the inventory fingerprint takes the extended fields, both must agree.
    if {"title", "output_schema", "meta"} <= set(
        inspect.signature(hash_tool_definition).parameters
    ):
        assert tool_definition_digest(EXTENDED) == hash_tool_definition(
            "send",
            EXTENDED["description"],
            EXTENDED["inputSchema"],
            title=EXTENDED["title"],
            output_schema=EXTENDED["outputSchema"],
            meta=EXTENDED["_meta"],
        )


def test_lone_surrogate_in_a_served_descriptor_is_an_authorization_error(tmp_path):
    values = list(fixture(tmp_path))
    serve(values, json.loads('{"name": "send", "description": "\\ud800"}'))
    with pytest.raises(AuthorizationError) as denied:
        invoke(values)
    assert denied.value.reason == "descriptor-not-json"


def test_executor_receives_arguments_as_sent(tmp_path):
    values = list(fixture(tmp_path))
    autonomous(values)
    arguments = {"to": "team@example.test", "zeta": 1.0, "alpha": -0.0, "big": 1e20}
    values[1] = values[1].model_copy(update={"arguments": arguments})
    assert invoke(values, approval=None) == "executed"
    executed = values[-1][0].arguments
    assert list(executed) == ["to", "zeta", "alpha", "big"]
    assert [type(executed[key]) for key in ("zeta", "alpha", "big")] == [float, float, float]
    assert str(executed["alpha"]) == "-0.0"
    assert executed is not arguments


def test_executor_can_receive_the_form_the_approval_binds(tmp_path):
    values = list(fixture(tmp_path))
    autonomous(values)
    values[0] = values[0].bind_adapters(describe=values[0].describe, execute=values[0].execute)
    values[0].canonical_arguments = True
    arguments = {"to": "team@example.test", "zeta": 1.0, "alpha": -0.0, "big": 1e20}
    values[1] = values[1].model_copy(update={"arguments": arguments})
    assert invoke(values, approval=None) == "executed"
    executed = values[-1][0].arguments
    assert list(executed) == ["alpha", "big", "to", "zeta"]
    assert executed == {"alpha": 0, "big": 10**20, "to": "team@example.test", "zeta": 1}
    assert {type(executed[key]) for key in ("alpha", "big", "zeta")} == {int}


def test_canonical_arguments_is_a_gateway_option(tmp_path):
    gateway = fixture(tmp_path)[0]
    assert gateway.canonical_arguments is False
    options = {
        name: getattr(gateway, name)
        for name in (
            "snapshot_keys",
            "approval_keys",
            "trust_keys",
            "state",
            "authenticate",
            "describe",
            "resolve_scope",
            "execute",
        )
    }
    assert runtime.ReferenceGateway(**options, canonical_arguments=True).canonical_arguments


def test_request_digest_is_over_the_canonical_form():
    call = ToolCall(server_id="s", tool_name="t", action="a", resource="r", arguments={"x": 1.0})
    same = call.model_copy(update={"arguments": {"x": 1}})
    assert request_digest(call) == request_digest(same) == digest(call.model_dump(mode="json"))
    with pytest.raises(AuthorizationError) as out_of_range:
        request_digest(call.model_copy(update={"arguments": {"x": -(2**53)}}))
    assert out_of_range.value.reason == "arguments-number-out-of-range"


def test_oversized_companion_bom_is_refused_before_hashing(tmp_path, monkeypatch):
    values = list(fixture(tmp_path))
    monkeypatch.setattr(runtime, "MAX_BOM_NODES", 50)
    with pytest.raises(AuthorizationError) as denied:
        invoke(values, bom={"components": list(range(100))})
    assert denied.value.reason == "bom-too-large"
