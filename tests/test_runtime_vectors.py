"""Known-answer vectors pin the runtime wire format and every digest an approval binds.

Both sides of each check are computed independently: digests with rfc8785 and hashlib
here, signatures with a DSSE pre-authentication encoding written out below. A change
to tests/vectors/runtime/contracts.json changes the wire format or a digest preimage,
so it requires a new predicate or profile version instead of regenerated vectors.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.runtime import (
    CONTRACTS,
    PREDICATES,
    Envelope,
    ExecutionContext,
    ToolCall,
    bom_digest,
    contract_digest,
    key_id,
    request_digest,
    sign_contract,
    tool_definition_digest,
    verify_contract,
)

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "runtime" / "contracts.json").read_text(encoding="utf-8")
)
KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTORS["key"]["seed_hex"]))
KINDS = ["snapshot", "approval", "trust", "model"]


def independent_digest(value):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def test_published_test_key_and_key_id():
    public = serialization.load_pem_public_key(VECTORS["key"]["public_key_pem"].encode())
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    assert public.public_bytes(*raw) == KEY.public_key().public_bytes(*raw)
    spki = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert hashlib.sha256(spki).hexdigest() == VECTORS["key"]["key_id"]
    assert key_id(KEY.public_key()) == VECTORS["key"]["key_id"]


@pytest.mark.parametrize("kind", KINDS)
def test_signing_reproduces_the_committed_envelope_byte_for_byte(kind):
    vector = VECTORS["contracts"][kind]
    contract = CONTRACTS[kind].model_validate(vector["predicate"])
    assert contract.model_dump(mode="json") == vector["predicate"]
    assert contract_digest(contract) == vector["digest"] == independent_digest(vector["predicate"])
    envelope = sign_contract(contract, kind, (KEY,))
    assert envelope.model_dump(mode="json", by_alias=True) == vector["envelope"]


@pytest.mark.parametrize("kind", KINDS)
def test_committed_envelope_verifies_independently_and_in_the_library(kind):
    vector = VECTORS["contracts"][kind]
    wire = vector["envelope"]
    assert wire["payloadType"] == "application/vnd.in-toto+json"
    payload = base64.b64decode(wire["payload"], validate=True)
    pae = b"DSSEv1 28 application/vnd.in-toto+json %d %s" % (len(payload), payload)
    [signature] = wire["signatures"]
    assert signature["keyid"] == VECTORS["key"]["key_id"]
    KEY.public_key().verify(base64.b64decode(signature["sig"], validate=True), pae)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": PREDICATES[kind],
        "subject": [{"name": kind, "digest": {"sha256": vector["digest"].split(":", 1)[1]}}],
        "predicate": vector["predicate"],
    }
    assert payload == rfc8785.dumps(statement)
    contract, accepted = verify_contract(
        Envelope.model_validate(wire), kind, {VECTORS["key"]["key_id"]: KEY.public_key()}
    )
    assert contract.model_dump(mode="json") == vector["predicate"]
    assert accepted == {VECTORS["key"]["key_id"]}


def test_approval_vector_binds_the_snapshot_context_and_request_vectors():
    approval = VECTORS["contracts"]["approval"]["predicate"]
    snapshot = VECTORS["contracts"]["snapshot"]["predicate"]
    context, request, bom = VECTORS["context"], VECTORS["request"], VECTORS["bom"]
    assert approval["snapshot_digest"] == VECTORS["contracts"]["snapshot"]["digest"]
    assert approval["context_digest"] == context["digest"] == independent_digest(context["value"])
    assert contract_digest(ExecutionContext.model_validate(context["value"])) == context["digest"]
    assert approval["request_digest"] == request["digest"] == independent_digest(request["value"])
    assert request_digest(ToolCall.model_validate(request["value"])) == request["digest"]
    assert snapshot["bom_digest"] == bom["digest"] == independent_digest(bom["value"])
    assert bom_digest(bom["value"]) == bom["digest"]
    grant = snapshot["tools"][0]
    assert grant["definition_digest"] == VECTORS["descriptors"][3]["digest"]


@pytest.mark.parametrize(
    "vector", VECTORS["descriptors"], ids=[str(n) for n in range(len(VECTORS["descriptors"]))]
)
def test_descriptor_digest_vectors(vector):
    definition = vector["definition"]
    # The rfc8785-jcs-v2 preimage, restated from docs/runtime-contract-reference.md.
    preimage = {
        "name": definition["name"],
        "description": definition.get("description", ""),
        "annotations": definition.get("annotations") or {},
    }
    for field in ("inputSchema", "title", "outputSchema", "_meta"):
        if definition.get(field) is not None:
            preimage[field] = definition[field]
    assert tool_definition_digest(definition) == vector["digest"] == independent_digest(preimage)
    assert vector["digest"] == hash_tool_definition(
        definition["name"],
        definition.get("description", ""),
        definition.get("inputSchema"),
        definition.get("annotations"),
        title=definition.get("title"),
        output_schema=definition.get("outputSchema"),
        meta=definition.get("_meta"),
    )
