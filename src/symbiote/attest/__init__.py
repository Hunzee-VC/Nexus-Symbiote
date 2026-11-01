"""Attestation: in-toto statements, DSSE envelopes, key-based signing and verification (``spec/attestation.md``)."""

from __future__ import annotations

from symbiote.attest.dsse import (
    Envelope,
    KeyRing,
    Signature,
    generate_signing_key,
    key_id,
    load_private_key,
    load_public_key,
    pae,
    sign_envelope,
    verify_envelope,
)
from symbiote.attest.statements import (
    PAYLOAD_TYPE,
    PREDICATE_BASE,
    STATEMENT_TYPE,
    predicate_type,
    snapshot_predicate,
    snapshot_statement,
    statement,
    subject,
    toolset_predicate,
    toolset_statement,
    trust_status_statement,
)

__all__ = [
    "PAYLOAD_TYPE",
    "PREDICATE_BASE",
    "STATEMENT_TYPE",
    "Envelope",
    "KeyRing",
    "Signature",
    "generate_signing_key",
    "key_id",
    "load_private_key",
    "load_public_key",
    "pae",
    "predicate_type",
    "sign_envelope",
    "snapshot_predicate",
    "snapshot_statement",
    "statement",
    "subject",
    "toolset_predicate",
    "toolset_statement",
    "trust_status_statement",
    "verify_envelope",
]
