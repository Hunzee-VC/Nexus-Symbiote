"""Detached, key-signed attestations for inventory files.

An attestation is a DSSE envelope around an in-toto Statement v1 whose subject is
the SHA-256 of the exact file bytes. It shows that a holder of a trusted Ed25519 key
signed those bytes; it does not show that the inventory is complete or correct. The
wire format is the one runtime contracts use, with its own predicate type, so one
signature can never be read as the other.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, ValidationError, field_validator

from nexus_symbiote import __version__
from nexus_symbiote.runtime import (
    MAX_SIGNATURES,
    MAX_STATEMENT_BYTES,
    STATEMENT_TYPE,
    AuthorizationError,
    Contract,
    ContractSigner,
    Envelope,
    EnvelopeSignature,
    _accepted_signers,
    _aware,
    _pae,
    _validate_threshold,
    canonical_bytes,
    key_id,
    strict_json,
)

# Signed into attestations and matched by verifiers: a wire-format identifier in the
# namespace of the runtime predicates, not a link.
PREDICATE_TYPE = "https://github.com/aisecnomad/nexus-symbiote/attestation/inventory/v1"
MAX_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_SUBJECT_NAME_CHARS = 255


class InventoryAttestation(Contract):
    """What the signer states about the file: which tool wrote the statement, and when.

    ``signed_at`` is the signer's own clock, not a trusted timestamp.
    """

    version: Literal["1"] = "1"
    generator: Literal["nexus-symbiote"] = "nexus-symbiote"
    generator_version: str = Field(min_length=1, max_length=64)
    signed_at: datetime

    @field_validator("signed_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        return _aware(value)


def file_digest(content: bytes) -> str:
    """Lowercase hex SHA-256 of the exact bytes, as an in-toto subject records it."""
    if len(content) > MAX_INVENTORY_BYTES:
        raise AuthorizationError(
            "inventory exceeds the supported size", reason="json-budget-exceeded"
        )
    return hashlib.sha256(content).hexdigest()


def sign_inventory(
    content: bytes,
    keys: Sequence[ContractSigner],
    *,
    name: str = "inventory",
    now: datetime | None = None,
) -> Envelope:
    """Sign the SHA-256 of ``content``; ``name`` is a label that verification ignores."""
    if not keys or len(keys) > MAX_SIGNATURES:
        raise AuthorizationError("1 to 32 signing keys required", reason="configuration-invalid")
    if not name or len(name) > MAX_SUBJECT_NAME_CHARS:
        raise AuthorizationError("subject name is empty or too long", reason="statement-invalid")
    predicate = InventoryAttestation(
        generator_version=__version__, signed_at=now or datetime.now(UTC)
    )
    statement = {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATE_TYPE,
        "subject": [{"name": name, "digest": {"sha256": file_digest(content)}}],
        "predicate": predicate.model_dump(mode="json"),
    }
    payload = canonical_bytes(statement)
    message = _pae(payload)
    signatures = []
    for signer in keys:
        public = signer.public_key()
        raw = signer.sign(message)
        try:
            if not isinstance(public, Ed25519PublicKey):
                raise InvalidSignature
            public.verify(raw, message)
        except InvalidSignature as exc:
            raise AuthorizationError(
                "signer did not return a valid Ed25519 signature", reason="configuration-invalid"
            ) from exc
        signatures.append(
            EnvelopeSignature(key_id=key_id(public), signature=base64.b64encode(raw).decode())
        )
    return Envelope(payload=base64.b64encode(payload).decode(), signatures=tuple(signatures))


def verify_inventory(
    content: bytes,
    envelope: Envelope,
    trusted_keys: Mapping[str, Ed25519PublicKey],
    *,
    threshold: int = 1,
) -> tuple[InventoryAttestation, set[str]]:
    """Return the statement and the trusted key IDs that signed exactly these bytes.

    Signatures are checked before the payload is parsed, and the subject is matched
    by digest only: its name is the signer's label.
    """
    _validate_threshold(threshold)
    if not trusted_keys:
        raise AuthorizationError("trusted keys required", reason="configuration-invalid")
    try:
        payload = base64.b64decode(envelope.payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuthorizationError(
            "envelope payload is not base64", reason="envelope-invalid"
        ) from exc
    if len(payload) > MAX_STATEMENT_BYTES:
        raise AuthorizationError("statement exceeds limit", reason="statement-too-large")
    accepted = _accepted_signers(envelope, payload, trusted_keys)
    if len(accepted) < threshold:
        raise AuthorizationError(
            "insufficient distinct trusted signers", reason="signers-insufficient"
        )
    try:
        statement = strict_json(payload)
    except AuthorizationError as exc:
        raise AuthorizationError("invalid in-toto statement", reason="statement-invalid") from exc
    if not isinstance(statement, dict) or set(statement) != {
        "_type",
        "predicateType",
        "subject",
        "predicate",
    }:
        raise AuthorizationError("invalid in-toto statement", reason="statement-invalid")
    if statement["_type"] != STATEMENT_TYPE or statement["predicateType"] != PREDICATE_TYPE:
        raise AuthorizationError("statement purpose mismatch", reason="statement-purpose-mismatch")
    try:
        attestation = InventoryAttestation.model_validate(statement["predicate"])
    except ValidationError as exc:
        raise AuthorizationError(
            "attestation predicate does not validate", reason="contract-invalid"
        ) from exc
    if not _names_digest(statement["subject"], file_digest(content)):
        raise AuthorizationError("subject digest mismatch", reason="subject-mismatch")
    return attestation, accepted


def _names_digest(subject: Any, expected: str) -> bool:
    if not isinstance(subject, list) or len(subject) != 1 or not isinstance(subject[0], dict):
        return False
    digests = subject[0].get("digest")
    recorded = digests.get("sha256") if isinstance(digests, dict) else None
    return isinstance(recorded, str) and hmac.compare_digest(recorded, expected)
