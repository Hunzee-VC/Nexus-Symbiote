"""DSSE v1 envelopes with key-based ECDSA P-256 / Ed25519 signatures (``spec/attestation.md §2``).

sigstore-python's envelope accepts exactly one signature and has no key-based path, so Symbiote carries its own
minimal, spec-exact implementation for air-gapped and multi-party signing. Keyless Sigstore signing lives in
``symbiote.attest.sigstore_backend`` (optional ``[sign]`` extra).
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pydantic import Field

from symbiote.model.base import SymbioteModel

PrivateKey = ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
PublicKey = ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding: ``DSSEv1 <len(type)> <type> <len(payload)> <payload>``."""
    pt = payload_type.encode("utf-8")
    return b" ".join([b"DSSEv1", str(len(pt)).encode(), pt, str(len(payload)).encode(), payload])


def key_id(public_key: PublicKey) -> str:
    """``sha256(SubjectPublicKeyInfo DER)`` as lowercase hex."""
    spki = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).hexdigest()


class Signature(SymbioteModel):
    keyid: str
    sig: str  # base64


class Envelope(SymbioteModel):
    payload_type: str = Field(alias="payloadType")
    payload: str  # base64
    signatures: list[Signature] = Field(default_factory=list)

    @property
    def payload_bytes(self) -> bytes:
        return base64.b64decode(self.payload)

    def to_json(self) -> dict[str, Any]:
        return {
            "payloadType": self.payload_type,
            "payload": self.payload,
            "signatures": [s.to_json_dict() for s in self.signatures],
        }


def _sign(private_key: PrivateKey, message: bytes) -> bytes:
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return private_key.sign(message)


def _verify(public_key: PublicKey, signature: bytes, message: bytes) -> bool:
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def sign_envelope(
    payload: bytes,
    payload_type: str,
    private_keys: list[PrivateKey] | PrivateKey,
    envelope: Envelope | None = None,
) -> Envelope:
    """Sign ``payload`` (or add signatures to an existing envelope over the same payload)."""
    keys = private_keys if isinstance(private_keys, list) else [private_keys]
    if envelope is not None:
        if envelope.payload_bytes != payload or envelope.payload_type != payload_type:
            raise ValueError("existing envelope carries a different payload")
        sigs = list(envelope.signatures)
    else:
        sigs = []
    message = pae(payload_type, payload)
    for key in keys:
        sigs.append(
            Signature(
                keyid=key_id(key.public_key()), sig=base64.b64encode(_sign(key, message)).decode("ascii")
            )
        )
    return Envelope(
        payloadType=payload_type, payload=base64.b64encode(payload).decode("ascii"), signatures=sigs
    )


class KeyRing:
    """Trusted public keys addressed by key id."""

    def __init__(self, keys: Mapping[str, PublicKey] | None = None) -> None:
        self._keys: dict[str, PublicKey] = dict(keys or {})

    @classmethod
    def from_public_keys(cls, keys: list[PublicKey]) -> KeyRing:
        return cls({key_id(k): k for k in keys})

    def add(self, key: PublicKey) -> str:
        kid = key_id(key)
        self._keys[kid] = key
        return kid

    def get(self, kid: str) -> PublicKey | None:
        return self._keys.get(kid)

    def __len__(self) -> int:
        return len(self._keys)


def verify_envelope(envelope: Envelope, keyring: KeyRing, *, threshold: int = 1) -> tuple[bytes, list[str]]:
    """Return ``(payload, accepted_keyids)``; raises ``InvalidSignature`` when fewer than ``threshold`` trusted signatures verify."""
    payload = envelope.payload_bytes
    message = pae(envelope.payload_type, payload)
    accepted: list[str] = []
    for sig in envelope.signatures:
        key = keyring.get(sig.keyid)
        if key is None:
            continue
        if _verify(key, base64.b64decode(sig.sig), message):
            accepted.append(sig.keyid)
    if len(accepted) < threshold:
        raise InvalidSignature(f"{len(accepted)} trusted signature(s) verified, {threshold} required")
    return payload, accepted


def generate_signing_key(kind: str = "ecdsa-p256") -> PrivateKey:
    if kind == "ecdsa-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(f"unsupported key kind {kind!r}")


def save_private_key(key: PrivateKey, path: Path, *, password: bytes | None = None) -> None:
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))


def save_public_key(key: PublicKey, path: Path) -> None:
    path.write_bytes(
        key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def load_private_key(path: Path, *, password: bytes | None = None) -> PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    if not isinstance(key, ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey):
        raise ValueError("only ECDSA P-256 and Ed25519 keys are supported")
    return key


def load_public_key(path: Path) -> PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey):
        raise ValueError("only ECDSA P-256 and Ed25519 keys are supported")
    return key


__all__ = [
    "Envelope",
    "KeyRing",
    "PrivateKey",
    "PublicKey",
    "Signature",
    "generate_signing_key",
    "key_id",
    "load_private_key",
    "load_public_key",
    "pae",
    "save_private_key",
    "save_public_key",
    "sign_envelope",
    "verify_envelope",
]
