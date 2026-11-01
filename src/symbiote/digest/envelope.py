"""Typed digest envelopes (``spec/digests.md §2``)."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from symbiote import BASE_URI
from symbiote.digest.jcs import UndigestableError, canonical_bytes
from symbiote.model.common import DigestResult
from symbiote.model.enums import DigestStatus

DIGEST_TYPE_BASE = f"{BASE_URI}digest/"


def type_uri(kind: str) -> str:
    """``https://aisecnomad.github.io/symbiote/digest/<kind>`` where ``kind`` is like ``tooldef/v1``."""
    return f"{DIGEST_TYPE_BASE}{kind}"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_str(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def strip_prefix(digest: str) -> str:
    return digest.split(":", 1)[1] if ":" in digest else digest


def envelope_bytes(kind: str, payload: Mapping[str, Any]) -> bytes:
    if "_type" in payload:
        raise UndigestableError("reserved-key", "_type")
    return canonical_bytes({"_type": type_uri(kind), **payload})


def envelope_digest(kind: str, payload: Mapping[str, Any]) -> DigestResult:
    """Digest ``payload`` under ``kind``; fail closed with an ``undigestable`` result (ADR-0004)."""
    try:
        return DigestResult(algorithm=kind, value=digest_str(envelope_bytes(kind, payload)))
    except UndigestableError as exc:
        return DigestResult(algorithm=kind, status=DigestStatus.UNDIGESTABLE, reason=str(exc))


__all__ = [
    "DIGEST_TYPE_BASE",
    "digest_str",
    "envelope_bytes",
    "envelope_digest",
    "sha256_hex",
    "strip_prefix",
    "type_uri",
]
