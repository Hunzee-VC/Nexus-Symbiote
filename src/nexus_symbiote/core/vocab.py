"""Shared vocabularies: the single source of truth for scanner names and state strings.

Strings written by scanners and read by validators, the diff engine, and generators
must come from this module, so producers and consumers cannot drift apart.
"""

from __future__ import annotations

from typing import Final

# Registered scanner names. Each must match the ``name`` attribute of its scanner class.
SCANNER_NAMES: Final[tuple[str, ...]] = (
    "a2a",
    "ide_agents",
    "mcp",
    "model",
    "prompt",
    "rag",
    "registry",
    "shadowscan",
)

# Every built-in scanner is required for a complete claim. A scanner that is not run
# is recorded as "unknown", which keeps the claim partial and fails the gate.
REQUIRED_SCANNERS: Final[frozenset[str]] = frozenset(SCANNER_NAMES)

# Per-scanner outcomes recorded in CompletenessClaim.scanner_status.
SCANNER_COMPLETE: Final[str] = "complete"
SCANNER_PARTIAL: Final[str] = "partial"
SCANNER_FAILED: Final[str] = "failed"
SCANNER_UNKNOWN: Final[str] = "unknown"

# Signing evidence. Scanners only observe signature files, so the strongest value a
# scanner can report is "present but unverified". "signature-verified" is reserved for
# a result from utils.crypto that actually verified an identity, issuer and digest.
SIGNING_NOT_FOUND: Final[str] = "signature-not-found"
SIGNING_PRESENT_UNVERIFIED: Final[str] = "signature-present-unverified"
SIGNING_VERIFIED: Final[str] = "signature-verified"

# Higher rank means stronger evidence. The diff engine uses this to detect regressions.
SIGNING_RANK: Final[dict[str, int]] = {
    SIGNING_NOT_FOUND: 0,
    SIGNING_PRESENT_UNVERIFIED: 1,
    SIGNING_VERIFIED: 2,
}

# Spellings from older BOMs and other producers. None of them means "verified".
_LEGACY_SIGNING: Final[dict[str, str]] = {
    "unsigned": SIGNING_NOT_FOUND,
    "sigstore-signed": SIGNING_PRESENT_UNVERIFIED,
    "pgp-signed": SIGNING_PRESENT_UNVERIFIED,
}


def normalize_signing_status(value: str | None) -> str | None:
    """Map a stored signing status onto the current vocabulary. None stays None."""
    if value is None:
        return None
    key = value.strip().lower()
    return _LEGACY_SIGNING.get(key, key)


def signing_rank(value: str | None) -> int | None:
    """Evidence strength of a signing status.

    Returns None when no status is recorded. Unrecognised values rank as 0, which means
    no evidence.
    """
    if value is None:
        return None
    return SIGNING_RANK.get(normalize_signing_status(value) or "", 0)
