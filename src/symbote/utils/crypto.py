"""Cryptographic verification utilities for model signing and file integrity.

Provides Sigstore bundle verification (when the sigstore extra is installed)
and standalone file-hash verification against known digests.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Outcome of a signature or hash verification."""

    verified: bool
    identity: str | None = None
    issuer: str | None = None
    error: str | None = None
    details: dict[str, Any] | None = None


def verify_file_hash(
    path: Path,
    expected_hash: str,
    algorithm: str | None = None,
) -> VerificationResult:
    """Verify a file's digest against an expected hash string.

    The expected_hash may be prefixed with the algorithm (e.g. "sha256:abcd...")
    or provided bare with an explicit algorithm argument.
    """
    if ":" in expected_hash and algorithm is None:
        algorithm, expected_digest = expected_hash.split(":", 1)
    else:
        algorithm = algorithm or "sha256"
        expected_digest = expected_hash

    try:
        h = hashlib.new(algorithm)
    except ValueError:
        return VerificationResult(
            verified=False,
            error=f"Unsupported hash algorithm: {algorithm}",
        )

    try:
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
    except OSError as e:
        return VerificationResult(verified=False, error=f"Failed to read file: {e}")

    actual_digest = h.hexdigest()
    if actual_digest == expected_digest:
        return VerificationResult(
            verified=True,
            details={"algorithm": algorithm, "digest": actual_digest},
        )
    return VerificationResult(
        verified=False,
        error=f"Hash mismatch: expected {expected_digest[:16]}..., got {actual_digest[:16]}...",
        details={
            "algorithm": algorithm,
            "expected": expected_digest,
            "actual": actual_digest,
        },
    )


def verify_sigstore_bundle(
    artifact_path: Path,
    bundle_path: Path,
    expected_identity: str | None = None,
    expected_issuer: str | None = None,
) -> VerificationResult:
    """Verify a Sigstore bundle against an artifact.

    Requires the `sigstore` optional dependency. Returns a VerificationResult
    indicating whether the bundle's signature is valid and the signing identity
    matches expectations.
    """
    if not expected_identity or not expected_issuer:
        return VerificationResult(
            verified=False,
            error="A trusted signer identity and OIDC issuer are required for verification.",
        )

    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify import policy as sigstore_policy
    except ImportError:
        return VerificationResult(
            verified=False,
            error=("sigstore package not installed. Install with: pip install symbote[sigstore]"),
        )

    try:
        bundle = Bundle.from_json(bundle_path.read_text(encoding="utf-8"))
    except Exception as e:
        return VerificationResult(
            verified=False,
            error=f"Failed to parse Sigstore bundle: {e}",
        )

    try:
        verifier = Verifier.production()
    except Exception as e:
        return VerificationResult(
            verified=False,
            error=f"Failed to initialize Sigstore verifier: {e}",
        )

    identity_policy = sigstore_policy.Identity(
        identity=expected_identity,
        issuer=expected_issuer,
    )

    try:
        artifact_data = artifact_path.read_bytes()
        # In sigstore-python 3.x verify_artifact returns None on success and
        # raises on verification failure. Identity policy binds both fields.
        verifier.verify_artifact(artifact_data, bundle, identity_policy)
        return VerificationResult(
            verified=True,
            identity=expected_identity,
            issuer=expected_issuer,
            details={"bundle_path": str(bundle_path)},
        )
    except Exception as e:
        return VerificationResult(
            verified=False,
            error=f"Sigstore verification failed: {e}",
        )


def compute_file_hash(path: Path, algorithm: str = "sha256") -> str | None:
    """Compute a file's hash, returning None on failure."""
    try:
        h = hashlib.new(algorithm)
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return f"{algorithm}:{h.hexdigest()}"
    except (OSError, ValueError):
        return None


def verify_hash_consistency(hashes: dict[str, str], path: Path) -> list[VerificationResult]:
    """Verify all hashes in a component's hash dict against the actual file."""
    results = []
    for algo, expected in hashes.items():
        full_expected = expected if ":" in expected else f"{algo}:{expected}"
        results.append(verify_file_hash(path, full_expected))
    return results
