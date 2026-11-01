"""Cryptographic verification utilities for model signing and file integrity.

Provides Sigstore bundle verification (when the sigstore extra is installed)
and standalone file-hash verification against known digests.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from importlib import import_module
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


def verify_sigstore_digest(
    digest_hex: str,
    bundle_json: bytes,
    expected_identity: str,
    expected_issuer: str,
) -> VerificationResult:
    """Verify the SHA-256 of the bytes inspected under an operator's signer policy."""
    if not expected_identity or not expected_issuer:
        return VerificationResult(False, error="Both an expected identity and issuer are required")
    try:
        digest = bytes.fromhex(digest_hex.removeprefix("sha256:"))
        if len(digest) != hashlib.sha256().digest_size:
            raise ValueError("expected a SHA-256 digest")
        # Sigstore is an optional extra. Use its public v3 verification API.
        bundle = import_module("sigstore.models").Bundle.from_json(bundle_json)
        hashed = import_module("sigstore.hashes").Hashed(
            algorithm=import_module(
                "sigstore_protobuf_specs.dev.sigstore.common.v1"
            ).HashAlgorithm.SHA2_256,
            digest=digest,
        )
        policy = import_module("sigstore.verify.policy").Identity(
            identity=expected_identity, issuer=expected_issuer
        )
        verifier = import_module("sigstore.verify").Verifier.production(offline=True)
        verifier.verify_artifact(hashed, bundle, policy)
    except ImportError:
        return VerificationResult(False, error="Sigstore unavailable. Install nexus-symbiote[sigstore].")
    except Exception as exc:
        return VerificationResult(False, error=f"Sigstore verification failed: {exc}")
    return VerificationResult(True, identity=expected_identity, issuer=expected_issuer)


def verify_sigstore_bundle(
    artifact_path: Path,
    bundle_path: Path,
    expected_identity: str | None = None,
    expected_issuer: str | None = None,
) -> VerificationResult:
    """Bind a local artifact to a Sigstore bundle under an explicit signer policy."""
    if not expected_identity or not expected_issuer:
        return VerificationResult(False, error="Both an expected identity and issuer are required")
    try:
        with artifact_path.open("rb") as artifact:
            digest = hashlib.file_digest(artifact, "sha256").hexdigest()
        bundle = bundle_path.read_bytes()
    except OSError as exc:
        return VerificationResult(False, error=f"Cannot read verification input: {exc}")
    return verify_sigstore_digest(digest, bundle, expected_identity, expected_issuer)


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
