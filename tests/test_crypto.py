"""Tests for cryptographic utilities."""

from __future__ import annotations

import hashlib
import json
import sys

import pytest

from nexus_symbiote.utils.crypto import (
    DSSE_UNSUPPORTED,
    SIGSTORE_MISSING,
    compute_file_hash,
    verify_file_hash,
    verify_sigstore_bundle,
)


class TestVerifyFileHash:
    def test_correct_sha256(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()
        result = verify_file_hash(f, f"sha256:{expected}")
        assert result.verified is True

    def test_wrong_hash_fails(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"hello world")
        result = verify_file_hash(f, "sha256:0000000000000000000000000000000000000000")
        assert result.verified is False
        assert (
            "mismatch" in (result.error or "").lower()
            or "malformed" in (result.error or "").lower()
        )

    def test_bare_hash_with_explicit_algo(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        expected = hashlib.sha256(b"data").hexdigest()
        result = verify_file_hash(f, expected, algorithm="sha256")
        assert result.verified is True

    def test_unsupported_algorithm(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        result = verify_file_hash(f, "fakealgo:abc123")
        assert result.verified is False
        assert "unsupported" in (result.error or "").lower()

    def test_missing_file(self, tmp_path):
        result = verify_file_hash(tmp_path / "nonexistent", "sha256:abc")
        assert result.verified is False
        assert result.error is not None

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        result = verify_file_hash(f, f"sha256:{expected}")
        assert result.verified is True

    def test_sha512(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"test data")
        expected = hashlib.sha512(b"test data").hexdigest()
        result = verify_file_hash(f, expected, algorithm="sha512")
        assert result.verified is True


class TestComputeFileHash:
    def test_sha256_default(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"hello")
        result = compute_file_hash(f)
        assert result is not None
        assert result.startswith("sha256:")
        expected = hashlib.sha256(b"hello").hexdigest()
        assert result == f"sha256:{expected}"

    def test_sha512(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"hello")
        result = compute_file_hash(f, algorithm="sha512")
        assert result is not None
        assert result.startswith("sha512:")

    def test_missing_file_returns_none(self, tmp_path):
        result = compute_file_hash(tmp_path / "missing")
        assert result is None

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        result = compute_file_hash(f)
        assert result is not None


class TestVerifySigstoreBundle:
    def test_sigstore_not_installed_graceful(self, tmp_path, monkeypatch):
        artifact = tmp_path / "artifact.bin"
        bundle = tmp_path / "artifact.sigstore.json"
        artifact.write_bytes(b"data")
        bundle.write_text("{}")
        for module in ("sigstore", "sigstore.models", "sigstore.verify", "sigstore_models"):
            monkeypatch.setitem(sys.modules, module, None)
        result = verify_sigstore_bundle(
            artifact, bundle, "publisher@example.test", "https://issuer.example.test"
        )
        assert result.verified is False
        assert result.error == SIGSTORE_MISSING

    def test_dsse_bundle_is_refused_with_its_own_reason(self, tmp_path, monkeypatch):
        artifact = tmp_path / "model.safetensors"
        bundle = tmp_path / "model.sig"
        artifact.write_bytes(b"data")
        bundle.write_text(
            json.dumps(
                {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "verificationMaterial": {},
                    "dsseEnvelope": {"payload": "", "payloadType": "application/vnd.in-toto+json"},
                }
            )
        )
        for module in ("sigstore", "sigstore.models", "sigstore.verify", "sigstore_models"):
            monkeypatch.setitem(sys.modules, module, None)
        result = verify_sigstore_bundle(
            artifact, bundle, "publisher@example.test", "https://issuer.example.test"
        )
        assert not result.verified
        assert result.error == DSSE_UNSUPPORTED


@pytest.mark.parametrize(
    ("identity", "issuer"), [(None, None), ("publisher", None), (None, "issuer"), (" ", "issuer")]
)
def test_missing_trust_policy_is_rejected_before_verification(tmp_path, identity, issuer):
    result = verify_sigstore_bundle(
        tmp_path / "missing", tmp_path / "missing.bundle", identity, issuer
    )
    assert not result.verified
    assert result.identity is None
    assert "required" in result.error


def test_conflicting_or_weak_hash_algorithms_are_rejected(tmp_path):
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"data")
    for expected, algorithm in [("sha512:" + "a" * 128, "sha256"), ("a" * 40, "sha1")]:
        result = verify_file_hash(artifact, expected, algorithm)
        assert not result.verified


@pytest.fixture
def local_signed_bundle(tmp_path, monkeypatch):
    """Genuine local ECDSA bytes with Sigstore's actual artifact verifier.

    Certificate-chain and transparency-log authentication are mocked boundaries;
    this fixture is not proof of complete public Sigstore provenance. The real
    Sigstore code verifies Identity/OIDC policy, signature and Rekor consistency.
    No network, Fulcio identity or public signing service is involved.
    """
    pytest.importorskip("sigstore")
    from datetime import UTC, datetime, timedelta
    from types import SimpleNamespace

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    from cryptography.x509.oid import NameOID, ObjectIdentifier
    from sigstore.hashes import Hashed
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify.verifier import _hashedrekord_from_parts
    from sigstore_models.common.v1 import HashAlgorithm

    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"genuinely signed local artifact")
    identity, issuer = "publisher@example.test", "https://issuer.example.test"
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local-test-only")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(minutes=10))
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(identity)]), critical=False)
        .add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.57264.1.1"), issuer.encode()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    digest = hashlib.sha256(artifact.read_bytes()).digest()
    signature = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    hashed = Hashed(algorithm=HashAlgorithm.SHA2_256, digest=digest)
    record = _hashedrekord_from_parts(cert, signature, hashed)
    body = record.model_dump_json(by_alias=True).encode()
    bundle = SimpleNamespace(
        signing_certificate=cert,
        _inner=SimpleNamespace(
            message_signature=SimpleNamespace(signature=signature, message_digest=None)
        ),
        log_entry=SimpleNamespace(
            _inner=SimpleNamespace(
                kind_version=SimpleNamespace(kind="hashedrekord", version="0.0.1"),
                canonicalized_body=body,
            ),
        ),
    )
    verifier = object.__new__(Verifier)
    monkeypatch.setattr(
        verifier, "_verify_common_signing_cert", lambda b, p: p.verify(b.signing_certificate)
    )
    monkeypatch.setattr(Verifier, "production", classmethod(lambda cls, **kwargs: verifier))
    monkeypatch.setattr(Bundle, "from_json", classmethod(lambda cls, raw: bundle))
    bundle_path = tmp_path / "artifact.bundle.json"
    bundle_path.write_text("{}")
    return artifact, bundle_path, identity, issuer


def test_supported_sigstore_api_verifies_genuine_local_signature(local_signed_bundle):
    artifact, bundle, identity, issuer = local_signed_bundle
    result = verify_sigstore_bundle(artifact, bundle, identity, issuer)
    assert result.verified
    assert result.identity == identity
    assert result.issuer == issuer
    assert (
        result.details["artifact_digest"]
        == "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    )


@pytest.mark.parametrize("change", ["artifact", "identity", "issuer"])
def test_actual_verifier_rejects_changed_artifact_or_signer(local_signed_bundle, change):
    artifact, bundle, identity, issuer = local_signed_bundle
    if change == "artifact":
        artifact.write_bytes(b"tampered artifact")
    elif change == "identity":
        identity = "attacker@example.test"
    else:
        issuer = "https://attacker.example.test"
    result = verify_sigstore_bundle(artifact, bundle, identity, issuer)
    assert not result.verified
    assert result.identity is None
    assert result.error is not None


def test_file_hash_refuses_parent_symlink_and_special_file(tmp_path):
    from nexus_symbiote.utils.crypto import compute_file_hash

    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "artifact").write_bytes(b"private")
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    assert compute_file_hash(linked / "artifact") is None
    assert compute_file_hash(actual) is None


def test_actual_sigstore_parser_rejects_invalid_bundle_before_network(tmp_path, monkeypatch):
    pytest.importorskip("sigstore")
    from sigstore.verify import Verifier

    def unexpected_network_setup(cls, **kwargs):
        pytest.fail("An invalid bundle must be rejected before verifier setup")

    monkeypatch.setattr(Verifier, "production", classmethod(unexpected_network_setup))
    artifact = tmp_path / "artifact"
    bundle = tmp_path / "bundle"
    artifact.write_bytes(b"data")
    bundle.write_text("{}")
    result = verify_sigstore_bundle(
        artifact, bundle, "publisher@example.test", "https://issuer.example.test"
    )
    assert not result.verified
    assert result.identity is None


def test_actual_verifier_rejects_corrupt_signature(local_signed_bundle):
    from sigstore.models import Bundle

    artifact, bundle_path, identity, issuer = local_signed_bundle
    bundle = Bundle.from_json("{}")
    bundle._inner.message_signature.signature = b"corrupt signature"
    result = verify_sigstore_bundle(artifact, bundle_path, identity, issuer)
    assert not result.verified
    assert result.identity is None
