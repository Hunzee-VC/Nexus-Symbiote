"""Tests for cryptographic utilities."""

from __future__ import annotations

import hashlib

from symbote.utils.crypto import (
    compute_file_hash,
    verify_file_hash,
    verify_hash_consistency,
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
        assert "mismatch" in (result.error or "").lower()

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
        assert "read" in (result.error or "").lower() or "failed" in (result.error or "").lower()

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


class TestVerifyHashConsistency:
    def test_all_pass(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        sha256 = hashlib.sha256(b"data").hexdigest()
        sha512 = hashlib.sha512(b"data").hexdigest()
        results = verify_hash_consistency({"sha256": sha256, "sha512": sha512}, f)
        assert len(results) == 2
        assert all(r.verified for r in results)

    def test_partial_failure(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        sha256 = hashlib.sha256(b"data").hexdigest()
        results = verify_hash_consistency({"sha256": sha256, "sha512": "wrong"}, f)
        assert len(results) == 2
        passed = [r for r in results if r.verified]
        failed = [r for r in results if not r.verified]
        assert len(passed) == 1
        assert len(failed) == 1


class TestVerifySigstoreBundle:
    def test_sigstore_not_installed_graceful(self, tmp_path):
        artifact = tmp_path / "artifact.bin"
        bundle = tmp_path / "artifact.sigstore.json"
        artifact.write_bytes(b"data")
        bundle.write_text("{}")
        result = verify_sigstore_bundle(artifact, bundle)
        assert result.verified is False
        assert "expected identity and issuer" in result.error
        assert not verify_sigstore_bundle(artifact, bundle, "alice", "issuer").verified
