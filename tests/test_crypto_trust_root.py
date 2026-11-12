"""Tests for the Sigstore trust-root cache check and explicit trust-root override.

The cache tests point XDG_CACHE_HOME at tmp_path so they never touch the real
user cache. The verifier itself is stubbed at the sigstore boundary, mirroring
tests/test_crypto.py: only the cache/override handling is exercised here, not
real Sigstore provenance.
"""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.utils import crypto
from nexus_symbiote.utils.crypto import (
    TRUST_ROOT_ENV,
    TRUST_ROOT_SHA256_ENV,
    _prepare_sigstore_cache,
    _resolve_explicit_trust_root,
    verify_sigstore_bundle,
    verify_sigstore_digest,
)

IDENTITY = "publisher@example.test"
ISSUER = "https://issuer.example.test"


@pytest.fixture
def private_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the sigstore cache at a fresh tmp directory."""
    cache = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.delenv(TRUST_ROOT_ENV, raising=False)
    monkeypatch.delenv(TRUST_ROOT_SHA256_ENV, raising=False)
    return cache


@pytest.fixture
def stub_verifier(monkeypatch: pytest.MonkeyPatch) -> list:
    """Stub Bundle parsing and Verifier.production; record verify_artifact calls."""
    pytest.importorskip("sigstore")
    from sigstore.models import Bundle
    from sigstore.verify import Verifier

    calls: list = []

    class StubVerifier:
        def verify_artifact(self, hashed: object, bundle: object, policy: object) -> None:
            calls.append((hashed, bundle, policy))

    monkeypatch.setattr(Bundle, "from_json", classmethod(lambda cls, raw: object()))
    monkeypatch.setattr(Verifier, "production", classmethod(lambda cls, **kwargs: StubVerifier()))
    return calls


def _expected_cache_path(cache: Path) -> Path:
    from sigstore._internal.tuf import DEFAULT_TUF_URL, _get_dirs

    _metadata_dir, targets_dir = _get_dirs(DEFAULT_TUF_URL)
    return targets_dir / "trusted_root.json"


def test_missing_cache_dir_is_created_private_and_passes(
    private_cache: Path, stub_verifier: list
) -> None:
    path, error = _prepare_sigstore_cache()
    assert error is None
    assert path is not None
    assert path == _expected_cache_path(private_cache)
    targets = path.parent
    assert stat.S_IMODE(targets.stat().st_mode) == 0o700
    assert stat.S_IMODE(targets.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(targets.parent.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(private_cache.stat().st_mode) == 0o700
    result = verify_sigstore_digest("0" * 64, b"{}", IDENTITY, ISSUER)
    assert result.verified
    assert result.details is not None
    assert result.details["trust_root_path"] == str(path)
    assert result.details["trust_root_source"] == "cache"
    assert len(stub_verifier) == 1


def test_group_writable_cache_dir_fails_closed(private_cache: Path, stub_verifier: list) -> None:
    path, error = _prepare_sigstore_cache()
    assert error is None and path is not None
    path.parent.chmod(0o775)  # the insecure fixture under test
    failed_path, failed_error = _prepare_sigstore_cache()
    assert failed_path is None
    assert failed_error is not None
    assert "group/world-writable" in failed_error
    result = verify_sigstore_digest("0" * 64, b"{}", IDENTITY, ISSUER)
    assert not result.verified
    assert result.error is not None
    assert "group/world-writable" in result.error
    assert stub_verifier == []


def test_world_writable_trusted_root_file_fails_closed(
    private_cache: Path, stub_verifier: list
) -> None:
    path, error = _prepare_sigstore_cache()
    assert error is None and path is not None
    # The file is only dangerous when someone else can reach it, so make the
    # targets directory traversable first; a private directory is covered by
    # test_group_writable_root_in_private_dir_passes.
    path.parent.chmod(0o755)  # the traversable directory under test
    path.write_bytes(b"planted root")
    path.chmod(0o666)  # the insecure fixture under test
    failed_path, failed_error = _prepare_sigstore_cache()
    assert failed_path is None
    assert failed_error is not None
    assert "group/world-writable" in failed_error
    assert not verify_sigstore_digest("0" * 64, b"{}", IDENTITY, ISSUER).verified
    assert stub_verifier == []


def test_group_writable_root_in_private_dir_passes(
    private_cache: Path, stub_verifier: list
) -> None:
    # Regression: sigstore-python seeds trusted_root.json with the ambient
    # umask, so under umask 002/007 the file is group-writable. The private
    # directory the CLI creates (mode 0700) is what protects it, so a second
    # verification in the same cache must still pass.
    path, error = _prepare_sigstore_cache()
    assert error is None and path is not None
    path.write_bytes(b"seeded root")
    path.chmod(0o660)
    again_path, again_error = _prepare_sigstore_cache()
    assert again_error is None
    assert again_path == path
    result = verify_sigstore_digest("0" * 64, b"{}", IDENTITY, ISSUER)
    assert result.verified
    assert len(stub_verifier) == 1


def test_symlinked_cache_dir_fails_closed(private_cache: Path) -> None:
    path, error = _prepare_sigstore_cache()
    assert error is None and path is not None
    real = private_cache / "elsewhere"
    real.mkdir()
    path.parent.rmdir()
    path.parent.symlink_to(real, target_is_directory=True)
    failed_path, failed_error = _prepare_sigstore_cache()
    assert failed_path is None
    assert failed_error is not None
    assert "symlink" in failed_error


def test_symlinked_trusted_root_file_fails_closed(private_cache: Path) -> None:
    path, error = _prepare_sigstore_cache()
    assert error is None and path is not None
    planted = private_cache / "planted.json"
    planted.write_bytes(b"planted root")
    path.symlink_to(planted)
    failed_path, failed_error = _prepare_sigstore_cache()
    assert failed_path is None
    assert failed_error is not None
    assert "symlink" in failed_error


def test_foreign_owned_cache_dir_fails_closed(
    private_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nexus_symbiote.utils import crypto

    path, error = _prepare_sigstore_cache()
    assert error is None and path is not None
    monkeypatch.setattr(crypto, "_current_uid", lambda: 12345)
    failed_path, failed_error = _prepare_sigstore_cache()
    assert failed_path is None
    assert failed_error is not None
    assert "not owned by the current user" in failed_error


def test_explicit_trust_root_flag_is_honoured(
    private_cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("sigstore")
    from sigstore.models import Bundle
    from sigstore.verify import Verifier

    root = tmp_path / "trusted_root.json"
    root.write_bytes(b"operator trust root")
    root.chmod(0o600)
    calls: list = []
    sentinel = object()

    class FakeVerifier:
        def __init__(self, *, trusted_root: object) -> None:
            calls.append(trusted_root)

        def verify_artifact(self, hashed: object, bundle: object, policy: object) -> None:
            calls.append("verified")

    monkeypatch.setattr(Bundle, "from_json", classmethod(lambda cls, raw: object()))
    monkeypatch.setattr(
        crypto,
        "_trusted_root_from_bytes",
        lambda content: sentinel if content == root.read_bytes() else None,
    )
    monkeypatch.setattr(Verifier, "__init__", FakeVerifier.__init__)
    monkeypatch.setattr(Verifier, "verify_artifact", FakeVerifier.verify_artifact)
    result = verify_sigstore_digest("0" * 64, b"{}", IDENTITY, ISSUER, trust_root=str(root))
    assert result.verified
    assert result.details is not None
    assert result.details["trust_root_path"] == str(root)
    assert result.details["trust_root_source"] == "flag"
    assert calls == [sentinel, "verified"]


def test_explicit_trust_root_directory_resolves_to_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root_dir = tmp_path / "root-dir"
    root_dir.mkdir()
    root_dir.chmod(0o700)  # Plain mkdir follows the ambient umask, which may be group-writable.
    (root_dir / "trusted_root.json").write_bytes(b"operator trust root")
    (root_dir / "trusted_root.json").chmod(0o600)
    path, source, error = _resolve_explicit_trust_root(root_dir, None)
    assert error is None
    assert path == root_dir / "trusted_root.json"
    assert source == "flag"


def test_explicit_trust_root_env_var_is_honoured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "trusted_root.json"
    root.write_bytes(b"operator trust root")
    root.chmod(0o600)
    monkeypatch.setenv(TRUST_ROOT_ENV, str(root))
    path, source, error = _resolve_explicit_trust_root(None, None)
    assert error is None
    assert path == root
    assert source == "environment"


def test_flag_beats_env_for_trust_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_root = tmp_path / "env.json"
    flag_root = tmp_path / "flag.json"
    for candidate in (env_root, flag_root):
        candidate.write_bytes(b"operator trust root")
        candidate.chmod(0o600)
    monkeypatch.setenv(TRUST_ROOT_ENV, str(env_root))
    path, source, error = _resolve_explicit_trust_root(str(flag_root), None)
    assert error is None
    assert path == flag_root
    assert source == "flag"


def test_explicit_trust_root_pinned_hash(tmp_path: Path) -> None:
    root = tmp_path / "trusted_root.json"
    content = b"operator trust root"
    root.write_bytes(content)
    root.chmod(0o664)  # A pinned hash excuses permissive modes: content is pinned.
    digest = hashlib.sha256(content).hexdigest()
    path, source, error = _resolve_explicit_trust_root(str(root), f"sha256:{digest}")
    assert error is None
    assert path == root
    assert source == "flag"
    bad_path, _bad_source, bad_error = _resolve_explicit_trust_root(str(root), "sha256:" + "0" * 64)
    assert bad_path is None
    assert bad_error is not None
    assert "pinned SHA-256" in bad_error
    malformed_path, _malformed_source, malformed_error = _resolve_explicit_trust_root(
        str(root), "not-a-digest"
    )
    assert malformed_path is None
    assert malformed_error is not None
    assert "SHA-256" in malformed_error


def test_pinned_hash_without_a_trust_root_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(TRUST_ROOT_SHA256_ENV, "sha256:" + "0" * 64)
    path, _source, error = _resolve_explicit_trust_root(None, None)
    assert path is None
    assert error is not None
    assert "without a trust root" in error


def test_explicit_trust_root_requires_a_private_file(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o755)  # the traversable directory under test
    root = parent / "trusted_root.json"
    root.write_bytes(b"operator trust root")
    root.chmod(0o664)
    path, _source, error = _resolve_explicit_trust_root(str(root), None)
    assert path is None
    assert error is not None
    assert "group/world-writable" in error


def test_explicit_trust_root_group_writable_file_in_private_dir_passes(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "private"
    parent.mkdir()
    parent.chmod(0o700)  # Nobody else can traverse to the file.
    root = parent / "trusted_root.json"
    root.write_bytes(b"operator trust root")
    root.chmod(0o664)
    path, _source, error = _resolve_explicit_trust_root(str(root), None)
    assert error is None
    assert path == root


def test_explicit_trust_root_symlink_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_bytes(b"operator trust root")
    link = tmp_path / "trusted_root.json"
    link.symlink_to(real)
    path, _source, error = _resolve_explicit_trust_root(str(link), None)
    assert path is None
    assert error is not None
    assert "symlink" in error


def test_explicit_trust_root_group_writable_parent_is_rejected(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    root = parent / "trusted_root.json"
    root.write_bytes(b"operator trust root")
    root.chmod(0o600)
    parent.chmod(0o775)  # the insecure fixture under test
    path, _source, error = _resolve_explicit_trust_root(str(root), None)
    assert path is None
    assert error is not None
    assert "group/world-writable" in error


def test_verify_bundle_reports_trust_root_path(
    private_cache: Path, tmp_path: Path, stub_verifier: list
) -> None:
    artifact = tmp_path / "artifact.bin"
    bundle = tmp_path / "artifact.sigstore.json"
    artifact.write_bytes(b"data")
    bundle.write_text("{}")
    result = verify_sigstore_bundle(artifact, bundle, IDENTITY, ISSUER)
    assert result.verified
    assert result.details is not None
    assert result.details["trust_root_path"] == str(_expected_cache_path(private_cache))
    assert result.details["trust_root_source"] == "cache"


def test_cli_verify_artifact_prints_trust_root(
    private_cache: Path, tmp_path: Path, stub_verifier: list
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifact = project / "artifact.bin"
    artifact.write_bytes(b"artifact bytes")
    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}")
    digest = "sha256:" + hashlib.sha256(b"artifact bytes").hexdigest()
    result = CliRunner().invoke(
        main,
        [
            "verify-artifact",
            str(artifact),
            "--project",
            str(project),
            "--sha256",
            digest,
            "--bundle",
            str(bundle),
            "--signer-identity",
            IDENTITY,
            "--issuer",
            ISSUER,
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Trust root: " + str(_expected_cache_path(private_cache)) in result.output


def test_cli_verify_discovery_prints_trust_root(
    private_cache: Path, tmp_path: Path, stub_verifier: list
) -> None:
    fixtures = Path(__file__).parent / "fixtures"
    report = fixtures / "shadowscan" / "code-report-0.1.4.json"
    bom_path = tmp_path / "bom.json"
    imported = CliRunner().invoke(
        main, ["import-shadowscan", str(report), "-o", str(bom_path), "--report-only"]
    )
    assert imported.exit_code == 0, imported.output
    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}")
    result = CliRunner().invoke(
        main,
        [
            "verify-discovery",
            str(bom_path),
            str(report),
            "--bundle",
            str(bundle),
            "--signer-identity",
            IDENTITY,
            "--issuer",
            ISSUER,
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Trust root: " + str(_expected_cache_path(private_cache)) in result.output


def test_cli_verify_artifact_trust_root_flag(
    private_cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("sigstore")
    from sigstore.models import Bundle
    from sigstore.verify import Verifier

    project = tmp_path / "project"
    project.mkdir()
    artifact = project / "artifact.bin"
    artifact.write_bytes(b"artifact bytes")
    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}")
    digest = "sha256:" + hashlib.sha256(b"artifact bytes").hexdigest()
    root = tmp_path / "trusted_root.json"
    content = b"operator trust root"
    root.write_bytes(content)
    root.chmod(0o600)
    sentinel = object()
    calls: list = []

    class FakeVerifier:
        def __init__(self, *, trusted_root: object) -> None:
            calls.append(trusted_root)

        def verify_artifact(self, hashed: object, bundle: object, policy: object) -> None:
            calls.append("verified")

    monkeypatch.setattr(Bundle, "from_json", classmethod(lambda cls, raw: object()))
    monkeypatch.setattr(
        crypto,
        "_trusted_root_from_bytes",
        lambda content: sentinel if content == root.read_bytes() else None,
    )
    monkeypatch.setattr(Verifier, "__init__", FakeVerifier.__init__)
    monkeypatch.setattr(Verifier, "verify_artifact", FakeVerifier.verify_artifact)
    result = CliRunner().invoke(
        main,
        [
            "verify-artifact",
            str(artifact),
            "--project",
            str(project),
            "--sha256",
            digest,
            "--bundle",
            str(bundle),
            "--signer-identity",
            IDENTITY,
            "--issuer",
            ISSUER,
            "--trust-root",
            str(root),
            "--trust-root-sha256",
            "sha256:" + hashlib.sha256(content).hexdigest(),
        ],
    )
    assert result.exit_code == 0, result.output
    assert f"Trust root: {root}" in result.output
    assert calls == [sentinel, "verified"]


def test_explicit_trust_root_symlinked_directory_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    real.chmod(0o700)
    (real / "trusted_root.json").write_bytes(b"operator trust root")
    (real / "trusted_root.json").chmod(0o600)
    link = tmp_path / "linked"
    link.symlink_to(real, target_is_directory=True)
    path, _source, error = _resolve_explicit_trust_root(str(link / "trusted_root.json"), None)
    assert path is None
    assert error is not None
    assert "symlink" in error


def test_explicit_trust_root_pinned_symlink_is_rejected(tmp_path: Path) -> None:
    content = b"operator trust root"
    real = tmp_path / "real.json"
    real.write_bytes(content)
    link = tmp_path / "trusted_root.json"
    link.symlink_to(real)
    digest = hashlib.sha256(content).hexdigest()
    path, _source, error = _resolve_explicit_trust_root(str(link), f"sha256:{digest}")
    assert path is None
    assert error == "Explicit Sigstore trust root does not match the pinned SHA-256"
