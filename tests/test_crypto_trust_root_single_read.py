"""The explicit trust root is checked and loaded from one read of one descriptor.

Each test swaps the trust-root path to different, valid trust-root bytes as soon
as the first descriptor that read it is closed, the way a concurrent writer could
rename a file over it between the check and sigstore's load.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.utils.crypto import (
    TRUST_ROOT_ENV,
    TRUST_ROOT_SHA256_ENV,
    verify_sigstore_digest,
)

IDENTITY = "publisher@example.test"
ISSUER = "https://issuer.example.test"


def _trust_roots() -> tuple[bytes, bytes]:
    from sigstore._internal.tuf import DEFAULT_TUF_URL
    from sigstore._utils import read_embedded

    pinned = read_embedded("trusted_root.json", DEFAULT_TUF_URL)
    document = json.loads(pinned)
    document["tlogs"] = document["tlogs"][:1]
    document["ctlogs"] = []
    planted = json.dumps(document).encode()
    assert planted != pinned
    return pinned, planted


def _swap_after_first_read(
    monkeypatch: pytest.MonkeyPatch, root: Path, planted: bytes
) -> list[bool]:
    swapped: list[bool] = []
    real_fdopen = os.fdopen

    def fdopen(fd: int, *args: Any, **kwargs: Any) -> Any:
        stream = real_fdopen(fd, *args, **kwargs)
        info = os.fstat(fd)
        target = os.stat(root, follow_symlinks=False)
        if swapped or (info.st_dev, info.st_ino) != (target.st_dev, target.st_ino):
            return stream
        real_close = stream.close

        def close() -> None:
            real_close()
            if not swapped:
                swapped.append(True)
                replacement = root.with_name(root.name + ".planted")
                replacement.write_bytes(planted)
                replacement.chmod(0o600)
                os.replace(replacement, root)

        stream.close = close
        return stream

    monkeypatch.setattr(os, "fdopen", fdopen)
    return swapped


def _capture_verifier(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    from sigstore.models import Bundle
    from sigstore.verify import Verifier

    loaded: list[Any] = []

    def init(self: Any, *, trusted_root: Any) -> None:
        loaded.append(trusted_root)

    monkeypatch.setattr(Bundle, "from_json", classmethod(lambda cls, raw: object()))
    monkeypatch.setattr(Verifier, "__init__", init)
    monkeypatch.setattr(Verifier, "verify_artifact", lambda self, *args: None)
    return loaded


@pytest.mark.parametrize("pinned_hash", [True, False])
def test_trust_root_replaced_after_check_is_not_loaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pinned_hash: bool
) -> None:
    pytest.importorskip("sigstore")
    from sigstore_models.trustroot import v1 as trustroot_v1

    monkeypatch.delenv(TRUST_ROOT_ENV, raising=False)
    monkeypatch.delenv(TRUST_ROOT_SHA256_ENV, raising=False)
    pinned, planted = _trust_roots()
    directory = tmp_path / "roots"
    directory.mkdir()
    directory.chmod(0o700)
    root = directory / "trusted_root.json"
    root.write_bytes(pinned)
    root.chmod(0o600)
    loaded = _capture_verifier(monkeypatch)
    swapped = _swap_after_first_read(monkeypatch, root, planted)
    digest = f"sha256:{hashlib.sha256(pinned).hexdigest()}" if pinned_hash else None
    if not pinned_hash:
        # The unpinned check reads ownership and mode; trigger the swap from it too.
        real_lstat = os.lstat

        def lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            result = real_lstat(path, *args, **kwargs)
            if Path(path) == root and not swapped:
                swapped.append(True)
                replacement = root.with_name(root.name + ".planted")
                replacement.write_bytes(planted)
                replacement.chmod(0o600)
                os.replace(replacement, root)
            return result

        monkeypatch.setattr(os, "lstat", lstat)

    result = verify_sigstore_digest(
        "0" * 64, b"{}", IDENTITY, ISSUER, trust_root=str(root), trust_root_sha256=digest
    )

    assert swapped, "the simulated replacement never ran"
    if result.verified:
        assert len(loaded) == 1
        assert loaded[0]._inner == trustroot_v1.TrustedRoot.from_json(pinned)
    else:
        assert loaded == []


def test_trust_root_is_loaded_from_the_checked_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("sigstore")
    from sigstore.models import TrustedRoot
    from sigstore_models.trustroot import v1 as trustroot_v1

    monkeypatch.delenv(TRUST_ROOT_ENV, raising=False)
    monkeypatch.delenv(TRUST_ROOT_SHA256_ENV, raising=False)
    pinned, _planted = _trust_roots()
    root = tmp_path / "trusted_root.json"
    root.write_bytes(pinned)
    root.chmod(0o644)
    loaded = _capture_verifier(monkeypatch)

    def refuse(cls: Any, path: str) -> Any:
        raise AssertionError("the trust root must not be re-read by path")

    monkeypatch.setattr(TrustedRoot, "from_file", classmethod(refuse))
    result = verify_sigstore_digest(
        "0" * 64,
        b"{}",
        IDENTITY,
        ISSUER,
        trust_root=str(root),
        trust_root_sha256=f"sha256:{hashlib.sha256(pinned).hexdigest()}",
    )
    assert result.verified, result.error
    assert result.details is not None
    assert result.details["trust_root_path"] == str(root)
    assert loaded[0]._inner == trustroot_v1.TrustedRoot.from_json(pinned)


def test_oversized_trust_root_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("sigstore")
    from nexus_symbiote.utils import crypto

    monkeypatch.delenv(TRUST_ROOT_ENV, raising=False)
    monkeypatch.delenv(TRUST_ROOT_SHA256_ENV, raising=False)
    root = tmp_path / "trusted_root.json"
    content = b"x" * 64
    root.write_bytes(content)
    root.chmod(0o600)
    monkeypatch.setattr(crypto, "MAX_TRUST_ROOT_BYTES", 32, raising=False)
    loaded = _capture_verifier(monkeypatch)
    unpinned = verify_sigstore_digest("0" * 64, b"{}", IDENTITY, ISSUER, trust_root=str(root))
    assert not unpinned.verified
    assert unpinned.error is not None
    assert "byte limit" in unpinned.error
    pinned = verify_sigstore_digest(
        "0" * 64,
        b"{}",
        IDENTITY,
        ISSUER,
        trust_root=str(root),
        trust_root_sha256=f"sha256:{hashlib.sha256(content).hexdigest()}",
    )
    assert not pinned.verified
    assert pinned.error == f"Explicit Sigstore trust root {root} exceeds the 32-byte limit"
    assert loaded == []


def test_cached_trust_root_replaced_after_check_is_not_loaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("sigstore")
    from sigstore._internal.tuf import DEFAULT_TUF_URL, _get_dirs
    from sigstore_models.trustroot import v1 as trustroot_v1

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.delenv(TRUST_ROOT_ENV, raising=False)
    monkeypatch.delenv(TRUST_ROOT_SHA256_ENV, raising=False)
    pinned, planted = _trust_roots()
    _metadata_dir, targets_dir = _get_dirs(DEFAULT_TUF_URL)
    targets_dir.mkdir(parents=True)
    for directory in (targets_dir, *targets_dir.parents):
        if directory == tmp_path / "cache":
            break
        directory.chmod(0o700)
    root = targets_dir / "trusted_root.json"
    root.write_bytes(pinned)
    root.chmod(0o600)
    loaded = _capture_verifier(monkeypatch)
    # Swap as soon as the last check of the file ends: a descriptor read, or an lstat.
    swapped = _swap_after_first_read(monkeypatch, root, planted)
    real_lstat = os.lstat

    def lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        result = real_lstat(path, *args, **kwargs)
        if Path(path) == root and not swapped:
            swapped.append(True)
            replacement = root.with_name(root.name + ".planted")
            replacement.write_bytes(planted)
            replacement.chmod(0o600)
            os.replace(replacement, root)
        return result

    monkeypatch.setattr(os, "lstat", lstat)

    result = verify_sigstore_digest("0" * 64, b"{}", IDENTITY, ISSUER)

    assert swapped, "the simulated replacement never ran"
    if result.verified:
        assert result.details is not None
        assert result.details["trust_root_source"] == "cache"
        assert len(loaded) == 1
        assert loaded[0]._inner == trustroot_v1.TrustedRoot.from_json(pinned)
    else:
        assert loaded == []


def test_cached_trust_root_is_loaded_from_the_checked_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("sigstore")
    from sigstore._internal.tuf import DEFAULT_TUF_URL, _get_dirs
    from sigstore.models import ClientTrustConfig, TrustedRoot
    from sigstore_models.trustroot import v1 as trustroot_v1

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.delenv(TRUST_ROOT_ENV, raising=False)
    monkeypatch.delenv(TRUST_ROOT_SHA256_ENV, raising=False)
    pinned, _planted = _trust_roots()
    loaded = _capture_verifier(monkeypatch)

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the cached trust root must not be re-read by path")

    monkeypatch.setattr(TrustedRoot, "from_file", classmethod(refuse))
    monkeypatch.setattr(ClientTrustConfig, "from_tuf", classmethod(refuse))
    result = verify_sigstore_digest("0" * 64, b"{}", IDENTITY, ISSUER)
    assert result.verified, result.error
    assert result.details is not None
    assert result.details["trust_root_source"] == "cache"
    _metadata_dir, targets_dir = _get_dirs(DEFAULT_TUF_URL)
    root = targets_dir / "trusted_root.json"
    assert result.details["trust_root_path"] == str(root)
    # A missing cache is seeded privately from the root embedded in sigstore-python.
    assert root.read_bytes() == pinned
    assert root.stat().st_mode & 0o077 == 0
    assert loaded[0]._inner == trustroot_v1.TrustedRoot.from_json(pinned)
