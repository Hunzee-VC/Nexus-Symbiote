"""Real same-inode changes cannot reuse a digest merely by restoring mtime."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import descriptor_binding
from nexus_symbiote.core.models import PromptComponent
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.validators.integrity import IntegrityValidator, _ArtifactDigests

ORIGINAL = b"original"
REPLACED = b"replaced"
COARSE_TICK_BUDGET_SECONDS = 0.050


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def change(path: Path, kind: str) -> tuple[os.stat_result, os.stat_result]:
    before = path.stat()
    deadline = time.monotonic() + COARSE_TICK_BUDGET_SECONDS
    if kind == "content":
        path.write_bytes(REPLACED)
        while True:
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            after = path.stat()
            if after.st_ctime_ns != before.st_ctime_ns or time.monotonic() >= deadline:
                break
            time.sleep(0.001)
        assert after.st_mode == before.st_mode
    else:
        target_mode = (before.st_mode & 0o777) ^ 0o100
        while True:
            path.chmod(target_mode)
            after = path.stat()
            if after.st_ctime_ns != before.st_ctime_ns or time.monotonic() >= deadline:
                break
            time.sleep(0.001)
        assert (after.st_mode & 0o777) == target_mode
    assert (before.st_dev, before.st_ino, before.st_nlink, before.st_size, before.st_mtime_ns) == (
        after.st_dev,
        after.st_ino,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
    )
    assert before.st_ctime_ns != after.st_ctime_ns
    return before, after


@pytest.mark.parametrize("kind", ["content", "metadata"])
def test_change_during_observation_is_refused_and_fresh_observation_succeeds(
    tmp_path: Path, kind: str
) -> None:
    path = tmp_path / "prompt.txt"
    path.write_bytes(ORIGINAL)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        with (
            pytest.raises(OSError, match="changed during collection"),
            files.open_regular(path.name) as stream,
        ):
            assert stream.read(len(ORIGINAL)) == ORIGINAL
            before, after = change(path, kind)
        assert descriptor_binding(before) != descriptor_binding(after)
        assert failures
        expected = REPLACED if kind == "content" else ORIGINAL
        with files.open_regular(path.name) as stream:
            assert stream.read(len(expected)) == expected


@pytest.mark.parametrize("kind", ["content", "metadata"])
def test_cache_rehashes_after_ctime_changes_and_charges_the_new_read(
    tmp_path: Path, kind: str
) -> None:
    path = tmp_path / "prompt.txt"
    path.write_bytes(ORIGINAL)
    cache = _ArtifactDigests(1024)
    assert cache.digest(path, "sha256") == digest(ORIGINAL)
    remaining = cache.remaining
    assert cache.digest(path, "sha256") == digest(ORIGINAL)
    assert cache.remaining == remaining
    change(path, kind)
    expected = REPLACED if kind == "content" else ORIGINAL
    assert cache.digest(path, "sha256") == digest(expected)
    assert cache.remaining == remaining - len(expected)


def test_integrity_rejects_changed_bytes_between_two_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "prompt.txt"
    path.write_bytes(ORIGINAL)
    bom = AIBOM(
        components=[
            PromptComponent(
                bom_ref=f"prompt:{i}",
                name=f"prompt{i}",
                source_path=path.name,
                content_hash=digest(ORIGINAL),
            )
            for i in (1, 2)
        ]
    )
    real_digest = _ArtifactDigests.digest
    reads: list[str] = []

    def mutate_after_first_read(self: _ArtifactDigests, target: Path, algorithm: str) -> str:
        result = real_digest(self, target, algorithm)
        reads.append(result)
        if len(reads) == 1:
            change(path, "content")
        return result

    monkeypatch.setattr(_ArtifactDigests, "digest", mutate_after_first_read)
    report = IntegrityValidator().validate(bom, tmp_path)
    assert len(reads) == 2
    assert not report.is_valid
    assert report.hashes_verified == 1
    assert report.hashes_failed == 1
    assert path.read_bytes() == REPLACED
