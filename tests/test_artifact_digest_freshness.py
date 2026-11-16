"""Real same-inode changes cannot reuse a digest merely by restoring mtime."""

import hashlib
import os
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import descriptor_binding
from nexus_symbiote.core.models import PromptComponent
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.validators.integrity import IntegrityValidator, _ArtifactDigests

ORIGINAL = b"original"
REPLACED = b"replaced"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def change(path: Path, kind: str):
    before = path.stat()
    if kind == "content":
        path.write_bytes(REPLACED)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    else:
        path.chmod(before.st_mode ^ 0o100)
    after = path.stat()
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
def test_change_during_observation_is_refused_and_fresh_observation_succeeds(tmp_path, kind):
    path = tmp_path / "prompt.txt"
    path.write_bytes(ORIGINAL)
    failures = []
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
def test_cache_rehashes_after_ctime_changes_and_charges_the_new_read(tmp_path, kind):
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


def test_integrity_rejects_changed_bytes_between_two_references(tmp_path, monkeypatch):
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
    reads = []

    def mutate_after_first_read(self, target, algorithm):
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
