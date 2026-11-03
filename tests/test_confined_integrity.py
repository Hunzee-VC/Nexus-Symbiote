"""Adversarial tests for BOM-supplied artifact paths."""

import hashlib
import os
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import ModelComponent, PromptComponent
from nexus_symbiote.utils.confined import descriptor_binding, hash_confined_file
from nexus_symbiote.validators.integrity import IntegrityValidator


def digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def validate_path(root: Path, path: str, expected: str):
    bom = AIBOM()
    bom.add_component(
        PromptComponent(
            bom_ref="prompt:test", name="prompt", source_path=path, content_hash=expected
        )
    )
    return IntegrityValidator().validate(bom, root)


def test_relative_and_absolute_paths_within_root(tmp_path: Path) -> None:
    f = tmp_path / "model.bin"
    f.write_bytes(b"model")
    for path in ("model.bin", str(f)):
        report = validate_path(tmp_path, path, digest(b"model"))
        assert report.is_valid
        assert report.hashes_verified == 1


def test_parent_absolute_and_symlink_escape_fail(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"external-canary")
    (root / "link").symlink_to(outside)
    (root / "parent-link").symlink_to(tmp_path, target_is_directory=True)
    for path in ("../outside", str(outside), "link", "parent-link/outside", "missing"):
        report = validate_path(root, path, digest(b"external-canary"))
        assert not report.is_valid
        assert report.hashes_failed == 1
        assert digest(b"external-canary") not in str(report.to_dict())


def test_missing_project_or_source_fails_verification(tmp_path: Path) -> None:
    bom = AIBOM()
    bom.add_component(
        ModelComponent(bom_ref="model:test", name="model", hashes={"sha256": digest(b"data")})
    )
    for root in (None, tmp_path):
        result = IntegrityValidator().validate(bom, root)
        assert not result.is_valid
        assert result.hashes_failed == 1


def test_prompt_missing_file_fails_verification(tmp_path: Path) -> None:
    bom = AIBOM()
    bom.add_component(
        PromptComponent(
            bom_ref="prompt:1", name="prompt", source_path="missing", content_hash=digest(b"prompt")
        )
    )
    result = IntegrityValidator().validate(bom, tmp_path)
    assert not result.is_valid
    assert result.hashes_failed == 1


def test_hash_limit_and_algorithm_are_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "model.bin").write_bytes(b"data")
    monkeypatch.setattr("nexus_symbiote.utils.confined.MAX_HASH_BYTES", 3)
    with pytest.raises(OSError):
        hash_confined_file(tmp_path, "model.bin")
    with pytest.raises(OSError):
        hash_confined_file(tmp_path, "model.bin", "md5")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO required")
def test_fifo_rejected_without_blocking(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(OSError):
        hash_confined_file(tmp_path, "pipe")


def test_descriptor_binding_detects_rename_over_without_timestamp_change(tmp_path):
    """A rename-over inside one coarse timestamp tick must still change the binding."""
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"original")
    fd = os.open(target, os.O_RDONLY)
    try:
        before = os.fstat(fd)
        replacement = tmp_path / "replacement.bin"
        replacement.write_bytes(b"replaced")
        # Pin the replacement's timestamps to the original so size/mtime/ctime
        # alone cannot distinguish the two inodes.
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        replacement.replace(target)
        after = os.fstat(fd)
        assert after.st_nlink == 0
        assert descriptor_binding(before) != descriptor_binding(after)
        # Pathname-based observation now sees different bytes than the descriptor.
        assert target.read_bytes() == b"replaced"
        assert os.read(fd, 16) == b"original"
    finally:
        os.close(fd)
