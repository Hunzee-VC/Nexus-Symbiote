"""File-read and coverage regressions for model and registry scanners."""

import hashlib
from pathlib import Path

import pytest

from nexus_symbiote.scanners.base import hash_regular_file
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.scanners.registry import RegistryScanner


def test_model_symlink_is_not_hashed_and_failure_is_reported(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.write_bytes(b"external-canary")
    project = tmp_path / "project"
    project.mkdir()
    (project / "model.safetensors").symlink_to(external)
    result = ModelScanner().scan(project)
    assert result.scan_failures
    assert result.components and not result.components[0].hashes
    assert hashlib.sha256(b"external-canary").hexdigest() not in repr(result)


def test_hash_stream_is_bounded_and_preserves_normal_hash(tmp_path: Path) -> None:
    path = tmp_path / "model.safetensors"
    path.write_bytes(b"data")
    assert hash_regular_file(path, max_bytes=4) == "sha256:" + hashlib.sha256(b"data").hexdigest()
    with pytest.raises(OSError):
        hash_regular_file(path, max_bytes=3)


@pytest.mark.parametrize(
    "filename", ["package.json", "requirements.txt", "pyproject.toml", "Dockerfile"]
)
def test_registry_symlink_reports_failure(tmp_path: Path, filename: str) -> None:
    external = tmp_path / "external"
    external.write_text("CANARY", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / filename).symlink_to(external)
    result = RegistryScanner().scan(project)
    assert result.scan_failures
    assert not result.components
    assert "CANARY" not in repr(result)
