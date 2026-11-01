"""Tests for safetensors per-tensor fingerprinting and tensor-inventory integrity."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import safetensors_fingerprint
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.validators.integrity import IntegrityValidator


def _write_safetensors(
    path: Path,
    tensors: dict[str, dict],
    data: bytes | None = None,
) -> None:
    header = json.dumps(tensors).encode("utf-8")
    if data is None:
        data = b"\x00" * sum(
            (t["data_offsets"][1] - t["data_offsets"][0]) for t in tensors.values()
        )
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(header)))
        f.write(header)
        f.write(data)


def _tensors() -> dict[str, dict]:
    return {
        "model.layers.0.weight": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]},
        "model.layers.1.weight": {"dtype": "F32", "shape": [4, 4], "data_offsets": [64, 128]},
    }


def test_fingerprint_stable_for_identical_files(tmp_path: Path) -> None:
    a = tmp_path / "a.safetensors"
    b = tmp_path / "b.safetensors"
    _write_safetensors(a, _tensors())
    _write_safetensors(b, _tensors())

    fa, fb = safetensors_fingerprint(a), safetensors_fingerprint(b)
    assert fa is not None and fb is not None
    assert fa["tensor_inventory_sha256"] == fb["tensor_inventory_sha256"]


def test_single_tensor_swap_changes_inventory_digest(tmp_path: Path) -> None:
    """The core defense: one poisoned tensor changes the inventory digest."""
    good = tmp_path / "good.safetensors"
    _write_safetensors(good, _tensors())

    poisoned_tensors = _tensors()
    poisoned_tensors["model.layers.1.weight"] = {
        "dtype": "F32",
        "shape": [4, 4],
        "data_offsets": [64, 128],
    }
    # A trojan adds a new tensor rather than modifying offsets.
    poisoned_tensors["backdoor.bias"] = {
        "dtype": "F32",
        "shape": [16],
        "data_offsets": [128, 192],
    }
    poisoned = tmp_path / "poisoned.safetensors"
    _write_safetensors(poisoned, poisoned_tensors)

    fg = safetensors_fingerprint(good)
    fp = safetensors_fingerprint(poisoned)
    assert fg is not None and fp is not None
    assert fg["tensor_inventory_sha256"] != fp["tensor_inventory_sha256"]
    assert fg["tensor_count"] == "2"
    assert fp["tensor_count"] == "3"


def test_data_only_change_keeps_inventory_but_changes_file_hash(tmp_path: Path) -> None:
    """Rewriting weight bytes changes the whole-file hash, not the inventory."""
    a = tmp_path / "a.safetensors"
    b = tmp_path / "b.safetensors"
    _write_safetensors(a, _tensors(), data=b"\x01" * 128)
    _write_safetensors(b, _tensors(), data=b"\x02" * 128)

    fa, fb = safetensors_fingerprint(a), safetensors_fingerprint(b)
    assert fa is not None and fb is not None
    assert fa["tensor_inventory_sha256"] == fb["tensor_inventory_sha256"]
    assert fa["safetensors_header_sha256"] == fb["safetensors_header_sha256"]


def test_invalid_file_returns_none(tmp_path: Path) -> None:
    bad = tmp_path / "bad.safetensors"
    bad.write_bytes(b"not a safetensors file at all")
    assert safetensors_fingerprint(bad) is None


def test_model_scanner_records_tensor_fingerprint(tmp_path: Path) -> None:
    model_dir = tmp_path / "my-model"
    model_dir.mkdir()
    _write_safetensors(model_dir / "model.safetensors", _tensors())

    result = ModelScanner().scan(tmp_path)
    models = [c for c in result.components if c.component_type.value == "model"]
    assert len(models) == 1

    comp = models[0]
    assert comp.tensor_inventory_hash is not None
    assert comp.tensor_inventory_hash.startswith("sha256:")
    assert "tensor_inventory_sha256" in comp.hashes
    assert "sha256" in comp.hashes


def test_integrity_flags_tensor_inventory_mismatch(tmp_path: Path) -> None:
    """A tampered tensor inventory fails integrity even with a fresh file hash."""
    model_dir = tmp_path / "my-model"
    model_dir.mkdir()
    original = _tensors()
    _write_safetensors(model_dir / "model.safetensors", original)

    result = ModelScanner().scan(tmp_path)
    comp = [c for c in result.components if c.component_type.value == "model"][0]

    # Tamper: add a backdoor tensor after the BOM was recorded.
    tampered = _tensors()
    tampered["backdoor.bias"] = {"dtype": "F32", "shape": [16], "data_offsets": [128, 192]}
    _write_safetensors(model_dir / "model.safetensors", tampered)

    validator = IntegrityValidator()
    report = validator.validate(_load_bom([comp]), tmp_path)

    issues = [i for i in report.issues if i.category == "tensor_inventory_mismatch"]
    assert issues, "tensor inventory tampering must be flagged"
    assert not report.is_valid


def test_integrity_passes_untampered_model(tmp_path: Path) -> None:
    model_dir = tmp_path / "my-model"
    model_dir.mkdir()
    _write_safetensors(model_dir / "model.safetensors", _tensors())

    result = ModelScanner().scan(tmp_path)
    comp = [c for c in result.components if c.component_type.value == "model"][0]

    validator = IntegrityValidator()
    report = validator.validate(_load_bom([comp]), tmp_path)
    assert not [i for i in report.issues if i.category == "tensor_inventory_mismatch"]


def _load_bom(components) -> AIBOM:
    bom = AIBOM()
    for c in components:
        bom.add_component(c)
    return bom
