"""Pickle and object-dtype NumPy payloads are found by content, not only by suffix."""

from __future__ import annotations

import io
import pickle
import zipfile
from pathlib import Path

import pytest

from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.scanners.model import ModelScanner, sniffed_payload


def _reduce_pickle() -> bytes:
    class Boom:
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (eval, ("1+1",))

    return pickle.dumps(Boom(), protocol=4)


def _npy(descr: str) -> bytes:
    header = f"{{'descr': '{descr}', 'fortran_order': False, 'shape': (1,), }}"
    pad = (64 - ((10 + len(header) + 1) % 64)) % 64
    text = header + (" " * pad) + "\n"
    return b"\x93NUMPY\x01\x00" + len(text).to_bytes(2, "little") + text.encode() + b"\x00"


def _component(root: Path, relative: str):
    found = [
        component
        for component in ModelScanner().scan(root).components
        if component.source_path == relative
    ]
    return found[0] if found else None


def test_renamed_pickle_and_object_arrays_are_critical(tmp_path: Path) -> None:
    payload = _reduce_pickle()
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "weights").write_bytes(payload)
    (tmp_path / "models" / "model.dat").write_bytes(payload)
    (tmp_path / "tensors").mkdir()
    (tmp_path / "tensors" / "objects.npy").write_bytes(_npy("|O"))
    (tmp_path / "tensors" / "numbers.npy").write_bytes(_npy("<f8"))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("weights/data.pkl", payload)
    (tmp_path / "checkpoints").mkdir()
    (tmp_path / "checkpoints" / "bundle.bin.not").write_bytes(buffer.getvalue())

    weights = _component(tmp_path, "models/weights")
    dat = _component(tmp_path, "models/model.dat")
    objects = _component(tmp_path, "tensors/objects.npy")
    archive_file = _component(tmp_path, "checkpoints/bundle.bin.not")
    assert weights is not None and dat is not None and objects is not None
    assert archive_file is not None
    assert _component(tmp_path, "tensors/numbers.npy") is None
    for component in (weights, dat, objects, archive_file):
        assert component.serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION
        assert any(
            risk.severity is RiskSeverity.CRITICAL and risk.category == "serialization_format"
            for risk in component.risks
        )
    assert "1+1" not in weights.model_dump_json()


def test_a_suffix_list_file_is_still_rated_without_a_recognized_stream(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(b"not a pickle")
    component = _component(tmp_path, "model.pkl")
    assert component is not None
    assert component.serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION


def test_a_later_or_pickle_named_zip_member_is_critical(tmp_path: Path) -> None:
    payload = _reduce_pickle()
    (tmp_path / "models").mkdir()
    hidden = io.BytesIO()
    with zipfile.ZipFile(hidden, "w") as archive:
        archive.writestr("version", b"1")
        archive.writestr("archive/data.pkl", payload)
    renamed = io.BytesIO()
    with zipfile.ZipFile(renamed, "w") as archive:
        archive.writestr("version", b"1")
        archive.writestr("weights/data.pickle", payload)
    plain = io.BytesIO()
    with zipfile.ZipFile(plain, "w") as archive:
        archive.writestr("version", b"1")
        archive.writestr("README.txt", b"numbers only")
    (tmp_path / "models" / "hidden.zip").write_bytes(hidden.getvalue())
    (tmp_path / "models" / "renamed.dat").write_bytes(renamed.getvalue())
    (tmp_path / "models" / "notes.dat").write_bytes(plain.getvalue())

    for relative in ("models/hidden.zip", "models/renamed.dat"):
        component = _component(tmp_path, relative)
        assert component is not None
        assert component.serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert _component(tmp_path, "models/notes.dat") is None
    assert sniffed_payload(hidden.getvalue()) is not None
    assert sniffed_payload(renamed.getvalue()) is not None
    assert sniffed_payload(plain.getvalue()) is None


def test_sniffed_payload_ignores_a_numeric_header_and_a_short_magic_byte() -> None:
    assert sniffed_payload(_npy("<f8")) is None
    assert sniffed_payload(b"\x80\x02") is None
    assert sniffed_payload(_npy("|O")) is not None
    assert sniffed_payload(_reduce_pickle()) is not None


def _npz(descr: str, compression: int) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        archive.writestr("array.npy", _npy(descr))
    return buffer.getvalue()


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_object_array_headers_are_recognized_in_npz_members(compression: int) -> None:
    assert sniffed_payload(_npz("|O", compression)) is not None
    assert sniffed_payload(_npz("<f8", compression)) is None


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_npz_object_arrays_are_inventoried_without_loading_them(
    tmp_path: Path, compression: int
) -> None:
    (tmp_path / "objects.npz").write_bytes(_npz("|O", compression))
    (tmp_path / "numbers.npz").write_bytes(_npz("<f8", compression))
    objects = _component(tmp_path, "objects.npz")
    assert objects is not None
    assert objects.serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    assert any(
        risk.category == "serialization_format" and risk.severity is RiskSeverity.CRITICAL
        for risk in objects.risks
    )
    assert _component(tmp_path, "numbers.npz") is None


@pytest.mark.parametrize("truncated_bytes", [0, 1, 2])
def test_an_incomplete_compressed_header_is_not_a_recognized_array(truncated_bytes: int) -> None:
    archive = _npz("|O", zipfile.ZIP_DEFLATED)
    offset = 30 + int.from_bytes(archive[26:28], "little")
    offset += int.from_bytes(archive[28:30], "little")
    assert sniffed_payload(archive[: offset + truncated_bytes]) is None


def test_invalid_raw_deflate_is_refused_without_a_parser_exception() -> None:
    archive = _npz("|O", zipfile.ZIP_DEFLATED)
    offset = 30 + int.from_bytes(archive[26:28], "little")
    offset += int.from_bytes(archive[28:30], "little")
    assert sniffed_payload(archive[:offset] + b"\x07") is None
