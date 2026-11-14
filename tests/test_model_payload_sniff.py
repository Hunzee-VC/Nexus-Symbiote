"""Pickle and object-dtype NumPy payloads are found by content, not only by suffix."""

from __future__ import annotations

import io
import pickle
import zipfile
from pathlib import Path

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


def test_sniffed_payload_ignores_a_numeric_header_and_a_short_magic_byte() -> None:
    assert sniffed_payload(_npy("<f8")) is None
    assert sniffed_payload(b"\x80\x02") is None
    assert sniffed_payload(_npy("|O")) is not None
    assert sniffed_payload(_reduce_pickle()) is not None
