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


def _npy(descr: str, *, version: tuple[int, int] = (1, 0), pad_len: int = 0) -> bytes:
    header = f"{{'descr': {descr!r}, 'fortran_order': False, 'shape': (1,), }}"
    if pad_len:
        header += " " * pad_len
    if version[0] == 1:
        pad = (64 - ((10 + len(header) + 1) % 64)) % 64
        text = header + (" " * pad) + "\n"
        return (
            b"\x93NUMPY\x01\x00"
            + len(text).to_bytes(2, "little")
            + text.encode("latin-1")
            + b"\x00"
        )
    pad = (64 - ((12 + len(header) + 1) % 64)) % 64
    text = header + (" " * pad) + "\n"
    encoding = "latin-1" if version[0] == 2 else "utf-8"
    return (
        b"\x93NUMPY"
        + bytes(version)
        + len(text).to_bytes(4, "little")
        + text.encode(encoding)
        + b"\x00"
    )


def _npy_raw(descr_literal: str, *, version: tuple[int, int] = (1, 0), pad_len: int = 0) -> bytes:
    header = f"{{'descr': {descr_literal}, 'fortran_order': False, 'shape': (1,), }}"
    if pad_len:
        header += " " * pad_len
    if version[0] == 1:
        pad = (64 - ((10 + len(header) + 1) % 64)) % 64
        text = header + (" " * pad) + "\n"
        return (
            b"\x93NUMPY\x01\x00"
            + len(text).to_bytes(2, "little")
            + text.encode("latin-1")
            + b"\x00"
        )
    pad = (64 - ((12 + len(header) + 1) % 64)) % 64
    text = header + (" " * pad) + "\n"
    encoding = "latin-1" if version[0] == 2 else "utf-8"
    return (
        b"\x93NUMPY"
        + bytes(version)
        + len(text).to_bytes(4, "little")
        + text.encode(encoding)
        + b"\x00"
    )


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


def test_large_renamed_binary_pickle_beyond_prefix_is_recognized(tmp_path: Path) -> None:
    class Boom:
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (eval, ("1+1",))

    payload = pickle.dumps(
        [f"{idx:04d}".encode() + b"A" * 1000 for idx in range(80)] + [Boom()], protocol=4
    )
    assert len(payload) > 65536
    assert sniffed_payload(payload[:65536]) is not None
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "weights").write_bytes(payload)
    (tmp_path / "models" / "weights.dat").write_bytes(payload)
    for rel in ("models/weights", "models/weights.dat"):
        component = _component(tmp_path, rel)
        assert component is not None
        assert component.serialization_safety is SerializationSafety.UNSAFE_CODE_EXECUTION


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
    assert sniffed_payload(b"\x80\x04.") is None
    assert sniffed_payload(_npy("|O")) is not None
    assert sniffed_payload(_reduce_pickle()) is not None


@pytest.mark.parametrize(
    ("descr_literal", "version", "pad_len", "expected"),
    [
        ("[('meta', [('id', '<i4')]), ('payload', '|O')]", (1, 0), 0, True),
        ("[('col]1', '<i4'), ('payload', '|O')]", (1, 0), 0, True),
        (r"'|\x4f'", (1, 0), 0, True),
        ("'object'", (1, 0), 0, True),
        ("'|O8'", (1, 0), 0, True),
        ("'<i4, (2, 2)|O'", (1, 0), 0, True),
        (
            "{'names': ['a', 'b'], 'formats': ['<i4', '|O'], 'offsets': [0, 8], 'itemsize': 16}",
            (1, 0),
            0,
            True,
        ),
        ("{'a': ('<i4', 0), 'b': ('object', 8)}", (1, 0), 0, True),
        ("('<f8', [('x', '|O')])", (1, 0), 0, True),
        ("[('a', '<i4'), ('payload', '|O')]", (1, 0), 2048, True),
        ("'|O'", (2, 0), 2048, True),
        ("[('\u03c4', '<i4'), ('p', '|O')]", (3, 0), 0, True),
        ("[('O', '<f8')]", (1, 0), 0, False),
    ],
)
def test_structured_escaped_and_extended_npy_headers(
    descr_literal: str, version: tuple[int, int], pad_len: int, expected: bool
) -> None:
    blob = _npy_raw(descr_literal, version=version, pad_len=pad_len)
    assert (sniffed_payload(blob) is not None) is expected


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
def test_multi_member_and_streamed_npz_object_arrays_are_recognized(compression: int) -> None:
    multi = io.BytesIO()
    with zipfile.ZipFile(multi, "w", compression=compression) as archive:
        archive.writestr("first.npy", _npy("<f8", pad_len=1500))
        archive.writestr("second.npy", _npy("|O", pad_len=1500))
    assert sniffed_payload(multi.getvalue()) is not None

    streamed = io.BytesIO()
    with zipfile.ZipFile(streamed, "w", compression=compression) as archive:
        with archive.open("first.npy", "w") as handle:
            handle.write(_npy("<f8"))
        with archive.open("second.npy", "w") as handle:
            handle.write(_npy("|O"))
    assert sniffed_payload(streamed.getvalue()) is not None

    numeric_only = io.BytesIO()
    with zipfile.ZipFile(numeric_only, "w", compression=compression) as archive:
        archive.writestr("first.npy", _npy("<f8", pad_len=1500))
        archive.writestr("second.npy", _npy("<i4", pad_len=1500))
    assert sniffed_payload(numeric_only.getvalue()) is None


def test_large_npz_recognizes_early_object_member_within_prefix_and_bounds_bombs() -> None:
    import hashlib

    incompressible = b"".join(
        hashlib.sha256(idx.to_bytes(4, "little")).digest() for idx in range(3000)
    )
    large = io.BytesIO()
    with zipfile.ZipFile(large, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.npy", _npy("<f8", pad_len=1000))
        archive.writestr("b.npy", _npy("|O"))
        archive.writestr("tail.npy", _npy("<f8") + incompressible)
    assert len(large.getvalue()) > 65536
    assert sniffed_payload(large.getvalue()[:65536]) is not None

    late = io.BytesIO()
    with zipfile.ZipFile(late, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("lead.npy", _npy("<f8") + incompressible)
        archive.writestr("late_object.npy", _npy("|O"))
    assert len(late.getvalue()) > 65536
    assert sniffed_payload(late.getvalue()[:65536]) is None

    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for idx in range(40):
            archive.writestr(f"m{idx}.npy", _npy("<f8") + b"\x00" * 60000)
    assert sniffed_payload(bomb.getvalue()[:65536]) is None


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
