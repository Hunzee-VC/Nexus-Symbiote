"""NumPy object-dtype arrays are recognized by their header, alone or as any ZIP member."""

from __future__ import annotations

import io
import pickle
import zipfile
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.scanners.model import (
    MAX_PICKLE_INSPECTION_BYTES,
    NUMPY_HEADER_UNREAD,
    NUMPY_OBJECT_ARRAY,
    ZIP_MEMBER_UNREAD,
    ZIP_OBJECT_ARRAY,
    ZIP_PICKLE_MEMBER,
    ZIP_WITHOUT_PICKLE,
    ModelScanner,
    inspect_model_format,
)

UNSAFE = SerializationSafety.UNSAFE_CODE_EXECUTION
NOT_RECOGNIZED = (
    SerializationSafety.UNKNOWN,
    "No bounded structural validator for this format/loader",
)


def _npy(
    descr: str,
    *,
    version: int = 1,
    lead: int = 0,
    padding: int = 0,
    shape: str = "(1,)",
    minor: int = 0,
) -> bytes:
    """An array file with ``descr`` written as Python literal text, as NumPy writes it."""
    text = "{" + " " * lead + f"'descr': {descr}, 'fortran_order': False, 'shape': {shape}, }}"
    width = 2 if version == 1 else 4
    text += " " * (padding + (-(10 + width + len(text) + padding) % 64)) + "\n"
    encoded = text.encode("utf-8" if version == 3 else "latin-1")
    return (
        b"\x93NUMPY"
        + bytes([version, minor])
        + len(encoded).to_bytes(width, "little")
        + encoded
        + pickle.dumps(["payload"], protocol=2)
    )


def _zip(members: list[tuple[str, bytes]], compression: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


def _inspect(tmp_path: Path, content: bytes, name: str = "model.onnx") -> tuple[object, str]:
    path = tmp_path / name
    path.write_bytes(content)
    return inspect_model_format(path)


@pytest.mark.parametrize(
    ("descr", "options"),
    [
        ("'|O'", {}),
        ("'O'", {"version": 2}),
        ("'<O8'", {"version": 3}),
        ("'object'", {}),
        ("'i4,(2,3)O'", {}),
        ("'(2,)O'", {}),
        ("[('a', '<i4'), ('b', '|O')]", {}),
        ("[('n', [('m', [('deep', '|O')])])]", {}),
        ("[('s', '|O', (2,))]", {}),
        ("[(('title', 'name'), '|O')]", {}),
        ("[('café', '|O')]", {"version": 3}),
        # The descr after 2 KiB of whitespace, which a literal reader skips.
        ("'|O'", {"lead": 2048}),
        # Python 2 wrote a long integer with an L; np.load still reads that header.
        ("'|O'", {"shape": "(1L,)"}),
        ("'|O'", {"version": 2, "shape": "(2L, 3L)"}),
    ],
)
def test_an_object_dtype_is_found_however_the_header_spells_it(
    tmp_path: Path, descr: str, options: dict[str, Any]
) -> None:
    assert _inspect(tmp_path, _npy(descr, **options)) == (UNSAFE, NUMPY_OBJECT_ARRAY)


@pytest.mark.parametrize(
    ("descr", "options"),
    [
        ("'<f8'", {}),
        ("'M8[ns]'", {}),
        # Field names are not types, whatever they spell.
        ("[('O', '<f8'), ('|O', '<i4'), ('object', 'u1')]", {}),
        ("[('n', [('O', '<f4')])]", {}),
        ("[(('O', 'O'), '<f8')]", {}),
        # np.load refuses a minor version other than 0 and a malformed header.
        ("'|O'", {"minor": 1}),
        ("'|O' + 'x'", {}),
    ],
)
def test_a_numeric_dtype_is_not_an_object_array(
    tmp_path: Path, descr: str, options: dict[str, Any]
) -> None:
    assert _inspect(tmp_path, _npy(descr, **options)) == NOT_RECOGNIZED


def test_an_array_header_is_read_to_the_largest_a_version_1_header_holds(
    tmp_path: Path,
) -> None:
    longest = _npy("'|O'", lead=65_535 - 200)
    assert 65_000 < int.from_bytes(longest[8:10], "little") <= MAX_PICKLE_INSPECTION_BYTES
    assert _inspect(tmp_path, longest) == (UNSAFE, NUMPY_OBJECT_ARRAY)
    longer = _npy("'|O'", version=2, lead=MAX_PICKLE_INSPECTION_BYTES)
    assert int.from_bytes(longer[8:12], "little") > MAX_PICKLE_INSPECTION_BYTES
    assert _inspect(tmp_path, longer) == (SerializationSafety.UNKNOWN, NUMPY_HEADER_UNREAD)


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_every_member_of_an_archive_is_checked_for_an_object_array(
    tmp_path: Path, compression: int
) -> None:
    numbers = _npy("'<f8'", shape="(9000,)") + b"\0" * 72_000
    found = _inspect(
        tmp_path, _zip([("numbers.npy", numbers), ("objects.npy", _npy("'|O'"))], compression)
    )
    assert found == (UNSAFE, ZIP_OBJECT_ARRAY)
    # np.load reads any member that starts with the NumPy magic, whatever its name.
    renamed = _zip([("version", b"3"), ("payload", _npy("[('a', '|O')]"))], compression)
    assert _inspect(tmp_path, renamed) == (UNSAFE, ZIP_OBJECT_ARRAY)
    plain = _zip([("numbers.npy", numbers), ("more.npy", _npy("[('O', '<f8')]"))], compression)
    assert _inspect(tmp_path, plain) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)


def test_a_zip64_directory_locates_every_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A low ZIP64 limit makes zipfile write each offset and size in ZIP64 fields.
    monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 16)
    archive = _zip([(f"n{index}.npy", _npy("'<f8'")) for index in range(3)] + [("o", _npy("'O'"))])
    assert b"PK\x06\x06" in archive
    assert _inspect(tmp_path, archive) == (UNSAFE, ZIP_OBJECT_ARRAY)


@pytest.mark.parametrize("compression", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_a_member_compressed_by_another_method_is_not_left_unrated(
    tmp_path: Path, compression: int
) -> None:
    archive = _zip([("objects.npy", _npy("'|O'"))], compression)
    assert _inspect(tmp_path, archive) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)


def test_overlapping_members_are_not_read_twice(tmp_path: Path) -> None:
    archive = bytearray(_zip([("a.npy", _npy("'<f8'")), ("b.npy", _npy("'<f8'"))]))
    # Point the second directory entry at the first member's local header.
    second = archive.index(b"PK\x01\x02", archive.index(b"PK\x01\x02") + 4)
    archive[second + 42 : second + 46] = (0).to_bytes(4, "little")
    assert _inspect(tmp_path, bytes(archive)) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)


def test_a_member_whose_array_header_is_over_the_bound_is_not_left_unrated(
    tmp_path: Path,
) -> None:
    archive = _zip([("a.npy", _npy("'<f8'", version=2, lead=MAX_PICKLE_INSPECTION_BYTES))])
    assert _inspect(tmp_path, archive) == (SerializationSafety.UNKNOWN, ZIP_MEMBER_UNREAD)


def test_invalid_raw_deflate_is_not_an_array(tmp_path: Path) -> None:
    archive = bytearray(_zip([("objects.npy", _npy("'|O'"))], zipfile.ZIP_DEFLATED))
    data = 30 + int.from_bytes(archive[26:28], "little") + int.from_bytes(archive[28:30], "little")
    # Block type 3 is reserved: zipfile cannot inflate the member, so np.load cannot read it.
    archive[data] = 0x07
    assert _inspect(tmp_path, bytes(archive)) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)


def test_a_pickle_family_member_after_another_is_unsafe_under_a_model_name(
    tmp_path: Path,
) -> None:
    for member in ("weights/data.pickle", "archive/data.pkl.gz", "nested/model.pt"):
        archive = _zip([("archive/version", b"3"), (member, pickle.dumps({"w": [0.0]}))])
        assert _inspect(tmp_path, archive, "model.gguf") == (UNSAFE, ZIP_PICKLE_MEMBER)


def test_an_object_array_under_a_model_name_is_a_critical_component(tmp_path: Path) -> None:
    (tmp_path / "model.onnx").write_bytes(_zip([("arr_0.npy", _npy("'|O'"))]))
    (tmp_path / "weights.h5").write_bytes(_npy("[('a', '<i4'), ('b', '|O')]"))
    result = ModelScanner().scan(tmp_path)
    assert not result.scan_failures
    assert {c.name: c.serialization_safety for c in result.components} == {
        "model.onnx": UNSAFE,
        "weights.h5": UNSAFE,
    }
    for component in result.components:
        assert any(
            risk.severity is RiskSeverity.CRITICAL and risk.category == "serialization_format"
            for risk in component.risks
        )
