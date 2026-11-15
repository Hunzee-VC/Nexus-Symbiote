"""NumPy object-dtype arrays are recognized by their header, alone or as any ZIP member."""

from __future__ import annotations

import io
import pickle
import zipfile
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.scanners import model
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
from nexus_symbiote.utils import model_formats

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


def test_array_headers_spend_the_inspection_budget_one_scan_shares(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed: list[int] = []
    declares = model._declares_object

    def counted(header: bytes, major: int) -> bool:
        parsed.append(len(header))
        return declares(header, major)

    monkeypatch.setattr(model, "_declares_object", counted)
    monkeypatch.setattr(model_formats, "MAX_INSPECTION_UNITS", 200_000)
    # Each 60 KiB header inflates from about a hundred bytes.
    padded = _npy("'<f8'", version=2, lead=60_000)
    archive = _zip([(f"m{index}.npy", padded) for index in range(40)], zipfile.ZIP_DEFLATED)
    assert len(archive) < 40 * 1024
    (tmp_path / "arrays.npz").write_bytes(archive)
    (tmp_path / "first.npy").write_bytes(_npy("'|O'", lead=60_000))
    (tmp_path / "second.npy").write_bytes(_npy("'|O'", lead=60_000))
    result = ModelScanner().scan(tmp_path)
    assert not result.scan_failures
    assert sum(parsed) <= 200_000
    assert {c.name: c.properties["format_inspection"] for c in result.components} == {
        "arrays.npz": ZIP_MEMBER_UNREAD,
        "first.npy": NUMPY_HEADER_UNREAD,
        "second.npy": NUMPY_HEADER_UNREAD,
    }


def test_a_header_that_claims_more_than_it_holds_costs_only_what_it_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(model_formats, "MAX_INSPECTION_UNITS", 4_096)
    claim = b"\x93NUMPY\x02\x00" + MAX_PICKLE_INSPECTION_BYTES.to_bytes(4, "little") + b"{}"
    for index in range(100):
        (tmp_path / f"short{index:03d}.npy").write_bytes(claim)
    (tmp_path / "zz.npy").write_bytes(_npy("'|O'"))
    result = ModelScanner().scan(tmp_path)
    assert not result.scan_failures
    assert {c.name: c.serialization_safety for c in result.components} == {"zz.npy": UNSAFE}


@pytest.mark.parametrize("descr", ["'|T'", "'T'", "[('text', '|T')]"])
def test_numpy_string_dtype_is_treated_as_pickle_backed_object_array(
    tmp_path: Path, descr: str
) -> None:
    # NZ-1: NumPy 2.0 StringDType ('T') serializes strings with pickle.
    assert _inspect(tmp_path, _npy(descr)) == (UNSAFE, NUMPY_OBJECT_ARRAY)
    assert _inspect(tmp_path, _zip([("strings.npy", _npy(descr))])) == (UNSAFE, ZIP_OBJECT_ARRAY)


def test_empty_zip_and_spanning_prefixes_do_not_hide_zip_members(tmp_path: Path) -> None:
    # NZ-2: An empty ZIP starts with PK\x05\x06; zipfile opens a real ZIP concatenated after it.
    empty = _zip([])
    assert empty[:4] == b"PK\x05\x06"
    (tmp_path / "empty.dat").write_bytes(empty)
    assert ModelScanner().scan(tmp_path).components == []
    assert _inspect(tmp_path, empty) == (SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE)

    concat_pkl = empty + _zip([("archive/data.pkl", pickle.dumps({"w": 1}))])
    concat_obj = empty + _zip([("arr_0.npy", _npy("'|O'"))])
    spanned_pkl = b"PK\x07\x08" + b"\x00" * 12 + _zip([("data.pkl", pickle.dumps({"w": 1}))])
    with zipfile.ZipFile(io.BytesIO(concat_pkl)) as zf:
        assert zf.namelist() == ["archive/data.pkl"]
    with zipfile.ZipFile(io.BytesIO(concat_obj)) as zf:
        assert zf.namelist() == ["arr_0.npy"]
    assert _inspect(tmp_path, concat_pkl, "weights.dat") == (UNSAFE, ZIP_PICKLE_MEMBER)
    assert _inspect(tmp_path, concat_obj, "weights.dat") == (UNSAFE, ZIP_OBJECT_ARRAY)
    assert _inspect(tmp_path, spanned_pkl, "weights.dat") == (UNSAFE, ZIP_PICKLE_MEMBER)


def _cd_entry(name: bytes, payload: bytes, local_offset: int, comment: bytes = b"") -> bytes:
    import struct
    import zlib

    crc = zlib.crc32(payload) & 0xFFFFFFFF
    data_size = len(payload)
    return (
        struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            data_size,
            data_size,
            len(name),
            0,
            len(comment),
            0,
            0,
            0,
            local_offset,
        )
        + name
        + comment
    )


def _local_entry(name: bytes, payload: bytes) -> bytes:
    import struct
    import zlib

    crc = zlib.crc32(payload) & 0xFFFFFFFF
    return (
        struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(name),
            0,
        )
        + name
        + payload
    )


def test_concat_shifted_and_unshifted_central_directories_are_both_checked(
    tmp_path: Path,
) -> None:
    import struct

    # NZ-3a: Decoy central directory at offset_cd (benign.txt), real central directory
    # immediately before EOCD (arr.npy with '|O') shifted by concat, which zipfile opens.
    benign_payload = b"hello" * 20
    benign_local = _local_entry(b"benign.txt", benign_payload)
    evil_payload = _npy("'|O'")
    evil_local_offset = len(benign_local)
    evil_local = _local_entry(b"arr.npy", evil_payload)
    decoy_cd_offset = len(benign_local) + len(evil_local)
    decoy_cd = _cd_entry(b"benign.txt", benign_payload, 0)
    # concat == len(decoy_cd); stored offset + concat == evil_local_offset.
    assert evil_local_offset >= len(decoy_cd)
    real_cd = _cd_entry(b"arr.npy", evil_payload, evil_local_offset - len(decoy_cd))
    padded_decoy_cd = _cd_entry(
        b"benign.txt", benign_payload, 0, b" " * max(0, len(real_cd) - len(decoy_cd))
    )
    real_cd = _cd_entry(b"arr.npy", evil_payload, evil_local_offset - len(padded_decoy_cd))
    eocd_zipfile = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,
        0,
        1,
        1,
        len(real_cd),
        decoy_cd_offset,
        0,
    )
    polyglot_zipfile = benign_local + evil_local + padded_decoy_cd + real_cd + eocd_zipfile
    with zipfile.ZipFile(io.BytesIO(polyglot_zipfile)) as zf:
        assert zf.namelist() == ["arr.npy"]
        assert zf.read("arr.npy").startswith(b"\x93NUMPY")
    assert _inspect(tmp_path, polyglot_zipfile, "polyglot.dat") == (UNSAFE, ZIP_OBJECT_ARRAY)

    # NZ-3b: Reverse polyglot where directory_end - directory_size holds benign.txt (for zipfile)
    # while offset_cd holds an unshifted central directory with objects_array.npy (for miniz).
    miniz_local = _local_entry(b"objects_array.npy", evil_payload)
    evil_cd_offset = len(benign_local) + len(miniz_local)
    evil_cd = _cd_entry(b"objects_array.npy", evil_payload, evil_local_offset)
    assert len(evil_cd) >= len(decoy_cd)
    padded_benign_cd = _cd_entry(
        b"benign.txt", benign_payload, 0, b" " * (len(evil_cd) - len(decoy_cd))
    )
    eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,
        0,
        1,
        1,
        len(evil_cd),
        evil_cd_offset,
        0,
    )
    polyglot_miniz = benign_local + miniz_local + evil_cd + padded_benign_cd + eocd
    with zipfile.ZipFile(io.BytesIO(polyglot_miniz)) as zf:
        assert zf.namelist() == ["benign.txt"]
    assert _inspect(tmp_path, polyglot_miniz, "miniz.dat") == (UNSAFE, ZIP_OBJECT_ARRAY)

    # Even if zipfile's primary region is corrupt, miniz's view catches evil_cd.
    corrupt_primary = benign_local + miniz_local + evil_cd + (b"\x00" * len(evil_cd)) + eocd
    assert _inspect(tmp_path, corrupt_primary, "miniz_only.dat") == (UNSAFE, ZIP_OBJECT_ARRAY)


def test_unconditional_zip64_locator_without_overflow_sentinels_is_checked(
    tmp_path: Path,
) -> None:
    import struct

    # NZ-4: 32-bit EOCD has ordinary (non-0xFFFF / non-0xFFFFFFFF) counts pointing at benign_cd,
    # while PK\x06\x06 + PK\x06\x07 immediately precede EOCD and point to evil_cd.
    benign_local = _local_entry(b"benign.txt", b"ok")
    evil_payload = _npy("'|O'")
    evil_local = _local_entry(b"arr.npy", evil_payload)
    benign_cd_off = len(benign_local) + len(evil_local)
    benign_cd = _cd_entry(b"benign.txt", b"ok", 0)
    evil_cd_off = benign_cd_off + len(benign_cd)
    evil_cd = _cd_entry(b"arr.npy", evil_payload, len(benign_local))
    z64_off = evil_cd_off + len(evil_cd)
    z64_eocd = struct.pack(
        "<4sQHHIIQQQQ",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        1,
        1,
        len(evil_cd),
        evil_cd_off,
    )
    z64_loc = struct.pack("<4sIQI", b"PK\x06\x07", 0, z64_off, 1)
    eocd32 = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,
        0,
        1,
        1,
        len(benign_cd),
        benign_cd_off,
        0,
    )
    crafted = benign_local + evil_local + benign_cd + evil_cd + z64_eocd + z64_loc + eocd32
    with zipfile.ZipFile(io.BytesIO(crafted)) as zf:
        assert zf.namelist() == ["arr.npy"]
    assert _inspect(tmp_path, crafted, "zip64_decoy.dat") == (UNSAFE, ZIP_OBJECT_ARRAY)
    # Prepended empty ZIP exercises zipfile's fallback from reloff to offset64!
    prepended = _zip([]) + crafted
    with zipfile.ZipFile(io.BytesIO(prepended)) as zf:
        assert zf.namelist() == ["arr.npy"]
    assert _inspect(tmp_path, prepended, "zip64_prepended.dat") == (UNSAFE, ZIP_OBJECT_ARRAY)
