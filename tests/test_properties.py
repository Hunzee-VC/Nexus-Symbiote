"""Property-based checks for parsers, canonical hashing and bounded inspection."""

from __future__ import annotations

import json
import pickletools
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.hashing import canonical_json, hash_tool_definition, parse_json_strict
from nexus_symbiote.runtime import AuthorizationError, strict_json
from nexus_symbiote.runtime_validation import ValidationBudgetError, check_json_budget
from nexus_symbiote.scanners.base import sanitized_origin
from nexus_symbiote.scanners.model import (
    _GGUF_MAGIC,
    _TAR_MAGIC,
    _TAR_MAGIC_OFFSET,
    _WRAPPER_MAGIC,
    PICKLE_NAME_EMPTY,
    PICKLE_NAME_GGUF,
    PICKLE_NAME_UNEVIDENCED,
    PICKLE_NAME_WRAPPED,
    _lzma_alone_header,
    _tar_header,
    inspect_model_format,
)

PROPERTY_SETTINGS = settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

_OPCODE_BYTES = frozenset(opcode.code.encode("latin-1")[0] for opcode in pickletools.opcodes)
_ARGLESS_OPCODE_BYTES = frozenset(
    opcode.code.encode("latin-1")[0] for opcode in pickletools.opcodes if opcode.arg is None
)
SAFE_INT = st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1)
FINITE = st.floats(min_value=-(2.0**53) + 1, max_value=2.0**53 - 1, allow_nan=False)
TEXT = st.text(st.characters(exclude_categories=("Cs",)), max_size=20)
JSON_VALUES = st.recursive(
    st.none() | st.booleans() | SAFE_INT | FINITE | TEXT,
    lambda children: st.lists(children, max_size=5) | st.dictionaries(TEXT, children, max_size=5),
    max_leaves=25,
)
JSON_OBJECTS = st.dictionaries(TEXT, JSON_VALUES, max_size=6)


def _reordered(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _reordered(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [_reordered(item) for item in value]
    return value


@PROPERTY_SETTINGS
@given(JSON_VALUES)
def test_strict_parsers_round_trip_canonical_json(value):
    encoded = canonical_json(value)
    assert parse_json_strict(encoded) == value
    assert strict_json(encoded) == value
    assert canonical_json(parse_json_strict(encoded)) == encoded


@PROPERTY_SETTINGS
@given(TEXT, JSON_VALUES, JSON_VALUES)
def test_strict_parsers_reject_any_duplicate_key(key, first, second):
    raw = "{" + json.dumps(key) + ":" + json.dumps(first) + ","
    raw += json.dumps(key) + ":" + json.dumps(second) + "}"
    with pytest.raises(ValueError, match="Duplicate"):
        parse_json_strict(raw)
    with pytest.raises(AuthorizationError, match="duplicate"):
        strict_json(raw)


@PROPERTY_SETTINGS
@given(TEXT, TEXT, JSON_OBJECTS, JSON_OBJECTS)
def test_tool_fingerprint_ignores_key_order_but_not_content(name, description, schema, notes):
    digest = hash_tool_definition(name, description, schema, notes)
    assert digest == hash_tool_definition(name, description, _reordered(schema), _reordered(notes))
    assert digest != hash_tool_definition(name, description + "x", schema, notes)
    assert hash_tool_definition(name, description, schema, None) == hash_tool_definition(
        name, description, schema, {}
    )


@PROPERTY_SETTINGS
@given(JSON_VALUES, st.integers(min_value=1, max_value=4096))
def test_json_budget_is_an_upper_bound_on_compact_size(value, maximum):
    try:
        check_json_budget(value, maximum=maximum)
    except ValidationBudgetError:
        return
    compact = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    assert len(compact) <= maximum


URL_PARTS = st.text(st.sampled_from("abc.:@/?#%[]1-_ "), max_size=40)


@PROPERTY_SETTINGS
@given(
    st.sampled_from(["https", "HTTP", "wss", "", "file"]),
    URL_PARTS,
    URL_PARTS,
    URL_PARTS,
)
def test_sanitized_origin_never_echoes_credentials_paths_or_queries(scheme, userinfo, host, rest):
    marker = "s3cretTOKEN"
    url = f"{scheme}://{userinfo}{marker}@{host}/{rest}{marker}?q={marker}#{marker}"
    origin = sanitized_origin(url)
    assert marker not in origin
    assert origin == "[redacted]" or origin.count("/") == 2
    assert "?" not in origin
    assert "#" not in origin


DTYPES = st.sampled_from([("U8", 1), ("F16", 2), ("F32", 4), ("I64", 8)])
TENSORS = st.lists(
    st.tuples(DTYPES, st.lists(st.integers(min_value=0, max_value=4), max_size=3)),
    min_size=1,
    max_size=4,
)


def _safetensors(tensors: list[tuple[tuple[str, int], list[int]]]) -> bytes:
    header: dict[str, Any] = {"__metadata__": {"format": "pt"}}
    offset = 0
    for index, ((dtype, width), shape) in enumerate(tensors):
        size = width
        for dim in shape:
            size *= dim
        header[f"t{index}"] = {
            "dtype": dtype,
            "shape": shape,
            "data_offsets": [offset, offset + size],
        }
        offset += size
    raw = json.dumps(header).encode()
    return struct.pack("<Q", len(raw)) + raw + b"\0" * offset


def _inspect(payload: bytes) -> SerializationSafety:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "model.safetensors"
        path.write_bytes(payload)
        return inspect_model_format(path)[0]


@settings(PROPERTY_SETTINGS, max_examples=60)
@given(TENSORS, st.data())
def test_safetensors_inspection_accepts_exact_layouts_and_rejects_truncation(tensors, data):
    payload = _safetensors(tensors)
    assert _inspect(payload) is SerializationSafety.SAFE
    cut = data.draw(st.integers(min_value=0, max_value=len(payload) - 1))
    assert _inspect(payload[:cut]) is SerializationSafety.UNKNOWN
    assert _inspect(payload + b"\0") is SerializationSafety.UNKNOWN


def _opens_no_pickle(payload: bytes) -> bool:
    """Whether no opcode reads the first byte, or the second after an opcode with no argument."""
    if payload[0] in _ARGLESS_OPCODE_BYTES and len(payload) > 1:
        return payload[1] not in _OPCODE_BYTES
    return payload[0] not in _OPCODE_BYTES


def _wrapped_or_gguf(payload: bytes) -> bool:
    """Whether the scanner reads ``payload`` as a compressed or archived stream or GGUF."""
    return (
        payload.startswith((*_WRAPPER_MAGIC, _GGUF_MAGIC))
        or _lzma_alone_header(payload)
        or payload[_TAR_MAGIC_OFFSET : _TAR_MAGIC_OFFSET + len(_TAR_MAGIC)] == _TAR_MAGIC
        or _tar_header(payload)
    )


@settings(PROPERTY_SETTINGS, max_examples=80)
@given(st.binary(max_size=512), st.sampled_from([".safetensors", ".bin", ".pkl"]))
@example(b"\x1f\x8b\x08\x00", ".bin")
@example(b"\x78\x9c\x01\x02", ".pkl")
@example(b"\xfd7zXZ\x00\x00", ".bin")
@example(b"\x04\x22\x4d\x18\x00", ".pkl")
@example(b"\x5d\x00\x10\x00\x00" + b"\xff" * 8 + b"\x00", ".pkl")
@example(bytes(148) + b"000460\0 " + b"0" + bytes(355), ".bin")
@example(bytes(_TAR_MAGIC_OFFSET) + _TAR_MAGIC + bytes(250), ".pkl")
def test_model_inspection_classifies_arbitrary_bytes_without_raising(payload, suffix):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"model{suffix}"
        path.write_bytes(payload)
        safety, reason = inspect_model_format(path)
    assert isinstance(safety, SerializationSafety)
    assert reason
    if suffix in (".pkl", ".bin"):
        assert safety is not SerializationSafety.SAFE
        if not payload:
            assert (safety, reason) == (SerializationSafety.UNKNOWN, PICKLE_NAME_EMPTY)
        elif _wrapped_or_gguf(payload):
            assert safety is SerializationSafety.UNSAFE_CODE_EXECUTION
            assert reason in (PICKLE_NAME_WRAPPED, PICKLE_NAME_GGUF)
        elif (
            _opens_no_pickle(payload)
            and payload[:4] not in (b"PK\x03\x04", b"PK\x05\x06")
            and not b"\x93NUMPY".startswith(payload[:6])
        ):
            # Bytes that start no pickle, ZIP archive, NumPy array or wrapper are no evidence.
            assert (safety, reason) == (SerializationSafety.UNKNOWN, PICKLE_NAME_UNEVIDENCED)


@settings(PROPERTY_SETTINGS, max_examples=60)
@given(
    st.integers(min_value=0, max_value=2**24 - 1),
    st.none() | st.integers(min_value=0, max_value=2**63 - 1),
    st.binary(max_size=64),
    st.sampled_from([".pkl", ".bin", ".joblib"]),
)
@example(16, 2**63 - 1, b"", ".pkl")
def test_an_lzma_alone_header_under_a_pickle_family_name_is_a_wrapped_stream(
    dictionary_units, unpacked, tail, suffix
):
    # joblib unwraps content that starts 5d 00 whatever the rest of the dictionary size.
    size = b"\xff" * 8 if unpacked is None else unpacked.to_bytes(8, "little")
    header = b"\x5d" + (dictionary_units * 256).to_bytes(4, "little") + size
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"model{suffix}"
        path.write_bytes(header + b"\0" + tail)
        verdict = inspect_model_format(path)
    assert verdict == (SerializationSafety.UNSAFE_CODE_EXECUTION, PICKLE_NAME_WRAPPED)


def _signed(byte: int) -> int:
    return byte - 256 if byte > 0x7F else byte


def _tar_number(width: int) -> st.SearchStrategy[bytes]:
    """A number field that tarfile parses: octal text, cut at a NUL, or base-256."""
    octal = st.tuples(
        st.integers(min_value=0, max_value=8 ** (width - 1) - 1),
        st.sampled_from([b"0", b" "]),
        st.binary(max_size=width),
    ).map(lambda parts: ((b"%o" % parts[0]).rjust(width - 1, parts[1]) + b"\0" + parts[2])[:width])
    base256 = st.tuples(
        st.sampled_from([b"\x80", b"\xff"]), st.binary(min_size=width - 1, max_size=width - 1)
    ).map(b"".join)
    return octal | base256 | st.just(bytes(width)) | st.just(b" " * width)


@settings(PROPERTY_SETTINGS, max_examples=60)
@given(
    st.text(st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_-/"), max_size=99),
    st.integers(min_value=0, max_value=255),
    st.tuples(*(_tar_number(width) for width in (8, 8, 8, 12, 12))).map(b"".join),
    st.binary(min_size=172, max_size=172),
    st.tuples(_tar_number(8), _tar_number(8)).map(b"".join),
    st.binary(min_size=167, max_size=167),
    st.booleans(),
    st.sampled_from(["zero-padded", "space-padded", "base-256"]),
    st.binary(max_size=64),
    st.sampled_from([".pt", ".ckpt"]),
)
def test_a_tar_header_with_a_valid_checksum_under_a_torch_name_is_a_wrapped_stream(
    name, typeflag, fields, links, devices, rest, signed, encoding, tail, suffix
):
    # tarfile reads a first block whatever its name and type when its checksum matches and
    # its number fields parse; the name alphabet holds no newline or STOP, so the block
    # never reads as a pickle.
    block = bytearray(512)
    block[: len(name)] = name.encode()
    block[100:148] = fields
    block[156] = typeflag
    block[157:329] = links
    block[329:345] = devices
    block[345:] = rest
    checksum = 256 + sum(_signed(byte) if signed else byte for byte in block)
    if checksum >= 0 and encoding == "zero-padded":
        block[148:156] = b"%06o\0 " % checksum
    elif checksum >= 0 and encoding == "space-padded":
        block[148:156] = b"%7o\0" % checksum
    else:
        block[148:156] = (b"\x80" if checksum >= 0 else b"\xff") + (checksum % 256**7).to_bytes(
            7, "big"
        )
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"model{suffix}"
        path.write_bytes(bytes(block) + tail)
        verdict = inspect_model_format(path)
    assert verdict == (SerializationSafety.UNSAFE_CODE_EXECUTION, PICKLE_NAME_WRAPPED)


@settings(PROPERTY_SETTINGS, max_examples=60)
@given(st.binary(max_size=512), st.sampled_from([".bin", ".pkl", ".pt"]))
def test_gguf_magic_under_a_pickle_family_name_is_critical_whatever_follows(tail, suffix):
    # 'G' is an opcode byte, so the property above never reaches these bytes; llama.cpp
    # opens a model by this magic, and the chat-template check runs only under .gguf.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"model{suffix}"
        path.write_bytes(b"GGUF" + tail)
        verdict = inspect_model_format(path)
    assert verdict == (SerializationSafety.UNSAFE_CODE_EXECUTION, PICKLE_NAME_GGUF)
