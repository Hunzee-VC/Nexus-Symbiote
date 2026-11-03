"""Property-based checks for parsers, canonical hashing and bounded inspection."""

from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.hashing import canonical_json, hash_tool_definition, parse_json_strict
from nexus_symbiote.runtime import AuthorizationError, strict_json
from nexus_symbiote.runtime_validation import ValidationBudgetError, check_json_budget
from nexus_symbiote.scanners.base import sanitized_origin
from nexus_symbiote.scanners.model import inspect_model_format

PROPERTY_SETTINGS = settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
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


@settings(PROPERTY_SETTINGS, max_examples=80)
@given(st.binary(max_size=512), st.sampled_from([".safetensors", ".bin", ".pkl"]))
def test_model_inspection_classifies_arbitrary_bytes_without_raising(payload, suffix):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"model{suffix}"
        path.write_bytes(payload)
        safety, reason = inspect_model_format(path)
    assert isinstance(safety, SerializationSafety)
    assert reason
    if suffix == ".pkl":
        assert safety is SerializationSafety.UNSAFE_CODE_EXECUTION
    if suffix == ".bin":
        assert safety is not SerializationSafety.SAFE
