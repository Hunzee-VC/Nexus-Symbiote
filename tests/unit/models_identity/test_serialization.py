"""Tests for static serialization-risk analysis. Hostile fixtures are raw opcode bytes, never executed."""

from __future__ import annotations

import collections
import json
import pickle
import struct
import zipfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from symbiote.models_identity.serialization import (
    assess_file,
    classify_global,
    max_risk,
    read_gguf_metadata,
    read_safetensors_header,
    scan_chat_template,
    scan_pickle_bytes,
    sniff_format,
)

# protocol 2: GLOBAL 'posix system', BINUNICODE 'id', TUPLE1, REDUCE, STOP  (a classic RCE payload shape)
P2_SYSTEM = b"\x80\x02cposix\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03."
# protocol 4 with memo indirection: SHORT_BINUNICODE os, MEMOIZE, SHORT_BINUNICODE system, MEMOIZE,
# BINGET 0, BINGET 1, STACK_GLOBAL, SHORT_BINUNICODE id, TUPLE1, REDUCE, STOP
P4_MEMO_SYSTEM = b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94h\x00h\x01\x93\x8c\x02id\x85R."
# nullifAI shape: the payload comes first, then a deliberately invalid opcode breaks the stream
NULLIFAI = b"\x80\x02cbuiltins\nexec\nq\x00X\x04\x00\x00\x00passq\x01\x85q\x02Rq\x03\xff\xfe"


def test_protocol2_global_is_dangerous() -> None:
    scan = scan_pickle_bytes(P2_SYSTEM)
    assert scan.protocol == 2
    assert [g.qualified for g in scan.dangerous] == ["posix.system"]
    assert "REDUCE" in scan.exec_opcodes
    assert scan.verdict == "malicious-indicators"
    assert not scan.malformed


def test_stack_global_resolved_through_memo() -> None:
    scan = scan_pickle_bytes(P4_MEMO_SYSTEM)
    assert [g.qualified for g in scan.globals] == ["os.system"]
    assert scan.globals[0].opcode == "STACK_GLOBAL"
    assert scan.verdict == "malicious-indicators"


def test_benign_ordereddict_has_no_indicators() -> None:
    data = pickle.dumps(collections.OrderedDict(weight=1.0), protocol=4)
    scan = scan_pickle_bytes(data)
    assert [g.qualified for g in scan.globals] == ["collections.OrderedDict"]
    assert scan.globals[0].verdict == "safe"
    assert scan.verdict == "no-indicators"


def test_nullifai_broken_stream_still_reports_payload() -> None:
    scan = scan_pickle_bytes(NULLIFAI)
    assert scan.malformed
    assert scan.error
    assert [g.qualified for g in scan.dangerous] == ["builtins.exec"]
    assert scan.verdict == "malicious-indicators"


@pytest.mark.parametrize(
    ("module", "name", "verdict"),
    [
        ("torch._utils", "_rebuild_tensor_v2", "safe"),
        ("torch", "FloatStorage", "safe"),
        ("torch", "bfloat16", "safe"),
        ("builtins", "eval", "dangerous"),
        ("__builtin__", "getattr", "dangerous"),
        ("subprocess", "Popen", "dangerous"),
        ("operator", "attrgetter", "dangerous"),
        ("numpy.testing._private.utils", "runstring", "dangerous"),
        ("torch.storage", "_load_from_bytes", "dangerous"),
        ("mypackage.models", "Net", "unknown"),
    ],
)
def test_classify_global(module: str, name: str, verdict: str) -> None:
    assert classify_global(module, name) == verdict


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=512))
def test_scanner_never_raises_on_arbitrary_bytes(data: bytes) -> None:
    scan = scan_pickle_bytes(data)
    assert scan.bytes_scanned == len(data)


def _write_torch_zip(path: Path, payload: bytes) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("archive/data.pkl", payload)
        zf.writestr("archive/version", "3\n")
        zf.writestr("archive/data/0", b"\x00" * 16)


def test_torch_zip_benign_and_malicious(tmp_path: Path) -> None:
    benign = tmp_path / "pytorch_model.bin"
    _write_torch_zip(benign, pickle.dumps(collections.OrderedDict(), protocol=2))
    result = assess_file(benign)
    assert result.format == "torch-zip"
    assert result.risk_class == "code-exec-on-load"
    assert not result.malicious_indicators

    bad = tmp_path / "evil.pt"
    _write_torch_zip(bad, P2_SYSTEM)
    result_bad = assess_file(bad)
    assert result_bad.malicious_indicators
    assert result_bad.pickle_scans[0][0] == "archive/data.pkl"


def test_legacy_pickle_disguised_as_bin(tmp_path: Path) -> None:
    path = tmp_path / "weights.bin"
    path.write_bytes(P2_SYSTEM)
    assert sniff_format(path) == "pickle"
    assert assess_file(path).malicious_indicators


def _safetensors(path: Path, header: dict[str, object], data: bytes) -> None:
    raw = json.dumps(header).encode()
    path.write_bytes(struct.pack("<Q", len(raw)) + raw + data)


def test_safetensors_valid(tmp_path: Path) -> None:
    path = tmp_path / "model.safetensors"
    header = {
        "__metadata__": {"format": "pt"},
        "a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
        "b": {"dtype": "F16", "shape": [2, 2], "data_offsets": [8, 16]},
    }
    _safetensors(path, header, b"\x00" * 16)
    assert sniff_format(path) == "safetensors"
    parsed = read_safetensors_header(path)
    assert parsed.anomalies == ()
    assert parsed.tensor_count == 2
    assert parsed.metadata_keys == ("format",)
    result = assess_file(path)
    assert result.risk_class == "none"


def test_safetensors_anomalies(tmp_path: Path) -> None:
    path = tmp_path / "bad.safetensors"
    header = {
        "a": {"dtype": "F32", "shape": [4], "data_offsets": [0, 8]},
        "b": {"dtype": "F32", "shape": [2], "data_offsets": [4, 12]},
    }
    _safetensors(path, header, b"\x00" * 12)
    anomalies = read_safetensors_header(path).anomalies
    assert "size-mismatch:a" in anomalies
    assert "overlapping-tensors" in anomalies


def test_safetensors_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "dup.safetensors"
    raw = b'{"a": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}, "a": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}'
    path.write_bytes(struct.pack("<Q", len(raw)) + raw + b"\x00" * 4)
    assert read_safetensors_header(path).anomalies == ("duplicate-keys",)


def _gguf_string(value: str) -> bytes:
    data = value.encode()
    return struct.pack("<Q", len(data)) + data


def _write_gguf(path: Path, kvs: list[tuple[str, int, bytes]]) -> None:
    body = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", len(kvs))
    for key, vtype, value in kvs:
        body += _gguf_string(key) + struct.pack("<I", vtype) + value
    path.write_bytes(body)


def test_gguf_chat_template_ssti(tmp_path: Path) -> None:
    template = "{% for c in ''.__class__.__mro__[1].__subclasses__() %}{{ c }}{% endfor %}"
    tokens = struct.pack("<I", 8) + struct.pack("<Q", 3) + b"".join(_gguf_string(t) for t in ("a", "b", "c"))
    path = tmp_path / "model.gguf"
    _write_gguf(
        path,
        [
            ("general.architecture", 8, _gguf_string("llama")),
            ("general.base_model.count", 4, struct.pack("<I", 1)),
            ("general.base_model.0.name", 8, _gguf_string("Base 7B")),
            ("general.base_model.0.repo_url", 8, _gguf_string("https://huggingface.co/org/base-7b")),
            ("tokenizer.ggml.tokens", 9, tokens),
            ("tokenizer.chat_template", 8, _gguf_string(template)),
        ],
    )
    meta = read_gguf_metadata(path)
    assert meta.error is None
    assert meta.values["general.architecture"] == "llama"
    assert meta.base_models == ({"name": "Base 7B", "repo_url": "https://huggingface.co/org/base-7b"},)
    assert len(meta.chat_templates) == 1
    assert "dunder-class-walk" in meta.chat_templates[0].ssti_indicators
    result = assess_file(path)
    assert result.format == "gguf"
    assert result.risk_class == "template-execution"
    assert result.malicious_indicators


def test_gguf_truncated_is_reported_not_raised(tmp_path: Path) -> None:
    path = tmp_path / "trunc.gguf"
    path.write_bytes(b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 5) + b"\x10")
    meta = read_gguf_metadata(path)
    assert meta.error


def _npy(path: Path, descr: str) -> None:
    header = f"{{'descr': '{descr}', 'fortran_order': False, 'shape': (1,), }}"
    header += " " * (63 - len(header) % 64) + "\n"
    path.write_bytes(b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header.encode() + b"\x00" * 8)


def test_npy_object_dtype_requires_pickle(tmp_path: Path) -> None:
    obj = tmp_path / "obj.npy"
    _npy(obj, "|O")
    assert assess_file(obj).risk_class == "code-exec-on-load"
    flt = tmp_path / "f.npy"
    _npy(flt, "<f4")
    assert assess_file(flt).risk_class == "none"


def test_keras_lambda_layer(tmp_path: Path) -> None:
    path = tmp_path / "model.keras"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            "config.json", json.dumps({"config": {"layers": [{"class_name": "Lambda", "config": {}}]}})
        )
        zf.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\n")
        zf.writestr("metadata.json", "{}")
    result = assess_file(path)
    assert result.format == "keras-v3"
    assert result.risk_class == "code-exec-on-load"


def test_7z_archive_is_opaque_and_high_risk(tmp_path: Path) -> None:
    path = tmp_path / "pytorch_model.bin"
    path.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)
    result = assess_file(path)
    assert result.format == "archive-7z"
    assert result.risk_class == "code-exec-on-load"


def test_chat_template_digest_and_clean_template() -> None:
    finding = scan_chat_template("x", "default", "{% for m in messages %}{{ m['content'] }}{% endfor %}")
    assert finding.ssti_indicators == ()
    assert finding.digest.startswith("sha256:") and len(finding.digest) == 71


def test_max_risk_order() -> None:
    assert max_risk([]) == "none"
    assert max_risk(["low", "template-execution", "none"]) == "template-execution"
    assert max_risk(["code-exec-on-load", "low"]) == "code-exec-on-load"
