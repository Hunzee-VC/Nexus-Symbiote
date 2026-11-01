"""Additional format and lineage cases for WP3 (coverage of the less common paths)."""

from __future__ import annotations

import json
import os
import struct
import zipfile
from pathlib import Path

import pytest

from symbiote.models_identity.hf import analyze_model_dir
from symbiote.models_identity.serialization import (
    assess_file,
    iter_model_files,
    read_safetensors_header,
    sniff_format,
)


def _gguf_string(value: str) -> bytes:
    data = value.encode()
    return struct.pack("<Q", len(data)) + data


def _npy_bytes(descr: str) -> bytes:
    header = f"{{'descr': '{descr}', 'fortran_order': False, 'shape': (1,), }}"
    header += " " * (63 - len(header) % 64) + "\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header.encode() + b"\x00" * 8


def test_npz_with_object_member(tmp_path: Path) -> None:
    path = tmp_path / "arrays.npz"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.npy", _npy_bytes("<f4"))
        zf.writestr("b.npy", _npy_bytes("|O"))
    result = assess_file(path)
    assert result.format == "npz"
    assert result.risk_class == "code-exec-on-load"
    assert any("b.npy" in r for r in result.reasons)


def test_keras_h5_lambda_heuristic(tmp_path: Path) -> None:
    path = tmp_path / "model.h5"
    path.write_bytes(b"\x89HDF\r\n\x1a\n" + b"\x00" * 64 + b'{"class_name": "Lambda", "config": {}}')
    result = assess_file(path)
    assert result.format == "keras-h5"
    assert result.risk_class == "code-exec-on-load"


def test_keras_h5_plain_is_low(tmp_path: Path) -> None:
    path = tmp_path / "model.h5"
    path.write_bytes(b"\x89HDF\r\n\x1a\n" + b"\x00" * 64)
    assert assess_file(path).risk_class == "low"


def test_tf_savedmodel_io_ops(tmp_path: Path) -> None:
    model = tmp_path / "saved"
    model.mkdir()
    (model / "saved_model.pb").write_bytes(b"\x08\x01 graph WriteFile ReadFile")
    result = assess_file(model)
    assert result.format == "tf-savedmodel"
    assert result.risk_class == "low"
    assert any("ReadFile" in r and "WriteFile" in r for r in result.reasons)


def test_mlflow_and_unknown_directories(tmp_path: Path) -> None:
    ml = tmp_path / "ml"
    ml.mkdir()
    (ml / "MLmodel").write_text("flavors:\n  python_function:\n    loader_module: mlflow.sklearn\n")
    assert sniff_format(ml) == "mlflow-pyfunc"
    assert assess_file(ml).risk_class == "code-exec-on-load"
    other = tmp_path / "other"
    other.mkdir()
    assert sniff_format(other) == "other"


@pytest.mark.parametrize(
    ("name", "content", "fmt"),
    [
        ("model.joblib", b"\x78\x9c compressed", "joblib"),
        ("state.pkl", b"(lp0\nI1\na.", "pickle"),
        ("model.onnx", b"\x08\x07\x12\x04onnx", "onnx"),
        ("weights.unknown", b"\x00\x01\x02", "other"),
        ("archive.zip", b"PK\x03\x04garbage", "other"),
    ],
)
def test_extension_fallbacks(tmp_path: Path, name: str, content: bytes, fmt: str) -> None:
    path = tmp_path / name
    path.write_bytes(content)
    assert sniff_format(path) == fmt


def test_protocol0_pickle_by_extension_is_scanned(tmp_path: Path) -> None:
    path = tmp_path / "legacy.pkl"
    path.write_bytes(b"cos\nsystem\n(S'id'\ntR.")
    result = assess_file(path)
    assert result.format == "pickle"
    assert result.malicious_indicators


@pytest.mark.parametrize(
    ("payload", "anomaly"),
    [
        (struct.pack("<Q", 10**12) + b"{}", "header-length-out-of-bounds"),
        (struct.pack("<Q", 4) + b"nope" + b"\x00", "header-not-json"),
        (struct.pack("<Q", 2) + b"[]", "header-not-object"),
        (b"\x01\x02", "truncated-header-length"),
    ],
)
def test_safetensors_rejects_bad_headers(tmp_path: Path, payload: bytes, anomaly: str) -> None:
    path = tmp_path / "x.safetensors"
    path.write_bytes(payload)
    assert anomaly in read_safetensors_header(path).anomalies


def test_safetensors_field_anomalies(tmp_path: Path) -> None:
    header = {
        "__metadata__": {"format": 1},
        "a": {"dtype": "Q99", "shape": [1], "data_offsets": [0, 4]},
        "b": {"dtype": "F32", "shape": "bad", "data_offsets": [4, 8]},
        "c": {"dtype": "F32", "shape": [1], "data_offsets": [8, 4]},
        "d": "not-an-object",
        "e": {"dtype": "F32", "shape": [1], "data_offsets": [16, 20]},
    }
    raw = json.dumps(header).encode()
    path = tmp_path / "f.safetensors"
    path.write_bytes(struct.pack("<Q", len(raw)) + raw + b"\x00" * 24)
    anomalies = read_safetensors_header(path).anomalies
    for expected in (
        "metadata-not-string-map",
        "unknown-dtype:a",
        "bad-shape:b",
        "bad-offsets:c",
        "tensor-entry-not-object:d",
        "gap-between-tensors",
    ):
        assert expected in anomalies


def test_mergekit_gguf_and_jinja_lineage(tmp_path: Path) -> None:
    (tmp_path / "mergekit_config.yml").write_text(
        "merge_method: slerp\nbase_model: org/base\nmodels:\n  - model: org/a\n  - model: org/b\n"
    )
    (tmp_path / "chat_template.jinja").write_text("{{ messages | length }}")
    (tmp_path / "tokenizer_config.json").write_text(
        json.dumps(
            {
                "chat_template": [{"name": "tool_use", "template": "{{ tools }}"}],
                "auto_map": {"AutoTokenizer": ["t.T", None]},
            }
        )
    )
    kv = [
        ("general.source.huggingface.repository", 8, _gguf_string("org/merged")),
        ("general.name", 8, _gguf_string("merged")),
    ]
    body = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", len(kv))
    for key, vtype, value in kv:
        body += _gguf_string(key) + struct.pack("<I", vtype) + value
    (tmp_path / "merged.Q4_K_M.gguf").write_bytes(body)
    (tmp_path / "README.md").write_text("---\nbase_model:\n  - org/a\n---\n")
    result = analyze_model_dir(tmp_path)
    kinds = {(d.kind, d.parent) for d in result.derivations}
    assert {
        ("mergeOf", "org/a"),
        ("mergeOf", "org/b"),
        ("mergeOf", "org/base"),
        ("conversionOf", "org/merged"),
    } <= kinds
    sources = {t.source for t in result.chat_templates}
    assert "chat_template.jinja" in sources
    assert "tokenizer_config.json#/chat_template/0" in sources
    assert result.trust_remote_code is True  # tokenizer auto_map


def test_bad_json_and_card_are_warnings(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text("{not json")
    (tmp_path / "README.md").write_text("---\n: : bad\n  - [\n---\n")
    result = analyze_model_dir(tmp_path)
    assert any("config.json" in w for w in result.warnings)
    assert result.trust_remote_code is None


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_iter_model_files_skips_git_and_symlinks(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("x")
    (tmp_path / "a.bin").write_bytes(b"x")
    (tmp_path / "link.bin").symlink_to(tmp_path / "a.bin")
    assert [p.name for p in iter_model_files(tmp_path)] == ["a.bin"]
    assert list(iter_model_files(tmp_path, max_files=0)) == []


def test_unreadable_file_is_reported(tmp_path: Path) -> None:
    missing = tmp_path / "gone.bin"
    result = assess_file(missing)
    assert result.format == "other"
    assert result.reasons[0].startswith("unreadable")


def test_zip_member_truncation_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import symbiote.models_identity.serialization as ser

    monkeypatch.setattr(ser, "MAX_PICKLE_BYTES", 8)
    path = tmp_path / "big.pt"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("archive/data.pkl", b"\x80\x02" + b"N" * 32 + b".")
    result = assess_file(path)
    assert result.pickle_scans[0][1].truncated
