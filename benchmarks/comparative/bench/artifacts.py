"""Deterministic builders for binary fixtures, written with the standard library only.

Nothing here loads a model or unpickles anything. The executing pickles are assembled
opcode by opcode; the corpus never deserializes them.
"""

from __future__ import annotations

import hashlib
import io
import json
import struct
import zipfile
from collections.abc import Sequence

GGUF_STRING = 8
GGUF_UINT32 = 4
GgufValue = str | int


def digest_bytes(label: str, size: int) -> bytes:
    """Reproducible filler bytes derived from a label."""
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"{label}:{counter}".encode()).digest()
        counter += 1
    return out[:size]


def hex40(label: str) -> str:
    """A reproducible 40-digit hexadecimal revision."""
    return hashlib.sha1(f"comparative-bench:{label}".encode(), usedforsecurity=False).hexdigest()


def hex64(label: str) -> str:
    return hashlib.sha256(f"comparative-bench:{label}".encode()).hexdigest()


def synthetic_secret(label: str, prefix: str, length: int, alphabet: str) -> str:
    """A token-shaped canary that exists only in a materialized corpus.

    It is derived, never written in this repository, so no literal credential
    pattern is committed.
    """
    stream = digest_bytes(f"secret:{label}", length)
    return prefix + "".join(alphabet[byte % len(alphabet)] for byte in stream)


def safetensors(
    tensors: Sequence[tuple[str, str, Sequence[int], bytes]],
    metadata: dict[str, str] | None = None,
) -> bytes:
    header: dict[str, object] = {}
    if metadata is not None:
        header["__metadata__"] = metadata
    offset = 0
    payload = b""
    for name, dtype, shape, data in tensors:
        header[name] = {
            "dtype": dtype,
            "shape": list(shape),
            "data_offsets": [offset, offset + len(data)],
        }
        offset += len(data)
        payload += data
    encoded = json.dumps(header, separators=(",", ":")).encode()
    encoded += b" " * ((8 - len(encoded) % 8) % 8)
    return struct.pack("<Q", len(encoded)) + encoded + payload


def _gguf_string(value: str) -> bytes:
    raw = value.encode()
    return struct.pack("<Q", len(raw)) + raw


def gguf(metadata: Sequence[tuple[str, GgufValue]], tensor_label: str = "weights") -> bytes:
    """A valid GGUF version 3 file with one small F32 tensor."""
    out = b"GGUF" + struct.pack("<IQQ", 3, 1, len(metadata))
    for key, value in metadata:
        out += _gguf_string(key)
        if isinstance(value, str):
            out += struct.pack("<I", GGUF_STRING) + _gguf_string(value)
        else:
            out += struct.pack("<II", GGUF_UINT32, value)
    out += _gguf_string("token_embd.weight") + struct.pack("<IQIQ", 1, 8, 0, 0)
    out += b"\0" * ((32 - len(out) % 32) % 32)
    return out + digest_bytes(tensor_label, 32)


def _pb_bytes(field_number: int, value: bytes) -> bytes:
    return bytes([(field_number << 3) | 2, len(value)]) + value


def _pb_varint(field_number: int, value: int) -> bytes:
    return bytes([field_number << 3, value])


def onnx(producer: str, graph_name: str) -> bytes:
    """A minimal ONNX ModelProto: IR version, producer, opset import and an empty graph."""
    return (
        _pb_varint(1, 9)
        + _pb_bytes(2, producer.encode())
        + _pb_bytes(3, b"1.0")
        + _pb_bytes(7, _pb_bytes(1, graph_name.encode()))
        + _pb_bytes(8, _pb_varint(2, 21))
    )


def pickle_benign(label: str) -> bytes:
    """Protocol 2 pickle of ``{"weights": [float, float]}``, assembled by hand."""
    key = b"weights"
    floats = digest_bytes(label, 16)
    return (
        b"\x80\x02}q\x00(X"
        + struct.pack("<I", len(key))
        + key
        + b"q\x01]q\x02(G"
        + floats[:8]
        + b"G"
        + floats[8:]
        + b"eu."
    )


def pickle_exec(module: str, name: str, argument: str) -> bytes:
    """Protocol 2 pickle that calls ``module.name(argument)`` when loaded.

    GLOBAL, BINUNICODE, TUPLE1, REDUCE, STOP. The corpus never loads it.
    """
    raw = argument.encode()
    return (
        b"\x80\x02c"
        + module.encode()
        + b"\n"
        + name.encode()
        + b"\nq\x00X"
        + struct.pack("<I", len(raw))
        + raw
        + b"q\x01\x85q\x02Rq\x03."
    )


def zip_stored(entries: Sequence[tuple[str, bytes]]) -> bytes:
    """An uncompressed archive with fixed timestamps, so its bytes never vary."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def torch_archive(stem: str, data_pkl: bytes) -> bytes:
    """The layout ``torch.save`` writes: a zip with ``data.pkl`` and a tensor blob."""
    return zip_stored(
        [
            (f"{stem}/data.pkl", data_pkl),
            (f"{stem}/byteorder", b"little"),
            (f"{stem}/data/0", digest_bytes(f"torch:{stem}", 64)),
            (f"{stem}/version", b"3\n"),
        ]
    )


def keras_archive(layers: Sequence[dict[str, object]]) -> bytes:
    """A Keras 3 ``.keras`` archive. The weights member is a placeholder, not HDF5 data."""
    config = {
        "module": "keras",
        "class_name": "Sequential",
        "config": {"name": "sequential", "layers": list(layers)},
    }
    metadata = {"keras_version": "3.6.0", "date_saved": "2026-01-01@00:00:00"}
    return zip_stored(
        [
            ("metadata.json", json.dumps(metadata, sort_keys=True).encode()),
            ("config.json", json.dumps(config, sort_keys=True).encode()),
            ("model.weights.h5", b"\x89HDF\r\n\x1a\n" + b"\0" * 56),
        ]
    )


def faiss_flat_index(dimension: int, label: str) -> bytes:
    """Bytes shaped like a FAISS ``IndexFlatL2`` header followed by vectors."""
    return b"IxF2" + struct.pack("<iqqq", dimension, 2, 1 << 20, 1 << 20) + digest_bytes(label, 64)
