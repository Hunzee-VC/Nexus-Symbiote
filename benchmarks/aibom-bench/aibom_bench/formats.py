"""Byte-exact encoders for the model-file fixtures.

Each encoder writes the smallest file that a format-aware parser accepts, so a tool is
credited for reading the format and not for trusting a file extension. Nothing here loads
or executes a model.
"""

from __future__ import annotations

import io
import json
import struct
import zipfile

GGUF_STRING = 8
GGUF_UINT32 = 4
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def _gguf_string(value: str) -> bytes:
    raw = value.encode()
    return struct.pack("<Q", len(raw)) + raw


def gguf(metadata: dict[str, str | int]) -> bytes:
    """A GGUF v3 file with metadata and no tensors."""
    body = b"GGUF" + struct.pack("<IQQ", 3, 0, len(metadata))
    for key, value in metadata.items():
        body += _gguf_string(key)
        if isinstance(value, int):
            body += struct.pack("<II", GGUF_UINT32, value)
        else:
            body += struct.pack("<I", GGUF_STRING) + _gguf_string(value)
    return body + b"\x00" * (-len(body) % 32)


def gguf_length_bomb() -> bytes:
    """A GGUF header that claims 2**62 metadata entries and tensors in a 24-byte file."""
    return b"GGUF" + struct.pack("<IQQ", 3, 2**62, 2**62)


def safetensors(metadata: dict[str, str], fill: int = 0) -> bytes:
    """A SafeTensors file holding one 2x2 float32 tensor."""
    header = json.dumps(
        {
            "__metadata__": metadata,
            "weight": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
        },
        separators=(",", ":"),
    ).encode()
    header += b" " * (-len(header) % 8)
    return struct.pack("<Q", len(header)) + header + bytes([fill]) * 16


def safetensors_length_bomb() -> bytes:
    """A SafeTensors file whose header length field claims 2**62 bytes."""
    return struct.pack("<Q", 2**62) + b'{"__metadata__":{}}'


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _field(number: int, payload: bytes | int) -> bytes:
    if isinstance(payload, int):
        return _varint(number << 3) + _varint(payload)
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def onnx(producer: str, graph: str, metadata: dict[str, str]) -> bytes:
    """An ONNX ModelProto with an empty graph, opset 17 and metadata properties."""
    body = _field(1, 9) + _field(2, producer.encode()) + _field(3, b"1.0.0")
    body += _field(7, _field(2, graph.encode()))
    body += _field(8, _field(2, 17))
    for key, value in metadata.items():
        body += _field(14, _field(1, key.encode()) + _field(2, value.encode()))
    return body


def system_call_pickle(command: str) -> bytes:
    """A protocol-0 pickle whose load calls ``os.system(command)``.

    Building these bytes runs nothing. The harness uses the command as a canary: it only
    creates a marker file, and that file existing after a scan shows the scanner
    deserialized the pickle.
    """
    return b"cos\nsystem\n(S" + repr(command).encode() + b"\ntR."


def torch_archive(name: str, data_pickle: bytes) -> bytes:
    """The zip layout ``torch.save`` writes, with the given ``data.pkl``."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for member, payload in (
            (f"{name}/data.pkl", data_pickle),
            (f"{name}/version", b"3\n"),
            (f"{name}/byteorder", b"little"),
        ):
            archive.writestr(zipfile.ZipInfo(member, ZIP_EPOCH), payload)
    return buffer.getvalue()
