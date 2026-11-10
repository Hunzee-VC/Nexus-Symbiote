"""The one SafeTensors header validator; tensor bytes require whole-file hashes.

The SAFE verdict and the tensor fingerprint both come from ``read_header`` so
the collector and the validator cannot disagree about the same bytes. The
rules follow the reference format: a UTF-8 JSON object, string metadata,
known dtypes, element counts that fit an unsigned 64-bit integer and tensor
spans that index the whole data region without holes or overlaps.
"""

from __future__ import annotations

import os
from typing import BinaryIO

from nexus_symbiote.core.hashing import hash_bytes, hash_canonical, parse_json_strict

MAX_HEADER_BYTES = 1024 * 1024
_U64 = 2**64
DTYPE_BYTES = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "F8_E4M3": 1,
    "F8_E4M3FN": 1,
    "F8_E5M2": 1,
    "I16": 2,
    "U16": 2,
    "F16": 2,
    "BF16": 2,
    "I32": 4,
    "U32": 4,
    "F32": 4,
    "I64": 8,
    "U64": 8,
    "F64": 8,
}

TensorEntry = dict[str, object]


class HeaderLimitError(ValueError):
    """A well-formed header length exceeds the inspection limit."""


def header_length(prefix: bytes, size: int, *, max_header_bytes: int = MAX_HEADER_BYTES) -> int:
    """Return the declared header length, or raise when it cannot index ``size`` bytes."""
    if len(prefix) != 8:
        raise ValueError("missing SafeTensors header length")
    length = int.from_bytes(prefix, "little")
    if not 2 <= length <= size - 8:
        raise ValueError("invalid SafeTensors header length")
    if length > max_header_bytes:
        raise HeaderLimitError("SafeTensors header exceeds the inspection limit")
    return length


def _tensor(name: str, entry: object, data_bytes: int) -> tuple[TensorEntry, tuple[int, int]]:
    if not isinstance(entry, dict) or set(entry) != {"dtype", "shape", "data_offsets"}:
        raise ValueError("invalid tensor descriptor")
    dtype, shape, offsets = entry["dtype"], entry["shape"], entry["data_offsets"]
    if not isinstance(dtype, str) or dtype not in DTYPE_BYTES:
        raise ValueError("unsupported tensor dtype")
    if (
        not isinstance(shape, list)
        or len(shape) > 64
        or not all(type(n) is int and 0 <= n < _U64 for n in shape)
    ):
        raise ValueError("invalid tensor shape")
    if (
        not isinstance(offsets, list)
        or len(offsets) != 2
        or not all(type(n) is int and 0 <= n <= data_bytes for n in offsets)
    ):
        raise ValueError("invalid tensor offsets")
    elements = 1
    for dim in shape:
        # The reference parser multiplies in order with overflow checks.
        elements *= dim
        if elements >= _U64:
            raise ValueError("tensor element count overflows")
    start, end = offsets
    if end < start or end - start != elements * DTYPE_BYTES[dtype]:
        raise ValueError("tensor shape disagrees with byte span")
    return {"name": name, "dtype": dtype, "shape": shape, "offsets": offsets}, (start, end)


def parse_header(raw: bytes, data_bytes: int) -> list[TensorEntry]:
    """Validate a raw header against the data region it must index exactly."""
    if not raw.startswith(b"{"):
        raise ValueError("invalid SafeTensors header")
    # json.loads would detect UTF-16 and UTF-32; the reference format is UTF-8 only.
    header = parse_json_strict(raw.decode("utf-8"), max_bytes=len(raw))
    if not isinstance(header, dict):
        raise ValueError("invalid SafeTensors object")
    inventory: list[TensorEntry] = []
    spans: list[tuple[int, int]] = []
    for name, entry in header.items():
        if name == "__metadata__":
            if not isinstance(entry, dict) or not all(isinstance(v, str) for v in entry.values()):
                raise ValueError("invalid SafeTensors metadata")
            continue
        tensor, span = _tensor(name, entry, data_bytes)
        inventory.append(tensor)
        spans.append(span)
    cursor = 0
    for start, end in sorted(spans):
        if start != cursor:
            raise ValueError("tensor spans contain holes or overlap")
        cursor = end
    if cursor != data_bytes:
        raise ValueError("tensor payload is not fully indexed")
    return inventory


def read_header(
    stream: BinaryIO,
    size: int,
    *,
    prefix: bytes | None = None,
    max_header_bytes: int = MAX_HEADER_BYTES,
) -> tuple[bytes, list[TensorEntry]]:
    """Read and validate the header of a ``size``-byte artifact from its start.

    Pass ``prefix`` when the caller has already consumed the 8-byte length.
    """
    length = header_length(
        stream.read(8) if prefix is None else prefix, size, max_header_bytes=max_header_bytes
    )
    raw = stream.read(length)
    if len(raw) != length:
        raise ValueError("truncated SafeTensors header")
    return raw, parse_header(raw, size - 8 - length)


def fingerprint_stream(
    stream: BinaryIO,
    *,
    artifact_size: int | None = None,
    max_header_bytes: int = MAX_HEADER_BYTES,
) -> dict[str, str]:
    """Fingerprint a structurally valid header without deserializing tensor values."""
    size = os.fstat(stream.fileno()).st_size if artifact_size is None else artifact_size
    raw, inventory = read_header(stream, size, max_header_bytes=max_header_bytes)
    return {
        "safetensors_header_sha256": hash_bytes(raw),
        "tensor_inventory_sha256": hash_canonical(
            {"tensors": sorted(inventory, key=lambda x: str(x["name"]))}
        ),
        "tensor_count": str(len(inventory)),
    }
