"""Bounded SafeTensors metadata fingerprints; tensor bytes require whole-file hashes."""

from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO

from nexus_symbiote.core.hashing import hash_bytes, hash_canonical, parse_json_strict
from nexus_symbiote.utils.confined import MAX_HASH_BYTES, ConfinedCollection

MAX_HEADER_BYTES = 1024 * 1024
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


def fingerprint_stream(stream: BinaryIO, *, artifact_size: int | None = None) -> dict[str, str]:
    """Fingerprint a structurally valid header without deserializing tensor values."""
    size = os.fstat(stream.fileno()).st_size if artifact_size is None else artifact_size
    prefix = stream.read(8)
    if len(prefix) != 8:
        raise ValueError("missing SafeTensors header")
    length = int.from_bytes(prefix, "little")
    if not 2 <= length <= MAX_HEADER_BYTES or length > size - 8:
        raise ValueError("invalid SafeTensors header length")
    raw = stream.read(length)
    if len(raw) != length or not raw.startswith(b"{"):
        raise ValueError("invalid SafeTensors header")
    header = parse_json_strict(raw, max_bytes=MAX_HEADER_BYTES)
    if not isinstance(header, dict):
        raise ValueError("invalid SafeTensors object")
    data_bytes = size - 8 - length
    inventory: list[dict[str, object]] = []
    spans: list[tuple[int, int]] = []
    for name, meta in header.items():
        if name == "__metadata__":
            if not isinstance(meta, dict) or not all(isinstance(v, str) for v in meta.values()):
                raise ValueError("invalid SafeTensors metadata")
            continue
        if not isinstance(meta, dict) or set(meta) != {"dtype", "shape", "data_offsets"}:
            raise ValueError("invalid tensor descriptor")
        dtype, shape, offsets = meta["dtype"], meta["shape"], meta["data_offsets"]
        if not isinstance(dtype, str) or dtype not in DTYPE_BYTES:
            raise ValueError("unsupported tensor dtype")
        if (
            not isinstance(shape, list)
            or len(shape) > 64
            or not all(type(n) is int and 0 <= n <= MAX_HASH_BYTES for n in shape)
        ):
            raise ValueError("invalid tensor shape")
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or not all(type(n) is int and 0 <= n <= data_bytes for n in offsets)
        ):
            raise ValueError("invalid tensor offsets")
        start, end = offsets
        elements = 1
        for n in shape:
            elements *= n
        if end < start or end - start != elements * DTYPE_BYTES[dtype]:
            raise ValueError("tensor shape disagrees with byte span")
        spans.append((start, end))
        inventory.append({"name": name, "dtype": dtype, "shape": shape, "offsets": offsets})
    cursor = 0
    for start, end in sorted(spans):
        if start != cursor:
            raise ValueError("tensor spans contain holes or overlap")
        cursor = end
    if cursor != data_bytes:
        raise ValueError("tensor payload is not fully indexed")
    return {
        "safetensors_header_sha256": hash_bytes(raw),
        "tensor_inventory_sha256": hash_canonical(
            {"tensors": sorted(inventory, key=lambda x: str(x["name"]))}
        ),
        "tensor_count": str(len(inventory)),
    }


def safetensors_fingerprint(
    path: Path, *, root: Path, expected_digest: str | None = None
) -> dict[str, str]:
    """Bind metadata and complete-file hash to one confined artifact observation."""
    from nexus_symbiote.core.enums import SerializationSafety
    from nexus_symbiote.scanners.model import inspect_model_artifact

    metadata: dict[str, str] = {}
    with (
        ConfinedCollection(root, [], max_total_bytes=MAX_HASH_BYTES) as files,
        files.open_regular(path, max_bytes=MAX_HASH_BYTES) as stream,
    ):
        safety, _, digest = inspect_model_artifact(path, stream=stream, metadata=metadata)
    if safety != SerializationSafety.SAFE or not metadata:
        raise ValueError("SafeTensors metadata could not be corroborated")
    if expected_digest is not None and expected_digest != digest:
        raise ValueError("Tensor metadata belongs to different artifact bytes")
    return metadata
