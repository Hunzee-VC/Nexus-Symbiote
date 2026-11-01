"""Per-tensor digests inside safetensors files (``spec/digests.md §3.10``)."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from pydantic import Field

from symbiote.digest.envelope import envelope_digest
from symbiote.digest.jcs import UndigestableError
from symbiote.digest.merkle import merkle_root
from symbiote.model.base import SymbioteModel
from symbiote.model.common import DigestResult, DigestStr

SAFETENSORS_MAX_HEADER = 100 * 1024 * 1024  # the reference implementation's limit


class TensorEntry(SymbioteModel):
    name: str
    dtype: str
    shape: list[int]
    digest: DigestStr


class TensorManifest(SymbioteModel):
    file: str
    format: str = "safetensors"
    tensors: list[TensorEntry]
    root: DigestStr
    metadata_digest: DigestStr | None = Field(
        default=None, description="digest of the __metadata__ header block, if any"
    )


def parse_safetensors_header(data: bytes) -> tuple[dict, int]:
    """Return ``(header_json, data_start)`` for a safetensors byte string."""
    if len(data) < 8:
        raise UndigestableError("safetensors-truncated", "fewer than 8 bytes")
    (n,) = struct.unpack("<Q", data[:8])
    if n > SAFETENSORS_MAX_HEADER or 8 + n > len(data):
        raise UndigestableError("safetensors-header", f"header length {n} out of range")
    try:
        header = json.loads(data[8 : 8 + n].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UndigestableError("safetensors-header", str(exc)) from exc
    if not isinstance(header, dict):
        raise UndigestableError("safetensors-header", "header is not an object")
    return header, 8 + n


def tensor_manifest_from_bytes(name: str, data: bytes) -> TensorManifest:
    header, start = parse_safetensors_header(data)
    tensors: list[TensorEntry] = []
    metadata_digest: str | None = None
    for tname, info in header.items():
        if tname == "__metadata__":
            metadata_digest = (
                "sha256:"
                + hashlib.sha256(json.dumps(info, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            )
            continue
        if not isinstance(info, dict) or "data_offsets" not in info:
            raise UndigestableError("safetensors-header", f"tensor {tname!r} has no data_offsets")
        begin, end = info["data_offsets"]
        if not (0 <= begin <= end <= len(data) - start):
            raise UndigestableError("safetensors-header", f"tensor {tname!r} offsets out of range")
        digest = "sha256:" + hashlib.sha256(data[start + begin : start + end]).hexdigest()
        tensors.append(
            TensorEntry(
                name=tname,
                dtype=str(info.get("dtype", "")),
                shape=[int(s) for s in info.get("shape", [])],
                digest=digest,
            )
        )
    tensors.sort(key=lambda t: t.name.encode("utf-8"))
    leaves = [hashlib.sha256(b"\x00" + bytes.fromhex(t.digest[7:])).digest() for t in tensors]
    return TensorManifest(
        file=name,
        tensors=tensors,
        root="sha256:" + merkle_root(leaves).hex(),
        metadata_digest=metadata_digest,
    )


def tensor_manifest(path: Path) -> TensorManifest:
    path = Path(path)
    return tensor_manifest_from_bytes(path.name, path.read_bytes())


def tensormanifest_digest(manifest: TensorManifest) -> DigestResult:
    """``tensormanifest/v1`` envelope digest."""
    return envelope_digest(
        "tensormanifest/v1",
        {
            "file": manifest.file,
            "format": manifest.format,
            "tensors": [t.to_json_dict() for t in manifest.tensors],
        },
    )


__all__ = [
    "TensorEntry",
    "TensorManifest",
    "parse_safetensors_header",
    "tensor_manifest",
    "tensor_manifest_from_bytes",
    "tensormanifest_digest",
]
