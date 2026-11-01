"""Canonical hashing for AgentBOM components.

Implements RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic
hashing of tool definitions, prompt templates, and other mutable artifacts.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import rfc8785


def canonical_json(data: Any) -> str:
    """Serialize I-JSON to RFC 8785 bytes, rejecting unsupported values.

    Hashes made by releases before this correction may differ. Do not compare
    old and new fingerprints without re-collecting both snapshots.
    """
    return rfc8785.dumps(data).decode("utf-8")


def hash_canonical(data: dict[str, Any], algorithm: str = "sha256") -> str:
    """Hash a dict using JCS canonicalization and the specified algorithm."""
    canon = canonical_json(data)
    h = hashlib.new(algorithm)
    h.update(canon.encode("utf-8"))
    return f"{algorithm}:{h.hexdigest()}"


def hash_tool_definition(
    name: str,
    description: str,
    input_schema: dict[str, Any] | None = None,
    annotations: dict[str, Any] | None = None,
) -> str:
    """Hash an MCP tool definition in canonical form.

    This is the primary defense against tool-description poisoning and
    rug-pull attacks: any change to the tool's name, description, schema,
    or annotations produces a different hash.
    """
    definition: dict[str, Any] = {
        "name": name,
        "description": description,
    }
    if input_schema is not None:
        definition["inputSchema"] = input_schema
    if annotations is not None:
        definition["annotations"] = annotations
    return hash_canonical(definition)


def hash_file(path: Path, algorithm: str = "sha256") -> str | None:
    """Hash a file's contents. Returns None if the file does not exist."""
    if not path.is_file():
        return None
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return f"{algorithm}:{h.hexdigest()}"


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Hash raw bytes."""
    h = hashlib.new(algorithm)
    h.update(data)
    return f"{algorithm}:{h.hexdigest()}"


def safetensors_fingerprint(path: Path) -> dict[str, str] | None:
    """Per-tensor fingerprint for a safetensors file.

    A whole-file digest cannot distinguish a legitimate reload from a single
    poisoned tensor. This parses the safetensors header (little-endian u64
    length prefix + JSON) and derives two digests: the header itself and the
    sorted tensor inventory (names + dtypes + byte ranges). Any single-layer
    trojan, weight swap, or tensor addition changes the inventory digest.
    """
    import struct

    try:
        with open(path, "rb") as f:
            header_len_bytes = f.read(8)
            if len(header_len_bytes) != 8:
                return None
            header_len = struct.unpack("<Q", header_len_bytes)[0]
            if header_len <= 0 or header_len > 64 * 1024 * 1024:
                return None
            header_raw = f.read(header_len)
            if len(header_raw) != header_len:
                return None
    except OSError:
        return None

    try:
        header = json.loads(header_raw)
    except (ValueError, UnicodeError):
        return None
    if not isinstance(header, dict):
        return None

    tensors: list[dict[str, str]] = []
    for name, meta in header.items():
        if name == "__metadata__" or not isinstance(meta, dict):
            continue
        offsets = meta.get("data_offsets", [0, 0])
        tensors.append(
            {
                "name": name,
                "dtype": str(meta.get("dtype", "")),
                "shape": json.dumps(meta.get("shape", []), separators=(",", ":")),
                "offsets": f"{offsets[0]}:{offsets[1]}",
            }
        )
    if not tensors:
        return None
    tensors.sort(key=lambda t: t["name"])

    header_digest = hash_bytes(header_raw)
    inventory_raw = json.dumps(tensors, separators=(",", ":"), sort_keys=False)
    inventory_digest = hash_bytes(inventory_raw.encode("utf-8"))

    return {
        "safetensors_header_sha256": header_digest,
        "tensor_inventory_sha256": inventory_digest,
        "tensor_count": str(len(tensors)),
    }


_RANGE_PREFIX = re.compile(r"^[~^>=<!]+")
_VERSION_PATTERN = re.compile(
    r"(?:^|[/@:])(\d+\.\d+(?:\.\d+)?(?:[-+][a-zA-Z0-9.]+)?)(?:$|[/?#,;\s])"
)


def extract_version_pin(reference: str) -> str | None:
    """Extract a pinned version from a package reference or URL.

    Returns None for range specifiers (^, ~, >=, etc.) and floating/latest.
    Returns the version only for exact pins (@1.2.3, ==1.2.3, bare 1.2.3).
    """
    stripped = reference.strip()
    if stripped in ("*", "latest") or stripped.endswith("@latest") or stripped.endswith(":latest"):
        return None
    if _RANGE_PREFIX.match(stripped):
        prefix = _RANGE_PREFIX.match(stripped)
        if prefix and prefix.group(0) not in ("==",):
            return None
        if prefix and prefix.group(0) == "==":
            rest = stripped[prefix.end() :]
            m = re.match(r"(\d+\.\d+(?:\.\d+)?(?:[-+][a-zA-Z0-9.]+)?)", rest)
            return m.group(1) if m else None
    m = _VERSION_PATTERN.search(stripped)
    return m.group(1) if m else None
