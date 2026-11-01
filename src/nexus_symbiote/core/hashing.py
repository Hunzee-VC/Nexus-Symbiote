"""Canonical hashing for AgentBOM components.

Implements RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic
hashing of tool definitions, prompt templates, and other mutable artifacts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, BinaryIO

import rfc8785


def canonical_json(data: Any) -> str:
    """Serialize strict I-JSON with RFC 8785, rejecting ambiguous inputs.

    Nonfinite numbers, out-of-range integers, lone surrogates and unsupported
    Python values fail instead of being coerced into a different JSON value.
    """
    return rfc8785.dumps(data).decode("utf-8")


def parse_json_strict(text: str | bytes, *, max_bytes: int = 4 * 1024 * 1024) -> Any:
    """Parse bounded I-JSON, rejecting duplicate keys and invalid numbers."""
    if len(text if isinstance(text, bytes) else text.encode("utf-8")) > max_bytes:
        raise ValueError("JSON exceeds the configured byte limit")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON object key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"Nonfinite JSON number: {value}")

    result = json.loads(text, object_pairs_hook=object_pairs, parse_constant=reject_constant)
    canonical_json(result)
    return result


# v2 normalizes omitted/empty MCP annotations. Older fingerprints require
# collection and approval under the current contract; never silently relabel them.
TOOL_DEFINITION_HASH_VERSION = "rfc8785-jcs-v2"

SECURE_HASH_ALGORITHMS = {"sha256": 64, "sha384": 96, "sha512": 128}


def normalize_digest(expected_hash: str, algorithm: str | None = None) -> tuple[str, str]:
    """Validate a security digest and reconcile its optional algorithm prefix."""
    if ":" in expected_hash:
        prefix, digest = expected_hash.split(":", 1)
        if algorithm is not None and prefix.lower() != algorithm.lower():
            raise ValueError("Digest algorithm prefix disagrees with its field")
        algorithm = prefix.lower()
    else:
        digest = expected_hash
        algorithm = (algorithm or "sha256").lower()
    length = SECURE_HASH_ALGORITHMS.get(algorithm)
    if length is None:
        raise ValueError(f"Unsupported security hash algorithm: {algorithm}")
    if len(digest) != length or re.fullmatch(r"[a-fA-F0-9]+", digest) is None:
        raise ValueError(f"Malformed {algorithm} digest")
    return algorithm, digest.lower()


def open_regular_file(path: Path) -> BinaryIO:
    """Open a regular file without following any symlink or blocking on a FIFO.

    Descriptor-relative traversal also protects the parent path from symlink
    replacement between a check and the final open. Fail closed on platforms
    without the required no-follow APIs.
    """
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
    ):
        raise OSError("Descriptor-relative no-follow file access is unavailable")
    absolute = Path(os.path.abspath(path))
    parent_fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(absolute.name, flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("Artifact is not a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


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
    """Hash v2 model-visible metadata, normalizing omitted annotations to {}.

    Callers carry TOOL_DEFINITION_HASH_VERSION beside the digest. Comparing to an
    authenticated approved baseline detects metadata drift; this fingerprint does
    not establish publisher identity or constrain a tool's implementation.
    """
    definition: dict[str, Any] = {
        "name": name,
        "description": description,
    }
    if input_schema is not None:
        definition["inputSchema"] = input_schema
    # Missing and empty MCP annotations have the same defined digest contract.
    # A producer and consumer must not disagree because the model fills defaults.
    definition["annotations"] = annotations or {}
    return hash_canonical(definition)


def hash_file(path: Path, algorithm: str = "sha256") -> str | None:
    """Hash a file's contents. Returns None if the file does not exist."""
    if not path.is_file():
        return None
    h = hashlib.new(algorithm)
    with open_regular_file(path) as f:
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
    immutable = re.search(r"@sha256:([0-9a-fA-F]{64})$", stripped)
    if immutable:
        return "sha256:" + immutable.group(1).lower()
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
