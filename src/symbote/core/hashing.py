"""Canonical hashing for AgentBOM components.

Implements RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic
hashing of tool definitions, prompt templates, and other mutable artifacts.
"""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from typing import Any


def _serialize_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return "null"
        return _serialize_float(value)
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, list):
        items = ",".join(_serialize_value(item) for item in value)
        return f"[{items}]"
    if isinstance(value, dict):
        return _serialize_object(value)
    return _serialize_string(str(value))


def _serialize_float(value: float) -> str:
    if value == 0.0:
        return "0"
    if value == int(value) and abs(value) < 2**53:
        return str(int(value))
    return repr(value)


def _serialize_string(value: str) -> str:
    result = ['"']
    for ch in value:
        cp = ord(ch)
        if ch == '"':
            result.append('\\"')
        elif ch == "\\":
            result.append("\\\\")
        elif cp < 0x20:
            if ch == "\b":
                result.append("\\b")
            elif ch == "\f":
                result.append("\\f")
            elif ch == "\n":
                result.append("\\n")
            elif ch == "\r":
                result.append("\\r")
            elif ch == "\t":
                result.append("\\t")
            else:
                result.append(f"\\u{cp:04x}")
        else:
            result.append(ch)
    result.append('"')
    return "".join(result)


def _serialize_object(obj: dict) -> str:
    sorted_keys = sorted(obj.keys(), key=lambda k: [ord(c) for c in k])
    pairs = []
    for key in sorted_keys:
        val = obj[key]
        if val is not None:
            pairs.append(f"{_serialize_string(key)}:{_serialize_value(val)}")
    return "{" + ",".join(pairs) + "}"


def canonical_json(data: dict[str, Any]) -> str:
    """Produce RFC 8785 JCS canonical form of a JSON object."""
    return _serialize_object(data)


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


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    """Hash a file's contents."""
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


_VERSION_PATTERN = re.compile(
    r"(?:^|[/@:])(\d+\.\d+(?:\.\d+)?(?:[-+][a-zA-Z0-9.]+)?)(?:$|[/?#])"
)


def extract_version_pin(reference: str) -> str | None:
    """Extract a pinned version from a package reference or URL.

    Returns None if no pinned version is found (floating/latest).
    """
    if reference.endswith("@latest") or reference.endswith(":latest"):
        return None
    m = _VERSION_PATTERN.search(reference)
    return m.group(1) if m else None
