"""Canonical hashing for AgentBOM components.

Implements RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic
hashing of tool definitions, prompt templates, and other mutable artifacts.
"""

from __future__ import annotations

import hashlib
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


_SEMVER = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_DIGEST_PIN = re.compile(r"[^@\s]+@(sha256:[0-9a-f]{64})")
_PEP508_EXACT = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?\s*==\s*([0-9][0-9A-Za-z.!+_-]*)"
)


def extract_version_pin(reference: str) -> str | None:
    """Return the exact version or digest that a package reference pins, or None.

    Recognises npm (name@1.2.3, scoped names included), PEP 508 (name==1.2.3) and Docker
    digests (image@sha256:...). Ranges, tags, URLs and bare versions are not pins.
    """
    value = reference.strip()
    if not value or value in ("*", "latest") or value.endswith(("@latest", ":latest")):
        return None
    if "://" in value:
        return None

    digest = _DIGEST_PIN.fullmatch(value)
    if digest:
        return digest.group(1)

    exact = _PEP508_EXACT.fullmatch(value.split(";", 1)[0].strip())
    if exact:
        return exact.group(1)

    name, separator, spec = value.rpartition("@")
    if separator and name:
        version = spec.removeprefix("v")
        if _SEMVER.fullmatch(version):
            return version
    return None
