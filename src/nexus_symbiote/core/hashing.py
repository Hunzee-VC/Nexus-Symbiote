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
    # Empty and absent schema/annotations MUST canonicalize identically, so the
    # scanner (which passes {}) and the validator (which passes None) produce
    # the same fingerprint for an unchanged tool. Without this normalization an
    # annotation-less tool failed its own integrity check as a false rug-pull.
    if input_schema:
        definition["inputSchema"] = input_schema
    if annotations:
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


_SEMVER = r"\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.]+)?"
_DIGEST = re.compile(r"(?:sha1|sha256|sha384|sha512):[0-9a-fA-F]{32,128}")
_EXACT_PIP = re.compile(r"(?:^|[^=!<>~^ ])==\s*(" + _SEMVER + r")$")
_EXACT_GITSHA = re.compile(r"[@:]([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_EXACT_SUFFIX = re.compile(r"[@:]v?(" + _SEMVER + r")$")
_EXACT_BARE = re.compile(r"^v?(" + _SEMVER + r")$")
_RANGE_CHARS = frozenset("^~<>*")


def extract_version_pin(reference: str) -> str | None:
    """Return an exact version/digest pin, or None for ranges/floating refs.

    Treated as PINNED (returns the concrete token):
      - exact pip pins ``pkg==1.2.3`` / ``==1.2.3``
      - npm / OCI tag pins ``pkg@1.2.3`` / ``image:1.2.3`` / ``v1.2.3``
      - content digests ``...@sha256:<hex>`` or a bare ``sha256:<hex>``
      - git commit / bare digest pins ``...@<40 or 64 hex>``
      - bare versions ``1.2.3``
    Treated as NOT pinned (returns None):
      - range specifiers ``^ ~ >= <= > < != *``
      - comma / ``||`` / hyphen constraint lists
      - floating tags ``latest`` / ``*`` / ``x``
    """
    s = reference.strip()
    if not s:
        return None
    low = s.lower()
    if low in ("*", "x", "latest") or low.endswith(("@latest", ":latest")):
        return None
    digest = _DIGEST.search(s)
    if digest:
        return digest.group(0)
    if "," in s or "||" in s or " - " in s:
        return None
    if any(c in _RANGE_CHARS for c in s) or "!=" in s:
        return None
    for pattern in (_EXACT_PIP, _EXACT_GITSHA, _EXACT_SUFFIX, _EXACT_BARE):
        m = pattern.search(s)
        if m:
            return m.group(1)
    return None
