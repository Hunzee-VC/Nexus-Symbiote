"""Deterministic identifiers (``spec/agentbom-profile.md §1.1``)."""

from __future__ import annotations

import hashlib
import re
import unicodedata
import uuid

#: Project UUIDv5 namespace used for content-addressed serial numbers and derived ids.
SYMBIOTE_UUID_NAMESPACE = uuid.UUID("6f9b2d3e-5c1a-4f0e-9b7a-2e1c3d4f5a6b")

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def slugify(value: str, *, max_length: int = 96) -> str:
    """Lowercase ``[a-z0-9._-]`` slug; non-ASCII is transliterated by NFKD then dropped."""
    norm = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii").lower()
    slug = _SLUG_RE.sub("-", norm).strip("-.")
    slug = re.sub(r"-{2,}", "-", slug)
    if not slug:
        slug = "x" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return slug[:max_length].rstrip("-.")


def make_id(kind: str, *parts: str, collision_seed: str | None = None) -> str:
    """Build ``<kind>:<slug>[/<slug>...]``; ``collision_seed`` appends a 6-hex suffix when callers detect a clash."""
    body = "/".join(slugify(p) for p in parts if p)
    if collision_seed:
        body += "-" + hashlib.sha256(collision_seed.encode("utf-8")).hexdigest()[:6]
    return f"{kind}:{body}"


def tool_id(server_id: str, tool_name: str) -> str:
    """``tool:<server-slug>/<tool-name>`` — the MCP tool name is kept verbatim (already restricted by MCP)."""
    server_slug = server_id.split(":", 1)[1] if ":" in server_id else slugify(server_id)
    return f"tool:{server_slug}/{tool_name}"


def evidence_id(digest: str) -> str:
    """``ev:<first 12 hex of the digest>``."""
    hexpart = digest.split(":", 1)[1] if ":" in digest else digest
    return "ev:" + hexpart[:12]


def snapshot_id(serial: int, digest: str) -> str:
    hexpart = digest.split(":", 1)[1] if ":" in digest else digest
    return f"snap:{serial}:{hexpart[:12]}"


def uuid5_for_digest(digest: str) -> uuid.UUID:
    """Content-addressed UUIDv5 used as the CycloneDX ``serialNumber``."""
    return uuid.uuid5(SYMBIOTE_UUID_NAMESPACE, digest)


__all__ = [
    "SYMBIOTE_UUID_NAMESPACE",
    "evidence_id",
    "make_id",
    "slugify",
    "snapshot_id",
    "tool_id",
    "uuid5_for_digest",
]
