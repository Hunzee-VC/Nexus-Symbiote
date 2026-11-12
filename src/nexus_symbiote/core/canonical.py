"""Deterministic JSON text, content digests and the serial-number namespace.

``core.aibom`` builds the canonical native document from these, and the standard
exporters in ``nexus_symbiote.generators`` reuse them; this module imports neither.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

NAMESPACE = uuid.UUID("ccaa2a43-8ba9-58e6-8f22-f8793a2039d5")


def json_text(value: Any) -> str:
    """Deterministic UTF-8 JSON representation; not a claim of RFC 8785 canonicalization."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def content_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json_text(value).encode("utf-8")).hexdigest()
