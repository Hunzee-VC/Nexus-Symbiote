"""Conservative redaction for collector output, never credential retrieval."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

REDACTED = "***"
_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+")
_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:api[-_]?key|access[-_]?token|auth[-_]?token|token|password|passwd|secret)\s*[:=]\s*)[^\s,;]+"
)
_AUTH = re.compile(r"(?i)(\b(?:Bearer|Basic)\s+)[A-Za-z0-9_+/=.-]+")


def redact_url(value: str) -> str:
    """Keep URL origin only; paths, userinfo, queries and fragments may hold secrets.

    These are locators with credentials omitted, not round-trippable connection
    strings. No URL is fetched or resolved by this helper.
    """
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.hostname:
            return "[redacted-url]"
        host = parts.hostname
        if ":" in host:
            host = f"[{host}]"
        if parts.port is not None:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, "", "", ""))
    except ValueError:
        return "[redacted-url]"


def redact_text(value: str, secrets: Iterable[str] = ()) -> str:
    """Remove known secret values and common URL/auth/assignment encodings."""
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        value = value.replace(secret, REDACTED)
    value = _URL.sub(lambda match: redact_url(match.group()), value)
    value = _ASSIGNMENT.sub(lambda match: match.group(1) + REDACTED, value)
    return _AUTH.sub(lambda match: match.group(1) + REDACTED, value)


def redact_metadata(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Redact textual metadata while retaining its JSON structure."""
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, dict):
        return {redact_text(str(k), secrets): redact_metadata(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_metadata(item, secrets) for item in value]
    return value
