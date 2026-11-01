"""Redaction of credential-shaped values before an AIBOM leaves the process.

Redaction covers free-text and extension fields. Tool definition text, input schemas,
annotations, and every hash are left untouched. Definitions are fingerprinted for
integrity checks, and rewriting them would make the fingerprint describe different text.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from pydantic import BaseModel

if TYPE_CHECKING:
    from nexus_symbiote.core.aibom import AIBOM

REDACTED = "[redacted]"

# Matches whole key segments only, so "tokenizer_hash" is not treated as a token.
_SECRET_KEY = re.compile(
    r"(?i)(?:^|[-_:.])(?:token|secret|passwd|password|api[-_]?key|authorization|cookie"
    r"|credentials?|private[-_]?key|session[-_]?id)(?:$|[-_:.])"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_TOKEN_SHAPES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
)
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[-_]?key)(\s*[=:]\s*)([^\s,;'\"]+)"
)
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")

# Fields never redacted: references, hashes, and text that is fingerprinted.
_PROTECTED_FIELDS = frozenset(
    {
        "bom_ref",
        "component_type",
        "name",
        "description_text",
        "input_schema",
        "annotations",
        "hashes",
        "definition_hash",
        "definition_hash_version",
        "content_hash",
        "schema_hash",
    }
)


def redact_url(value: str) -> str:
    """Keep scheme, host, port, and path. Drop userinfo, query, and fragment."""
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.hostname:
            return REDACTED
        host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return REDACTED
    return f"{parts.scheme.lower()}://{host}{port}{parts.path}"


def redact_string(value: str) -> str:
    """Replace credential-shaped substrings. Applying it twice changes nothing more."""
    text = _PRIVATE_KEY_BLOCK.sub(REDACTED, value)
    for shape in _TOKEN_SHAPES:
        text = shape.sub(REDACTED, text)
    text = _ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    return _URL.sub(lambda m: redact_url(m.group(0)), text)


def redact_value(key: str | None, value: Any) -> Any:
    """Redact a JSON-like value. A secret-looking key redacts its string value outright."""
    if isinstance(value, str):
        if key is not None and _SECRET_KEY.search(key):
            return REDACTED
        return redact_string(value)
    if isinstance(value, dict):
        return {k: redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(key, item) for item in value]
    return value


def _is_protected(field_name: str) -> bool:
    return field_name in _PROTECTED_FIELDS or field_name.endswith(
        ("_ref", "_refs", "_hash", "_hashes", "_hash_version")
    )


def _redact_model(model: BaseModel) -> int:
    changed = 0
    for field_name in type(model).model_fields:
        if _is_protected(field_name):
            continue
        original = getattr(model, field_name)
        if isinstance(original, BaseModel):
            changed += _redact_model(original)
        elif (
            isinstance(original, list)
            and original
            and all(isinstance(item, BaseModel) for item in original)
        ):
            for item in original:
                changed += _redact_model(item)
        else:
            redacted = redact_value(field_name, original)
            if redacted != original:
                setattr(model, field_name, redacted)
                changed += 1
    return changed


def redact_aibom(bom: AIBOM) -> int:
    """Redact credential-shaped values in place. Returns the number of fields changed."""
    return sum(_redact_model(component) for component in bom.components)
