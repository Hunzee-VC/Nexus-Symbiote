"""RFC 8785 canonical JSON with strict parsing (``spec/digests.md §1``, ADR-0004)."""

from __future__ import annotations

import json
import math
from collections.abc import Hashable
from typing import Any

import rfc8785


class UndigestableError(ValueError):
    """Raised when input cannot be canonicalised; callers convert it into a fail-closed ``DigestResult``."""

    def __init__(self, reason_class: str, detail: str = "") -> None:
        self.reason_class = reason_class
        self.detail = detail
        super().__init__(f"{reason_class}: {detail}" if detail else reason_class)


def _check_domain(obj: Any, path: str = "$") -> None:
    """Reject values JCS cannot represent faithfully before handing them to the serializer."""
    if isinstance(obj, bool) or obj is None or isinstance(obj, str):
        return
    if isinstance(obj, int):
        if abs(obj) >= 2**53:
            raise UndigestableError("integer-out-of-range", f"{path}: |{obj}| >= 2^53")
        return
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise UndigestableError("non-finite-number", f"{path}: {obj}")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise UndigestableError("non-string-key", f"{path}: {k!r}")
            _check_domain(v, f"{path}.{k}")
        return
    if isinstance(obj, list | tuple):
        for i, v in enumerate(obj):
            _check_domain(v, f"{path}[{i}]")
        return
    raise UndigestableError("unsupported-type", f"{path}: {type(obj).__name__}")


def canonical_bytes(obj: Any) -> bytes:
    """Serialise ``obj`` with RFC 8785 (JCS). Raises :class:`UndigestableError` instead of guessing."""
    _check_domain(obj)
    try:
        return rfc8785.dumps(obj)
    except (rfc8785.CanonicalizationError, ValueError, TypeError) as exc:  # pragma: no cover - defensive
        raise UndigestableError("canonicalization-error", str(exc)) from exc


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise UndigestableError("duplicate-key", k)
        out[k] = v
    return out


def _reject_constant(name: str) -> Any:
    raise UndigestableError("non-finite-number", name)


def parse_json_strict(text: str | bytes) -> Any:
    """Parse JSON text, rejecting duplicate object keys and non-finite numbers (which JCS cannot carry)."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UndigestableError("invalid-utf8", str(exc)) from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise UndigestableError("invalid-json", str(exc)) from exc


def utf16_sort_key(value: str) -> bytes:
    """Sort key giving UTF-16 code-unit order (the order JCS uses for object keys)."""
    return value.encode("utf-16-be")


def freeze(obj: Any) -> Hashable:
    """Hashable form of a JSON value (for set-based comparisons in tests and diffs)."""
    if isinstance(obj, dict):
        return tuple(sorted((k, freeze(v)) for k, v in obj.items()))
    if isinstance(obj, list):
        return tuple(freeze(v) for v in obj)
    return obj


__all__ = ["UndigestableError", "canonical_bytes", "freeze", "parse_json_strict", "utf16_sort_key"]
