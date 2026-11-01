"""Validate SPDX 3.0.1 JSON-LD against the vendored official JSON schema and round-trip it through the bindings."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads(
        resources.files("symbiote")
        .joinpath("schemas/vendor/spdx/spdx-json-schema-3.0.1.json")
        .read_text(encoding="utf-8")
    )
    return Draft202012Validator(schema)


def validate_spdx(doc: dict[str, Any], *, bindings: bool = True) -> list[str]:
    """Return schema violations (empty when valid); also checks the document deserialises with spdx-python-model."""
    errors = [
        f"{'/'.join(str(p) for p in e.absolute_path) or '$'}: {e.message[:300]}"
        for e in sorted(_validator().iter_errors(doc), key=lambda e: list(e.absolute_path))
    ]
    if errors or not bindings:
        return errors
    try:
        import io

        from spdx_python_model.bindings import v3_0_1 as m

        objset = m.SHACLObjectSet()
        m.JSONLDDeserializer().read(io.BytesIO(json.dumps(doc).encode("utf-8")), objset)
    except Exception as exc:
        errors.append(f"spdx-python-model: {type(exc).__name__}: {exc}")
    return errors


__all__ = ["validate_spdx"]
