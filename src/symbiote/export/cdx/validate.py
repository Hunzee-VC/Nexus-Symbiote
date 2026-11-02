"""Validate CycloneDX JSON against the vendored official schemas (1.6 and 1.7, with jsf and spdx sub-schemas)."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

from jsonschema import Draft7Validator, ValidationError, validators
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

_VENDOR = "schemas/vendor/cyclonedx"
_FILES = {
    "1.7": "bom-1.7.schema.json",
    "1.6": "bom-1.6.schema.json",
}


def _canonical(value: Any) -> Any:
    """A hashable form with JSON Schema equality: ``1 == 1.0``, ``true != 1``, objects compare by content."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return (type(value).__name__, value)
    if isinstance(value, (int, float)):
        return (
            ("number", float(value) if not isinstance(value, int) else value)
            if not (isinstance(value, float) and value.is_integer())
            else ("number", int(value))
        )
    if isinstance(value, list):
        return ("array", tuple(_canonical(v) for v in value))
    if isinstance(value, dict):
        return ("object", frozenset((k, _canonical(v)) for k, v in value.items()))
    return ("other", repr(value))


def _unique_items(validator: Any, unique: Any, instance: Any, schema: Any) -> Any:
    """``uniqueItems`` in linear time (jsonschema compares every pair of unhashable items: quadratic).

    A hostile document with thousands of components would otherwise cost minutes per validation.
    """
    del validator, schema
    if not unique or not isinstance(instance, list):
        return
    seen: set[Any] = set()
    for item in instance:
        key = _canonical(item)
        if key in seen:
            yield ValidationError(f"{instance!r:.200} has non-unique elements")
            return
        seen.add(key)


_FastDraft7 = validators.extend(Draft7Validator, {"uniqueItems": _unique_items})


def _load(name: str) -> dict[str, Any]:
    return json.loads(resources.files("symbiote").joinpath(f"{_VENDOR}/{name}").read_text(encoding="utf-8"))


@lru_cache(maxsize=4)
def _validator(version: str) -> Any:
    schema = _load(_FILES[version])
    jsf = _load("jsf-0.82.schema.json")
    spdx = _load("spdx.schema.json")
    base = schema.get("$id", f"http://cyclonedx.org/schema/bom-{version}.schema.json")
    base_dir = base.rsplit("/", 1)[0] + "/"
    registry = Registry().with_resources(
        [
            (base, Resource.from_contents(schema, default_specification=DRAFT7)),
            (base_dir + "jsf-0.82.schema.json", Resource.from_contents(jsf, default_specification=DRAFT7)),
            (base_dir + "spdx.schema.json", Resource.from_contents(spdx, default_specification=DRAFT7)),
            ("jsf-0.82.schema.json", Resource.from_contents(jsf, default_specification=DRAFT7)),
            ("spdx.schema.json", Resource.from_contents(spdx, default_specification=DRAFT7)),
        ]
    )
    return _FastDraft7(schema, registry=registry)


#: Above this many components + services + dependencies the redundant second validator is skipped.
SECOND_VALIDATOR_ELEMENT_BUDGET = 500


def _element_count(doc: dict[str, Any]) -> int:
    return sum(len(doc.get(k) or []) for k in ("components", "services", "dependencies"))


def referential_errors(doc: dict[str, Any]) -> list[str]:
    """What JSON Schema cannot express: every ``bom-ref`` unique, every dependency reference resolvable."""
    refs: dict[str, str] = {}
    errors: list[str] = []
    stack: list[tuple[str, Any]] = [("metadata/component", (doc.get("metadata") or {}).get("component"))]
    stack += [(f"components/{i}", c) for i, c in enumerate(doc.get("components") or [])]
    stack += [(f"services/{i}", c) for i, c in enumerate(doc.get("services") or [])]
    while stack:
        where, node = stack.pop()
        if not isinstance(node, dict):
            continue
        ref = node.get("bom-ref")
        if isinstance(ref, str):
            if ref in refs:
                errors.append(f"{where}: duplicate bom-ref {ref!r:.120} (also at {refs[ref]})")
            else:
                refs[ref] = where
        stack += [(f"{where}/components/{i}", c) for i, c in enumerate(node.get("components") or [])]
        stack += [(f"{where}/services/{i}", c) for i, c in enumerate(node.get("services") or [])]
    for i, dep in enumerate(doc.get("dependencies") or []):
        if not isinstance(dep, dict):
            continue
        for target in [dep.get("ref"), *(dep.get("dependsOn") or []), *(dep.get("provides") or [])]:
            if isinstance(target, str) and target not in refs:
                errors.append(
                    f"dependencies/{i}: reference {target!r:.120} resolves to no component or service"
                )
    return sorted(errors)[:200]


def validate_cyclonedx(doc: dict[str, Any], version: str | None = None) -> list[str]:
    """Return schema violations (empty when valid). Also runs cyclonedx-python-lib's strict validator when present."""
    version = version or str(doc.get("specVersion", "1.7"))
    if version not in _FILES:
        return [f"unsupported specVersion {version!r}"]
    errors = [
        f"{'/'.join(str(p) for p in e.absolute_path) or '$'}: {e.message[:300]}"
        for e in sorted(_validator(version).iter_errors(doc), key=lambda e: list(e.absolute_path))
    ]
    if errors:
        return errors
    errors = referential_errors(doc)
    if errors:
        return errors
    if _element_count(doc) > SECOND_VALIDATOR_ELEMENT_BUDGET:
        # cyclonedx-python-lib validates with stock jsonschema, whose uniqueItems is quadratic: a hostile
        # document with thousands of entries would cost minutes. The full-schema pass above is authoritative.
        return errors
    try:  # second, independent validator
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator

        sv = {"1.7": SchemaVersion.V1_7, "1.6": SchemaVersion.V1_6}[version]
        err = JsonStrictValidator(sv).validate_str(json.dumps(doc))
        if err is not None:
            errors.append(f"cyclonedx-python-lib: {err}")
    except ImportError:  # pragma: no cover
        pass
    return errors


__all__ = ["SECOND_VALIDATOR_ELEMENT_BUDGET", "referential_errors", "validate_cyclonedx"]
