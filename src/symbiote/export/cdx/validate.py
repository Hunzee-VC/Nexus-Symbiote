"""Validate CycloneDX JSON against the vendored official schemas (1.6 and 1.7, with jsf and spdx sub-schemas)."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

_VENDOR = "schemas/vendor/cyclonedx"
_FILES = {
    "1.7": "bom-1.7.schema.json",
    "1.6": "bom-1.6.schema.json",
}


def _load(name: str) -> dict[str, Any]:
    return json.loads(resources.files("symbiote").joinpath(f"{_VENDOR}/{name}").read_text(encoding="utf-8"))


@lru_cache(maxsize=4)
def _validator(version: str) -> Draft7Validator:
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
    return Draft7Validator(schema, registry=registry)


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


__all__ = ["validate_cyclonedx"]
