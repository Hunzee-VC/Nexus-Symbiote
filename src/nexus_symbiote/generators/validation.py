"""Offline validation against pinned official schemas and local graph constraints."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft7Validator, Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7


def _schema(name: str) -> dict[str, Any]:
    schema = json.loads(
        files("nexus_symbiote.generators").joinpath("schemas/vendor/" + name).read_text()
    )
    if not isinstance(schema, dict):
        raise ValueError("vendored schema must be a JSON object")
    return schema


@lru_cache(maxsize=2)
def _validator(fmt: str) -> Any:
    if fmt == "spdx":
        return Draft202012Validator(
            _schema("spdx/spdx-json-schema-3.0.1.json"), format_checker=FormatChecker()
        )
    main = _schema("cyclonedx/bom-1.7.schema.json")
    base = main["$id"]
    directory = base.rsplit("/", 1)[0] + "/"
    schemas = [(base, Resource.from_contents(main, default_specification=DRAFT7))]
    for name in ("jsf-0.82.schema.json", "spdx.schema.json"):
        resource = Resource.from_contents(
            _schema("cyclonedx/" + name), default_specification=DRAFT7
        )
        schemas.extend([(directory + name, resource), (name, resource)])
    return Draft7Validator(
        main, registry=Registry().with_resources(schemas), format_checker=FormatChecker()
    )


def validate_cyclonedx(document: dict[str, Any]) -> list[str]:
    errors = _schema_errors(document, "cyclonedx")
    if errors:
        return errors
    refs = [c["bom-ref"] for c in document.get("components", []) if "bom-ref" in c]
    if len(refs) != len(set(refs)):
        errors.append("duplicate CycloneDX bom-ref")
    known = set(refs)
    dep_refs: set[str] = set()
    for dependency in document.get("dependencies", []):
        ref = dependency.get("ref")
        if ref in dep_refs:
            errors.append("duplicate CycloneDX dependency ref")
        dep_refs.add(ref)
        for target in [ref, *dependency.get("dependsOn", []), *dependency.get("provides", [])]:
            if target not in known:
                errors.append(f"unresolved CycloneDX reference: {target}")
    return errors


def validate_spdx(document: dict[str, Any]) -> list[str]:
    errors = _schema_errors(document, "spdx")
    if errors:
        return errors
    graph = document.get("@graph", [])
    ids = [n.get("spdxId", n.get("@id")) for n in graph]
    if None in ids or len(ids) != len(set(ids)):
        errors.append("missing or duplicate SPDX graph identifier")
    known = set(ids)
    for node in graph:
        if node.get("type") == "SpdxDocument" and not set(node.get("rootElement", [])).issubset(
            node.get("element", [])
        ):
            errors.append("SPDX rootElement is not in document element collection")
        for field in (
            "creationInfo",
            "createdBy",
            "createdUsing",
            "suppliedBy",
            "element",
            "rootElement",
            "from",
            "to",
        ):
            values = node.get(field, [])
            values = values if isinstance(values, list) else [values]
            for value in values:
                if isinstance(value, str) and value not in known:
                    errors.append(f"unresolved SPDX {field}: {value}")
    return errors


def _schema_errors(document: dict[str, Any], fmt: str) -> list[str]:
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:180]}"
        for e in _validator(fmt).iter_errors(document)
    ]


def require_valid(document: dict[str, Any], fmt: str) -> None:
    errors = validate_spdx(document) if fmt == "spdx" else validate_cyclonedx(document)
    if errors:
        raise ValueError(f"invalid {fmt} export: " + "; ".join(errors[:10]))
