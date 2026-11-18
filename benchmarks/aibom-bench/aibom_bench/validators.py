"""Schema validation of tool output against the upstream CycloneDX, SPDX and SARIF schemas.

Schemas are read from a directory the operator fills (see README); none is bundled. Only
structure is checked, not ``format`` annotations.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator, Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from .extract import Output

CYCLONEDX_SUPPORT = ("spdx.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json")


class Validators:
    def __init__(self, schema_dir: Path) -> None:
        self.schema_dir = schema_dir
        self.used: dict[str, str] = {}

    def _load(self, name: str) -> Any:
        path = self.schema_dir / name
        if not path.is_file():
            return None
        raw = path.read_bytes()
        self.used[name] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)

    def _errors(self, schema: Any, doc: Any, registry: Registry | None = None) -> list[str]:
        draft = (
            Draft202012Validator if "2020-12" in str(schema.get("$schema", "")) else Draft7Validator
        )
        validator = draft(schema, registry=registry) if registry is not None else draft(schema)
        return [
            f"{'/'.join(str(part) for part in error.absolute_path)}: {error.message[:160]}"
            for error in list(validator.iter_errors(doc))[:5]
        ]

    def _result(self, outputs: list[Output], check: Any, partial: float = 0.5) -> dict[str, Any]:
        if not outputs:
            return {"score": 0.0, "note": "format not emitted"}
        reports = {f"{o.label}:{o.format}": check(o.doc) for o in outputs}
        valid = [name for name, report in reports.items() if report.get("valid")]
        return {"score": 1.0 if len(valid) == len(reports) else partial, "documents": reports}

    def cyclonedx(self, outputs: list[Output]) -> dict[str, Any]:
        def check(doc: dict[str, Any]) -> dict[str, Any]:
            version = str(doc.get("specVersion", ""))
            schema = self._load(f"bom-{version}.schema.json")
            if schema is None:
                return {
                    "valid": False,
                    "spec_version": version,
                    "errors": ["no schema for this version"],
                }
            registry: Registry = Registry()
            for name in CYCLONEDX_SUPPORT:
                support = self._load(name)
                if support is not None:
                    resource = Resource.from_contents(support, default_specification=DRAFT7)
                    registry = registry.with_resource(
                        f"http://cyclonedx.org/schema/{name}", resource
                    )
            errors = self._errors(schema, doc, registry)
            return {"valid": not errors, "spec_version": version, "errors": errors}

        return self._result(outputs, check)

    def spdx(self, outputs: list[Output]) -> dict[str, Any]:
        def check(doc: dict[str, Any]) -> dict[str, Any]:
            if "@graph" in doc:
                schema = self._load("spdx-3.0.1.schema.json")
                version = "3.0"
            else:
                schema = self._load("spdx-2.3.schema.json")
                version = str(doc.get("spdxVersion", "2.x"))
            if schema is None:
                return {"valid": False, "spec_version": version, "errors": ["no schema available"]}
            errors = self._errors(schema, doc)
            return {"valid": not errors, "spec_version": version, "errors": errors}

        result = self._result(outputs, check)
        versions = {report["spec_version"] for report in result.get("documents", {}).values()}
        if result["score"] == 1.0 and "3.0" not in versions:
            result["score"] = 0.5
            result["note"] = "valid SPDX 2.x only; the AI and Dataset profiles need SPDX 3"
        return result

    def sarif(self, outputs: list[Output]) -> dict[str, Any]:
        def check(doc: dict[str, Any]) -> dict[str, Any]:
            schema = self._load("sarif-2.1.0.schema.json")
            if schema is None:
                return {"valid": False, "errors": ["no schema available"]}
            errors = self._errors(schema, doc)
            return {"valid": not errors, "errors": errors}

        return self._result(outputs, check)
