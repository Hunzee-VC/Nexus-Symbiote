"""Companion JSON Schema generation (``spec/companion.md §2``)."""

from __future__ import annotations

import json
from typing import Any

from symbiote import BASE_URI, SPEC_VERSION
from symbiote.model.document import AgentBOM

COMPANION_SCHEMA_ID = f"{BASE_URI}schemas/agentbom/{SPEC_VERSION}/agentbom.schema.json"
COMPANION_MEDIA_TYPE = "application/vnd.agentbom+json"


def _forbid_additional(node: Any) -> None:
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node and "additionalProperties" not in node:
            node["additionalProperties"] = False
        for v in node.values():
            _forbid_additional(v)
    elif isinstance(node, list):
        for v in node:
            _forbid_additional(v)


def companion_json_schema() -> dict[str, Any]:
    """Draft 2020-12 schema of the companion document, derived from the Pydantic model."""
    schema = AgentBOM.model_json_schema(by_alias=True, mode="serialization")
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": COMPANION_SCHEMA_ID,
        "title": "AgentBOM companion document",
        "description": "Structured source of truth of a Symbiote AgentBOM snapshot (spec/agentbom-profile.md).",
        **schema,
    }
    _forbid_additional(schema)
    return schema


def companion_json_schema_text() -> str:
    return json.dumps(companion_json_schema(), indent=2, sort_keys=True) + "\n"


__all__ = [
    "COMPANION_MEDIA_TYPE",
    "COMPANION_SCHEMA_ID",
    "companion_json_schema",
    "companion_json_schema_text",
]
