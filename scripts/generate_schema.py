#!/usr/bin/env python3
"""Generate the native AIBOM JSON Schema from the Pydantic models.

The schema is derived from the models so it can never drift from what the tool
actually emits — previously the hand-written schema omitted five component types
(mcp-client, a2a-client, a2a-server, ide-agent, verified-extension) that the
scanners produce, so real `scan` output failed the tool's own schema (NS-07).

Run this whenever the models change:  python scripts/generate_schema.py
CI verifies the committed schema is in sync (see tests/test_schema_conformance.py).
"""

from __future__ import annotations

import json
from pathlib import Path

from nexus_symbiote.core.aibom import AIBOM

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent
    / "schemas"
    / "nexus-symbiote-aibom-1.0.schema.json"
)


def build_schema() -> dict:
    schema = AIBOM.model_json_schema(mode="serialization")
    # Stable, human-facing header (model_json_schema does not set these).
    ordered = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/aisecnomad/nexus-symbiote/schemas/nexus-symbiote-aibom-1.0.schema.json",
        "title": "Nexus SymBiote AgentBOM Schema",
        "description": (
            "JSON Schema for Nexus SymBiote Agent Bill of Materials (AIBOM) documents. "
            "GENERATED from the Pydantic models by scripts/generate_schema.py — do not edit by hand. "
            "Covers every agent-native component type the tool emits."
        ),
        "version": "1.0.0",
    }
    ordered.update(schema)
    return ordered


def render() -> str:
    return json.dumps(build_schema(), indent=2, sort_keys=True) + "\n"


def main() -> None:
    SCHEMA_PATH.write_text(render(), encoding="utf-8")
    print(f"wrote {SCHEMA_PATH}")


if __name__ == "__main__":
    main()
