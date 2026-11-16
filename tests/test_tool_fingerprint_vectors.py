"""Known-answer vectors for the rfc8785-jcs-v2 tool fingerprint.

Stored baselines, approved snapshots and drift comparisons depend on these exact
values. A changed expectation is a new fingerprint profile, not a test update.
The four-field vectors were computed with the 0.1.0 implementation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.hashing import TOOL_DEFINITION_HASH_VERSION, hash_tool_definition
from nexus_symbiote.core.models import ToolComponent
from nexus_symbiote.scanners.live_mcp import check_served_tool
from nexus_symbiote.scanners.mcp import MCPScanner

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "tool-definition-rfc8785-jcs-v2.json").read_text(
        encoding="utf-8"
    )
)
CASES = VECTORS["vectors"]


def _digest(case: dict[str, Any]) -> str:
    return hash_tool_definition(
        case["name"],
        case["description"],
        case.get("inputSchema"),
        case.get("annotations"),
        title=case.get("title"),
        output_schema=case.get("outputSchema"),
        meta=case.get("_meta"),
    )


def test_vector_file_names_the_current_profile():
    assert VECTORS["profile"] == TOOL_DEFINITION_HASH_VERSION
    assert len(CASES) >= 12
    assert len({case["id"] for case in CASES}) == len(CASES)


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_tool_definition_known_answer(case):
    assert _digest(case) == case["digest"]
    # The preimage itself is pinned, so a digest cannot match by a shared mistake.
    canonical = hashlib.sha256(case["canonical"].encode("utf-8")).hexdigest()
    assert "sha256:" + canonical == case["digest"]


def test_absent_optional_fields_keep_every_existing_fingerprint():
    by_id = {case["id"]: case for case in CASES}
    four_field = by_id["input-schema"]
    assert (
        hash_tool_definition(
            four_field["name"],
            four_field["description"],
            four_field["inputSchema"],
            None,
            title=None,
            output_schema=None,
            meta=None,
        )
        == four_field["digest"]
    )
    assert by_id["empty-annotations-equal-absent"]["digest"] == four_field["digest"]
    assert by_id["empty-title-differs-from-absent"]["digest"] != four_field["digest"]
    assert by_id["empty-meta-differs-from-absent"]["digest"] != four_field["digest"]


def _descriptor(case: dict[str, Any]) -> dict[str, Any]:
    return {
        key: case[key]
        for key in ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
        if key in case
    } | ({"_meta": case["_meta"]} if "_meta" in case else {})


@pytest.mark.parametrize(
    "case_id", ["input-schema", "title", "output-schema", "meta", "all-optional-fields"]
)
def test_static_configuration_and_served_descriptor_share_the_vector(tmp_path, case_id):
    case = next(case for case in CASES if case["id"] == case_id)
    descriptor = _descriptor(case)
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "weather": {"command": "npx", "args": ["weather@1.0.0"], "tools": [descriptor]}
                }
            }
        )
    )
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    [tool] = [c for c in result.components if isinstance(c, ToolComponent)]
    assert tool.definition_hash == case["digest"]
    assert check_served_tool(descriptor).fingerprint == case["digest"]


@pytest.mark.parametrize(
    "field,value", [("title", 3), ("outputSchema", "object"), ("_meta", ["x"])]
)
def test_static_configuration_rejects_wrongly_typed_optional_fields(tmp_path, field, value):
    case = next(case for case in CASES if case["id"] == "input-schema")
    descriptor = {**_descriptor(case), field: value}
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"weather": {"command": "npx", "tools": [descriptor]}}})
    )
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == [
        ".mcp.json: invalid tool definition for server 'weather'; "
        + "the server and its risks are not inventoried"
    ]
    assert not [c for c in result.components if isinstance(c, ToolComponent)]
