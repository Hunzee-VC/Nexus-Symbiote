"""Declared-tool heuristics match words, not substrings, and honour typed hints."""

from __future__ import annotations

import json

import pytest

from nexus_symbiote.core.enums import CapabilityClass, SideEffectProfile
from nexus_symbiote.core.models import ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner


def tool(
    tmp_path, name: str, annotations: dict | None = None, description: str = ""
) -> ToolComponent:
    entry = {"name": name, "description": description, "annotations": annotations or {}}
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"s": {"command": "node", "tools": [entry]}}})
    )
    result = MCPScanner().scan(tmp_path, config_only=True)
    return next(c for c in result.components if isinstance(c, ToolComponent))


@pytest.mark.parametrize(
    "name,profile",
    [
        ("compute_stats", SideEffectProfile.UNKNOWN),
        ("dropdown_options", SideEffectProfile.UNKNOWN),
        ("budget_report", SideEffectProfile.UNKNOWN),
        ("deleteFile", SideEffectProfile.DESTRUCTIVE),
        ("getUser", SideEffectProfile.READ_ONLY),
        ("update_issue", SideEffectProfile.STATE_MODIFYING),
        ("transfer_funds", SideEffectProfile.FINANCIAL_TRANSACTION),
        ("refundOrder", SideEffectProfile.FINANCIAL_TRANSACTION),
        ("list_payments", SideEffectProfile.READ_ONLY),
        ("transfer_file", SideEffectProfile.UNKNOWN),
    ],
)
def test_side_effects_follow_name_words(tmp_path, name, profile):
    recorded = tool(tmp_path, name)
    assert recorded.capabilities.side_effect_profile == profile
    harmful = profile in {SideEffectProfile.DESTRUCTIVE, SideEffectProfile.FINANCIAL_TRANSACTION}
    assert any(r.severity.value == "high" for r in recorded.risks) is harmful


def test_read_only_hint_does_not_hide_a_destructive_name(tmp_path):
    recorded = tool(tmp_path, "purge_tenant", {"readOnlyHint": True})
    assert recorded.capabilities.side_effect_profile == SideEffectProfile.DESTRUCTIVE
    assert {(r.severity.value, r.category) for r in recorded.risks} == {
        ("high", "capability_scope"),
        ("medium", "capability_scope"),
    }


@pytest.mark.parametrize(
    "annotations,profile",
    [
        ({"destructiveHint": "false"}, SideEffectProfile.READ_ONLY),
        ({"readOnlyHint": "no", "destructiveHint": True}, SideEffectProfile.DESTRUCTIVE),
        ({"readOnlyHint": 1}, SideEffectProfile.READ_ONLY),
    ],
)
def test_only_boolean_hints_count(tmp_path, annotations, profile):
    assert tool(tmp_path, "get_record", annotations).capabilities.side_effect_profile == profile


@pytest.mark.parametrize(
    "name,description,present,absent",
    [
        ("monkey_patch", "Patch a module", [], [CapabilityClass.CREDENTIALS]),
        ("author_lookup", "Find an author", [CapabilityClass.READ], [CapabilityClass.CREDENTIALS]),
        ("rotate_api_key", "Rotate the API key", [CapabilityClass.CREDENTIALS], []),
        ("fetch_url", "Fetch content from a URL via http", [CapabilityClass.NETWORK], []),
        ("read_file", "Read a file from the filesystem path", [CapabilityClass.FILESYSTEM], []),
        ("pay_invoice", "Pay an invoice", [CapabilityClass.PAYMENT], []),
        ("runtime_info", "Describe the runtime", [], [CapabilityClass.EXECUTE]),
    ],
)
def test_capabilities_follow_words(tmp_path, name, description, present, absent):
    capabilities = tool(tmp_path, name, description=description).capabilities.capabilities
    assert all(item in capabilities for item in present)
    assert not any(item in capabilities for item in absent)
