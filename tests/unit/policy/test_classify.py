"""Side-effect classification and approval gates implied by client settings."""

from __future__ import annotations

from typing import Any

import pytest

from symbiote.authz.classify import (
    approval_gate,
    capabilities,
    is_open_world,
    server_approval_gate,
    side_effect_class,
)
from symbiote.digest import tooldef_digest
from symbiote.model.common import Claim
from symbiote.model.entities import (
    Authentication,
    SideEffectProfile,
    ToolAnnotations,
    ToolDefinition,
    ToolServer,
)
from symbiote.model.enums import (
    ApprovalGate,
    AuthMode,
    CapabilityClass,
    SideEffectClass,
    ToolServerKind,
    ToolSource,
    Transport,
)


def _tool(
    annotations: dict[str, Any] | None = None, effects: SideEffectProfile | None = None
) -> ToolDefinition:
    raw = {"name": "t", "inputSchema": {"type": "object"}}
    return ToolDefinition(
        id="tool:s/t",
        server_ref="server:s",
        tool_name="t",
        input_schema=raw["inputSchema"],
        annotations=Claim.declared(ToolAnnotations(**annotations)) if annotations is not None else None,
        side_effects=Claim.observed(effects) if effects is not None else None,
        digest=tooldef_digest(raw),
        source=ToolSource.SERVED_LIVE,
    )


@pytest.mark.parametrize(
    ("annotations", "expected"),
    [
        (None, SideEffectClass.UNKNOWN),
        ({}, SideEffectClass.UNKNOWN),
        ({"read_only_hint": True}, SideEffectClass.READ_ONLY),
        ({"read_only_hint": False}, SideEffectClass.DESTRUCTIVE),  # MCP default destructive
        (
            {"read_only_hint": False, "destructive_hint": False},
            SideEffectClass.COMMUNICATE,
        ),  # default open world
        (
            {"read_only_hint": False, "destructive_hint": False, "open_world_hint": False},
            SideEffectClass.STATE_MODIFYING,
        ),
    ],
)
def test_side_effect_class_from_annotations(
    annotations: dict[str, Any] | None, expected: SideEffectClass
) -> None:
    assert side_effect_class(_tool(annotations)) is expected


def test_observed_effects_override_hints() -> None:
    tool = _tool({"read_only_hint": True}, SideEffectProfile(write=True, destructive=True))
    assert side_effect_class(tool) is SideEffectClass.DESTRUCTIVE
    egress = _tool(
        {"read_only_hint": True}, SideEffectProfile(read=True, egress_destinations=["evil.example"])
    )
    assert side_effect_class(egress) is SideEffectClass.COMMUNICATE
    assert is_open_world(egress) is True
    assert CapabilityClass.NETWORK_EGRESS in capabilities(egress)
    assert side_effect_class(_tool(None, SideEffectProfile(financial=True))) is SideEffectClass.FINANCIAL
    assert side_effect_class(_tool(None, SideEffectProfile(read=True))) is SideEffectClass.READ_ONLY
    assert side_effect_class(_tool(None, SideEffectProfile(write=True))) is SideEffectClass.STATE_MODIFYING
    assert is_open_world(_tool(None)) is None


def _server(client: str, **flags: str) -> ToolServer:
    return ToolServer(
        id="server:s",
        name="s",
        kind=ToolServerKind.MCP,
        client=client,
        transport=Claim.declared(Transport.STDIO),
        authentication=Claim.declared(Authentication(mode=AuthMode.NONE)),
        crosses_trust_boundary=Claim.declared(False),
        client_trust_flags=flags,
    )


@pytest.mark.parametrize(
    ("client", "flags", "tool", "gate"),
    [
        ("claude-code", {}, "t", ApprovalGate.REQUIRED),
        ("claude-code", {"claude-code.defaultMode.user": "bypassPermissions"}, "t", ApprovalGate.NONE),
        ("claude-code", {"claude-code.permissions.allow": "t,other"}, "t", ApprovalGate.NONE),
        ("claude-code", {"claude-code.permissions.allow": "other"}, "t", ApprovalGate.REQUIRED),
        ("claude-code", {"claude-code.permissions.allow": "*"}, "t", ApprovalGate.NONE),
        ("vscode", {"vscode.chat.tools.autoApprove": "true"}, "t", ApprovalGate.NONE),
        ("vscode", {}, "t", ApprovalGate.REQUIRED),
        ("gemini-cli", {"gemini-cli.trust": "true"}, "t", ApprovalGate.NONE),
        ("codex", {"codex.approval_policy": "never"}, "t", ApprovalGate.NONE),
        ("codex", {"codex.approval_policy": "untrusted"}, "t", ApprovalGate.REQUIRED),
        ("codex", {}, "t", ApprovalGate.CONDITIONAL),
        ("cline", {"cline.autoApprove": "t"}, "t", ApprovalGate.NONE),
        ("cline", {}, "t", ApprovalGate.REQUIRED),
        ("roo", {"roo.alwaysAllow": "t"}, "t", ApprovalGate.CONDITIONAL),
        ("kiro", {"kiro.autoApprove": "t"}, "t", ApprovalGate.NONE),
        ("zed", {"zed.agent.tool_permissions.default": "allow"}, "t", ApprovalGate.NONE),
        ("zed", {}, "t", ApprovalGate.REQUIRED),
        ("opencode", {"opencode.permission": "allow"}, "t", ApprovalGate.NONE),
        ("opencode", {}, "t", ApprovalGate.UNKNOWN),
        ("goose", {}, "t", ApprovalGate.NONE),
        ("goose", {"goose.GOOSE_MODE": "approve"}, "t", ApprovalGate.REQUIRED),
        ("amazon-q", {"amazon-q.allowedTools": "@s"}, "t", ApprovalGate.NONE),
        ("amazon-q", {}, "t", ApprovalGate.REQUIRED),
        ("openclaw", {}, "t", ApprovalGate.NONE),
        ("cursor", {}, "t", ApprovalGate.UNKNOWN),
    ],
)
def test_server_approval_gate(client: str, flags: dict[str, str], tool: str, gate: ApprovalGate) -> None:
    assert server_approval_gate(_server(client, **flags), tool).gate is gate


def test_tool_gate_wins_over_client() -> None:
    tool = _tool({"read_only_hint": True}).replace(approval_gate=ApprovalGate.REQUIRED)
    assert (
        approval_gate(tool, _server("vscode", **{"vscode.chat.tools.autoApprove": "true"})).gate
        is ApprovalGate.REQUIRED
    )
    assert approval_gate(_tool(), None).gate is ApprovalGate.UNKNOWN
