"""Side-effect classes, capability classes and approval gates (``spec/checks.md`` §1).

All functions are pure over model objects and return both a value and the *reason* it was chosen, so checks
and flags can cite their inputs. MCP tool annotations are untrusted hints declared by the server: when they
are absent the MCP defaults apply (``destructiveHint`` and ``openWorldHint`` default to ``true``), and
observed or verified side effects override declared hints when they conflict.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from symbiote.model.entities import SideEffectProfile, ToolAnnotations, ToolDefinition, ToolServer
from symbiote.model.enums import ApprovalGate, AssuranceLevel, CapabilityClass, SideEffectClass, ValueState

__all__ = [
    "ApprovalDecision",
    "approval_gate",
    "capabilities",
    "is_open_world",
    "server_approval_gate",
    "side_effect_class",
]

_EVIDENCED: Final = (AssuranceLevel.OBSERVED, AssuranceLevel.VERIFIED)


def _annotations(tool: ToolDefinition) -> ToolAnnotations | None:
    claim = tool.annotations
    if claim is None or claim.state is not ValueState.PRESENT:
        return None
    return claim.value


def _observed_effects(tool: ToolDefinition) -> SideEffectProfile | None:
    claim = tool.side_effects
    if claim is None or claim.state is not ValueState.PRESENT or claim.assurance not in _EVIDENCED:
        return None
    return claim.value


def side_effect_class(tool: ToolDefinition) -> SideEffectClass:
    """Classify a tool per ``checks.md`` §1 (observed effects win over declared hints)."""
    observed = _observed_effects(tool)
    if observed is not None:
        if observed.financial:
            return SideEffectClass.FINANCIAL
        if observed.destructive:
            return SideEffectClass.DESTRUCTIVE
        if observed.egress_destinations or observed.open_world:
            return SideEffectClass.COMMUNICATE
        if observed.write:
            return SideEffectClass.STATE_MODIFYING
        if observed.read:
            return SideEffectClass.READ_ONLY
    ann = _annotations(tool)
    if ann is None or not ann.any_present:
        return (
            tool.side_effect_class
            if tool.side_effect_class is not SideEffectClass.UNKNOWN
            else SideEffectClass.UNKNOWN
        )
    if ann.read_only_hint is True:
        return SideEffectClass.READ_ONLY
    if ann.destructive_hint is not False:  # MCP default: destructive unless declared otherwise
        return SideEffectClass.DESTRUCTIVE
    if ann.open_world_hint is not False:  # MCP default: open world
        return SideEffectClass.COMMUNICATE
    return SideEffectClass.STATE_MODIFYING


def is_open_world(tool: ToolDefinition) -> bool | None:
    """True/False from evidence or annotations; ``None`` when nothing is known (MCP default would be True)."""
    observed = _observed_effects(tool)
    if observed is not None:
        return bool(observed.open_world or observed.egress_destinations)
    ann = _annotations(tool)
    if ann is None or ann.open_world_hint is None:
        return None
    return ann.open_world_hint


_CLASS_CAPS: Final[dict[SideEffectClass, tuple[CapabilityClass, ...]]] = {
    SideEffectClass.READ_ONLY: (CapabilityClass.READ,),
    SideEffectClass.STATE_MODIFYING: (CapabilityClass.WRITE,),
    SideEffectClass.DESTRUCTIVE: (CapabilityClass.WRITE,),
    SideEffectClass.FINANCIAL: (CapabilityClass.PAYMENT, CapabilityClass.WRITE),
    SideEffectClass.COMMUNICATE: (CapabilityClass.COMMUNICATE, CapabilityClass.NETWORK_EGRESS),
    SideEffectClass.UNKNOWN: (),
}


def capabilities(
    tool: ToolDefinition, granted: tuple[CapabilityClass, ...] = ()
) -> tuple[CapabilityClass, ...]:
    """Union of declared capabilities, the side-effect class mapping, open-world egress and grants."""
    caps: set[CapabilityClass] = set(tool.capabilities) | set(granted)
    caps.update(_CLASS_CAPS[side_effect_class(tool)])
    if is_open_world(tool):
        caps.add(CapabilityClass.NETWORK_EGRESS)
    ann = _annotations(tool)
    observed = _observed_effects(tool)
    if (ann is not None and ann.read_only_hint is False and observed is None) or (
        observed is not None and observed.write
    ):
        caps.add(
            CapabilityClass.WRITE
        )  # readOnlyHint=false: the tool modifies its environment (MCP semantics)
    return tuple(sorted(caps, key=lambda c: c.value))


# --------------------------------------------------------------------------------------------- approval gates


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    gate: ApprovalGate
    reason: str


#: How each client behaves for MCP tool calls when no auto-approval setting applies.
_CLIENT_DEFAULT: Final[dict[str, ApprovalDecision]] = {
    "claude-code": ApprovalDecision(
        ApprovalGate.REQUIRED, "claude-code prompts for MCP tools unless allowed"
    ),
    "claude-desktop": ApprovalDecision(
        ApprovalGate.REQUIRED, "claude-desktop prompts for tool use by default"
    ),
    "vscode": ApprovalDecision(
        ApprovalGate.REQUIRED, "VS Code asks for confirmation of MCP tool calls by default"
    ),
    "gemini-cli": ApprovalDecision(
        ApprovalGate.REQUIRED, "gemini-cli confirms tool calls unless the server is trusted"
    ),
    "codex": ApprovalDecision(ApprovalGate.CONDITIONAL, "codex approval depends on approval_policy"),
}

_CODEX_POLICY: Final[dict[str, ApprovalDecision]] = {
    "never": ApprovalDecision(ApprovalGate.NONE, "codex approval_policy=never"),
    "on-failure": ApprovalDecision(ApprovalGate.CONDITIONAL, "codex approval_policy=on-failure"),
    "on-request": ApprovalDecision(ApprovalGate.CONDITIONAL, "codex approval_policy=on-request"),
    "untrusted": ApprovalDecision(ApprovalGate.REQUIRED, "codex approval_policy=untrusted"),
}


def _listed(flags: Mapping[str, str], key: str, tool_name: str | None) -> bool:
    value = flags.get(key)
    if not value:
        return False
    entries = {v.strip() for v in value.split(",") if v.strip()}
    return "*" in entries or (tool_name is not None and tool_name in entries)


def server_approval_gate(server: ToolServer, tool_name: str | None = None) -> ApprovalDecision:
    """Approval gate implied by the client's auto-approval settings for ``tool_name`` on ``server``.

    ``none`` means a human never sees the call: Claude Code ``bypassPermissions`` or an ``mcp__srv__tool``
    allow rule, VS Code ``chat.tools.autoApprove``, Gemini ``trust``, Codex ``approval_policy=never``, Cline
    ``autoApprove`` lists. Unknown clients yield ``unknown`` (never assumed safe).
    """
    flags = server.client_trust_flags
    client = server.client or ""
    if any(v == "bypassPermissions" for k, v in flags.items() if k.startswith("claude-code.defaultMode")):
        return ApprovalDecision(ApprovalGate.NONE, "claude-code defaultMode=bypassPermissions")
    if _listed(flags, "claude-code.permissions.allow", tool_name):
        return ApprovalDecision(ApprovalGate.NONE, "claude-code permissions.allow covers this tool")
    if (
        flags.get("vscode.chat.tools.autoApprove") == "true"
        or flags.get("vscode.chat.tools.global.autoApprove") == "true"
    ):
        return ApprovalDecision(ApprovalGate.NONE, "VS Code chat.tools.autoApprove=true")
    if flags.get("gemini-cli.trust") == "true":
        return ApprovalDecision(ApprovalGate.NONE, "gemini-cli trust=true bypasses confirmations")
    for key in ("cline.autoApprove", "roo.alwaysAllow", "kiro.autoApprove", "cline.alwaysAllow"):
        if _listed(flags, key, tool_name):
            return ApprovalDecision(ApprovalGate.NONE, f"{key} lists this tool")
    if client == "codex":
        policy = flags.get("codex.approval_policy")
        if policy in _CODEX_POLICY:
            return _CODEX_POLICY[policy]
    return _CLIENT_DEFAULT.get(
        client, ApprovalDecision(ApprovalGate.UNKNOWN, f"no approval facts for client {client or 'unknown'}")
    )


def approval_gate(tool: ToolDefinition, server: ToolServer | None) -> ApprovalDecision:
    """Effective approval gate for a tool: an explicit gate on the tool wins, then client settings."""
    if tool.approval_gate is not ApprovalGate.UNKNOWN:
        return ApprovalDecision(tool.approval_gate, "declared on the tool definition")
    if server is None:
        return ApprovalDecision(ApprovalGate.UNKNOWN, "tool has no server")
    return server_approval_gate(server, tool.tool_name)
