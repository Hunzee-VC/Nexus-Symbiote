"""Authorization checks ``SYM-AUTHZ-*``, human-in-the-loop and credential hygiene (``spec/checks.md``)."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterator

from symbiote.authz.classify import capabilities, server_approval_gate
from symbiote.authz.trifecta import assess_all
from symbiote.model.entities import CredentialBinding, Finding, ToolDefinition
from symbiote.model.enums import (
    ApprovalGate,
    CapabilityClass,
    CredentialKind,
    CredentialStorageKind,
    EdgeType,
    EnforcementPointKind,
    FindingState,
    Severity,
    TriState,
    ValueState,
)
from symbiote.policy.spec import CheckSpec, PolicyContext, asi, atlas, check

_DANGEROUS_CAPS = {
    CapabilityClass.WRITE,
    CapabilityClass.EXECUTE,
    CapabilityClass.PAYMENT,
    CapabilityClass.CREDENTIALS,
}
_NON_READ = set(CapabilityClass) - {CapabilityClass.READ}


@check(
    "SYM-AUTHZ-001",
    "Lethal trifecta / Rule of Two",
    Severity.CRITICAL,
    mappings=(asi(1), asi(2), atlas("AML.T0086"), atlas("AML.T0051")),
    inputs=(
        "edges[readsContextFrom]",
        "data_sources[]",
        "credential_bindings[]",
        "tools[]",
        "tool_servers[]",
    ),
    remediation=(
        "Break one leg: remove untrusted-content tools from this agent, or remove its access to private data, or "
        "require human approval on every tool that can send data out or change state. Prefer splitting the work "
        "across agents so no single context holds all three."
    ),
)
def trifecta(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Untrusted input + sensitive access + external communication (or state change) without a human gate."""
    for a in assess_all(ctx.index):
        legs = f"untrusted input={a.untrusted_input.value.value}, sensitive access={a.sensitive_access.value.value}, exfiltration={a.exfiltration.value.value}, state change={a.state_change.value.value}"
        note = " (some legs from name heuristics)" if a.heuristic else ""
        if a.lethal_trifecta is TriState.TRUE:
            yield spec.finding(
                ctx,
                subjects=[a.agent_id],
                inputs=a.inputs,
                message=f"Lethal trifecta: {legs}{note}. Reasons: {'; '.join([*a.untrusted_input.reasons[:2], *a.sensitive_access.reasons[:2], *a.exfiltration.reasons[:2]])}.",
            )
        elif a.rule_of_two is TriState.TRUE:
            yield spec.finding(
                ctx,
                subjects=[a.agent_id],
                inputs=a.inputs,
                severity=Severity.HIGH,
                message=f"Rule of Two violated (untrusted input, sensitive access and ungated state change): {legs}{note}.",
            )
        elif TriState.UNKNOWN in (a.lethal_trifecta, a.rule_of_two):
            yield spec.finding(
                ctx,
                subjects=[a.agent_id],
                inputs=a.inputs,
                state=FindingState.INDETERMINATE,
                message=f"Trifecta assessment incomplete: {legs}.",
            )


def _required_scopes(tool: ToolDefinition) -> set[str] | None:
    claim = tool.required_scopes
    if claim is None or claim.state is not ValueState.PRESENT or claim.value is None:
        return None
    return set(claim.value)


@check(
    "SYM-AUTHZ-002",
    "Least-privilege gap",
    Severity.HIGH,
    mappings=(asi(3),),
    inputs=("tools[].required_scopes", "credential_bindings[].scopes_granted"),
    remediation="Re-issue the credential with exactly the scopes the tools need; record required scopes so drift is detected.",
)
def least_privilege(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """granted - required is non-empty (over-privilege, high); required - granted is non-empty (misconfiguration, medium)."""
    for server in ctx.bom.tool_servers:
        tools = ctx.index.tools_of_server(server.id)
        required_sets = [r for r in (_required_scopes(t) for t in tools) if r is not None]
        if not required_sets:
            continue
        required = set().union(*required_sets)
        for binding in ctx.index.credentials_of(server.id):
            claim = binding.scopes_granted
            if claim is None or claim.state is not ValueState.PRESENT or claim.value is None:
                continue
            granted = set(claim.value)
            if granted - required:
                yield spec.finding(
                    ctx,
                    subjects=[binding.id],
                    inputs=[server.id, *(t.id for t in tools)],
                    message=f"Credential grants unused scopes {sorted(granted - required)}.",
                )
            if required - granted:
                yield spec.finding(
                    ctx,
                    subjects=[binding.id],
                    inputs=[server.id],
                    severity=Severity.MEDIUM,
                    message=f"Credential lacks required scopes {sorted(required - granted)}.",
                )


def _holder_caps(ctx: PolicyContext, binding: CredentialBinding) -> set[CapabilityClass] | None:
    holder = binding.subject_ref
    tools = ctx.index.tools_of_server(holder) or [t for t in ctx.bom.tools if t.id == holder]
    caps = {c for t in tools for c in capabilities(t)} | {g.capability for g in ctx.index.grants_for(holder)}
    return caps or None


@check(
    "SYM-AUTHZ-003",
    "Long-lived credential for a dangerous capability",
    Severity.HIGH,
    mappings=(asi(3), atlas("AML.T0098")),
    inputs=("credential_bindings[].kind", "tools[].capabilities", "grants[]"),
    remediation="Replace the static token with short-lived, task-scoped credentials (OAuth token exchange, workload identity, OIDC trusted publishing).",
)
def long_lived_dangerous(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """credential.kind = static-long-lived ∧ capability ∈ {write, execute, payment, credentials}."""
    for binding in ctx.bom.credential_bindings:
        if binding.credential_kind is not CredentialKind.STATIC_LONG_LIVED:
            continue
        caps = _holder_caps(ctx, binding)
        if caps is None:
            yield spec.finding(
                ctx,
                subjects=[binding.id],
                inputs=[binding.subject_ref],
                state=FindingState.INDETERMINATE,
                message=f"Static long-lived credential {binding.name or binding.id!r}; the capabilities it unlocks are unknown.",
            )
        elif caps & _DANGEROUS_CAPS:
            yield spec.finding(
                ctx,
                subjects=[binding.id],
                inputs=[binding.subject_ref],
                message=f"Static long-lived credential {binding.name or binding.id!r} unlocks {sorted(c.value for c in caps & _DANGEROUS_CAPS)}.",
            )


@check(
    "SYM-AUTHZ-004",
    "Unauthenticated write",
    Severity.HIGH,
    mappings=(asi(3),),
    inputs=("credential_bindings[].kind", "tools[].capabilities"),
    remediation="Authenticate the integration; anonymous write access cannot be attributed or revoked.",
)
def unauthenticated_write(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """An unauthenticated binding backs a non-read capability."""
    for binding in ctx.bom.credential_bindings:
        if binding.credential_kind is CredentialKind.UNAUTHENTICATED:
            caps = _holder_caps(ctx, binding) or set()
            if caps & _NON_READ:
                yield spec.finding(
                    ctx,
                    subjects=[binding.id],
                    inputs=[binding.subject_ref],
                    message="Unauthenticated access backs a non-read capability.",
                )


@check(
    "SYM-AUTHZ-005",
    "Unconstrained delegation",
    Severity.HIGH,
    mappings=(asi(7), asi(3)),
    inputs=("grants[].delegation_chain", "edges[delegatesTo]"),
    remediation="Constrain every delegation with an audience, scopes and an expiry (RFC 8693 token exchange); never forward the caller's full token.",
)
def unconstrained_delegation(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A delegation hop without scopes, constraints or expiry."""
    for grant in ctx.bom.grants:
        for hop in grant.delegation_chain:
            if not hop.scopes and not hop.constraints and hop.expires is None:
                yield spec.finding(
                    ctx,
                    subjects=[grant.id],
                    inputs=[hop.from_ref, hop.to_ref],
                    message=f"Delegation {hop.from_ref} → {hop.to_ref} carries no scopes, constraints or expiry.",
                )
    for edge in ctx.bom.edges:
        if edge.type is EdgeType.DELEGATES_TO and not any(
            k in edge.qualifiers for k in ("scopes", "constraints", "expires", "grant_ref", "grantRef")
        ):
            if "self-published-card" in getattr(ctx.index.get(edge.to_ref), "tags", []):
                continue
            yield spec.finding(
                ctx,
                subjects=[edge.from_ref],
                inputs=[edge.to_ref],
                state=FindingState.INDETERMINATE,
                message=f"Delegation to {edge.to_ref} has no recorded scope, constraint or expiry.",
            )


@check(
    "SYM-AUTHZ-006",
    "No enforcement point for a non-read grant",
    Severity.HIGH,
    mappings=(asi(10),),
    inputs=("grants[].enforcement_point",),
    remediation="Enforce the grant somewhere that can say no — a tool gateway, authorization service, sandbox or network policy — and record it.",
)
def no_enforcement_point(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """enforcement_point.kind = none on a non-read grant (unknown → indeterminate)."""
    for grant in ctx.bom.grants:
        if grant.capability is CapabilityClass.READ:
            continue
        kind = grant.enforcement_point.kind
        if kind is EnforcementPointKind.NONE:
            yield spec.finding(
                ctx,
                subjects=[grant.id],
                message=f"Grant {grant.capability.value} on {grant.subject_ref} is not enforced anywhere.",
            )
        elif kind is EnforcementPointKind.UNKNOWN:
            yield spec.finding(
                ctx,
                subjects=[grant.id],
                state=FindingState.INDETERMINATE,
                message=f"Enforcement point of grant {grant.capability.value} on {grant.subject_ref} is unknown.",
            )


@check(
    "SYM-AUTHZ-007",
    "Observed egress outside every grant",
    Severity.HIGH,
    mappings=(asi(2), atlas("AML.T0086")),
    inputs=("tools[].side_effects.egress_destinations", "grants[].scope.egress"),
    remediation="Block the destination at the egress proxy and investigate: data left for a host no grant allows.",
)
def undeclared_egress(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """An observed egress destination matches no grant scope."""
    patterns = [p.removeprefix("glob:") for g in ctx.bom.grants for p in g.scope.egress]
    for tool in ctx.bom.tools:
        claim = tool.side_effects
        if claim is None or claim.state is not ValueState.PRESENT or claim.value is None:
            continue
        for dest in claim.value.egress_destinations:
            if not any(fnmatch.fnmatch(dest, p) for p in patterns):
                yield spec.finding(
                    ctx,
                    subjects=[tool.id],
                    message=f"Tool {tool.tool_name!r} sent data to {dest!r}, which no grant allows.",
                )


@check(
    "SYM-HITL-001",
    "Human approval disabled by client settings",
    Severity.HIGH,
    mappings=(asi(9), asi(2)),
    inputs=("tool_servers[].client_trust_flags",),
    remediation=(
        "Remove blanket auto-approval (Claude Code bypassPermissions, VS Code chat.tools.autoApprove, Gemini trust, "
        "Codex approval_policy=never): approve read-only tools individually and keep a human on anything that writes "
        "or sends data."
    ),
    extension=True,
)
def approval_disabled(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A client setting removes the human from every call to a server (not a per-tool allow rule)."""
    for server in ctx.bom.tool_servers:
        decision = server_approval_gate(server, None)
        blanket = decision.gate is ApprovalGate.NONE and "covers this tool" not in decision.reason
        if blanket:
            yield spec.finding(
                ctx,
                subjects=[server.id],
                message=f"Server {server.name!r}: every tool call runs without approval ({decision.reason}).",
            )


@check(
    "SYM-CRED-001",
    "Credential stored in plaintext configuration",
    Severity.HIGH,
    mappings=(asi(3), atlas("AML.T0098")),
    inputs=("credential_bindings[].storage",),
    remediation="Move the secret to the OS keychain, a secret manager or an environment variable injected at runtime, rotate it, and reference it by name (${VAR} / ${input:id}).",
    extension=True,
)
def plaintext_credential(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """An inline secret in an agent or MCP client configuration file (harvestable by malware that reads configs)."""
    for binding in ctx.bom.credential_bindings:
        if binding.storage.kind is CredentialStorageKind.FILE and "inline-secret-in-config" in binding.tags:
            yield spec.finding(
                ctx,
                subjects=[binding.id],
                inputs=[binding.subject_ref],
                message=f"A secret is stored inline in {binding.storage.locator}.",
            )
