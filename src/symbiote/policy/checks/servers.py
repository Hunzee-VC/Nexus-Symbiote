"""Tool-server checks ``SYM-MCP-*`` (``spec/checks.md`` §2 and the §2.1 extensions)."""

from __future__ import annotations

from collections.abc import Iterator

from symbiote.authz.classify import capabilities, server_approval_gate
from symbiote.authz.flags import unauthenticated_tool_server
from symbiote.model.entities import Finding, ToolServer
from symbiote.model.enums import (
    ApprovalGate,
    CapabilityClass,
    FindingState,
    RegistryStatus,
    Severity,
    Transport,
    TriState,
    TrustZone,
    ValueState,
)
from symbiote.policy.spec import CheckSpec, PolicyContext, asi, atlas, check

_PRIVILEGED = {
    CapabilityClass.WRITE,
    CapabilityClass.EXECUTE,
    CapabilityClass.CREDENTIALS,
    CapabilityClass.PAYMENT,
}


def _float_reason(server: ToolServer) -> str:
    return next(
        (t.split(":", 1)[1] for t in server.tags if t.startswith("float:")), "no immutable version or digest"
    )


@check(
    "SYM-MCP-001",
    "Unauthenticated tool server across a trust boundary",
    Severity.HIGH,
    mappings=(asi(3),),
    inputs=(
        "tool_servers[].authentication",
        "tool_servers[].crosses_trust_boundary",
        "tools[].capabilities",
        "grants[]",
    ),
    remediation="Require OAuth 2.1 (MCP authorization) or mTLS on the server, and scope the token to the tools the agent needs.",
)
def unauthenticated(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """authentication.mode = none ∧ crosses_trust_boundary ∧ a capability in {write, execute, credentials, payment}."""
    for server in ctx.bom.tool_servers:
        value, inputs = unauthenticated_tool_server(server)
        if value is TriState.FALSE:
            continue
        tools = ctx.index.tools_of_server(server.id)
        caps = {c for t in tools for c in capabilities(t)} | {
            g.capability for g in ctx.index.grants_for(server.id)
        }
        privileged = caps & _PRIVILEGED
        if value is TriState.TRUE and privileged:
            yield spec.finding(
                ctx,
                subjects=[server.id],
                inputs=[*inputs, *(t.id for t in tools)],
                message=f"Server {server.name!r} accepts unauthenticated calls across a trust boundary and exposes {sorted(c.value for c in privileged)}.",
            )
        elif value is TriState.TRUE or (
            value is TriState.UNKNOWN and server.crosses_trust_boundary.value is True
        ):
            yield spec.finding(
                ctx,
                subjects=[server.id],
                inputs=inputs,
                state=FindingState.INDETERMINATE,
                message=f"Server {server.name!r} crosses a trust boundary; its authentication or tool capabilities are unknown.",
            )


@check(
    "SYM-MCP-002",
    "Floating package launch",
    Severity.HIGH,
    mappings=(asi(4), atlas("AML.T0010")),
    inputs=("tool_servers[].package",),
    remediation="Pin the launcher to an exact version (`npx -y pkg@1.2.3`, `uvx pkg==1.2.3`) or an OCI digest (`image@sha256:…`); better, install from a lockfile and launch the local binary.",
)
def floating_package(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A stdio launcher resolves a package without an immutable version or digest (npx -y pkg, pkg@latest, uvx pkg, image:tag)."""
    for server in ctx.bom.tool_servers:
        pkg = server.package
        if pkg is None or pkg.state is not ValueState.PRESENT or pkg.value is None or not pkg.value.floating:
            continue
        yield spec.finding(
            ctx,
            subjects=[server.id],
            message=f"Server {server.name!r} launches {pkg.value.purl or 'a registry package'} without pinning ({_float_reason(server)}): every start may fetch new code.",
        )


@check(
    "SYM-MCP-003",
    "Insecure transport to a remote server",
    Severity.MEDIUM,
    mappings=(asi(7),),
    inputs=("tool_servers[].endpoint", "tool_servers[].crosses_trust_boundary"),
    remediation="Use an https:// endpoint; plaintext MCP traffic exposes tokens and lets an on-path attacker rewrite tool definitions.",
)
def insecure_transport(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Remote endpoint scheme is not https."""
    for server in ctx.bom.tool_servers:
        if server.transport.value is Transport.STDIO or server.endpoint is None or not server.endpoint.value:
            continue
        crosses = server.crosses_trust_boundary.value is True
        if crosses and not server.endpoint.value.lower().startswith(("https://", "wss://")):
            yield spec.finding(
                ctx,
                subjects=[server.id],
                message=f"Server {server.name!r} is reached over plaintext ({server.endpoint.value}).",
            )


@check(
    "SYM-MCP-004",
    "Registry status deleted or deprecated",
    Severity.HIGH,
    mappings=(asi(4),),
    inputs=("resolutions[].registry.status",),
    remediation="Replace the server: a deleted registry entry can be re-registered by anyone (namespace reuse); a deprecated one no longer receives fixes.",
)
def registry_status(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Resolution status deleted (high) / deprecated (medium); unknown → indeterminate."""
    for res in ctx.bom.resolutions:
        status = res.registry.status if res.registry else RegistryStatus.UNKNOWN
        users = [e.from_ref for e in ctx.index.into(res.id)]
        if status is RegistryStatus.DELETED:
            yield spec.finding(
                ctx,
                subjects=[res.id, *users],
                message=f"{res.requested.ref!r} resolves to a deleted registry entry.",
            )
        elif status is RegistryStatus.DEPRECATED:
            yield spec.finding(
                ctx,
                subjects=[res.id, *users],
                severity=Severity.MEDIUM,
                message=f"{res.requested.ref!r} resolves to a deprecated registry entry.",
            )
        elif status is RegistryStatus.UNKNOWN and res.registry is not None:
            yield spec.finding(
                ctx,
                subjects=[res.id, *users],
                state=FindingState.INDETERMINATE,
                message=f"Registry status of {res.requested.ref!r} is unknown.",
            )


@check(
    "SYM-MCP-005",
    "Typosquat or name/package mismatch",
    Severity.HIGH,
    mappings=(asi(4), atlas("AML.T0010")),
    inputs=("resolutions[].typosquat_distance", "resolutions[].warnings"),
    remediation="Confirm the publisher out of band and pin the exact package identity; look-alike names are a standard registry attack.",
)
def typosquat(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Levenshtein ≤ 2 to a more popular registry name, or registry package identity ≠ configured package."""
    for res in ctx.bom.resolutions:
        near = res.typosquat_distance
        mismatch = [w for w in res.warnings if "mismatch" in w]
        if (near is not None and 0 < near.levenshtein <= 2) or mismatch:
            detail = (
                f"within edit distance {near.levenshtein} of {near.nearest!r}"
                if near and near.levenshtein <= 2
                else "; ".join(mismatch)
            )
            yield spec.finding(
                ctx, subjects=[res.id], message=f"{res.requested.ref!r} is suspicious: {detail}."
            )


@check(
    "SYM-MCP-006",
    "Mixed-trust composition without per-server gates",
    Severity.MEDIUM,
    mappings=(asi(4), asi(1)),
    inputs=("tool_servers[].trust_zone", "tool_servers[].client_trust_flags"),
    remediation="Gate the external servers (require approval) or split the agent so external and internal tools are not exposed to the same context.",
)
def mixed_trust(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Tools from external and internal zones exposed to one agent without per-server approval."""
    for agent in ctx.index.agents():
        servers = ctx.index.servers_of(agent.id)
        external = [s for s in servers if s.trust_zone in (TrustZone.EXTERNAL, TrustZone.PARTNER)]
        internal = [
            s
            for s in servers
            if s.trust_zone in (TrustZone.INTERNAL, TrustZone.LOCAL_PROCESS, TrustZone.LOOPBACK)
        ]
        ungated = [s for s in external if server_approval_gate(s).gate is not ApprovalGate.REQUIRED]
        if ungated and internal:
            yield spec.finding(
                ctx,
                subjects=[agent.id],
                inputs=[s.id for s in (*ungated, *internal)],
                message=f"Agent combines {len(ungated)} ungated external server(s) with {len(internal)} internal/local server(s).",
            )


@check(
    "SYM-MCP-007",
    "Tool server launched in a privileged container",
    Severity.HIGH,
    mappings=(asi(5), asi(3)),
    inputs=("tool_servers[].client_trust_flags"),
    remediation="Drop --privileged, host namespaces, docker.sock and host-root mounts; run the server as non-root with a read-only filesystem and an egress allowlist.",
    extension=True,
)
def privileged_container(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """docker/podman flags that hand the server the host (privileged, host network/pid, docker.sock, / mounts, root user)."""
    for server in ctx.bom.tool_servers:
        risks = sorted(
            {
                r
                for k, v in server.client_trust_flags.items()
                if k.endswith(".container-risks")
                for r in v.split(",")
                if r
            }
        )
        if risks:
            yield spec.finding(
                ctx,
                subjects=[server.id],
                message=f"Server {server.name!r} container runs with {', '.join(risks)}.",
            )


@check(
    "SYM-MCP-008",
    "Repository MCP servers auto-enabled",
    Severity.MEDIUM,
    mappings=(asi(4), asi(9)),
    inputs=("tool_servers[].client_trust_flags",),
    remediation="Turn off enableAllProjectMcpServers and approve project servers individually: a cloned repository should not be able to start processes on your machine.",
    extension=True,
)
def project_servers_auto_enabled(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Claude Code ``enableAllProjectMcpServers=true``: servers from a repository's .mcp.json start without consent."""
    affected = [
        s.id
        for s in ctx.bom.tool_servers
        if s.client_trust_flags.get("claude-code.enableAllProjectMcpServers") == "true"
        and "scope:project" in s.tags
    ]
    if affected:
        yield spec.finding(
            ctx,
            subjects=affected,
            message=f"{len(affected)} project-scoped server(s) are enabled automatically for any checkout of this repository.",
        )
