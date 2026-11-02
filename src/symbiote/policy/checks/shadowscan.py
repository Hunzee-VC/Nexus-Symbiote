"""ShadowScan reconciliation checks ``SYM-SS-*`` (``spec/checks.md §2.2``, ``spec/shadowscan-mapping.md §5``).

These checks read facts the ShadowScan importer records (``autonomy_assessment``, ``shadow`` tags, coverage
runs named ``shadowscan:*``) and, when a baseline is supplied, compare observed tool servers with declared
ones. ``symbiote shadowscan reconcile`` produces the same findings outside the engine through
:func:`specs`/``finding_plain`` so one vocabulary serves both paths.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from symbiote.model.entities import Finding
from symbiote.model.enums import CollectorStatus, FindingState, Severity, ToolServerKind
from symbiote.policy.spec import CHECKS, CheckSpec, PolicyContext, asi, atlas, check

_PREFIX = "SYM-SS-"


def finding_plain(
    spec: CheckSpec,
    *,
    subjects: Iterable[str],
    message: str,
    inputs: Iterable[str] = (),
    state: FindingState = FindingState.FAIL,
    severity: Severity | None = None,
    locator: str | None = None,
) -> Finding:
    """Build a finding for ``spec`` without a :class:`PolicyContext` (used by ``reconcile``)."""
    subject_list = sorted(dict.fromkeys(subjects))
    return Finding(
        check_id=spec.id,
        severity=severity or spec.severity,
        state=state,
        subject_refs=subject_list,
        inputs=sorted(dict.fromkeys([*subject_list, *inputs])),
        message=message,
        mappings=list(spec.mappings),
        locator=locator,
    )


def specs() -> dict[str, CheckSpec]:
    return {k: v for k, v in CHECKS.items() if k.startswith(_PREFIX)}


@check(
    "SYM-SS-001",
    "Shadow component observed by ShadowScan",
    Severity.MEDIUM,
    mappings=(asi(10), asi(4), atlas("AML.T0010")),
    inputs=(
        "agents[].tags",
        "tool_servers[].tags",
        "identities[].tags",
        "derived.flags[undeclared-component-observed]",
    ),
    remediation=(
        "Decide: either add the component to the AgentBOM (then regenerate the ShadowScan inventory with "
        "`symbiote shadowscan inventory`) or remove it from the estate. A shadow component is one nobody approved."
    ),
    extension=True,
)
def shadow_component(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """An imported ShadowScan finding carried ``shadow: true`` (no inventory entry claimed it)."""
    for attr in ("agents", "tool_servers", "identities", "models", "deployments"):
        for ent in getattr(ctx.bom, attr):
            if "shadow" not in ent.tags:
                continue
            risk = ent.foreign.get("shadowscan:risk-level", "unknown")
            severity = Severity.HIGH if risk in ("critical", "high") else Severity.MEDIUM
            yield spec.finding(
                ctx,
                subjects=[ent.id],
                severity=severity,
                message=f"{ent.name or ent.id} was discovered by ShadowScan but is not in the supplied inventory ({risk} heuristic risk).",
            )


@check(
    "SYM-SS-002",
    "Tool server observed by ShadowScan but not declared",
    Severity.HIGH,
    mappings=(asi(4), asi(10), atlas("AML.T0010")),
    inputs=("tool_servers[]", "baseline.tool_servers[]"),
    remediation=(
        "Declare the server in the agent's configuration under review (so `symbiote scan` records it) or remove the "
        "configuration ShadowScan found. An MCP server the BOM does not know is an unreviewed tool surface."
    ),
    extension=True,
)
def observed_not_declared(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A ShadowScan-observed MCP server (same client and name scheme as ``mcp-config``) is absent from the baseline."""
    if ctx.baseline is None:
        return
    declared = {s.id for s in ctx.baseline.tool_servers}
    for server in ctx.bom.tool_servers:
        if "implemented-server" in server.tags or server.id in declared:
            continue
        if server.foreign.get("shadowscan:finding-id") is None:
            continue
        yield spec.finding(
            ctx,
            subjects=[ctx.bom.subject],
            inputs=[server.id],
            message=f"ShadowScan observed tool server {server.name!r} (client {server.client or 'unknown'}) that the baseline does not declare.",
        )


@check(
    "SYM-SS-003",
    "Declared tool server not observed by ShadowScan",
    Severity.MEDIUM,
    mappings=(asi(4),),
    inputs=("baseline.tool_servers[]", "tool_servers[]", "coverage.collectors[shadowscan:*]"),
    remediation=(
        "If the server was removed, update the declaration and re-seal; if ShadowScan's scan did not cover the "
        "repository, rerun it over the same root before treating the declaration as stale."
    ),
    extension=True,
)
def declared_not_observed(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A baseline tool server has no counterpart in a complete ShadowScan code scan (indeterminate otherwise)."""
    if ctx.baseline is None:
        return
    observed = {s.id for s in ctx.bom.tool_servers}
    runs = [c for c in ctx.bom.coverage.collectors if c.name.startswith("shadowscan:code")]
    complete = bool(runs) and all(c.status is CollectorStatus.OK for c in runs)
    if not observed and not runs:
        return
    for server in ctx.baseline.tool_servers:
        # ShadowScan does not inventory A2A peers, so their absence from its report says nothing
        if server.id in observed or server.server_kind is ToolServerKind.A2A:
            continue
        yield spec.finding(
            ctx,
            subjects=[server.id],
            inputs=[ctx.bom.subject],
            state=FindingState.FAIL if complete and observed else FindingState.INDETERMINATE,
            message=f"Declared tool server {server.name!r} was not observed by ShadowScan"
            + (
                " in a complete code scan."
                if complete and observed
                else "; coverage is incomplete, so absence is unknown."
            ),
        )


@check(
    "SYM-SS-004",
    "Declared automation level below the observed autonomy floor",
    Severity.HIGH,
    mappings=(asi(9), asi(2)),
    inputs=("agents[].automation_level", "agents[].autonomy_assessment"),
    remediation=(
        "Raise the declared level to what the evidence proves, or remove the capabilities that raised the floor "
        "(side-effecting tools, approval bypass, triggers). An understated declaration misleads every downstream gate."
    ),
    extension=True,
)
def autonomy_understated(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """``declared < floor`` on an agent's autonomy assessment (ShadowScan tag ``autonomy-understated``)."""
    for agent in ctx.index.agents():
        a = agent.autonomy_assessment
        if a is None or not a.understated:
            continue
        yield spec.finding(
            ctx,
            subjects=[agent.id],
            message=f"{agent.name or agent.id}: declared level L{a.declared} is below the observed floor L{a.floor} (ceiling L{a.ceiling}, scale {a.scale}).",
        )


@check(
    "SYM-SS-005",
    "Declared automation level above the observed ceiling",
    Severity.INFO,
    mappings=(asi(9),),
    inputs=("agents[].autonomy_assessment",),
    remediation=(
        "Positive configuration evidence (per-action approval) rules the declared level out; either the declaration "
        "is stale or the approval setting is not what runs in production. Check which, then align the two."
    ),
    extension=True,
)
def autonomy_above_ceiling(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """``declared > ceiling`` (ShadowScan basis note ``declared-above-ceiling``)."""
    for agent in ctx.index.agents():
        a = agent.autonomy_assessment
        if a is None or not a.above_ceiling:
            continue
        yield spec.finding(
            ctx,
            subjects=[agent.id],
            message=f"{agent.name or agent.id}: declared level L{a.declared} exceeds the observed ceiling L{a.ceiling}.",
        )


@check(
    "SYM-SS-006",
    "Approval bypass observed",
    Severity.HIGH,
    mappings=(asi(9), asi(2), asi(5)),
    inputs=("agents[].autonomy_assessment.oversight",),
    remediation=(
        "Restore a human gate on side-effecting actions: remove bypass modes (`bypassPermissions`, "
        '`approval_policy = "never"`, `GOOSE_MODE: auto`), MCP auto-approval lists and unrestricted shell allow rules, '
        "or move the agent to a sandbox whose blast radius you accept."
    ),
    extension=True,
)
def approval_bypassed(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """ShadowScan recorded approval-bypass evidence (``oversight: bypassed``) for an agent."""
    for agent in ctx.index.agents():
        a = agent.autonomy_assessment
        if a is None or a.oversight.value != "bypassed":
            continue
        rules = ", ".join(sorted({b.rule for b in a.basis if b.bound in ("oversight", "floor")}))
        yield spec.finding(
            ctx,
            subjects=[agent.id],
            message=f"{agent.name or agent.id}: side-effecting actions run without per-action approval (floor L{a.floor}; basis {rules or 'n/a'}).",
        )


@check(
    "SYM-SS-007",
    "ShadowScan report incomplete",
    Severity.INFO,
    mappings=(),
    inputs=("coverage.collectors[shadowscan:*]",),
    remediation=(
        "Fix the failing connector (credentials, timeouts, malformed exports) and rescan; ShadowScan exits 3 for an "
        "incomplete scan and Symbiote keeps every absence claim at `unknown` until the surface is queried."
    ),
    extension=True,
)
def report_incomplete(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A ShadowScan connector recorded in coverage did not complete (indeterminate, never a pass)."""
    bad = [
        c
        for c in ctx.bom.coverage.collectors
        if c.name.startswith("shadowscan:") and c.status in (CollectorStatus.PARTIAL, CollectorStatus.FAILED)
    ]
    if not bad:
        return
    yield spec.finding(
        ctx,
        subjects=[ctx.bom.subject],
        state=FindingState.INDETERMINATE,
        message="Incomplete ShadowScan connectors: "
        + ", ".join(f"{c.name} ({c.status.value})" for c in bad[:8])
        + ".",
    )


__all__ = ["finding_plain", "specs"]
