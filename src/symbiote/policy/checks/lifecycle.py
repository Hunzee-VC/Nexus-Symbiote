"""Snapshot, coverage, trust, attestation, evaluation, A2A, sub-agent and registry checks."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from symbiote.model.entities import Finding
from symbiote.model.enums import (
    AssuranceLevel,
    CoverageStatus,
    EdgeType,
    EvidenceVerification,
    Severity,
    SignatureOutcome,
    SignatureStatus,
    Surface,
    TrustState,
    TrustSubjectKind,
    ValueState,
)
from symbiote.policy.spec import CheckSpec, PolicyContext, asi, check

#: Which coverage surface vouches for claims in each collection (for SYM-COV-002).
_SURFACE_OF: dict[str, Surface] = {
    "tool_servers": Surface.TOOLS,
    "tools": Surface.TOOLS,
    "data_sources": Surface.DATA,
    "models": Surface.CODE,
    "identities": Surface.IDENTITY,
    "credential_bindings": Surface.IDENTITY,
    "instructions": Surface.INSTRUCTIONS,
    "prompts": Surface.INSTRUCTIONS,
    "skills": Surface.INSTRUCTIONS,
    "resolutions": Surface.REGISTRY,
    "grants": Surface.POLICY,
    "policies": Surface.POLICY,
}


@check(
    "SYM-SNAP-001",
    "Snapshot serial regression",
    Severity.CRITICAL,
    inputs=("snapshot.serial", "state"),
    remediation="Reject the document: a lower or equal serial for the same agent and kind is a replay of an older approval.",
)
def serial_regression(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """serial ≤ last seen for (agent, kind)."""
    snap = ctx.bom.snapshot
    last = ctx.state.get((snap.agent_ref, snap.kind.value))
    if last is not None and snap.serial <= int(last.get("serial", 0)):
        yield spec.finding(
            ctx,
            subjects=[ctx.bom.subject],
            message=f"Serial {snap.serial} is not newer than the last seen serial {last.get('serial')}.",
        )


@check(
    "SYM-SNAP-002",
    "Snapshot expired",
    Severity.HIGH,
    inputs=("snapshot.validity",),
    remediation="Produce and approve a fresh snapshot; enforcement points must fail closed on expired documents.",
)
def expired(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """now ≥ validity.not_after."""
    not_after = ctx.bom.snapshot.validity.not_after
    if not_after is not None and ctx.now >= not_after:
        yield spec.finding(
            ctx, subjects=[ctx.bom.subject], message=f"Snapshot expired at {not_after.isoformat()}."
        )


@check(
    "SYM-SNAP-003",
    "Snapshot chain gap",
    Severity.MEDIUM,
    inputs=("snapshot.prev", "state"),
    remediation="Fetch the missing snapshots and verify the chain before trusting this one.",
)
def chain_gap(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """prev ≠ last-seen digest."""
    snap = ctx.bom.snapshot
    last = ctx.state.get((snap.agent_ref, snap.kind.value))
    if last is not None and last.get("digest") and snap.prev != last.get("digest"):
        yield spec.finding(
            ctx, subjects=[ctx.bom.subject], message="This snapshot does not chain to the last one seen."
        )


@check(
    "SYM-COV-001",
    "Surfaces not covered",
    Severity.HIGH,
    inputs=("coverage.surfaces",),
    remediation="Enable the collectors for the missing surfaces (--live, --registry, --include-user, OTel traces) or record explicit exclusions; Verified conformance requires every surface queried.",
)
def surfaces_not_covered(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Any surface whose status is not ``queried`` (one finding listing them)."""
    missing = sorted(
        s.value for s, cov in ctx.bom.coverage.surfaces.items() if cov.status is not CoverageStatus.QUERIED
    )
    if missing:
        yield spec.finding(
            ctx, subjects=[ctx.bom.subject], message=f"Not fully covered: {', '.join(missing)}."
        )


def _absent_claims(obj: Any, path: str) -> Iterator[str]:
    if isinstance(obj, dict):
        if obj.get("state") == ValueState.ABSENT_VERIFIED.value:
            yield path
        for key, value in obj.items():
            yield from _absent_claims(value, f"{path}/{key}")
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _absent_claims(value, f"{path}/{i}")


@check(
    "SYM-COV-002",
    "Absence claimed without coverage",
    Severity.CRITICAL,
    inputs=("coverage.surfaces", "*[].claims.state"),
    remediation="Downgrade the claim to unknown or run the collector that examines that surface; 'nothing found' is only meaningful where we looked.",
)
def absence_without_coverage(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """An absent-verified claim on a surface whose status is not ``queried``."""
    for attr, surface in _SURFACE_OF.items():
        status = ctx.bom.coverage.surfaces[surface].status
        if status is CoverageStatus.QUERIED:
            continue
        for entity in getattr(ctx.bom, attr):
            paths = list(_absent_claims(entity.model_dump(mode="json", by_alias=True), ""))
            if paths:
                yield spec.finding(
                    ctx,
                    subjects=[entity.id],
                    message=f"Claims absence at {paths[0]} although surface {surface.value} is {status.value}.",
                )


def _component_keys(ctx: PolicyContext) -> dict[str, list[str]]:
    keys: dict[str, list[str]] = {}
    for tool in ctx.bom.tools:
        if tool.digest.value:
            keys.setdefault(tool.digest.value, []).append(tool.id)
    for server in ctx.bom.tool_servers:
        if server.digest:
            keys.setdefault(server.digest, []).append(server.id)
    for model in ctx.bom.models:
        if model.weights is not None and model.weights.value is not None:
            keys.setdefault(model.weights.value.manifest_root, []).append(model.id)
    for skill in ctx.bom.skills:
        keys.setdefault(skill.digest, []).append(skill.id)
    for instr in ctx.bom.instructions:
        keys.setdefault(instr.digest, []).append(instr.id)
    return keys


@check(
    "SYM-TRUST-001",
    "Revoked or quarantined component in use",
    Severity.CRITICAL,
    mappings=(asi(4),),
    inputs=("trust_status[]", "*[].digest"),
    remediation="Remove or replace the component now and rotate any credential it could reach (see the blast radius in `symbiote index`).",
)
def revoked_component(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """The snapshot contains a subject whose trust status is revoked (critical) or quarantined (high)."""
    keys = _component_keys(ctx)
    for ts in ctx.bom.trust_status:
        if ts.subject_kind is TrustSubjectKind.PUBLISHER_IDENTITY or (ts.expires and ctx.now >= ts.expires):
            continue
        users = keys.get(ts.subject_key, [])
        if not users or ts.status is TrustState.ALLOWLISTED:
            continue
        sev = Severity.CRITICAL if ts.status is TrustState.REVOKED else Severity.HIGH
        yield spec.finding(
            ctx,
            subjects=users,
            inputs=[ts.id],
            severity=sev,
            message=f"{', '.join(users)} is {ts.status.value}: {ts.reason}.",
        )


@check(
    "SYM-TRUST-002",
    "Component from a revoked publisher",
    Severity.CRITICAL,
    mappings=(asi(4),),
    inputs=("trust_status[subject_kind=publisher-identity]", "resolutions[].publisher"),
    remediation="Treat everything from this publisher as compromised: remove it and re-resolve from a trusted source.",
)
def revoked_publisher(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A resolution's publisher identity is revoked."""
    revoked = {
        ts.subject_key: ts
        for ts in ctx.bom.trust_status
        if ts.subject_kind is TrustSubjectKind.PUBLISHER_IDENTITY and ts.status is TrustState.REVOKED
    }
    for res in ctx.bom.resolutions:
        ident = res.publisher.identity if res.publisher else None
        if ident and ident in revoked:
            yield spec.finding(
                ctx,
                subjects=[res.id, *(e.from_ref for e in ctx.index.into(res.id))],
                inputs=[revoked[ident].id],
                message=f"{res.requested.ref!r} was published by revoked identity {ident!r}.",
            )


@check(
    "SYM-ATT-001",
    "Signature from an unconstrained signer",
    Severity.MEDIUM,
    inputs=("*[].evidence[].verification", "models[].signature.outcome"),
    remediation="Configure an identity constraint (certificate identity + OIDC issuer) in the verification policy; a valid signature from anyone proves nothing.",
)
def unconstrained_signer(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Any signature-valid-unconstrained outcome."""
    for model in ctx.bom.models:
        if model.signature and model.signature.outcome is SignatureOutcome.SIGNATURE_VALID_UNCONSTRAINED:
            yield spec.finding(
                ctx,
                subjects=[model.id],
                message=f"Model {model.name or model.id!r} signature verified without a signer constraint.",
            )
    for res in ctx.bom.resolutions:
        if res.signer and res.signer.outcome is SignatureOutcome.SIGNATURE_VALID_UNCONSTRAINED:
            yield spec.finding(
                ctx,
                subjects=[res.id],
                message=f"{res.requested.ref!r} signature verified without a signer constraint.",
            )
    for _, entity in ctx.bom.iter_entities():
        refs = getattr(getattr(entity, "provenance", None), "evidence", []) or []
        if any(r.verification is EvidenceVerification.SIGNATURE_VALID_UNCONSTRAINED for r in refs):
            yield spec.finding(
                ctx,
                subjects=[entity.id],
                message=f"{entity.id} cites evidence signed by an unconstrained signer.",
            )


@check(
    "SYM-ATT-002",
    "Expired evidence still cited",
    Severity.MEDIUM,
    inputs=("evidence[].expires",),
    remediation="Refresh the evidence (re-run the scan, evaluation or attestation) and cite the new digest.",
)
def expired_evidence(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Evidence past its expiry."""
    for ev in ctx.bom.evidence:
        if ev.expires is not None and ctx.now >= ev.expires:
            yield spec.finding(
                ctx, subjects=[ev.id], message=f"Evidence {ev.id} expired at {ev.expires.isoformat()}."
            )


@check(
    "SYM-EVAL-001",
    "Stale evaluation",
    Severity.HIGH,
    mappings=(asi(1),),
    inputs=("evaluations[].subject_config", "*[].digest"),
    remediation="Re-run the evaluation against the deployed configuration; a red-team result only applies to the exact model, prompts, tools and data it tested.",
)
def stale_evaluation(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """An evaluation's subject_config references digests that are not in the current configuration."""
    current: set[str] = set(_component_keys(ctx))
    current.update(
        s.toolset_digest.value for s in ctx.bom.tool_servers if s.toolset_digest and s.toolset_digest.value
    )
    current.update(p.template_digest for p in ctx.bom.prompts)
    current.update(p.digest.value for p in ctx.bom.prompts if p.digest.value)
    for ev in ctx.bom.evaluations:
        cfg = ev.subject_config
        referenced = [*cfg.model_digests, *cfg.prompt_digests, *cfg.toolset_digests, *cfg.data_source_digests]
        drifted = [d for d in referenced if d not in current]
        if ev.status == "stale" or drifted:
            yield spec.finding(
                ctx,
                subjects=[ev.id],
                message=f"Evaluation {ev.name or ev.id!r} no longer matches the configuration ({len(drifted)} digest(s) changed).",
            )


@check(
    "SYM-A2A-001",
    "Unsigned agent card",
    Severity.MEDIUM,
    mappings=(asi(7),),
    inputs=("agents[].a2a_card",),
    remediation="Require signed Agent Cards (JWS) from peers, verify them against a pinned key set, and pin the card digest in the approval.",
)
def unsigned_card(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A peer agent card carries no signature."""
    for agent in ctx.bom.agents:
        card = agent.a2a_card
        if card is not None and card.signature_status == "none" and "self-published-card" not in agent.tags:
            yield spec.finding(
                ctx,
                subjects=[agent.id],
                message=f"Agent card of {agent.name or agent.id!r} is unsigned; its endpoint and skills can be spoofed.",
            )


@check(
    "SYM-SUB-001",
    "Undeclared sub-agent observed",
    Severity.HIGH,
    mappings=(asi(10), asi(8)),
    inputs=("edges[spawns|delegatesTo]", "baseline.edges"),
    remediation="Investigate the spawn; declare legitimate sub-agents (with their tools and grants) in the approved snapshot.",
)
def undeclared_sub_agent(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """An observed spawns/delegatesTo edge that the declared or approved baseline does not contain."""
    if ctx.baseline is None:
        return
    declared = {e.key for e in ctx.baseline.edges}
    for edge in ctx.bom.edges:
        if (
            edge.type in (EdgeType.SPAWNS, EdgeType.DELEGATES_TO)
            and edge.assurance is not AssuranceLevel.DECLARED
            and edge.key not in declared
        ):
            yield spec.finding(
                ctx,
                subjects=[edge.to_ref],
                inputs=[edge.from_ref],
                message=f"{edge.from_ref} {edge.type.value} {edge.to_ref}, which was never declared.",
            )


@check(
    "SYM-REG-001",
    "Resolution without transparency-log inclusion",
    Severity.LOW,
    mappings=(asi(4),),
    inputs=("resolutions[].signer", "resolutions[].transparency_log"),
    remediation="Verify against a transparency log (Rekor) so a signature cannot be presented to you alone (split view).",
)
def no_log_inclusion(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Signer present but no verified inclusion proof."""
    for res in ctx.bom.resolutions:
        signed = res.signer is not None and res.signer.status is not SignatureStatus.UNSIGNED
        logged = res.transparency_log is not None and res.transparency_log.inclusion_proof_verified
        if signed and not logged:
            yield spec.finding(
                ctx,
                subjects=[res.id],
                message=f"{res.requested.ref!r} is signed but has no verified transparency-log inclusion.",
            )
