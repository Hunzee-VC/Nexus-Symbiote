"""Digest-based diff between two AgentBOM documents → typed ``Delta`` (the diff *is* the finding).

Implements ``spec/agentbom-profile.md §2.2`` under invariant I8: equality is decided by digests —
identity digests where the model defines them, claim-noise-stripped body digests otherwise
(:mod:`symbiote.snapshot.body`). Re-collecting an unchanged fact, or upgrading its assurance,
produces no event.

The declared-vs-observed pairing is the detection primitive: an undeclared component at runtime is
the finding (``SYM-TOOL-002``/``SYM-SUB-001`` read this delta). Evaluation staleness
(``SYM-EVAL-001``) is reported by :func:`stale_evaluation_ids`: an evaluation applies only while
every digest in its ``subject_config`` is still present in the document's current configuration.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import TypeVar

from symbiote.model.common import Party
from symbiote.model.document import AgentBOM
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    DataSource,
    Entity,
    Grant,
    Model,
    RegistryResolution,
    ToolDefinition,
    ToolServer,
    TrustStatus,
)
from symbiote.model.enums import (
    AssuranceLevel,
    CapabilityClass,
    DataSourceKind,
    DeltaEventType,
    EdgeType,
    RegistryStatus,
    Severity,
    SideEffectClass,
    TrustState,
    TrustTier,
)
from symbiote.model.snapshot import Delta, DeltaEvent, Producer
from symbiote.snapshot.body import body_digest, comparison_digest

E = TypeVar("E", bound=Entity)

#: Default severity hint per event type; specific rules below override per instance.
DEFAULT_EVENT_SEVERITY: dict[DeltaEventType, Severity] = {
    DeltaEventType.TOOL_REGISTERED: Severity.MEDIUM,
    DeltaEventType.TOOL_REMOVED: Severity.LOW,
    DeltaEventType.TOOL_DEFINITION_CHANGED: Severity.CRITICAL,
    DeltaEventType.TOOL_ANNOTATIONS_CHANGED: Severity.MEDIUM,
    DeltaEventType.SERVER_ADDED: Severity.MEDIUM,
    DeltaEventType.SERVER_REMOVED: Severity.LOW,
    DeltaEventType.SERVER_IDENTITY_CHANGED: Severity.CRITICAL,
    DeltaEventType.MODEL_ADDED: Severity.MEDIUM,
    DeltaEventType.MODEL_ROUTED: Severity.HIGH,
    DeltaEventType.MODEL_ALIAS_RESOLVED: Severity.HIGH,
    DeltaEventType.SUB_AGENT_SPAWNED: Severity.HIGH,
    DeltaEventType.MEMORY_WRITER_ADDED: Severity.HIGH,
    DeltaEventType.INSTRUCTION_CHANGED: Severity.CRITICAL,
    DeltaEventType.SKILL_CHANGED: Severity.HIGH,
    DeltaEventType.GRANT_ADDED: Severity.HIGH,
    DeltaEventType.GRANT_REMOVED: Severity.LOW,
    DeltaEventType.GRANT_CHANGED: Severity.HIGH,
    DeltaEventType.IDENTITY_CHANGED: Severity.HIGH,
    DeltaEventType.REGISTRY_STATUS_CHANGED: Severity.HIGH,
    DeltaEventType.SIGNER_CHANGED: Severity.HIGH,
    DeltaEventType.DATA_SOURCE_ADDED: Severity.MEDIUM,
    DeltaEventType.DATA_SOURCE_CHANGED: Severity.HIGH,
    DeltaEventType.DATA_SOURCE_REMOVED: Severity.HIGH,
    DeltaEventType.TRUST_STATUS_CHANGED: Severity.HIGH,
}

_PRIVILEGED_CAPABILITIES = frozenset(
    {
        CapabilityClass.WRITE,
        CapabilityClass.EXECUTE,
        CapabilityClass.NETWORK_EGRESS,
        CapabilityClass.CREDENTIALS,
        CapabilityClass.PAYMENT,
        CapabilityClass.COMMUNICATE,
        CapabilityClass.DELEGATE,
        CapabilityClass.MEMORY_WRITE,
        CapabilityClass.FILESYSTEM,
    }
)


def _by_id(entities: Iterable[E]) -> dict[str, E]:
    return {e.id: e for e in entities}


def _assurance(entity: Entity | Party, fallback: AssuranceLevel) -> AssuranceLevel:
    provenance = getattr(entity, "provenance", None)
    level = getattr(provenance, "assurance", None)
    return level if isinstance(level, AssuranceLevel) else fallback


class _Collector:
    """Accumulates events with deterministic ordering and shared defaults."""

    def __init__(self, default_assurance: AssuranceLevel) -> None:
        self.events: list[DeltaEvent] = []
        self.default_assurance = default_assurance

    def emit(
        self,
        type_: DeltaEventType,
        subject: str,
        *,
        before: str | None = None,
        after: str | None = None,
        severity: Severity | None = None,
        assurance: AssuranceLevel | None = None,
        detail: str | None = None,
    ) -> None:
        self.events.append(
            DeltaEvent(
                type=type_,
                subject_ref=subject,
                before=before,
                after=after,
                assurance=assurance or self.default_assurance,
                severity_hint=severity or DEFAULT_EVENT_SEVERITY[type_],
                detail=detail,
            )
        )


def _diff_tools(c: _Collector, a: Mapping[str, ToolDefinition], b: Mapping[str, ToolDefinition]) -> None:
    for tid in sorted(b.keys() - a.keys()):
        tool = b[tid]
        privileged = tool.side_effect_class in (
            SideEffectClass.DESTRUCTIVE,
            SideEffectClass.FINANCIAL,
            SideEffectClass.UNKNOWN,
        )
        c.emit(
            DeltaEventType.TOOL_REGISTERED,
            tid,
            after=tool.digest.value,
            severity=Severity.HIGH if privileged else Severity.MEDIUM,
            assurance=_assurance(tool, c.default_assurance),
            detail=f"side-effect class {tool.side_effect_class.value}",
        )
    for tid in sorted(a.keys() - b.keys()):
        c.emit(DeltaEventType.TOOL_REMOVED, tid, before=a[tid].digest.value)
    for tid in sorted(a.keys() & b.keys()):
        old, new = a[tid], b[tid]
        if not old.digest.ok or not new.digest.ok:
            if old.digest.value != new.digest.value or old.digest.status != new.digest.status:
                c.emit(
                    DeltaEventType.TOOL_DEFINITION_CHANGED,
                    tid,
                    before=old.digest.value,
                    after=new.digest.value,
                    severity=Severity.CRITICAL,
                    detail="definition is or became undigestable (fail closed)",
                )
            continue
        if old.digest.value != new.digest.value:
            desc_changed = old.description_digest != new.description_digest
            schema_changed = old.input_schema_digest != new.input_schema_digest
            if desc_changed:
                detail = "model-visible description changed" + (
                    " and input schema changed" if schema_changed else " (schema unchanged)"
                )
                severity = Severity.CRITICAL
                type_ = DeltaEventType.TOOL_DEFINITION_CHANGED
            elif schema_changed:
                detail = "input schema changed (description unchanged)"
                severity = Severity.HIGH
                type_ = DeltaEventType.TOOL_DEFINITION_CHANGED
            else:
                detail = "annotations/title/output schema changed (description and input schema unchanged)"
                severity = Severity.MEDIUM
                type_ = DeltaEventType.TOOL_ANNOTATIONS_CHANGED
            c.emit(
                type_,
                tid,
                before=old.digest.value,
                after=new.digest.value,
                severity=severity,
                assurance=_assurance(new, c.default_assurance),
                detail=detail,
            )
        elif (
            old.full_digest is not None
            and new.full_digest is not None
            and old.full_digest.value != new.full_digest.value
        ):
            c.emit(
                DeltaEventType.TOOL_ANNOTATIONS_CHANGED,
                tid,
                before=old.full_digest.value,
                after=new.full_digest.value,
                severity=Severity.LOW,
                detail="non-model-visible fields changed (_meta/icons/execution)",
            )


def _diff_servers(c: _Collector, a: Mapping[str, ToolServer], b: Mapping[str, ToolServer]) -> None:
    for sid in sorted(b.keys() - a.keys()):
        server = b[sid]
        claim = server.crosses_trust_boundary
        if claim.is_unknown:
            # I2 / checks.md posture: an unknown boundary is triaged worst-case,
            # and the unknown is named instead of silently reading as benign.
            severity, detail = Severity.HIGH, "trust boundary unknown (treated as crossing)"
        elif claim.value:
            severity, detail = Severity.HIGH, "crosses a trust boundary"
        else:
            severity, detail = Severity.MEDIUM, None
        c.emit(
            DeltaEventType.SERVER_ADDED,
            sid,
            after=server.digest,
            severity=severity,
            assurance=_assurance(server, c.default_assurance),
            detail=detail,
        )
    for sid in sorted(a.keys() - b.keys()):
        c.emit(DeltaEventType.SERVER_REMOVED, sid, before=a[sid].digest)
    for sid in sorted(a.keys() & b.keys()):
        old, new = a[sid], b[sid]
        if old.digest != new.digest:
            c.emit(
                DeltaEventType.SERVER_IDENTITY_CHANGED,
                sid,
                before=old.digest,
                after=new.digest,
                detail="server/v1 identity changed (kind, transport, endpoint, package, "
                "serverInfo or instructions)",
            )
            continue
        if body_digest(old).value != body_digest(new).value:
            c.emit(
                DeltaEventType.SERVER_IDENTITY_CHANGED,
                sid,
                before=body_digest(old).value,
                after=body_digest(new).value,
                severity=Severity.HIGH,
                detail="server facts outside server/v1 changed (command shape, env/header names, "
                "authentication or trust zone)",
            )


def _diff_models(c: _Collector, a: Mapping[str, Model], b: Mapping[str, Model]) -> None:
    for mid in sorted(b.keys() - a.keys()):
        c.emit(
            DeltaEventType.MODEL_ADDED,
            mid,
            after=comparison_digest(b[mid]),
            assurance=_assurance(b[mid], c.default_assurance),
        )
    for mid in sorted(a.keys() & b.keys()):
        old, new = a[mid], b[mid]
        old_root = old.weights.value.manifest_root if old.weights and old.weights.value else None
        new_root = new.weights.value.manifest_root if new.weights and new.weights.value else None
        if old_root != new_root and (old_root or new_root):
            c.emit(
                DeltaEventType.MODEL_ADDED,
                mid,
                before=old_root,
                after=new_root,
                severity=Severity.CRITICAL,
                detail="weights identity changed in place: treat as a different model",
            )
        old_hosted = old.hosted.value if old.hosted else None
        new_hosted = new.hosted.value if new.hosted else None
        if old_hosted and new_hosted:
            old_ref = old_hosted.resolved_ref.value
            new_ref = new_hosted.resolved_ref.value
            if old_ref != new_ref or old_hosted.requested_ref != new_hosted.requested_ref:
                c.emit(
                    DeltaEventType.MODEL_ALIAS_RESOLVED,
                    mid,
                    detail=(
                        f"requested {old_hosted.requested_ref!r}→{new_hosted.requested_ref!r}, "
                        f"resolved {old_ref!r}→{new_ref!r} "
                        f"(pinning: {new_hosted.alias_pinning.value})"
                    ),
                )
        old_sig = (
            (old.signature.identity, old.signature.issuer, old.signature.status) if old.signature else None
        )
        new_sig = (
            (new.signature.identity, new.signature.issuer, new.signature.status) if new.signature else None
        )
        if old_sig != new_sig:
            c.emit(
                DeltaEventType.SIGNER_CHANGED,
                mid,
                before=old.signature.bundle_digest if old.signature else None,
                after=new.signature.bundle_digest if new.signature else None,
                detail=f"model signature facts changed: {old_sig} → {new_sig}",
            )


def _diff_simple(
    c: _Collector,
    a: Mapping[str, Entity],
    b: Mapping[str, Entity],
    *,
    changed: DeltaEventType,
    added_severity: Severity,
    removed_severity: Severity,
    changed_severity: Severity | None = None,
    label: str = "",
) -> None:
    prefix = f"{label}: " if label else ""
    for eid in sorted(b.keys() - a.keys()):
        c.emit(
            changed,
            eid,
            after=comparison_digest(b[eid]),
            severity=added_severity,
            assurance=_assurance(b[eid], c.default_assurance),
            detail=f"{prefix}added",
        )
    for eid in sorted(a.keys() - b.keys()):
        c.emit(
            changed,
            eid,
            before=comparison_digest(a[eid]),
            severity=removed_severity,
            detail=f"{prefix}removed",
        )
    for eid in sorted(a.keys() & b.keys()):
        before, after = comparison_digest(a[eid]), comparison_digest(b[eid])
        if before != after:
            c.emit(
                changed,
                eid,
                before=before,
                after=after,
                severity=changed_severity,
                assurance=_assurance(b[eid], c.default_assurance),
                detail=f"{prefix}changed" if prefix else None,
            )


def _diff_grants(c: _Collector, a: Mapping[str, Grant], b: Mapping[str, Grant]) -> None:
    for gid in sorted(b.keys() - a.keys()):
        grant = b[gid]
        c.emit(
            DeltaEventType.GRANT_ADDED,
            gid,
            after=body_digest(grant).value,
            severity=Severity.HIGH if grant.capability in _PRIVILEGED_CAPABILITIES else Severity.MEDIUM,
            assurance=_assurance(grant, c.default_assurance),
            detail=f"capability {grant.capability.value} ({grant.layer.value})",
        )
    for gid in sorted(a.keys() - b.keys()):
        c.emit(DeltaEventType.GRANT_REMOVED, gid, before=body_digest(a[gid]).value)
    for gid in sorted(a.keys() & b.keys()):
        before, after = body_digest(a[gid]).value, body_digest(b[gid]).value
        if before != after:
            c.emit(DeltaEventType.GRANT_CHANGED, gid, before=before, after=after)


def _diff_resolutions(
    c: _Collector, a: Mapping[str, RegistryResolution], b: Mapping[str, RegistryResolution]
) -> None:
    for rid in sorted(a.keys() & b.keys()):
        old, new = a[rid], b[rid]
        old_status = old.registry.status if old.registry else None
        new_status = new.registry.status if new.registry else None
        if old_status != new_status:
            severity = (
                Severity.HIGH
                if new_status is RegistryStatus.DELETED
                else Severity.MEDIUM
                if new_status is RegistryStatus.DEPRECATED
                else Severity.LOW
            )
            c.emit(
                DeltaEventType.REGISTRY_STATUS_CHANGED,
                rid,
                severity=severity,
                detail=f"registry status {getattr(old_status, 'value', None)} → "
                f"{getattr(new_status, 'value', None)}",
            )
        old_sig = (old.signer.identity, old.signer.issuer, old.signer.status) if old.signer else None
        new_sig = (new.signer.identity, new.signer.issuer, new.signer.status) if new.signer else None
        if old_sig != new_sig:
            c.emit(
                DeltaEventType.SIGNER_CHANGED,
                rid,
                detail=f"resolution signer changed: {old_sig} → {new_sig}",
            )


def _diff_trust(c: _Collector, a: Mapping[str, TrustStatus], b: Mapping[str, TrustStatus]) -> None:
    def sev(status: TrustState) -> Severity:
        if status is TrustState.REVOKED:
            return Severity.CRITICAL
        if status is TrustState.QUARANTINED:
            return Severity.HIGH
        return Severity.MEDIUM

    for tid in sorted(b.keys() - a.keys()):
        c.emit(
            DeltaEventType.TRUST_STATUS_CHANGED,
            tid,
            after=body_digest(b[tid]).value,
            severity=sev(b[tid].status),
            detail=f"{b[tid].subject_kind.value} {b[tid].subject_key}: → {b[tid].status.value}",
        )
    for tid in sorted(a.keys() & b.keys()):
        if a[tid].status != b[tid].status or a[tid].serial != b[tid].serial:
            c.emit(
                DeltaEventType.TRUST_STATUS_CHANGED,
                tid,
                before=body_digest(a[tid]).value,
                after=body_digest(b[tid]).value,
                severity=sev(b[tid].status),
                detail=f"{b[tid].subject_kind.value} {b[tid].subject_key}: "
                f"{a[tid].status.value} → {b[tid].status.value}",
            )


def _diff_data_sources(c: _Collector, a: Mapping[str, DataSource], b: Mapping[str, DataSource]) -> None:
    for did in sorted(b.keys() - a.keys()):
        source = b[did]
        tier_untrusted = source.trust_tier in (TrustTier.UNTRUSTED_PUBLIC, TrustTier.UNKNOWN)
        bearing = source.instruction_bearing
        bearing_risky = bool(bearing.value) or bearing.is_unknown
        risky = tier_untrusted and bearing_risky
        unknowns = []
        if source.trust_tier is TrustTier.UNKNOWN:
            unknowns.append("trust tier unknown")
        if bearing.is_unknown:
            unknowns.append("instruction-bearing unknown")
        detail = None
        if risky:
            detail = "untrusted and instruction-bearing"
            if unknowns:
                detail += " (" + "; ".join(unknowns) + " - treated as worst case)"
        c.emit(
            DeltaEventType.DATA_SOURCE_ADDED,
            did,
            after=comparison_digest(source),
            severity=Severity.HIGH if risky else Severity.MEDIUM,
            assurance=_assurance(source, c.default_assurance),
            detail=detail,
        )
    for did in sorted(a.keys() - b.keys()):
        c.emit(DeltaEventType.DATA_SOURCE_REMOVED, did, before=comparison_digest(a[did]))
    for did in sorted(a.keys() & b.keys()):
        old, new = a[did], b[did]
        before, after = comparison_digest(old), comparison_digest(new)
        if before == after:
            continue
        if new.data_kind is DataSourceKind.MEMORY_STORE:
            old_writers = set(old.writers.value or []) if old.writers else set()
            new_writers = set(new.writers.value or []) if new.writers else set()
            added = sorted(new_writers - old_writers)
            if added:
                c.emit(
                    DeltaEventType.MEMORY_WRITER_ADDED,
                    did,
                    before=before,
                    after=after,
                    assurance=_assurance(new, c.default_assurance),
                    detail="new memory writers: " + ", ".join(added),
                )
                # Preserve the specific event for a pure addition. A concurrent revocation or
                # other data change must still be visible.
                if (
                    not old_writers - new_writers
                    and comparison_digest(new.replace(writers=old.writers)) == before
                ):
                    continue
        c.emit(
            DeltaEventType.DATA_SOURCE_CHANGED,
            did,
            before=before,
            after=after,
            assurance=_assurance(new, c.default_assurance),
        )


def _diff_edges(c: _Collector, a: AgentBOM, b: AgentBOM) -> None:
    a_edges: dict[tuple[str, str, str], Edge] = {e.key: e for e in a.edges}
    b_edges: dict[tuple[str, str, str], Edge] = {e.key: e for e in b.edges}
    for key in sorted(b_edges.keys() - a_edges.keys()):
        edge = b_edges[key]
        if edge.type is EdgeType.SPAWNS or (
            edge.type is EdgeType.DELEGATES_TO and edge.to_ref.startswith("agent:")
        ):
            c.emit(
                DeltaEventType.SUB_AGENT_SPAWNED,
                edge.to_ref,
                assurance=edge.assurance,
                detail=f"{edge.type.value} edge from {edge.from_ref}",
            )
        elif edge.type is EdgeType.USES_MODEL:
            c.emit(
                DeltaEventType.MODEL_ROUTED,
                edge.to_ref,
                assurance=edge.assurance,
                detail=f"new model route from {edge.from_ref}"
                + (f" (role {edge.qualifiers['role']})" if "role" in edge.qualifiers else ""),
            )
        elif edge.type is EdgeType.WRITES_MEMORY_TO:
            c.emit(
                DeltaEventType.MEMORY_WRITER_ADDED,
                edge.to_ref,
                assurance=edge.assurance,
                detail=f"writer {edge.from_ref}",
            )
    for key in sorted(a_edges.keys() & b_edges.keys()):
        old, new = a_edges[key], b_edges[key]
        if old.type is EdgeType.USES_MODEL and old.qualifiers != new.qualifiers:
            c.emit(
                DeltaEventType.MODEL_ROUTED,
                new.to_ref,
                assurance=new.assurance,
                detail=f"routing qualifiers changed: {old.qualifiers} → {new.qualifiers}",
            )


def diff(
    a: AgentBOM,
    b: AgentBOM,
    *,
    producer: Producer | None = None,
    produced_at: datetime | None = None,
) -> Delta:
    """Typed change record from snapshot ``a`` to snapshot ``b`` (any snapshot kinds; I4 is the
    caller's concern — pairing ``approved`` with ``observed`` is exactly how drift is detected)."""
    default_assurance = (
        AssuranceLevel.OBSERVED if b.snapshot.kind.value == "observed" else AssuranceLevel.DECLARED
    )
    c = _Collector(default_assurance)
    _diff_tools(c, _by_id(a.tools), _by_id(b.tools))
    _diff_servers(c, _by_id(a.tool_servers), _by_id(b.tool_servers))
    _diff_models(c, _by_id(a.models), _by_id(b.models))
    _diff_simple(
        c,
        _by_id(a.instructions),
        _by_id(b.instructions),
        changed=DeltaEventType.INSTRUCTION_CHANGED,
        added_severity=Severity.MEDIUM,
        removed_severity=Severity.LOW,
    )
    _diff_simple(
        c,
        _by_id(a.prompts),
        _by_id(b.prompts),
        changed=DeltaEventType.INSTRUCTION_CHANGED,
        added_severity=Severity.MEDIUM,
        removed_severity=Severity.LOW,
        label="prompt template",
    )
    _diff_simple(
        c,
        _by_id(a.skills),
        _by_id(b.skills),
        changed=DeltaEventType.SKILL_CHANGED,
        added_severity=Severity.MEDIUM,
        removed_severity=Severity.LOW,
    )
    _diff_simple(
        c,
        _by_id(a.identities),
        _by_id(b.identities),
        changed=DeltaEventType.IDENTITY_CHANGED,
        added_severity=Severity.MEDIUM,
        removed_severity=Severity.LOW,
    )
    _diff_grants(c, _by_id(a.grants), _by_id(b.grants))
    _diff_resolutions(c, _by_id(a.resolutions), _by_id(b.resolutions))
    _diff_trust(c, _by_id(a.trust_status), _by_id(b.trust_status))
    _diff_data_sources(c, _by_id(a.data_sources), _by_id(b.data_sources))
    _diff_edges(c, a, b)
    events = sorted(c.events, key=lambda e: (e.type.value, e.subject_ref, e.detail or ""))
    from_digest = a.snapshot.digest
    to_digest = b.snapshot.digest
    return Delta(
        id=f"delta:{from_digest[len('sha256:') :][:12]}:{to_digest[len('sha256:') :][:12]}",
        from_snapshot=from_digest,
        to_snapshot=to_digest,
        produced_at=produced_at or b.snapshot.produced_at,
        producer=producer or b.producer,
        events=events,
    )


def current_config_digests(bom: AgentBOM) -> set[str]:
    """Every configuration digest an ``Evaluation.subject_config`` may legitimately reference."""
    digests: set[str] = set()
    for model in bom.models:
        if model.weights and model.weights.value:
            digests.add(model.weights.value.manifest_root)
        if model.tensor_manifest_root:
            digests.add(model.tensor_manifest_root)
        if model.generation_config_digest:
            digests.add(model.generation_config_digest)
    for prompt in bom.prompts:
        if prompt.digest.value:
            digests.add(prompt.digest.value)
        digests.add(prompt.template_digest)
    for instr in bom.instructions:
        digests.add(instr.digest)
    for server in bom.tool_servers:
        if server.toolset_digest and server.toolset_digest.value:
            digests.add(server.toolset_digest.value)
        if server.toolset_digest_result and server.toolset_digest_result.value:
            digests.add(server.toolset_digest_result.value)
    for source in bom.data_sources:
        if source.snapshot and source.snapshot.value:
            digests.add(source.snapshot.value.commitment)
    for policy in bom.policies:
        digests.add(policy.bundle_digest)
    for agent in bom.agents:
        if agent.policy_bundle and agent.policy_bundle.value:
            digests.add(agent.policy_bundle.value)
    return digests


def stale_evaluation_ids(bom: AgentBOM) -> dict[str, list[str]]:
    """Evaluations whose ``subject_config`` references digests no longer in the configuration.

    Returns ``{evaluation id: [missing digests]}`` — input for ``SYM-EVAL-001`` and for collectors
    that set ``Evaluation.status = "stale"`` before sealing the next snapshot. An evaluation with
    an empty ``subject_config`` is never stale by this rule (nothing was pinned).
    """
    current = current_config_digests(bom)
    stale: dict[str, list[str]] = {}
    for evaluation in bom.evaluations:
        cfg = evaluation.subject_config
        referenced = [
            *cfg.model_digests,
            *cfg.prompt_digests,
            *cfg.toolset_digests,
            *cfg.data_source_digests,
            *([cfg.policy_digest] if cfg.policy_digest else []),
        ]
        missing = sorted(d for d in referenced if d not in current)
        if missing:
            stale[evaluation.id] = missing
    return stale


__all__ = [
    "DEFAULT_EVENT_SEVERITY",
    "current_config_digests",
    "diff",
    "stale_evaluation_ids",
]
