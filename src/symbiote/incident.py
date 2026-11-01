"""Offline incident evidence for a specific tenant, descriptor digest, and time interval."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Literal

from pydantic import AwareDatetime, Field, TypeAdapter

from symbiote.attest import (
    PAYLOAD_TYPE,
    STATEMENT_TYPE,
    Envelope,
    KeyRing,
    predicate_type,
    snapshot_statement,
    verify_envelope,
)
from symbiote.attest.statements import subject
from symbiote.digest import bytes_digest, canonical_bytes, parse_json_strict
from symbiote.export.companion import load_companion
from symbiote.model.base import SymbioteModel
from symbiote.model.common import DigestStr
from symbiote.model.document import AgentBOM
from symbiote.model.entities import Deployment, ToolDefinition, TrustStatus
from symbiote.model.enums import (
    AssuranceLevel,
    EdgeScope,
    EdgeType,
    GrantLayer,
    SnapshotKind,
    ToolSource,
    ToolState,
)
from symbiote.snapshot import verify_document

EXECUTION_TYPE = "application/vnd.symbiote.tool-execution.v1+json"


REPORT_TYPE = "application/vnd.symbiote.incident-report.v1+json"


class Execution(SymbioteModel):
    """An execution outcome signed by a trusted observer at the tool boundary."""

    event_id: str = Field(min_length=1)
    tenant: str = Field(min_length=1)
    deployment: str = Field(min_length=1)
    agent: str = Field(min_length=1)
    workload: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    server: str = Field(min_length=1)
    descriptor_digest: DigestStr
    companion_digest: DigestStr
    snapshot_digest: DigestStr
    evidence_digest: DigestStr
    observed_at: AwareDatetime
    outcome: Literal["completed", "failed"]


def _verified(envelope: Envelope, ring: KeyRing, media_type: str) -> tuple[dict[str, Any], list[str]]:
    if envelope.payload_type != media_type:
        raise ValueError("wrong signed evidence type")
    payload, keys = verify_envelope(envelope, ring)
    parsed = parse_json_strict(payload)
    if not isinstance(parsed, dict):
        raise ValueError("expected a signed JSON object")
    return parsed, sorted(set(keys))


def _snapshot(raw: bytes, envelope: Envelope, ring: KeyRing) -> tuple[AgentBOM, list[str], str]:
    statement, signers = _verified(envelope, ring, PAYLOAD_TYPE)
    parse_json_strict(raw)
    bom = load_companion(raw)
    if bom.redacted or not verify_document(bom):
        raise ValueError("incident analysis requires a complete, verifiable companion")
    digest = bytes_digest(raw)
    expected = snapshot_statement(bom, companion_digest=digest)
    subjects = statement.get("subject")
    if (
        not isinstance(subjects, list)
        or not all(s in subjects for s in expected["subject"])
        or any(not isinstance(s, dict) or not isinstance(s.get("name"), str) for s in subjects)
        or len({s["name"] for s in subjects}) != len(subjects)
        or any(statement.get(k) != expected[k] for k in ("_type", "predicateType", "predicate"))
    ):
        raise ValueError("snapshot statement does not bind the supplied companion and predicate")
    return bom, signers, digest


def _aware(time: datetime) -> datetime:
    if time.tzinfo is None or time.utcoffset() is None:
        raise ValueError("evidence and query times must include a timezone")
    return time


def _effective(
    bom: AgentBOM, tool: ToolDefinition, dep: Deployment, start: datetime, end: datetime
) -> list[dict[str, Any]]:
    """Report the signed grant and all restrictions; do not simulate a PDP decision."""
    result = []
    for grant in bom.grants:
        if grant.layer != GrantLayer.EFFECTIVE or grant.subject_ref != tool.id or not grant.scope.resources:
            continue
        credential = next((c for c in bom.credential_bindings if c.id == grant.credential_binding_ref), None)
        if not credential or credential.subject_ref not in (
            tool.id,
            tool.server_ref,
            dep.workload_identity_ref,
        ):
            continue
        principal = next(
            (i for i in bom.identities if i.id == credential.identity_ref and i.tenant == dep.tenant), None
        )
        if not principal:
            continue
        validity = grant.validity
        if principal.id != dep.workload_identity_ref or not validity.not_before or not validity.not_after:
            continue
        since = max(start, _aware(validity.not_before))
        until = min(end, _aware(validity.not_after))
        if since < until:
            result.append(
                {
                    "principal": principal.id,
                    "principalRef": principal.ref,
                    "credential": credential.id,
                    "validFrom": since.isoformat(),
                    "validUntil": until.isoformat(),
                    "grant": grant.to_json_dict(),
                }
            )
    return result


def revoked_interval(
    envelope: Envelope,
    keys: KeyRing,
    *,
    tenant: str,
    target_kind: str,
    target_value: str,
    start: datetime,
    end: datetime,
) -> tuple[datetime, datetime, dict[str, Any]]:
    """Validate a signed trust-status statement and bound the query to its supported interval."""
    doc, signers = _verified(envelope, keys, PAYLOAD_TYPE)
    if doc.get("_type") != STATEMENT_TYPE or doc.get("predicateType") != predicate_type("trust-status"):
        raise ValueError("expected a trust-status statement")
    pred = doc["predicate"]
    entries = pred["entries"]
    if doc["subject"] != [subject("trust-status:" + tenant, bytes_digest(canonical_bytes(entries)))]:
        raise ValueError("revocation tenant or entry commitment mismatch")
    matches = [
        e
        for raw in entries
        if (e := TrustStatus.model_validate(raw)).subject_kind.value == target_kind
        and e.subject_key == target_value
    ]
    if len(matches) != 1 or matches[0].status.value != "revoked" or matches[0].serial != pred["serial"]:
        raise ValueError("expected one matching revocation at this serial")
    entry = matches[0]
    lo = max(_aware(start), _aware(entry.decided_at))
    hi = min(_aware(end), _aware(datetime.fromisoformat(pred["expires"])))
    if entry.expires:
        hi = min(hi, _aware(entry.expires))
    if lo >= hi:
        raise ValueError("requested interval does not intersect revocation")
    return (
        lo,
        hi,
        {
            "serial": entry.serial,
            "effectiveAt": entry.decided_at.isoformat(),
            "signingKeys": signers,
            "statementDigest": bytes_digest(envelope.payload_bytes),
        },
    )


def incident_query(
    snapshots: Sequence[tuple[bytes, Envelope]],
    *,
    tenant: str,
    descriptor_digest: str | None = None,
    publisher: str | None = None,
    issuer: str | None = None,
    artifact_digest: str | None = None,
    provenance_keys: KeyRing | None = None,
    start: datetime,
    end: datetime,
    deployment_keys: KeyRing,
    policy_keys: KeyRing | None = None,
    observations: Sequence[Envelope] = (),
    observer_keys: KeyRing | None = None,
    deployment: str | None = None,
    revocation: Envelope | None = None,
    trust_keys: KeyRing | None = None,
) -> dict[str, Any]:
    """All paths and keys are operator inputs. Results cover only the supplied evidence set."""
    targets = {
        kind: value
        for kind, value in (
            ("tool-digest", descriptor_digest),
            ("server-identity", artifact_digest),
            ("publisher-identity", publisher),
        )
        if value
    }
    if len(targets) != 1 or bool(issuer) != bool(publisher):
        raise ValueError("select one descriptor, artifact or publisher; publisher requires its issuer")
    target_kind, target_value = next(iter(targets.items()))
    if not publisher:
        TypeAdapter(DigestStr).validate_python(target_value)
    elif not provenance_keys:
        raise ValueError("publisher mapping requires an independent provenance key")
    if not tenant or not snapshots or _aware(start) >= _aware(end):
        raise ValueError("a tenant, signed snapshot and ordered time interval are required")
    revocation_info = None
    if revocation is not None:
        if trust_keys is None:
            raise ValueError("revocation requires an operator-trusted revocation key")
        start, end, revocation_info = revoked_interval(
            revocation,
            trust_keys,
            tenant=tenant,
            target_kind=target_kind,
            target_value=target_value,
            start=start,
            end=end,
        )
    executions: dict[tuple[str, str, str], tuple[Execution, list[str]]] = {}
    for env in observations:
        if observer_keys is None:
            raise ValueError("an independent observer key is required")
        body, keys = _verified(env, observer_keys, EXECUTION_TYPE)
        if any(deployment_keys.get(k) or (policy_keys and policy_keys.get(k)) for k in keys):
            raise ValueError("observer keys must be distinct from deployment and policy keys")
        event = Execution.model_validate(body)
        if event.tenant != tenant or (deployment and event.deployment != deployment):
            continue
        key = (event.tenant, event.deployment, event.event_id)
        prior = executions.get(key)
        if prior and prior[0] != event:
            raise ValueError("conflicting observer evidence for an event ID")
        executions[key] = event, keys

    rows: list[dict[str, Any]] = []
    seen_records: set[tuple[str, str]] = set()
    for raw, env in snapshots:
        bom, signers, digest = _snapshot(raw, env, deployment_keys)
        snap = bom.snapshot
        if snap.kind != SnapshotKind.DEPLOYED:
            continue
        dep = next((d for d in bom.deployments if d.id == snap.deployment_ref), None)
        if (
            not dep
            or dep.tenant != tenant
            or dep.agent_ref != bom.subject
            or (deployment and dep.id != deployment)
        ):
            continue
        if not dep.workload_identity_ref or not any(
            i.id == dep.workload_identity_ref and i.tenant == tenant for i in bom.identities
        ):
            continue
        if not snap.validity.not_before or not snap.validity.not_after:
            continue
        lo = max(start, _aware(snap.validity.not_before), _aware(dep.started_at) if dep.started_at else start)
        hi = min(end, _aware(snap.validity.not_after), _aware(dep.ended_at) if dep.ended_at else end)
        if lo >= hi:
            continue
        policy_signers: list[str] = []
        if policy_keys and any(policy_keys.get(s.keyid) for s in env.signatures):
            _, policy_signers = _verified(env, policy_keys, PAYLOAD_TYPE)
            if set(policy_signers) & set(signers):
                raise ValueError("policy and deployment keys must be distinct")
        provenance_signers: list[str] = []
        if publisher and provenance_keys:
            _, provenance_signers = _verified(env, provenance_keys, PAYLOAD_TYPE)
            if set(provenance_signers) & set(signers):
                raise ValueError("deployment and provenance signing keys must be distinct")
        matched_servers: set[str] = set()
        for server in bom.tool_servers:
            if descriptor_digest or (artifact_digest and server.digest == artifact_digest):
                matched_servers.add(server.id)
            elif publisher and server.digest:
                resolution = next(
                    (r for r in bom.resolutions if r.id == server.registry_resolution_ref), None
                )
                if (
                    not resolution
                    or resolution.resolved.digest != server.digest
                    or resolution.resolved.state != "present"
                ):
                    continue
                signer = resolution.signer
                if (
                    signer
                    and signer.status.value == "verified"
                    and signer.outcome.value == "verified"
                    and signer.identity == publisher
                    and signer.issuer == issuer
                    and not signer.subject_name_mismatch
                    and signer.bundle_digest
                    and _aware(resolution.resolved_at) <= lo
                ):
                    matched_servers.add(server.id)
        # Deployment evidence must span the reported interval. Shorter edge evidence
        # can be queried by narrowing the interval instead of extending its validity.
        edges = {
            (e.type, e.from_ref, e.to_ref)
            for e in bom.edges
            if e.scope == EdgeScope.RUNTIME
            and e.assurance in (AssuranceLevel.OBSERVED, AssuranceLevel.VERIFIED)
            and e.evidence
            and (
                not e.validity
                or (
                    (not e.validity.not_before or _aware(e.validity.not_before) <= lo)
                    and (not e.validity.not_after or _aware(e.validity.not_after) >= hi)
                )
            )
        }
        for tool in bom.tools:
            if not (
                tool.digest.ok
                and tool.digest.algorithm == "tooldef/v1"
                and (not descriptor_digest or tool.digest.value == descriptor_digest)
                and tool.source in (ToolSource.SERVED_LIVE, ToolSource.TRACE)
                and tool.state in (ToolState.SERVED, ToolState.INVOKED)
                and (EdgeType.PROVIDES_TOOL, tool.server_ref, tool.id) in edges
                and (
                    (EdgeType.INVOKES_TOOL, bom.subject, tool.id) in edges
                    or (EdgeType.DEPENDS_ON, bom.subject, tool.server_ref) in edges
                )
                and tool.server_ref in matched_servers
            ):
                continue
            if (digest, tool.id) in seen_records:
                raise ValueError("duplicate deployment snapshot and tool supplied")
            seen_records.add((digest, tool.id))
            grants = _effective(bom, tool, dep, lo, hi) if policy_signers else []
            events = [
                {"event": event.to_json_dict(), "signingKeys": keys}
                for event, keys in executions.values()
                if event.companion_digest == digest
                and event.snapshot_digest == snap.digest
                and event.agent == bom.subject
                and event.deployment == dep.id
                and event.workload == dep.workload_identity_ref
                and event.tool == tool.id
                and event.server == tool.server_ref
                and event.descriptor_digest == tool.digest.value
                and lo <= event.observed_at < hi
            ]
            rows.append(
                {
                    "deployment": dep.id,
                    "workload": dep.workload_identity_ref,
                    "agent": bom.subject,
                    "tool": tool.id,
                    "descriptorDigest": tool.digest.value,
                    "provenanceSigningKeys": provenance_signers,
                    "server": tool.server_ref,
                    "snapshot": snap.digest,
                    "companionDigest": digest,
                    "validFrom": lo.isoformat(),
                    "validUntil": hi.isoformat(),
                    "deployed": {"status": "evidenced", "signingKeys": signers, "source": tool.source.value},
                    "effectivePermission": {
                        "status": "evidenced" if grants else "unknown",
                        "grants": grants,
                        "signingKeys": policy_signers,
                    },
                    "observedExecution": {
                        "status": "evidenced" if events else "unknown",
                        "events": sorted(events, key=lambda e: e["event"]["eventId"]),
                    },
                }
            )
    return {
        "tenant": tenant,
        "descriptorDigest": descriptor_digest,
        "subject": {"kind": target_kind, "value": target_value, "issuer": issuer},
        "from": start.isoformat(),
        "until": end.isoformat(),
        "revocation": revocation_info,
        "deployedStatus": "evidenced" if rows else "unknown",
        "completeness": "unknown",
        "deployments": sorted(rows, key=lambda r: (r["deployment"], r["snapshot"], r["tool"])),
    }
