"""in-toto Statement v1 builders and Symbiote predicate payloads (``spec/attestation.md §1``)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from symbiote import BASE_URI
from symbiote.digest.envelope import digest_str, strip_prefix
from symbiote.digest.jcs import canonical_bytes
from symbiote.model.common import DigestResult
from symbiote.model.document import AgentBOM
from symbiote.model.entities import TrustStatus

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_BASE = f"{BASE_URI}attestation/"


def predicate_type(kind: str) -> str:
    """``https://aisecnomad.github.io/symbiote/attestation/<kind>/v1``."""
    return f"{PREDICATE_BASE}{kind}/v1"


def subject(name: str, digest: str) -> dict[str, Any]:
    return {"name": name, "digest": {"sha256": strip_prefix(digest)}}


def statement(
    subjects: Iterable[Mapping[str, Any]], pred_type: str, predicate: Mapping[str, Any]
) -> dict[str, Any]:
    subs = list(subjects)
    if not subs:
        raise ValueError("a statement needs at least one subject")
    return {
        "_type": STATEMENT_TYPE,
        "subject": subs,
        "predicateType": pred_type,
        "predicate": dict(predicate),
    }


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def snapshot_predicate(bom: AgentBOM, *, produced_at: str | None = None) -> dict[str, Any]:
    """``agentbom-snapshot/v1`` payload."""
    if bom.merkle is None:
        raise ValueError("finalize the document before attesting it")
    agent = bom.root_agent
    toolsets: dict[str, str] = {}
    for srv in bom.tool_servers:
        if srv.toolset_digest and srv.toolset_digest.value:
            toolsets[srv.id] = srv.toolset_digest.value
    model_ids = []
    for m in bom.models:
        ident: str = "unknown"
        if m.weights and m.weights.value:
            ident = m.weights.value.manifest_root
        elif m.hosted and m.hosted.value and m.hosted.value.resolved_ref.value:
            ident = str(m.hosted.value.resolved_ref.value)
        model_ids.append({"id": m.id, "identity": ident})
    grants_digest = digest_str(
        canonical_bytes([g.to_json_dict() for g in sorted(bom.grants, key=lambda g: g.id)])
    )
    return {
        "agent": {"id": agent.id, "name": agent.name, "version": agent.version},
        "kind": bom.snapshot.kind.value,
        "serial": bom.snapshot.serial,
        "prev": bom.snapshot.prev,
        "validity": {
            "notBefore": _iso(bom.snapshot.validity.not_before),
            "notAfter": _iso(bom.snapshot.validity.not_after),
        },
        "producedAt": produced_at or _iso(bom.snapshot.produced_at),
        "producer": {
            "name": bom.producer.name,
            "version": bom.producer.version,
            "digest": bom.producer.digest,
        },
        "leafCount": bom.merkle.leaf_count,
        "leaves": [
            {"kind": leaf.kind, "id": leaf.id, "leafHash": leaf.leaf_hash} for leaf in bom.merkle.leaves
        ],
        "coverageDigest": digest_str(canonical_bytes(bom.coverage.to_json_dict())),
        "policyBundleDigest": bom.snapshot.policy_bundle.value
        if bom.snapshot.policy_bundle and bom.snapshot.policy_bundle.value
        else None,
        "toolsetDigests": toolsets,
        "modelIdentities": model_ids,
        "grantsDigest": grants_digest,
        "redactions": [{"class": r.redaction_class, "count": r.count} for r in bom.redactions],
    }


def snapshot_statement(
    bom: AgentBOM,
    *,
    companion_digest: str | None = None,
    cyclonedx_digest: str | None = None,
    spdx_digest: str | None = None,
) -> dict[str, Any]:
    subs = [subject(f"snapshot:{bom.subject}", bom.snapshot.digest)]
    if companion_digest:
        subs.append(subject("companion", companion_digest))
    if cyclonedx_digest:
        subs.append(subject("cyclonedx", cyclonedx_digest))
    if spdx_digest:
        subs.append(subject("spdx", spdx_digest))
    return statement(subs, predicate_type("agentbom-snapshot"), snapshot_predicate(bom))


def toolset_predicate(
    *,
    server: Mapping[str, Any],
    tools: Iterable[tuple[str, DigestResult, DigestResult | None]],
    method: str,
    observed_at: str | None = None,
    capture_digest: str | None = None,
    truncated: bool = False,
) -> dict[str, Any]:
    """``tool-definition-set/v1`` payload."""
    tool_entries = []
    for name, digest, full in tools:
        if not digest.ok:
            raise ValueError(f"cannot attest an undigestable tool definition: {name}")
        tool_entries.append(
            {
                "name": name,
                "digest": digest.value,
                "fullDigest": full.value if full and full.ok else None,
                "textFlags": [],
            }
        )
    tool_entries.sort(key=lambda t: t["name"].encode("utf-16-be"))
    return {
        "server": dict(server),
        "observedAt": observed_at or _now(),
        "method": method,
        "capture": {"digest": capture_digest, "mediaType": "application/json"} if capture_digest else None,
        "tools": tool_entries,
        "truncated": truncated,
    }


def toolset_statement(server_id: str, toolset_digest: str, predicate: Mapping[str, Any]) -> dict[str, Any]:
    subs = [
        subject(f"tool:{server_id.split(':', 1)[-1]}/{t['name']}", t["digest"]) for t in predicate["tools"]
    ]
    subs.append(subject(f"toolset:{server_id}", toolset_digest))
    return statement(subs, predicate_type("tool-definition-set"), predicate)


def trust_status_statement(
    org: str,
    entries: Iterable[TrustStatus],
    *,
    serial: int,
    expires: str,
    decided_by: str,
    supersedes: str | None = None,
) -> dict[str, Any]:
    items = [e.to_json_dict() for e in sorted(entries, key=lambda e: e.id)]
    digest = digest_str(canonical_bytes(items))
    predicate = {
        "serial": serial,
        "supersedes": supersedes,
        "issuedAt": _now(),
        "expires": expires,
        "decidedBy": decided_by,
        "entries": items,
    }
    return statement([subject(f"trust-status:{org}", digest)], predicate_type("trust-status"), predicate)


def statement_bytes(stmt: Mapping[str, Any]) -> bytes:
    """Canonical (JCS) bytes of a statement — what gets signed."""
    return canonical_bytes(dict(stmt))


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__ = [
    "PAYLOAD_TYPE",
    "PREDICATE_BASE",
    "STATEMENT_TYPE",
    "predicate_type",
    "snapshot_predicate",
    "snapshot_statement",
    "statement",
    "statement_bytes",
    "subject",
    "toolset_predicate",
    "toolset_statement",
    "trust_status_statement",
]
