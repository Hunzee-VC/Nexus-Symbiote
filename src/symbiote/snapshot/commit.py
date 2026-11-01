"""Build the Merkle commitment of an AgentBOM and finalise its snapshot header."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from symbiote.digest.merkle import MerkleBuilder, verify_commitment
from symbiote.model.common import Validity
from symbiote.model.document import COLLECTIONS, AgentBOM
from symbiote.model.enums import SnapshotKind
from symbiote.model.ids import snapshot_id
from symbiote.model.snapshot import MerkleCommitment, ObservationWindow, Producer, Snapshot

PLACEHOLDER_DIGEST = "sha256:" + "0" * 64


def entity_body(entity: Any) -> dict[str, Any]:
    """Canonical leaf body of an entity: its companion JSON form."""
    return entity.to_json_dict()


def collect_leaves(bom: AgentBOM) -> list[tuple[str, str, Any]]:
    """``(kind, id, body)`` for every entity, edge, coverage object and derived flag/finding."""
    leaves: list[tuple[str, str, Any]] = []
    for attr in COLLECTIONS:
        for ent in getattr(bom, attr):
            leaves.append(
                (
                    ent.entity_kind if hasattr(ent, "entity_kind") else ent.id.split(":", 1)[0],
                    ent.id,
                    entity_body(ent),
                )
            )
    for edge in bom.edges:
        leaves.append(("edge", f"{edge.type.value}:{edge.from_ref}->{edge.to_ref}", edge.to_json_dict()))
    leaves.append(("coverage", "coverage", bom.coverage.to_json_dict()))
    for flag in bom.derived.flags:
        leaves.append(("flag", f"{flag.flag.value}:{flag.subject_ref}", flag.to_json_dict()))
    for i, finding in enumerate(bom.derived.findings):
        leaves.append(("finding", f"{finding.check_id}:{i}", finding.to_json_dict()))
    for red in bom.redactions:
        leaves.append(
            ("redaction", f"{red.redaction_class}:{red.applied_at.isoformat()}", red.to_json_dict())
        )
    return leaves


def compute_commitment(
    bom: AgentBOM, nonce: bytes | None = None, *, include_nonce: bool = True
) -> MerkleCommitment:
    builder = MerkleBuilder(nonce=nonce)
    for kind, eid, body in collect_leaves(bom):
        builder.add(kind, eid, body)
    return builder.build(include_nonce=include_nonce)


def provisional_snapshot(
    agent_ref: str, kind: SnapshotKind, *, serial: int = 1, produced_at: datetime | None = None
) -> Snapshot:
    """A placeholder header so an :class:`AgentBOM` can be constructed before its digest is known."""
    produced_at = produced_at or datetime.now(UTC)
    window = ObservationWindow(start=produced_at, end=produced_at) if kind is SnapshotKind.OBSERVED else None
    return Snapshot(
        id=snapshot_id(serial, PLACEHOLDER_DIGEST),
        kind=kind,
        digest=PLACEHOLDER_DIGEST,
        serial=serial,
        agent_ref=agent_ref,
        produced_at=produced_at,
        observation_window=window,
    )


def new_document(
    *,
    subject: str,
    producer: Producer,
    kind: SnapshotKind,
    serial: int = 1,
    produced_at: datetime | None = None,
    **collections: Any,
) -> AgentBOM:
    """Construct an unfinalised document (placeholder snapshot digest); call :func:`finalize` afterwards."""
    return AgentBOM(
        snapshot=provisional_snapshot(subject, kind, serial=serial, produced_at=produced_at),
        subject=subject,
        producer=producer,
        **collections,
    )


def finalize(
    bom: AgentBOM,
    *,
    nonce: bytes | None = None,
    prev: str | None = None,
    validity: Validity | None = None,
    observation_window: ObservationWindow | None = None,
    approvals: list[str] | None = None,
    include_nonce: bool = True,
) -> AgentBOM:
    """Sort collections, compute the salted Merkle commitment and write the snapshot header (digest = root)."""
    sorted_bom = bom.sorted()
    commitment = compute_commitment(sorted_bom, nonce, include_nonce=include_nonce)
    old = sorted_bom.snapshot
    header = Snapshot(
        id=snapshot_id(old.serial, commitment.root),
        kind=old.kind,
        digest=commitment.root,
        serial=old.serial,
        prev=prev if prev is not None else old.prev,
        agent_ref=old.agent_ref,
        deployment_ref=old.deployment_ref,
        validity=validity or old.validity,
        produced_at=old.produced_at,
        producer_ref=old.producer_ref,
        observation_window=observation_window or old.observation_window,
        approvals=approvals if approvals is not None else old.approvals,
        policy_bundle=old.policy_bundle,
    )
    return sorted_bom.replace(
        snapshot=header.model_dump(mode="python"), merkle=commitment.model_dump(mode="python")
    )


def verify_document(bom: AgentBOM) -> bool:
    """Recompute the Merkle root from the document's leaves (disclosed with salts, redacted by hash) and compare."""
    if bom.merkle is None:
        return False
    bodies = {(k, i): b for k, i, b in collect_leaves(bom)}
    return verify_commitment(bom.merkle, bodies) and bom.snapshot.digest == bom.merkle.root


__all__ = [
    "PLACEHOLDER_DIGEST",
    "collect_leaves",
    "compute_commitment",
    "entity_body",
    "finalize",
    "new_document",
    "provisional_snapshot",
    "verify_document",
]
