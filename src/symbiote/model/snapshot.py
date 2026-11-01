"""Snapshot header, Merkle commitment and deltas (``spec/agentbom-profile.md §2``)."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from symbiote.model.base import SymbioteModel
from symbiote.model.common import Claim, DigestStr, EntityId, EvidenceRef, Validity
from symbiote.model.entities import Collector
from symbiote.model.enums import AssuranceLevel, DeltaEventType, Severity, SnapshotKind


class Producer(SymbioteModel):
    name: str = "symbiote"
    version: str
    digest: DigestStr | None = None
    collectors: list[Collector] = Field(default_factory=list)


class ObservationWindow(SymbioteModel):
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _ordered(self) -> ObservationWindow:
        if self.end < self.start:
            raise ValueError("observation window end precedes start")
        return self


class Snapshot(SymbioteModel):
    id: str = Field(pattern=r"^snap:[0-9]+:[0-9a-f]{12}$")
    kind: SnapshotKind
    digest: DigestStr
    serial: int = Field(ge=1)
    prev: DigestStr | None = None
    agent_ref: EntityId
    deployment_ref: EntityId | None = None
    validity: Validity = Field(default_factory=Validity)
    produced_at: datetime
    producer_ref: str = "symbiote"
    observation_window: ObservationWindow | None = None
    approvals: list[EntityId] = Field(default_factory=list)
    policy_bundle: Claim[DigestStr] | None = None

    @model_validator(mode="after")
    def _id_matches(self) -> Snapshot:
        expected = f"snap:{self.serial}:{self.digest[len('sha256:') :][:12]}"
        if self.id != expected:
            raise ValueError(f"Snapshot.id must be {expected}")
        if self.kind is SnapshotKind.OBSERVED and self.observation_window is None:
            raise ValueError("an observed snapshot needs an observation window")
        return self


class MerkleLeaf(SymbioteModel):
    kind: str
    id: str
    leaf_hash: DigestStr
    salt: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{32}$", description="hex salt; absent for redacted leaves"
    )


class MerkleCommitment(SymbioteModel):
    algorithm: str = "rfc6962-sha256-salted"
    root: DigestStr
    leaf_count: int = Field(ge=0)
    nonce: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$", description="per-snapshot nonce; withheld in redacted views"
    )
    leaves: list[MerkleLeaf] = Field(default_factory=list)


class DeltaEvent(SymbioteModel):
    type: DeltaEventType
    subject_ref: EntityId
    before: DigestStr | None = None
    after: DigestStr | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    assurance: AssuranceLevel = AssuranceLevel.OBSERVED
    severity_hint: Severity = Severity.MEDIUM
    detail: str | None = None


class Delta(SymbioteModel):
    id: str
    from_snapshot: DigestStr
    to_snapshot: DigestStr
    produced_at: datetime
    producer: Producer
    events: list[DeltaEvent] = Field(default_factory=list)


__all__ = [
    "Delta",
    "DeltaEvent",
    "MerkleCommitment",
    "MerkleLeaf",
    "ObservationWindow",
    "Producer",
    "Snapshot",
]
