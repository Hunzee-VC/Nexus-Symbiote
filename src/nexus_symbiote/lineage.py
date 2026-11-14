"""Identity and data-lineage evidence without inferring unavailable guarantees.

A library helper for integrations that mediate retrieval; no command uses it. Every
operation is linear in the size of the lineage, and ancestry checks are iterative, so
append-only memory and cache lineages of any depth stay usable.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, PrivateAttr, model_validator

from nexus_symbiote.runtime import (
    Contract,
    Envelope,
    HostedModelAttestation,
    _window,
    digest,
    verify_contract,
)


class HostedModelIdentity(Contract):
    provider: str
    endpoint: str
    requested_alias: str
    revision: str | None = None
    identity_assurance: Literal["alias-only", "provider-reported", "provider-attested"] = (
        "alias-only"
    )
    evidence_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    observed_at: datetime
    _verified_digest: str | None = PrivateAttr(default=None)
    _verified_until: datetime | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def evidence_requirements(self) -> HostedModelIdentity:
        if self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.identity_assurance != "alias-only" and not self.revision:
            raise ValueError("a reported/attested identity requires a revision")
        if self.identity_assurance == "provider-attested" and not self.evidence_digest:
            raise ValueError("attestation claim requires evidence digest")
        return self

    @property
    def immutable_identity_established(self) -> bool:
        return self.identity_is_verified()

    def identity_is_verified(self, *, now: datetime | None = None) -> bool:
        timestamp = now or datetime.now(UTC)
        return bool(
            timestamp.utcoffset() is not None
            and self.identity_assurance == "provider-attested"
            and self._verified_digest == digest(self.model_dump(mode="json"))
            and self._verified_until is not None
            and timestamp < self._verified_until
        )

    def verify_attestation(
        self, envelope: Envelope, trusted_keys: Mapping[str, Ed25519PublicKey], *, now: datetime
    ) -> None:
        self._verified_digest = None
        self._verified_until = None
        contract, _ = verify_contract(envelope, "model", trusted_keys)
        if not isinstance(contract, HostedModelAttestation):
            raise ValueError("expected hosted-model attestation")
        _window(contract, now, timedelta(hours=24))
        if not contract.not_before <= self.observed_at <= now:
            raise ValueError("observation is outside the attested window or in the future")
        expected = (self.provider, self.endpoint, self.requested_alias, self.revision)
        actual = (
            contract.provider,
            contract.endpoint,
            contract.requested_alias,
            contract.resolved_revision,
        )
        if (
            actual != expected
            or digest(envelope.model_dump(mode="json", by_alias=True)) != self.evidence_digest
        ):
            raise ValueError("hosted-model attestation subject mismatch")
        if self.identity_assurance == "provider-attested":
            self._verified_digest = digest(self.model_dump(mode="json"))
            self._verified_until = contract.not_after


class DataVersion(Contract):
    id: str
    tenant: str
    kind: Literal["source", "chunk", "index", "cache", "memory"]
    content_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    parents: tuple[str, ...] = ()
    transformation_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    embedding_revision: str | None = None
    acl_revision: str
    allowed_principals: tuple[str, ...]
    writer: str | None = None
    withdrawn: bool = False


class RetrievalRecord(Contract):
    tenant: str
    principal: str
    observed_at: datetime
    source_versions: tuple[str, ...]
    source_digests: tuple[str, ...]
    acl_revisions: tuple[str, ...]
    read_watermark: str


class LineageIndex:
    """Tenant-local immutable version graph with cascading source withdrawal."""

    def __init__(self, tenant: str, versions: tuple[DataVersion, ...] = ()) -> None:
        self.tenant = tenant
        self.versions: dict[str, DataVersion] = {}
        self._children: dict[str, list[str]] = {}
        self._acl_revisions: dict[str, set[str]] = {}
        by_id: dict[str, DataVersion] = {}
        for value in versions:
            if value.id in by_id:
                raise ValueError("cross-tenant or duplicate lineage version")
            by_id[value.id] = value
        # Kahn's algorithm: each version is added once all of its parents are.
        waiting = {value.id: len(set(value.parents)) for value in versions}
        dependents: dict[str, list[str]] = {}
        for value in versions:
            for parent in set(value.parents):
                dependents.setdefault(parent, []).append(value.id)
        ready = deque(value.id for value in versions if waiting[value.id] == 0)
        while ready:
            current = ready.popleft()
            self.add(by_id[current])
            for child in dependents.get(current, ()):
                waiting[child] -= 1
                if waiting[child] == 0:
                    ready.append(child)
        if len(self.versions) != len(by_id):
            raise ValueError("lineage contains missing parents or a cycle")

    def add(self, value: DataVersion) -> None:
        if value.tenant != self.tenant or value.id in self.versions:
            raise ValueError("cross-tenant or duplicate lineage version")
        if value.id in value.parents or any(p not in self.versions for p in value.parents):
            raise ValueError("missing or cyclic parent")
        if value.kind != "source" and not value.parents:
            raise ValueError("derived records require parent evidence")
        # A record withdrawn with its parent, as withdraw() leaves it, can be loaded again.
        if not value.withdrawn and any(self.versions[p].withdrawn for p in value.parents):
            raise ValueError("cannot derive from withdrawn records")
        self.versions[value.id] = value
        self._acl_revisions[value.id] = {value.acl_revision}
        for parent in set(value.parents):
            self._children.setdefault(parent, []).append(value.id)

    def withdraw(self, source_id: str) -> tuple[str, ...]:
        if source_id not in self.versions:
            raise KeyError(source_id)
        queue = deque([source_id])
        affected: set[str] = set()
        while queue:
            current = queue.popleft()
            if current in affected:
                continue
            affected.add(current)
            self.versions[current] = self.versions[current].model_copy(update={"withdrawn": True})
            queue.extend(self._children.get(current, ()))
        return tuple(sorted(affected))

    def update_acl(self, version: str, *, revision: str, principals: tuple[str, ...]) -> None:
        """Apply a new ACL revision; a revision used before cannot be restored.

        Revisions have no order, so reuse is what is refused: otherwise an earlier, wider
        ACL could be reinstated under its old revision and replay retrievals approved
        against it.
        """
        current = self.versions[version]
        used = self._acl_revisions.setdefault(version, {current.acl_revision})
        if revision in used:
            raise ValueError("ACL revision was already used for this version")
        used.add(revision)
        self.versions[version] = current.model_copy(
            update={"acl_revision": revision, "allowed_principals": principals}
        )

    def retrieve(
        self,
        ids: tuple[str, ...],
        *,
        principal: str,
        acl_revision: str,
        observed_at: datetime,
        read_watermark: str,
    ) -> RetrievalRecord:
        if observed_at.utcoffset() is None:
            raise ValueError("retrieval time must be timezone-aware")
        selected = [self.versions[i] for i in ids]
        checked: set[str] = set()
        for value in selected:
            self._authorize_ancestry(value.id, principal, acl_revision, checked)
        return RetrievalRecord(
            tenant=self.tenant,
            principal=principal,
            observed_at=observed_at,
            source_versions=ids,
            source_digests=tuple(v.content_digest for v in selected),
            acl_revisions=tuple(v.acl_revision for v in selected),
            read_watermark=read_watermark,
        )

    def _authorize_ancestry(self, version: str, principal: str, acl: str, seen: set[str]) -> None:
        pending = [version]
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            value = self.versions[current]
            if (
                value.withdrawn
                or principal not in value.allowed_principals
                or value.acl_revision != acl
            ):
                raise PermissionError("withdrawn, unauthorized, or stale ACL evidence")
            pending.extend(value.parents)
