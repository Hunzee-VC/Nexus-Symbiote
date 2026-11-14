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
from pydantic import ConfigDict, Field, PrivateAttr, model_validator

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
    # model_copy(update=...) and model_construct() can produce invalid instances.
    # Revalidate them even when nested inside a snapshot or supplied to add().
    model_config = ConfigDict(revalidate_instances="always")

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


class LineageSnapshot(Contract):
    """Serializable graph and ACL history; ``None`` marks an unknown history.

    This is a state representation, not an authenticated or rollback-protected
    document. The caller is responsible for protecting it and loading the latest
    committed snapshot.
    """

    format: Literal["nexus-symbiote-lineage/1"]
    tenant: str
    versions: tuple[DataVersion, ...]
    acl_revisions: dict[str, tuple[str, ...] | None]


class LineageIndex:
    """Tenant-local version graph with cascading withdrawal and ACL history.

    Versions passed to the constructor have unknown ACL history. Use ``add``
    for a new record, or ``from_snapshot`` to restore recorded history.
    """

    def __init__(self, tenant: str, versions: tuple[DataVersion, ...] = ()) -> None:
        self.tenant = tenant
        self.versions: dict[str, DataVersion] = {}
        self._children: dict[str, list[str]] = {}
        self._acl_revisions: dict[str, set[str] | None] = {}
        by_id: dict[str, DataVersion] = {}
        for supplied in versions:
            value = DataVersion.model_validate(supplied)
            if value.id in by_id:
                raise ValueError("cross-tenant or duplicate lineage version")
            by_id[value.id] = value
        # Kahn's algorithm: each version is added once all of its parents are.
        waiting = {value.id: len(set(value.parents)) for value in by_id.values()}
        dependents: dict[str, list[str]] = {}
        for value in by_id.values():
            for parent in set(value.parents):
                dependents.setdefault(parent, []).append(value.id)
        ready = deque(value.id for value in by_id.values() if waiting[value.id] == 0)
        while ready:
            current = ready.popleft()
            self._add_validated(by_id[current])
            # A versions-only import may have omitted prior ACL revisions. It is
            # safe for retrieval against the current ACL, but cannot accept updates
            # until the operator recovers the complete history.
            self._acl_revisions[current] = None
            for child in dependents.get(current, ()):
                waiting[child] -= 1
                if waiting[child] == 0:
                    ready.append(child)
        if len(self.versions) != len(by_id):
            raise ValueError("lineage contains missing parents or a cycle")

    @classmethod
    def from_new_versions(cls, tenant: str, versions: tuple[DataVersion, ...]) -> LineageIndex:
        """Initialize a new graph whose versions have never had earlier ACL revisions.

        This is an operator assertion, not a safe way to restore an existing graph.
        """
        result = cls(tenant, versions)
        for version_id, value in result.versions.items():
            result._acl_revisions[version_id] = {value.acl_revision}
        return result

    @classmethod
    def from_snapshot(cls, snapshot: LineageSnapshot | Mapping[str, object]) -> LineageIndex:
        """Restore a snapshot after the caller has established its trust and freshness."""
        # Revalidate even a model object: model_copy(update=...) skips validation.
        document = (
            snapshot.model_dump(mode="python", warnings="none")
            if isinstance(snapshot, LineageSnapshot)
            else snapshot
        )
        state = LineageSnapshot.model_validate(document)
        result = cls(state.tenant, state.versions)
        if set(state.acl_revisions) != set(result.versions):
            raise ValueError("ACL history must name exactly the lineage versions")
        for version_id, revisions in state.acl_revisions.items():
            if revisions is None:
                continue
            if len(revisions) != len(set(revisions)):
                raise ValueError("ACL history contains a duplicate revision")
            if result.versions[version_id].acl_revision not in revisions:
                raise ValueError("ACL history must contain the current revision")
            result._acl_revisions[version_id] = set(revisions)
        return result

    @classmethod
    def from_legacy_versions(
        cls,
        tenant: str,
        versions: tuple[DataVersion, ...],
        *,
        acl_revisions: Mapping[str, tuple[str, ...]],
    ) -> LineageIndex:
        """Migrate versions using complete ACL histories supplied by the operator.

        The index can validate structure and current revisions, not whether the
        supplied histories contain every prior revision.
        """
        state = LineageSnapshot(
            format="nexus-symbiote-lineage/1",
            tenant=tenant,
            versions=versions,
            acl_revisions=dict(acl_revisions),
        )
        if any(revisions is None for revisions in state.acl_revisions.values()):
            raise ValueError("migration requires complete ACL history for every version")
        return cls.from_snapshot(state)

    def snapshot(self) -> LineageSnapshot:
        """Return a deterministic state snapshot, including unknown histories."""
        return LineageSnapshot(
            format="nexus-symbiote-lineage/1",
            tenant=self.tenant,
            versions=tuple(self.versions[key] for key in sorted(self.versions)),
            acl_revisions={
                key: None if revisions is None else tuple(sorted(revisions))
                for key, revisions in sorted(self._acl_revisions.items())
            },
        )

    def add(self, value: DataVersion) -> None:
        self._add_validated(DataVersion.model_validate(value))

    def _add_validated(self, value: DataVersion) -> None:
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
        used = self._acl_revisions[version]
        if used is None:
            raise ValueError("ACL history is unknown; restore or migrate complete history first")
        candidate = DataVersion.model_validate(
            {
                **current.model_dump(mode="python", warnings="none"),
                "acl_revision": revision,
                "allowed_principals": principals,
            }
        )
        if candidate.acl_revision in used:
            raise ValueError("ACL revision was already used for this version")
        used.add(candidate.acl_revision)
        self.versions[version] = candidate

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
