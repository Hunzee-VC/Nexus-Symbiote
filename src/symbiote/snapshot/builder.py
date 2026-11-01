"""Snapshot builder: entity collections → salted Merkle commitment → sealed ``AgentBOM``.

Implements ``spec/agentbom-profile.md §2.1`` and ``spec/digests.md §5``:

* leaves = every entity (kind = its id prefix, body = :func:`symbiote.snapshot.body.leaf_body`),
  every edge, the coverage block and every derived flag — findings are *not* leaves (they are
  recomputable policy output; sealing them would make ``policy check`` mutate the root);
* ``snapshot.digest`` = the salted RFC 6962 root; ``Snapshot.id`` = ``snap:<serial>:<digest12>``;
* ``serial``/``prev`` come from an explicit argument or the :class:`~symbiote.snapshot.state.ChainStore`;
* under a fixed nonce and fixed timestamps the sealed document is byte-identical (I7).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from symbiote.digest import MerkleBuilder
from symbiote.model.common import Claim, DigestStr, EntityId, Party, Validity
from symbiote.model.document import COLLECTIONS, AgentBOM, Derived
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    Agent,
    Approval,
    Coverage,
    CredentialBinding,
    DataSource,
    Deployment,
    Entity,
    Evaluation,
    Evidence,
    ForeignProperty,
    Grant,
    Identity,
    Instruction,
    Links,
    LossReport,
    Model,
    Policy,
    PromptTemplate,
    Redaction,
    RegistryResolution,
    Skill,
    SoftwareComponent,
    ToolDefinition,
    ToolServer,
    TrustStatus,
    VexStatement,
)
from symbiote.model.enums import SnapshotKind
from symbiote.model.snapshot import (
    Delta,
    MerkleCommitment,
    ObservationWindow,
    Producer,
    Snapshot,
)
from symbiote.snapshot.body import edge_leaf_id, flag_leaf_id, leaf_body
from symbiote.snapshot.state import ChainIssue, ChainStore

_TYPE_TO_COLLECTION: tuple[tuple[type, str], ...] = (
    (Agent, "agents"),
    (Deployment, "deployments"),
    (ToolServer, "tool_servers"),
    (ToolDefinition, "tools"),
    (Instruction, "instructions"),
    (PromptTemplate, "prompts"),
    (Skill, "skills"),
    (Model, "models"),
    (DataSource, "data_sources"),
    (Identity, "identities"),
    (CredentialBinding, "credential_bindings"),
    (Grant, "grants"),
    (Approval, "approvals"),
    (RegistryResolution, "resolutions"),
    (Evidence, "evidence"),
    (Evaluation, "evaluations"),
    (VexStatement, "vex"),
    (TrustStatus, "trust_status"),
    (Party, "parties"),
    (Policy, "policies"),
    (SoftwareComponent, "software"),
)


class SnapshotBuilder:
    """Accumulates entities, edges and document blocks, then seals one ``AgentBOM`` snapshot.

    Collectors (WP9/WP10) feed :meth:`add`; :meth:`build` computes the commitment, mints the
    snapshot header and validates the whole document through the frozen model.
    """

    def __init__(
        self,
        *,
        kind: SnapshotKind,
        subject: EntityId,
        producer: Producer,
        store: ChainStore | None = None,
        nonce: bytes | None = None,
    ) -> None:
        self.kind = kind
        self.subject = subject
        self.producer = producer
        self.store = store
        self.nonce = nonce
        self._collections: dict[str, list[Entity | Party]] = {name: [] for name in COLLECTIONS}
        self._edges: list[Edge] = []
        self.coverage: Coverage = Coverage()
        self.derived: Derived = Derived()
        self.links: Links = Links()
        self._redactions: list[Redaction] = []
        self._deltas: list[Delta] = []
        self._foreign: list[ForeignProperty] = []
        self.loss_report: LossReport | None = None
        self.chain_issues: list[ChainIssue] = []

    # ------------------------------------------------------------------ accumulation

    def add(self, *entities: Entity | Party) -> SnapshotBuilder:
        """Route each entity to its collection (type-dispatched; order never matters)."""
        for entity in entities:
            for cls, attr in _TYPE_TO_COLLECTION:
                if isinstance(entity, cls):
                    self._collections[attr].append(entity)
                    break
            else:
                raise TypeError(f"no AgentBOM collection for {type(entity).__name__}")
        return self

    def add_edges(self, *edges: Edge) -> SnapshotBuilder:
        self._edges.extend(edges)
        return self

    def set_coverage(self, coverage: Coverage) -> SnapshotBuilder:
        self.coverage = coverage
        return self

    def set_derived(self, derived: Derived) -> SnapshotBuilder:
        self.derived = derived
        return self

    def set_links(self, links: Links) -> SnapshotBuilder:
        self.links = links
        return self

    def add_redactions(self, *redactions: Redaction) -> SnapshotBuilder:
        self._redactions.extend(redactions)
        return self

    def add_deltas(self, *deltas: Delta) -> SnapshotBuilder:
        self._deltas.extend(deltas)
        return self

    def add_foreign_properties(self, *props: ForeignProperty) -> SnapshotBuilder:
        self._foreign.extend(props)
        return self

    # ------------------------------------------------------------------ sealing

    def commitment(self, *, include_nonce: bool = True) -> MerkleCommitment:
        """The salted commitment over entities, edges, coverage and derived flags."""
        mb = MerkleBuilder(nonce=self.nonce)
        for attr in COLLECTIONS:
            for entity in self._collections[attr]:
                mb.add(entity.id.split(":", 1)[0], entity.id, leaf_body(entity))
        for edge in self._edges:
            mb.add("edge", edge_leaf_id(edge), edge.to_json_dict())
        mb.add("coverage", "coverage", self.coverage.to_json_dict())
        for flag in self.derived.flags:
            mb.add("flag", flag_leaf_id(flag), flag.to_json_dict())
        if self.nonce is None:
            self.nonce = mb.nonce  # keep the generated nonce so commitment() is stable per builder
        return mb.build(include_nonce=include_nonce)

    def build(
        self,
        *,
        produced_at: datetime,
        serial: int | None = None,
        prev: DigestStr | None = None,
        validity: Validity | None = None,
        deployment_ref: EntityId | None = None,
        observation_window: ObservationWindow | None = None,
        approvals: Iterable[EntityId] = (),
        policy_bundle: Claim[DigestStr] | None = None,
        include_nonce: bool = True,
        record: bool = True,
        force: bool = False,
    ) -> AgentBOM:
        """Seal the document.

        ``serial``/``prev`` resolution: explicit arguments win; otherwise the chain store
        allocates; otherwise ``(1, None)``. With a store and ``record=True`` the sealed snapshot
        is committed to the chain — anti-rollback conflicts raise
        :class:`~symbiote.snapshot.state.ChainConflictError` unless ``force`` — and any
        non-critical chain issues are kept on :attr:`chain_issues` for the caller to surface.
        """
        if serial is None:
            if self.store is not None:
                serial, allocated_prev = self.store.allocate(self.subject, self.kind)
                prev = prev if prev is not None else allocated_prev
            else:
                serial = 1
        commitment = self.commitment(include_nonce=include_nonce)
        snapshot = Snapshot(
            id=f"snap:{serial}:{commitment.root[len('sha256:') :][:12]}",
            kind=self.kind,
            digest=commitment.root,
            serial=serial,
            prev=prev,
            agent_ref=self.subject,
            deployment_ref=deployment_ref,
            validity=validity or Validity(),
            produced_at=produced_at,
            producer_ref=self.producer.name,
            observation_window=observation_window,
            approvals=list(approvals),
            policy_bundle=policy_bundle,
        )
        bom = AgentBOM(
            snapshot=snapshot,
            subject=self.subject,
            producer=self.producer,
            edges=self._edges,
            coverage=self.coverage,
            derived=self.derived,
            merkle=commitment,
            redactions=self._redactions,
            links=self.links,
            loss_report=self.loss_report,
            deltas=self._deltas,
            foreign_properties=self._foreign,
            **{attr: self._collections[attr] for attr in COLLECTIONS},
        ).sorted()
        if self.store is not None and record:
            self.chain_issues = self.store.commit(snapshot, force=force)
        return bom


__all__ = ["SnapshotBuilder"]
