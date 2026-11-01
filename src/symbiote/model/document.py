"""The AgentBOM document (``spec/agentbom-profile.md §2``)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Literal

from pydantic import Field, model_validator

from symbiote import SPEC_VERSION
from symbiote.model.base import SymbioteModel
from symbiote.model.common import EntityId, Party
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
    Finding,
    Flag,
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
from symbiote.model.snapshot import Delta, MerkleCommitment, Producer, Snapshot


class Derived(SymbioteModel):
    flags: list[Flag] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


#: Collection attribute name → entity id prefix (kind).
COLLECTIONS: dict[str, str] = {
    "agents": "agent",
    "deployments": "deploy",
    "tool_servers": "server",
    "tools": "tool",
    "instructions": "instr",
    "prompts": "prompt",
    "skills": "skill",
    "models": "model",
    "data_sources": "data",
    "identities": "ident",
    "credential_bindings": "cred",
    "grants": "grant",
    "approvals": "appr",
    "resolutions": "res",
    "evidence": "ev",
    "evaluations": "eval",
    "vex": "vex",
    "trust_status": "trust",
    "parties": "party",
    "policies": "policy",
    "software": "sw",
}


class AgentBOM(SymbioteModel):
    """One snapshot of one agent: the structured source of truth that CycloneDX and SPDX project."""

    spec_version: Literal["0.1"] = SPEC_VERSION  # type: ignore[assignment]
    snapshot: Snapshot
    subject: EntityId
    producer: Producer
    agents: list[Agent] = Field(default_factory=list)
    deployments: list[Deployment] = Field(default_factory=list)
    tool_servers: list[ToolServer] = Field(default_factory=list)
    tools: list[ToolDefinition] = Field(default_factory=list)
    instructions: list[Instruction] = Field(default_factory=list)
    prompts: list[PromptTemplate] = Field(default_factory=list)
    skills: list[Skill] = Field(default_factory=list)
    models: list[Model] = Field(default_factory=list)
    data_sources: list[DataSource] = Field(default_factory=list)
    identities: list[Identity] = Field(default_factory=list)
    credential_bindings: list[CredentialBinding] = Field(default_factory=list)
    grants: list[Grant] = Field(default_factory=list)
    approvals: list[Approval] = Field(default_factory=list)
    resolutions: list[RegistryResolution] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    evaluations: list[Evaluation] = Field(default_factory=list)
    vex: list[VexStatement] = Field(default_factory=list)
    trust_status: list[TrustStatus] = Field(default_factory=list)
    parties: list[Party] = Field(default_factory=list)
    policies: list[Policy] = Field(default_factory=list)
    software: list[SoftwareComponent] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    derived: Derived = Field(default_factory=Derived)
    merkle: MerkleCommitment | None = None
    redactions: list[Redaction] = Field(default_factory=list)
    links: Links = Field(default_factory=Links)
    loss_report: LossReport | None = None
    deltas: list[Delta] = Field(default_factory=list)
    foreign_properties: list[ForeignProperty] = Field(default_factory=list)

    # ---------------------------------------------------------------- validation

    @model_validator(mode="after")
    def _integrity(self) -> AgentBOM:
        ids: dict[str, str] = {}
        for attr, prefix in COLLECTIONS.items():
            for ent in getattr(self, attr):
                eid = ent.id
                if not eid.startswith(prefix + ":"):
                    raise ValueError(f"{attr}: entity id {eid!r} must start with {prefix!r}:")
                if eid in ids:
                    raise ValueError(f"duplicate entity id {eid!r} (in {ids[eid]} and {attr})")
                ids[eid] = attr
        if self.subject not in ids:
            raise ValueError(f"subject {self.subject!r} is not among the agents")
        if self.snapshot.agent_ref != self.subject:
            raise ValueError("snapshot.agent_ref must equal subject")
        dangling = [e for e in self.edges if e.from_ref not in ids or e.to_ref not in ids]
        if dangling:
            d = dangling[0]
            raise ValueError(f"edge {d.type.value} {d.from_ref} -> {d.to_ref} references an unknown entity")
        if self.merkle is not None and self.merkle.root != self.snapshot.digest:
            raise ValueError("snapshot.digest must equal merkle.root")
        return self

    # ---------------------------------------------------------------- access helpers

    def iter_entities(self) -> Iterator[tuple[str, Entity | Party]]:
        """Yield ``(collection, entity)`` for every entity, in collection order then id order."""
        for attr in COLLECTIONS:
            for ent in sorted(getattr(self, attr), key=lambda e: e.id):
                yield attr, ent

    def entity(self, entity_id: EntityId) -> Entity | Party | None:
        for _, ent in self.iter_entities():
            if ent.id == entity_id:
                return ent
        return None

    def __contains__(self, entity_id: object) -> bool:
        return isinstance(entity_id, str) and self.entity(entity_id) is not None

    @property
    def root_agent(self) -> Agent:
        for a in self.agents:
            if a.id == self.subject:
                return a
        raise LookupError(self.subject)

    def edges_from(self, entity_id: EntityId, *types: str) -> list[Edge]:
        return [e for e in self.edges if e.from_ref == entity_id and (not types or e.type.value in types)]

    def edges_to(self, entity_id: EntityId, *types: str) -> list[Edge]:
        return [e for e in self.edges if e.to_ref == entity_id and (not types or e.type.value in types)]

    def sorted(self) -> AgentBOM:
        """Return a copy with every collection in canonical order (I7 determinism)."""
        changes: dict[str, Any] = {
            attr: sorted(getattr(self, attr), key=lambda e: e.id) for attr in COLLECTIONS
        }
        changes["edges"] = sorted(self.edges, key=lambda e: e.key)
        return self.model_copy(update=changes)


__all__ = ["COLLECTIONS", "AgentBOM", "Derived"]
