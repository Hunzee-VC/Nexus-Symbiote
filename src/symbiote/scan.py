"""``symbiote scan``: run collectors over a repository and produce a finalised declared snapshot."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from symbiote import __version__
from symbiote.collect import CollectContext, CollectionResult, load_collectors, merge_coverage, run_collectors
from symbiote.model import AgentBOM, Claim, Edge, Party
from symbiote.model import enums as E
from symbiote.model.document import COLLECTIONS
from symbiote.model.entities import (
    Agent,
    Approval,
    Collector,
    CredentialBinding,
    DataSource,
    Deployment,
    Entity,
    Evaluation,
    Evidence,
    FrameworkRef,
    Grant,
    Identity,
    Instruction,
    Model,
    Policy,
    PromptTemplate,
    RegistryResolution,
    Skill,
    SoftwareComponent,
    ToolDefinition,
    ToolServer,
    TrustStatus,
    VexStatement,
)
from symbiote.model.ids import make_id
from symbiote.model.snapshot import Producer
from symbiote.snapshot import finalize, new_document

_COLLECTION_BY_TYPE: list[tuple[type, str]] = [
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
    (Policy, "policies"),
    (SoftwareComponent, "software"),
]

AGENT_DECLARATION_FILES = ("symbiote.yaml", "symbiote.yml", "agent.yaml", "agent.yml")


@dataclass
class ScanOutcome:
    bom: AgentBOM
    results: list[CollectionResult]
    warnings: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {attr: len(getattr(self.bom, attr)) for attr in COLLECTIONS if getattr(self.bom, attr)}


def _collection_for(entity: Entity) -> str:
    for cls, attr in _COLLECTION_BY_TYPE:
        if isinstance(entity, cls):
            return attr
    raise TypeError(f"no collection for {type(entity).__name__}")


def read_agent_declaration(root: Path) -> tuple[dict[str, Any], str | None]:
    """Load ``symbiote.yaml`` / ``agent.yaml`` if present (declared facts about the root agent)."""
    for name in AGENT_DECLARATION_FILES:
        path = root / name
        if path.is_file():
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except (yaml.YAMLError, OSError):
                return {}, name
            return (data if isinstance(data, dict) else {}), name
    return {}, None


def root_agent_from(
    root: Path, declaration: dict[str, Any], locator: str | None, *, agent_name: str | None = None
) -> tuple[Agent, list[Party]]:
    name = agent_name or str(declaration.get("name") or root.resolve().name or "agent")
    version = str(declaration.get("version") or "0.0.0")
    parties: list[Party] = []
    owner_ref = None
    owner = declaration.get("owner")
    if isinstance(owner, dict) and owner.get("name"):
        kind = (
            E.PartyKind.PERSON
            if str(owner.get("kind", "organization")).lower() == "person"
            else E.PartyKind.ORGANIZATION
        )
        party = Party(
            id=make_id("party", str(owner["name"])),
            kind=kind,
            name=str(owner["name"]),
            urls=[str(owner["url"])] if owner.get("url") else [],
        )
        parties.append(party)
        owner_ref = party.id
    framework = declaration.get("framework")
    fw_claim = None
    if isinstance(framework, dict) and framework.get("name"):
        fw_claim = Claim.declared(
            FrameworkRef(
                name=str(framework["name"]),
                version=str(framework.get("version")) if framework.get("version") else None,
            ),
            locator=f"{locator}#/framework" if locator else None,
        )
    agent = Agent(
        id=make_id("agent", name),
        name=name,
        version=version,
        role=E.AgentRole.ROOT,
        purpose=str(declaration["purpose"]) if declaration.get("purpose") else None,
        owner_ref=owner_ref,
        framework=fw_claim,
        provenance={"assurance": "declared", "method": "config", "locator": locator}
        if locator
        else {"assurance": "declared", "method": "heuristic", "locator": str(root)},
    )
    return agent, parties


def scan(
    root: Path,
    *,
    agent_name: str | None = None,
    kind: E.SnapshotKind = E.SnapshotKind.DECLARED,
    home: Path | None = None,
    deterministic: bool = False,
    nonce: bytes | None = None,
    now: datetime | None = None,
    include_text: bool = False,
    collectors: list[str] | None = None,
    budget_seconds: float = 20.0,
) -> ScanOutcome:
    """Collect declared facts from ``root`` and return a finalised document."""
    root = Path(root).resolve()
    now = now or (datetime(2000, 1, 1, tzinfo=UTC) if deterministic else datetime.now(UTC))
    declaration, decl_file = read_agent_declaration(root)
    agent, parties = root_agent_from(root, declaration, decl_file, agent_name=agent_name)
    ctx = CollectContext(
        root=root,
        agent_id=agent.id,
        home=home,
        now=now,
        deterministic=deterministic,
        include_text=include_text,
        budget_seconds=budget_seconds,
    )
    loaded = load_collectors(collectors) if collectors else load_collectors()
    results = run_collectors(ctx, loaded)

    buckets: dict[str, dict[str, Entity]] = {attr: {} for attr in COLLECTIONS}
    buckets["agents"][agent.id] = agent
    party_map: dict[str, Party] = {p.id: p for p in parties}
    edges: dict[tuple[str, str, str], Edge] = {}
    warnings: list[str] = []
    for res in results:
        warnings.extend(f"{res.collector.name}: {w}" for w in res.warnings)
        for ent in res.entities:
            attr = _collection_for(ent)
            if ent.id in buckets[attr] and buckets[attr][ent.id] != ent:
                warnings.append(
                    f"{res.collector.name}: duplicate entity {ent.id} with differing content; first wins"
                )
                continue
            buckets[attr][ent.id] = ent
        for p in res.parties:
            party_map.setdefault(p.id, p)
        for ev in res.evidence:
            buckets["evidence"].setdefault(ev.id, ev)
        for e in res.edges:
            edges.setdefault(e.key, e)

    known = {eid for b in buckets.values() for eid in b} | set(party_map)
    kept_edges = []
    for e in edges.values():
        if e.from_ref in known and e.to_ref in known:
            kept_edges.append(e)
        else:
            warnings.append(f"dropped dangling edge {e.type.value} {e.from_ref} -> {e.to_ref}")

    producer = Producer(
        version=__version__,
        collectors=[
            Collector(name=r.collector.name, version=r.collector.version, mode=E.CollectorMode.DECLARED)
            for r in results
        ],
    )
    coverage = merge_coverage(results, text_included=include_text)
    collections: dict[str, Any] = {
        attr: sorted(b.values(), key=lambda x: x.id) for attr, b in buckets.items()
    }
    collections["parties"] = sorted(party_map.values(), key=lambda p: p.id)
    redactions = [r for res in results for r in res.redactions]
    doc = new_document(
        subject=agent.id,
        producer=producer,
        kind=kind,
        produced_at=now,
        edges=sorted(kept_edges, key=lambda e: e.key),
        coverage=coverage,
        redactions=redactions,
        **collections,
    )
    bom = finalize(doc, nonce=nonce if nonce is not None else (bytes(32) if deterministic else None))
    return ScanOutcome(bom=bom, results=results, warnings=warnings)


__all__ = ["AGENT_DECLARATION_FILES", "ScanOutcome", "read_agent_declaration", "root_agent_from", "scan"]
