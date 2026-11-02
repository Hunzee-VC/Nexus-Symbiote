"""Invert the Symbiote CycloneDX projection (``spec/cyclonedx-mapping.md``) back into model entities.

:class:`Inverter` reads a CycloneDX-shaped document (components, services, metadata, dependencies,
declarations, vulnerabilities, formulation, citations) and fills a :class:`Draft`. Elements that carry
``agentbom:*`` properties are inverted exactly against the exporter's property grammar; elements without
them (a plain software SBOM, or whatever a dialect adapter left unclaimed) are mapped generically:
``machine-learning-model`` → :class:`Model`, ``data`` → :class:`DataSource`, ``services[]`` →
:class:`ToolServer`, everything else → :class:`SoftwareComponent` kept verbatim.

Nothing here fabricates assurance: a claim the document does not carry becomes an explicit ``unknown``
(I2), ``verified`` without a reconstructible constraint record becomes ``observed`` plus the recorded fact
``imported-verified-without-constraint`` (I3), and whatever the model cannot represent lands in the loss
report and in ``foreign`` passthrough — never silently.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from symbiote import __version__
from symbiote.export.cdx.emit import (
    _EDGE_PROP,
    _KIND_BY_DATA,
    _KIND_BY_SERVER,
    _LIFECYCLE_PHASE,
    _VEX_JUSTIFICATION,
    _VEX_STATE,
    EVIDENCE_AUTHOR,
    EVIDENCE_MEDIA_TYPE,
    EVIDENCE_NAME,
    EVIDENCE_REDACTION,
    EVIDENCE_URI,
    PRODUCER_REF,
    SOURCE_BOM_REF,
)
from symbiote.imp._common import (
    DOCUMENT_ELEMENT,
    ImportContext,
    PropertyBag,
    all_hashes_sha256,
    as_digest,
    assurance_from,
    claim_from,
    ensure_id,
    enum_or_none,
    hashes_sha256,
    is_url,
    parse_bool,
    parse_int,
    parse_json,
    parse_time,
    parse_tristate,
    properties_of,
    provenance_from,
    software_id,
    valid_entity_id,
)
from symbiote.model import enums as E
from symbiote.model.common import (
    Claim,
    Contact,
    DigestResult,
    EvidenceRef,
    ExternalRef,
    Party,
    ThreatRef,
    Validity,
)
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    A2ACard,
    A2ASkill,
    Agent,
    Authentication,
    AutonomyAssessment,
    AutonomyBasis,
    AutonomyEntry,
    Chunking,
    Collector,
    CollectorRun,
    Condition,
    Coverage,
    CredentialBinding,
    CredentialStorage,
    DataOrigin,
    DataSource,
    DelegationHop,
    Deployment,
    Derivation,
    DirManifest,
    EnforcementPoint,
    Evidence,
    Exclusion,
    Fingerprint,
    Flag,
    FrameworkRef,
    Grant,
    HostedIdentity,
    Identity,
    Instruction,
    Model,
    ModelCardFacts,
    ModelManifest,
    PackageRef,
    Policy,
    PolicyRef,
    PromptTemplate,
    PublisherFacts,
    Quarantine,
    RedactedEntity,
    Redaction,
    RegistryFacts,
    RegistryResolution,
    RequestedRef,
    ResolvedRef,
    Sanitizer,
    Scope,
    ScriptRef,
    Serialization,
    ServerInfo,
    SignatureFacts,
    Skill,
    SkillFrontmatter,
    SnapshotCommitment,
    SoftwareComponent,
    SourceRun,
    SurfaceCoverage,
    ToolAnnotations,
    ToolDefinition,
    ToolListMeta,
    ToolServer,
    TransparencyLog,
    TyposquatDistance,
    VcsSource,
    VexStatement,
    VexSubject,
    WeightsIdentity,
    Window,
)
from symbiote.model.ids import make_id, slugify
from symbiote.model.snapshot import ObservationWindow, Producer

# Inverse tables of the exporter's closed vocabularies (imported from the exporter so the two cannot drift).
_EDGE_BY_PROP: dict[str, E.EdgeType] = {name: et for et, name in _EDGE_PROP.items()}
_SERVER_BY_KIND: dict[str, E.ToolServerKind] = {name: k for k, name in _KIND_BY_SERVER.items()}
_DATA_BY_KIND: dict[str, E.DataSourceKind] = {
    name: k for k, name in _KIND_BY_DATA.items() if k is not E.DataSourceKind.TOOL_OUTPUT_CHANNEL
}
_KIND_BY_PHASE: dict[str, E.SnapshotKind] = {phase: k for k, phase in _LIFECYCLE_PHASE.items()}
_VEX_STATUS_BY_STATE: dict[str, str] = {state: status for status, state in _VEX_STATE.items()}
_VEX_JUSTIFICATION_BY_CDX: dict[str, str] = {}
for _ours, _cdx in _VEX_JUSTIFICATION.items():  # first (most specific) wins on the ambiguous ones
    _VEX_JUSTIFICATION_BY_CDX.setdefault(_cdx, _ours)
_FRAMEWORK_BY_SOURCE_NAME = {
    "MITRE ATLAS": "mitre-atlas",
    "OWASP Top 10 for Agentic Applications": "owasp-asi-2025",
    "OWASP Top 10 for LLM Applications": "owasp-llm-2025",
    "CWE": "cwe",
    "NIST AI RMF": "nist-ai-rmf",
}
_AGENT_KINDS = {
    "agent": E.AgentRole.ROOT,
    "sub-agent": E.AgentRole.SUB_AGENT,
    "external-agent": E.AgentRole.EXTERNAL_AGENT,
}
_SYNTHETIC_REF_COMMENTS = {"agentbom:source-locator", "agentbom-companion", "a2a-agent-card"}
_CLAIM_METHOD_BY_SOURCE = {
    "config": E.ClaimMethod.CONFIG,
    "manifest": E.ClaimMethod.MANIFEST,
    "live-query": E.ClaimMethod.LIVE_QUERY,
    "trace": E.ClaimMethod.TRACE,
}
_COLLECTOR_UID_RE = re.compile(r"^collector:([a-z0-9][a-z0-9._-]*)@([A-Za-z0-9._+-]+)$")
_COLLECTOR_REF_RE = re.compile(r"^(?:collector:)?([a-z0-9][a-z0-9._-]*)@([A-Za-z0-9._+-]+)$")
_COVERAGE_SOURCE_RE = re.compile(r"^(?P<source>[^@=]+)@(?P<locator>.*)=(?P<status>[a-z-]+)$")


def _index_of(name: str) -> int:
    """The trailing ``<i>`` of an indexed property name (``0`` when absent)."""
    tail = name.rsplit(":", 1)[-1]
    return int(tail) if tail.isdigit() else 0


# ------------------------------------------------------------------------------------------------ draft


@dataclass
class Draft:
    """Everything an importer has reconstructed, before the document is assembled and re-finalised."""

    subject: str | None = None
    kind: E.SnapshotKind | None = None
    serial: int = 1
    prev: str | None = None
    produced_at: datetime | None = None
    validity: Validity = field(default_factory=Validity)
    window: ObservationWindow | None = None
    deployment_ref: str | None = None
    producer: Producer | None = None
    collector_runs: list[CollectorRun] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    text_included: bool | None = None
    flags: list[Flag] = field(default_factory=list)
    redactions: list[Redaction] = field(default_factory=list)
    redacted: list[RedactedEntity] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    entities: dict[str, list[Any]] = field(
        default_factory=lambda: {
            "agents": [],
            "deployments": [],
            "tool_servers": [],
            "tools": [],
            "instructions": [],
            "prompts": [],
            "skills": [],
            "models": [],
            "data_sources": [],
            "identities": [],
            "credential_bindings": [],
            "grants": [],
            "approvals": [],
            "resolutions": [],
            "evidence": [],
            "evaluations": [],
            "vex": [],
            "trust_status": [],
            "parties": [],
            "policies": [],
            "software": [],
        }
    )
    #: bom-ref → entity id (ids are re-minted when a bom-ref is not a conformant entity id)
    id_map: dict[str, str] = field(default_factory=dict)
    serial_number: str | None = None
    doc_version: int | None = None

    _COLLECTION_OF: dict[type, str] = field(
        default_factory=lambda: {
            Agent: "agents",
            Deployment: "deployments",
            ToolServer: "tool_servers",
            ToolDefinition: "tools",
            Instruction: "instructions",
            PromptTemplate: "prompts",
            Skill: "skills",
            Model: "models",
            DataSource: "data_sources",
            Identity: "identities",
            CredentialBinding: "credential_bindings",
            Grant: "grants",
            RegistryResolution: "resolutions",
            Evidence: "evidence",
            VexStatement: "vex",
            Party: "parties",
            Policy: "policies",
            SoftwareComponent: "software",
        },
        repr=False,
    )

    def ids(self) -> set[str]:
        out = {e.id for coll in self.entities.values() for e in coll}
        out |= {r.id for r in self.redacted}
        return out

    def has(self, entity_id: str) -> bool:
        return entity_id in self.ids()

    def add(self, entity: Any, *, bom_ref: str | None = None) -> bool:
        """Add an entity unless its id is taken; returns whether it was added."""
        for cls, attr in self._COLLECTION_OF.items():
            if isinstance(entity, cls):
                if any(e.id == entity.id for e in self.entities[attr]) or any(
                    r.id == entity.id for r in self.redacted
                ):
                    return False
                self.entities[attr].append(entity)
                if bom_ref:
                    self.id_map[bom_ref] = entity.id
                return True
        raise TypeError(f"no collection for {type(entity).__name__}")

    def get(self, entity_id: str) -> Any | None:
        for coll in self.entities.values():
            for e in coll:
                if e.id == entity_id:
                    return e
        return None

    def replace(self, entity: Any) -> None:
        for coll in self.entities.values():
            for i, e in enumerate(coll):
                if e.id == entity.id:
                    coll[i] = entity
                    return

    def edge(self, edge_type: E.EdgeType, from_ref: str, to_ref: str, **extra: Any) -> None:
        key = (edge_type.value, from_ref, to_ref)
        if any(e.key == key for e in self.edges):
            return
        self.edges.append(Edge(type=edge_type, from_ref=from_ref, to_ref=to_ref, **extra))

    def map_ref(self, ref: str | None) -> str | None:
        if ref is None:
            return None
        return self.id_map.get(ref, ref)


# ------------------------------------------------------------------------------------------------ inverter


@dataclass
class _Citation:
    locator: str | None = None
    collector: str | None = None
    timestamp: datetime | None = None


@dataclass
class _PendingCredential:
    subject: str
    bag: PropertyBag
    identity_bag: PropertyBag | None
    index: int


class Inverter:
    """Map one CycloneDX-shaped document into a :class:`Draft` (see the module docstring)."""

    def __init__(
        self,
        doc: Mapping[str, Any],
        ctx: ImportContext,
        draft: Draft | None = None,
        *,
        claimed: set[str] | None = None,
        native: bool,
    ) -> None:
        self.doc = doc
        self.ctx = ctx
        self.draft = draft or Draft()
        self.claimed: set[str] = claimed or set()
        self.native = native
        self.components: list[Mapping[str, Any]] = [
            c for c in (doc.get("components") or []) if isinstance(c, Mapping)
        ]
        self.services: list[Mapping[str, Any]] = [
            s for s in (doc.get("services") or []) if isinstance(s, Mapping)
        ]
        self.by_ref: dict[str, Mapping[str, Any]] = {}
        for c in self.components:
            if c.get("bom-ref"):
                self.by_ref[str(c["bom-ref"])] = c
        for s in self.services:
            if s.get("bom-ref"):
                self.by_ref[str(s["bom-ref"])] = s
        self.citations: dict[str, _Citation] = {}
        self.collector_refs: dict[str, str] = {}
        self.pending_credentials: list[_PendingCredential] = []
        self.instruction_digests: dict[str, str] = {}
        self.endpoint_services: set[str] = set()
        self.package_components: set[str] = set()
        self.element_kind: dict[str, str] = {}
        self.redaction_classes: list[str] = []
        self.metadata_flags: dict[str, tuple[list[str], list[str]]] = {}
        self.skill_md_digests: dict[str, str] = {}
        #: entity id -> explicit ``agentbom:name`` / ``agentbom:description`` (applied after the main pass)
        self.explicit_text: dict[str, dict[str, str]] = {}

    # ---------------------------------------------------------------- orchestration

    def run(self, adapter: DialectAdapter | None = None) -> Draft:
        self.metadata()
        self.prepass()
        root = self.root_agent()
        if adapter is not None:
            self.claimed |= set(adapter.adapt(self.doc, self.ctx, self.draft, root))
            root = self.draft.get(root.id) or root
        order = sorted(
            (c for c in self.components if str(c.get("bom-ref", "")) not in self.claimed),
            key=self._component_order,
        )
        for comp in order:
            self.component(comp)
        for svc in self.services:
            self.service(svc)
        self.resolve_credentials()
        self.resolve_skill_links()
        self.apply_explicit_text()
        self.dependencies(root)
        self.claims_and_flags(root)
        self.evidence()
        self.vulnerabilities()
        if adapter is not None:
            adapter.post(self.doc, self.ctx, self.draft, root)
        self.prune_edges()
        return self.draft

    @staticmethod
    def _component_order(comp: Mapping[str, Any]) -> tuple[int, str]:
        kind = next(
            (
                str(p.get("value"))
                for p in comp.get("properties", []) or []
                if p.get("name") == "agentbom:kind"
            ),
            "",
        )
        rank = {"instruction": 0, "prompt-template": 0}.get(kind, 1)
        return rank, str(comp.get("bom-ref", ""))

    # ---------------------------------------------------------------- metadata

    def metadata(self) -> None:
        d, ctx = self.draft, self.ctx
        md = self.doc.get("metadata") or {}
        bag = PropertyBag(properties_of(md))
        d.serial_number = (
            self.doc.get("serialNumber") if isinstance(self.doc.get("serialNumber"), str) else None
        )
        d.doc_version = self.doc.get("version") if isinstance(self.doc.get("version"), int) else None
        d.produced_at = parse_time(md.get("timestamp"))
        # snapshot header
        kind_raw = bag.get("agentbom:snapshot:kind")
        kind = enum_or_none(E.SnapshotKind, kind_raw)
        for lc in md.get("lifecycles") or []:
            if not isinstance(lc, Mapping):
                continue
            name = str(lc.get("name", ""))
            if name.startswith("agentbom:snapshot:"):
                kind = enum_or_none(E.SnapshotKind, name.split(":", 2)[2]) or kind
            elif kind is None and lc.get("phase") in _KIND_BY_PHASE:
                kind = _KIND_BY_PHASE[str(lc["phase"])]
        d.kind = kind
        serial = parse_int(bag.get("agentbom:snapshot:serial"))
        d.serial = (
            serial
            if serial and serial >= 1
            else (d.doc_version if d.doc_version and d.doc_version >= 1 else 1)
        )
        prev = bag.get("agentbom:snapshot:prev")
        d.prev = as_digest(prev) if prev and prev != "none" else None
        d.validity = Validity(
            not_before=parse_time(bag.get("agentbom:snapshot:not-before")),
            not_after=parse_time(bag.get("agentbom:snapshot:not-after")),
        )
        start = parse_time(bag.get("agentbom:snapshot:observation-start"))
        end = parse_time(bag.get("agentbom:snapshot:observation-end"))
        if start and end and end >= start:
            d.window = ObservationWindow(start=start, end=end)
        # the previous commitment cannot be reused: the salted leaves are recomputed here
        for name in (
            "agentbom:snapshot:digest",
            "agentbom:merkle:root",
            "agentbom:merkle:leaf-count",
            "agentbom:merkle:algorithm",
            "agentbom:companion:ref",
            "agentbom:companion:digest",
            "agentbom:companion:schema",
        ):
            value = bag.get(name)
            if value is not None:
                ctx.foreign_property(DOCUMENT_ELEMENT, name, value)
        if bag.peek("agentbom:spec-version") is not None:
            bag.drop("agentbom:spec-version")
        bag.drop("agentbom:authorization-use")
        for raw in bag.get_all("agentbom:authz:grant-record"):
            record = parse_json(raw)
            try:
                grant = Grant.model_validate(record)
            except (ValueError, TypeError):
                ctx.foreign_property(DOCUMENT_ELEMENT, "agentbom:authz:grant-record", raw)
                ctx.lose(
                    "/grants",
                    E.LossReason.STRING_FLATTENED,
                    E.LossPreservedIn.COMPANION,
                    E.LossSeverity.SECURITY_RELEVANT,
                    field_name="grant-record",
                )
                continue
            gfacts: list[str] = []
            if grant.provenance.assurance is E.AssuranceLevel.VERIFIED and not any(
                e.verification is E.EvidenceVerification.VERIFIED_CONSTRAINED
                for e in grant.provenance.evidence
            ):
                level = assurance_from(
                    "verified", ctx, path=f"/grants/{grant.id}", entity=grant.id, facts=gfacts
                )
                grant = grant.replace(
                    provenance=grant.provenance.replace(assurance=level), tags=[*grant.tags, *gfacts]
                )
            d.add(grant)
        if any(n.startswith("agentbom:merkle:") or n == "agentbom:snapshot:digest" for n in bag.names()):
            ctx.lose("/merkle", E.LossReason.PRECISION_LOST, E.LossPreservedIn.COMPANION, field_name="root")
        # coverage
        surfaces: dict[E.Surface, SurfaceCoverage] = {}
        for surface in E.Surface:
            status = enum_or_none(E.CoverageStatus, bag.get(f"agentbom:coverage:{surface.value}"))
            if status is not None:
                surfaces[surface] = SurfaceCoverage(status=status)
        sources: list[SourceRun] = []
        for raw in bag.get_all("agentbom:coverage:source"):
            m = _COVERAGE_SOURCE_RE.match(raw)
            if not m:
                ctx.foreign_property(DOCUMENT_ELEMENT, "agentbom:coverage:source", raw)
                continue
            status = m.group("status")
            sources.append(
                SourceRun(
                    source=m.group("source"),
                    locator=None if m.group("locator") in ("", "-") else m.group("locator"),
                    ok=status == "ok",
                    error_class=None if status == "ok" else status,
                )
            )
        if sources:
            # the projection does not say which surface a source served; every source is attached to the
            # surfaces that were actually examined (the exporter flattens this, reported as collapsed)
            examined = [s for s, c in surfaces.items() if c.status is not E.CoverageStatus.NOT_ATTEMPTED]
            targets = examined or [E.Surface.TOOLS]
            for s in targets:
                cov = surfaces.get(s, SurfaceCoverage())
                surfaces[s] = cov.replace(sources=sources)
            if len(targets) > 1:
                ctx.lose(
                    "/coverage/surfaces/*/sources",
                    E.LossReason.CARDINALITY_COLLAPSED,
                    E.LossPreservedIn.PROPERTY,
                    field_name="sources",
                )
        ctx.lose("/coverage/surfaces/*/itemsSeen", E.LossReason.PRECISION_LOST, E.LossPreservedIn.DROPPED)
        window = None
        ws, we = (
            parse_time(bag.get("agentbom:coverage:window-start")),
            parse_time(bag.get("agentbom:coverage:window-end")),
        )
        if ws and we and we >= ws:
            window = Window(start=ws, end=we)
        exclusions = [Exclusion(pattern=p) for p in bag.get_all("agentbom:coverage:exclusion")]
        d.coverage = Coverage(surfaces=surfaces, exclusions=exclusions, window=window)
        # flags at document level are read together with declarations.claims (see claims_and_flags)
        self.metadata_flags = {
            name: (bag.get_all(name), bag.get_all(f"{name}:input"))
            for name in sorted(
                {n for n in bag.names() if n.startswith("agentbom:flag:") and not n.endswith(":input")}
            )
        }
        # redactions are recorded, never silent
        for red_class in bag.get_all("agentbom:redaction:applied"):
            self.redaction_classes.append(red_class)
        for publisher in bag.get_all("agentbom:trust:revoked-publisher"):
            ctx.foreign_property(DOCUMENT_ELEMENT, "agentbom:trust:revoked-publisher", publisher)
            ctx.lose(
                "/trustStatus",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.COMPANION,
                E.LossSeverity.SECURITY_RELEVANT,
                field_name="revoked-publisher",
            )
        for name in (
            "agentbom:loss:items",
            "agentbom:loss:security-relevant",
            "symbiote:level:claimed",
            "symbiote:level:validated",
            "symbiote:score",
        ):
            bag.drop(name)
        self.producer_and_collectors(md, bag)
        for name, value in bag.remaining():
            ctx.foreign_property(DOCUMENT_ELEMENT, name, value)
        if bag.remaining():
            ctx.lose("/metadata/properties", E.LossReason.FOREIGN_UNMAPPED, E.LossPreservedIn.COMPANION)

    def producer_and_collectors(self, md: Mapping[str, Any], bag: PropertyBag) -> None:
        """``metadata.tools`` → producer (native) or the generating tool as a collector (foreign)."""
        tools = md.get("tools")
        components: list[Mapping[str, Any]] = []
        if isinstance(tools, Mapping):
            components = [t for t in tools.get("components", []) or [] if isinstance(t, Mapping)]
        elif isinstance(tools, list):  # CycloneDX ≤ 1.4 shape still accepted by 1.5
            components = [t for t in tools if isinstance(t, Mapping)]
        producer: Producer | None = None
        collectors: list[Collector] = []
        for t in components:
            ref = str(t.get("bom-ref", ""))
            name = str(t.get("name") or t.get("vendor") or "tool")
            version = str(t.get("version") or "unknown")
            tbag = PropertyBag(properties_of(t))
            if ref == PRODUCER_REF or (self.native and name == "symbiote" and producer is None):
                producer = Producer(name=name, version=version, digest=hashes_sha256(t))
                continue
            mode = (
                enum_or_none(E.CollectorMode, tbag.get("symbiote:collector:mode")) or E.CollectorMode.DECLARED
            )
            collectors.append(Collector(name=slugify(name), version=version, mode=mode))
            self.collector_refs[ref or name] = f"collector:{slugify(name)}@{version}"
        statuses: dict[str, tuple[str | None, str | None]] = {}
        for n, v in bag.consume_prefix("symbiote:collector:"):
            parts = n.split(":")
            if len(parts) == 4:
                cname, what = parts[2], parts[3]
                cur = statuses.get(cname, (None, None))
                statuses[cname] = (
                    (v, cur[1]) if what == "version" else ((cur[0], v) if what == "status" else cur)
                )
        symbiote_version = bag.get("symbiote:version")
        if producer is None:
            producer = Producer(
                name="symbiote",
                version=symbiote_version if (self.native and symbiote_version) else __version__,
            )
        runs = self._formulation_runs()
        known_runs = {r.name for r in runs}
        for cname, (cver, cstatus) in sorted(statuses.items()):
            if cname not in known_runs:
                runs.append(
                    CollectorRun(
                        name=cname,
                        version=cver or next((c.version for c in collectors if c.name == cname), "unknown"),
                        status=enum_or_none(E.CollectorStatus, cstatus) or E.CollectorStatus.OK,
                    )
                )
                known_runs.add(cname)
        for c in collectors:
            if c.name not in known_runs:
                runs.append(CollectorRun(name=c.name, version=c.version, status=E.CollectorStatus.OK))
                known_runs.add(c.name)
        self.draft.producer = producer.replace(collectors=sorted(collectors, key=lambda c: c.name))
        self.draft.collector_runs = sorted(runs, key=lambda r: r.name)

    def _formulation_runs(self) -> list[CollectorRun]:
        runs: list[CollectorRun] = []
        for form in self.doc.get("formulation") or []:
            if not isinstance(form, Mapping):
                continue
            for wf in form.get("workflows") or []:
                if not isinstance(wf, Mapping):
                    continue
                for task in wf.get("tasks") or []:
                    if not isinstance(task, Mapping):
                        continue
                    m = _COLLECTOR_UID_RE.match(str(task.get("uid", "")))
                    if not m:
                        continue
                    tbag = PropertyBag(properties_of(task))
                    status = enum_or_none(E.CollectorStatus, tbag.get("agentbom:coverage:status"))
                    runs.append(
                        CollectorRun(
                            name=m.group(1),
                            version=m.group(2),
                            status=status or E.CollectorStatus.SKIPPED,
                            reason=tbag.get("agentbom:coverage:reason"),
                        )
                    )
        return runs

    # ---------------------------------------------------------------- pre-pass

    def prepass(self) -> None:
        """Index synthetic helper elements (packages, endpoints, citations) before the main pass."""
        for comp in self.components:
            ref = str(comp.get("bom-ref", ""))
            kind = PropertyBag(properties_of(comp)).peek("agentbom:kind")
            if kind == "mcp-package" and ref.endswith("/package"):
                self.package_components.add(ref)
        for svc in self.services:
            ref = str(svc.get("bom-ref", ""))
            bag = PropertyBag(properties_of(svc))
            if (
                ref.endswith("/endpoint")
                and ref.startswith("model:")
                and bag.peek("agentbom:model:endpoint-origin")
            ):
                self.endpoint_services.add(ref)
        for cit in self.doc.get("citations") or []:
            if not isinstance(cit, Mapping):
                continue
            target = None
            for pointer in cit.get("pointers") or []:
                if pointer == "/metadata/component":
                    comp = (self.doc.get("metadata") or {}).get("component") or {}
                    target = str(comp.get("bom-ref", "")) or None
                else:
                    m = re.match(r"^/(components|services)/(\d+)$", str(pointer))
                    if m:
                        seq = self.components if m.group(1) == "components" else self.services
                        idx = int(m.group(2))
                        if idx < len(seq):
                            target = str(seq[idx].get("bom-ref", "")) or None
            if target:
                attributed = str(cit.get("attributedTo", ""))
                self.citations[target] = _Citation(
                    locator=cit.get("note"),
                    collector=self.collector_refs.get(attributed),
                    timestamp=parse_time(cit.get("timestamp")),
                )

    # ---------------------------------------------------------------- common element handling

    def apply_explicit_text(self) -> None:
        """``agentbom:name`` / ``agentbom:description`` win over what the native fields inverted to."""
        for entity_id, fields in self.explicit_text.items():
            entity = self.draft.get(entity_id)
            if entity is not None:
                self.draft.replace(entity.replace(**fields))

    def list_claim(
        self, bag: PropertyBag, name: str, *, path: str, entity: str, facts: list[str]
    ) -> Claim[list[str]] | None:
        """Invert ``Props.list_claim()``; documents without the qualifiers keep the old "values or None"."""
        values = bag.get_all(name)
        assurance = bag.get(f"{name}:assurance")
        locator = bag.get(f"{name}:locator")
        unknown = bag.get(f"{name}:unknown-reason")
        if unknown is not None and not values:
            reason = enum_or_none(E.UnknownReason, unknown) or E.UnknownReason.NOT_COLLECTED
            return Claim.unknown(reason, locator=locator)
        if not values and assurance is None:
            return None
        level = assurance_from(assurance, self.ctx, path=f"{path}/{name}", entity=entity, facts=facts)
        return Claim(value=values, assurance=level, locator=locator)

    def json_prop(self, bag: PropertyBag, name: str, *, path: str, entity: str) -> Any:
        raw = bag.get(name)
        if raw is None:
            return None
        value = parse_json(raw)
        if value is None:
            self.ctx.lose(
                f"{path}/{name}",
                E.LossReason.STRING_FLATTENED,
                E.LossPreservedIn.DROPPED,
                entity=entity,
                field_name=name,
            )
        return value

    def _finish(self, bag: PropertyBag, entity_id: str, path: str, *, bom_ref: str) -> dict[str, Any]:
        """Consume the cross-cutting properties every element carries; return the common entity fields."""
        ctx = self.ctx
        facts: list[str] = []
        bag.drop("agentbom:kind")
        explicit = {
            field_name: value
            for field_name, value in (
                ("name", bag.get("agentbom:name")),
                ("description", bag.get("agentbom:description")),
            )
            if value is not None
        }
        if explicit:
            self.explicit_text[entity_id] = explicit
        prov = provenance_from(bag, ctx, path=path, entity=entity_id, facts=facts)
        cit = self.citations.get(bom_ref)
        if cit is not None and (prov.locator is None or prov.collector is None):
            prov = prov.replace(
                locator=prov.locator or cit.locator,
                collector=prov.collector or cit.collector,
                observed_at=prov.observed_at or (cit.timestamp if cit.collector else None),
            )
        self.authority(bag, entity_id, path, facts)
        for name, value in bag.consume_prefix("agentbom:edge:"):
            edge_type = _EDGE_BY_PROP.get(name[len("agentbom:edge:") :])
            if edge_type is None:
                ctx.foreign_property(entity_id, name, value)
                continue
            self.draft.edge(edge_type, entity_id, value)
        trust = bag.consume_prefix("agentbom:trust:")
        if trust:
            for name, value in trust:
                ctx.foreign_property(entity_id, name, value)
            ctx.lose(
                f"{path}/trust",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.PROPERTY,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=entity_id,
                field_name="trust_ref",
            )
        if bag.get("agentbom:merkle:leaf") is not None:
            ctx.lose("/merkle/leaves", E.LossReason.PRECISION_LOST, E.LossPreservedIn.DROPPED)
        for name, value in bag.consume_prefix("agentbom:redaction:applied"):
            facts.append(f"redaction:{value}")
            ctx.foreign_property(entity_id, name, value)
        dialect_hint = bag.get("agentbom:import:dialect")
        bag.drop("agentbom:import:source-digest")
        foreign: dict[str, str] = {}
        for name, value in bag.remaining():
            ctx.foreign_property(entity_id, name, value, dialect=dialect_hint or None)
            foreign.setdefault(name, ctx.sanitize(value, count=False))
        if foreign:
            ctx.lose(
                path,
                E.LossReason.FOREIGN_UNMAPPED,
                E.LossPreservedIn.PROPERTY,
                entity=entity_id,
                field_name="foreign",
            )
        if len(foreign) != len(bag.remaining()):
            ctx.lose(
                path,
                E.LossReason.CARDINALITY_COLLAPSED,
                E.LossPreservedIn.COMPANION,
                entity=entity_id,
                field_name="foreign",
            )
        return {"provenance": prov, "tags": sorted(set(facts)), "foreign": foreign}

    def authority(self, bag: PropertyBag, subject: str, path: str, facts: list[str]) -> None:
        """``agentbom:authz:<i>:*`` → grants; ``agentbom:credential|identity:<i>:*`` → bindings and identities."""
        ctx = self.ctx
        for i, g in bag.indexed("agentbom:authz").items():
            gid = ensure_id("grant", g.get("id"), subject, str(i))
            if self.draft.has(gid):
                for n in list(g.names()):
                    g.get(n)
                continue
            capability = enum_or_none(E.CapabilityClass, g.get("capability"))
            layer = enum_or_none(E.GrantLayer, g.get("layer"))
            if capability is None or layer is None:
                ctx.lose(
                    f"{path}/authz/{i}",
                    E.LossReason.ENUM_NARROWED,
                    E.LossPreservedIn.DROPPED,
                    E.LossSeverity.SECURITY_RELEVANT,
                    entity=gid,
                )
                for n, v in g.remaining():
                    ctx.foreign_property(subject, f"agentbom:authz:{i}:{n}", v)
                continue
            policy_digest = as_digest(g.get("policy-digest"))
            chain_raw = parse_json(g.get("delegation-chain:json"))
            chain: list[DelegationHop] = []
            if isinstance(chain_raw, list):
                for hop in chain_raw:
                    try:
                        chain.append(DelegationHop.model_validate(hop))
                    except ValueError:
                        ctx.lose(
                            f"/grants/{gid}/delegationChain",
                            E.LossReason.STRING_FLATTENED,
                            E.LossPreservedIn.DROPPED,
                            E.LossSeverity.SECURITY_RELEVANT,
                            entity=gid,
                        )
            gfacts: list[str] = []
            level = assurance_from(g.get("assurance"), ctx, path=f"/grants/{gid}", entity=gid, facts=gfacts)
            conditions = [Condition(kind=E.ConditionKind.OTHER, expr=c) for c in g.get_all("condition")]
            granter = g.get("granter")
            grant = Grant(
                id=gid,
                provenance={"assurance": level},
                tags=gfacts,
                layer=layer,
                subject_ref=subject,
                capability=capability,
                scope=Scope(
                    resources=g.get_all("scope:resource"),
                    egress=g.get_all("scope:egress"),
                    data_classes=g.get_all("scope:data-class"),
                ),
                granter_ref=granter if granter and valid_entity_id(granter) else None,
                delegation_chain=chain,
                conditions=conditions,
                approval_gate=enum_or_none(E.ApprovalGate, g.get("approval-gate")) or E.ApprovalGate.NONE,
                validity=Validity(
                    not_before=parse_time(g.get("not-before")), not_after=parse_time(g.get("not-after"))
                ),
                policy_ref=PolicyRef(bundle_digest=policy_digest) if policy_digest else None,
                enforcement_point=EnforcementPoint(
                    kind=enum_or_none(E.EnforcementPointKind, g.get("enforcement-point"))
                    or E.EnforcementPointKind.UNKNOWN,
                    attested=parse_bool(g.get("enforcement-attested")) or False,
                ),
                credential_binding_ref=g.get("credential-binding"),
            )
            g.drop("scope-digest")
            for n, v in g.remaining():
                ctx.foreign_property(gid, f"agentbom:authz:{i}:{n}", v)
            self.draft.add(grant)
        identities = bag.indexed("agentbom:identity", detach=True)
        for i, c in bag.indexed("agentbom:credential", detach=True).items():
            self.pending_credentials.append(
                _PendingCredential(subject=subject, bag=c, identity_bag=identities.pop(i, None), index=i)
            )
        for i, ib in identities.items():  # identity blocks without a credential block
            self._identity_from(ib, f"{path}/identity/{i}")

    def _identity_from(
        self, ib: PropertyBag, path: str, *, identity_id: str | None = None
    ) -> Identity | None:
        kind = enum_or_none(E.IdentityKind, ib.get("kind"))
        ref = ib.get("ref")
        block_id = ib.get("id")
        name = ib.get("name")
        if identity_id is None and block_id and block_id.startswith("ident:") and valid_entity_id(block_id):
            identity_id = block_id
        if kind is None or not ref:
            for n, v in ib.remaining():
                self.ctx.foreign_property(identity_id or DOCUMENT_ELEMENT, f"agentbom:identity:{n}", v)
            return None
        iid = ensure_id("ident", identity_id, ref)
        existing = self.draft.get(iid)
        ident = Identity(
            id=iid, name=name, identity_kind=kind, ref=ref, issuer=ib.get("issuer"), tenant=ib.get("tenant")
        )
        if existing is None:
            self.draft.add(ident)
        elif isinstance(existing, Identity) and name and not existing.name:
            self.draft.replace(existing.replace(name=name))
        return ident

    def resolve_credentials(self) -> None:
        """Credential blocks carry no id; the ``holdsCredential`` edges of the same subject do (sorted by id)."""
        by_subject: dict[str, list[_PendingCredential]] = {}
        for p in self.pending_credentials:
            by_subject.setdefault(p.subject, []).append(p)
        for subject, pendings in by_subject.items():
            pendings.sort(key=lambda p: p.index)
            targets = sorted(
                {
                    e.to_ref
                    for e in self.draft.edges
                    if e.type is E.EdgeType.HOLDS_CREDENTIAL and e.from_ref == subject
                }
            )
            matched = len(targets) == len(pendings)
            if not matched and pendings:
                self.ctx.lose(
                    f"/credentialBindings/{subject}",
                    E.LossReason.PRECISION_LOST,
                    E.LossPreservedIn.DROPPED,
                    E.LossSeverity.SECURITY_RELEVANT,
                    entity=subject,
                    field_name="id",
                )
            for n, p in enumerate(pendings):
                c = p.bag
                identity_ref = c.get("identity")
                ident = None
                if p.identity_bag is not None:
                    ident = self._identity_from(
                        p.identity_bag,
                        f"/credentialBindings/{subject}/identity/{p.index}",
                        identity_id=identity_ref,
                    )
                iid = ident.id if ident else ensure_id("ident", identity_ref, subject, str(p.index))
                if ident is None and not self.draft.has(iid):
                    self.ctx.lose(
                        f"/identities/{iid}",
                        E.LossReason.NO_NATIVE_CONSTRUCT,
                        E.LossPreservedIn.DROPPED,
                        E.LossSeverity.SECURITY_RELEVANT,
                        entity=iid,
                    )
                cred_id = (
                    targets[n]
                    if matched
                    else make_id("cred", subject.split(":", 1)[-1], iid.split(":", 1)[-1])
                )
                scopes = [
                    v
                    for _, v in sorted(
                        (
                            (int(n2.rsplit(":", 1)[-1]) if n2.rsplit(":", 1)[-1].isdigit() else 0, v)
                            for n2, v in c.consume_prefix("scope-granted:")
                        )
                    )
                ]
                binding = CredentialBinding(
                    id=ensure_id("cred", cred_id, subject, iid),
                    name=c.get("name"),
                    subject_ref=subject,
                    identity_ref=iid,
                    credential_kind=enum_or_none(E.CredentialKind, c.get("kind")) or E.CredentialKind.UNKNOWN,
                    lifetime=c.get("lifetime"),
                    scopes_granted=Claim(value=scopes) if scopes else None,
                    storage=CredentialStorage(
                        kind=enum_or_none(E.CredentialStorageKind, c.get("storage-kind"))
                        or E.CredentialStorageKind.UNKNOWN,
                        locator=c.get("storage-locator"),
                    ),
                )
                for n2, v in c.remaining():
                    self.ctx.foreign_property(binding.id, f"agentbom:credential:{p.index}:{n2}", v)
                self.draft.add(binding)
                self.draft.edge(E.EdgeType.HOLDS_CREDENTIAL, subject, binding.id)

    def _external_refs(
        self, obj: Mapping[str, Any], *, skip_types: set[str] | None = None
    ) -> list[ExternalRef]:
        refs = []
        for r in obj.get("externalReferences") or []:
            if not isinstance(r, Mapping) or not r.get("url"):
                continue
            if r.get("comment") in _SYNTHETIC_REF_COMMENTS:
                continue
            if skip_types and r.get("type") in skip_types:
                continue
            refs.append(
                ExternalRef(
                    type=str(r.get("type", "other")),
                    url=str(r["url"]),
                    digests=all_hashes_sha256(r),
                    comment=r.get("comment"),
                )
            )
        return refs

    def _name(
        self, comp: Mapping[str, Any], entity_id: str, *derived: str | None, slug_fallback: bool = True
    ) -> str | None:
        """Invert the exporter's ``name or <fallback>``: a name equal to the fallback was absent.

        The fallback is the full id for agents (``slug_fallback=False``) and the id slug (or the frontmatter
        name for skills) for every other element; instruction, prompt and tool names are never projected.
        """
        name = comp.get("name")
        if not isinstance(name, str) or not name:
            return None
        fallbacks = [entity_id, *[d for d in derived if d]]
        if slug_fallback:
            fallbacks.append(entity_id.split(":", 1)[-1])
        if name in fallbacks:
            return None
        return name

    def _party_from(self, obj: Mapping[str, Any] | None, ref_hint: str | None) -> str | None:
        """``supplier``/``manufacturer`` → a :class:`Party` (kind defaults to organization)."""
        if not isinstance(obj, Mapping) or not obj.get("name"):
            return ref_hint
        name = str(obj["name"])
        pid = ensure_id("party", ref_hint, name)
        if not self.draft.has(pid):
            contacts = [
                Contact(name=c.get("name"), email=c.get("email"))
                for c in obj.get("contact") or []
                if isinstance(c, Mapping)
            ]
            urls = obj.get("url") or []
            self.draft.add(
                Party(
                    id=pid,
                    party_kind=E.PartyKind.ORGANIZATION,
                    name=name,
                    urls=[str(u) for u in urls] if isinstance(urls, list) else [str(urls)],
                    contacts=contacts,
                )
            )
            self.ctx.lose(
                f"/parties/{pid}",
                E.LossReason.ENUM_NARROWED,
                E.LossPreservedIn.DROPPED,
                entity=pid,
                field_name="kind",
            )
        return pid

    # ---------------------------------------------------------------- agents

    def root_agent(self) -> Agent:
        md = self.doc.get("metadata") or {}
        comp = md.get("component") if isinstance(md.get("component"), Mapping) else {}
        agent = self.agent(comp or {}, root=True)
        self.draft.subject = agent.id
        return agent

    def agent(self, comp: Mapping[str, Any], *, root: bool) -> Agent:
        bag = PropertyBag(properties_of(comp))
        bom_ref = str(comp.get("bom-ref") or "")
        name_raw = str(comp.get("name") or bom_ref or "agent")
        aid = ensure_id("agent", bom_ref or None, name_raw, taken=None if root else self.draft.ids())
        if bom_ref and aid != bom_ref:
            self.ctx.lose(
                f"/agents/{aid}",
                E.LossReason.PRECISION_LOST,
                E.LossPreservedIn.COMPANION,
                entity=aid,
                field_name="id",
            )
        path = "/metadata/component" if root else f"/agents/{aid}"
        role = enum_or_none(E.AgentRole, bag.get("agentbom:agent:role"))
        if role is None:
            kind = bag.peek("agentbom:kind")
            role = _AGENT_KINDS.get(kind or "", E.AgentRole.ROOT if root else E.AgentRole.SUB_AGENT)
        facts: list[str] = []
        framework = None
        fw_name = bag.get("agentbom:agent:framework")
        if fw_name:
            framework = Claim(
                value=FrameworkRef(name=fw_name, version=bag.get("agentbom:agent:framework-version"))
            )
        owner_ref = self._party_from(comp.get("supplier"), bag.get("agentbom:agent:owner"))
        operator_ref = self._party_from(comp.get("manufacturer"), bag.get("agentbom:agent:operator"))
        automation = claim_from(
            bag,
            "agentbom:agent:automation-level",
            lambda v: enum_or_none(E.IsoAutomationLevel, v),
            self.ctx,
            path=path,
            entity=aid,
            facts=facts,
        )
        autonomy = []
        for _, ab in bag.indexed("agentbom:agent:autonomy").items():
            cap, mode = (
                enum_or_none(E.CapabilityClass, ab.get("capability")),
                enum_or_none(E.AutonomyMode, ab.get("mode")),
            )
            if cap and mode:
                autonomy.append(AutonomyEntry(capability=cap, mode=mode))
        assessment = self._autonomy_assessment(bag, aid, path, facts)
        policy_bundle = claim_from(
            bag,
            "agentbom:agent:policy-bundle-digest",
            as_digest,
            self.ctx,
            path=path,
            entity=aid,
            facts=facts,
        )
        identities = [i for i in bag.get_all("agentbom:identity:ref") if i.startswith("ident:")]
        card = None
        card_digest = as_digest(bag.get("agentbom:a2a:card-digest"))
        if card_digest:
            skill_ids = bag.get_all("agentbom:a2a:skill")
            skills = [
                A2ASkill(
                    id=sb.get("id") or "",
                    name=sb.get("name"),
                    tags=[v for _, v in sorted((_index_of(n), v) for n, v in sb.consume_prefix("tag:"))],
                )
                for sb in bag.indexed("agentbom:a2a:skill").values()
            ]
            skills = [sk for sk in skills if sk.id] or [A2ASkill(id=s) for s in skill_ids]
            card = A2ACard(
                url=bag.get("agentbom:a2a:card-url"),
                digest=card_digest,
                version=bag.get("agentbom:a2a:card-version"),
                protocol_versions=bag.get_all("agentbom:a2a:protocol-version"),
                skills=skills,
                security_schemes=bag.get_all("agentbom:a2a:security-scheme"),
                signature_status=bag.get("agentbom:a2a:signature-status") or "none",
            )
        else:
            bag.consume_prefix("agentbom:a2a:")
        digest = as_digest(bag.get("agentbom:agent:digest"))
        entrypoint = bag.get("agentbom:agent:entrypoint")
        parent = bag.get("agentbom:agent:parent")
        bag.consume_prefix("agentbom:deployment:")
        common = self._finish(bag, aid, path, bom_ref=bom_ref)
        common["tags"] = sorted(set(common["tags"]) | set(facts))
        agent = Agent(
            id=aid,
            name=self._name(comp, aid, slug_fallback=False),
            description=None,
            external_refs=self._external_refs(comp),
            version=str(comp.get("version") or "unknown"),
            digest=digest,
            role=role,
            purpose=comp.get("description") if isinstance(comp.get("description"), str) else None,
            framework=framework,
            owner_ref=owner_ref,
            operator_ref=operator_ref,
            automation_level=automation,
            autonomy_profile=autonomy,
            autonomy_assessment=assessment,
            identities=identities,
            entrypoint=entrypoint,
            parent_ref=parent if parent and parent.startswith("agent:") else None,
            a2a_card=card,
            policy_bundle=policy_bundle,
            **common,
        )
        if not comp.get("version"):
            self.ctx.lose(
                path, E.LossReason.PRECISION_LOST, E.LossPreservedIn.DROPPED, entity=aid, field_name="version"
            )
        self.draft.add(agent, bom_ref=bom_ref or None)
        self.element_kind[bom_ref] = "agent"
        return agent

    def _autonomy_assessment(
        self, bag: PropertyBag, aid: str, path: str, facts: list[str]
    ) -> AutonomyAssessment | None:
        """``agentbom:agent:autonomy-assessment:*`` → the evidence interval (``spec/shadowscan-mapping.md §3``)."""
        prefix = "agentbom:agent:autonomy-assessment:"
        if not any(n.startswith(prefix) for n in bag.names()):
            return None
        scale = bag.get(f"{prefix}scale")
        floor, ceiling = parse_int(bag.get(f"{prefix}floor")), parse_int(bag.get(f"{prefix}ceiling"))
        floor_level = enum_or_none(E.IsoAutomationLevel, bag.get(f"{prefix}floor-level"))
        ceiling_level = enum_or_none(E.IsoAutomationLevel, bag.get(f"{prefix}ceiling-level"))
        basis = []
        for raw in bag.get_all(f"{prefix}basis"):
            bound, sep, rest = raw.partition(":")
            rule, sep2, value = rest.partition("=")
            if sep and sep2:
                basis.append(AutonomyBasis(bound=bound, rule=rule, value=value))
        evidence = [
            EvidenceRef(digest=d) for d in (as_digest(v) for v in bag.get_all(f"{prefix}evidence")) if d
        ]
        level = assurance_from(
            bag.get(f"{prefix}assurance"),
            ctx=self.ctx,
            path=f"{path}/autonomyAssessment",
            entity=aid,
            facts=facts,
        )
        declared = parse_int(bag.get(f"{prefix}declared"))
        declared_source = bag.get(f"{prefix}declared-source")
        assessor = bag.get(f"{prefix}assessor")
        oversight = (
            enum_or_none(E.AutonomyOversight, bag.get(f"{prefix}oversight")) or E.AutonomyOversight.UNKNOWN
        )
        initiation = (
            enum_or_none(E.AutonomyInitiation, bag.get(f"{prefix}initiation")) or E.AutonomyInitiation.UNKNOWN
        )
        if scale is None or floor is None or ceiling is None or floor_level is None or ceiling_level is None:
            self.ctx.lose(
                f"{path}/autonomyAssessment",
                E.LossReason.PRECISION_LOST,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=aid,
                field_name="autonomy_assessment",
            )
            return None
        if level is E.AssuranceLevel.DECLARED and bag.peek(f"{prefix}assurance") is None:
            level = E.AssuranceLevel.OBSERVED  # the model's default for an assessment
        try:
            return AutonomyAssessment(
                scale=scale,
                floor=floor,
                ceiling=ceiling,
                floor_level=floor_level,
                ceiling_level=ceiling_level,
                oversight=oversight,
                initiation=initiation,
                basis=basis,
                declared=declared,
                declared_source=declared_source,
                assessor=assessor,
                assurance=level,
                evidence=evidence,
            )
        except ValueError:
            self.ctx.lose(
                f"{path}/autonomyAssessment",
                E.LossReason.PRECISION_LOST,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=aid,
                field_name="autonomy_assessment",
            )
            return None

    # ---------------------------------------------------------------- components

    def component(self, comp: Mapping[str, Any]) -> None:
        bom_ref = str(comp.get("bom-ref") or "")
        if bom_ref in self.claimed or bom_ref in self.package_components:
            return
        bag = PropertyBag(properties_of(comp))
        kind = bag.peek("agentbom:kind")
        ctype = str(comp.get("type", ""))
        if kind == "collector":
            return
        if self._is_redacted_placeholder(bag, comp):
            self.redacted_placeholder(comp, bag)
            return
        if kind in _AGENT_KINDS:
            self.agent(comp, root=False)
        elif kind == "tool":
            self.tool(comp, bag)
        elif kind == "instruction":
            self.instruction(comp, bag)
        elif kind == "prompt-template":
            self.prompt(comp, bag)
        elif kind == "skill":
            self.skill(comp, bag)
        elif kind == "model" or (kind is None and ctype == "machine-learning-model"):
            self.model(comp, bag)
        elif kind in _DATA_BY_KIND or (kind is None and ctype == "data"):
            self.data_source(comp, bag)
        elif kind == "policy-bundle":
            self.policy(comp, bag)
        else:
            self.software(comp, bag)

    @staticmethod
    def _is_redacted_placeholder(bag: PropertyBag, comp: Mapping[str, Any]) -> bool:
        if bag.peek("agentbom:redaction:applied") is None or bag.peek("agentbom:merkle:leaf") is None:
            return False
        others = {
            n
            for n in bag.names()
            if n not in ("agentbom:kind", "agentbom:redaction:applied", "agentbom:merkle:leaf")
        }
        return not others and not comp.get("hashes")

    def redacted_placeholder(self, comp: Mapping[str, Any], bag: PropertyBag) -> None:
        ref = str(comp.get("bom-ref") or comp.get("name") or "")
        leaf = as_digest(bag.get("agentbom:merkle:leaf"))
        if not ref or not leaf:
            return
        kind = bag.get("agentbom:kind") or ref.split(":", 1)[0]
        red_class = bag.get("agentbom:redaction:applied") or "unspecified"
        self.draft.redacted.append(
            RedactedEntity(id=ref, kind=kind, redaction_class=red_class, leaf_hash=leaf)
        )
        self.ctx.lose(f"/redacted/{ref}", E.LossReason.REDACTED, E.LossPreservedIn.COMPANION, entity=ref)

    def _digest_result(
        self, algorithm: str, value: str | None, status: str | None, reason: str | None
    ) -> DigestResult | None:
        st = enum_or_none(E.DigestStatus, status) if status else None
        d = as_digest(value)
        if st is E.DigestStatus.UNDIGESTABLE or (d is None and st is not None):
            return DigestResult(
                algorithm=algorithm,
                status=E.DigestStatus.UNDIGESTABLE,
                reason=reason or "undigestable (reason not carried by the source document)",
            )
        if d is None:
            return None
        return DigestResult(algorithm=algorithm, value=d)

    def tool(self, comp: Mapping[str, Any], bag: PropertyBag) -> None:
        bom_ref = str(comp.get("bom-ref") or "")
        server_ref = bag.get("agentbom:tool:server-ref") or (
            str(comp.get("group")) if comp.get("group") else None
        )
        server_ref = ensure_id("server", server_ref, "unknown")
        data = next((d for d in comp.get("data") or [] if isinstance(d, Mapping)), {})
        tool_name = str(data.get("name") or comp.get("name") or bom_ref.rsplit("/", 1)[-1] or "tool")
        tid = (
            bom_ref
            if bom_ref.startswith("tool:") and bom_ref.count("/") >= 1
            else f"tool:{server_ref.split(':', 1)[1]}/{tool_name}"
        )
        path = f"/tools/{tid}"
        payload: dict[str, Any] = {}
        attachment = (
            (data.get("contents") or {}).get("attachment")
            if isinstance(data.get("contents"), Mapping)
            else None
        )
        if isinstance(attachment, Mapping) and attachment.get("content"):
            try:
                raw = base64.b64decode(str(attachment["content"]), validate=True)
                decoded = json.loads(raw)
                if isinstance(decoded, dict):
                    payload = decoded
            except (ValueError, TypeError):
                self.ctx.lose(
                    f"{path}/inputSchema",
                    E.LossReason.LIBRARY_LIMITATION,
                    E.LossPreservedIn.DROPPED,
                    entity=tid,
                    field_name="input_schema",
                )
        input_schema = payload.get("inputSchema")
        if not isinstance(input_schema, dict):
            input_schema = {}
            self.ctx.lose(
                f"{path}/inputSchema",
                E.LossReason.REDACTED,
                E.LossPreservedIn.DROPPED,
                entity=tid,
                field_name="input_schema",
            )
        digest = self._digest_result(
            "tooldef/v1",
            bag.get("agentbom:tool:definition-digest") or hashes_sha256(comp),
            bag.get("agentbom:tool:definition-digest-status"),
            bag.get("agentbom:tool:definition-digest-reason"),
        ) or DigestResult(
            algorithm="tooldef/v1",
            status=E.DigestStatus.UNDIGESTABLE,
            reason="no definition digest in the source document",
        )
        full = self._digest_result("tooldef-full/v1", bag.get("agentbom:tool:full-digest"), None, None)
        annotations = None
        ann_vals = {
            k: bag.get(f"agentbom:tool:annotation:{k}")
            for k in ("read-only", "destructive", "idempotent", "open-world")
        }
        if any(v is not None for v in ann_vals.values()):
            annotations = Claim(
                value=ToolAnnotations(
                    read_only_hint=parse_bool(ann_vals["read-only"]),
                    destructive_hint=parse_bool(ann_vals["destructive"]),
                    idempotent_hint=parse_bool(ann_vals["idempotent"]),
                    open_world_hint=parse_bool(ann_vals["open-world"]),
                )
            )
        scopes = bag.get_all("agentbom:tool:required-scope")
        source = enum_or_none(E.ToolSource, bag.get("agentbom:tool:source"))
        if source is None:
            source = E.ToolSource.DECLARED_CONFIG
            self.ctx.lose(
                f"{path}/source",
                E.LossReason.ENUM_NARROWED,
                E.LossPreservedIn.DROPPED,
                entity=tid,
                field_name="source",
            )
        capabilities = [
            c
            for c in (enum_or_none(E.CapabilityClass, v) for v in bag.get_all("agentbom:tool:capability"))
            if c
        ]
        text_flags = [
            f for f in (enum_or_none(E.TextFlag, v) for v in bag.get_all("agentbom:tool:text-flag")) if f
        ]
        tool = ToolDefinition(
            id=tid,
            description=payload.get("description")
            if isinstance(payload.get("description"), str)
            else (comp.get("description") if isinstance(comp.get("description"), str) else None),
            external_refs=self._external_refs(comp),
            server_ref=server_ref,
            tool_name=tool_name,
            title=payload.get("title") if isinstance(payload.get("title"), str) else None,
            input_schema=input_schema,
            output_schema=payload.get("outputSchema")
            if isinstance(payload.get("outputSchema"), dict)
            else None,
            annotations=annotations,
            digest=digest,
            full_digest=full,
            description_digest=as_digest(bag.get("agentbom:tool:description-digest")),
            input_schema_digest=as_digest(bag.get("agentbom:tool:input-schema-digest")),
            source=source,
            side_effect_class=enum_or_none(E.SideEffectClass, bag.get("agentbom:tool:side-effect-class"))
            or E.SideEffectClass.UNKNOWN,
            capabilities=capabilities,
            required_scopes=Claim(value=scopes) if scopes else None,
            approval_gate=enum_or_none(E.ApprovalGate, bag.get("agentbom:tool:approval-gate"))
            or E.ApprovalGate.UNKNOWN,
            text_flags=text_flags,
            state=enum_or_none(E.ToolState, bag.get("agentbom:tool:state")) or E.ToolState.DECLARED,
            invocation_count=parse_int(bag.get("agentbom:tool:invocation-count")),
            first_seen=parse_time(bag.get("agentbom:tool:first-seen")),
            last_seen=parse_time(bag.get("agentbom:tool:last-seen")),
            **self._finish(bag, tid, path, bom_ref=bom_ref),
        )
        self.draft.add(tool, bom_ref=bom_ref or None)
        self.element_kind[bom_ref] = "tool"
        if payload:
            self.draft.text_included = True

    def instruction(self, comp: Mapping[str, Any], bag: PropertyBag) -> None:
        bom_ref = str(comp.get("bom-ref") or "")
        location = bag.get("agentbom:instruction:path")
        iid = ensure_id("instr", bom_ref or None, location or str(comp.get("name") or "instruction"))
        path = f"/instructions/{iid}"
        digest = as_digest(hashes_sha256(comp))
        if digest is None:
            self.ctx.lose(
                path,
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=iid,
                field_name="digest",
            )
            self.software(comp, bag)
            return
        facts: list[str] = []
        editors = self.list_claim(bag, "agentbom:instruction:editor", path=path, entity=iid, facts=facts)
        remote = self.list_claim(bag, "agentbom:instruction:loads-remote", path=path, entity=iid, facts=facts)
        frontmatter = self.json_prop(bag, "agentbom:instruction:frontmatter:json", path=path, entity=iid)
        source = None
        vcs = next(
            (
                r
                for r in comp.get("externalReferences") or []
                if isinstance(r, Mapping) and r.get("type") == "vcs"
            ),
            None,
        )
        if vcs:
            source = VcsSource(vcs_url=str(vcs.get("url")), revision=vcs.get("comment"))
        kind = (
            enum_or_none(E.InstructionKind, bag.get("agentbom:instruction:kind")) or E.InstructionKind.OTHER
        )
        media_type = bag.get("agentbom:instruction:media-type") or str(
            comp.get("mime-type") or "text/markdown"
        )
        instr = Instruction(
            id=iid,
            name=None,
            description=comp.get("description") if isinstance(comp.get("description"), str) else None,
            external_refs=self._external_refs(comp, skip_types={"vcs"} if vcs else None),
            instruction_kind=kind,
            path=None if is_url(location) else location,
            uri=location if is_url(location) else None,
            media_type=media_type,
            size=parse_int(bag.get("agentbom:instruction:size")) or 0,
            digest=digest,
            normalized_digest=as_digest(bag.get("agentbom:instruction:normalized-digest")),
            line_endings=enum_or_none(E.LineEndings, bag.get("agentbom:instruction:line-endings"))
            or E.LineEndings.LF,
            precedence=parse_int(bag.get("agentbom:instruction:precedence")) or 0,
            editors=editors,
            loads_remote=remote,
            contains_secret_like=parse_bool(bag.get("agentbom:instruction:secret-like-redacted")) or False,
            frontmatter=frontmatter if isinstance(frontmatter, dict) else None,
            source=source,
            **self._finish(bag, iid, path, bom_ref=bom_ref),
        )
        if facts:
            instr = instr.replace(tags=sorted(set(instr.tags) | set(facts)))
        self.draft.add(instr, bom_ref=bom_ref or None)
        self.instruction_digests[digest] = iid
        self.element_kind[bom_ref] = "instr"

    def prompt(self, comp: Mapping[str, Any], bag: PropertyBag) -> None:
        bom_ref = str(comp.get("bom-ref") or "")
        pid = ensure_id("prompt", bom_ref or None, str(comp.get("name") or "prompt"))
        path = f"/prompts/{pid}"
        template_digest = hashes_sha256(comp)
        if template_digest is None:
            self.ctx.lose(
                path,
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=pid,
                field_name="template_digest",
            )
            self.software(comp, bag)
            return
        digest = self._digest_result(
            "prompt/v1", bag.get("agentbom:prompt:digest"), None, None
        ) or DigestResult(
            algorithm="prompt/v1",
            status=E.DigestStatus.UNDIGESTABLE,
            reason="no prompt digest in the source document",
        )
        prompt_path = bag.get("agentbom:prompt:path")
        if prompt_path is None:
            self.ctx.lose(
                f"{path}/path",
                E.LossReason.PRECISION_LOST,
                E.LossPreservedIn.DROPPED,
                entity=pid,
                field_name="path",
            )
        variables = self.json_prop(bag, "agentbom:prompt:variables-schema:json", path=path, entity=pid)
        prompt = PromptTemplate(
            id=pid,
            name=None,
            external_refs=self._external_refs(comp),
            engine=enum_or_none(E.TemplateEngine, bag.get("agentbom:prompt:engine")) or E.TemplateEngine.NONE,
            role=enum_or_none(E.PromptRole, bag.get("agentbom:prompt:role")) or E.PromptRole.SYSTEM,
            digest=digest,
            template_digest=template_digest,
            variables_schema=variables if isinstance(variables, dict) else None,
            variables_schema_digest=as_digest(bag.get("agentbom:prompt:variables-schema-digest")),
            path=prompt_path,
            risk_class=enum_or_none(E.TemplateRiskClass, bag.get("agentbom:prompt:risk-class"))
            or E.TemplateRiskClass.NONE,
            **self._finish(bag, pid, path, bom_ref=bom_ref),
        )
        self.draft.add(prompt, bom_ref=bom_ref or None)
        self.element_kind[bom_ref] = "prompt"

    def skill(self, comp: Mapping[str, Any], bag: PropertyBag) -> None:
        bom_ref = str(comp.get("bom-ref") or "")
        skill_name = bag.get("agentbom:skill:name") or (str(comp.get("name")) if comp.get("name") else None)
        sid = ensure_id("skill", bom_ref or None, skill_name or "skill")
        path = f"/skills/{sid}"
        digest = as_digest(bag.get("agentbom:skill:manifest-root")) or hashes_sha256(comp)
        if digest is None:
            self.ctx.lose(
                path,
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=sid,
                field_name="digest",
            )
            self.software(comp, bag)
            return
        scripts = []
        for nested in comp.get("components") or []:
            if not isinstance(nested, Mapping):
                continue
            nbag = PropertyBag(properties_of(nested))
            sdigest = hashes_sha256(nested)
            if nbag.peek("agentbom:kind") == "skill-script" and sdigest:
                scripts.append(
                    ScriptRef(
                        path=str(nested.get("name") or nested.get("bom-ref")),
                        digest=sdigest,
                        interpreter=nbag.get("agentbom:skill:interpreter"),
                    )
                )
            else:
                self.ctx.lose(
                    f"{path}/components", E.LossReason.FOREIGN_UNMAPPED, E.LossPreservedIn.DROPPED, entity=sid
                )
        version = comp.get("version")
        md_digest = as_digest(bag.get("agentbom:skill:skill-md-digest"))
        if md_digest:
            self.skill_md_digests[sid] = md_digest
        bag.drop("agentbom:skill:file-count")
        bag.drop("agentbom:skill:script-count")
        skill_path = bag.get("agentbom:skill:path")
        manifest = None
        manifest_raw = self.json_prop(bag, "agentbom:skill:manifest:json", path=path, entity=sid)
        if isinstance(manifest_raw, dict):
            try:
                manifest = DirManifest.model_validate(manifest_raw)
            except ValueError:
                manifest = None
        metadata = self.json_prop(bag, "agentbom:skill:metadata:json", path=path, entity=sid)
        has_servers = any(n.startswith("agentbom:skill:referenced-server:") for n in bag.names())
        servers = [
            v
            for _, v in sorted(
                (_index_of(n), v) for n, v in bag.consume_prefix("agentbom:skill:referenced-server:")
            )
        ]
        for lost, present in (
            ("path", skill_path is not None),
            ("manifest", manifest is not None),
            ("referenced_servers", has_servers or manifest is not None),
        ):
            if present:
                continue
            self.ctx.lose(
                f"{path}/{lost}",
                E.LossReason.PRECISION_LOST,
                E.LossPreservedIn.DROPPED,
                entity=sid,
                field_name=lost,
            )
        skill = Skill(
            id=sid,
            name=self._name(comp, sid, skill_name),
            external_refs=self._external_refs(comp),
            path=skill_path or skill_name or sid.split(":", 1)[1],
            digest=digest,
            manifest=manifest or DirManifest(resources=[], root=digest),
            frontmatter=SkillFrontmatter(
                name=skill_name,
                description=comp.get("description") if isinstance(comp.get("description"), str) else None,
                license=bag.get("agentbom:skill:license"),
                compatibility=bag.get("agentbom:skill:compatibility"),
                allowed_tools=bag.get_all("agentbom:skill:allowed-tool"),
                metadata=metadata
                if isinstance(metadata, dict)
                else ({"version": version} if version else {}),
            ),
            referenced_servers=servers,
            scripts=scripts,
            has_scripts=parse_bool(bag.get("agentbom:skill:has-scripts"))
            if bag.peek("agentbom:skill:has-scripts") is not None
            else bool(scripts),
            name_matches_directory=parse_bool(bag.get("agentbom:skill:name-matches-directory"))
            if bag.peek("agentbom:skill:name-matches-directory") is not None
            else True,
            **self._finish(bag, sid, path, bom_ref=bom_ref),
        )
        self.draft.add(skill, bom_ref=bom_ref or None)
        self.element_kind[bom_ref] = "skill"

    def resolve_skill_links(self) -> None:
        for sid, md_digest in self.skill_md_digests.items():
            iid = self.instruction_digests.get(md_digest)
            skill = self.draft.get(sid)
            if iid and isinstance(skill, Skill):
                self.draft.replace(skill.replace(skill_md_ref=iid))

    def model(self, comp: Mapping[str, Any], bag: PropertyBag) -> None:
        bom_ref = str(comp.get("bom-ref") or "")
        mid = ensure_id("model", bom_ref or None, str(comp.get("name") or comp.get("purl") or "model"))
        path = f"/models/{mid}"
        facts: list[str] = []
        kind = enum_or_none(E.ModelKind, bag.get("agentbom:model:kind"))
        hashes = hashes_sha256(comp)
        supplier = comp.get("supplier") if isinstance(comp.get("supplier"), Mapping) else None
        if kind is None:
            kind = (
                E.ModelKind.HOSTED
                if (comp.get("isExternal") or (hashes is None and comp.get("purl") is None))
                else E.ModelKind.WEIGHTS
            )
        hosted = None
        provider = bag.get("agentbom:model:provider") or (
            str(supplier.get("name")) if supplier and supplier.get("name") else None
        )
        requested = bag.get("agentbom:model:requested-ref")
        if requested is not None or kind is E.ModelKind.HOSTED:
            if requested is None and bag.peek("agentbom:model:requested-ref:unknown-reason") is not None:
                hosted = claim_from(
                    bag,
                    "agentbom:model:requested-ref",
                    lambda v: v,
                    self.ctx,
                    path=path,
                    entity=mid,
                    facts=facts,
                    required=True,
                )
            else:
                resolved = claim_from(
                    bag,
                    "agentbom:model:resolved-ref",
                    lambda v: v,
                    self.ctx,
                    path=path,
                    entity=mid,
                    facts=facts,
                ) or (
                    Claim(value=str(comp["version"]))
                    if comp.get("version")
                    else Claim.unknown(E.UnknownReason.NOT_COLLECTED)
                )
                fp = None
                fp_digest = as_digest(bag.get("agentbom:model:fingerprint:digest"))
                fp_method = bag.get("agentbom:model:fingerprint:method")
                if fp_digest and fp_method:
                    fp = Fingerprint(
                        method=fp_method,
                        digest=fp_digest,
                        sampled_at=parse_time(bag.get("agentbom:model:fingerprint:sampled-at")),
                        expires=parse_time(bag.get("agentbom:model:fingerprint:expires")),
                    )
                hosted = Claim(
                    value=HostedIdentity(
                        provider=provider or "unknown",
                        endpoint_origin=bag.get("agentbom:model:endpoint-origin"),
                        requested_ref=requested or str(comp.get("name") or mid),
                        resolved_ref=resolved,
                        alias_pinning=enum_or_none(E.AliasPinning, bag.get("agentbom:model:alias-pinning"))
                        or E.AliasPinning.UNKNOWN,
                        fingerprint=fp,
                    )
                )
        weights = None
        manifest_root = as_digest(bag.get("agentbom:model:manifest-root")) or hashes
        if manifest_root:
            formats = [
                f
                for f in (
                    enum_or_none(E.SerializationFormat, v)
                    for v in bag.get_all("agentbom:model:serialization:format")
                )
                if f
            ]
            weights = Claim(
                value=WeightsIdentity(
                    purl=str(comp["purl"]) if comp.get("purl") else None,
                    manifest_root=manifest_root,
                    manifest_ref=bag.get("agentbom:model:manifest-ref"),
                    file_count=parse_int(bag.get("agentbom:model:manifest-items")) or 0,
                    formats=formats,
                ),
                assurance=assurance_from(
                    bag.get("agentbom:model:manifest-root:assurance"),
                    self.ctx,
                    path=path,
                    entity=mid,
                    facts=facts,
                ),
                locator=bag.get("agentbom:model:manifest-root:locator"),
            )
        elif bag.peek("agentbom:model:manifest-root:unknown-reason") is not None:
            weights = claim_from(
                bag,
                "agentbom:model:manifest-root",
                as_digest,
                self.ctx,
                path=path,
                entity=mid,
                facts=facts,
                required=True,
            )
        bag.drop("agentbom:model:manifest-format")
        if (
            hosted is None
            and weights is None
            and kind in (E.ModelKind.WEIGHTS, E.ModelKind.ADAPTER, E.ModelKind.EMBEDDING, E.ModelKind.HOSTED)
        ):
            unknown: Claim[Any] = Claim.unknown(E.UnknownReason.NOT_COLLECTED)
            if kind is E.ModelKind.HOSTED:
                hosted = unknown
            else:
                weights = unknown
        serialization = None
        risk = bag.get("agentbom:model:serialization:risk")
        trc, cte = (
            bag.get("agentbom:model:trust-remote-code"),
            bag.get("agentbom:model:chat-template-executable"),
        )
        scanner = bag.get("agentbom:model:scanner")
        scanner_digest = as_digest(bag.get("agentbom:model:scanner-report-digest"))
        if any(v is not None for v in (risk, trc, cte, scanner, scanner_digest)):
            sname, _, sver = (scanner or "").partition("@")
            serialization = Claim(
                value=Serialization(
                    formats=weights.value.formats if weights and weights.value else [],
                    risk_class=enum_or_none(E.SerializationRisk, risk) or E.SerializationRisk.NONE,
                    trust_remote_code=parse_tristate(trc) or E.TriState.UNKNOWN,
                    chat_template_executable=parse_tristate(cte) or E.TriState.UNKNOWN,
                    scanner_name=sname or None,
                    scanner_version=sver or None,
                    scanner_report_digest=scanner_digest,
                )
            )
        derivations = []
        for _, db in bag.indexed("agentbom:model:derivation").items():
            dkind = enum_or_none(E.DerivationKind, db.get("kind"))
            parent = db.get("parent")
            if dkind and parent:
                params = parse_json(db.get("parameters:json"))
                derivations.append(
                    Derivation(
                        kind=dkind,
                        parent=parent,
                        parameters=params if isinstance(params, dict) else {},
                        parameters_digest=as_digest(db.get("parameters-digest")),
                    )
                )
        if not derivations:
            for anc in (
                ((comp.get("pedigree") or {}).get("ancestors") or [])
                if isinstance(comp.get("pedigree"), Mapping)
                else []
            ):
                if isinstance(anc, Mapping) and anc.get("name"):
                    dk = (
                        enum_or_none(
                            E.DerivationKind, PropertyBag(properties_of(anc)).get("agentbom:derivation:kind")
                        )
                        or E.DerivationKind.FINE_TUNE_OF
                    )
                    derivations.append(Derivation(kind=dk, parent=str(anc["name"])))
        signature = self.signature_facts(bag, "agentbom:model:signature", mid, facts)
        card = None
        mc = comp.get("modelCard") if isinstance(comp.get("modelCard"), Mapping) else None
        if mc:
            params = mc.get("modelParameters") if isinstance(mc.get("modelParameters"), Mapping) else {}
            cons = mc.get("considerations") if isinstance(mc.get("considerations"), Mapping) else {}
            approach = (
                params.get("approach", {}).get("type")
                if isinstance(params.get("approach"), Mapping)
                else None
            )
            card = ModelCardFacts(
                task=params.get("task"),
                architecture=params.get("architectureFamily") or params.get("modelArchitecture"),
                approach=approach,
                limitations=(cons.get("technicalLimitations") or [None])[0]
                if isinstance(cons.get("technicalLimitations"), list)
                else None,
                users=(cons.get("users") or [None])[0] if isinstance(cons.get("users"), list) else None,
                use_cases=(cons.get("useCases") or [None])[0]
                if isinstance(cons.get("useCases"), list)
                else None,
            )
            if mc.get("properties"):
                self.ctx.lose(
                    f"{path}/modelCard/properties",
                    E.LossReason.FOREIGN_UNMAPPED,
                    E.LossPreservedIn.DROPPED,
                    entity=mid,
                )
        chat_digest = as_digest(bag.get("agentbom:model:chat-template-digest"))
        model_manifest = None
        manifest_raw = self.json_prop(bag, "agentbom:model:manifest:json", path=path, entity=mid)
        if isinstance(manifest_raw, dict):
            try:
                model_manifest = ModelManifest.model_validate(manifest_raw)
            except ValueError:
                self.ctx.lose(
                    f"{path}/manifest",
                    E.LossReason.STRING_FLATTENED,
                    E.LossPreservedIn.DROPPED,
                    entity=mid,
                    field_name="manifest",
                )
        artifact = None
        artifact_raw = parse_json(bag.get("agentbom:model:artifact-digest-claim"))
        if isinstance(artifact_raw, dict):
            try:
                artifact = Claim[str].model_validate(artifact_raw)
            except ValueError:
                self.ctx.lose(
                    f"{path}/artifactDigest",
                    E.LossReason.STRING_FLATTENED,
                    E.LossPreservedIn.DROPPED,
                    E.LossSeverity.SECURITY_RELEVANT,
                    entity=mid,
                    field_name="artifact_digest",
                )
            if artifact is not None and artifact.assurance is E.AssuranceLevel.VERIFIED:
                artifact = artifact.replace(
                    assurance=assurance_from(
                        "verified", self.ctx, path=f"{path}/artifactDigest", entity=mid, facts=facts
                    )
                )
        model = Model(
            id=mid,
            name=self._name(comp, mid),
            description=comp.get("description") if isinstance(comp.get("description"), str) else None,
            external_refs=self._external_refs(comp),
            model_kind=kind,
            artifact_digest=artifact,
            weights=weights,
            hosted=hosted,
            manifest=model_manifest,
            tensor_manifest_root=as_digest(bag.get("agentbom:model:tensor-manifest-root")),
            serialization=serialization,
            derivations=derivations,
            signature=signature,
            chat_template_ref=self.instruction_digests.get(chat_digest or ""),
            generation_config_digest=as_digest(bag.get("agentbom:model:generation-config-digest")),
            card=card,
            **self._finish(bag, mid, path, bom_ref=bom_ref),
        )
        model = model.replace(tags=sorted(set(model.tags) | set(facts)))
        self.draft.add(model, bom_ref=bom_ref or None)
        self.element_kind[bom_ref] = "model"
        if f"{bom_ref}/endpoint" in self.endpoint_services:
            self.claimed.add(f"{bom_ref}/endpoint")

    def signature_facts(
        self, bag: PropertyBag, prefix: str, entity: str, facts: list[str]
    ) -> SignatureFacts | None:
        raw = {
            k: bag.get(f"{prefix}:{k}")
            for k in (
                "status",
                "outcome",
                "reason",
                "identity",
                "issuer",
                "log-entry",
                "subject-name-mismatch",
                "bundle-digest",
            )
        }
        if all(v is None for v in raw.values()):
            return None
        status = enum_or_none(E.SignatureStatus, raw["status"]) or E.SignatureStatus.CLAIMED
        outcome = enum_or_none(E.SignatureOutcome, raw["outcome"]) or E.SignatureOutcome.NONE
        if status is E.SignatureStatus.VERIFIED and (
            outcome is not E.SignatureOutcome.VERIFIED or not raw["identity"]
        ):
            status = (
                E.SignatureStatus.CLAIMED
            )  # I3: never launder an unconstrained or identity-less signature
            if "imported-verified-without-constraint" not in facts:
                facts.append("imported-verified-without-constraint")
            self.ctx.lose(
                f"/models/{entity}/signature",
                E.LossReason.ENUM_NARROWED,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=entity,
                field_name="signature.status",
            )
        return SignatureFacts(
            status=status,
            outcome=outcome,
            reason=raw["reason"],
            identity=raw["identity"],
            issuer=raw["issuer"],
            log_entry=raw["log-entry"],
            subject_name_mismatch=parse_bool(raw["subject-name-mismatch"]),
            bundle_digest=as_digest(raw["bundle-digest"]),
        )

    def data_source(self, comp: Mapping[str, Any], bag: PropertyBag) -> None:
        bom_ref = str(comp.get("bom-ref") or "")
        did = ensure_id("data", bom_ref or None, str(comp.get("name") or "data"))
        path = f"/dataSources/{did}"
        facts: list[str] = []
        entry = next((d for d in comp.get("data") or [] if isinstance(d, Mapping)), {})
        kind = enum_or_none(E.DataSourceKind, bag.get("agentbom:data:kind")) or _DATA_BY_KIND.get(
            bag.peek("agentbom:kind") or "", E.DataSourceKind.DATASET
        )
        classification = (
            enum_or_none(E.Classification, bag.get("agentbom:data:classification"))
            or enum_or_none(E.Classification, entry.get("classification"))
            or E.Classification.UNKNOWN
        )
        instruction_bearing = claim_from(
            bag,
            "agentbom:data:instruction-bearing",
            parse_bool,
            self.ctx,
            path=path,
            entity=did,
            facts=facts,
            required=True,
        )
        assert instruction_bearing is not None
        snapshot = None
        commitment = as_digest(bag.get("agentbom:data:snapshot:commitment")) or hashes_sha256(comp)
        if commitment:
            snapshot = Claim(
                value=SnapshotCommitment(
                    commitment=commitment,
                    method=enum_or_none(E.SnapshotMethod, bag.get("agentbom:data:snapshot:method"))
                    or E.SnapshotMethod.HASH,
                    at=parse_time(bag.get("agentbom:data:snapshot:at")),
                )
            )
        sanitization = [
            Sanitizer(name=sb.get("name") or "sanitizer", digest=as_digest(sb.get("digest")))
            for _, sb in bag.indexed("agentbom:data:sanitization").items()
        ]
        sources = [
            DataOrigin(
                uri=sb.get("uri") or "",
                digest=as_digest(sb.get("digest")),
                fetched_at=parse_time(sb.get("fetched-at")),
                license=sb.get("license"),
                consent_status=sb.get("consent-status"),
            )
            for _, sb in bag.indexed("agentbom:data:source").items()
            if sb.peek("uri")
        ]
        chunk_raw = parse_json(bag.get("agentbom:data:chunking:json"))
        chunking = Chunking.model_validate(chunk_raw) if isinstance(chunk_raw, dict) else None
        writers_vals = bag.get_all("agentbom:data:writer")
        writers = (
            Claim(value=writers_vals)
            if writers_vals
            else claim_from(
                bag, "agentbom:data:writer", lambda v: [v], self.ctx, path=path, entity=did, facts=facts
            )
        )
        quarantine = None
        if bag.peek("agentbom:data:quarantine-status") is not None:
            quarantine = Quarantine(
                status=str(bag.get("agentbom:data:quarantine-status")),
                since=parse_time(bag.get("agentbom:data:quarantine-since")),
            )
        poison = as_digest(bag.get("agentbom:data:poison-scan-digest"))
        contents = entry.get("contents") if isinstance(entry.get("contents"), Mapping) else {}
        ds = DataSource(
            id=did,
            name=self._name(comp, did),
            description=comp.get("description") if isinstance(comp.get("description"), str) else None,
            external_refs=self._external_refs(comp),
            data_kind=kind,
            location=str(contents.get("url")) if contents.get("url") else None,
            classification=classification,
            data_classes=bag.get_all("agentbom:data:data-class"),
            trust_tier=enum_or_none(E.TrustTier, bag.get("agentbom:data:trust-tier")) or E.TrustTier.UNKNOWN,
            instruction_bearing=instruction_bearing,
            sanitization=sanitization,
            snapshot=snapshot,
            live=parse_bool(bag.get("agentbom:data:live")) or False,
            refresh_policy=bag.get("agentbom:data:refresh-policy"),
            embedding_model_ref=bag.get("agentbom:data:embedding-model"),
            chunking=chunking,
            sources=sources,
            acl_mode=enum_or_none(E.AclMode, bag.get("agentbom:data:acl-mode")) or E.AclMode.UNKNOWN,
            writers=writers,
            tenant_isolation=enum_or_none(E.TenantIsolation, bag.get("agentbom:data:tenant-isolation"))
            or E.TenantIsolation.UNKNOWN,
            retention=bag.get("agentbom:data:retention"),
            quarantine=quarantine,
            invalidation_dependents=[
                v for v in bag.get_all("agentbom:data:invalidation-dependent") if ":" in v
            ],
            poison_scan=EvidenceRef(digest=poison) if poison else None,
            **self._finish(bag, did, path, bom_ref=bom_ref),
        )
        ds = ds.replace(tags=sorted(set(ds.tags) | set(facts)))
        self.draft.add(ds, bom_ref=bom_ref or None)
        self.element_kind[bom_ref] = "data"

    def policy(self, comp: Mapping[str, Any], bag: PropertyBag) -> None:
        bom_ref = str(comp.get("bom-ref") or "")
        pid = ensure_id("policy", bom_ref or None, str(comp.get("name") or "policy"))
        path = f"/policies/{pid}"
        digest = as_digest(bag.get("agentbom:policy:bundle-digest")) or hashes_sha256(comp)
        if digest is None:
            self.ctx.lose(
                path,
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=pid,
                field_name="bundle_digest",
            )
            self.software(comp, bag)
            return
        policy = Policy(
            id=pid,
            name=self._name(comp, pid),
            description=comp.get("description") if isinstance(comp.get("description"), str) else None,
            external_refs=self._external_refs(comp),
            policy_kind=enum_or_none(E.PolicyKind, bag.get("agentbom:policy:kind"))
            or E.PolicyKind.AUTHORIZATION_POLICY,
            engine=bag.get("agentbom:policy:engine"),
            bundle_digest=digest,
            enforcement_point=EnforcementPoint(
                kind=enum_or_none(E.EnforcementPointKind, bag.get("agentbom:policy:enforcement-point"))
                or E.EnforcementPointKind.UNKNOWN
            ),
            **self._finish(bag, pid, path, bom_ref=bom_ref),
        )
        self.draft.add(policy, bom_ref=bom_ref or None)
        self.element_kind[bom_ref] = "policy"

    def software(self, comp: Mapping[str, Any], bag: PropertyBag) -> None:
        """A software-layer component is kept verbatim (``spec/agentbom-profile.md §3.15``)."""
        bom_ref = str(comp.get("bom-ref") or "")
        purl = str(comp["purl"]) if comp.get("purl") else None
        name = str(comp["name"]) if comp.get("name") else None
        version = str(comp["version"]) if comp.get("version") else None
        sid = software_id(purl, name, version, bom_ref or None)
        taken = self.draft.ids()
        if sid in taken:
            sid = make_id(
                "sw", sid.split(":", 1)[1], collision_seed=bom_ref or json.dumps(comp, sort_keys=True)
            )
        verbatim = {k: v for k, v in comp.items() if k != "bom-ref"}
        source_ref = bag.get(SOURCE_BOM_REF)
        if source_ref is not None:
            props = [
                p
                for p in verbatim.get("properties") or []
                if not (isinstance(p, Mapping) and p.get("name") == SOURCE_BOM_REF)
            ]
            verbatim.pop("properties", None)
            if props:
                verbatim["properties"] = props
            verbatim["bom-ref"] = source_ref
        kind = bag.peek("agentbom:kind")
        if kind not in (None, "software"):
            self.ctx.lose(
                f"/software/{sid}",
                E.LossReason.ENUM_NARROWED,
                E.LossPreservedIn.PROPERTY,
                entity=sid,
                field_name="kind",
            )
        bag.drop("agentbom:kind")
        sw = SoftwareComponent(
            id=sid,
            name=name,
            description=comp.get("description") if isinstance(comp.get("description"), str) else None,
            purl=purl,
            version=version,
            component_type=str(comp.get("type") or "library"),
            hashes=all_hashes_sha256(comp),
            cyclonedx=verbatim,
        )
        self.draft.add(sw, bom_ref=bom_ref or None)
        self.element_kind[bom_ref] = "sw"
        for nested in comp.get("components") or []:
            if isinstance(nested, Mapping):
                self.software(nested, PropertyBag(properties_of(nested)))
                nref = str(nested.get("bom-ref") or "")
                nid = self.draft.map_ref(nref)
                if nid and nid != nref:
                    self.draft.edge(E.EdgeType.DEPENDS_ON, sid, nid)

    # ---------------------------------------------------------------- services

    def service(self, svc: Mapping[str, Any]) -> None:
        bom_ref = str(svc.get("bom-ref") or "")
        if bom_ref in self.claimed or bom_ref in self.endpoint_services:
            return
        bag = PropertyBag(properties_of(svc))
        kind_name = bag.peek("agentbom:kind")
        kind = _SERVER_BY_KIND.get(kind_name or "") or enum_or_none(
            E.ToolServerKind, bag.peek("agentbom:mcp:kind")
        )
        if kind is None:
            kind = E.ToolServerKind.OPENAPI
        sid = ensure_id("server", bom_ref or None, str(svc.get("name") or "service"), taken=self.draft.ids())
        path = f"/toolServers/{sid}"
        facts: list[str] = []
        mcp_kind = enum_or_none(E.ToolServerKind, bag.get("agentbom:mcp:kind"))
        kind = mcp_kind or kind
        transport = claim_from(
            bag,
            "agentbom:mcp:transport",
            lambda v: enum_or_none(E.Transport, v),
            self.ctx,
            path=path,
            entity=sid,
            facts=facts,
            required=True,
        )
        endpoints = [str(e) for e in svc.get("endpoints") or [] if isinstance(e, str)]
        endpoint_origin = bag.get("agentbom:mcp:endpoint-origin") or (endpoints[0] if endpoints else None)
        endpoint = Claim(value=endpoint_origin) if endpoint_origin else None
        if transport is not None and transport.is_unknown and not self.native and endpoint_origin:
            transport = Claim(
                value=E.Transport.STREAMABLE_HTTP
                if not endpoint_origin.rstrip("/").endswith("/sse")
                else E.Transport.SSE
            )
        package = None
        purl = bag.get("agentbom:mcp:package-purl")
        launcher = enum_or_none(E.Launcher, bag.get("agentbom:mcp:launcher"))
        pinned = bag.get("agentbom:mcp:pinned")
        pkg_comp = self.by_ref.get(f"{bom_ref}/package")
        if purl or launcher or (pkg_comp is not None):
            pkg_digest = hashes_sha256(pkg_comp) if pkg_comp else None
            if pkg_comp is not None and not purl and pkg_comp.get("purl"):
                purl = str(pkg_comp["purl"])
            floating = pinned != "true"
            package = Claim(
                value=PackageRef(
                    purl=purl, digest=pkg_digest, floating=floating, launcher=launcher or E.Launcher.OTHER
                )
            )
            if pkg_comp is not None:
                self.claimed.add(f"{bom_ref}/package")
        elif pinned == "unknown":
            package = Claim.unknown(E.UnknownReason.NOT_COLLECTED)
        env_names = [n for n in bag.get_all("agentbom:mcp:env-var-name") if "=" not in n]
        header_names = [n for n in bag.get_all("agentbom:mcp:header-name") if "=" not in n]
        auth_mode = enum_or_none(E.AuthMode, bag.peek("agentbom:mcp:auth-mode"))
        if auth_mode is not None:
            bag.get("agentbom:mcp:auth-mode")
            authentication = Claim(
                value=Authentication(
                    mode=auth_mode,
                    issuer=bag.get("agentbom:mcp:auth-issuer"),
                    scopes_requested=bag.get_all("agentbom:mcp:scope-requested"),
                ),
                assurance=assurance_from(
                    bag.get("agentbom:mcp:auth-mode:assurance"), self.ctx, path=path, entity=sid, facts=facts
                ),
                locator=bag.get("agentbom:mcp:auth-mode:locator"),
            )
        else:
            authentication = claim_from(
                bag,
                "agentbom:mcp:auth-mode",
                lambda v: None,
                self.ctx,
                path=path,
                entity=sid,
                facts=facts,
                required=True,
            )
            assert authentication is not None
            if authentication.is_unknown and not self.native and svc.get("authenticated") is not None:
                authentication = Claim(
                    value=Authentication(
                        mode=E.AuthMode.OTHER if svc.get("authenticated") else E.AuthMode.NONE
                    )
                )
        crosses = claim_from(
            bag,
            "agentbom:mcp:crosses-trust-boundary",
            parse_bool,
            self.ctx,
            path=path,
            entity=sid,
            facts=facts,
            required=True,
        )
        assert crosses is not None
        if crosses.is_unknown and isinstance(svc.get("x-trust-boundary"), bool):
            crosses = Claim(value=bool(svc["x-trust-boundary"]))
        trust_zone = (
            enum_or_none(E.TrustZone, bag.get("agentbom:mcp:trust-zone"))
            or enum_or_none(E.TrustZone, svc.get("trustZone"))
            or E.TrustZone.UNKNOWN
        )
        server_info = None
        sname = bag.get("agentbom:mcp:server-name")
        sver = bag.get("agentbom:mcp:server-version") or (str(svc["version"]) if svc.get("version") else None)
        if sname or sver:
            server_info = Claim(value=ServerInfo(name=sname or str(svc.get("name") or sid), version=sver))
        toolset = claim_from(
            bag, "agentbom:mcp:toolset-digest", as_digest, self.ctx, path=path, entity=sid, facts=facts
        )
        toolset_result = None
        ts_status = bag.get("agentbom:mcp:toolset-digest-status")
        if ts_status is not None:
            toolset_result = self._digest_result(
                "toolset/v1", toolset.value if toolset and toolset.value else None, ts_status, None
            )
        meta = None
        ttl, scope = (
            parse_int(bag.get("agentbom:mcp:tools-list-ttl-ms")),
            bag.get("agentbom:mcp:tools-list-cache-scope"),
        )
        if ttl is not None or scope is not None:
            meta = ToolListMeta(ttl_ms=ttl, cache_scope=scope)
        trust_flags = {
            n[len("agentbom:mcp:client-trust:") :]: v
            for n, v in bag.consume_prefix("agentbom:mcp:client-trust:")
        }
        bag.drop("agentbom:mcp:tool-count")
        resolution_ref = self.resolution(bag, sid, path)
        server = ToolServer(
            id=sid,
            name=self._name(svc, sid),
            description=svc.get("description") if isinstance(svc.get("description"), str) else None,
            external_refs=self._external_refs(svc, skip_types={"configuration"} if self.native else None),
            server_kind=kind,
            digest=as_digest(bag.get("agentbom:mcp:server-digest")),
            client=bag.get("agentbom:mcp:client") or (str(svc["group"]) if svc.get("group") else None),
            transport=transport,
            endpoint=endpoint,
            package=package,
            command=bag.get("agentbom:mcp:command"),
            args_digest=as_digest(bag.get("agentbom:mcp:args-digest")),
            env_var_names=env_names,
            header_names=header_names,
            server_info=server_info,
            protocol_version=claim_from(
                bag,
                "agentbom:mcp:protocol-version",
                lambda v: v,
                self.ctx,
                path=path,
                entity=sid,
                facts=facts,
            ),
            instructions_digest=claim_from(
                bag,
                "agentbom:mcp:instructions-digest",
                as_digest,
                self.ctx,
                path=path,
                entity=sid,
                facts=facts,
            ),
            authentication=authentication,
            trust_zone=trust_zone,
            crosses_trust_boundary=crosses,
            tool_list_meta=meta,
            toolset_digest=toolset,
            toolset_digest_result=toolset_result,
            registry_resolution_ref=resolution_ref,
            client_trust_flags=trust_flags,
            **self._finish(bag, sid, path, bom_ref=bom_ref),
        )
        server = server.replace(tags=sorted(set(server.tags) | set(facts)))
        self.draft.add(server, bom_ref=bom_ref or None)
        self.element_kind[bom_ref] = "server"
        if resolution_ref:
            self.draft.edge(E.EdgeType.RESOLVED_FROM, sid, resolution_ref)

    def resolution(self, bag: PropertyBag, server_id: str, path: str) -> str | None:
        """``agentbom:resolution:*`` + ``agentbom:registry:*`` on a server → a :class:`RegistryResolution`."""
        res_props = bag.with_prefix("agentbom:resolution:") + bag.with_prefix("agentbom:registry:")
        if not res_props:
            return None
        requested, rkind = (
            bag.get("agentbom:resolution:requested"),
            enum_or_none(E.RequestedRefKind, bag.get("agentbom:resolution:requested-kind")),
        )
        resolved_at, resolver = (
            parse_time(bag.get("agentbom:resolution:resolved-at")),
            bag.get("agentbom:resolution:resolver"),
        )
        if not (requested and rkind and resolved_at and resolver):
            for n, v in bag.consume_prefix("agentbom:resolution:") + bag.consume_prefix("agentbom:registry:"):
                self.ctx.foreign_property(server_id, n, v)
            self.ctx.lose(
                f"{path}/resolution",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.PROPERTY,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=server_id,
                field_name="registry_resolution_ref",
            )
            return None
        edge_target = next(
            (
                e.to_ref
                for e in self.draft.edges
                if e.type is E.EdgeType.RESOLVED_FROM and e.from_ref == server_id
            ),
            None,
        )
        prop_target = next((v for n, v in bag.with_prefix("agentbom:edge:resolved-from")), None)
        rid = ensure_id("res", edge_target or prop_target, server_id.split(":", 1)[1])
        signer_facts: list[str] = []
        signer = None
        if bag.peek("agentbom:resolution:signer-status") is not None:
            status = (
                enum_or_none(E.SignatureStatus, bag.get("agentbom:resolution:signer-status"))
                or E.SignatureStatus.UNSIGNED
            )
            outcome = (
                enum_or_none(E.SignatureOutcome, bag.get("agentbom:resolution:signer-outcome"))
                or E.SignatureOutcome.NONE
            )
            identity = bag.get("agentbom:resolution:signer-identity")
            if status is E.SignatureStatus.VERIFIED and (
                outcome is not E.SignatureOutcome.VERIFIED or not identity
            ):
                status = E.SignatureStatus.CLAIMED
                signer_facts.append("imported-verified-without-constraint")
            signer = SignatureFacts(
                status=status,
                outcome=outcome,
                identity=identity,
                issuer=bag.get("agentbom:resolution:signer-issuer"),
            )
        log = None
        if (
            bag.peek("agentbom:resolution:log-type") is not None
            or bag.peek("agentbom:resolution:log-index") is not None
        ):
            log = TransparencyLog(
                type=bag.get("agentbom:resolution:log-type") or "rekor",
                log_index=parse_int(bag.get("agentbom:resolution:log-index")),
                inclusion_proof_verified=parse_bool(bag.get("agentbom:resolution:log-inclusion-verified"))
                or False,
            )
        registry = None
        if any(
            bag.peek(f"agentbom:registry:{k}") is not None
            for k in ("url", "entry-id", "entry-version", "status", "published-at", "is-latest")
        ):
            registry = RegistryFacts(
                url=bag.get("agentbom:registry:url"),
                entry_id=bag.get("agentbom:registry:entry-id"),
                version=bag.get("agentbom:registry:entry-version"),
                status=enum_or_none(E.RegistryStatus, bag.get("agentbom:registry:status"))
                or E.RegistryStatus.UNKNOWN,
                published_at=parse_time(bag.get("agentbom:registry:published-at")),
                is_latest=parse_bool(bag.get("agentbom:registry:is-latest")),
            )
        publisher = None
        if (
            bag.peek("agentbom:registry:publisher") is not None
            or bag.peek("agentbom:registry:publisher-verification") is not None
        ):
            publisher = PublisherFacts(
                identity=bag.get("agentbom:registry:publisher"),
                verification=enum_or_none(
                    E.PublisherVerification, bag.get("agentbom:registry:publisher-verification")
                )
                or E.PublisherVerification.UNKNOWN,
            )
        typo = None
        nearest, dist = (
            bag.get("agentbom:resolution:typosquat-nearest"),
            parse_int(bag.get("agentbom:resolution:typosquat-distance")),
        )
        if nearest and dist is not None:
            typo = TyposquatDistance(nearest=nearest, levenshtein=dist)
        res = RegistryResolution(
            id=rid,
            tags=signer_facts,
            requested=RequestedRef(kind=rkind, ref=requested),
            resolved_at=resolved_at,
            resolver=resolver,
            resolved=ResolvedRef(
                immutable_ref=bag.get("agentbom:resolution:resolved"),
                digest=as_digest(bag.get("agentbom:resolution:resolved-digest")),
                state=bag.get("agentbom:resolution:resolved-state") or "present",
            ),
            registry=registry,
            publisher=publisher,
            signer=signer,
            transparency_log=log,
            alias_policy=enum_or_none(E.AliasPinning, bag.get("agentbom:resolution:alias-policy"))
            or E.AliasPinning.UNKNOWN,
            typosquat_distance=typo,
            warnings=bag.get_all("agentbom:resolution:warning"),
        )
        for n, v in bag.consume_prefix("agentbom:resolution:") + bag.consume_prefix("agentbom:registry:"):
            self.ctx.foreign_property(rid, n, v)
        if not self.draft.has(rid):
            self.draft.add(res)
        return rid

    # ---------------------------------------------------------------- document-level sections

    def dependencies(self, root: Agent) -> None:
        """``dependencies[]`` → edges that no ``agentbom:edge:*`` property already expressed."""
        deps = [d for d in self.doc.get("dependencies") or [] if isinstance(d, Mapping)]
        known = self.draft.ids()
        explicit = {(e.from_ref, e.to_ref) for e in self.draft.edges}
        saw_root = False
        for d in deps:
            src = self.draft.map_ref(str(d.get("ref", "")))
            if src is None or src not in known:
                continue
            if src == root.id:
                saw_root = True
            for target in d.get("provides") or []:
                dst = self.draft.map_ref(str(target))
                if dst in known and dst is not None:
                    self.draft.edge(
                        E.EdgeType.PROVIDES_TOOL if dst.startswith("tool:") else E.EdgeType.DEPENDS_ON,
                        src,
                        dst,
                    )
            for target in d.get("dependsOn") or []:
                raw = str(target)
                if raw in self.claimed or raw in self.package_components or raw in self.endpoint_services:
                    continue
                dst = self.draft.map_ref(raw)
                if dst is None or dst not in known or (src, dst) in explicit:
                    continue
                self.draft.edge(E.EdgeType.DEPENDS_ON, src, dst)
        for t in self.draft.entities["tools"]:  # a server provides its tools even without an explicit edge
            if t.server_ref in known:
                self.draft.edge(E.EdgeType.PROVIDES_TOOL, t.server_ref, t.id)
        if not self.native:
            # a foreign document lists what the described application is made of: link it to the agent
            targets = [e for e in self.draft.edges if e.from_ref == root.id]
            if not saw_root and not targets:
                for attr, edge_type in (
                    ("software", E.EdgeType.DEPENDS_ON),
                    ("tool_servers", E.EdgeType.DEPENDS_ON),
                    ("models", E.EdgeType.USES_MODEL),
                    ("data_sources", E.EdgeType.READS_CONTEXT_FROM),
                    ("instructions", E.EdgeType.LOADS_INSTRUCTION),
                    ("prompts", E.EdgeType.LOADS_INSTRUCTION),
                    ("skills", E.EdgeType.LOADS_INSTRUCTION),
                ):
                    for ent in self.draft.entities[attr]:
                        self.draft.edge(edge_type, root.id, ent.id)
            for t in self.draft.entities["tools"]:
                self.draft.edge(E.EdgeType.INVOKES_TOOL, root.id, t.id)

    def claims_and_flags(self, root: Agent) -> None:
        """``declarations.claims`` (per-subject) or ``agentbom:flag:*`` metadata properties → derived flags."""
        decl = self.doc.get("declarations") if isinstance(self.doc.get("declarations"), Mapping) else {}
        known = self.draft.ids()
        seen_names: set[str] = set()
        for claim in decl.get("claims") or []:
            if not isinstance(claim, Mapping):
                continue
            predicate = str(claim.get("predicate", ""))
            m = re.match(r"^agentbom:flag:([a-z0-9-]+)=(true|false|unknown)$", predicate)
            if not m:
                continue
            flag = enum_or_none(E.FlagName, m.group(1))
            target = self.draft.map_ref(str(claim.get("target", "")))
            if flag is None or target not in known or target is None:
                continue
            reasoning = str(claim.get("reasoning") or "")
            inputs = (
                [i.strip() for i in reasoning[len("inputs: ") :].split(",")]
                if reasoning.startswith("inputs: ")
                else []
            )
            inputs = [i for i in inputs if i and ":" in i]
            seen_names.add(f"agentbom:flag:{m.group(1)}")
            self._add_flag(Flag(flag=flag, subject_ref=target, value=E.TriState(m.group(2)), inputs=inputs))
        for name, (values, inputs) in self.metadata_flags.items():
            if name in seen_names:
                continue
            flag = enum_or_none(E.FlagName, name[len("agentbom:flag:") :])
            if flag is None:
                for v in values:
                    self.ctx.foreign_property(DOCUMENT_ELEMENT, name, v)
                continue
            for value in sorted(set(values)):
                tri = enum_or_none(E.TriState, value)
                if tri is None:
                    continue
                self._add_flag(
                    Flag(flag=flag, subject_ref=root.id, value=tri, inputs=[i for i in inputs if ":" in i])
                )
            if values:
                self.ctx.lose(
                    f"/derived/flags/{flag.value}",
                    E.LossReason.CARDINALITY_COLLAPSED,
                    E.LossPreservedIn.DROPPED,
                    field_name="subject_ref",
                )
        if decl.get("assessors") or decl.get("attestations"):
            self.ctx.lose(
                "/evaluations",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.DROPPED,
                field_name="results",
            )

    def _add_flag(self, flag: Flag) -> None:
        if not any(f.flag is flag.flag and f.subject_ref == flag.subject_ref for f in self.draft.flags):
            self.draft.flags.append(flag)

    def evidence(self) -> None:
        decl = self.doc.get("declarations") if isinstance(self.doc.get("declarations"), Mapping) else {}
        for ev in decl.get("evidence") or []:
            if not isinstance(ev, Mapping):
                continue
            ref = str(ev.get("bom-ref", ""))
            items = [d for d in ev.get("data") or [] if isinstance(d, Mapping)]
            data = items[0] if items else {}
            contents = data.get("contents") if isinstance(data.get("contents"), Mapping) else {}
            url = contents.get("url") if isinstance(contents.get("url"), str) else None
            digest = as_digest(url)
            named: dict[str, str] = {}
            for item in items[1:]:
                ic = item.get("contents") if isinstance(item.get("contents"), Mapping) else {}
                att = ic.get("attachment") if isinstance(ic.get("attachment"), Mapping) else {}
                value = ic.get("url") if isinstance(ic.get("url"), str) else att.get("content")
                if isinstance(item.get("name"), str) and isinstance(value, str):
                    named.setdefault(item["name"], value)
            if digest is None:
                self.ctx.lose(
                    f"/evidence/{ref or 'unknown'}",
                    E.LossReason.NO_NATIVE_CONSTRUCT,
                    E.LossPreservedIn.DROPPED,
                    E.LossSeverity.SECURITY_RELEVANT,
                    entity=ref or None,
                    field_name="digest",
                )
                continue
            created = parse_time(ev.get("created")) or self.draft.produced_at or self.ctx.now
            if parse_time(ev.get("created")) is None:
                self.ctx.lose(
                    f"/evidence/{ref}",
                    E.LossReason.PRECISION_LOST,
                    E.LossPreservedIn.DROPPED,
                    entity=ref or None,
                    field_name="created",
                )
            kind = enum_or_none(E.EvidenceKind, ev.get("propertyName")) or E.EvidenceKind.OTHER
            author = named.get(EVIDENCE_AUTHOR)
            entity = Evidence(
                id="ev:" + digest[len("sha256:") :][:12],
                name=named.get(EVIDENCE_NAME),
                description=ev.get("description") if isinstance(ev.get("description"), str) else None,
                evidence_kind=kind,
                media_type=named.get(EVIDENCE_MEDIA_TYPE) or "application/octet-stream",
                digest=digest,
                uri=named.get(EVIDENCE_URI),
                created=created,
                expires=parse_time(ev.get("expires")),
                author_ref=author if author and valid_entity_id(author) else None,
                redaction_class=enum_or_none(E.RedactionClass, named.get(EVIDENCE_REDACTION)),
            )
            self.draft.add(entity, bom_ref=ref or None)

    def vulnerabilities(self) -> None:
        known = self.draft.ids()
        for v in self.doc.get("vulnerabilities") or []:
            if not isinstance(v, Mapping):
                continue
            bag = PropertyBag(properties_of(v))
            ref = str(v.get("bom-ref") or "")
            weakness_id = str(v.get("id") or "")
            if not weakness_id:
                continue
            affects = [
                a.get("ref") for a in v.get("affects") or [] if isinstance(a, Mapping) and a.get("ref")
            ]
            subject_ref = self.draft.map_ref(
                bag.get("agentbom:vex:scope:subject") or (str(affects[0]) if affects else None)
            )
            if subject_ref is None or subject_ref not in known:
                self.ctx.lose(
                    f"/vex/{ref or weakness_id}",
                    E.LossReason.NO_NATIVE_CONSTRUCT,
                    E.LossPreservedIn.DROPPED,
                    E.LossSeverity.SECURITY_RELEVANT,
                    entity=ref or None,
                    field_name="subject",
                )
                continue
            source = v.get("source") if isinstance(v.get("source"), Mapping) else {}
            framework = _FRAMEWORK_BY_SOURCE_NAME.get(
                str(source.get("name", "")), slugify(str(source.get("name") or "other"))
            )
            analysis = v.get("analysis") if isinstance(v.get("analysis"), Mapping) else {}
            status = _VEX_STATUS_BY_STATE.get(str(analysis.get("state", "")), "under-investigation")
            justification = bag.get("agentbom:vex:justification") or _VEX_JUSTIFICATION_BY_CDX.get(
                str(analysis.get("justification", ""))
            )
            issued = parse_time(analysis.get("firstIssued"))
            vid = ensure_id("vex", ref or None, f"{framework}-{weakness_id}-{subject_ref}")
            if issued is None:
                issued = self.draft.produced_at or self.ctx.now
                self.ctx.lose(
                    f"/vex/{vid}",
                    E.LossReason.PRECISION_LOST,
                    E.LossPreservedIn.DROPPED,
                    entity=vid,
                    field_name="issued_at",
                )
            vex = VexStatement(
                id=vid,
                weakness=ThreatRef(
                    framework=framework,
                    id=weakness_id,
                    uri=source.get("url") if isinstance(source.get("url"), str) else None,
                ),
                subject=VexSubject(
                    ref=subject_ref, config_digest=as_digest(bag.get("agentbom:vex:scope:config-digest"))
                ),
                status=status,
                justification=justification,
                detail=analysis.get("detail") if isinstance(analysis.get("detail"), str) else None,
                issued_at=issued,
                last_updated=parse_time(analysis.get("lastUpdated")),
                expires=parse_time(bag.get("agentbom:vex:expires")),
            )
            for n, val in bag.remaining():
                self.ctx.foreign_property(vid, n, val)
            self.draft.add(vex, bom_ref=ref or None)

    def prune_edges(self) -> None:
        """Edges to or from entities that could not be imported are dropped (reported), never left dangling."""
        known = self.draft.ids()
        kept = []
        for e in self.draft.edges:
            if e.from_ref in known and e.to_ref in known:
                kept.append(e)
                continue
            security = e.type in (
                E.EdgeType.HOLDS_CREDENTIAL,
                E.EdgeType.ACTS_AS,
                E.EdgeType.GRANTED_BY,
                E.EdgeType.ENFORCED_AT,
                E.EdgeType.APPROVED_UNDER,
                E.EdgeType.DELEGATES_TO,
            )
            self.ctx.lose(
                f"/edges/{e.type.value}:{e.from_ref}->{e.to_ref}",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT if security else E.LossSeverity.INFO,
                field_name="edge",
            )
        self.draft.edges = sorted(kept, key=lambda e: e.key)
        # redaction records (document-level classes, counted from placeholders where possible)
        counts: dict[str, int] = {}
        for r in self.draft.redacted:
            counts[r.redaction_class] = counts.get(r.redaction_class, 0) + 1
        applied_at = self.draft.produced_at or self.ctx.now
        for red_class in sorted(set(self.redaction_classes)):
            self.draft.redactions.append(
                Redaction(
                    redaction_class=red_class,
                    count=max(1, counts.get(red_class, 0)),
                    applied_by="unknown (imported)",
                    applied_at=applied_at,
                    ids=sorted(r.id for r in self.draft.redacted if r.redaction_class == red_class),
                )
            )
            self.ctx.lose(
                f"/redactions/{red_class}",
                E.LossReason.PRECISION_LOST,
                E.LossPreservedIn.DROPPED,
                field_name="applied_by",
            )


class DialectAdapter(Protocol):
    """A dialect adapter maps the elements it understands before the generic pass and may enrich afterwards."""

    name: str
    default_kind: E.SnapshotKind

    def adapt(self, doc: Mapping[str, Any], ctx: ImportContext, draft: Draft, root: Agent) -> set[str]:
        """Map dialect-specific elements into ``draft``; return the bom-refs that must not be mapped again."""

    def post(self, doc: Mapping[str, Any], ctx: ImportContext, draft: Draft, root: Agent) -> None:
        """Enrich the draft after the generic pass (edges, coverage, names) — before dangling edges are pruned."""


def invert(
    doc: Mapping[str, Any],
    ctx: ImportContext,
    *,
    native: bool,
    draft: Draft | None = None,
    claimed: set[str] | None = None,
    adapter: DialectAdapter | None = None,
) -> Draft:
    """Run the :class:`Inverter` over ``doc``; ``claimed`` bom-refs were already handled elsewhere."""
    return Inverter(doc, ctx, draft, claimed=claimed, native=native).run(adapter)


__all__ = ["DialectAdapter", "Draft", "Inverter", "invert"]
