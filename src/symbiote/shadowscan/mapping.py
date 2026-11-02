"""Map ShadowScan findings onto the AgentBOM profile (``spec/shadowscan-mapping.md §2``).

Two consumers share one mapper: :func:`import_report` builds a complete *observed* snapshot from a report, and the
``shadowscan-report`` collector (:mod:`symbiote.collect.shadowscan`) contributes the same entities to a
``symbiote scan`` run. The rules that matter most:

* **Assurance follows the surface.** Findings read from files (``code.*``) are ``declared`` facts about the
  configuration; findings read from a live API, host, log or process inventory are ``observed``. Nothing is
  ``verified``: ShadowScan is a discovery tool, not a signature verifier (I3).
* **Every finding is evidence.** Each finding becomes an ``Evidence`` record (``scan-report``) whose digest is
  the SHA-256 of the published finding; every entity derived from it cites that digest.
* **Unknown stays unknown.** ``shadow: null`` (no inventory) becomes a flag with value ``unknown``; an
  incomplete connector becomes ``partial`` coverage, never an empty surface; ShadowScan's ceiling L5 means
  "not ruled out" and is kept as the ceiling, never collapsed into a single level.
* **Kinds that only enable an agent** (credentials, grants, identities, infrastructure, network contacts) do
  not become agents. They become identities, credential bindings, grants, or observation-only records.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from symbiote import __version__
from symbiote.collect.launchers import parse_launch
from symbiote.model import enums as E
from symbiote.model.common import Claim, DigestResult, EvidenceRef, ExternalRef, Party, Provenance
from symbiote.model.document import AgentBOM, Derived
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    Agent,
    Authentication,
    AutonomyAssessment,
    AutonomyEntry,
    Collector,
    CollectorRun,
    CredentialBinding,
    CredentialStorage,
    Deployment,
    Entity,
    Environment,
    Evidence,
    Flag,
    ForeignProperty,
    FrameworkRef,
    Grant,
    HostedIdentity,
    Identity,
    LossItem,
    LossReport,
    Model,
    PackageRef,
    Scope,
    ServerInfo,
    SourceRun,
    SurfaceCoverage,
    ToolDefinition,
    ToolServer,
)
from symbiote.model.ids import make_id, slugify, tool_id
from symbiote.model.snapshot import ObservationWindow, Producer
from symbiote.shadowscan.autonomy import assessment_from_metadata, widen
from symbiote.shadowscan.report import AUTONOMY_KINDS, ShadowScanFinding, ShadowScanReport

COLLECTOR_NAME = "shadowscan-report"
DIALECT = "shadowscan"
PARTY_ID = "party:nexus-shadowscan"
FINDING_MEDIA_TYPE = "application/vnd.shadowscan.finding+json"
REPORT_MEDIA_TYPE = "application/vnd.shadowscan.report+json"
AGENT_KINDS = frozenset(
    {"agent", "workflow", "bot-app", "cloud-resource", "ai-app", "runtime-process", "gateway-caller"}
)
OBSERVATION_ONLY_KINDS = frozenset({"network-contact", "infra"})
#: ShadowScan client labels → the client slugs Symbiote's ``mcp-config`` collector uses in server ids.
CLIENT_SLUGS = {
    "claude code": "claude-code",
    "claude desktop": "claude-desktop",
    "cursor": "cursor",
    "vs code / copilot": "vscode",
    "vs code": "vscode",
    "visual studio code": "vscode",
    "visual studio": "visual-studio",
    "windsurf": "windsurf",
    "openai codex": "codex",
    "codex": "codex",
    "gemini cli": "gemini-cli",
    "cline": "cline",
    "roo code": "roo-code",
    "amazon q / kiro": "kiro",
    "continue": "continue",
    "opencode": "opencode",
}
_SURFACE_ASSURANCE: dict[str, tuple[E.AssuranceLevel, E.ClaimMethod]] = {
    "code": (E.AssuranceLevel.DECLARED, E.ClaimMethod.CONFIG),
    "endpoint": (E.AssuranceLevel.OBSERVED, E.ClaimMethod.CONFIG),
    "identity": (E.AssuranceLevel.OBSERVED, E.ClaimMethod.LIVE_QUERY),
    "cloud": (E.AssuranceLevel.OBSERVED, E.ClaimMethod.LIVE_QUERY),
    "lowcode": (E.AssuranceLevel.OBSERVED, E.ClaimMethod.LIVE_QUERY),
    "saas": (E.AssuranceLevel.OBSERVED, E.ClaimMethod.LIVE_QUERY),
    "gateway": (E.AssuranceLevel.OBSERVED, E.ClaimMethod.TRACE),
    "network": (E.AssuranceLevel.OBSERVED, E.ClaimMethod.TRACE),
    "runtime": (E.AssuranceLevel.OBSERVED, E.ClaimMethod.TRACE),
}
#: ShadowScan surface (connector family) → the Symbiote coverage surfaces it informs.
_COVERAGE: dict[str, tuple[E.Surface, ...]] = {
    "code": (E.Surface.CODE, E.Surface.TOOLS, E.Surface.INSTRUCTIONS),
    "endpoint": (E.Surface.TOOLS, E.Surface.RUNTIME),
    "identity": (E.Surface.IDENTITY,),
    "cloud": (E.Surface.RUNTIME, E.Surface.IDENTITY),
    "lowcode": (E.Surface.RUNTIME,),
    "saas": (E.Surface.RUNTIME, E.Surface.IDENTITY),
    "gateway": (E.Surface.MODEL_GATEWAY,),
    "network": (E.Surface.NETWORK,),
    "runtime": (E.Surface.RUNTIME,),
}
_SEVERITY = {
    "critical": E.Severity.CRITICAL,
    "high": E.Severity.HIGH,
    "medium": E.Severity.MEDIUM,
    "low": E.Severity.LOW,
    "info": E.Severity.INFO,
}
_SERVERLESS = ("lambda", "function", "cloud-run", "logic-app", "step-function")
_WRITE_HINT = re.compile(r"write|manage|admin|delete|modify|update|create|\*|all|readwrite", re.IGNORECASE)
_EXEC_HINT = re.compile(r"exec|invoke|run|passrole|assume", re.IGNORECASE)
_SEEN_FORMATS = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z")


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _client_slug(label: str | None) -> str:
    if not label:
        return "unknown-client"
    return CLIENT_SLUGS.get(label.strip().lower(), slugify(label))


def _display_path(value: str | None, root: str | None) -> str | None:
    """Repo-relative display of a path-shaped resource (the scan root itself is ``.``)."""
    if not value:
        return None
    if root and value == root:
        return "."
    if root and value.startswith(root.rstrip("/") + "/"):
        return value[len(root.rstrip("/")) + 1 :]
    return value


def _flag_value(shadow: bool | None) -> E.TriState:
    if shadow is None:
        return E.TriState.UNKNOWN
    return E.TriState.TRUE if shadow else E.TriState.FALSE


def _capability_for(permission: str) -> E.CapabilityClass:
    if _EXEC_HINT.search(permission) and not _WRITE_HINT.search(permission):
        return E.CapabilityClass.EXECUTE
    if _WRITE_HINT.search(permission):
        return E.CapabilityClass.WRITE
    return E.CapabilityClass.READ


def _identity_kind(f: ShadowScanFinding) -> E.IdentityKind:
    rt = f.resource_type.lower()
    if f.kind == "iam-grant" or "iam" in rt or "role" in rt:
        return E.IdentityKind.IAM_ROLE
    if "github-app" in rt or f.provider == "github":
        return E.IdentityKind.GITHUB_APP
    if "managed" in rt:
        return E.IdentityKind.AZURE_MANAGED_IDENTITY
    if f.kind in ("oauth-grant", "token") or "service-principal" in rt or "application" in rt or "oidc" in rt:
        return E.IdentityKind.OAUTH_CLIENT
    if "service" in rt or rt == "sa":
        return E.IdentityKind.SERVICE_ACCOUNT
    return E.IdentityKind.OTHER


def _environment(f: ShadowScanFinding) -> Environment:
    rt = f.resource_type.lower()
    if f.surface == "cloud" and any(h in rt for h in _SERVERLESS):
        kind = E.EnvironmentKind.SERVERLESS
    elif f.surface == "cloud" and ("kubernetes" in f.connector or "openshift" in f.connector):
        kind = E.EnvironmentKind.K8S
    elif f.surface == "cloud":
        kind = E.EnvironmentKind.VM
    elif f.surface in ("endpoint", "runtime"):
        kind = E.EnvironmentKind.DESKTOP
    else:
        kind = E.EnvironmentKind.OTHER
    host = f.account if f.surface in ("endpoint", "runtime") else None
    return Environment(kind=kind, host=host, region=f.region)


@dataclass(slots=True)
class ShadowScanImport:
    """Everything one report contributes, before it is assembled into a document or a collector result."""

    report: ShadowScanReport
    root: Agent
    agents: list[Agent] = field(default_factory=list)
    deployments: list[Deployment] = field(default_factory=list)
    tool_servers: list[ToolServer] = field(default_factory=list)
    tools: list[ToolDefinition] = field(default_factory=list)
    models: list[Model] = field(default_factory=list)
    identities: list[Identity] = field(default_factory=list)
    credential_bindings: list[CredentialBinding] = field(default_factory=list)
    grants: list[Grant] = field(default_factory=list)
    parties: list[Party] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    flags: list[Flag] = field(default_factory=list)
    foreign_properties: list[ForeignProperty] = field(default_factory=list)
    coverage: dict[E.Surface, SurfaceCoverage] = field(default_factory=dict)
    collector_runs: list[CollectorRun] = field(default_factory=list)
    losses: list[LossItem] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: finding id → ids of the entities derived from it (for reconcile and the collector)
    derived_from: dict[str, list[str]] = field(default_factory=dict)
    root_findings: list[str] = field(default_factory=list)

    @property
    def entities(self) -> list[Entity]:
        return [
            *self.agents,
            *self.deployments,
            *self.tool_servers,
            *self.tools,
            *self.models,
            *self.identities,
            *self.credential_bindings,
            *self.grants,
        ]

    @property
    def collector(self) -> Collector:
        return Collector(
            name=COLLECTOR_NAME,
            version=self.report.version or "unknown",
            mode=E.CollectorMode.OBSERVED,
            surfaces=sorted(
                {s for s, c in self.coverage.items() if c.status is not E.CoverageStatus.NOT_ATTEMPTED}
            ),
        )


class _Mapper:
    def __init__(
        self,
        report: ShadowScanReport,
        *,
        agent_name: str | None,
        root: Agent | None,
        now: datetime,
        scope: str,
        root_hint: str | None,
    ) -> None:
        self.report = report
        self.now = now
        self.scope = scope
        roots = report.scan_roots
        self.scan_root = root_hint or (roots[0] if roots else None)
        self.collector_ref = f"collector:{COLLECTOR_NAME}@{report.version or 'unknown'}"
        self.observed_at = _parse_time(report.finished_at) or _parse_time(report.started_at) or now
        name = (
            agent_name
            or (PurePosixPath(self.scan_root).name if self.scan_root else None)
            or "shadowscan-estate"
        )
        if root is None:
            root = Agent(
                id=make_id("agent", name),
                name=name,
                version="0.0.0",
                role=E.AgentRole.ROOT,
                purpose=(
                    f"Agent estate discovered by ShadowScan {report.version} ({len(report.findings)} findings)"
                    if not self.scan_root
                    else None
                ),
                provenance=Provenance(
                    assurance=E.AssuranceLevel.OBSERVED,
                    method=E.ClaimMethod.HEURISTIC,
                    locator=self.scan_root,
                    collector=self.collector_ref,
                    observed_at=self.observed_at,
                ),
            )
        self.out = ShadowScanImport(report=report, root=root)
        self.used_ids: set[str] = {root.id}
        self.evidence_refs: dict[str, EvidenceRef] = {}
        self.root_assessments: list[AutonomyAssessment] = []
        self.root_tags: set[str] = set()
        self.root_foreign: dict[str, str] = {}
        self.root_profile: dict[tuple[str, str], AutonomyEntry] = {}
        self.root_framework: Claim[FrameworkRef] | None = None
        self.entity_by_finding: dict[str, str] = {}

    # ------------------------------------------------------------------ helpers

    def unique(self, kind: str, *parts: str, seed: str) -> str:
        eid = make_id(kind, *parts)
        if eid in self.used_ids:
            eid = make_id(kind, *parts, collision_seed=seed)
        n = 2
        base = eid
        while eid in self.used_ids:
            eid = f"{base}-{n}"
            n += 1
        self.used_ids.add(eid)
        return eid

    def attached_to_root(self, f: ShadowScanFinding) -> bool:
        if f.surface != "code" or not self.scan_root or f.scan_root != self.scan_root:
            return False
        if f.kind in ("mcp-server", "agent-config", "framework-usage", "secret", "infra"):
            return True
        return f.kind == "agent" and f.resource_type not in ("agent-manifest",)

    def assurance(self, f: ShadowScanFinding) -> tuple[E.AssuranceLevel, E.ClaimMethod]:
        return _SURFACE_ASSURANCE.get(f.surface, (E.AssuranceLevel.OBSERVED, E.ClaimMethod.HEURISTIC))

    def evidence_for(self, f: ShadowScanFinding) -> EvidenceRef:
        ref = self.evidence_refs.get(f.id)
        if ref is not None:
            return ref
        digest = f.digest()
        uri = f"shadowscan:finding:{f.id}"
        ref = EvidenceRef(
            digest=digest, media_type=FINDING_MEDIA_TYPE, uri=uri, verification=E.EvidenceVerification.PRESENT
        )
        self.evidence_refs[f.id] = ref
        ev_id = "ev:" + digest[len("sha256:") :][:12]
        if ev_id not in self.used_ids:
            self.used_ids.add(ev_id)
            self.out.evidence.append(
                Evidence(
                    id=ev_id,
                    name=f.title,
                    kind=E.EvidenceKind.SCAN_REPORT,
                    media_type=FINDING_MEDIA_TYPE,
                    digest=digest,
                    uri=uri,
                    created=self.observed_at,
                    author_ref=PARTY_ID,
                    redaction_class=E.RedactionClass.CREDENTIAL_SHAPED_TOKEN
                    if "[REDACTED]" in str(f.raw)
                    else None,
                    tags=[f"ss:kind:{f.kind}", f"ss:surface:{f.surface}"],
                )
            )
        return ref

    def provenance(self, f: ShadowScanFinding, locator: str | None = None) -> Provenance:
        assurance, method = self.assurance(f)
        return Provenance(
            assurance=assurance,
            method=method,
            evidence=[self.evidence_for(f)],
            locator=locator or _display_path(f.resource, self.scan_root),
            collector=self.collector_ref,
            observed_at=_parse_time(f.last_seen) or self.observed_at,
        )

    def claim(self, f: ShadowScanFinding, value: Any, *, locator: str | None = None) -> Claim[Any]:
        assurance, method = self.assurance(f)
        return Claim(
            value=value,
            assurance=assurance,
            method=method,
            evidence=[self.evidence_for(f)],
            locator=locator or _display_path(f.resource, self.scan_root),
            collector=self.collector_ref,
            observed_at=_parse_time(f.last_seen) or self.observed_at,
            confidence=round(f.confidence, 3) if method is E.ClaimMethod.HEURISTIC else None,
        )

    def foreign(self, f: ShadowScanFinding) -> dict[str, str]:
        out = {
            "shadowscan:finding-id": f.id,
            "shadowscan:kind": f.kind,
            "shadowscan:surface": f.surface,
            "shadowscan:connector": f.connector,
            "shadowscan:resource": f.resource,
            "shadowscan:resource-type": f.resource_type,
            "shadowscan:discriminator": f.identity_discriminator,
            "shadowscan:confidence": f"{f.confidence:.3f}",
            "shadowscan:likelihood": f.likelihood,
            "shadowscan:risk-level": f.risk.level,
            "shadowscan:risk-score": str(int(f.risk.score)),
            "shadowscan:danger-score": str(int(f.risk.danger_score)),
            "shadowscan:shadow": "unknown" if f.shadow is None else str(f.shadow).lower(),
        }
        for key, value in (
            ("shadowscan:registry-match", f.registry_match),
            ("shadowscan:owner", f.owner),
            ("shadowscan:provider", f.provider),
            ("shadowscan:account", f.account),
            ("shadowscan:region", f.region),
            ("shadowscan:capabilities", ", ".join(f.capabilities) or None),
            ("shadowscan:tags", ", ".join(f.tags) or None),
            ("shadowscan:frameworks", ", ".join(f.frameworks) or None),
            ("shadowscan:model-providers", ", ".join(f.model_providers) or None),
            ("shadowscan:permissions", ", ".join(f.permissions) or None),
        ):
            if value:
                out[key] = value
        for name in ("threats", "controls"):
            refs = f.metadata.get(name)
            if isinstance(refs, list) and refs:
                out[f"shadowscan:{name}"] = ", ".join(str(r) for r in refs[:32])
        if f.metadata.get("registry_match_reason"):
            out["shadowscan:registry-match-reason"] = str(f.metadata["registry_match_reason"])
        return out

    def tags(self, f: ShadowScanFinding) -> list[str]:
        tags = [f"ss:{t}" for t in f.tags]
        if f.shadow is True:
            tags.append("shadow")
        if f.registry_match:
            tags.append("registered")
        return tags

    def external_refs(self, f: ShadowScanFinding) -> list[ExternalRef]:
        refs: list[ExternalRef] = []
        for key in ("url", "homepage"):
            value = f.metadata.get(key)
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                refs.append(ExternalRef(type="website", url=value, comment=f"shadowscan:{key}"))
        return refs

    def record(self, f: ShadowScanFinding, entity_id: str) -> None:
        self.out.derived_from.setdefault(f.id, []).append(entity_id)
        self.entity_by_finding.setdefault(f.id, entity_id)

    def shadow_flag(self, f: ShadowScanFinding, subject: str) -> None:
        self.out.flags.append(
            Flag(
                flag=E.FlagName.UNDECLARED_COMPONENT_OBSERVED,
                subject_ref=subject,
                value=_flag_value(f.shadow),
                inputs=[subject],
                assurance="observed",
            )
        )

    def assessment(self, f: ShadowScanFinding) -> AutonomyAssessment | None:
        block = f.autonomy
        if block is None:
            if f.kind in AUTONOMY_KINDS and self.report.source_format == "json":
                self.out.warnings.append(f"{f.id}: applicable finding carries no autonomy block")
            return None
        assessed = assessment_from_metadata(
            block,
            assessor=f"shadowscan@{self.report.version or 'unknown'}",
            evidence=[self.evidence_for(f)],
            observed_at=_parse_time(f.last_seen) or self.observed_at,
        )
        if assessed is None:
            self.out.warnings.append(f"{f.id}: malformed autonomy block ignored (fail closed: no assessment)")
        return assessed

    def automation_claim(
        self, f: ShadowScanFinding, assessed: AutonomyAssessment
    ) -> Claim[E.IsoAutomationLevel]:
        return Claim(
            value=assessed.floor_level,
            assurance=E.AssuranceLevel.OBSERVED,
            method=E.ClaimMethod.HEURISTIC,
            evidence=list(assessed.evidence),
            locator=_display_path(f.resource, self.scan_root),
            collector=self.collector_ref,
            observed_at=assessed.observed_at,
            confidence=round(f.confidence, 3),
        )

    def loss(
        self,
        path: str,
        *,
        entity: str | None,
        reason: E.LossReason,
        preserved: E.LossPreservedIn,
        security: bool = False,
    ) -> None:
        self.out.losses.append(
            LossItem(
                path=path,
                entity=entity,
                reason=reason,
                preserved_in=preserved,
                severity=E.LossSeverity.SECURITY_RELEVANT if security else E.LossSeverity.INFO,
            )
        )

    # ------------------------------------------------------------------ kinds

    def map_models(self, f: ShadowScanFinding, owner: str, *, hosted: bool = True) -> None:
        names = list(f.models)
        extra = f.metadata.get("model")
        if isinstance(extra, str) and extra and extra not in names:
            names.append(extra)
        provider = f.model_providers[0].split(".", 1)[-1] if f.model_providers else (f.provider or "unknown")
        for name in names[:20]:
            mid = self.unique("model", f"{provider}-{name}", seed=f.id)
            if hosted:
                model = Model(
                    id=mid,
                    name=name,
                    provenance=self.provenance(f),
                    tags=self.tags(f),
                    kind=E.ModelKind.HOSTED,
                    hosted=self.claim(
                        f,
                        HostedIdentity(
                            provider=provider,
                            requested_ref=name,
                            resolved_ref=Claim.unknown(
                                E.UnknownReason.NOT_COLLECTED, collector=self.collector_ref
                            ),
                            alias_pinning=E.AliasPinning.UNKNOWN,
                        ),
                    ),
                    foreign={"shadowscan:finding-id": f.id},
                )
            else:
                model = Model(
                    id=mid,
                    name=name,
                    provenance=self.provenance(f),
                    tags=self.tags(f),
                    kind=E.ModelKind.WEIGHTS,
                    weights=Claim.unknown(
                        E.UnknownReason.NOT_COLLECTED,
                        locator=_display_path(f.resource, self.scan_root),
                        collector=self.collector_ref,
                    ),
                    foreign={
                        "shadowscan:finding-id": f.id,
                        "shadowscan:runtime": str(f.metadata.get("runtime", "")),
                    },
                )
            self.out.models.append(model)
            self.record(f, mid)
            self.out.edges.append(
                Edge.model_validate(
                    {
                        "type": E.EdgeType.USES_MODEL,
                        "from": owner,
                        "to": mid,
                        "assurance": self.assurance(f)[0],
                        "evidence": [self.evidence_for(f)],
                        "declaredBy": f"shadowscan:finding:{f.id}",
                    }
                )
            )
        if len(names) > 20:
            self.loss(
                f"findings[{f.id}].models",
                entity=owner,
                reason=E.LossReason.CARDINALITY_COLLAPSED,
                preserved=E.LossPreservedIn.DROPPED,
            )

    def map_grants(self, f: ShadowScanFinding, subject: str) -> None:
        for permission in f.permissions[:64]:
            gid = self.unique("grant", f"{subject.split(':', 1)[1]}-{permission}", seed=f.id)
            self.out.grants.append(
                Grant(
                    id=gid,
                    name=permission,
                    provenance=self.provenance(f),
                    tags=self.tags(f),
                    layer=E.GrantLayer.OBSERVED
                    if self.assurance(f)[0] is E.AssuranceLevel.OBSERVED
                    else E.GrantLayer.DECLARED,
                    subject_ref=subject,
                    capability=_capability_for(permission),
                    scope=Scope(resources=[permission]),
                    approval_gate=E.ApprovalGate.UNKNOWN,
                    foreign={"shadowscan:finding-id": f.id, "shadowscan:permission": permission},
                )
            )
            self.record(f, gid)

    def map_servers(self, f: ShadowScanFinding, owner: str | None) -> None:
        client_label = f.metadata.get("client") if isinstance(f.metadata.get("client"), str) else None
        client = _client_slug(client_label)
        config = _display_path(f.resource, self.scan_root) or f.resource
        for position, server in enumerate(f.servers):
            name = (
                server.get("name")
                if isinstance(server.get("name"), str) and server.get("name")
                else f"unnamed-{position + 1}"
            )
            sid = self.unique("server", f"{client}-{name}", seed=f"{f.id}:{position}")
            command = server.get("command") if isinstance(server.get("command"), str) else None
            args = (
                [a for a in server.get("args", []) if isinstance(a, str)]
                if isinstance(server.get("args"), list)
                else []
            )
            urls = [u for u in (server.get("urls") or [server.get("url")]) if isinstance(u, str) and u]
            transport_text = str(server.get("transport") or "").lower()
            if command:
                transport = E.Transport.STDIO
            elif transport_text in ("sse",):
                transport = E.Transport.SSE
            elif transport_text in ("http", "streamable-http", "streamable_http", "https"):
                transport = E.Transport.STREAMABLE_HTTP
            elif transport_text == "websocket":
                transport = E.Transport.WEBSOCKET
            elif urls:
                transport = (
                    E.Transport.SSE if urls[0].rstrip("/").endswith("/sse") else E.Transport.STREAMABLE_HTTP
                )
            else:
                transport = None
            locator = f"{config}#/mcpServers/{name}"
            package_claim: Claim[PackageRef] | None = None
            launch = parse_launch(command, args) if command else None
            if launch is not None and launch.package_name is not None:
                package_claim = self.claim(
                    f,
                    PackageRef(
                        purl=launch.purl,
                        digest=launch.digest if launch.digest else None,
                        floating=not launch.pinned,
                        launcher=launch.launcher,
                    ),
                    locator=locator,
                )
            headers = (
                [h for h in server.get("headers", []) if isinstance(h, str)]
                if isinstance(server.get("headers"), list)
                else []
            )
            env_names = (
                [e for e in server.get("env_names", []) if isinstance(e, str)]
                if isinstance(server.get("env_names"), list)
                else []
            )
            risks = (
                [
                    r if isinstance(r, str) else str(r.get("id"))
                    for r in server.get("risks", [])
                    if isinstance(r, (str, dict))
                ]
                if isinstance(server.get("risks"), list)
                else []
            )
            tags = self.tags(f) + [f"ss:risk:{r}" for r in risks]
            if server.get("disabled") is True:
                tags.append("disabled")
            inline = server.get("secrets_inline") is True
            if inline:
                tags.append("inline-secret-in-config")
            if transport is E.Transport.STDIO:
                auth = self.claim(f, Authentication(mode=E.AuthMode.NONE), locator=locator)
                zone, crosses = E.TrustZone.LOCAL_PROCESS, False
            elif headers and any(h.lower() == "authorization" for h in headers):
                auth = self.claim(f, Authentication(mode=E.AuthMode.API_KEY), locator=locator)
                zone, crosses = E.TrustZone.UNKNOWN, True
            else:
                auth = Claim.unknown(
                    E.UnknownReason.NOT_COLLECTED, locator=locator, collector=self.collector_ref
                )
                zone, crosses = E.TrustZone.UNKNOWN, bool(urls)
            auto = server.get("auto_approve")
            trust_flags: dict[str, str] = {}
            if auto is True or (isinstance(auto, list) and auto):
                trust_flags["shadowscan.autoApprove"] = (
                    "true" if auto is True else ", ".join(str(a) for a in auto[:16])
                )
            foreign = self.foreign(f)
            foreign["shadowscan:mcp:client"] = client_label or client
            registry = server.get("registry")
            if isinstance(registry, list) and registry:
                foreign["shadowscan:mcp:registry"] = ", ".join(
                    f"{r.get('registry')}:{r.get('name')}" for r in registry if isinstance(r, dict)
                )[:512]
            server_entity = ToolServer(
                id=sid,
                name=name,
                provenance=self.provenance(f, locator),
                tags=tags,
                kind=E.ToolServerKind.MCP,
                client=client,
                transport=self.claim(f, transport, locator=locator)
                if transport is not None
                else Claim.unknown(
                    E.UnknownReason.NOT_COLLECTED, locator=locator, collector=self.collector_ref
                ),
                endpoint=self.claim(f, urls[0], locator=locator)
                if urls and transport is not E.Transport.STDIO
                else None,
                package=package_claim,
                command=command,
                env_var_names=sorted(env_names),
                header_names=sorted(headers),
                authentication=auth,
                trust_zone=zone,
                crosses_trust_boundary=self.claim(f, crosses, locator=locator),
                client_trust_flags=trust_flags,
                foreign=foreign,
                external_refs=[ExternalRef(type="other", url=u, comment="mcp-endpoint") for u in urls[1:5]],
            )
            self.out.tool_servers.append(server_entity)
            self.record(f, sid)
            self.shadow_flag(f, sid)
            if "mcp-unpinned-package" in risks or (
                package_claim and package_claim.value and package_claim.value.floating
            ):
                self.out.flags.append(
                    Flag(
                        flag=E.FlagName.UNPINNED_TOOL,
                        subject_ref=sid,
                        value=E.TriState.TRUE,
                        inputs=[sid],
                        assurance="observed",
                    )
                )
            if inline:
                self.map_inline_secret(f, sid, locator, server.get("secret_locations"))
            if owner is not None:
                self.out.edges.append(
                    Edge.model_validate(
                        {
                            "type": E.EdgeType.DEPENDS_ON,
                            "from": owner,
                            "to": sid,
                            "scope": E.EdgeScope.RUNTIME,
                            "qualifiers": {
                                "relation": "mcp-server",
                                "client": client,
                                "discoveredBy": "shadowscan",
                            },
                            "assurance": self.assurance(f)[0],
                            "evidence": [self.evidence_for(f)],
                            "declaredBy": locator,
                        }
                    )
                )
        omitted = f.metadata.get("server_count")
        if isinstance(omitted, int) and omitted > len(f.servers):
            self.loss(
                f"findings[{f.id}].metadata.servers",
                entity=None,
                reason=E.LossReason.CARDINALITY_COLLAPSED,
                preserved=E.LossPreservedIn.DROPPED,
                security=True,
            )

    def map_inline_secret(self, f: ShadowScanFinding, subject: str, locator: str, where: Any) -> None:
        slug = subject.split(":", 1)[1]
        ident_id = self.unique("ident", f"{slug}-inline-secret", seed=f.id)
        cred_id = self.unique("cred", f"{slug}-inline-secret", seed=f.id)
        places = ", ".join(str(w) for w in where) if isinstance(where, list) else "configuration"
        self.out.identities.append(
            Identity(
                id=ident_id,
                name=f"inline secret in {places}",
                provenance=self.provenance(f, locator),
                kind=E.IdentityKind.API_KEY_REF,
                ref=f"redacted:{slug}",
                tags=["inline-secret-in-config", *self.tags(f)],
            )
        )
        self.out.credential_bindings.append(
            CredentialBinding(
                id=cred_id,
                provenance=self.provenance(f, locator),
                subject_ref=subject,
                identity_ref=ident_id,
                kind=E.CredentialKind.STATIC_LONG_LIVED,
                storage=CredentialStorage(kind=E.CredentialStorageKind.FILE, locator=locator),
                tags=["inline-secret-in-config"],
                foreign={"shadowscan:finding-id": f.id},
            )
        )
        self.record(f, ident_id)
        self.record(f, cred_id)
        self.out.edges.append(
            Edge.model_validate(
                {
                    "type": E.EdgeType.HOLDS_CREDENTIAL,
                    "from": subject,
                    "to": ident_id,
                    "assurance": self.assurance(f)[0],
                    "evidence": [self.evidence_for(f)],
                }
            )
        )
        self.out.flags.append(
            Flag(
                flag=E.FlagName.STATIC_LONG_LIVED_CREDENTIAL,
                subject_ref=subject,
                value=E.TriState.TRUE,
                inputs=[cred_id],
                assurance="observed",
            )
        )

    def map_implemented_server(self, f: ShadowScanFinding, owner: str) -> None:
        tools = f.metadata.get("mcp_tools")
        details = f.metadata.get("mcp_server") if isinstance(f.metadata.get("mcp_server"), dict) else {}
        if "mcp-server" not in f.capabilities and not tools:
            return
        sid = self.unique("server", f"{owner.split(':', 1)[1]}-implemented", seed=f.id)
        transports = [t for t in details.get("transports", []) if isinstance(t, str)] if details else []
        transport = None
        if len(transports) == 1:
            transport = {
                "stdio": E.Transport.STDIO,
                "sse": E.Transport.SSE,
                "http": E.Transport.STREAMABLE_HTTP,
            }.get(transports[0].lower())
        self.out.tool_servers.append(
            ToolServer(
                id=sid,
                name=f"{f.title} (implemented MCP server)",
                provenance=self.provenance(f),
                tags=[*self.tags(f), "implemented-server"],
                kind=E.ToolServerKind.MCP,
                transport=self.claim(f, transport)
                if transport
                else Claim.unknown(E.UnknownReason.NOT_COLLECTED, collector=self.collector_ref),
                authentication=Claim.unknown(E.UnknownReason.NOT_COLLECTED, collector=self.collector_ref),
                crosses_trust_boundary=Claim.unknown(
                    E.UnknownReason.NOT_COLLECTED, collector=self.collector_ref
                ),
                server_info=self.claim(f, ServerInfo(name=f.title)),
                foreign={**self.foreign(f), "shadowscan:mcp:implementation": "source"},
            )
        )
        self.record(f, sid)
        self.out.edges.append(
            Edge.model_validate(
                {
                    "type": E.EdgeType.PROVIDES_TOOL,
                    "from": owner,
                    "to": sid,
                    "qualifiers": {"relation": "implements"},
                    "assurance": self.assurance(f)[0],
                    "evidence": [self.evidence_for(f)],
                }
            )
        )
        for name in [t for t in tools if isinstance(t, str) and t] if isinstance(tools, list) else []:
            tid = tool_id(sid, name)
            if tid in self.used_ids:
                continue
            self.used_ids.add(tid)
            self.out.tools.append(
                ToolDefinition(
                    id=tid,
                    name=name,
                    provenance=self.provenance(f),
                    server_ref=sid,
                    tool_name=name,
                    input_schema={},
                    digest=DigestResult(
                        algorithm="tooldef/v1",
                        status=E.DigestStatus.UNDIGESTABLE,
                        reason="name-only: ShadowScan reports tool names, not definitions",
                    ),
                    source=E.ToolSource.DECLARED_CONFIG,
                    state=E.ToolState.DECLARED,
                    foreign={"shadowscan:finding-id": f.id},
                )
            )
            self.record(f, tid)
            self.out.edges.append(
                Edge.model_validate(
                    {
                        "type": E.EdgeType.PROVIDES_TOOL,
                        "from": sid,
                        "to": tid,
                        "assurance": self.assurance(f)[0],
                    }
                )
            )

    def map_builtin_tools(self, f: ShadowScanFinding, owner: str) -> None:
        tools = f.metadata.get("tools")
        if not isinstance(tools, list) or not tools:
            return
        sid = self.unique("server", f"{owner.split(':', 1)[1]}-tools", seed=f.id)
        self.out.tool_servers.append(
            ToolServer(
                id=sid,
                name=f"{f.title} tools",
                provenance=self.provenance(f),
                tags=self.tags(f),
                kind=E.ToolServerKind.BUILTIN,
                transport=self.claim(f, E.Transport.IN_PROCESS),
                authentication=Claim.unknown(E.UnknownReason.NOT_COLLECTED, collector=self.collector_ref),
                crosses_trust_boundary=self.claim(f, False),
                trust_zone=E.TrustZone.INTERNAL,
                foreign=self.foreign(f),
            )
        )
        self.record(f, sid)
        for item in tools[:64]:
            name = item.get("name") if isinstance(item, dict) else item
            if not isinstance(name, str) or not name:
                continue
            tid = tool_id(sid, slugify(name))
            if tid in self.used_ids:
                continue
            self.used_ids.add(tid)
            ttype = str(item.get("type", "")) if isinstance(item, dict) else ""
            self.out.tools.append(
                ToolDefinition(
                    id=tid,
                    name=name,
                    provenance=self.provenance(f),
                    server_ref=sid,
                    tool_name=name,
                    input_schema={},
                    digest=DigestResult(
                        algorithm="tooldef/v1",
                        status=E.DigestStatus.UNDIGESTABLE,
                        reason="platform tool record without a definition",
                    ),
                    source=E.ToolSource.DECLARED_CONFIG,
                    side_effect_class=E.SideEffectClass.STATE_MODIFYING
                    if ttype in ("script", "flow", "action")
                    else E.SideEffectClass.UNKNOWN,
                    capabilities=[E.CapabilityClass.EXECUTE] if ttype == "script" else [],
                    foreign={"shadowscan:finding-id": f.id, "shadowscan:tool-type": ttype},
                )
            )
            self.record(f, tid)
            self.out.edges.append(
                Edge.model_validate(
                    {
                        "type": E.EdgeType.PROVIDES_TOOL,
                        "from": sid,
                        "to": tid,
                        "assurance": self.assurance(f)[0],
                    }
                )
            )
            self.out.edges.append(
                Edge.model_validate(
                    {
                        "type": E.EdgeType.INVOKES_TOOL,
                        "from": owner,
                        "to": tid,
                        "assurance": self.assurance(f)[0],
                        "evidence": [self.evidence_for(f)],
                    }
                )
            )

    def map_agent(self, f: ShadowScanFinding, *, sub_agent: bool) -> str:
        card = f.metadata.get("agent_card") if isinstance(f.metadata.get("agent_card"), dict) else {}
        display = (
            card.get("name")
            or f.metadata.get("agent_name")
            or f.metadata.get("name")
            or (f.metadata.get("caller") if f.kind == "gateway-caller" else None)
            or f.title.split(":")[-1].strip()
        )
        aid = self.unique("agent", str(display), seed=f.id)
        assessed = self.assessment(f)
        framework = None
        if f.frameworks:
            framework = self.claim(f, FrameworkRef(name=f.frameworks[0].split(".", 1)[-1]))
        foreign = self.foreign(f)
        for key in ("url", "version", "protocol_version", "signature"):
            if isinstance(card.get(key), str):
                foreign[f"shadowscan:a2a:{key.replace('_', '-')}"] = card[key]
        if card.get("skills"):
            foreign["shadowscan:a2a:skills"] = ", ".join(str(s) for s in card["skills"][:16])
        ext = self.external_refs(f)
        if isinstance(card.get("url"), str) and card["url"].startswith("http"):
            ext.append(ExternalRef(type="other", url=card["url"], comment="a2a-agent-card"))
        version = card.get("version") if isinstance(card.get("version"), str) else None
        agent = Agent(
            id=aid,
            name=str(display),
            description=card.get("description")
            if isinstance(card.get("description"), str)
            else (f.metadata.get("description") if isinstance(f.metadata.get("description"), str) else None),
            provenance=self.provenance(f),
            tags=[*self.tags(f), f"ss:kind:{f.kind}"],
            external_refs=ext,
            version=version or "unknown",
            role=E.AgentRole.SUB_AGENT if sub_agent else E.AgentRole.EXTERNAL_AGENT,
            parent_ref=self.out.root.id if sub_agent else None,
            framework=framework,
            automation_level=self.automation_claim(f, assessed) if assessed else None,
            autonomy_assessment=assessed,
            foreign=foreign,
        )
        self.out.agents.append(agent)
        self.record(f, aid)
        self.shadow_flag(f, aid)
        self.map_models(f, aid)
        self.map_builtin_tools(f, aid)
        self.map_implemented_server(f, aid)
        if f.kind in ("bot-app", "workflow", "cloud-resource", "ai-app", "runtime-process", "gateway-caller"):
            self.map_grants(f, aid)
            did = self.unique("deploy", str(display), seed=f.id)
            self.out.deployments.append(
                Deployment(
                    id=did,
                    name=f"{display} on {f.provider or f.surface}",
                    provenance=self.provenance(f),
                    tags=self.tags(f),
                    agent_ref=aid,
                    environment=_environment(f),
                    tenant=f.account,
                    started_at=_parse_time(f.first_seen),
                    observed_by=[self.collector_ref],
                    foreign={"shadowscan:finding-id": f.id},
                )
            )
            self.record(f, did)
        env_names = f.metadata.get("env_names")
        if (
            isinstance(env_names, list)
            and env_names
            and any(t in f.tags for t in ("secret-in-env", "plaintext-credential"))
        ):
            self.map_env_secret(f, aid, [e for e in env_names if isinstance(e, str)])
        if sub_agent:
            self.out.edges.append(
                Edge.model_validate(
                    {
                        "type": E.EdgeType.SPAWNS,
                        "from": self.out.root.id,
                        "to": aid,
                        "scope": E.EdgeScope.DESIGN,
                        "qualifiers": {"relation": "sub-project"},
                        "assurance": self.assurance(f)[0],
                        "evidence": [self.evidence_for(f)],
                    }
                )
            )
        elif self.attached_root_card(f):
            self.out.edges.append(
                Edge.model_validate(
                    {
                        "type": E.EdgeType.DELEGATES_TO,
                        "from": self.out.root.id,
                        "to": aid,
                        "qualifiers": {"relation": "a2a-card-in-repository"},
                        "assurance": self.assurance(f)[0],
                        "evidence": [self.evidence_for(f)],
                    }
                )
            )
        return aid

    def attached_root_card(self, f: ShadowScanFinding) -> bool:
        return (
            f.surface == "code"
            and f.resource_type == "agent-manifest"
            and bool(self.scan_root)
            and f.scan_root == self.scan_root
        )

    def map_env_secret(self, f: ShadowScanFinding, subject: str, names: list[str]) -> None:
        slug = subject.split(":", 1)[1]
        for name in names[:16]:
            ident_id = self.unique("ident", f"{slug}-env-{name}", seed=f.id)
            cred_id = self.unique("cred", f"{slug}-env-{name}", seed=f.id)
            self.out.identities.append(
                Identity(
                    id=ident_id,
                    name=name,
                    provenance=self.provenance(f),
                    kind=E.IdentityKind.API_KEY_REF,
                    ref=f"env:{name}",
                    tags=self.tags(f),
                )
            )
            self.out.credential_bindings.append(
                CredentialBinding(
                    id=cred_id,
                    provenance=self.provenance(f),
                    subject_ref=subject,
                    identity_ref=ident_id,
                    kind=E.CredentialKind.STATIC_LONG_LIVED,
                    storage=CredentialStorage(kind=E.CredentialStorageKind.ENV, locator=f.resource),
                    tags=["plaintext-env-secret", *self.tags(f)],
                    foreign={"shadowscan:finding-id": f.id},
                )
            )
            self.record(f, ident_id)
            self.record(f, cred_id)
            self.out.edges.append(
                Edge.model_validate(
                    {
                        "type": E.EdgeType.HOLDS_CREDENTIAL,
                        "from": subject,
                        "to": ident_id,
                        "assurance": self.assurance(f)[0],
                    }
                )
            )
        self.out.flags.append(
            Flag(
                flag=E.FlagName.STATIC_LONG_LIVED_CREDENTIAL,
                subject_ref=subject,
                value=E.TriState.TRUE,
                inputs=[subject],
                assurance="observed",
            )
        )

    def map_identity(self, f: ShadowScanFinding) -> str:
        ref = f.resource
        for key in ("client_id", "app_id", "subject", "principal"):
            value = f.metadata.get(key)
            if isinstance(value, str) and value and "[REDACTED]" not in value:
                ref = value
                break
        iid = self.unique("ident", f.title.split(":")[-1].strip() or ref, seed=f.id)
        tenant = f.account
        issuer = f.metadata.get("issuer") if isinstance(f.metadata.get("issuer"), str) else None
        self.out.identities.append(
            Identity(
                id=iid,
                name=f.title,
                provenance=self.provenance(f),
                tags=[*self.tags(f), f"ss:kind:{f.kind}"],
                kind=_identity_kind(f),
                ref=ref,
                issuer=issuer,
                tenant=tenant,
                foreign=self.foreign(f),
            )
        )
        self.record(f, iid)
        self.shadow_flag(f, iid)
        self.map_grants(f, iid)
        if f.kind == "token":
            cred_id = self.unique("cred", f"{iid.split(':', 1)[1]}-token", seed=f.id)
            hours = f.metadata.get("lifetime_hours")
            self.out.credential_bindings.append(
                CredentialBinding(
                    id=cred_id,
                    provenance=self.provenance(f),
                    subject_ref=iid,
                    identity_ref=iid,
                    kind=E.CredentialKind.OBO_TOKEN
                    if "delegation" in f.tags
                    else E.CredentialKind.EPHEMERAL_TASK_SCOPED,
                    lifetime=f"{hours}h" if isinstance(hours, (int, float)) else None,
                    tags=self.tags(f),
                    foreign={
                        "shadowscan:finding-id": f.id,
                        "shadowscan:signature-verified": str(
                            f.metadata.get("signature_verified", "unknown")
                        ).lower(),
                    },
                )
            )
            self.record(f, cred_id)
        if f.kind == "oauth-grant":
            # The consented application is an AI system acting on the tenant's data: record it as an agent too.
            display = f.title.split(":")[-1].strip()
            aid = self.unique("agent", display, seed=f"{f.id}:agent")
            self.out.agents.append(
                Agent(
                    id=aid,
                    name=display,
                    provenance=self.provenance(f),
                    tags=[*self.tags(f), "ss:kind:oauth-grant"],
                    version="unknown",
                    role=E.AgentRole.EXTERNAL_AGENT,
                    identities=[iid],
                    foreign={"shadowscan:finding-id": f.id},
                )
            )
            self.record(f, aid)
            self.out.edges.append(
                Edge.model_validate(
                    {
                        "type": E.EdgeType.ACTS_AS,
                        "from": aid,
                        "to": iid,
                        "assurance": self.assurance(f)[0],
                        "evidence": [self.evidence_for(f)],
                    }
                )
            )
        return iid

    def map_secret(self, f: ShadowScanFinding, subject: str) -> None:
        locator = _display_path(f.resource, self.scan_root) or f.resource
        slug = subject.split(":", 1)[1]
        providers = f.model_providers or f.frameworks or ["unknown"]
        ident_id = self.unique("ident", f"{slug}-hardcoded-{slugify(locator)}", seed=f.id)
        cred_id = self.unique("cred", f"{slug}-hardcoded-{slugify(locator)}", seed=f.id)
        self.out.identities.append(
            Identity(
                id=ident_id,
                name=f"hardcoded credential ({', '.join(p.split('.', 1)[-1] for p in providers[:3])})",
                provenance=self.provenance(f, locator),
                kind=E.IdentityKind.API_KEY_REF,
                ref=f"redacted:{locator}",
                tags=["hardcoded-credential", *self.tags(f)],
                foreign=self.foreign(f),
            )
        )
        self.out.credential_bindings.append(
            CredentialBinding(
                id=cred_id,
                provenance=self.provenance(f, locator),
                subject_ref=subject,
                identity_ref=ident_id,
                kind=E.CredentialKind.STATIC_LONG_LIVED,
                storage=CredentialStorage(kind=E.CredentialStorageKind.FILE, locator=locator),
                tags=["inline-secret-in-config", "hardcoded-credential"],
                foreign={"shadowscan:finding-id": f.id},
            )
        )
        self.record(f, ident_id)
        self.record(f, cred_id)
        self.out.edges.append(
            Edge.model_validate(
                {
                    "type": E.EdgeType.HOLDS_CREDENTIAL,
                    "from": subject,
                    "to": ident_id,
                    "assurance": self.assurance(f)[0],
                    "evidence": [self.evidence_for(f)],
                }
            )
        )
        self.out.flags.append(
            Flag(
                flag=E.FlagName.STATIC_LONG_LIVED_CREDENTIAL,
                subject_ref=subject,
                value=E.TriState.TRUE,
                inputs=[cred_id],
                assurance="observed",
            )
        )

    def map_agent_config(self, f: ShadowScanFinding) -> None:
        sig = f.frameworks[0] if f.frameworks else f.identity_discriminator.split(":")[-1]
        harness = sig.split(".", 1)[-1]
        self.root_tags.add(f"harness:{harness}")
        for tag in f.tags:
            self.root_tags.add(f"ss:{tag}")
        gate = f.metadata.get("approval_gate")
        scope = gate.get("scope") if isinstance(gate, dict) else None
        bypass = any(
            t in f.tags
            for t in ("posture-permissions-bypassed", "mcp-auto-approve", "posture-unrestricted-shell")
        )
        self.root_foreign[f"shadowscan:agent-config:{harness}"] = f.id
        self.root_foreign[f"shadowscan:agent-config:{harness}:approval-gate"] = (
            "bypassed" if bypass else (str(scope) if isinstance(scope, str) else "none-recorded")
        )
        if isinstance(gate, dict) and isinstance(gate.get("settings"), list):
            self.root_foreign[f"shadowscan:agent-config:{harness}:approval-settings"] = "; ".join(
                f"{s.get('file')}:{s.get('setting')}={s.get('value')}"
                for s in gate["settings"][:8]
                if isinstance(s, dict)
            )[:512]
        if "code-exec" in f.capabilities:
            mode = (
                E.AutonomyMode.AUTONOMOUS
                if bypass
                else (E.AutonomyMode.APPROVAL_REQUIRED if scope == "every-action" else None)
            )
            if mode is not None:
                self.root_profile.setdefault(
                    (E.CapabilityClass.EXECUTE.value, mode.value),
                    AutonomyEntry(capability=E.CapabilityClass.EXECUTE, mode=mode),
                )
        assessed = self.assessment(f)
        if assessed:
            self.root_assessments.append(assessed)
        self.map_models(f, self.out.root.id)
        self.record(f, self.out.root.id)
        self.out.root_findings.append(f.id)
        self.evidence_for(f)

    def map_framework_usage(self, f: ShadowScanFinding) -> None:
        if f.frameworks and self.root_framework is None:
            self.root_framework = self.claim(f, FrameworkRef(name=f.frameworks[0].split(".", 1)[-1]))
        for tag in f.tags:
            self.root_tags.add(f"ss:{tag}")
        assessed = self.assessment(f)
        if assessed:
            self.root_assessments.append(assessed)
        self.map_models(f, self.out.root.id)
        self.map_implemented_server(f, self.out.root.id)
        self.record(f, self.out.root.id)
        self.out.root_findings.append(f.id)

    def map_observation_only(self, f: ShadowScanFinding) -> None:
        ref = self.evidence_for(f)
        for name, value in self.foreign(f).items():
            self.out.foreign_properties.append(
                ForeignProperty(dialect=DIALECT, element_id=ref.evidence_id, name=name, value=value)
            )
        self.record(f, ref.evidence_id)
        self.loss(
            f"findings[{f.id}]",
            entity=ref.evidence_id,
            reason=E.LossReason.NO_NATIVE_CONSTRUCT,
            preserved=E.LossPreservedIn.EMBEDDED_RECORD,
        )

    # ------------------------------------------------------------------ driver

    def run(self) -> ShadowScanImport:
        report = self.report
        self.out.parties.append(
            Party(
                id=PARTY_ID,
                kind=E.PartyKind.ORGANIZATION,
                name=f"Nexus ShadowScan {report.version}".strip(),
                urls=["https://github.com/aisecnomad/Nexus-ShadowScan"],
            )
        )
        self.used_ids.add(PARTY_ID)
        if report.source_digest:
            ev_id = "ev:" + report.source_digest[len("sha256:") :][:12]
            self.used_ids.add(ev_id)
            self.out.evidence.append(
                Evidence(
                    id=ev_id,
                    name=f"ShadowScan {report.source_format} report",
                    kind=E.EvidenceKind.SCAN_REPORT,
                    media_type=REPORT_MEDIA_TYPE
                    if report.source_format == "json"
                    else "application/vnd.cyclonedx+json",
                    digest=report.source_digest,
                    uri=f"file:{report.source_path}" if report.source_path else None,
                    created=self.observed_at,
                    author_ref=PARTY_ID,
                    tags=[
                        "shadowscan:report",
                        f"shadowscan:status:{'complete' if report.complete else 'incomplete'}",
                    ],
                )
            )
        for f in sorted(report.findings, key=lambda x: (x.surface, x.kind, x.id)):
            root_bound = self.attached_to_root(f)
            if self.scope == "root" and not root_bound and not self.attached_root_card(f):
                continue
            if f.kind == "agent-config" and root_bound:
                self.map_agent_config(f)
            elif f.kind == "framework-usage" and root_bound:
                self.map_framework_usage(f)
            elif f.kind == "mcp-server":
                self.map_servers(f, self.out.root.id if root_bound else None)
                if root_bound:
                    assessed = self.assessment(f)
                    if assessed:
                        self.root_assessments.append(assessed)
                    self.out.root_findings.append(f.id)
                if "mcp-server" in f.capabilities and f.metadata.get("mcp_tools"):
                    self.map_implemented_server(f, self.out.root.id)
            elif f.kind == "secret":
                self.map_secret(f, self.out.root.id)
            elif f.kind in ("oauth-grant", "service-identity", "iam-grant", "token"):
                self.map_identity(f)
            elif f.kind == "local-model":
                self.map_models(f, self.out.root.id, hosted=False)
            elif f.kind in AGENT_KINDS or f.kind in ("agent-config", "framework-usage"):
                self.map_agent(f, sub_agent=root_bound and f.kind == "agent")
            elif f.kind in OBSERVATION_ONLY_KINDS:
                self.map_observation_only(f)
            else:
                self.out.warnings.append(f"{f.id}: unmapped ShadowScan kind {f.kind!r} kept as observation")
                self.map_observation_only(f)
        self.finish_root()
        self.coverage()
        return self.out

    def finish_root(self) -> None:
        root = self.out.root
        updates: dict[str, Any] = {}
        combined = widen(self.root_assessments)
        if combined is not None:
            updates["autonomy_assessment"] = combined.model_dump(mode="python")
            if root.automation_level is None or root.automation_level.assurance is E.AssuranceLevel.DECLARED:
                claim = Claim(
                    value=combined.floor_level,
                    assurance=E.AssuranceLevel.OBSERVED,
                    method=E.ClaimMethod.HEURISTIC,
                    evidence=list(combined.evidence),
                    locator=self.scan_root,
                    collector=self.collector_ref,
                    observed_at=combined.observed_at,
                )
                if root.automation_level is not None and root.automation_level.value is not None:
                    declared_level, _ = _declared_level(root.automation_level.value)
                    if declared_level is not None and combined.declared is None:
                        combined = combined.replace(declared=declared_level, declared_source=root.id)
                        updates["autonomy_assessment"] = combined.model_dump(mode="python")
                    # keep the owner's declaration; the observed interval lives in autonomy_assessment
                else:
                    updates["automation_level"] = claim.model_dump(mode="python")
        if self.root_tags:
            updates["tags"] = sorted(set(root.tags) | self.root_tags)
        if self.root_foreign:
            updates["foreign"] = {**root.foreign, **self.root_foreign}
        if self.root_profile:
            existing = {(a.capability.value, a.mode.value) for a in root.autonomy_profile}
            new = [a for key, a in self.root_profile.items() if key not in existing]
            if new:
                updates["autonomy_profile"] = [
                    a.model_dump(mode="python") for a in [*root.autonomy_profile, *new]
                ]
        if self.root_framework is not None and root.framework is None:
            updates["framework"] = self.root_framework.model_dump(mode="python")
        if updates:
            self.out.root = root.replace(**updates)
        if self.out.root_findings:
            self.out.flags.append(
                Flag(
                    flag=E.FlagName.UNDECLARED_COMPONENT_OBSERVED,
                    subject_ref=self.out.root.id,
                    value=_flag_value(self.root_shadow()),
                    inputs=[self.out.root.id],
                    assurance="observed",
                )
            )

    def root_shadow(self) -> bool | None:
        states = {f.shadow for f in self.report.findings if f.id in self.out.root_findings}
        if not states or states == {None}:
            return None
        return True in states

    def coverage(self) -> None:
        by_surface: dict[E.Surface, list[tuple[Any, bool]]] = {}
        for stats in self.report.stats:
            targets = _COVERAGE.get(stats.surface, ())
            for surface in targets:
                by_surface.setdefault(surface, []).append((stats, True))
            base = stats.name or stats.connector
            run_name = f"shadowscan:{base}" + (
                f"[{stats.connector}]" if stats.name and stats.connector != stats.name else ""
            )
            if any(r.name == run_name for r in self.out.collector_runs):
                continue
            self.out.collector_runs.append(
                CollectorRun(
                    name=run_name,
                    version=self.report.version or "unknown",
                    status={
                        "ok": E.CollectorStatus.OK,
                        "partial": E.CollectorStatus.PARTIAL,
                        "failed": E.CollectorStatus.FAILED,
                        "skipped": E.CollectorStatus.SKIPPED,
                    }[stats.status],
                    reason=stats.skip_reason
                    or (
                        "; ".join(stats.errors[:2])
                        if stats.errors
                        else (", ".join(stats.incomplete_reasons) or None)
                    ),
                )
            )
        for surface in E.Surface:
            entries = by_surface.get(surface, [])
            if not entries:
                self.out.coverage[surface] = SurfaceCoverage(status=E.CoverageStatus.NOT_ATTEMPTED)
                continue
            runs = [
                SourceRun(
                    source=f"shadowscan:{s.name or s.connector}",
                    locator=s.connector if s.connector != s.name else None,
                    ok=s.ok,
                    error_class=(", ".join(sorted(s.incomplete_reasons)) or ("error" if s.errors else None))
                    if not s.ok
                    else None,
                    items=s.findings,
                )
                for s, _ in entries
            ]
            if all(s.ok for s, _ in entries):
                status = E.CoverageStatus.QUERIED
            elif all(s.skipped for s, _ in entries):
                status = E.CoverageStatus.NOT_ATTEMPTED
            else:
                status = E.CoverageStatus.PARTIAL
            self.out.coverage[surface] = SurfaceCoverage(
                status=status, sources=runs, items_seen=sum(r.items for r in runs)
            )


def _declared_level(value: E.IsoAutomationLevel) -> tuple[int | None, bool]:
    from symbiote.shadowscan.autonomy import from_iso

    try:
        return from_iso(value)
    except ValueError:
        return None, False


def map_report(
    report: ShadowScanReport,
    *,
    agent_name: str | None = None,
    root: Agent | None = None,
    now: datetime | None = None,
    scope: str = "estate",
    scan_root: str | None = None,
) -> ShadowScanImport:
    """Map a report onto AgentBOM entities.

    ``scope`` is ``estate`` (every finding) or ``root`` (only findings about the scanned repository). ``root``
    lets a caller (the collector) supply the agent the findings are about; otherwise one is derived from the
    dominant scan root. ``scan_root`` overrides the detected scan root (useful when a report was produced on
    another machine).
    """
    if scope not in ("estate", "root"):
        raise ValueError("scope must be 'estate' or 'root'")
    mapper = _Mapper(
        report,
        agent_name=agent_name,
        root=root,
        now=now or datetime.now(UTC),
        scope=scope,
        root_hint=scan_root,
    )
    return mapper.run()


def import_report(
    report: ShadowScanReport,
    *,
    agent_name: str | None = None,
    now: datetime | None = None,
    deterministic: bool = False,
    nonce: bytes | None = None,
    scope: str = "estate",
    scan_root: str | None = None,
    policy: bool = True,
) -> AgentBOM:
    """Build a finalised **observed** AgentBOM snapshot from a ShadowScan report."""
    from symbiote.snapshot.commit import finalize, new_document

    now = now or (datetime(2000, 1, 1, tzinfo=UTC) if deterministic else datetime.now(UTC))
    mapped = map_report(report, agent_name=agent_name, now=now, scope=scope, scan_root=scan_root)
    start = _parse_time(report.started_at) or _parse_time(report.finished_at) or now
    end = _parse_time(report.finished_at) or start
    end = max(end, start)
    producer = Producer(version=__version__, collectors=[mapped.collector])
    from symbiote.model.entities import Coverage, Window

    coverage = Coverage(
        surfaces=mapped.coverage,
        window=Window(start=start, end=end),
        collectors=mapped.collector_runs,
        text_included=False,
    )
    loss = LossReport(
        direction="shadowscan→model",
        source_format=f"shadowscan-{report.source_format}",
        target_format="agentbom-model",
        items=[
            *mapped.losses,
            *(
                LossItem(
                    path="report",
                    reason=E.LossReason.UNSUPPORTED_IN_TARGET_VERSION,
                    preserved_in=E.LossPreservedIn.DROPPED,
                    severity=E.LossSeverity.SECURITY_RELEVANT,
                )
                for _ in report.losses
            ),
        ],
    )
    doc = new_document(
        subject=mapped.root.id,
        producer=producer,
        kind=E.SnapshotKind.OBSERVED,
        produced_at=now,
        agents=[mapped.root, *mapped.agents],
        deployments=mapped.deployments,
        tool_servers=mapped.tool_servers,
        tools=mapped.tools,
        models=mapped.models,
        identities=mapped.identities,
        credential_bindings=mapped.credential_bindings,
        grants=mapped.grants,
        parties=mapped.parties,
        evidence=mapped.evidence,
        edges=_dedupe_edges(mapped.edges),
        coverage=coverage,
        foreign_properties=mapped.foreign_properties,
        loss_report=loss,
        derived=Derived(flags=_dedupe_flags(mapped.flags)),
    )
    if policy:
        from symbiote.policy import run_policy

        result = run_policy(doc, now=now)
        doc = result.apply(doc)
        merged = _dedupe_flags([*doc.derived.flags, *mapped.flags])
        doc = doc.replace(
            derived=Derived(flags=merged, findings=list(doc.derived.findings)).model_dump(mode="python")
        )
    use_nonce = nonce if nonce is not None else (bytes(32) if deterministic else None)
    return finalize(doc, nonce=use_nonce, observation_window=ObservationWindow(start=start, end=end))


def _dedupe_edges(edges: Iterable[Edge]) -> list[Edge]:
    seen: dict[tuple[str, str, str], Edge] = {}
    for e in edges:
        seen.setdefault(e.key, e)
    return sorted(seen.values(), key=lambda e: e.key)


def _dedupe_flags(flags: Iterable[Flag]) -> list[Flag]:
    seen: dict[tuple[str, str], Flag] = {}
    for fl in flags:
        key = (fl.flag.value, fl.subject_ref)
        current = seen.get(key)
        # a definite value wins over unknown; true wins over false (a flag that fired stays fired)
        rank = {E.TriState.TRUE: 2, E.TriState.FALSE: 1, E.TriState.UNKNOWN: 0}
        if current is None or rank[fl.value] > rank[current.value]:
            seen[key] = fl
    return sorted(seen.values(), key=lambda f: (f.flag.value, f.subject_ref))


__all__ = [
    "AGENT_KINDS",
    "CLIENT_SLUGS",
    "COLLECTOR_NAME",
    "DIALECT",
    "FINDING_MEDIA_TYPE",
    "OBSERVATION_ONLY_KINDS",
    "PARTY_ID",
    "REPORT_MEDIA_TYPE",
    "ShadowScanImport",
    "import_report",
    "map_report",
]
