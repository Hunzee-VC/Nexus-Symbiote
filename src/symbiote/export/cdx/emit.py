"""Emit CycloneDX 1.7 JSON directly from the semantic model (``spec/cyclonedx-mapping.md``)."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from symbiote import __version__
from symbiote.digest.envelope import strip_prefix
from symbiote.digest.jcs import canonical_bytes
from symbiote.model import enums as E
from symbiote.model.common import Claim, Provenance
from symbiote.model.document import AgentBOM
from symbiote.model.entities import (
    Agent,
    DataSource,
    Entity,
    Instruction,
    LossItem,
    LossReport,
    Model,
    Policy,
    PromptTemplate,
    Skill,
    SoftwareComponent,
    ToolDefinition,
    ToolServer,
)
from symbiote.model.ids import uuid5_for_digest

CDX_SCHEMA_URI = "http://cyclonedx.org/schema/bom-1.7.schema.json"
SPEC_VERSION_PROFILE = "0.1"
PRODUCER_REF = "producer:symbiote"

_LIFECYCLE_PHASE = {
    E.SnapshotKind.DECLARED: "design",
    E.SnapshotKind.APPROVED: "post-build",
    E.SnapshotKind.DEPLOYED: "operations",
    E.SnapshotKind.OBSERVED: "discovery",
}
_KIND_BY_SERVER = {
    E.ToolServerKind.MCP: "mcp-server",
    E.ToolServerKind.A2A: "a2a-agent",
    E.ToolServerKind.OPENAPI: "openapi-service",
    E.ToolServerKind.BUILTIN: "builtin",
}
_KIND_BY_DATA = {
    E.DataSourceKind.DATASET: "dataset",
    E.DataSourceKind.RAG_INDEX: "rag-index",
    E.DataSourceKind.MEMORY_STORE: "memory-store",
    E.DataSourceKind.RETRIEVAL_CONNECTOR: "retrieval-connector",
    E.DataSourceKind.KNOWLEDGE_PLUGIN: "knowledge-plugin",
    E.DataSourceKind.LIVE_FEED: "live-feed",
    E.DataSourceKind.TOOL_OUTPUT_CHANNEL: "live-feed",
}
_CDX_DATA_TYPE = {
    E.DataSourceKind.DATASET: "dataset",
    E.DataSourceKind.RAG_INDEX: "dataset",
    E.DataSourceKind.MEMORY_STORE: "other",
    E.DataSourceKind.RETRIEVAL_CONNECTOR: "configuration",
    E.DataSourceKind.KNOWLEDGE_PLUGIN: "other",
    E.DataSourceKind.LIVE_FEED: "other",
    E.DataSourceKind.TOOL_OUTPUT_CHANNEL: "other",
}
_VEX_STATE = {
    "affected": "exploitable",
    "not-affected": "not_affected",
    "under-investigation": "in_triage",
    "fixed": "resolved",
}
_VEX_JUSTIFICATION = {
    "tool-disabled": "code_not_present",
    "guardrail-enforced": "protected_by_mitigating_control",
    "approval-required": "protected_at_runtime",
    "egress-denied": "protected_at_perimeter",
    "not-reachable": "code_not_reachable",
    "scope-restricted": "requires_configuration",
    "component-not-present": "code_not_present",
    "evaluated-resistant": "protected_by_mitigating_control",
}
_EDGE_PROP = {
    E.EdgeType.USES_MODEL: "uses-model",
    E.EdgeType.INVOKES_TOOL: "invokes-tool",
    E.EdgeType.PROVIDES_TOOL: "provides-tool",
    E.EdgeType.DELEGATES_TO: "delegates-to",
    E.EdgeType.SPAWNS: "spawns",
    E.EdgeType.LOADS_INSTRUCTION: "loads-instruction",
    E.EdgeType.READS_CONTEXT_FROM: "reads-context-from",
    E.EdgeType.READS_MEMORY_FROM: "reads-memory-from",
    E.EdgeType.WRITES_MEMORY_TO: "writes-memory-to",
    E.EdgeType.ACTS_AS: "acts-as",
    E.EdgeType.HOLDS_CREDENTIAL: "holds-credential",
    E.EdgeType.RESOLVED_FROM: "resolved-from",
    E.EdgeType.DERIVED_FROM: "derived-from",
    E.EdgeType.EMBEDS: "embeds",
    E.EdgeType.EVALUATED_BY: "evaluated-by",
    E.EdgeType.SENDS_DATA_TO: "sends-data-to",
}
_DEPENDS_EDGES = {
    E.EdgeType.DEPENDS_ON,
    E.EdgeType.USES_MODEL,
    E.EdgeType.INVOKES_TOOL,
    E.EdgeType.LOADS_INSTRUCTION,
    E.EdgeType.READS_CONTEXT_FROM,
    E.EdgeType.READS_MEMORY_FROM,
    E.EdgeType.WRITES_MEMORY_TO,
    E.EdgeType.EMBEDS,
    E.EdgeType.DELEGATES_TO,
    E.EdgeType.SPAWNS,
}
_SURFACE_ASSEMBLIES = {
    E.Surface.TOOLS: ("tool_servers", "tools"),
    E.Surface.INSTRUCTIONS: ("instructions", "prompts", "skills"),
    E.Surface.MODEL_GATEWAY: ("models",),
    E.Surface.DATA: ("data_sources",),
    E.Surface.CODE: ("software",),
    E.Surface.POLICY: ("policies",),
    E.Surface.IDENTITY: ("identities", "credential_bindings"),
    E.Surface.REGISTRY: ("resolutions",),
    E.Surface.RUNTIME: ("deployments",),
    E.Surface.NETWORK: (),
}
_AGGREGATE = {
    E.Completeness.COMPLETE: "complete",
    E.Completeness.INCOMPLETE: "incomplete",
    E.Completeness.UNKNOWN: "unknown",
}


# ------------------------------------------------------------------------------------------------ helpers


def _iso(dt: datetime | None) -> str | None:
    return (
        None if dt is None else dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _s(value: Any) -> str | None:
    """Render a property value as a string (bools lowercase, enums by value, None skipped)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


class Props:
    """Ordered, de-duplicated property list builder."""

    def __init__(self) -> None:
        self.items: list[dict[str, str]] = []

    def add(self, name: str, value: Any) -> None:
        v = _s(value)
        if v is None or v == "":
            return
        entry = {"name": name, "value": v}
        if entry not in self.items:
            self.items.append(entry)

    def add_many(self, name: str, values: Iterable[Any]) -> None:
        for v in values:
            self.add(name, v)

    def add_json(self, name: str, value: Any) -> None:
        if value is None:
            return
        self.add(name, canonical_bytes(value).decode("utf-8"))

    def claim(self, name: str, claim: Claim[Any] | None) -> None:
        """Emit a claim's value (or unknown reason) plus its assurance/state qualifiers."""
        if claim is None:
            return
        if claim.state is E.ValueState.UNKNOWN:
            self.add(f"{name}:unknown-reason", claim.unknown_reason)
        elif claim.value is not None:
            self.add(name, claim.value)
        self.add(f"{name}:assurance", claim.assurance)
        if claim.locator:
            self.add(f"{name}:locator", claim.locator)

    def provenance(self, prov: Provenance) -> None:
        self.add("agentbom:assurance", prov.assurance)
        if prov.locator:
            self.add("agentbom:evidence:locator", prov.locator)
        if prov.collector:
            self.add("agentbom:evidence:collector", prov.collector.split(":", 1)[1])
        if prov.method:
            self.add("agentbom:evidence:source", prov.method)
        if prov.observed_at:
            self.add("agentbom:evidence:collected-at", _iso(prov.observed_at))
        self.add_many("agentbom:evidence:ref", (e.digest for e in prov.evidence))

    def build(self) -> list[dict[str, str]] | None:
        return sorted(self.items, key=lambda p: (p["name"], p["value"])) or None


def _hash(digest: str | None) -> list[dict[str, str]] | None:
    return [{"alg": "SHA-256", "content": strip_prefix(digest)}] if digest else None


def _clean(obj: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in obj.items() if v is not None and v not in ([], {})}


def _party(bom: AgentBOM, ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    party = next((p for p in bom.parties if p.id == ref), None)
    if party is None:
        return {"name": ref}
    return _clean(
        {
            "name": party.name,
            "url": party.urls or None,
            "contact": [_clean({"name": c.name, "email": c.email}) for c in party.contacts] or None,
        }
    )


# ------------------------------------------------------------------------------------------------ builders


class _Builder:
    def __init__(
        self,
        bom: AgentBOM,
        *,
        include_text: bool,
        companion_digest: str | None,
        companion_ref: str | None,
        profile: str,
    ) -> None:
        self.bom = bom
        self.include_text = include_text
        self.companion_digest = companion_digest
        self.companion_ref = companion_ref
        self.profile = profile
        self.loss: list[LossItem] = []
        self.element_refs: set[str] = set()
        self.grants_by_subject: dict[str, list] = {}
        for g in bom.grants:
            self.grants_by_subject.setdefault(g.subject_ref, []).append(g)
        self.identity_by_id = {i.id: i for i in bom.identities}
        self.bindings_by_subject: dict[str, list] = {}
        for cb in bom.credential_bindings:
            self.bindings_by_subject.setdefault(cb.subject_ref, []).append(cb)
        self.edges_from: dict[str, list] = {}
        for e in bom.edges:
            self.edges_from.setdefault(e.from_ref, []).append(e)

    # ---- cross-cutting

    def _lose(
        self,
        path: str,
        reason: E.LossReason,
        preserved: E.LossPreservedIn,
        severity: E.LossSeverity = E.LossSeverity.INFO,
        *,
        entity: str | None = None,
        field: str | None = None,
    ) -> None:
        self.loss.append(
            LossItem(
                path=path,
                entity=entity,
                field=field,
                reason=reason,
                preserved_in=preserved,
                severity=severity,
            )
        )

    def _authority_props(self, props: Props, subject_id: str) -> None:
        for i, g in enumerate(sorted(self.grants_by_subject.get(subject_id, []), key=lambda g: g.id)):
            p = f"agentbom:authz:{i}"
            props.add(f"{p}:id", g.id)
            props.add(f"{p}:layer", g.layer)
            props.add(f"{p}:capability", g.capability)
            props.add_many(f"{p}:scope:resource", g.scope.resources)
            props.add_many(f"{p}:scope:egress", g.scope.egress)
            props.add_many(f"{p}:scope:data-class", g.scope.data_classes)
            props.add(f"{p}:granter", g.granter_ref)
            props.add(f"{p}:approval-gate", g.approval_gate)
            props.add(f"{p}:not-before", _iso(g.validity.not_before))
            props.add(f"{p}:not-after", _iso(g.validity.not_after))
            props.add(f"{p}:policy-digest", g.policy_ref.bundle_digest if g.policy_ref else None)
            props.add(f"{p}:enforcement-point", g.enforcement_point.kind)
            props.add(f"{p}:enforcement-attested", g.enforcement_point.attested)
            props.add(f"{p}:credential-binding", g.credential_binding_ref)
            props.add(f"{p}:assurance", g.provenance.assurance)
            if g.delegation_chain:
                props.add_json(f"{p}:delegation-chain:json", [h.to_json_dict() for h in g.delegation_chain])
            self._lose(
                f"/grants/{g.id}",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.PROPERTY,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=g.id,
            )
        for i, cb in enumerate(sorted(self.bindings_by_subject.get(subject_id, []), key=lambda c: c.id)):
            p = f"agentbom:credential:{i}"
            props.add(f"{p}:identity", cb.identity_ref)
            props.add(f"{p}:kind", cb.credential_kind)
            props.add(f"{p}:lifetime", cb.lifetime)
            props.add(f"{p}:storage-kind", cb.storage.kind)
            props.add(f"{p}:storage-locator", cb.storage.locator)
            if cb.scopes_granted and cb.scopes_granted.value:
                for j, sc in enumerate(cb.scopes_granted.value):
                    props.add(f"{p}:scope-granted:{j}", sc)
            ident = self.identity_by_id.get(cb.identity_ref)
            if ident is not None:
                q = f"agentbom:identity:{i}"
                props.add(f"{q}:kind", ident.identity_kind)
                props.add(f"{q}:ref", ident.ref)
                props.add(f"{q}:issuer", ident.issuer)
                props.add(f"{q}:tenant", ident.tenant)
            self._lose(
                f"/credentialBindings/{cb.id}",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.PROPERTY,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=cb.id,
            )

    def _edge_props(self, props: Props, source_id: str) -> None:
        for e in sorted(self.edges_from.get(source_id, []), key=lambda e: e.key):
            name = _EDGE_PROP.get(e.type)
            if name:
                props.add(f"agentbom:edge:{name}", e.to_ref)
            if e.qualifiers:
                self._lose(
                    f"/edges/{e.type.value}:{e.from_ref}->{e.to_ref}/qualifiers",
                    E.LossReason.NO_NATIVE_CONSTRUCT,
                    E.LossPreservedIn.COMPANION,
                    entity=e.from_ref,
                    field="qualifiers",
                )

    def _trust_props(self, props: Props, entity: Entity) -> None:
        if entity.trust_ref:
            ts = next((t for t in self.bom.trust_status if t.id == entity.trust_ref), None)
            if ts is not None:
                props.add("agentbom:trust:status", ts.status)
                props.add("agentbom:trust:reason", ts.reason)
                props.add("agentbom:trust:decided-by", ts.decided_by_ref)
                props.add("agentbom:trust:decided-at", _iso(ts.decided_at))
                props.add("agentbom:trust:expires", _iso(ts.expires))
                props.add("agentbom:trust:serial", ts.serial)

    def _common_props(self, props: Props, entity: Entity, kind: str) -> None:
        props.add("agentbom:kind", kind)
        props.provenance(entity.provenance)
        self._authority_props(props, entity.id)
        self._edge_props(props, entity.id)
        self._trust_props(props, entity)
        for k, v in sorted(entity.foreign.items()):
            props.add(k, v)
        if entity.foreign:
            props.add("agentbom:import:dialect", "generic")
        leaf = next(
            (leaf for leaf in (self.bom.merkle.leaves if self.bom.merkle else []) if leaf.id == entity.id),
            None,
        )
        if leaf is not None:
            props.add("agentbom:merkle:leaf", leaf.leaf_hash)

    def _ext_refs(self, entity: Entity) -> list[dict[str, Any]] | None:
        refs = [
            _clean(
                {
                    "type": r.type,
                    "url": r.url,
                    "comment": r.comment,
                    "hashes": [{"alg": "SHA-256", "content": strip_prefix(d)} for d in r.digests] or None,
                }
            )
            for r in entity.external_refs
        ]
        return refs or None

    # ---- components

    def agent(self, a: Agent, *, root: bool) -> dict[str, Any]:
        props = Props()
        self._common_props(
            props,
            a,
            "agent"
            if a.role is E.AgentRole.ROOT
            else ("sub-agent" if a.role is E.AgentRole.SUB_AGENT else "external-agent"),
        )
        props.add("agentbom:agent:role", a.role)
        props.add("agentbom:agent:digest", a.digest)
        if a.framework and a.framework.value:
            props.add("agentbom:agent:framework", a.framework.value.name)
            props.add("agentbom:agent:framework-version", a.framework.value.version)
        props.add("agentbom:agent:owner", a.owner_ref)
        props.add("agentbom:agent:operator", a.operator_ref)
        props.claim("agentbom:agent:automation-level", a.automation_level)
        for i, ap in enumerate(a.autonomy_profile):
            props.add(f"agentbom:agent:autonomy:{i}:capability", ap.capability)
            props.add(f"agentbom:agent:autonomy:{i}:mode", ap.mode)
        if a.autonomy_assessment is not None:
            aa = a.autonomy_assessment
            props.add("agentbom:agent:autonomy-assessment:scale", aa.scale)
            props.add("agentbom:agent:autonomy-assessment:floor", aa.floor)
            props.add("agentbom:agent:autonomy-assessment:ceiling", aa.ceiling)
            props.add("agentbom:agent:autonomy-assessment:floor-level", aa.floor_level)
            props.add("agentbom:agent:autonomy-assessment:ceiling-level", aa.ceiling_level)
            props.add("agentbom:agent:autonomy-assessment:oversight", aa.oversight)
            props.add("agentbom:agent:autonomy-assessment:initiation", aa.initiation)
            props.add("agentbom:agent:autonomy-assessment:declared", aa.declared)
            props.add("agentbom:agent:autonomy-assessment:declared-source", aa.declared_source)
            props.add("agentbom:agent:autonomy-assessment:assessor", aa.assessor)
            props.add("agentbom:agent:autonomy-assessment:assurance", aa.assurance)
            props.add_many(
                "agentbom:agent:autonomy-assessment:basis",
                (f"{b.bound}:{b.rule}={b.value}" for b in aa.basis),
            )
            props.add_many("agentbom:agent:autonomy-assessment:evidence", (e.digest for e in aa.evidence))
        props.add("agentbom:agent:entrypoint", a.entrypoint)
        props.add("agentbom:agent:parent", a.parent_ref)
        props.claim("agentbom:agent:policy-bundle-digest", a.policy_bundle)
        for ident in a.identities:
            props.add("agentbom:identity:ref", ident)
        ext = list(self._ext_refs(a) or [])
        if a.a2a_card:
            props.add("agentbom:a2a:card-digest", a.a2a_card.digest)
            props.add("agentbom:a2a:card-url", a.a2a_card.url)
            props.add_many("agentbom:a2a:protocol-version", a.a2a_card.protocol_versions)
            props.add_many("agentbom:a2a:skill", (s.id for s in a.a2a_card.skills))
            props.add_many("agentbom:a2a:security-scheme", a.a2a_card.security_schemes)
            props.add("agentbom:a2a:signature-status", a.a2a_card.signature_status)
            if a.a2a_card.url:
                ext.append(
                    {
                        "type": "other",
                        "url": a.a2a_card.url,
                        "comment": "a2a-agent-card",
                        "hashes": _hash(a.a2a_card.digest),
                    }
                )
        if root and self.companion_ref:
            ext.append(
                _clean(
                    {
                        "type": "other",
                        "url": self.companion_ref,
                        "comment": "agentbom-companion",
                        "hashes": _hash(self.companion_digest),
                    }
                )
            )
        return _clean(
            {
                "type": "application",
                "bom-ref": a.id,
                "name": a.name or a.id,
                "version": a.version,
                "description": a.purpose,
                "supplier": _party(self.bom, a.owner_ref),
                "manufacturer": _party(self.bom, a.operator_ref),
                "externalReferences": ext or None,
                "properties": props.build(),
                "tags": ["agent"],
            }
        )

    def tool_server(self, s: ToolServer) -> tuple[dict[str, Any], dict[str, Any] | None]:
        props = Props()
        self._common_props(props, s, _KIND_BY_SERVER[s.server_kind])
        props.add("agentbom:mcp:kind", s.server_kind)
        props.add("agentbom:mcp:client", s.client)
        props.claim("agentbom:mcp:transport", s.transport)
        endpoint = s.endpoint.value if s.endpoint and s.endpoint.value else None
        props.add("agentbom:mcp:endpoint-origin", endpoint)
        props.add("agentbom:mcp:command", s.command)
        props.add("agentbom:mcp:args-digest", s.args_digest)
        package = None
        if s.package and s.package.value:
            pk = s.package.value
            props.add("agentbom:mcp:launcher", pk.launcher)
            props.add("agentbom:mcp:package-purl", pk.purl)
            props.add("agentbom:mcp:pinned", not pk.floating)
            if pk.purl:
                package = _clean(
                    {
                        "type": "application",
                        "bom-ref": f"{s.id}/package",
                        "name": pk.purl.split("/")[-1].split("@")[0],
                        "purl": pk.purl,
                        "hashes": _hash(pk.digest),
                        "properties": [
                            {"name": "agentbom:kind", "value": "mcp-package"},
                            {"name": "agentbom:mcp:pinned", "value": "false" if pk.floating else "true"},
                        ],
                    }
                )
        elif s.package and s.package.is_unknown:
            props.add("agentbom:mcp:pinned", "unknown")
        props.add_many("agentbom:mcp:env-var-name", s.env_var_names)
        props.add_many("agentbom:mcp:header-name", s.header_names)
        if s.authentication.value:
            props.add("agentbom:mcp:auth-mode", s.authentication.value.mode)
            props.add("agentbom:mcp:auth-issuer", s.authentication.value.issuer)
            props.add_many("agentbom:mcp:scope-requested", s.authentication.value.scopes_requested)
        else:
            props.claim("agentbom:mcp:auth-mode", s.authentication)
        props.add("agentbom:mcp:trust-zone", s.trust_zone)
        props.claim("agentbom:mcp:crosses-trust-boundary", s.crosses_trust_boundary)
        props.claim("agentbom:mcp:protocol-version", s.protocol_version)
        if s.server_info and s.server_info.value:
            props.add("agentbom:mcp:server-name", s.server_info.value.name)
            props.add("agentbom:mcp:server-version", s.server_info.value.version)
        props.claim("agentbom:mcp:instructions-digest", s.instructions_digest)
        props.claim("agentbom:mcp:toolset-digest", s.toolset_digest)
        if s.toolset_digest_result:
            props.add("agentbom:mcp:toolset-digest-status", s.toolset_digest_result.status)
        props.add("agentbom:mcp:tool-count", len([t for t in self.bom.tools if t.server_ref == s.id]))
        props.add("agentbom:mcp:server-digest", s.digest)
        if s.tool_list_meta:
            props.add("agentbom:mcp:tools-list-ttl-ms", s.tool_list_meta.ttl_ms)
            props.add("agentbom:mcp:tools-list-cache-scope", s.tool_list_meta.cache_scope)
        for k, v in sorted(s.client_trust_flags.items()):
            props.add(f"agentbom:mcp:client-trust:{k}", v)
        if s.registry_resolution_ref:
            res = next((r for r in self.bom.resolutions if r.id == s.registry_resolution_ref), None)
            if res:
                self._resolution_props(props, res)
        ext = list(self._ext_refs(s) or [])
        if s.provenance.locator:
            ext.append(
                {
                    "type": "configuration",
                    "url": "file://" + s.provenance.locator.split("#", 1)[0]
                    if not s.provenance.locator.startswith(("file:", "http"))
                    else s.provenance.locator,
                    "comment": "agentbom:source-locator",
                }
            )
        authenticated = None
        if s.authentication.value:
            authenticated = s.authentication.value.mode is not E.AuthMode.NONE
        trust_boundary = (
            s.crosses_trust_boundary.value if s.crosses_trust_boundary.state is E.ValueState.PRESENT else None
        )
        service = _clean(
            {
                "bom-ref": s.id,
                "name": s.name or s.id.split(":", 1)[1],
                "group": s.client,
                "description": s.description,
                "version": s.server_info.value.version if s.server_info and s.server_info.value else None,
                "endpoints": [endpoint] if endpoint else None,
                "authenticated": authenticated,
                "x-trust-boundary": trust_boundary,
                "trustZone": s.trust_zone.value if s.trust_zone is not E.TrustZone.UNKNOWN else None,
                "externalReferences": ext or None,
                "properties": props.build(),
            }
        )
        return service, package

    def tool(self, t: ToolDefinition) -> dict[str, Any]:
        props = Props()
        self._common_props(props, t, "tool")
        props.add("agentbom:tool:server-ref", t.server_ref)
        props.add("agentbom:tool:definition-digest", t.digest.value)
        props.add("agentbom:tool:definition-digest-status", t.digest.status)
        props.add("agentbom:tool:definition-digest-reason", t.digest.reason)
        if t.full_digest:
            props.add("agentbom:tool:full-digest", t.full_digest.value)
        props.add("agentbom:tool:description-digest", t.description_digest)
        props.add("agentbom:tool:input-schema-digest", t.input_schema_digest)
        props.add("agentbom:tool:source", t.source)
        if t.annotations is not None and t.annotations.value is not None:
            ann = t.annotations.value
            for key, val in (
                ("read-only", ann.read_only_hint),
                ("destructive", ann.destructive_hint),
                ("idempotent", ann.idempotent_hint),
                ("open-world", ann.open_world_hint),
            ):
                props.add(f"agentbom:tool:annotation:{key}", "absent" if val is None else val)
        props.add("agentbom:tool:side-effect-class", t.side_effect_class)
        props.add_many("agentbom:tool:capability", t.capabilities)
        if t.required_scopes and t.required_scopes.value:
            props.add_many("agentbom:tool:required-scope", t.required_scopes.value)
        props.add("agentbom:tool:approval-gate", t.approval_gate)
        props.add_many("agentbom:tool:text-flag", t.text_flags)
        props.add("agentbom:tool:state", t.state)
        props.add("agentbom:tool:invocation-count", t.invocation_count)
        props.add("agentbom:tool:first-seen", _iso(t.first_seen))
        props.add("agentbom:tool:last-seen", _iso(t.last_seen))
        data: dict[str, Any] = {"type": "definition", "name": t.tool_name}
        if self.include_text:
            payload = {
                "name": t.tool_name,
                "title": t.title,
                "description": t.description,
                "inputSchema": t.input_schema,
                "outputSchema": t.output_schema,
            }
            payload = {k: v for k, v in payload.items() if v is not None}
            data["contents"] = {
                "attachment": {
                    "contentType": "application/json",
                    "encoding": "base64",
                    "content": base64.b64encode(canonical_bytes(payload)).decode("ascii"),
                }
            }
        else:
            self._lose(
                f"/tools/{t.id}/inputSchema",
                E.LossReason.REDACTED,
                E.LossPreservedIn.COMPANION,
                entity=t.id,
                field="input_schema",
            )
        return _clean(
            {
                "type": "data",
                "bom-ref": t.id,
                "name": t.tool_name,
                "group": t.server_ref,
                "description": t.description if self.include_text else None,
                "hashes": _hash(t.digest.value),
                "data": [data],
                "properties": props.build(),
                "tags": ["mcp-tool"],
            }
        )

    def instruction(self, i: Instruction) -> dict[str, Any]:
        props = Props()
        self._common_props(props, i, "instruction")
        props.add("agentbom:instruction:kind", i.instruction_kind)
        props.add("agentbom:instruction:path", i.path or i.uri)
        props.add("agentbom:instruction:size", i.size)
        props.add("agentbom:instruction:media-type", i.media_type)
        props.add("agentbom:instruction:line-endings", i.line_endings)
        props.add("agentbom:instruction:precedence", i.precedence)
        if i.editors and i.editors.value:
            props.add_many("agentbom:instruction:editor", i.editors.value)
        if i.loads_remote and i.loads_remote.value:
            props.add_many("agentbom:instruction:loads-remote", i.loads_remote.value)
        props.add("agentbom:instruction:secret-like-redacted", i.contains_secret_like)
        props.add("agentbom:instruction:normalized-digest", i.normalized_digest)
        ext = list(self._ext_refs(i) or [])
        if i.source and i.source.vcs_url:
            ext.append(_clean({"type": "vcs", "url": i.source.vcs_url, "comment": i.source.revision}))
        name = (i.path or i.uri or i.id).rsplit("/", 1)[-1]
        return _clean(
            {
                "type": "file",
                "bom-ref": i.id,
                "name": name,
                "mime-type": i.media_type,
                "hashes": _hash(i.digest),
                "externalReferences": ext or None,
                "properties": props.build(),
                "tags": ["instruction"],
            }
        )

    def prompt(self, p: PromptTemplate) -> dict[str, Any]:
        props = Props()
        self._common_props(props, p, "prompt-template")
        props.add("agentbom:prompt:engine", p.engine)
        props.add("agentbom:prompt:role", p.role)
        props.add("agentbom:prompt:digest", p.digest.value)
        props.add("agentbom:prompt:variables-schema-digest", p.variables_schema_digest)
        props.add("agentbom:prompt:risk-class", p.risk_class)
        return _clean(
            {
                "type": "file",
                "bom-ref": p.id,
                "name": (p.path or p.id).rsplit("/", 1)[-1],
                "hashes": _hash(p.template_digest),
                "properties": props.build(),
                "tags": ["prompt-template"],
            }
        )

    def skill(self, s: Skill) -> dict[str, Any]:
        props = Props()
        self._common_props(props, s, "skill")
        props.add("agentbom:skill:name", s.frontmatter.name)
        props.add("agentbom:skill:manifest-root", s.digest)
        props.add(
            "agentbom:skill:skill-md-digest",
            next((i.digest for i in self.bom.instructions if i.id == s.skill_md_ref), None),
        )
        props.add_many("agentbom:skill:allowed-tool", s.frontmatter.allowed_tools)
        props.add("agentbom:skill:compatibility", s.frontmatter.compatibility)
        props.add("agentbom:skill:file-count", len(s.manifest.resources))
        props.add("agentbom:skill:script-count", len(s.scripts))
        props.add("agentbom:skill:has-scripts", s.has_scripts)
        props.add("agentbom:skill:name-matches-directory", s.name_matches_directory)
        nested = [
            _clean(
                {
                    "type": "file",
                    "bom-ref": f"{s.id}/{sc.path}",
                    "name": sc.path,
                    "hashes": _hash(sc.digest),
                    "properties": [{"name": "agentbom:kind", "value": "skill-script"}]
                    + (
                        [{"name": "agentbom:skill:interpreter", "value": sc.interpreter}]
                        if sc.interpreter
                        else []
                    ),
                }
            )
            for sc in s.scripts
        ]
        return _clean(
            {
                "type": "library",
                "bom-ref": s.id,
                "name": s.frontmatter.name or s.id.split(":", 1)[1],
                "group": "skills",
                "version": str(s.frontmatter.metadata.get("version"))
                if s.frontmatter.metadata.get("version")
                else None,
                "description": s.frontmatter.description,
                "hashes": _hash(s.digest),
                "components": nested or None,
                "properties": props.build(),
                "tags": ["skill"],
            }
        )

    def model(self, m: Model) -> tuple[dict[str, Any], dict[str, Any] | None]:
        props = Props()
        self._common_props(props, m, "model")
        props.add("agentbom:model:kind", m.model_kind)
        version = None
        purl = None
        hashes = None
        supplier = None
        external = False
        endpoint_service = None
        if m.hosted is not None:
            if m.hosted.value:
                h = m.hosted.value
                props.add("agentbom:model:provider", h.provider)
                props.add("agentbom:model:requested-ref", h.requested_ref)
                props.claim("agentbom:model:resolved-ref", h.resolved_ref)
                props.add("agentbom:model:alias-pinning", h.alias_pinning)
                props.add("agentbom:model:endpoint-origin", h.endpoint_origin)
                if h.fingerprint:
                    props.add("agentbom:model:fingerprint:method", h.fingerprint.method)
                    props.add("agentbom:model:fingerprint:digest", h.fingerprint.digest)
                    props.add("agentbom:model:fingerprint:expires", _iso(h.fingerprint.expires))
                version = h.resolved_ref.value if h.resolved_ref.value else None
                supplier = {"name": h.provider}
                external = True
                if h.endpoint_origin:
                    endpoint_service = _clean(
                        {
                            "bom-ref": f"{m.id}/endpoint",
                            "name": h.provider,
                            "endpoints": [h.endpoint_origin],
                            "x-trust-boundary": True,
                            "provider": {"name": h.provider},
                            "properties": [
                                {"name": "agentbom:kind", "value": "openapi-service"},
                                {"name": "agentbom:model:endpoint-origin", "value": h.endpoint_origin},
                            ],
                        }
                    )
            else:
                props.claim("agentbom:model:requested-ref", m.hosted)
        if m.weights is not None:
            if m.weights.value:
                w = m.weights.value
                purl = w.purl
                hashes = _hash(w.manifest_root)
                props.add("agentbom:model:manifest-format", "oms-v1")
                props.add("agentbom:model:manifest-root", w.manifest_root)
                props.add("agentbom:model:manifest-ref", w.manifest_ref)
                props.add("agentbom:model:manifest-items", w.file_count)
                props.add_many("agentbom:model:serialization:format", w.formats)
            else:
                props.claim("agentbom:model:manifest-root", m.weights)
        props.add("agentbom:model:tensor-manifest-root", m.tensor_manifest_root)
        if m.serialization and m.serialization.value:
            ser = m.serialization.value
            props.add_many("agentbom:model:serialization:format", ser.formats)
            props.add("agentbom:model:serialization:risk", ser.risk_class)
            props.add("agentbom:model:trust-remote-code", ser.trust_remote_code)
            props.add("agentbom:model:chat-template-executable", ser.chat_template_executable)
            props.add(
                "agentbom:model:scanner",
                f"{ser.scanner_name}@{ser.scanner_version}" if ser.scanner_name else None,
            )
            props.add("agentbom:model:scanner-report-digest", ser.scanner_report_digest)
        ancestors = []
        for i, d in enumerate(m.derivations):
            props.add(f"agentbom:model:derivation:{i}:kind", d.kind)
            props.add(f"agentbom:model:derivation:{i}:parent", d.parent)
            props.add(f"agentbom:model:derivation:{i}:parameters-digest", d.parameters_digest)
            if d.parameters:
                props.add_json(f"agentbom:model:derivation:{i}:parameters:json", d.parameters)
            ancestors.append(
                _clean(
                    {
                        "type": "machine-learning-model",
                        "name": d.parent,
                        "properties": [{"name": "agentbom:derivation:kind", "value": d.kind.value}],
                    }
                )
            )
        if m.signature:
            sig = m.signature
            props.add("agentbom:model:signature:status", sig.status)
            props.add("agentbom:model:signature:outcome", sig.outcome)
            props.add("agentbom:model:signature:reason", sig.reason)
            props.add("agentbom:model:signature:identity", sig.identity)
            props.add("agentbom:model:signature:issuer", sig.issuer)
            props.add("agentbom:model:signature:log-entry", sig.log_entry)
            props.add("agentbom:model:signature:subject-name-mismatch", sig.subject_name_mismatch)
            props.add("agentbom:model:signature:bundle-digest", sig.bundle_digest)
        props.add(
            "agentbom:model:chat-template-digest",
            next((i.digest for i in self.bom.instructions if i.id == m.chat_template_ref), None),
        )
        props.add("agentbom:model:generation-config-digest", m.generation_config_digest)
        model_card = None
        if m.card:
            params = _clean(
                {
                    "task": m.card.task,
                    "architectureFamily": m.card.architecture,
                    "approach": {"type": m.card.approach}
                    if m.card.approach
                    in (
                        "supervised",
                        "unsupervised",
                        "reinforcement-learning",
                        "semi-supervised",
                        "self-supervised",
                    )
                    else None,
                }
            )
            considerations = _clean(
                {
                    "technicalLimitations": [m.card.limitations] if m.card.limitations else None,
                    "users": [m.card.users] if m.card.users else None,
                    "useCases": [m.card.use_cases] if m.card.use_cases else None,
                }
            )
            model_card = (
                _clean({"modelParameters": params or None, "considerations": considerations or None}) or None
            )
        comp = _clean(
            {
                "type": "machine-learning-model",
                "bom-ref": m.id,
                "name": m.name or m.id.split(":", 1)[1],
                "version": version,
                "purl": purl,
                "hashes": hashes,
                "supplier": supplier,
                "isExternal": True if external else None,
                "modelCard": model_card,
                "pedigree": {"ancestors": ancestors} if ancestors else None,
                "externalReferences": self._ext_refs(m),
                "properties": props.build(),
                "tags": ["model"],
            }
        )
        return comp, endpoint_service

    def data_source(self, d: DataSource) -> dict[str, Any]:
        props = Props()
        self._common_props(props, d, _KIND_BY_DATA[d.data_kind])
        props.add("agentbom:data:kind", d.data_kind)
        props.add("agentbom:data:classification", d.classification)
        props.add_many("agentbom:data:data-class", d.data_classes)
        props.add("agentbom:data:trust-tier", d.trust_tier)
        props.claim("agentbom:data:instruction-bearing", d.instruction_bearing)
        for i, s in enumerate(d.sanitization):
            props.add(f"agentbom:data:sanitization:{i}:name", s.name)
            props.add(f"agentbom:data:sanitization:{i}:digest", s.digest)
        if d.snapshot and d.snapshot.value:
            props.add("agentbom:data:snapshot:commitment", d.snapshot.value.commitment)
            props.add("agentbom:data:snapshot:method", d.snapshot.value.method)
            props.add("agentbom:data:snapshot:at", _iso(d.snapshot.value.at))
        props.add("agentbom:data:live", d.live)
        props.add("agentbom:data:refresh-policy", d.refresh_policy)
        props.add("agentbom:data:embedding-model", d.embedding_model_ref)
        if d.chunking:
            props.add_json("agentbom:data:chunking:json", d.chunking.to_json_dict())
        for i, src in enumerate(d.sources):
            props.add(f"agentbom:data:source:{i}:uri", src.uri)
            props.add(f"agentbom:data:source:{i}:digest", src.digest)
            props.add(f"agentbom:data:source:{i}:fetched-at", _iso(src.fetched_at))
            props.add(f"agentbom:data:source:{i}:license", src.license)
            props.add(f"agentbom:data:source:{i}:consent-status", src.consent_status)
        props.add("agentbom:data:acl-mode", d.acl_mode)
        if d.writers:
            if d.writers.value:
                props.add_many("agentbom:data:writer", d.writers.value)
            else:
                props.claim("agentbom:data:writer", d.writers)
        props.add("agentbom:data:tenant-isolation", d.tenant_isolation)
        props.add("agentbom:data:retention", d.retention)
        if d.quarantine:
            props.add("agentbom:data:quarantine-status", d.quarantine.status)
            props.add("agentbom:data:quarantine-since", _iso(d.quarantine.since))
        props.add_many("agentbom:data:invalidation-dependent", d.invalidation_dependents)
        props.add("agentbom:data:poison-scan-digest", d.poison_scan.digest if d.poison_scan else None)
        data_entry = _clean(
            {
                "type": _CDX_DATA_TYPE[d.data_kind],
                "name": d.name or d.id.split(":", 1)[1],
                "classification": d.classification.value
                if d.classification is not E.Classification.UNKNOWN
                else None,
                "contents": {"url": d.location} if d.location else None,
            }
        )
        return _clean(
            {
                "type": "data",
                "bom-ref": d.id,
                "name": d.name or d.id.split(":", 1)[1],
                "hashes": _hash(d.snapshot.value.commitment) if d.snapshot and d.snapshot.value else None,
                "data": [data_entry],
                "properties": props.build(),
                "tags": [_KIND_BY_DATA[d.data_kind]],
            }
        )

    def policy(self, p: Policy) -> dict[str, Any]:
        props = Props()
        self._common_props(props, p, "policy-bundle")
        props.add("agentbom:policy:kind", p.policy_kind)
        props.add("agentbom:policy:engine", p.engine)
        props.add("agentbom:policy:enforcement-point", p.enforcement_point.kind)
        props.add("agentbom:policy:bundle-digest", p.bundle_digest)
        return _clean(
            {
                "type": "data",
                "bom-ref": p.id,
                "name": p.name or p.id.split(":", 1)[1],
                "hashes": _hash(p.bundle_digest),
                "data": [{"type": "configuration", "name": p.name or p.id}],
                "properties": props.build(),
            }
        )

    def software(self, s: SoftwareComponent) -> dict[str, Any]:
        if s.cyclonedx:
            comp = dict(s.cyclonedx)
            comp["bom-ref"] = s.id
            return comp
        return _clean(
            {
                "type": s.component_type,
                "bom-ref": s.id,
                "name": s.name or s.id,
                "version": s.version,
                "purl": s.purl,
                "hashes": [{"alg": "SHA-256", "content": strip_prefix(h)} for h in s.hashes] or None,
            }
        )

    def _resolution_props(self, props: Props, r: Any) -> None:
        props.add("agentbom:resolution:requested", r.requested.ref)
        props.add("agentbom:resolution:requested-kind", r.requested.kind)
        props.add("agentbom:resolution:resolved", r.resolved.immutable_ref)
        props.add("agentbom:resolution:resolved-digest", r.resolved.digest)
        props.add("agentbom:resolution:resolved-state", r.resolved.state)
        props.add("agentbom:resolution:resolved-at", _iso(r.resolved_at))
        props.add("agentbom:resolution:resolver", r.resolver)
        props.add("agentbom:resolution:alias-policy", r.alias_policy)
        if r.registry:
            props.add("agentbom:registry:url", r.registry.url)
            props.add("agentbom:registry:entry-id", r.registry.entry_id)
            props.add("agentbom:registry:entry-version", r.registry.version)
            props.add("agentbom:registry:status", r.registry.status)
            props.add("agentbom:registry:published-at", _iso(r.registry.published_at))
            props.add("agentbom:registry:is-latest", r.registry.is_latest)
        if r.publisher:
            props.add("agentbom:registry:publisher", r.publisher.identity or r.publisher.namespace)
            props.add("agentbom:registry:publisher-verification", r.publisher.verification)
        if r.signer:
            props.add("agentbom:resolution:signer-status", r.signer.status)
            props.add("agentbom:resolution:signer-outcome", r.signer.outcome)
            props.add("agentbom:resolution:signer-identity", r.signer.identity)
            props.add("agentbom:resolution:signer-issuer", r.signer.issuer)
        if r.transparency_log:
            props.add("agentbom:resolution:log-type", r.transparency_log.type)
            props.add("agentbom:resolution:log-index", r.transparency_log.log_index)
            props.add(
                "agentbom:resolution:log-inclusion-verified", r.transparency_log.inclusion_proof_verified
            )
        if r.typosquat_distance:
            props.add("agentbom:resolution:typosquat-nearest", r.typosquat_distance.nearest)
            props.add("agentbom:resolution:typosquat-distance", r.typosquat_distance.levenshtein)
        props.add_many("agentbom:resolution:warning", r.warnings)

    # ---- document-level

    def metadata_properties(self) -> list[dict[str, str]]:
        bom = self.bom
        props = Props()
        props.add("agentbom:spec-version", SPEC_VERSION_PROFILE)
        props.add("agentbom:snapshot:kind", bom.snapshot.kind)
        props.add("agentbom:snapshot:serial", bom.snapshot.serial)
        props.add("agentbom:snapshot:prev", bom.snapshot.prev or "none")
        props.add("agentbom:snapshot:digest", bom.snapshot.digest)
        props.add("agentbom:snapshot:not-before", _iso(bom.snapshot.validity.not_before))
        props.add("agentbom:snapshot:not-after", _iso(bom.snapshot.validity.not_after))
        if bom.snapshot.observation_window:
            props.add("agentbom:snapshot:observation-start", _iso(bom.snapshot.observation_window.start))
            props.add("agentbom:snapshot:observation-end", _iso(bom.snapshot.observation_window.end))
        if bom.merkle:
            props.add("agentbom:merkle:root", bom.merkle.root)
            props.add("agentbom:merkle:leaf-count", bom.merkle.leaf_count)
            props.add("agentbom:merkle:algorithm", bom.merkle.algorithm)
        props.add("agentbom:companion:ref", self.companion_ref)
        props.add("agentbom:companion:digest", self.companion_digest)
        if self.companion_ref or self.companion_digest:
            props.add(
                "agentbom:companion:schema",
                "https://aisecnomad.github.io/symbiote/schemas/agentbom/0.1/agentbom.schema.json",
            )
        for surface in E.Surface:
            cov = bom.coverage.surfaces.get(surface)
            if cov:
                props.add(f"agentbom:coverage:{surface.value}", cov.status)
                for src in cov.sources:
                    props.add(
                        "agentbom:coverage:source",
                        f"{src.source}@{src.locator or '-'}={'ok' if src.ok else (src.error_class or 'failed')}",
                    )
        if bom.coverage.window:
            props.add("agentbom:coverage:window-start", _iso(bom.coverage.window.start))
            props.add("agentbom:coverage:window-end", _iso(bom.coverage.window.end))
        props.add_many("agentbom:coverage:exclusion", (x.pattern for x in bom.coverage.exclusions))
        for flag in bom.derived.flags:
            props.add(f"agentbom:flag:{flag.flag.value}", flag.value)
            props.add_many(f"agentbom:flag:{flag.flag.value}:input", flag.inputs)
        props.add_many("agentbom:redaction:applied", (r.redaction_class for r in bom.redactions))
        for ts in bom.trust_status:
            if ts.status is E.TrustState.REVOKED and ts.subject_kind is E.TrustSubjectKind.PUBLISHER_IDENTITY:
                props.add("agentbom:trust:revoked-publisher", ts.subject_key)
        if bom.loss_report:
            props.add("agentbom:loss:items", len(bom.loss_report.items))
        props.add("symbiote:version", __version__)
        for c in bom.coverage.collectors:
            props.add(f"symbiote:collector:{c.name}:version", c.version)
            props.add(f"symbiote:collector:{c.name}:status", c.status)
        props.add("symbiote:level:claimed", self.profile)
        return props.build() or []

    def dependencies(self, refs: set[str]) -> list[dict[str, Any]]:
        deps: dict[str, dict[str, set[str]]] = {}

        def dep(ref: str) -> dict[str, set[str]]:
            return deps.setdefault(ref, {"dependsOn": set(), "provides": set()})

        for e in self.bom.edges:
            if e.from_ref not in refs or e.to_ref not in refs:
                continue
            if e.type is E.EdgeType.PROVIDES_TOOL:
                dep(e.from_ref)["provides"].add(e.to_ref)
            elif e.type in _DEPENDS_EDGES:
                dep(e.from_ref)["dependsOn"].add(e.to_ref)
        for t in self.bom.tools:  # a server provides its tools even without an explicit edge
            if t.server_ref in refs and t.id in refs:
                dep(t.server_ref)["provides"].add(t.id)
        for s in self.bom.tool_servers:
            if f"{s.id}/package" in refs:
                dep(s.id)["dependsOn"].add(f"{s.id}/package")
        for m in self.bom.models:
            if f"{m.id}/endpoint" in refs:
                dep(m.id)["dependsOn"].add(f"{m.id}/endpoint")
        out = []
        for ref in sorted(deps):
            entry: dict[str, Any] = {"ref": ref}
            if deps[ref]["dependsOn"]:
                entry["dependsOn"] = sorted(deps[ref]["dependsOn"])
            if deps[ref]["provides"]:
                entry["provides"] = sorted(deps[ref]["provides"])
            if len(entry) > 1:
                out.append(entry)
        return out

    def compositions(self, refs: set[str]) -> list[dict[str, Any]]:
        out = []
        for surface in E.Surface:
            cov = self.bom.coverage.surfaces.get(surface)
            if cov is None:
                continue
            assemblies = sorted(
                ent.id
                for attr in _SURFACE_ASSEMBLIES.get(surface, ())
                for ent in getattr(self.bom, attr)
                if ent.id in refs
            )
            out.append(
                _clean(
                    {
                        "bom-ref": f"composition:{surface.value}",
                        "aggregate": _AGGREGATE[cov.completeness],
                        "assemblies": assemblies or None,
                    }
                )
            )
        out.append(
            {"bom-ref": "composition:document", "aggregate": _AGGREGATE[self.bom.coverage.completeness]}
        )
        return out

    def declarations(self, refs: set[str]) -> dict[str, Any] | None:
        bom = self.bom
        evidence = []
        for ev in bom.evidence:
            evidence.append(
                _clean(
                    {
                        "bom-ref": ev.id,
                        "propertyName": ev.evidence_kind.value,
                        "description": ev.description,
                        "data": [
                            _clean({"name": ev.evidence_kind.value, "contents": {"url": ev.uri or ev.digest}})
                        ],
                        "created": _iso(ev.created),
                        "expires": _iso(ev.expires),
                    }
                )
            )
        claims = []
        for flag in bom.derived.flags:
            if flag.subject_ref in refs:
                claims.append(
                    _clean(
                        {
                            "bom-ref": f"claim:flag:{flag.flag.value}:{flag.subject_ref}",
                            "target": flag.subject_ref,
                            "predicate": f"agentbom:flag:{flag.flag.value}={flag.value.value}",
                            "reasoning": "inputs: " + ", ".join(flag.inputs) if flag.inputs else None,
                        }
                    )
                )
        for g in bom.grants:
            if g.layer is E.GrantLayer.EFFECTIVE and g.subject_ref in refs:
                claims.append(
                    _clean(
                        {
                            "bom-ref": f"claim:{g.id}",
                            "target": g.subject_ref,
                            "predicate": f"agentbom:authz:effective:{g.capability.value}",
                            "reasoning": f"policy {g.policy_ref.bundle_digest}" if g.policy_ref else None,
                        }
                    )
                )
        assessors = [
            _clean(
                {
                    "bom-ref": f"assessor:{ev.assessor_ref}",
                    "thirdParty": ev.third_party,
                    "organization": _party(bom, ev.assessor_ref),
                }
            )
            for ev in bom.evaluations
        ]
        decl = _clean(
            {
                "evidence": evidence or None,
                "claims": claims or None,
                "assessors": _dedupe(assessors) or None,
                "targets": {
                    "components": [
                        {
                            "type": "application",
                            "bom-ref": "target:" + bom.subject,
                            "name": bom.root_agent.name or bom.subject,
                        }
                    ]
                }
                if claims
                else None,
            }
        )
        return decl or None

    def vulnerabilities(self, refs: set[str]) -> list[dict[str, Any]] | None:
        out = []
        for v in self.bom.vex:
            if v.subject.ref not in refs:
                continue
            fw = v.weakness.framework
            source_name = {
                "mitre-atlas": "MITRE ATLAS",
                "owasp-asi-2025": "OWASP Top 10 for Agentic Applications",
                "owasp-llm-2025": "OWASP Top 10 for LLM Applications",
                "cwe": "CWE",
                "nist-ai-rmf": "NIST AI RMF",
            }.get(fw, fw)
            props = Props()
            props.add("agentbom:vex:justification", v.justification)
            props.add("agentbom:vex:scope:config-digest", v.subject.config_digest)
            props.add("agentbom:vex:scope:subject", v.subject.ref)
            props.add("agentbom:vex:expires", _iso(v.expires))
            analysis = _clean(
                {
                    "state": _VEX_STATE.get(v.status, "in_triage"),
                    "justification": _VEX_JUSTIFICATION.get(v.justification or ""),
                    "detail": v.detail,
                    "firstIssued": _iso(v.issued_at),
                    "lastUpdated": _iso(v.last_updated),
                }
            )
            out.append(
                _clean(
                    {
                        "bom-ref": v.id,
                        "id": v.weakness.id,
                        "source": _clean({"name": source_name, "url": v.weakness.uri}),
                        "ratings": [{"method": "other", "severity": "unknown"}],
                        "affects": [{"ref": v.subject.ref}],
                        "analysis": analysis,
                        "properties": props.build(),
                    }
                )
            )
        return out or None

    def citations(
        self, ordered: list[tuple[str, Entity]], ts: str, collector_refs: dict[str, str]
    ) -> list[dict[str, Any]] | None:
        out = []
        for pointer, ent in ordered:
            prov = ent.provenance
            if not prov.locator:
                continue
            attributed = collector_refs.get(prov.collector or "", PRODUCER_REF)
            out.append(
                _clean(
                    {
                        "pointers": [pointer],
                        "timestamp": _iso(prov.observed_at) or ts,
                        "attributedTo": attributed,
                        "note": prov.locator,
                    }
                )
            )
        return out or None

    def formulation(self, ts: str, collector_refs: dict[str, str]) -> list[dict[str, Any]] | None:
        tasks = []
        for run in self.bom.coverage.collectors:
            props = Props()
            props.add("agentbom:coverage:status", run.status)
            props.add("agentbom:coverage:reason", run.reason)
            tasks.append(
                _clean(
                    {
                        "bom-ref": f"task:collector:{run.name}",
                        "uid": f"collector:{run.name}@{run.version}",
                        "name": run.name,
                        "taskTypes": ["scan"],
                        "properties": props.build(),
                    }
                )
            )
        if not tasks:
            return None
        workflow = {
            "bom-ref": "workflow:collection",
            "uid": self.bom.snapshot.id,
            "name": "symbiote-collection",
            "taskTypes": ["scan"],
            "tasks": tasks,
            "timeStart": ts,
        }
        if self.bom.coverage.window:
            workflow["timeStart"] = _iso(self.bom.coverage.window.start)
            workflow["timeEnd"] = _iso(self.bom.coverage.window.end)
        return [{"bom-ref": "formulation:collection", "workflows": [workflow]}]


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out = []
    for it in items:
        key = json.dumps(it, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


# ------------------------------------------------------------------------------------------------ public API


def export_cyclonedx(
    bom: AgentBOM,
    *,
    profile: str = "standard",
    include_text: bool = False,
    companion_digest: str | None = None,
    companion_ref: str | None = None,
) -> tuple[dict[str, Any], LossReport]:
    """Project an AgentBOM onto CycloneDX 1.7 JSON. Returns ``(document, loss_report)``."""
    bom = bom.sorted()
    b = _Builder(
        bom,
        include_text=include_text,
        companion_digest=companion_digest,
        companion_ref=companion_ref,
        profile=profile,
    )
    ts = _iso(bom.snapshot.produced_at) or datetime.now(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )

    collector_refs = {c.ref: f"producer:collector:{c.name}" for c in bom.producer.collectors}
    tools_components = [
        _clean(
            {
                "type": "application",
                "bom-ref": PRODUCER_REF,
                "name": bom.producer.name,
                "version": bom.producer.version,
                "hashes": _hash(bom.producer.digest),
            }
        )
    ]
    tools_components += [
        _clean(
            {
                "type": "application",
                "bom-ref": ref,
                "name": c.name,
                "version": c.version,
                "hashes": _hash(c.digest),
                "properties": [
                    {"name": "agentbom:kind", "value": "collector"},
                    {"name": "symbiote:collector:mode", "value": c.mode.value},
                ],
            }
        )
        for c, ref in ((c, collector_refs[c.ref]) for c in bom.producer.collectors)
    ]

    components: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    ordered: list[tuple[str, Entity]] = []
    root = bom.root_agent
    for a in bom.agents:
        if a.id != root.id:
            components.append(b.agent(a, root=False))
            ordered.append(("components", a))
    for s in bom.tool_servers:
        svc, pkg = b.tool_server(s)
        services.append(svc)
        ordered.append(("services", s))
        if pkg:
            components.append(pkg)
    for t in bom.tools:
        components.append(b.tool(t))
        ordered.append(("components", t))
    for i in bom.instructions:
        components.append(b.instruction(i))
        ordered.append(("components", i))
    for p in bom.prompts:
        components.append(b.prompt(p))
        ordered.append(("components", p))
    for sk in bom.skills:
        components.append(b.skill(sk))
        ordered.append(("components", sk))
    for m in bom.models:
        comp, endpoint = b.model(m)
        components.append(comp)
        ordered.append(("components", m))
        if endpoint:
            services.append(endpoint)
    for d in bom.data_sources:
        components.append(b.data_source(d))
        ordered.append(("components", d))
    for p in bom.policies:
        components.append(b.policy(p))
        ordered.append(("components", p))
    for sw in bom.software:
        components.append(b.software(sw))
    for red in bom.redacted:
        components.append(
            {
                "type": "data",
                "bom-ref": red.id,
                "name": red.id,
                "properties": [
                    {"name": "agentbom:kind", "value": red.kind},
                    {"name": "agentbom:redaction:applied", "value": red.redaction_class},
                    {"name": "agentbom:merkle:leaf", "value": red.leaf_hash},
                ],
            }
        )

    components.sort(key=lambda c: c["bom-ref"])
    services.sort(key=lambda s: s["bom-ref"])
    refs = {c["bom-ref"] for c in components} | {s["bom-ref"] for s in services} | {root.id}
    for c in components:
        for n in c.get("components", []) or []:
            refs.add(n["bom-ref"])

    # citations need stable JSON pointers: compute after sorting
    index_of_component = {c["bom-ref"]: i for i, c in enumerate(components)}
    index_of_service = {s["bom-ref"]: i for i, s in enumerate(services)}
    pointered: list[tuple[str, Entity]] = []
    for where, ent in ordered:
        if where == "components" and ent.id in index_of_component:
            pointered.append((f"/components/{index_of_component[ent.id]}", ent))
        elif where == "services" and ent.id in index_of_service:
            pointered.append((f"/services/{index_of_service[ent.id]}", ent))
    if root.provenance.locator:
        pointered.insert(0, ("/metadata/component", root))

    # identities not bound to any subject: record on the root agent
    for ident in bom.identities:
        if not any(cb.identity_ref == ident.id for cb in bom.credential_bindings):
            b._lose(
                f"/identities/{ident.id}",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.COMPANION,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=ident.id,
            )
    for r in bom.resolutions:
        if not any(s.registry_resolution_ref == r.id for s in bom.tool_servers):
            b._lose(
                f"/resolutions/{r.id}",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.COMPANION,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=r.id,
            )
    for ev in bom.evaluations:
        b._lose(
            f"/evaluations/{ev.id}/results",
            E.LossReason.NO_NATIVE_CONSTRUCT,
            E.LossPreservedIn.COMPANION,
            E.LossSeverity.INFO,
            entity=ev.id,
        )
    if bom.merkle and bom.merkle.leaves:
        b._lose(
            "/merkle/leaves",
            E.LossReason.NO_NATIVE_CONSTRUCT,
            E.LossPreservedIn.COMPANION,
            E.LossSeverity.INFO,
        )
    for a in bom.approvals:
        b._lose(
            f"/approvals/{a.id}",
            E.LossReason.NO_NATIVE_CONSTRUCT,
            E.LossPreservedIn.COMPANION,
            E.LossSeverity.SECURITY_RELEVANT,
            entity=a.id,
        )

    doc = _clean(
        {
            "$schema": CDX_SCHEMA_URI,
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": f"urn:uuid:{uuid5_for_digest(bom.snapshot.digest)}",
            "version": bom.snapshot.serial,
            "metadata": _clean(
                {
                    "timestamp": ts,
                    "lifecycles": [
                        {"phase": _LIFECYCLE_PHASE[bom.snapshot.kind]},
                        {
                            "name": f"agentbom:snapshot:{bom.snapshot.kind.value}",
                            "description": f"AgentBOM {bom.snapshot.kind.value} snapshot (spec/agentbom-profile.md)",
                        },
                    ],
                    "tools": {"components": tools_components},
                    "component": b.agent(root, root=True),
                    "properties": b.metadata_properties(),
                }
            ),
            "components": components or None,
            "services": services or None,
            "dependencies": b.dependencies(refs) or None,
            "compositions": b.compositions(refs) or None,
            "declarations": b.declarations(refs),
            "vulnerabilities": b.vulnerabilities(refs),
            "citations": b.citations(pointered, ts, collector_refs),
            "formulation": b.formulation(ts, collector_refs),
        }
    )
    report = LossReport(
        direction="model→cdx",
        source_format="agentbom-model",
        target_format="cyclonedx-1.7",
        model_digest=bom.snapshot.digest,
        items=b.loss,
    )
    return doc, report


__all__ = ["CDX_SCHEMA_URI", "PRODUCER_REF", "export_cyclonedx"]
