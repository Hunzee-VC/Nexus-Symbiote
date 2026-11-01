"""Emit SPDX 3.0.1 JSON-LD from the semantic model (``spec/spdx-mapping.md``).

Native classes and relationship types carry what they can; agent-specific qualifiers are typed extension
objects under Symbiote's vocabulary; every ``agentbom:`` property emitted by the CycloneDX exporter is mirrored
into ``extension_CdxPropertiesExtension`` so the two projections stay lossless with each other.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from typing import Any

from spdx_python_model.bindings import v3_0_1 as m

from symbiote import BASE_URI, __version__
from symbiote.digest.envelope import strip_prefix
from symbiote.digest.jcs import canonical_bytes
from symbiote.export import account_for_companion
from symbiote.export.cdx.emit import export_cyclonedx
from symbiote.model import enums as E
from symbiote.model.document import AgentBOM
from symbiote.model.entities import Entity, LossItem, LossReport

TERMS = f"{BASE_URI}spdx/0.1/terms/"
NOASSERTION_ELEMENT = "https://spdx.org/rdf/3.0.1/terms/Core/NoAssertionElement"
NONE_ELEMENT = "https://spdx.org/rdf/3.0.1/terms/Core/NoneElement"

_SBOM_TYPE = {
    E.SnapshotKind.DECLARED: "design",
    E.SnapshotKind.APPROVED: "build",
    E.SnapshotKind.DEPLOYED: "deployed",
    E.SnapshotKind.OBSERVED: "runtime",
}
_TLP = {
    E.Classification.PUBLIC: "clear",
    E.Classification.INTERNAL: "green",
    E.Classification.CONFIDENTIAL: "amber",
    E.Classification.RESTRICTED: "red",
}
_VEX_JUST = {
    "guardrail-enforced": "inlineMitigationsAlreadyExist",
    "evaluated-resistant": "inlineMitigationsAlreadyExist",
    "tool-disabled": "vulnerableCodeNotInExecutePath",
    "approval-required": "vulnerableCodeNotInExecutePath",
    "scope-restricted": "vulnerableCodeNotInExecutePath",
    "not-reachable": "vulnerableCodeCannotBeControlledByAdversary",
    "egress-denied": "vulnerableCodeCannotBeControlledByAdversary",
    "component-not-present": "componentNotPresent",
}
# edge type -> (native relationship type or None, reversed?)
_EDGE_REL: dict[E.EdgeType, tuple[str, bool]] = {
    E.EdgeType.USES_MODEL: ("dependsOn", False),
    E.EdgeType.INVOKES_TOOL: ("usesTool", False),
    E.EdgeType.PROVIDES_TOOL: ("contains", False),
    E.EdgeType.DELEGATES_TO: ("dependsOn", False),
    E.EdgeType.SPAWNS: ("dependsOn", False),
    E.EdgeType.LOADS_INSTRUCTION: ("configures", True),
    E.EdgeType.READS_CONTEXT_FROM: ("dependsOn", False),
    E.EdgeType.READS_MEMORY_FROM: ("dependsOn", False),
    E.EdgeType.WRITES_MEMORY_TO: ("modifiedBy", True),
    E.EdgeType.ACTS_AS: ("invokedBy", False),
    E.EdgeType.HOLDS_CREDENTIAL: ("dependsOn", False),
    E.EdgeType.GRANTED_BY: ("dependsOn", False),
    E.EdgeType.ENFORCED_AT: ("dependsOn", False),
    E.EdgeType.APPROVED_UNDER: ("hasEvidence", False),
    E.EdgeType.RESOLVED_FROM: ("dependsOn", False),
    E.EdgeType.DERIVED_FROM: ("descendantOf", False),
    E.EdgeType.EMBEDS: ("dependsOn", False),
    E.EdgeType.EVALUATED_BY: ("hasEvidence", False),
    E.EdgeType.OBSERVED_BY: ("dependsOn", False),
    E.EdgeType.DEPENDS_ON: ("dependsOn", False),
    E.EdgeType.SENDS_DATA_TO: ("dependsOn", False),
}
_SURFACE_OF_COLLECTION = {
    "tool_servers": E.Surface.TOOLS,
    "tools": E.Surface.TOOLS,
    "instructions": E.Surface.INSTRUCTIONS,
    "prompts": E.Surface.INSTRUCTIONS,
    "skills": E.Surface.INSTRUCTIONS,
    "models": E.Surface.MODEL_GATEWAY,
    "data_sources": E.Surface.DATA,
    "software": E.Surface.CODE,
    "policies": E.Surface.POLICY,
    "identities": E.Surface.IDENTITY,
    "credential_bindings": E.Surface.IDENTITY,
    "resolutions": E.Surface.REGISTRY,
    "deployments": E.Surface.RUNTIME,
}


def _iso(dt: datetime | None) -> datetime | None:
    return None if dt is None else dt.astimezone(UTC).replace(microsecond=0)


def _val(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, bool | int | float | str):
        return v
    if hasattr(v, "value"):
        return v.value
    if isinstance(v, datetime):
        return v.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(v, list | tuple):
        return [x for x in (_val(i) for i in v) if x is not None] or None
    if isinstance(v, dict):
        return canonical_bytes(v).decode("utf-8")
    return str(v)


def extension(type_name: str, **fields: Any) -> Any:
    """A typed Symbiote extension object (``https://aisecnomad.github.io/symbiote/spdx/0.1/terms/<Type>``)."""
    ext = m.extension_Extension(typ=TERMS + type_name)
    for key, value in fields.items():
        v = _val(value)
        if v is not None:
            ext._ext_data[TERMS + key] = v
    return ext


def cdx_mirror(props: list[dict[str, str]]) -> Any | None:
    if not props:
        return None
    ext = m.extension_CdxPropertiesExtension()
    entries = []
    for p in props:
        e = m.extension_CdxPropertyEntry()
        e.extension_cdxPropName = p["name"]
        e.extension_cdxPropValue = p["value"]
        entries.append(e)
    ext.extension_cdxProperty = entries
    return ext


def _hash(digest: str | None) -> list[Any]:
    if not digest:
        return []
    h = m.Hash()
    h.algorithm = m.HashAlgorithm.sha256
    h.hashValue = strip_prefix(digest)
    return [h]


class _Emitter:
    def __init__(
        self,
        bom: AgentBOM,
        cdx_doc: dict[str, Any],
        *,
        companion_digest: str | None,
        companion_ref: str | None,
    ) -> None:
        self.bom = bom
        self.companion_digest = companion_digest
        self.companion_ref = companion_ref
        digest12 = strip_prefix(bom.snapshot.digest)[:12]
        self.ns = f"{BASE_URI}spdx/doc/{bom.subject.split(':', 1)[1]}/{digest12}/"
        self.objset = m.SHACLObjectSet()
        self.elements: dict[str, Any] = {}
        self.loss: list[LossItem] = []
        self.props_by_ref: dict[str, list[dict[str, str]]] = {}
        for c in cdx_doc.get("components", []) or []:
            self.props_by_ref[c["bom-ref"]] = c.get("properties", []) or []
            for n in c.get("components", []) or []:
                self.props_by_ref[n["bom-ref"]] = n.get("properties", []) or []
        for s in cdx_doc.get("services", []) or []:
            self.props_by_ref[s["bom-ref"]] = s.get("properties", []) or []
        root = cdx_doc.get("metadata", {}).get("component", {})
        if root:
            self.props_by_ref[root["bom-ref"]] = root.get("properties", []) or []
        self.doc_props = cdx_doc.get("metadata", {}).get("properties", []) or []
        self.ci = m.CreationInfo()
        self.ci.specVersion = "3.0.1"
        self.ci.created = _iso(bom.snapshot.produced_at)
        self.ci.comment = f"Symbiote {__version__}; AgentBOM profile 0.1; snapshot {bom.snapshot.digest}"

    # ---- helpers

    def iri(self, ref: str) -> str:
        return self.ns + ref

    def register(self, ref: str, obj: Any) -> Any:
        obj.spdxId = self.iri(ref)
        obj.creationInfo = self.ci
        self.objset.add(obj)
        self.elements[ref] = obj
        return obj

    def finish_element(self, ref: str, obj: Any, ent: Entity | None, *exts: Any) -> None:
        extras = [e for e in exts if e is not None]
        mirror = cdx_mirror(self.props_by_ref.get(ref, []))
        if mirror is not None:
            extras.append(mirror)
        if extras:
            obj.extension = extras
        if ent is not None:
            if ent.description:
                obj.description = ent.description
            refs = []
            for r in ent.external_refs:
                er = m.ExternalRef()
                er.externalRefType = m.ExternalRefType.other
                er.locator = [r.url]
                er.comment = f"{r.type}: {r.comment}" if r.comment else r.type
                refs.append(er)
            if refs:
                obj.externalRef = refs

    def completeness_for(self, collection: str) -> Any:
        surface = _SURFACE_OF_COLLECTION.get(collection)
        if surface is None:
            return m.RelationshipCompleteness.noAssertion
        cov = self.bom.coverage.surfaces.get(surface)
        if cov is None or cov.status is E.CoverageStatus.NOT_ATTEMPTED:
            return m.RelationshipCompleteness.noAssertion
        return (
            m.RelationshipCompleteness.complete
            if cov.status is E.CoverageStatus.QUERIED
            else m.RelationshipCompleteness.incomplete
        )

    def relate(
        self,
        ref: str,
        from_ref: str,
        to_refs: list[str],
        rel_type: str,
        *,
        scope: str | None = "runtime",
        completeness: Any = None,
        qualifiers: dict[str, Any] | None = None,
    ) -> Any:
        rel = m.LifecycleScopedRelationship() if scope else m.Relationship()
        rel.spdxId = self.iri(ref)
        rel.creationInfo = self.ci
        rel.from_ = self.elements[from_ref]
        rel.to = [self.elements.get(t, t) for t in to_refs]
        rel.relationshipType = getattr(m.RelationshipType, rel_type)
        if scope:
            rel.scope = getattr(m.LifecycleScopeType, scope)
        if completeness is not None:
            rel.completeness = completeness
        if qualifiers:
            rel.extension = [extension("EdgeQualifiers", **qualifiers)]
        self.objset.add(rel)
        self.elements[ref] = rel
        return rel

    # ---- producers and parties

    def producers(self) -> tuple[Any, list[Any]]:
        agent = m.SoftwareAgent()
        agent.name = self.bom.producer.name
        self.register("producer:symbiote-agent", agent)
        tools = []
        tool = m.Tool()
        tool.name = self.bom.producer.name
        tool.summary = f"symbiote {self.bom.producer.version}"
        self.register("producer:symbiote", tool)
        tools.append(tool)
        for c in self.bom.producer.collectors:
            t = m.Tool()
            t.name = c.name
            t.summary = f"{c.name} {c.version} ({c.mode.value} collector)"
            self.register(f"producer:collector:{c.name}", t)
            tools.append(t)
        return agent, tools

    def parties(self) -> None:
        for p in self.bom.parties:
            obj = m.Person() if p.party_kind is E.PartyKind.PERSON else m.Organization()
            obj.name = p.name
            if p.urls:
                ids = []
                for u in p.urls:
                    ei = m.ExternalIdentifier()
                    ei.externalIdentifierType = m.ExternalIdentifierType.urlScheme
                    ei.identifier = u
                    ids.append(ei)
                obj.externalIdentifier = ids
            self.register(p.id, obj)

    # ---- entities

    def agents(self) -> None:
        for a in self.bom.agents:
            pkg = m.ai_AIPackage()
            pkg.name = a.name or a.id
            pkg.software_primaryPurpose = m.software_SoftwarePurpose.application
            pkg.software_packageVersion = a.version
            pkg.software_downloadLocation = "NOASSERTION"
            if a.purpose:
                pkg.ai_informationAboutApplication = a.purpose
            modes = {ap.mode for ap in a.autonomy_profile}
            if not a.autonomy_profile:
                pkg.ai_autonomyType = m.PresenceType.noAssertion
            elif E.AutonomyMode.AUTONOMOUS in modes:
                pkg.ai_autonomyType = m.PresenceType.yes
            else:
                pkg.ai_autonomyType = m.PresenceType.no
            if a.owner_ref and a.owner_ref in self.elements:
                pkg.suppliedBy = self.elements[a.owner_ref]
            pkg.verifiedUsing = _hash(a.digest)
            self.register(a.id, pkg)
            principal = m.SoftwareAgent()
            principal.name = (a.name or a.id) + " (principal)"
            self.register(f"{a.id}/principal", principal)
            self.finish_element(
                a.id,
                pkg,
                a,
                extension(
                    "AgentProfile",
                    role=a.role,
                    framework=a.framework.value.name if a.framework and a.framework.value else None,
                    frameworkVersion=a.framework.value.version if a.framework and a.framework.value else None,
                    automationLevel=a.automation_level.value
                    if a.automation_level and a.automation_level.value
                    else None,
                    autonomyProfile=[f"{ap.capability.value}:{ap.mode.value}" for ap in a.autonomy_profile]
                    or None,
                    policyBundleDigest=a.policy_bundle.value
                    if a.policy_bundle and a.policy_bundle.value
                    else None,
                    entrypoint=a.entrypoint,
                    parentRef=a.parent_ref,
                    principalRef=f"{a.id}/principal",
                    identities=a.identities or None,
                ),
                extension(
                    "A2ACard",
                    cardDigest=a.a2a_card.digest,
                    cardUrl=a.a2a_card.url,
                    protocolVersions=a.a2a_card.protocol_versions or None,
                    skills=[s.id for s in a.a2a_card.skills] or None,
                    signatureStatus=a.a2a_card.signature_status,
                )
                if a.a2a_card
                else None,
            )
            self.relate(f"rel:acts-as:{a.id}", a.id, [f"{a.id}/principal"], "invokedBy", scope=None)

    def tool_servers(self) -> None:
        for s in self.bom.tool_servers:
            pkg = m.software_Package()
            pkg.name = s.name or s.id.split(":", 1)[1]
            pkg.software_primaryPurpose = m.software_SoftwarePurpose.application
            endpoint = s.endpoint.value if s.endpoint and s.endpoint.value else None
            purl = s.package.value.purl if s.package and s.package.value and s.package.value.purl else None
            pkg.software_downloadLocation = endpoint or (
                purl.replace("pkg:", "pkg:") if purl else "NOASSERTION"
            )
            if purl:
                pkg.software_packageUrl = purl
            if endpoint:
                ei = m.ExternalIdentifier()
                ei.externalIdentifierType = m.ExternalIdentifierType.urlScheme
                ei.identifier = endpoint
                pkg.externalIdentifier = [ei]
            pkg.verifiedUsing = _hash(s.digest)
            self.register(s.id, pkg)
            self.finish_element(
                s.id,
                pkg,
                s,
                extension(
                    "ToolServer",
                    kind=s.server_kind,
                    client=s.client,
                    transport=s.transport.value,
                    endpointOrigin=endpoint,
                    packagePurl=purl,
                    floating=s.package.value.floating if s.package and s.package.value else None,
                    launcher=s.package.value.launcher if s.package and s.package.value else None,
                    authMode=s.authentication.value.mode if s.authentication.value else None,
                    trustZone=s.trust_zone,
                    crossesTrustBoundary=s.crosses_trust_boundary.value,
                    instructionsDigest=s.instructions_digest.value if s.instructions_digest else None,
                    protocolVersion=s.protocol_version.value if s.protocol_version else None,
                    toolsetDigest=s.toolset_digest.value if s.toolset_digest else None,
                    toolsetDigestStatus=s.toolset_digest_result.status if s.toolset_digest_result else None,
                    envVarNames=s.env_var_names or None,
                    headerNames=s.header_names or None,
                ),
            )

    def tools(self) -> None:
        for t in self.bom.tools:
            pkg = m.software_Package()
            pkg.name = t.tool_name
            pkg.software_primaryPurpose = m.software_SoftwarePurpose.specification
            pkg.software_downloadLocation = "NOASSERTION"
            pkg.verifiedUsing = _hash(t.digest.value)
            self.register(t.id, pkg)
            ann = t.annotations.value if t.annotations and t.annotations.value else None
            self.finish_element(
                t.id,
                pkg,
                t,
                extension(
                    "ToolDefinition",
                    serverRef=t.server_ref,
                    digestAlgorithm=t.digest.algorithm,
                    digestStatus=t.digest.status,
                    digestReason=t.digest.reason,
                    fullDigest=t.full_digest.value if t.full_digest else None,
                    descriptionDigest=t.description_digest,
                    inputSchemaDigest=t.input_schema_digest,
                    readOnlyHint=ann.read_only_hint if ann else None,
                    destructiveHint=ann.destructive_hint if ann else None,
                    idempotentHint=ann.idempotent_hint if ann else None,
                    openWorldHint=ann.open_world_hint if ann else None,
                    annotationsPresent=ann.any_present if ann else False,
                    sideEffectClass=t.side_effect_class,
                    capabilities=[c.value for c in t.capabilities] or None,
                    requiredScopes=t.required_scopes.value
                    if t.required_scopes and t.required_scopes.value
                    else None,
                    approvalGate=t.approval_gate,
                    textFlags=[f.value for f in t.text_flags] or None,
                    source=t.source,
                    state=t.state,
                ),
            )
            if t.server_ref in self.elements:
                self.relate(
                    f"rel:contains:{t.id}",
                    t.server_ref,
                    [t.id],
                    "contains",
                    scope=None,
                    completeness=self.completeness_for("tools"),
                )

    def files_and_skills(self) -> None:
        for i in self.bom.instructions:
            f = m.software_File()
            f.name = i.path or i.uri or i.id
            f.software_primaryPurpose = m.software_SoftwarePurpose.configuration
            f.software_contentType = i.media_type
            f.verifiedUsing = _hash(i.digest)
            self.register(i.id, f)
            self.finish_element(
                i.id,
                f,
                i,
                extension(
                    "Instruction",
                    kind=i.instruction_kind,
                    precedence=i.precedence,
                    lineEndings=i.line_endings,
                    size=i.size,
                    editors=i.editors.value if i.editors and i.editors.value else None,
                    loadsRemote=i.loads_remote.value if i.loads_remote and i.loads_remote.value else None,
                    secretLikeRedacted=i.contains_secret_like,
                    normalizedDigest=i.normalized_digest,
                ),
            )
        for p in self.bom.prompts:
            f = m.software_File()
            f.name = p.path or p.id
            f.software_primaryPurpose = m.software_SoftwarePurpose.configuration
            f.verifiedUsing = _hash(p.template_digest)
            self.register(p.id, f)
            self.finish_element(
                p.id,
                f,
                p,
                extension(
                    "PromptTemplate",
                    engine=p.engine,
                    role=p.role,
                    promptDigest=p.digest.value,
                    variablesSchemaDigest=p.variables_schema_digest,
                    riskClass=p.risk_class,
                ),
            )
        for s in self.bom.skills:
            pkg = m.software_Package()
            pkg.name = s.frontmatter.name or s.id.split(":", 1)[1]
            pkg.software_primaryPurpose = m.software_SoftwarePurpose.module
            pkg.software_downloadLocation = "NOASSERTION"
            pkg.verifiedUsing = _hash(s.digest)
            self.register(s.id, pkg)
            self.finish_element(
                s.id,
                pkg,
                s,
                extension(
                    "Skill",
                    manifestRoot=s.digest,
                    allowedTools=s.frontmatter.allowed_tools or None,
                    hasScripts=s.has_scripts,
                    nameMatchesDirectory=s.name_matches_directory,
                    scriptCount=len(s.scripts),
                    fileCount=len(s.manifest.resources),
                ),
            )
            for sc in s.scripts:
                f = m.software_File()
                f.name = sc.path
                f.software_primaryPurpose = m.software_SoftwarePurpose.source
                f.verifiedUsing = _hash(sc.digest)
                ref = f"{s.id}/{sc.path}"
                self.register(ref, f)
                self.relate(f"rel:contains:{ref}", s.id, [ref], "contains", scope=None)
            if s.skill_md_ref in self.elements:
                self.relate(f"rel:contains:{s.id}/skill-md", s.id, [s.skill_md_ref], "contains", scope=None)

    def models(self) -> None:
        for mo in self.bom.models:
            pkg = m.ai_AIPackage()
            pkg.name = mo.name or mo.id.split(":", 1)[1]
            pkg.software_primaryPurpose = m.software_SoftwarePurpose.model
            ext_fields: dict[str, Any] = {"kind": mo.model_kind}
            if mo.artifact_digest:
                ext_fields["artifactDigestClaim"] = mo.artifact_digest.to_json_dict()
            if mo.hosted and mo.hosted.value:
                h = mo.hosted.value
                pkg.software_downloadLocation = h.endpoint_origin or "NOASSERTION"
                pkg.software_packageVersion = h.resolved_ref.value or h.requested_ref
                ext_fields.update(
                    provider=h.provider,
                    requestedRef=h.requested_ref,
                    resolvedRef=h.resolved_ref.value,
                    resolvedRefState=h.resolved_ref.state,
                    aliasPinning=h.alias_pinning,
                    endpointOrigin=h.endpoint_origin,
                )
                if h.fingerprint:
                    ext_fields.update(
                        fingerprintMethod=h.fingerprint.method,
                        fingerprintDigest=h.fingerprint.digest,
                        fingerprintExpires=h.fingerprint.expires,
                    )
            else:
                pkg.software_downloadLocation = "NOASSERTION"
            if mo.weights and mo.weights.value:
                w = mo.weights.value
                if w.purl:
                    pkg.software_packageUrl = w.purl
                pkg.verifiedUsing = _hash(w.manifest_root)
                ext_fields.update(
                    manifestFormat="oms-v1",
                    manifestRoot=w.manifest_root,
                    manifestRef=w.manifest_ref,
                    fileCount=w.file_count,
                    formats=[f.value for f in w.formats] or None,
                )
            if mo.serialization and mo.serialization.value:
                ser = mo.serialization.value
                ext_fields.update(
                    serializationFormats=[f.value for f in ser.formats] or None,
                    serializationRisk=ser.risk_class,
                    trustRemoteCode=ser.trust_remote_code,
                    chatTemplateExecutable=ser.chat_template_executable,
                )
            if mo.signature:
                ext_fields.update(
                    signatureStatus=mo.signature.status,
                    signatureOutcome=mo.signature.outcome,
                    signatureIdentity=mo.signature.identity,
                    signatureIssuer=mo.signature.issuer,
                    logEntry=mo.signature.log_entry,
                )
            ext_fields.update(tensorManifestRoot=mo.tensor_manifest_root)
            pkg.ai_autonomyType = m.PresenceType.noAssertion
            if mo.card and mo.card.task:
                pkg.ai_domain = [mo.card.task]
            self.register(mo.id, pkg)
            self.finish_element(mo.id, pkg, mo, extension("ModelIdentity", **ext_fields))
            for i, d in enumerate(mo.derivations):
                parent_ref = d.parent if d.parent in self.elements else None
                if parent_ref:
                    self.relate(
                        f"rel:derived-from:{mo.id}:{i}",
                        mo.id,
                        [parent_ref],
                        "descendantOf",
                        scope=None,
                        qualifiers={"derivationKind": d.kind, "parametersDigest": d.parameters_digest},
                    )
                else:
                    self.loss.append(
                        LossItem(
                            path=f"/models/{mo.id}/derivations/{i}",
                            entity=mo.id,
                            field="derivations",
                            reason=E.LossReason.NO_NATIVE_CONSTRUCT,
                            preserved_in=E.LossPreservedIn.EXTENSION,
                            severity=E.LossSeverity.INFO,
                        )
                    )

    def data_sources(self) -> None:
        for d in self.bom.data_sources:
            pkg = m.dataset_DatasetPackage()
            pkg.name = d.name or d.id.split(":", 1)[1]
            pkg.software_primaryPurpose = m.software_SoftwarePurpose.data
            pkg.software_downloadLocation = d.location or "NOASSERTION"
            pkg.dataset_datasetType = [
                m.dataset_DatasetType.text
                if d.data_kind in (E.DataSourceKind.RAG_INDEX, E.DataSourceKind.MEMORY_STORE)
                else m.dataset_DatasetType.other
            ]
            if d.classification in _TLP:
                pkg.dataset_confidentialityLevel = getattr(
                    m.dataset_ConfidentialityLevelType, _TLP[d.classification]
                )
            if d.refresh_policy or d.live:
                pkg.dataset_datasetUpdateMechanism = d.refresh_policy or "live/unbounded"
            if d.data_classes:
                pkg.dataset_hasSensitivePersonalInformation = (
                    m.PresenceType.yes if "PII" in d.data_classes else m.PresenceType.noAssertion
                )
            pkg.verifiedUsing = _hash(d.snapshot.value.commitment) if d.snapshot and d.snapshot.value else []
            self.register(d.id, pkg)
            self.finish_element(
                d.id,
                pkg,
                d,
                extension(
                    "MutableStore",
                    kind=d.data_kind,
                    trustTier=d.trust_tier,
                    instructionBearing=d.instruction_bearing.value,
                    instructionBearingState=d.instruction_bearing.state,
                    live=d.live,
                    embeddingModelRef=d.embedding_model_ref,
                    aclMode=d.acl_mode,
                    writers=d.writers.value if d.writers and d.writers.value else None,
                    writersState=d.writers.state if d.writers else None,
                    tenantIsolation=d.tenant_isolation,
                    retention=d.retention,
                    quarantineStatus=d.quarantine.status if d.quarantine else None,
                    sources=[s.uri for s in d.sources] or None,
                    dataClasses=d.data_classes or None,
                ),
            )
            if d.embedding_model_ref in self.elements:
                self.relate(
                    f"rel:embeds:{d.id}",
                    d.id,
                    [d.embedding_model_ref],
                    "dependsOn",
                    scope="build",
                    qualifiers={"edgeType": "embeds"},
                )

    def policies_software_identities(self) -> None:
        for p in self.bom.policies:
            pkg = m.software_Package()
            pkg.name = p.name or p.id
            pkg.software_primaryPurpose = m.software_SoftwarePurpose.configuration
            pkg.software_downloadLocation = "NOASSERTION"
            pkg.verifiedUsing = _hash(p.bundle_digest)
            self.register(p.id, pkg)
            self.finish_element(
                p.id,
                pkg,
                p,
                extension(
                    "Policy", kind=p.policy_kind, engine=p.engine, enforcementPoint=p.enforcement_point.kind
                ),
            )
        for sw in self.bom.software:
            pkg = m.software_Package()
            pkg.name = sw.name or sw.id
            pkg.software_primaryPurpose = (
                getattr(m.software_SoftwarePurpose, sw.component_type, m.software_SoftwarePurpose.library)
                if sw.component_type in ("application", "library", "framework", "container", "file")
                else m.software_SoftwarePurpose.library
            )
            pkg.software_downloadLocation = "NOASSERTION"
            if sw.version:
                pkg.software_packageVersion = sw.version
            if sw.purl:
                pkg.software_packageUrl = sw.purl
            pkg.verifiedUsing = [h for d in sw.hashes for h in _hash(d)]
            self.register(sw.id, pkg)
            self.finish_element(sw.id, pkg, sw)
        for ident in self.bom.identities:
            obj = m.Person() if ident.identity_kind is E.IdentityKind.HUMAN else m.SoftwareAgent()
            obj.name = ident.name or ident.ref
            ei = m.ExternalIdentifier()
            ei.externalIdentifierType = m.ExternalIdentifierType.other
            ei.identifier = ident.ref
            ei.comment = ident.identity_kind.value
            obj.externalIdentifier = [ei]
            self.register(ident.id, obj)
            self.finish_element(
                ident.id,
                obj,
                ident,
                extension(
                    "Identity",
                    kind=ident.identity_kind,
                    ref=ident.ref,
                    issuer=ident.issuer,
                    tenant=ident.tenant,
                ),
            )
        for cb in self.bom.credential_bindings:
            subject = self.elements.get(cb.subject_ref)
            if subject is None:
                continue
            ext = extension(
                "CredentialBinding",
                id=cb.id,
                identityRef=cb.identity_ref,
                kind=cb.credential_kind,
                lifetime=cb.lifetime,
                storageKind=cb.storage.kind,
                storageLocator=cb.storage.locator,
                scopesGranted=cb.scopes_granted.value
                if cb.scopes_granted and cb.scopes_granted.value
                else None,
            )
            subject.extension = [*(subject.extension or []), ext]
            if cb.identity_ref in self.elements:
                self.relate(
                    f"rel:holds-credential:{cb.id}",
                    cb.subject_ref,
                    [cb.identity_ref],
                    "dependsOn",
                    qualifiers={"edgeType": "holdsCredential", "credentialKind": cb.credential_kind},
                )
        for index, g in enumerate(self.bom.grants):
            # The Sbom's CDX property bridge retains the complete record even for a subject
            # without a native SPDX element. The indexed fields below are query aids.
            self.loss.append(
                LossItem(
                    path=f"/grants/{index}",
                    entity=g.id,
                    reason=E.LossReason.NO_NATIVE_CONSTRUCT,
                    preserved_in=E.LossPreservedIn.EXTENSION,
                    severity=E.LossSeverity.SECURITY_RELEVANT,
                )
            )
            subject = self.elements.get(g.subject_ref)
            if subject is None:
                continue
            ext = extension(
                "CapabilityGrant",
                id=g.id,
                layer=g.layer,
                capability=g.capability,
                conditions=[condition.to_json_dict() for condition in g.conditions] or None,
                spendCeiling=g.scope.spend_ceiling.to_json_dict() if g.scope.spend_ceiling else None,
                rateLimit=g.scope.rate_limit,
                gateRef=g.gate_ref,
                enforcementPointLocator=g.enforcement_point.locator,
                scopeResources=g.scope.resources or None,
                scopeEgress=g.scope.egress or None,
                scopeDataClasses=g.scope.data_classes or None,
                granter=g.granter_ref,
                approvalGate=g.approval_gate,
                notBefore=g.validity.not_before,
                notAfter=g.validity.not_after,
                policyDigest=g.policy_ref.bundle_digest if g.policy_ref else None,
                enforcementPointKind=g.enforcement_point.kind,
                enforcementAttested=g.enforcement_point.attested,
                credentialBindingRef=g.credential_binding_ref,
                delegationChain=[h.to_json_dict() for h in g.delegation_chain] or None,
            )
            subject.extension = [*(subject.extension or []), ext]

    def evidence_and_vex(self) -> None:
        for ev in self.bom.evidence:
            f = m.software_File()
            f.name = ev.name or ev.id
            f.software_primaryPurpose = m.software_SoftwarePurpose.evidence
            f.software_contentType = ev.media_type
            f.verifiedUsing = _hash(ev.digest)
            self.register(ev.id, f)
            self.finish_element(
                ev.id,
                f,
                ev,
                extension(
                    "Evidence", kind=ev.evidence_kind, uri=ev.uri, created=ev.created, expires=ev.expires
                ),
            )
        for ev in self.bom.evaluations:
            f = m.software_File()
            f.name = ev.name or ev.id
            f.software_primaryPurpose = m.software_SoftwarePurpose.evidence
            self.register(ev.id, f)
            self.finish_element(
                ev.id,
                f,
                ev,
                extension(
                    "Evaluation",
                    harness=ev.harness.name,
                    harnessVersion=ev.harness.version,
                    harnessDigest=ev.harness.digest,
                    datasetDigest=ev.dataset.digest if ev.dataset else None,
                    subjectConfigDigest=canonical_bytes(ev.subject_config.to_json_dict()).decode(),
                    results=[r.to_json_dict() for r in ev.results] or None,
                    assessor=ev.assessor_ref,
                    thirdParty=ev.third_party,
                    performedAt=ev.performed_at,
                    expires=ev.validity.expires,
                    status=ev.status,
                ),
            )
        for v in self.bom.vex:
            vuln = m.security_Vulnerability()
            vuln.name = v.weakness.id
            vuln.summary = f"{v.weakness.framework}:{v.weakness.id}"
            ei = m.ExternalIdentifier()
            ei.externalIdentifierType = m.ExternalIdentifierType.securityOther
            ei.identifier = v.weakness.id
            ei.issuingAuthority = v.weakness.framework
            vuln.externalIdentifier = [ei]
            self.register(v.id, vuln)
            self.finish_element(
                v.id,
                vuln,
                v,
                extension(
                    "VexScope",
                    configDigest=v.subject.config_digest,
                    justification=v.justification,
                    expires=v.expires,
                    status=v.status,
                ),
            )
            if v.subject.ref not in self.elements:
                continue
            cls = {
                "not-affected": m.security_VexNotAffectedVulnAssessmentRelationship,
                "affected": m.security_VexAffectedVulnAssessmentRelationship,
                "under-investigation": m.security_VexUnderInvestigationVulnAssessmentRelationship,
                "fixed": m.security_VexFixedVulnAssessmentRelationship,
            }.get(v.status, m.security_VexUnderInvestigationVulnAssessmentRelationship)
            rel = cls()
            rel.spdxId = self.iri(f"rel:vex:{v.id}")
            rel.creationInfo = self.ci
            rel.from_ = vuln
            rel.to = [self.elements[v.subject.ref]]
            rel.relationshipType = {
                "not-affected": m.RelationshipType.doesNotAffect,
                "affected": m.RelationshipType.affects,
                "under-investigation": m.RelationshipType.underInvestigationFor,
                "fixed": m.RelationshipType.fixedIn,
            }.get(v.status, m.RelationshipType.underInvestigationFor)
            rel.security_assessedElement = self.elements[v.subject.ref]
            if v.status == "not-affected" and v.justification in _VEX_JUST:
                rel.security_justificationType = getattr(
                    m.security_VexJustificationType, _VEX_JUST[v.justification]
                )
                rel.security_impactStatement = v.detail or v.justification
            self.objset.add(rel)

    def edges(self) -> None:
        used: set[str] = {k for k in self.elements if k.startswith("rel:")}
        for n, e in enumerate(sorted(self.bom.edges, key=lambda e: e.key)):
            if e.from_ref not in self.elements or e.to_ref not in self.elements:
                continue
            rel_type, reverse = _EDGE_REL.get(e.type, ("dependsOn", False))
            src, dst = (e.to_ref, e.from_ref) if reverse else (e.from_ref, e.to_ref)
            ref = f"rel:{e.type.value}:{n}"
            if ref in used:
                continue
            qualifiers: dict[str, Any] = {"edgeType": e.type.value, "assurance": e.assurance}
            if e.type.value not in rel_type:
                qualifiers["nativeRelationship"] = rel_type
            qualifiers.update(
                {k: v for k, v in e.qualifiers.items() if isinstance(v, str | int | float | bool)}
            )
            scope = (
                e.scope.value
                if e.scope in (E.EdgeScope.BUILD, E.EdgeScope.RUNTIME, E.EdgeScope.TEST)
                else None
            )
            self.relate(
                ref, src, [dst], rel_type, scope=scope or None, completeness=None, qualifiers=qualifiers
            )

    def unknown_surfaces(self, root_ref: str) -> None:
        """Describe empty collections without inferring deployment-wide absence from scoped collection."""
        for collection, surface in (
            ("tool_servers", E.Surface.TOOLS),
            ("models", E.Surface.MODEL_GATEWAY),
            ("data_sources", E.Surface.DATA),
            ("instructions", E.Surface.INSTRUCTIONS),
            ("software", E.Surface.CODE),
        ):
            if getattr(self.bom, collection):
                continue
            cov = self.bom.coverage.surfaces.get(surface)
            # A completed query covers only its listed sources. Even an observed snapshot
            # can combine static files and sampled traces; it cannot prove a closed runtime set.
            try:
                self.relate(
                    f"rel:surface:{surface.value}",
                    root_ref,
                    [NOASSERTION_ELEMENT],
                    "dependsOn",
                    scope="runtime",
                    completeness=m.RelationshipCompleteness.noAssertion,
                    qualifiers={
                        "surface": surface.value,
                        "coverageStatus": cov.status if cov else "not-attempted",
                    },
                )
            except Exception:
                self.loss.append(
                    LossItem(
                        path=f"/coverage/surfaces/{surface.value}",
                        reason=E.LossReason.LIBRARY_LIMITATION,
                        preserved_in=E.LossPreservedIn.EXTENSION,
                        severity=E.LossSeverity.INFO,
                    )
                )

    def documents(self, agent_actor: Any, tools: list[Any]) -> tuple[Any, Any]:
        bom = self.bom
        self.ci.createdBy = [agent_actor] + (
            [self.elements[bom.root_agent.owner_ref]] if bom.root_agent.owner_ref in self.elements else []
        )
        self.ci.createdUsing = tools
        sbom = m.software_Sbom()
        sbom.name = f"AgentBOM {bom.subject} ({bom.snapshot.kind.value} snapshot {bom.snapshot.serial})"
        sbom.software_sbomType = [getattr(m.software_SbomType, _SBOM_TYPE[bom.snapshot.kind])]
        sbom.verifiedUsing = _hash(bom.snapshot.digest)
        coverage = {s.value: c.status.value for s, c in bom.coverage.surfaces.items()}
        snap_ext = extension(
            "Snapshot",
            kind=bom.snapshot.kind,
            serial=bom.snapshot.serial,
            prev=bom.snapshot.prev,
            digest=bom.snapshot.digest,
            merkleRoot=bom.merkle.root if bom.merkle else None,
            merkleLeafCount=bom.merkle.leaf_count if bom.merkle else None,
            notBefore=bom.snapshot.validity.not_before,
            notAfter=bom.snapshot.validity.not_after,
            observationStart=bom.snapshot.observation_window.start
            if bom.snapshot.observation_window
            else None,
            observationEnd=bom.snapshot.observation_window.end if bom.snapshot.observation_window else None,
            companionDigest=self.companion_digest,
            companionRef=self.companion_ref,
            specVersion="0.1",
        )
        cov_ext = extension(
            "Coverage",
            surfaces=canonical_bytes(coverage).decode(),
            collectors=[f"{c.name}@{c.version}:{c.status.value}" for c in bom.coverage.collectors] or None,
            textIncluded=bom.coverage.text_included,
            completeness=bom.coverage.completeness,
            exclusions=[x.pattern for x in bom.coverage.exclusions] or None,
            redactions=[f"{r.redaction_class}:{r.count}" for r in bom.redactions] or None,
        )
        flags_ext = (
            extension(
                "DerivedFlags",
                flags=[f"{f.flag.value}={f.value.value}@{f.subject_ref}" for f in bom.derived.flags] or None,
                findings=[f"{f.check_id}:{f.severity.value}:{f.state.value}" for f in bom.derived.findings]
                or None,
            )
            if (bom.derived.flags or bom.derived.findings)
            else None
        )
        sbom.extension = [
            e for e in (snap_ext, cov_ext, flags_ext, cdx_mirror(self.doc_props)) if e is not None
        ]
        all_elements = [obj for ref, obj in self.elements.items() if not ref.startswith("producer:")]
        sbom.rootElement = [self.elements[bom.subject]]
        sbom.element = all_elements
        self.register("sbom", sbom)
        doc = m.SpdxDocument()
        doc.name = f"Symbiote AgentBOM {bom.subject}"
        doc.rootElement = [sbom]
        doc.element = [sbom, *all_elements]
        profiles = [
            m.ProfileIdentifierType.core,
            m.ProfileIdentifierType.software,
            m.ProfileIdentifierType.ai,
            m.ProfileIdentifierType.dataset,
            m.ProfileIdentifierType.extension,
        ]
        if bom.vex:
            profiles.append(m.ProfileIdentifierType.security)
        doc.profileConformance = profiles
        self.register("document", doc)
        return sbom, doc


def export_spdx(
    bom: AgentBOM,
    *,
    companion_digest: str | None = None,
    companion_ref: str | None = None,
    include_text: bool = False,
) -> tuple[dict[str, Any], LossReport]:
    """Project an AgentBOM onto SPDX 3.0.1 JSON-LD. Returns ``(document, loss_report)``."""
    bom = bom.sorted()
    cdx_doc, _ = export_cyclonedx(
        bom, include_text=include_text, companion_digest=companion_digest, companion_ref=companion_ref
    )
    em = _Emitter(bom, cdx_doc, companion_digest=companion_digest, companion_ref=companion_ref)
    em.objset.add(em.ci)
    agent_actor, tools = em.producers()
    em.parties()
    em.agents()
    em.tool_servers()
    em.tools()
    em.files_and_skills()
    em.models()
    em.data_sources()
    em.policies_software_identities()
    em.evidence_and_vex()
    em.edges()
    em.unknown_surfaces(bom.subject)
    em.documents(agent_actor, tools)
    buf = io.BytesIO()
    m.JSONLDSerializer().write(em.objset, buf, force_at_graph=True)
    doc = json.loads(buf.getvalue().decode("utf-8"))
    # deterministic node order: sort the graph by (type, spdxId)
    doc["@graph"] = sorted(
        doc["@graph"], key=lambda n: (str(n.get("type")), str(n.get("spdxId") or n.get("@id") or ""))
    )
    for red in bom.redacted:
        em.loss.append(
            LossItem(
                path=f"/redacted/{red.id}",
                entity=red.id,
                reason=E.LossReason.REDACTED,
                preserved_in=E.LossPreservedIn.COMPANION,
                severity=E.LossSeverity.INFO,
            )
        )
    report = LossReport(
        direction="model→spdx",
        source_format="agentbom-model",
        target_format="spdx-3.0.1",
        model_digest=bom.snapshot.digest,
        items=account_for_companion(em.loss, companion_ref, companion_digest),
    )
    return doc, report


__all__ = ["NOASSERTION_ELEMENT", "NONE_ELEMENT", "TERMS", "export_spdx", "extension"]
