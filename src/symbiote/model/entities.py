"""Entities of the AgentBOM profile (``spec/agentbom-profile.md §3``)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator, model_validator

from symbiote.model.base import SymbioteModel
from symbiote.model.common import (
    Claim,
    CollectorRef,
    DigestResult,
    DigestStr,
    EntityId,
    EvidenceRef,
    ExternalRef,
    Provenance,
    ThreatRef,
    Validity,
    looks_like_secret,
)
from symbiote.model.enums import (
    AclMode,
    AgentRole,
    AliasPinning,
    ApprovalGate,
    AuthMode,
    AutonomyMode,
    CapabilityClass,
    Classification,
    CollectorMode,
    CollectorStatus,
    Completeness,
    ConditionKind,
    CoverageStatus,
    CredentialKind,
    CredentialStorageKind,
    DataSourceKind,
    DelegationProtocol,
    DerivationKind,
    EnforcementPointKind,
    EnvironmentKind,
    EvidenceKind,
    FindingState,
    FlagName,
    GrantLayer,
    IdentityKind,
    InstructionKind,
    IsoAutomationLevel,
    Launcher,
    LineEndings,
    LossPreservedIn,
    LossReason,
    LossSeverity,
    ModelKind,
    PolicyKind,
    PromptRole,
    PublisherVerification,
    RedactionClass,
    RegistryStatus,
    RequestedRefKind,
    SerializationFormat,
    SerializationRisk,
    Severity,
    SideEffectClass,
    SignatureOutcome,
    SignatureStatus,
    SnapshotMethod,
    Surface,
    TemplateEngine,
    TemplateRiskClass,
    TenantIsolation,
    TextFlag,
    ToolServerKind,
    ToolSource,
    ToolState,
    Transport,
    TriState,
    TrustState,
    TrustSubjectKind,
    TrustTier,
    TrustZone,
)

# --------------------------------------------------------------------------------------------- base


class Entity(SymbioteModel):
    """Fields common to every entity."""

    id: EntityId
    name: str | None = None
    description: str | None = None
    provenance: Provenance = Field(default_factory=Provenance)
    trust_ref: EntityId | None = None
    tags: list[str] = Field(default_factory=list)
    external_refs: list[ExternalRef] = Field(default_factory=list)
    foreign: dict[str, str] = Field(
        default_factory=dict, description="Importer passthrough of unmapped properties"
    )

    @property
    def entity_kind(self) -> str:
        """Entity kind = the id prefix (``agent``, ``tool``, ...)."""
        return self.id.split(":", 1)[0]


# --------------------------------------------------------------------------------------------- agent


class FrameworkRef(SymbioteModel):
    name: str
    version: str | None = None


class AutonomyEntry(SymbioteModel):
    capability: CapabilityClass
    mode: AutonomyMode


class InstructionRef(SymbioteModel):
    ref: EntityId
    precedence: int = 0


class A2ASkill(SymbioteModel):
    id: str
    name: str | None = None
    tags: list[str] = Field(default_factory=list)


class A2ACard(SymbioteModel):
    url: str | None = None
    digest: DigestStr
    version: str | None = None
    protocol_versions: list[str] = Field(default_factory=list)
    skills: list[A2ASkill] = Field(default_factory=list)
    security_schemes: list[str] = Field(default_factory=list)
    signature_status: str = "none"  # none | present | verified


class Agent(Entity):
    version: str
    digest: DigestStr | None = None
    role: AgentRole
    purpose: str | None = None
    framework: Claim[FrameworkRef] | None = None
    owner_ref: EntityId | None = None
    operator_ref: EntityId | None = None
    automation_level: Claim[IsoAutomationLevel] | None = None
    autonomy_profile: list[AutonomyEntry] = Field(default_factory=list)
    identities: list[EntityId] = Field(default_factory=list)
    instructions: list[InstructionRef] = Field(default_factory=list)
    entrypoint: str | None = None
    parent_ref: EntityId | None = None
    a2a_card: A2ACard | None = None
    policy_bundle: Claim[DigestStr] | None = None


class Environment(SymbioteModel):
    kind: EnvironmentKind
    cluster: str | None = None
    namespace: str | None = None
    host: str | None = None
    region: str | None = None


class WorkloadRef(SymbioteModel):
    group: str | None = None
    kind: str | None = None
    namespace: str | None = None
    name: str | None = None
    uid: str | None = None


class SnapshotRef(SymbioteModel):
    digest: DigestStr
    validity: Validity = Field(default_factory=Validity)


class Deployment(Entity):
    agent_ref: EntityId
    snapshot_refs: list[SnapshotRef] = Field(default_factory=list)
    environment: Environment
    tenant: str | None = None
    workload_identity_ref: EntityId | None = None
    workload_ref: WorkloadRef | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    observed_by: list[CollectorRef] = Field(default_factory=list)


# --------------------------------------------------------------------------------------------- tools


class PackageRef(SymbioteModel):
    purl: str | None = None
    digest: DigestStr | None = None
    floating: bool = True
    launcher: Launcher = Launcher.OTHER


class ServerInfo(SymbioteModel):
    name: str
    version: str | None = None
    title: str | None = None


class Authentication(SymbioteModel):
    mode: AuthMode
    issuer: str | None = None
    scopes_requested: list[str] = Field(default_factory=list)


class ToolListMeta(SymbioteModel):
    ttl_ms: int | None = None
    cache_scope: str | None = None


class ToolServer(Entity):
    server_kind: ToolServerKind = Field(alias="kind")
    digest: DigestStr | None = None
    client: str | None = None
    transport: Claim[Transport]
    endpoint: Claim[str] | None = None
    package: Claim[PackageRef] | None = None
    command: str | None = None
    args_digest: DigestStr | None = None
    env_var_names: list[str] = Field(default_factory=list)
    header_names: list[str] = Field(default_factory=list)
    server_info: Claim[ServerInfo] | None = None
    protocol_version: Claim[str] | None = None
    instructions_digest: Claim[DigestStr] | None = None
    authentication: Claim[Authentication]
    trust_zone: TrustZone = TrustZone.UNKNOWN
    crosses_trust_boundary: Claim[bool]
    tool_list_meta: ToolListMeta | None = None
    toolset_digest: Claim[DigestStr] | None = None
    toolset_digest_result: DigestResult | None = None
    registry_resolution_ref: EntityId | None = None
    client_trust_flags: dict[str, str] = Field(default_factory=dict)

    @field_validator("env_var_names", "header_names")
    @classmethod
    def _names_only(cls, v: list[str]) -> list[str]:
        for item in v:
            if "=" in item or looks_like_secret(item):
                raise ValueError("record variable/header NAMES only, never values")
        return v


class ToolAnnotations(SymbioteModel):
    """MCP ``ToolAnnotations`` as served; ``None`` means the server omitted the hint."""

    title: str | None = None
    read_only_hint: bool | None = None
    destructive_hint: bool | None = None
    idempotent_hint: bool | None = None
    open_world_hint: bool | None = None

    @property
    def any_present(self) -> bool:
        return any(
            v is not None
            for v in (self.read_only_hint, self.destructive_hint, self.idempotent_hint, self.open_world_hint)
        )


class SideEffectProfile(SymbioteModel):
    read: bool = False
    write: bool = False
    destructive: bool = False
    open_world: bool = False
    financial: bool = False
    egress_destinations: list[str] = Field(default_factory=list)


class ToolDefinition(Entity):
    server_ref: EntityId
    tool_name: str
    title: str | None = None
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    annotations: Claim[ToolAnnotations] | None = None
    digest: DigestResult
    full_digest: DigestResult | None = None
    description_digest: DigestStr | None = None
    input_schema_digest: DigestStr | None = None
    source: ToolSource
    side_effects: Claim[SideEffectProfile] | None = None
    side_effect_class: SideEffectClass = SideEffectClass.UNKNOWN
    capabilities: list[CapabilityClass] = Field(default_factory=list)
    required_scopes: Claim[list[str]] | None = None
    approval_gate: ApprovalGate = ApprovalGate.UNKNOWN
    text_flags: list[TextFlag] = Field(default_factory=list)
    state: ToolState = ToolState.DECLARED
    invocation_count: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


# --------------------------------------------------------------------------------------------- instructions


class VcsSource(SymbioteModel):
    vcs_url: str | None = None
    revision: str | None = None
    blob_id: str | None = None


class Instruction(Entity):
    instruction_kind: InstructionKind = Field(alias="kind")
    path: str | None = None
    uri: str | None = None
    media_type: str = "text/markdown"
    size: int = Field(ge=0)
    digest: DigestStr
    normalized_digest: DigestStr | None = None
    line_endings: LineEndings = LineEndings.LF
    precedence: int = 0
    editors: Claim[list[EntityId]] | None = None
    loads_remote: Claim[list[str]] | None = None
    contains_secret_like: bool = False
    frontmatter: dict[str, Any] | None = None
    source: VcsSource | None = None


class PromptTemplate(Entity):
    engine: TemplateEngine = TemplateEngine.NONE
    role: PromptRole = PromptRole.SYSTEM
    digest: DigestResult
    template_digest: DigestStr
    variables_schema: dict[str, Any] | None = None
    variables_schema_digest: DigestStr | None = None
    path: str | None = None
    risk_class: TemplateRiskClass = TemplateRiskClass.NONE


class ManifestItem(SymbioteModel):
    name: str
    digest: DigestStr
    size: int | None = Field(default=None, ge=0)


class DirManifest(SymbioteModel):
    method: str = "files"
    hash_type: str = "sha256"
    allow_symlinks: bool = False
    ignore: list[str] = Field(default_factory=lambda: [".git/**"])
    resources: list[ManifestItem]
    root: DigestStr


class ScriptRef(SymbioteModel):
    path: str
    digest: DigestStr
    interpreter: str | None = None


class SkillFrontmatter(SymbioteModel):
    name: str | None = None
    description: str | None = None
    license: str | None = None
    compatibility: str | None = None
    allowed_tools: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Skill(Entity):
    path: str
    digest: DigestStr
    manifest: DirManifest
    skill_md_ref: EntityId | None = None
    frontmatter: SkillFrontmatter = Field(default_factory=SkillFrontmatter)
    scripts: list[ScriptRef] = Field(default_factory=list)
    referenced_servers: list[str] = Field(default_factory=list)
    has_scripts: bool = False
    name_matches_directory: bool = True


# --------------------------------------------------------------------------------------------- models


class Fingerprint(SymbioteModel):
    method: str
    digest: DigestStr
    sampled_at: datetime | None = None
    expires: datetime | None = None


class WeightsIdentity(SymbioteModel):
    purl: str | None = None
    manifest_root: DigestStr
    manifest_ref: str | None = None
    file_count: int = Field(ge=0)
    formats: list[SerializationFormat] = Field(default_factory=list)


class HostedIdentity(SymbioteModel):
    provider: str
    endpoint_origin: str | None = None
    requested_ref: str
    resolved_ref: Claim[str]
    alias_pinning: AliasPinning = AliasPinning.UNKNOWN
    provider_evidence: list[EvidenceRef] = Field(default_factory=list)
    fingerprint: Fingerprint | None = None


class ModelManifest(DirManifest):
    format: str = "oms-v1"
    shard_size: int | None = None


class Serialization(SymbioteModel):
    formats: list[SerializationFormat] = Field(default_factory=list)
    risk_class: SerializationRisk = SerializationRisk.NONE
    trust_remote_code: TriState = TriState.UNKNOWN
    chat_template_executable: TriState = TriState.UNKNOWN
    scanner_name: str | None = None
    scanner_version: str | None = None
    scanner_report_digest: DigestStr | None = None


class Derivation(SymbioteModel):
    kind: DerivationKind
    parent: str = Field(description="entity ref, purl or free text")
    parent_state: str = "present"  # present | unknown
    parameters: dict[str, Any] = Field(default_factory=dict)
    parameters_digest: DigestStr | None = None
    assurance: str = "declared"


class SignatureFacts(SymbioteModel):
    status: SignatureStatus = SignatureStatus.UNSIGNED
    outcome: SignatureOutcome = SignatureOutcome.NONE
    reason: str | None = None
    identity: str | None = None
    issuer: str | None = None
    log_entry: str | None = None
    subject_name_mismatch: bool | None = None
    bundle_digest: DigestStr | None = None

    @model_validator(mode="after")
    def _no_laundering(self) -> SignatureFacts:
        # I3: "valid signature, unconstrained signer" can never be presented as verified.
        if self.status is SignatureStatus.VERIFIED and self.outcome is not SignatureOutcome.VERIFIED:
            raise ValueError("I3: status=verified requires outcome=verified")
        if self.status is SignatureStatus.VERIFIED and not self.identity:
            raise ValueError("I3: a verified signature records the constrained signer identity")
        return self


class ModelCardMetric(SymbioteModel):
    name: str
    value: str | float | int
    dataset_digest: DigestStr | None = None


class ModelCardFacts(SymbioteModel):
    task: str | None = None
    architecture: str | None = None
    approach: str | None = None
    datasets: list[EntityId] = Field(default_factory=list)
    metrics: list[ModelCardMetric] = Field(default_factory=list)
    limitations: str | None = None
    users: str | None = None
    use_cases: str | None = None


class Model(Entity):
    model_kind: ModelKind = Field(alias="kind")
    weights: Claim[WeightsIdentity] | None = None
    hosted: Claim[HostedIdentity] | None = None
    manifest: ModelManifest | None = None
    tensor_manifest_root: DigestStr | None = None
    serialization: Claim[Serialization] | None = None
    derivations: list[Derivation] = Field(default_factory=list)
    signature: SignatureFacts | None = None
    tokenizer_ref: EntityId | None = None
    chat_template_ref: EntityId | None = None
    generation_config_digest: DigestStr | None = None
    card: ModelCardFacts | None = None
    endpoint_ref: EntityId | None = None

    @model_validator(mode="after")
    def _identity_present(self) -> Model:
        if self.model_kind is ModelKind.HOSTED and self.hosted is None:
            raise ValueError("a hosted model needs a hosted identity claim (value or explicit unknown)")
        if (
            self.model_kind in (ModelKind.WEIGHTS, ModelKind.ADAPTER, ModelKind.EMBEDDING)
            and self.weights is None
            and self.hosted is None
        ):
            raise ValueError(
                "a weights-based model needs a weights identity claim (value or explicit unknown)"
            )
        return self


# --------------------------------------------------------------------------------------------- data


class Sanitizer(SymbioteModel):
    name: str
    digest: DigestStr | None = None


class SnapshotCommitment(SymbioteModel):
    commitment: DigestStr
    method: SnapshotMethod = SnapshotMethod.HASH
    at: datetime | None = None


class Chunking(SymbioteModel):
    strategy: str | None = None
    size: int | None = None
    overlap: int | None = None
    digest: DigestStr | None = None


class DataOrigin(SymbioteModel):
    uri: str
    digest: DigestStr | None = None
    fetched_at: datetime | None = None
    license: str | None = None
    consent_status: str | None = None


class Quarantine(SymbioteModel):
    status: str
    since: datetime | None = None


class DataSource(Entity):
    data_kind: DataSourceKind = Field(alias="kind")
    location: str | None = None
    classification: Classification = Classification.UNKNOWN
    data_classes: list[str] = Field(default_factory=list)
    trust_tier: TrustTier = TrustTier.UNKNOWN
    instruction_bearing: Claim[bool]
    sanitization: list[Sanitizer] = Field(default_factory=list)
    snapshot: Claim[SnapshotCommitment] | None = None
    live: bool = False
    refresh_policy: str | None = None
    embedding_model_ref: EntityId | None = None
    chunking: Chunking | None = None
    sources: list[DataOrigin] = Field(default_factory=list)
    acl_mode: AclMode = AclMode.UNKNOWN
    writers: Claim[list[EntityId]] | None = None
    tenant_isolation: TenantIsolation = TenantIsolation.UNKNOWN
    retention: str | None = None
    quarantine: Quarantine | None = None
    invalidation_dependents: list[EntityId] = Field(default_factory=list)
    poison_scan: EvidenceRef | None = None


# --------------------------------------------------------------------------------------------- identity & authority


class Identity(Entity):
    identity_kind: IdentityKind = Field(alias="kind")
    ref: str = Field(description="SPIFFE ID / client id / ARN / email — never a secret value")
    issuer: str | None = None
    tenant: str | None = None

    @field_validator("ref")
    @classmethod
    def _no_secret(cls, v: str) -> str:
        if looks_like_secret(v):
            raise ValueError("Identity.ref looks like a secret value; record a reference, never the secret")
        return v


class CredentialStorage(SymbioteModel):
    kind: CredentialStorageKind = CredentialStorageKind.UNKNOWN
    locator: str | None = None


class CredentialBinding(Entity):
    subject_ref: EntityId
    identity_ref: EntityId
    credential_kind: CredentialKind = Field(default=CredentialKind.UNKNOWN, alias="kind")
    lifetime: str | None = None
    scopes_granted: Claim[list[str]] | None = None
    storage: CredentialStorage = Field(default_factory=CredentialStorage)

    @field_validator("lifetime")
    @classmethod
    def _no_secret(cls, v: str | None) -> str | None:
        if v and looks_like_secret(v):
            raise ValueError("secret-shaped value in CredentialBinding")
        return v


class SpendCeiling(SymbioteModel):
    amount: float
    currency: str
    period: str


class Scope(SymbioteModel):
    resources: list[str] = Field(default_factory=list)
    egress: list[str] = Field(default_factory=list)
    data_classes: list[str] = Field(default_factory=list)
    spend_ceiling: SpendCeiling | None = None
    rate_limit: str | None = None


class DelegationHop(SymbioteModel):
    from_ref: EntityId = Field(alias="from")
    to_ref: EntityId = Field(alias="to")
    protocol: DelegationProtocol
    audience: str | None = None
    scopes: list[str] = Field(default_factory=list)
    constraints: str | None = None
    expires: datetime | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)


class Condition(SymbioteModel):
    kind: ConditionKind
    expr: str


class EnforcementPoint(SymbioteModel):
    kind: EnforcementPointKind = EnforcementPointKind.UNKNOWN
    locator: str | None = None
    attested: bool = False


class PolicyRef(SymbioteModel):
    policy_id: EntityId | None = None
    bundle_digest: DigestStr


class Grant(Entity):
    layer: GrantLayer
    subject_ref: EntityId
    capability: CapabilityClass
    scope: Scope = Field(default_factory=Scope)
    granter_ref: EntityId | None = None
    delegation_chain: list[DelegationHop] = Field(default_factory=list)
    conditions: list[Condition] = Field(default_factory=list)
    approval_gate: ApprovalGate = ApprovalGate.NONE
    gate_ref: str | None = None
    validity: Validity = Field(default_factory=Validity)
    policy_ref: PolicyRef | None = None
    enforcement_point: EnforcementPoint = Field(default_factory=EnforcementPoint)
    credential_binding_ref: EntityId | None = None


class ApprovalCovers(SymbioteModel):
    tool_digests: list[DigestStr] = Field(default_factory=list)
    model_ids: list[EntityId] = Field(default_factory=list)
    grant_ids: list[EntityId] = Field(default_factory=list)
    deployment_selector: str | None = None


class Approval(Entity):
    approver_ref: EntityId
    approved_snapshot_digest: DigestStr
    covers: ApprovalCovers = Field(default_factory=ApprovalCovers)
    policy_ref: PolicyRef | None = None
    issued_at: datetime
    expires: datetime | None = None
    revocation_ref: str | None = None
    attestation_ref: EvidenceRef | None = None


class RequestedRef(SymbioteModel):
    kind: RequestedRefKind
    ref: str


class ResolvedRef(SymbioteModel):
    immutable_ref: str | None = None
    digest: DigestStr | None = None
    state: str = "present"  # present | unknown


class RegistryFacts(SymbioteModel):
    url: str | None = None
    entry_id: str | None = None
    version: str | None = None
    status: RegistryStatus = RegistryStatus.UNKNOWN
    published_at: datetime | None = None
    updated_at: datetime | None = None
    is_latest: bool | None = None
    schema_version: str | None = None


class PublisherFacts(SymbioteModel):
    namespace: str | None = None
    identity: str | None = None
    verification: PublisherVerification = PublisherVerification.UNKNOWN


class TransparencyLog(SymbioteModel):
    type: str = "rekor"
    log_id: str | None = None
    log_index: int | None = None
    integrated_time: datetime | None = None
    inclusion_proof_verified: bool = False


class TyposquatDistance(SymbioteModel):
    nearest: str
    levenshtein: int


class RegistryResolution(Entity):
    requested: RequestedRef
    resolved_at: datetime
    resolver: str
    resolved: ResolvedRef
    registry: RegistryFacts | None = None
    publisher: PublisherFacts | None = None
    signer: SignatureFacts | None = None
    transparency_log: TransparencyLog | None = None
    alias_policy: AliasPinning = AliasPinning.UNKNOWN
    typosquat_distance: TyposquatDistance | None = None
    warnings: list[str] = Field(default_factory=list)


class TrustStatus(Entity):
    subject_kind: TrustSubjectKind
    subject_key: str
    status: TrustState
    reason: str
    decided_by_ref: EntityId
    decided_at: datetime
    expires: datetime | None = None
    serial: int = Field(ge=1)
    supersedes: EntityId | None = None


class Policy(Entity):
    policy_kind: PolicyKind = Field(alias="kind")
    engine: str | None = None
    bundle_digest: DigestStr
    enforcement_point: EnforcementPoint = Field(default_factory=EnforcementPoint)


# --------------------------------------------------------------------------------------------- evidence


class Evidence(Entity):
    evidence_kind: EvidenceKind = Field(alias="kind")
    media_type: str
    digest: DigestStr
    uri: str | None = None
    created: datetime
    expires: datetime | None = None
    author_ref: EntityId | None = None
    redaction_class: RedactionClass | None = None

    @model_validator(mode="after")
    def _id_from_digest(self) -> Evidence:
        expected = "ev:" + self.digest[len("sha256:") :][:12]
        if self.id != expected:
            raise ValueError(f"Evidence.id must be {expected}")
        return self


class SubjectConfig(SymbioteModel):
    model_digests: list[DigestStr] = Field(default_factory=list)
    prompt_digests: list[DigestStr] = Field(default_factory=list)
    toolset_digests: list[DigestStr] = Field(default_factory=list)
    data_source_digests: list[DigestStr] = Field(default_factory=list)
    policy_digest: DigestStr | None = None


class Harness(SymbioteModel):
    name: str
    version: str | None = None
    digest: DigestStr | None = None


class EvalDataset(SymbioteModel):
    name: str
    digest: DigestStr | None = None
    size: int | None = None


class AttackConditions(SymbioteModel):
    attacker_knowledge: str | None = None
    channels: list[str] = Field(default_factory=list)
    budget: str | None = None


class EvalResult(SymbioteModel):
    metric: str
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=1)
    value: float | None = None
    threshold: float | None = None
    passed: bool | None = None


class EvalValidity(SymbioteModel):
    expires: datetime | None = None
    invalidated_by: list[str] = Field(default_factory=list)


class Evaluation(Entity):
    subject_config: SubjectConfig
    threat_model: list[ThreatRef] = Field(default_factory=list)
    harness: Harness
    dataset: EvalDataset | None = None
    attack_conditions: AttackConditions = Field(default_factory=AttackConditions)
    results: list[EvalResult] = Field(default_factory=list)
    assessor_ref: EntityId
    third_party: bool = False
    performed_at: datetime
    validity: EvalValidity = Field(default_factory=EvalValidity)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    status: str = "valid"  # valid | stale


class VexSubject(SymbioteModel):
    ref: EntityId
    config_digest: DigestStr | None = None


class VexStatement(Entity):
    weakness: ThreatRef
    subject: VexSubject
    status: str
    justification: str | None = None
    detail: str | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    issued_at: datetime
    last_updated: datetime | None = None
    expires: datetime | None = None
    author_ref: EntityId | None = None


# --------------------------------------------------------------------------------------------- coverage & collectors


class SourceRun(SymbioteModel):
    source: str
    locator: str | None = None
    ok: bool
    error_class: str | None = None
    items: int = 0


class SurfaceCoverage(SymbioteModel):
    status: CoverageStatus = CoverageStatus.NOT_ATTEMPTED
    sources: list[SourceRun] = Field(default_factory=list)
    items_seen: int = 0
    truncated_at: int | None = None

    @property
    def completeness(self) -> Completeness:
        if self.status is CoverageStatus.QUERIED:
            return Completeness.COMPLETE
        if self.status in (CoverageStatus.PARTIAL, CoverageStatus.TRUNCATED):
            return Completeness.INCOMPLETE
        return Completeness.UNKNOWN


class CollectorRun(SymbioteModel):
    name: str
    version: str
    status: CollectorStatus = CollectorStatus.SKIPPED
    reason: str | None = None


class Exclusion(SymbioteModel):
    pattern: str
    reason: str | None = None


class Window(SymbioteModel):
    start: datetime
    end: datetime


class Coverage(SymbioteModel):
    surfaces: dict[Surface, SurfaceCoverage] = Field(
        default_factory=lambda: {s: SurfaceCoverage() for s in Surface}
    )
    exclusions: list[Exclusion] = Field(default_factory=list)
    window: Window | None = None
    collectors: list[CollectorRun] = Field(default_factory=list)
    text_included: bool = False

    @model_validator(mode="after")
    def _all_surfaces(self) -> Coverage:
        missing = [s for s in Surface if s not in self.surfaces]
        if missing:
            new = dict(self.surfaces)
            for s in missing:
                new[s] = SurfaceCoverage()
            object.__setattr__(self, "surfaces", new)
        return self

    @property
    def completeness(self) -> Completeness:
        states = {c.completeness for c in self.surfaces.values()}
        if states == {Completeness.COMPLETE}:
            return Completeness.COMPLETE
        if Completeness.COMPLETE in states or Completeness.INCOMPLETE in states:
            return Completeness.INCOMPLETE
        return Completeness.UNKNOWN


class Collector(SymbioteModel):
    name: str
    version: str
    digest: DigestStr | None = None
    mode: CollectorMode = CollectorMode.DECLARED
    surfaces: list[Surface] = Field(default_factory=list)

    @property
    def ref(self) -> str:
        return f"collector:{self.name}@{self.version}"


class SoftwareComponent(Entity):
    """A verbatim CycloneDX component from a merged software SBOM."""

    purl: str | None = None
    version: str | None = None
    component_type: str = "library"
    hashes: list[DigestStr] = Field(default_factory=list)
    cyclonedx: dict[str, Any] = Field(default_factory=dict, description="Original component JSON, verbatim")


# --------------------------------------------------------------------------------------------- derived


class Flag(SymbioteModel):
    flag: FlagName
    subject_ref: EntityId
    value: TriState
    inputs: list[EntityId] = Field(default_factory=list)
    assurance: str = "declared"


class Finding(SymbioteModel):
    check_id: str
    severity: Severity
    state: FindingState = FindingState.FAIL
    subject_refs: list[EntityId] = Field(default_factory=list)
    inputs: list[EntityId] = Field(default_factory=list)
    message: str
    mappings: list[ThreatRef] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    locator: str | None = None


class Redaction(SymbioteModel):
    redaction_class: str
    count: int = Field(ge=1)
    applied_by: str
    applied_at: datetime
    ids: list[EntityId] = Field(default_factory=list)


class LossItem(SymbioteModel):
    path: str
    entity: str | None = None
    field: str | None = None
    reason: LossReason
    preserved_in: LossPreservedIn
    severity: LossSeverity = LossSeverity.INFO


class LossReport(SymbioteModel):
    direction: str
    source_format: str
    target_format: str
    model_digest: DigestStr | None = None
    items: list[LossItem] = Field(default_factory=list)

    @property
    def lossless(self) -> bool:
        return not any(i.preserved_in is LossPreservedIn.DROPPED for i in self.items)

    @property
    def security_relevant_dropped(self) -> list[LossItem]:
        return [
            i
            for i in self.items
            if i.severity is LossSeverity.SECURITY_RELEVANT and i.preserved_in is LossPreservedIn.DROPPED
        ]


class CycloneDXLink(SymbioteModel):
    serial_number: str
    version: int
    bom_link: str
    digest: DigestStr


class SpdxLink(SymbioteModel):
    document_iri: str
    digest: DigestStr


class Links(SymbioteModel):
    cyclonedx: CycloneDXLink | None = None
    spdx: SpdxLink | None = None


class ForeignProperty(SymbioteModel):
    dialect: str
    element_id: str
    name: str
    value: str


__all__ = [
    n
    for n, o in list(globals().items())
    if isinstance(o, type) and getattr(o, "__module__", None) == __name__
]
