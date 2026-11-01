"""Pydantic domain models for all AgentBOM component types.

These extend CycloneDX/SPDX with agent-native semantics that neither standard
provides: tool capability declarations, prompt provenance, memory governance,
registry trust, and authorization records.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SerializerFunctionWrapHandler, model_serializer

from nexus_symbiote.core.enums import (
    AssuranceLevel,
    AutonomyLevel,
    CapabilityClass,
    ComponentType,
    ExecutionIsolation,
    HumanInTheLoop,
    RiskSeverity,
    SerializationSafety,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.evidence import DeploymentProfile


class InventoryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClaimEvidence(InventoryModel):
    """Evidence about one named claim; observation never establishes runtime permission."""

    assurance: AssuranceLevel = AssuranceLevel.DECLARED
    method: str
    scope: str
    collector: str | None = None
    locator: str | None = None
    observed_at: datetime | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    unknown_reason: str | None = None


class ComponentBase(InventoryModel):
    """Base for every AgentBOM component."""

    model_config = ConfigDict(extra="forbid")

    bom_ref: str = Field(description="Unique reference within this BOM")
    component_type: ComponentType
    name: str
    version: str | None = None
    supplier: str | None = None
    description: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)
    trust_tier: TrustTier = TrustTier.UNKNOWN
    assurance_level: AssuranceLevel = AssuranceLevel.DECLARED
    source_path: str | None = Field(
        default=None, description="Filesystem path or URL where this was discovered"
    )
    properties: dict[str, Any] = Field(default_factory=dict, description="Extension properties")
    claims: dict[str, ClaimEvidence] = Field(default_factory=dict)


class CapabilityDeclaration(InventoryModel):
    """What a component is permitted to do."""

    capabilities: list[CapabilityClass] = Field(default_factory=list)
    oauth_scopes: list[str] = Field(default_factory=list)
    egress_domains: list[str] = Field(default_factory=list)
    filesystem_paths: list[str] = Field(default_factory=list)
    side_effect_profile: SideEffectProfile = SideEffectProfile.UNKNOWN
    execution_isolation: ExecutionIsolation | None = Field(
        default=None, description="Declared isolation; null or absent means unknown"
    )
    human_in_the_loop: HumanInTheLoop | None = Field(
        default=None, description="Declared human-approval setting; null or absent means unknown"
    )


class AuthorizationRecord(InventoryModel):
    """Who authorized what, under which policy."""

    principal: str
    delegating_principal: str | None = None
    action: str
    resource_scope: str | None = None
    conditions: list[str] = Field(default_factory=list)
    approval_required: bool | None = None
    expires_at: datetime | None = None
    policy_reference: str | None = None


class RiskAssessment(InventoryModel):
    """Per-component supply chain risk assessment."""

    severity: RiskSeverity
    category: str
    detail: str
    recommendation: str | None = None
    references: list[str] = Field(default_factory=list)


class AgentComponent(ComponentBase):
    """An autonomous AI agent deployment."""

    component_type: Literal[ComponentType.AGENT] = ComponentType.AGENT
    autonomy_level: AutonomyLevel | None = AutonomyLevel.L2_AGENT
    deployment_status: Literal["unknown", "declared", "observed"] = "unknown"
    deployment_id: str | None = None
    workload_identity: str | None = None
    tenant: str | None = None
    data_refs: list[str] = Field(default_factory=list)
    skill_refs: list[str] = Field(default_factory=list)
    framework: str | None = Field(
        default=None, description="Agent framework (LangGraph, CrewAI, etc.)"
    )
    model_refs: list[str] = Field(
        default_factory=list, description="bom_ref pointers to model components"
    )
    tool_refs: list[str] = Field(
        default_factory=list, description="bom_ref pointers to tool/MCP components"
    )
    memory_refs: list[str] = Field(default_factory=list)
    prompt_refs: list[str] = Field(default_factory=list)
    guardrail_refs: list[str] = Field(default_factory=list)
    sub_agent_refs: list[str] = Field(
        default_factory=list,
        description="bom_ref pointers to delegated sub-agents",
    )
    capabilities: CapabilityDeclaration | None = None
    authorizations: list[AuthorizationRecord] = Field(default_factory=list)
    risks: list[RiskAssessment] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def preserve_unknown_autonomy(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        # The legacy constructor default is L2; explicit unknown must survive exclude_none exports.
        if self.autonomy_level is None:
            data["autonomy_level"] = None
        return data

    deployment_profile: DeploymentProfile | None = Field(
        default=None,
        description="Optional deployment-scoped authority claims and their evidence provenance",
    )


class MCPServerComponent(ComponentBase):
    """An MCP server that provides tools to agents."""

    component_type: Literal[ComponentType.MCP_SERVER] = ComponentType.MCP_SERVER
    transport: str | None = Field(default=None, description="stdio, sse, streamable-http")
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    endpoint_url: str | None = None
    tool_count: int = 0
    tool_refs: list[str] = Field(default_factory=list)
    registry_source: str | None = None
    version_pinned: bool = False
    schema_hash: str | None = Field(
        default=None,
        description="Hash of the aggregate tool definitions served by this MCP server",
    )
    risks: list[RiskAssessment] = Field(default_factory=list)


class ToolComponent(ComponentBase):
    """A single tool definition (from MCP, plugin, or function call)."""

    component_type: Literal[ComponentType.TOOL] = ComponentType.TOOL
    mcp_server_ref: str | None = None
    input_schema: dict[str, Any] | None = None
    description_text: str | None = Field(
        default=None,
        description="The natural-language description fed into the LLM context",
    )
    definition_hash: str | None = Field(
        default=None,
        description="JCS canonical hash of (name, description, inputSchema, annotations)",
    )
    capabilities: CapabilityDeclaration | None = None
    annotations: dict[str, Any] = Field(
        default_factory=dict,
        description="MCP tool annotations (readOnlyHint, destructiveHint, etc.)",
    )
    risks: list[RiskAssessment] = Field(default_factory=list)

    definition_hash_version: str | None = Field(
        default=None,
        description="Canonicalization protocol, or unknown for legacy fingerprints",
    )


class ModelComponent(ComponentBase):
    """A model (weights, adapter, embedding model) used by an agent."""

    component_type: Literal[ComponentType.MODEL] = ComponentType.MODEL
    model_type: str | None = Field(
        default=None,
        description="foundation, fine-tuned, adapter, embedding, quantized",
    )
    provider: str | None = None
    endpoint: str | None = None
    requested_alias: str | None = Field(
        default=None, description="The alias requested (e.g. 'gpt-4o')"
    )
    resolved_revision: str | None = Field(
        default=None, description="Provider-specific snapshot identifier"
    )
    serialization_format: str | None = None
    serialization_safety: SerializationSafety = SerializationSafety.UNKNOWN
    signing_status: str | None = Field(
        default=None, description="unsigned, sigstore-signed, pgp-signed"
    )
    signing_identity: str | None = None
    base_model_ref: str | None = Field(
        default=None, description="bom_ref of the base model this derives from"
    )
    derivation_type: str | None = Field(
        default=None,
        description="fine-tune, lora, qlora, merge, quantization, distillation",
    )
    quantization_method: str | None = None
    tokenizer_hash: str | None = None
    chat_template_hash: str | None = None
    trust_remote_code: bool | None = Field(
        default=None, description="Declared configuration only; the runtime value may differ"
    )
    risks: list[RiskAssessment] = Field(default_factory=list)

    @property
    def unverified_safetensors(self) -> bool:
        return (
            self.serialization_format in {"safetensors", "safe-tensors"}
            and self.serialization_safety == SerializationSafety.UNKNOWN
        )


class PromptComponent(ComponentBase):
    """A system prompt, instruction template, or behavior-shaping artifact."""

    component_type: Literal[ComponentType.PROMPT_TEMPLATE] = ComponentType.PROMPT_TEMPLATE
    prompt_type: str | None = Field(
        default=None,
        description="system-prompt, planner, instruction, rules-file, skill-definition",
    )
    content_hash: str | None = Field(default=None, description="Hash of the exact prompt bytes")
    variable_schema: dict[str, Any] | None = Field(
        default=None, description="Schema of template variables"
    )
    modification_authority: str | None = Field(
        default=None,
        description="Who can edit this prompt (owner, admin, agent, public)",
    )
    risks: list[RiskAssessment] = Field(default_factory=list)


class GuardrailComponent(ComponentBase):
    """A safety classifier, content filter, or output validator."""

    component_type: Literal[ComponentType.GUARDRAIL_POLICY] = ComponentType.GUARDRAIL_POLICY
    guardrail_type: str | None = Field(
        default=None,
        description="input-filter, output-filter, classifier, rate-limiter",
    )
    model_ref: str | None = Field(
        default=None, description="bom_ref of the model backing this guardrail"
    )
    policy_version: str | None = None
    config_hash: str | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class MemoryStoreComponent(ComponentBase):
    """Persistent memory (conversation history, learned facts, skills)."""

    component_type: Literal[ComponentType.MEMORY_STORE] = ComponentType.MEMORY_STORE
    store_type: str | None = Field(
        default=None,
        description="conversation, episodic, semantic, procedural, skill",
    )
    write_authority: str | None = Field(
        default=None,
        description="Who may write: agent-only, user, system, public",
    )
    retention_policy: str | None = None
    tenant_isolated: bool | None = None
    encryption_at_rest: bool | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class RAGSourceComponent(ComponentBase):
    """A retrieval-augmented generation data source or vector index."""

    component_type: Literal[ComponentType.RAG_SOURCE] = ComponentType.RAG_SOURCE
    corpus_type: str | None = Field(
        default=None,
        description="vector-store, knowledge-base, web-scraper, api-connector",
    )
    embedding_model_ref: str | None = None
    embedding_model_name: str | None = None
    chunking_strategy: str | None = None
    index_snapshot_hash: str | None = None
    source_uris: list[str] = Field(default_factory=list)
    refresh_policy: str | None = None
    last_indexed_at: datetime | None = None
    document_count: int | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class DataSourceComponent(ComponentBase):
    """A training or fine-tuning dataset."""

    component_type: Literal[ComponentType.DATA_SOURCE] = ComponentType.DATA_SOURCE
    dataset_type: str | None = Field(
        default=None,
        description="pre-training, fine-tuning, evaluation, alignment",
    )
    source_uri: str | None = None
    content_hash: str | None = None
    collection_date: str | None = None
    license: str | None = None
    consent_status: str | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class RegistryEntryComponent(ComponentBase):
    """A registry from which components are discovered or installed."""

    component_type: Literal[ComponentType.REGISTRY_ENTRY] = ComponentType.REGISTRY_ENTRY
    registry_type: str | None = Field(
        default=None,
        description="npm, pypi, huggingface, mcp-registry, skill-marketplace, docker-hub",
    )
    registry_uri: str | None = None
    publisher_identity: str | None = None
    publisher_verified: bool | None = None
    attestation_status: str | None = None
    signing_key_reference: str | None = None
    trust_model: str | None = Field(default=None, description="tofu, pki, sigstore, none")
    risks: list[RiskAssessment] = Field(default_factory=list)


class SkillPackageComponent(ComponentBase):
    """A skill or plugin package that extends agent capabilities."""

    component_type: Literal[ComponentType.SKILL_PACKAGE] = ComponentType.SKILL_PACKAGE
    skill_type: str | None = Field(
        default=None, description="skill, plugin, connector, hook, extension"
    )
    registry_ref: str | None = None
    entry_point: str | None = None
    capabilities: CapabilityDeclaration | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class MCPClientComponent(ComponentBase):
    """An MCP client that connects to MCP servers."""

    component_type: Literal[ComponentType.MCP_CLIENT] = ComponentType.MCP_CLIENT
    host_application: str | None = Field(
        default=None, description="The IDE or agent host (claude-code, cursor, etc.)"
    )
    server_refs: list[str] = Field(
        default_factory=list, description="bom_ref pointers to connected MCP servers"
    )
    config_path: str | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class A2AClientComponent(ComponentBase):
    """An A2A protocol client that discovers and invokes remote agents."""

    component_type: Literal[ComponentType.A2A_CLIENT] = ComponentType.A2A_CLIENT
    agent_card_url: str | None = Field(default=None, description="URL of the remote agent card")
    supported_protocols: list[str] = Field(default_factory=list)
    authentication_methods: list[str] = Field(default_factory=list)
    capabilities: CapabilityDeclaration | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class A2AServerComponent(ComponentBase):
    """An A2A protocol server exposing agent capabilities to other agents."""

    component_type: Literal[ComponentType.A2A_SERVER] = ComponentType.A2A_SERVER
    agent_card_path: str | None = Field(
        default=None, description="Path or URL to the agent card JSON"
    )
    endpoint_url: str | None = None
    supported_protocols: list[str] = Field(default_factory=list)
    skills_declared: list[str] = Field(default_factory=list)
    authentication_required: bool | None = None
    capabilities: CapabilityDeclaration | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class IDEAgentComponent(ComponentBase):
    """An IDE coding agent configuration (Claude Code, Codex, Cursor, etc.)."""

    component_type: Literal[ComponentType.IDE_AGENT] = ComponentType.IDE_AGENT
    ide_type: str | None = Field(
        default=None,
        description="claude-code, codex, cursor, antigravity, xai, windsurf, cline",
    )
    config_files: list[str] = Field(default_factory=list)
    mcp_server_refs: list[str] = Field(default_factory=list)
    prompt_refs: list[str] = Field(default_factory=list)
    permission_mode: str | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class VerifiedExtensionComponent(ComponentBase):
    """An AI agent extension with verification/attestation status."""

    component_type: Literal[ComponentType.VERIFIED_EXTENSION] = ComponentType.VERIFIED_EXTENSION
    extension_type: str | None = Field(
        default=None, description="plugin, skill, connector, integration, action"
    )
    publisher: str | None = None
    publisher_verified: bool = False
    attestation_status: str | None = Field(
        default=None, description="verified, unverified, revoked, expired"
    )
    signing_identity: str | None = None
    marketplace_url: str | None = None
    install_count: int | None = None
    capabilities: CapabilityDeclaration | None = None
    risks: list[RiskAssessment] = Field(default_factory=list)


class CompletenessClaim(InventoryModel):
    """What was actually scanned and what was excluded."""

    scope: str = Field(description="What this completeness claim covers (e.g. 'full-agent')")
    surfaces_scanned: list[str] = Field(default_factory=list)
    surfaces_excluded: list[str] = Field(default_factory=list)
    scan_failures: list[str] = Field(default_factory=list)
    timestamp: datetime | None = None
    assurance_level: AssuranceLevel = AssuranceLevel.DECLARED
    collectors_requested: list[str] = Field(default_factory=list)
    collectors_completed: list[str] = Field(default_factory=list)
    unobserved_surfaces: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)

    scanner_status: dict[str, str] = Field(default_factory=dict)


class AIBOMMetadata(InventoryModel):
    """Header metadata for an AgentBOM document."""

    spec_version: str = "1.0.0"
    serial_number: str | None = None
    version: int = 1
    timestamp: datetime | None = None
    tool_name: str = "nexus-symbiote"
    tool_version: str | None = None
    tool_vendor: str = "aisecnomad"
    authors: list[str] = Field(default_factory=list)
    completeness: CompletenessClaim | None = None


AnyComponent = Annotated[
    (
        AgentComponent
        | MCPServerComponent
        | ToolComponent
        | ModelComponent
        | PromptComponent
        | GuardrailComponent
        | MemoryStoreComponent
        | RAGSourceComponent
        | DataSourceComponent
        | RegistryEntryComponent
        | SkillPackageComponent
        | MCPClientComponent
        | A2AClientComponent
        | A2AServerComponent
        | IDEAgentComponent
        | VerifiedExtensionComponent
    ),
    Field(discriminator="component_type"),
]
