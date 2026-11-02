"""Closed enumerations of the AgentBOM profile (``spec/agentbom-profile.md``).

Adding a member is a MINOR profile change; removing or renaming one is MAJOR (``spec/versioning.md``).
"""

from __future__ import annotations

from enum import StrEnum


class AssuranceLevel(StrEnum):
    DECLARED = "declared"
    OBSERVED = "observed"
    VERIFIED = "verified"


class ValueState(StrEnum):
    PRESENT = "present"
    ABSENT_VERIFIED = "absent-verified"
    UNKNOWN = "unknown"


class UnknownReason(StrEnum):
    NOT_COLLECTED = "not-collected"
    PERMISSION_DENIED = "permission-denied"
    UNREACHABLE = "unreachable"
    UNSUPPORTED_SOURCE = "unsupported-source"
    TRUNCATED = "truncated"
    PROVIDER_UNDISCLOSED = "provider-undisclosed"
    TIMEOUT = "timeout"


class ClaimMethod(StrEnum):
    CONFIG = "config"
    MANIFEST = "manifest"
    LIVE_QUERY = "live-query"
    TRACE = "trace"
    HASH_COMPARISON = "hash-comparison"
    SIGNATURE_VERIFICATION = "signature-verification"
    HEURISTIC = "heuristic"
    HUMAN = "human"


class EvidenceVerification(StrEnum):
    NONE = "none"
    PRESENT = "present"
    SIGNATURE_VALID_UNCONSTRAINED = "signature-valid-unconstrained"
    VERIFIED_CONSTRAINED = "verified-constrained"


class SnapshotKind(StrEnum):
    DECLARED = "declared"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    OBSERVED = "observed"


class AgentRole(StrEnum):
    ROOT = "root"
    SUB_AGENT = "sub-agent"
    EXTERNAL_AGENT = "external-agent"


class IsoAutomationLevel(StrEnum):
    """ISO/IEC 22989 automation ladder; names match SPDX 3.1 ``isoAutomationLevel``."""

    NOT_AUTOMATED = "notAutomated"
    ASSISTIVE_AUTOMATION = "assistiveAutomation"
    PARTIAL_AUTOMATION = "partialAutomation"
    CONDITIONAL_AUTOMATION = "conditionalAutomation"
    HIGH_AUTOMATION = "highAutomation"
    FULL_AUTOMATION = "fullAutomation"
    AUTONOMOUS = "autonomous"


class AutonomyMode(StrEnum):
    AUTONOMOUS = "autonomous"
    APPROVAL_REQUIRED = "approval-required"
    FORBIDDEN = "forbidden"


class AutonomyOversight(StrEnum):
    """Whether a person approves an agent's side-effecting actions (ShadowScan ``oversight`` vocabulary)."""

    BYPASSED = "bypassed"
    GATED = "gated"
    UNKNOWN = "unknown"


class AutonomyInitiation(StrEnum):
    """What starts a run: a schedule, an event, a person, or unknown."""

    SCHEDULE = "schedule"
    EVENT = "event"
    HUMAN = "human"
    UNKNOWN = "unknown"


class CapabilityClass(StrEnum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK_EGRESS = "network-egress"
    FILESYSTEM = "filesystem"
    CREDENTIALS = "credentials"
    PAYMENT = "payment"
    COMMUNICATE = "communicate"
    DELEGATE = "delegate"
    MEMORY_WRITE = "memory-write"


class EnvironmentKind(StrEnum):
    K8S = "k8s"
    SERVERLESS = "serverless"
    VM = "vm"
    DESKTOP = "desktop"
    CI = "ci"
    BROWSER = "browser"
    OTHER = "other"


class ToolServerKind(StrEnum):
    MCP = "mcp"
    A2A = "a2a"
    OPENAPI = "openapi"
    BUILTIN = "builtin"


class Transport(StrEnum):
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"
    SSE = "sse"
    WEBSOCKET = "websocket"
    IN_PROCESS = "in-process"


class Launcher(StrEnum):
    NPX = "npx"
    UVX = "uvx"
    DOCKER = "docker"
    DNX = "dnx"
    BINARY = "binary"
    OTHER = "other"


class AuthMode(StrEnum):
    NONE = "none"
    OAUTH2 = "oauth2"
    API_KEY = "api-key"
    MTLS = "mtls"
    OBO_TOKEN = "obo-token"  # noqa: S105 - enum label, not a credential
    OTHER = "other"


class TrustZone(StrEnum):
    LOCAL_PROCESS = "local-process"
    LOOPBACK = "loopback"
    INTERNAL = "internal"
    PARTNER = "partner"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class ToolSource(StrEnum):
    DECLARED_CONFIG = "declared-config"
    REGISTRY = "registry"
    SERVED_LIVE = "served-live"
    TRACE = "trace"
    APPROVED_FILE = "approved-file"


class SideEffectClass(StrEnum):
    READ_ONLY = "read-only"
    STATE_MODIFYING = "state-modifying"
    DESTRUCTIVE = "destructive"
    FINANCIAL = "financial"
    COMMUNICATE = "communicate"
    UNKNOWN = "unknown"


class ApprovalGate(StrEnum):
    REQUIRED = "required"
    CONDITIONAL = "conditional"
    NONE = "none"
    UNKNOWN = "unknown"


class TextFlag(StrEnum):
    HIDDEN_UNICODE = "hidden-unicode"
    EXTERNAL_REF = "external-ref"
    CROSS_TOOL_DIRECTIVE = "cross-tool-directive"
    SECRET_SHAPED_TOKEN = "secret-shaped-token"  # noqa: S105 - enum label, not a credential


class ToolState(StrEnum):
    DECLARED = "declared"
    SERVED = "served"
    INVOKED = "invoked"


class DigestStatus(StrEnum):
    OK = "ok"
    UNDIGESTABLE = "undigestable"


class InstructionKind(StrEnum):
    SYSTEM_PROMPT = "system-prompt"
    DEVELOPER_PROMPT = "developer-prompt"
    AGENTS_MD = "agents-md"
    CLAUDE_MD = "claude-md"
    CURSOR_RULES = "cursor-rules"
    COPILOT_INSTRUCTIONS = "copilot-instructions"
    GEMINI_MD = "gemini-md"
    WINDSURF_RULES = "windsurf-rules"
    SKILL_MD = "skill-md"
    MCP_INSTRUCTIONS = "mcp-instructions"
    HOOK = "hook"
    RULES_FILE = "rules-file"
    POLICY_TEXT = "policy-text"
    OTHER = "other"


class LineEndings(StrEnum):
    LF = "lf"
    CRLF = "crlf"
    MIXED = "mixed"
    NONE = "none"


class TemplateEngine(StrEnum):
    NONE = "none"
    JINJA2 = "jinja2"
    F_STRING = "f-string"
    MUSTACHE = "mustache"
    HANDLEBARS = "handlebars"
    LIQUID = "liquid"
    OTHER = "other"


class PromptRole(StrEnum):
    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    TOOL = "tool"


class TemplateRiskClass(StrEnum):
    NONE = "none"
    TEMPLATE_EXECUTION = "template-execution"


class ModelKind(StrEnum):
    UNKNOWN = "unknown"
    WEIGHTS = "weights"
    HOSTED = "hosted"
    ADAPTER = "adapter"
    TOKENIZER = "tokenizer"
    CHAT_TEMPLATE = "chat-template"
    EMBEDDING = "embedding"


class AliasPinning(StrEnum):
    PINNED = "pinned"
    FLOATING = "floating"
    UNKNOWN = "unknown"


class SerializationFormat(StrEnum):
    SAFETENSORS = "safetensors"
    ONNX = "onnx"
    GGUF = "gguf"
    PICKLE = "pickle"
    TORCH_ZIP = "torch-zip"
    TF_SAVEDMODEL = "tf-savedmodel"
    KERAS_H5 = "keras-h5"
    JOBLIB = "joblib"
    NPZ = "npz"
    OTHER = "other"


class SerializationRisk(StrEnum):
    NONE = "none"
    LOW = "low"
    CODE_EXEC_ON_LOAD = "code-exec-on-load"
    TEMPLATE_EXECUTION = "template-execution"


class DerivationKind(StrEnum):
    FINE_TUNE_OF = "fineTuneOf"
    ADAPTER_OF = "adapterOf"
    QUANTIZATION_OF = "quantizationOf"
    MERGE_OF = "mergeOf"
    DISTILLATION_OF = "distillationOf"
    CONVERSION_OF = "conversionOf"


class SignatureStatus(StrEnum):
    UNSIGNED = "unsigned"
    CLAIMED = "claimed"
    VERIFIED = "verified"


class SignatureOutcome(StrEnum):
    VERIFIED = "verified"
    SIGNATURE_VALID_UNCONSTRAINED = "signature-valid-unconstrained"
    IDENTITY_MISMATCH = "identity-mismatch"
    DIGEST_MISMATCH = "digest-mismatch"
    SUBJECT_NAME_MISMATCH = "subject-name-mismatch"
    FAILED = "failed"
    ERROR = "error"
    NONE = "none"


class DataSourceKind(StrEnum):
    DATASET = "dataset"
    RAG_INDEX = "rag-index"
    MEMORY_STORE = "memory-store"
    RETRIEVAL_CONNECTOR = "retrieval-connector"
    KNOWLEDGE_PLUGIN = "knowledge-plugin"
    LIVE_FEED = "live-feed"
    TOOL_OUTPUT_CHANNEL = "tool-output-channel"


class Classification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class TrustTier(StrEnum):
    INTERNAL_VERIFIED = "0-internal-verified"
    INTERNAL = "1-internal"
    PARTNER = "2-partner"
    UNTRUSTED_PUBLIC = "3-untrusted-public"
    UNKNOWN = "unknown"


class SnapshotMethod(StrEnum):
    MERKLE = "merkle"
    HASH = "hash"
    ETAG = "etag"
    TIMESTAMP = "timestamp"
    NONE = "none"


class AclMode(StrEnum):
    DOCUMENT_LEVEL = "document-level"
    INDEX_LEVEL = "index-level"
    NONE = "none"
    UNKNOWN = "unknown"


class TenantIsolation(StrEnum):
    TENANT = "tenant"
    SHARED = "shared"
    UNKNOWN = "unknown"


class IdentityKind(StrEnum):
    SPIFFE = "spiffe"
    OAUTH_CLIENT = "oauth-client"
    SERVICE_ACCOUNT = "service-account"
    K8S_SA = "k8s-sa"
    IAM_ROLE = "iam-role"
    GITHUB_APP = "github-app"
    AZURE_MANAGED_IDENTITY = "azure-managed-identity"
    GCP_SA = "gcp-sa"
    API_KEY_REF = "api-key-ref"
    DID = "did"
    HUMAN = "human"
    UNAUTHENTICATED = "unauthenticated"
    OTHER = "other"


class CredentialKind(StrEnum):
    STATIC_LONG_LIVED = "static-long-lived"
    EPHEMERAL_TASK_SCOPED = "ephemeral-task-scoped"
    OBO_TOKEN = "obo-token"  # noqa: S105 - enum label, not a credential
    SERVICE_ACCOUNT = "service-account"
    UNAUTHENTICATED = "unauthenticated"
    UNKNOWN = "unknown"


class CredentialStorageKind(StrEnum):
    ENV = "env"
    FILE = "file"
    SECRET_MANAGER = "secret-manager"  # noqa: S105 - enum label, not a credential
    KEYCHAIN = "keychain"
    UNKNOWN = "unknown"


class PartyKind(StrEnum):
    ORGANIZATION = "organization"
    PERSON = "person"


class GrantLayer(StrEnum):
    DECLARED = "declared"
    EFFECTIVE = "effective"
    OBSERVED = "observed"


class DelegationProtocol(StrEnum):
    A2A = "a2a"
    MCP = "mcp"
    IN_PROCESS = "in-process"
    OBO = "obo"


class ConditionKind(StrEnum):
    TIME = "time"
    TENANT = "tenant"
    INPUT_TRUST = "input-trust"
    APPROVAL = "approval"
    OTHER = "other"


class EnforcementPointKind(StrEnum):
    GATEWAY = "gateway"
    AUTHZ_SERVICE = "authz-service"
    SANDBOX = "sandbox"
    NETWORK_POLICY = "network-policy"
    IDP = "idp"
    RUNTIME = "runtime"
    NONE = "none"
    UNKNOWN = "unknown"


class RequestedRefKind(StrEnum):
    MCP_REGISTRY = "mcp-registry"
    NPM = "npm"
    PYPI = "pypi"
    OCI = "oci"
    NUGET = "nuget"
    HUGGINGFACE = "huggingface"
    A2A_CARD = "a2a-card"
    URL = "url"
    HOSTED_ALIAS = "hosted-alias"


class RegistryStatus(StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    DELETED = "deleted"
    UNKNOWN = "unknown"


class PublisherVerification(StrEnum):
    GITHUB_OIDC = "github-oidc"
    GITHUB_OAUTH = "github-oauth"
    DNS = "dns"
    HTTP = "http"
    NONE = "none"
    UNKNOWN = "unknown"


class TrustState(StrEnum):
    ALLOWLISTED = "allowlisted"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"


class TrustSubjectKind(StrEnum):
    TOOL_DIGEST = "tool-digest"
    SERVER_IDENTITY = "server-identity"
    PUBLISHER_IDENTITY = "publisher-identity"
    MODEL_MANIFEST = "model-manifest"
    SKILL_DIGEST = "skill-digest"
    INSTRUCTION_DIGEST = "instruction-digest"
    REGISTRY_ENTRY = "registry-entry"


class PolicyKind(StrEnum):
    AUTHORIZATION_POLICY = "authorization-policy"
    GUARDRAIL = "guardrail"
    EGRESS_POLICY = "egress-policy"
    APPROVAL_POLICY = "approval-policy"
    GATEWAY_ALLOWLIST = "gateway-allowlist"


class EvidenceKind(StrEnum):
    ATTESTATION_DSSE = "attestation-dsse"
    SIGSTORE_BUNDLE = "sigstore-bundle"
    TOOLS_LIST_CAPTURE = "tools-list-capture"
    TRACE_SUMMARY = "trace-summary"
    SCAN_REPORT = "scan-report"
    CONFIG_FILE = "config-file"
    API_RESPONSE = "api-response"
    REGISTRY_RECORD = "registry-record"
    HUMAN_ATTESTATION = "human-attestation"
    OTHER = "other"


class ThreatFramework(StrEnum):
    OWASP_ASI_2025 = "owasp-asi-2025"
    OWASP_LLM_2025 = "owasp-llm-2025"
    MITRE_ATLAS = "mitre-atlas"
    CWE = "cwe"
    NIST_AI_RMF = "nist-ai-rmf"


class VexStatus(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not-affected"
    UNDER_INVESTIGATION = "under-investigation"
    FIXED = "fixed"


class VexJustification(StrEnum):
    TOOL_DISABLED = "tool-disabled"
    GUARDRAIL_ENFORCED = "guardrail-enforced"
    APPROVAL_REQUIRED = "approval-required"
    SCOPE_RESTRICTED = "scope-restricted"
    EGRESS_DENIED = "egress-denied"
    NOT_REACHABLE = "not-reachable"
    COMPONENT_NOT_PRESENT = "component-not-present"
    EVALUATED_RESISTANT = "evaluated-resistant"
    OTHER = "other"


class Surface(StrEnum):
    CODE = "code"
    REGISTRY = "registry"
    IDENTITY = "identity"
    MODEL_GATEWAY = "model-gateway"
    TOOLS = "tools"
    DATA = "data"
    RUNTIME = "runtime"
    NETWORK = "network"
    INSTRUCTIONS = "instructions"
    POLICY = "policy"


class CoverageStatus(StrEnum):
    QUERIED = "queried"
    PARTIAL = "partial"
    PERMISSION_DENIED = "permission-denied"
    UNREACHABLE = "unreachable"
    NOT_ATTEMPTED = "not-attempted"
    TRUNCATED = "truncated"


class Completeness(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNKNOWN = "unknown"


class CollectorStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class CollectorMode(StrEnum):
    DECLARED = "declared"
    OBSERVED = "observed"


class FlagName(StrEnum):
    LETHAL_TRIFECTA = "lethal-trifecta"
    RULE_OF_TWO_VIOLATION = "rule-of-two-violation"
    UNPINNED_TOOL = "unpinned-tool"
    FLOATING_MODEL_ALIAS = "floating-model-alias"
    DESTRUCTIVE_OPEN_WORLD_UNGATED = "destructive-open-world-ungated"
    UNSIGNED_MODEL = "unsigned-model"
    UNSAFE_SERIALIZATION = "unsafe-serialization"
    UNAUTHENTICATED_TOOL_SERVER = "unauthenticated-tool-server"
    STATIC_LONG_LIVED_CREDENTIAL = "static-long-lived-credential"
    UNDECLARED_COMPONENT_OBSERVED = "undeclared-component-observed"


class TriState(StrEnum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingState(StrEnum):
    FAIL = "fail"
    INDETERMINATE = "indeterminate"


class EdgeScope(StrEnum):
    DESIGN = "design"
    BUILD = "build"
    RUNTIME = "runtime"
    TEST = "test"


class EdgeType(StrEnum):
    USES_MODEL = "usesModel"
    INVOKES_TOOL = "invokesTool"
    PROVIDES_TOOL = "providesTool"
    DELEGATES_TO = "delegatesTo"
    SPAWNS = "spawns"
    LOADS_INSTRUCTION = "loadsInstruction"
    READS_CONTEXT_FROM = "readsContextFrom"
    READS_MEMORY_FROM = "readsMemoryFrom"
    WRITES_MEMORY_TO = "writesMemoryTo"
    ACTS_AS = "actsAs"
    HOLDS_CREDENTIAL = "holdsCredential"
    GRANTED_BY = "grantedBy"
    ENFORCED_AT = "enforcedAt"
    APPROVED_UNDER = "approvedUnder"
    RESOLVED_FROM = "resolvedFrom"
    DERIVED_FROM = "derivedFrom"
    EMBEDS = "embeds"
    EVALUATED_BY = "evaluatedBy"
    OBSERVED_BY = "observedBy"
    DEPENDS_ON = "dependsOn"
    SENDS_DATA_TO = "sendsDataTo"


class DeltaEventType(StrEnum):
    TOOL_REGISTERED = "tool-registered"
    TOOL_REMOVED = "tool-removed"
    TOOL_DEFINITION_CHANGED = "tool-definition-changed"
    TOOL_ANNOTATIONS_CHANGED = "tool-annotations-changed"
    SERVER_ADDED = "server-added"
    SERVER_REMOVED = "server-removed"
    SERVER_IDENTITY_CHANGED = "server-identity-changed"
    MODEL_ADDED = "model-added"
    MODEL_ROUTED = "model-routed"
    MODEL_ALIAS_RESOLVED = "model-alias-resolved"
    SUB_AGENT_SPAWNED = "sub-agent-spawned"
    MEMORY_WRITER_ADDED = "memory-writer-added"
    INSTRUCTION_CHANGED = "instruction-changed"
    SKILL_CHANGED = "skill-changed"
    GRANT_ADDED = "grant-added"
    GRANT_REMOVED = "grant-removed"
    GRANT_CHANGED = "grant-changed"
    IDENTITY_CHANGED = "identity-changed"
    REGISTRY_STATUS_CHANGED = "registry-status-changed"
    SIGNER_CHANGED = "signer-changed"
    DATA_SOURCE_ADDED = "data-source-added"
    DATA_SOURCE_CHANGED = "data-source-changed"
    DATA_SOURCE_REMOVED = "data-source-removed"
    TRUST_STATUS_CHANGED = "trust-status-changed"


class LossReason(StrEnum):
    NO_NATIVE_CONSTRUCT = "no-native-construct"
    ENUM_NARROWED = "enum-narrowed"
    PRECISION_LOST = "precision-lost"
    CARDINALITY_COLLAPSED = "cardinality-collapsed"
    UNSUPPORTED_IN_TARGET_VERSION = "unsupported-in-target-version"
    STRING_FLATTENED = "string-flattened"
    REDACTED = "redacted"
    LIBRARY_LIMITATION = "library-limitation"
    FOREIGN_UNMAPPED = "foreign-unmapped"


class LossPreservedIn(StrEnum):
    COMPANION = "companion"
    PROPERTY = "property"
    EXTENSION = "extension"
    EMBEDDED_RECORD = "embedded-record"
    DROPPED = "dropped"


class LossSeverity(StrEnum):
    NONE = "none"
    INFO = "info"
    SECURITY_RELEVANT = "security-relevant"


class RedactionClass(StrEnum):
    CREDENTIAL_SHAPED_TOKEN = "credential-shaped-token"  # noqa: S105 - enum label, not a credential
    ENDPOINT_INTERNAL_HOST = "endpoint-internal-host"
    TOOL_TEXT = "tool-text"
    PROMPT_TEXT = "prompt-text"
    INSTRUCTION_BODY = "instruction-body"
    IDENTITY_REF = "identity-ref"
    GRANT_DETAIL = "grant-detail"
    DATA_SOURCE_DETAIL = "data-source-detail"
