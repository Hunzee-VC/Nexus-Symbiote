# AgentBOM profile — semantic model (v0.1)

The AgentBOM profile answers, for a deployed agent: *which agent is running, what can it access or change,
where did its dependencies come from, who authorized it, and has any of that changed since approval?*
It is organised in four planes: **Composition** (what was built or declared), **Authorization** (what the
agent is permitted to do), **Observability** (what is deployed and what it actually did) and **Assurance**
(why each claim should be trusted). CycloneDX 1.7 and SPDX 3.0.1 documents are *projections* of this model
(see the mapping specs); the model itself is serialised as the companion document (`companion.md`).

Implementation: `symbiote.model` (Pydantic v2, `extra="forbid"`, frozen value objects). Field names below are
the model's Python/JSON names (snake_case in Python, camelCase in the companion JSON via alias generator).

## 1. Conventions

### 1.1 Identifiers
Every entity has a stable, deterministic `id` string (safe as a CycloneDX `bom-ref` and as an SPDX IRI
suffix). Formats (slugs are lowercase `[a-z0-9._-]+`, derived from the entity's locator):

| Entity | id format | Entity | id format |
|---|---|---|---|
| Agent | `agent:<slug>` | Identity | `ident:<slug>` |
| Deployment | `deploy:<slug>` | CredentialBinding | `cred:<slug>` |
| ToolServer | `server:<slug>` | Grant | `grant:<slug>` |
| ToolDefinition | `tool:<server-slug>/<tool-name>` | Approval | `appr:<slug>` |
| Instruction | `instr:<slug>` | RegistryResolution | `res:<slug>` |
| PromptTemplate | `prompt:<slug>` | Evidence | `ev:<first 12 hex of digest>` |
| Skill | `skill:<slug>` | Evaluation | `eval:<slug>` |
| Model | `model:<slug>` | VexStatement | `vex:<slug>` |
| DataSource | `data:<slug>` | TrustStatus | `trust:<slug>` |
| Party | `party:<slug>` | SoftwareComponent | `sw:<purl-or-slug>` |
| Policy | `policy:<slug>` | Collector | `collector:<name>` |

`<tool-name>` is the MCP tool name verbatim (it is already restricted by the MCP spec). Where a slug would
collide, a `-<digest6>` suffix is appended.

### 1.2 Digests, times, validity
`Digest` is rendered `sha256:<64 lowercase hex>` in the companion and in properties; as
`{"alg":"SHA-256","content":"<hex>"}` in CycloneDX `hashes[]`; as `Hash{algorithm: sha256, hashValue}` in
SPDX; as `{"sha256": "<hex>"}` in in-toto `DigestSet`s. SHA-256 is mandatory; BLAKE3 MAY be added for large
shards. Times are RFC 3339 UTC (`Z`). `Validity = {not_before?, not_after?}` is half-open.

### 1.3 Claims, assurance and state (ADR-0005)
A **Claim** wraps any fact that can be wrong:

```
Claim[T] = {
  value: T | null,
  state: "present" | "absent-verified" | "unknown",
  assurance: "declared" | "observed" | "verified",
  method?: "config" | "manifest" | "live-query" | "trace" | "hash-comparison" | "signature-verification" | "heuristic" | "human",
  evidence: [EvidenceRef],              # by digest, never inline
  locator?: string,                    # exact source path, e.g. ".mcp.json#/mcpServers/github/args/2"
  collector?: string,                  # "collector:<name>@<version>"
  observed_at?: datetime,
  confidence?: number (0..1),          # heuristics only; never upgrades assurance
  unknown_reason?: "not-collected" | "permission-denied" | "unreachable" | "unsupported-source" | "truncated" | "provider-undisclosed" | "timeout"
}
```
Rules: `state=unknown` ⇒ `value=null` and `unknown_reason` set. `state=absent-verified` means a collector
examined the surface and found nothing. `assurance=verified` requires at least one `EvidenceRef` with
`verification=verified-constrained`. Every entity carries a `provenance: Claim[null]`-shaped
`Provenance` block (assurance, method, evidence, locator, collector, observed_at) for its existence; fields
that are individually contestable are typed `Claim[...]` below.

`EvidenceRef = {digest, media_type, uri?, predicate_type?, verification: "none" | "present" | "signature-valid-unconstrained" | "verified-constrained", signer_identity?, signer_issuer?, log_entry?}`.

### 1.4 Snapshot kinds
`SnapshotKind = declared | approved | deployed | observed`. One document = one kind (ADR-0005).

## 2. Document: `AgentBOM`

| Field | Type | Req | Notes |
|---|---|---|---|
| `spec_version` | const `"0.1"` | ✓ | AgentBOM profile version |
| `snapshot` | `Snapshot` | ✓ | Header: kind, serial, digest, chain, validity |
| `subject` | ref→Agent | ✓ | Root agent |
| `producer` | `Producer{name, version, digest?, collectors: [Collector]}` | ✓ | |
| `agents`, `deployments`, `tool_servers`, `tools`, `instructions`, `prompts`, `skills`, `models`, `data_sources`, `identities`, `credential_bindings`, `grants`, `approvals`, `resolutions`, `evidence`, `evaluations`, `vex`, `trust_status`, `parties`, `policies`, `software` | lists | ✓ (may be empty) | Entity collections, each sorted by `id` |
| `edges` | `[Edge]` | ✓ | §4 |
| `coverage` | `Coverage` | ✓ | §3.14; may be all-unknown, never absent |
| `derived` | `{flags: [Flag], findings: [Finding]}` | ✓ | Computed by policy; inputs cited (§3.16) |
| `merkle` | `{algorithm: "rfc6962-sha256", root, leaf_count, leaves?: [{kind, id, leaf_hash}]}` | Standard+ | `digests.md §5` |
| `redactions` | `[Redaction{class, count, applied_by, applied_at, ids?}]` | ✓ (may be empty) | Never silent |
| `redacted` | `[RedactedEntity{id, kind, class, leaf_hash}]` | ✓ (may be empty) | Placeholders for redacted entities; edges may still reference them |
| `links` | `{cyclonedx?: {serial_number, version, bom_link, digest}, spdx?: {document_iri, digest}}` | | Bidirectional linkage |
| `loss_report` | `LossReport` | | Attached after a conversion (`companion.md §4`) |
| `foreign_properties` | `[{dialect, element_id, name, value}]` | | Verbatim passthrough of imported, unmapped properties |

### 2.1 `Snapshot`
`{id: "snap:<serial>:<digest12>", kind, digest (= merkle.root), serial: int ≥ 1, prev: Digest|null, agent_ref, deployment_ref?, validity: Validity, produced_at, producer_ref, observation_window?: {start, end}, approvals: [ref→Approval] (kind=approved), policy_bundle?: Claim[Digest]}`.
`serial` is monotone per `(agent_ref, kind)`; `prev` forms a hash chain. The document's `snapshot.digest`
equals the Merkle root over all entity leaves (`digests.md §5`), so the snapshot digest commits to the whole
document and is the attestation subject.

### 2.2 `Delta`
A standalone, signable change record between two snapshots:
`{id, from_snapshot: Digest, to_snapshot: Digest, produced_at, producer, events: [DeltaEvent]}` with
`DeltaEvent = {type, subject: id, before: Digest|null, after: Digest|null, evidence: [EvidenceRef], assurance, severity_hint}` and
`type ∈ {tool-registered, tool-removed, tool-definition-changed, tool-annotations-changed, server-added, server-removed, server-identity-changed, model-added, model-routed, model-alias-resolved, sub-agent-spawned, memory-writer-added, instruction-changed, skill-changed, grant-added, grant-removed, grant-changed, identity-changed, registry-status-changed, signer-changed, data-source-added, data-source-changed, data-source-removed, trust-status-changed}`.

## 3. Entities

Common fields on every entity: `id`, `name?`, `description?`, `provenance: Provenance`, `trust?: ref→TrustStatus`, `tags: [str]`, `external_refs: [{type, url, digests?, comment?}]`, `foreign: {str: str}` (importer passthrough).

### 3.1 `Agent`
| Field | Type | Req | Notes |
|---|---|---|---|
| `version` | str | ✓ | Release of the agent definition |
| `digest` | Digest | derived | `digests.md §3.9` over the canonical definition |
| `role` | `root` \| `sub-agent` \| `external-agent` | ✓ | |
| `purpose` | str | | Intended purpose (EU AI Act Art. 13 system-level) |
| `framework` | `Claim[{name, version?}]` | | `langgraph`, `crewai`, `openai-agents`, `claude-agent-sdk`, `autogen`, `semantic-kernel`, `custom`, … |
| `owner`, `operator` | ref→Party | owner ✓ (Standard+) | |
| `automation_level` | `Claim[IsoAutomationLevel]` | | ISO/IEC 22989 ladder, same names as SPDX 3.1 `isoAutomationLevel`: `notAutomated, assistiveAutomation, partialAutomation, conditionalAutomation, highAutomation, fullAutomation, autonomous` |
| `autonomy_profile` | `[{capability: CapabilityClass, mode: autonomous \| approval-required \| forbidden}]` | | **Action-specific autonomy**; the agent-wide level is only a summary |
| `autonomy_assessment` | `{scale, floor, ceiling, floor_level, ceiling_level, oversight: bypassed \| gated \| unknown, initiation: schedule \| event \| human \| unknown, basis: [{bound, rule, value}], declared?, declared_source?, assessor?, assurance, evidence}` | | An evidence **interval** on a named scale (ShadowScan `shadowscan.autonomy/v1`, `shadowscan-mapping.md §3`): the floor is what the evidence proves, the ceiling what positive evidence has not ruled out; `automation_level` summarises the floor |
| `identities` | `[ref→Identity]` | | Workload principals it may act as |
| `instructions` | `[{ref, precedence}]` | ✓ | Ordered loading stack |
| `entrypoint` | str | | Module/command that starts it |
| `parent` | ref→Agent | | For sub-agents |
| `a2a_card` | `{url?, digest, version?, protocol_versions: [str], skills: [{id, name, tags}], security_schemes: [str], signature_status: none \| present \| verified}` | | A2A Agent Card facts |
| `policy_bundle` | `Claim[Digest]` | | Digest of the policy bundle the runtime enforces |

### 3.2 `Deployment`
`{agent_ref, snapshot_refs: [{digest, validity}], environment: {kind: k8s \| serverless \| vm \| desktop \| ci \| browser \| other, cluster?, namespace?, host?, region?}, tenant?, workload_identity: ref→Identity, workload_ref?: {group, kind, namespace, name, uid} (k8s), started_at, ended_at?, observed_by: [collector]}`.

### 3.3 `ToolServer` (MCP server, A2A peer, OpenAPI provider or built-in tool set)
| Field | Type | Req | Notes |
|---|---|---|---|
| `kind` | `mcp` \| `a2a` \| `openapi` \| `builtin` | ✓ | |
| `digest` | `Digest` (`server/v1`) | derived | Server identity: `digests.md §3.4` |
| `client` | str | | `claude-code`, `claude-desktop`, `cursor`, `vscode`, `windsurf`, `codex`, `gemini-cli`, `generic` |
| `transport` | `Claim[stdio \| streamable-http \| sse \| websocket \| in-process]` | ✓ | |
| `endpoint` | `Claim[URL]` | remote | Origin (scheme+host+port) **and path** are identity-bearing |
| `package` | `Claim[{purl, digest?, floating: bool, launcher: npx \| uvx \| docker \| dnx \| binary \| other}]` | stdio | `floating=true` when no immutable version/digest |
| `command` | str | | argv[0] only; argument *shape* recorded as `args_digest` |
| `env_var_names`, `header_names` | `[str]` | ✓ | Names only; values never recorded |
| `server_info` | `Claim[{name, version, title?}]` | | From MCP `initialize` |
| `protocol_version` | `Claim[str]` | | |
| `instructions_digest` | `Claim[Digest]` | | MCP `InitializeResult.instructions` is model-visible text → also an `Instruction` of kind `mcp-instructions` |
| `authentication` | `Claim[{mode: none \| oauth2 \| api-key \| mtls \| obo-token \| other, issuer?, scopes_requested: [str]}]` | ✓ | |
| `trust_zone` | str | ✓ | `local-process`, `loopback`, `internal`, `partner`, `external`, `unknown` |
| `crosses_trust_boundary` | `Claim[bool]` | ✓ | |
| `tool_list_meta` | `{ttl_ms?, cache_scope?}` | | From `ListToolsResult` where present |
| `toolset_digest` | `Claim[Digest]` (`toolset/v1`) | Standard+ | The allowlist unit |
| `registry_resolution` | ref→RegistryResolution | | |
| `client_trust_flags` | `{str: str}` | | e.g. Gemini `trust`, `includeTools`/`excludeTools`, Codex `approval_policy` |

### 3.4 `ToolDefinition` (the model-visible contract; primary enforcement object)
| Field | Type | Req | Notes |
|---|---|---|---|
| `server_ref` | ref→ToolServer | ✓ | |
| `name`, `title?`, `description?` | str | name ✓ | As served/declared, verbatim |
| `input_schema`, `output_schema?` | JSON | input ✓ | As served; `$ref`s never expanded |
| `annotations` | `Claim[{read_only_hint?, destructive_hint?, idempotent_hint?, open_world_hint?, title?}]` | | Server-declared hints (`assurance=declared`); absent hints recorded as absent (policy applies MCP defaults: destructive=true, open-world=true) |
| `digest` | `{algorithm: "tooldef/v1", value?: Digest, status: ok \| undigestable, reason?}` | ✓ | `digests.md §3.1` |
| `full_digest` | same, `tooldef-full/v1` | | Includes `_meta`, `icons`, `execution` |
| `description_digest`, `input_schema_digest` | Digest | | Finer drift attribution |
| `source` | `declared-config` \| `registry` \| `served-live` \| `trace` \| `approved-file` | ✓ | |
| `side_effects` | `Claim[{read, write, destructive, open_world, financial, egress_destinations: [str]}]` | | Independent assessment (observed/verified), kept separate from `annotations` |
| `side_effect_class` | `read-only` \| `state-modifying` \| `destructive` \| `financial` \| `communicate` \| `unknown` | ✓ | Derived (`checks.md §1`) |
| `capabilities` | `[CapabilityClass]` | ✓ | Derived/declared |
| `required_scopes` | `Claim[[str]]` | | From docs/config/OAuth protected-resource metadata |
| `approval_gate` | `required` \| `conditional` \| `none` \| `unknown` | ✓ | From client permissions/grants |
| `text_flags` | `[hidden-unicode \| external-ref \| cross-tool-directive \| secret-shaped-token]` | | Lint facts over model-visible text |
| `state` | `declared` \| `served` \| `invoked` | ✓ | |

### 3.5 `Instruction`
`{kind: system-prompt \| developer-prompt \| agents-md \| claude-md \| cursor-rules \| copilot-instructions \| gemini-md \| windsurf-rules \| skill-md \| mcp-instructions \| hook \| rules-file \| policy-text \| other, path | uri, media_type, size, digest (sha256 of exact bytes), normalized_digest? (triage only), line_endings: lf \| crlf \| mixed, precedence: int, editors: Claim[[ref→Identity|Party]], loads_remote: Claim[[URL]], contains_secret_like: bool, frontmatter?: {name, description, allowed_tools: [str], …}, source?: {vcs_url, revision, blob_id}}`.
Content is never embedded unless explicitly requested and under 4 KiB, and never when `contains_secret_like`.

### 3.6 `PromptTemplate`
`{engine: none \| jinja2 \| f-string \| mustache \| handlebars \| liquid \| other, role: system \| developer \| user \| tool, digest (prompt/v1), template_digest (sha256 bytes), variables_schema?: JSON, variables_schema_digest?, path?, risk_class: none \| template-execution}`.

### 3.7 `Skill`
`{path, digest (dirmanifest/v1 root), manifest: DirManifest, skill_md_ref: ref→Instruction, frontmatter: {name, description, license?, compatibility?, allowed_tools: [str], metadata: {}}, scripts: [{path, digest, interpreter?}], referenced_servers: [str], has_scripts: bool, name_matches_directory: bool}`.

### 3.8 `Model`
| Field | Type | Req | Notes |
|---|---|---|---|
| `kind` | `weights` \| `hosted` \| `adapter` \| `tokenizer` \| `chat-template` \| `embedding` \| `unknown` | ✓ | |
| `identity` | `Claim[ModelIdentity]` | ✓ | weights: `{purl?, manifest_root: Digest, manifest_ref?, file_count, formats: [str]}`; hosted: `{provider, endpoint_origin?, requested_ref, resolved_ref: Claim[str], alias_pinning: pinned \| floating \| unknown, provider_evidence: [EvidenceRef], fingerprint?: {method, digest, sampled_at, expires}}` |
| `manifest` | `ModelManifest` | weights | `digests.md §3.6`; OMS-compatible |
| `serialization` | `Claim[{formats: [safetensors \| onnx \| gguf \| pickle \| torch-zip \| tf-savedmodel \| keras-h5 \| joblib \| npz \| other], risk_class: none \| low \| code-exec-on-load \| template-execution, trust_remote_code: bool \| unknown, chat_template_executable: bool \| unknown, scanner?: {name, version, report_digest}}]` | weights | |
| `derivations` | `[{kind: fineTuneOf \| adapterOf \| quantizationOf \| mergeOf \| distillationOf \| conversionOf, parent: ref \| purl \| str, parameters: {}, parameters_digest, assurance}]` | | Typed lineage with parameters |
| `signature` | `{status: unsigned \| claimed \| verified, outcome: verified \| signature-valid-unconstrained \| identity-mismatch \| digest-mismatch \| subject-name-mismatch \| failed \| error \| none, reason?, identity?, issuer?, log_entry?, subject_name_mismatch?: bool, bundle_digest?}` | | k8s-aibom field set; `signature-valid-unconstrained` ≠ verified |
| `tokenizer_ref`, `chat_template_ref`, `generation_config_digest` | refs / Digest | | Separately compromisable artefacts |
| `card` | `{task?, architecture?, approach?, datasets: [ref], metrics: [{name, value, dataset_digest?}], limitations?, users?, use_cases?}` | | Free-text model-card fields pass through to native constructs |
| `endpoint_ref` | ref→ToolServer(kind=openapi)/Service | hosted | Provider API endpoint |

### 3.9 `DataSource`
`{kind: dataset \| rag-index \| memory-store \| retrieval-connector \| knowledge-plugin \| live-feed \| tool-output-channel, location?, classification: public \| internal \| confidential \| restricted \| unknown, data_classes: [str] (PII, source-code, credentials, …), trust_tier: 0-internal-verified \| 1-internal \| 2-partner \| 3-untrusted-public \| unknown, instruction_bearing: Claim[bool], sanitization: [{name, digest}], snapshot?: Claim[{commitment: Digest, method: merkle \| hash \| etag \| timestamp \| none, at}], live: bool, refresh_policy?, embedding_model_ref?, chunking?: {strategy, size, overlap, digest}, sources: [{uri, digest?, fetched_at?, license?, consent_status?}], acl_mode: document-level \| index-level \| none \| unknown, writers: Claim[[ref→Identity|Agent]], tenant_isolation: tenant \| shared \| unknown, retention?, quarantine?: {status, since}, invalidation_dependents: [ref], poison_scan?: EvidenceRef}`.

### 3.10 `Identity`, `CredentialBinding`, `Party`
`Identity = {kind: spiffe \| oauth-client \| service-account \| k8s-sa \| iam-role \| github-app \| azure-managed-identity \| gcp-sa \| api-key-ref \| did \| human \| unauthenticated \| other, ref (SPIFFE ID / client id / ARN / email — **never secret values**; a validator rejects token shapes), issuer?, tenant?}`.
`CredentialBinding = {subject_ref, identity_ref, kind: static-long-lived \| ephemeral-task-scoped \| obo-token \| service-account \| unauthenticated \| unknown, lifetime?: duration, scopes_granted: Claim[[str]], storage: {kind: env \| file \| secret-manager \| keychain \| unknown, locator}}`.
`Party = {kind: organization \| person, name, urls: [str], contacts: [{name?, email?}]}`.

### 3.11 `Grant` (authorization record)
| Field | Type | Req | Notes |
|---|---|---|---|
| `layer` | `declared` \| `effective` \| `observed` | ✓ | Three records may coexist for one subject |
| `subject_ref` | ref→Agent/ToolDefinition/ToolServer/Identity | ✓ | |
| `capability` | `CapabilityClass` = `read` \| `write` \| `execute` \| `network-egress` \| `filesystem` \| `credentials` \| `payment` \| `communicate` \| `delegate` \| `memory-write` | ✓ | |
| `scope` | `{resources: [pattern], egress: [host-pattern], data_classes: [str], spend_ceiling?: {amount, currency, period}, rate_limit?}` | ✓ | Patterns tagged `glob:`, `cidr:`, `re:` |
| `granter` | ref→Party/Identity | ✓ | |
| `delegation_chain` | `[{from, to, protocol: a2a \| mcp \| in-process \| obo, audience?, scopes: [str], constraints?, expires?, evidence}]` | | |
| `conditions` | `[{kind: time \| tenant \| input-trust \| approval \| other, expr}]` | | |
| `approval_gate` | `none` \| `conditional` \| `required` | ✓ | plus `gate_ref?` |
| `validity` | `Validity` | | |
| `policy_ref` | `{policy_id?, bundle_digest}` | | |
| `enforcement_point` | `{kind: gateway \| authz-service \| sandbox \| network-policy \| idp \| runtime \| none \| unknown, locator?, attested: bool}` | ✓ | `none` is a finding |
| `credential_binding_ref` | ref | | |

### 3.12 `Approval`, `RegistryResolution`, `TrustStatus`, `Policy`
`Approval = {approver: ref, approved_snapshot_digest, covers: {tool_digests: [Digest], model_ids: [ref], grant_ids: [ref], deployment_selector?}, policy_ref?, issued_at, expires?, revocation_ref?, attestation_ref?: EvidenceRef}`.
`RegistryResolution` — `digests.md §4` (requested → resolved → signer → log inclusion; `state` may be `unknown`).
`TrustStatus = {subject_kind: tool-digest \| server-identity \| publisher-identity \| model-manifest \| skill-digest \| instruction-digest \| registry-entry, subject_key, status: allowlisted \| quarantined \| revoked, reason, decided_by: ref→Party, decided_at, expires, serial, supersedes?}` — keyed on identity digests, never display names.
`Policy = {kind: authorization-policy \| guardrail \| egress-policy \| approval-policy \| gateway-allowlist, engine?, bundle_digest (dirmanifest/v1 or sha256), enforcement_point}`.

### 3.13 `Evidence`, `Evaluation`, `VexStatement`
`Evidence = {id (= "ev:" + digest12), kind: attestation-dsse \| sigstore-bundle \| tools-list-capture \| trace-summary \| scan-report \| config-file \| api-response \| registry-record \| human-attestation \| other, media_type, digest, uri?, created, expires?, author: ref, redaction_class?}`.
`Evaluation = {subject_config: {model_digests: [Digest], prompt_digests: [Digest], toolset_digests: [Digest], data_source_digests: [Digest], policy_digest?}, threat_model: [ThreatRef], harness: {name, version, digest?}, dataset: {name, digest, size?}, attack_conditions: {attacker_knowledge?, channels: [str], budget?}, results: [{metric, numerator: int, denominator: int, value?, threshold?, pass?}], assessor: ref→Party, third_party: bool, performed_at, validity: {expires?, invalidated_by: [str]}, evidence: [EvidenceRef]}` — a result applies only while every element of `subject_config` is unchanged; `symbiote diff` marks drifted evaluations `stale`.
`ThreatRef = {framework: owasp-asi-2025 \| owasp-llm-2025 \| mitre-atlas \| cwe \| nist-ai-rmf, id, uri?}`.
`VexStatement = {weakness: ThreatRef, subject: {ref, config_digest}, status: affected \| not-affected \| under-investigation \| fixed, justification: tool-disabled \| guardrail-enforced \| approval-required \| scope-restricted \| egress-denied \| not-reachable \| component-not-present \| evaluated-resistant \| other, detail?, evidence: [EvidenceRef], issued_at, last_updated?, expires?, author: ref}`.

### 3.14 `Coverage`
`{surfaces: {code, registry, identity, model-gateway, tools, data, runtime, network, instructions, policy: SurfaceCoverage}, exclusions: [{pattern, reason}], window?: {start, end}, collectors: [{name, version, status: ok \| partial \| failed \| skipped, reason?}], text_included: bool}` with
`SurfaceCoverage = {status: queried \| partial \| permission-denied \| unreachable \| not-attempted \| truncated, sources: [{source, locator, ok, error_class?, items: int}], items_seen: int, truncated_at?: int}`.
Aggregate completeness per surface and for the document: `complete` (all `queried`), `incomplete`, `unknown`.
**A failed registry query yields `registry: unreachable` and a resolution with `state=unknown`, never "not registered".**

### 3.15 `Collector`, `SoftwareComponent`
`Collector = {name, version, digest?, mode: declared \| observed, surfaces: [Surface]}`.
`SoftwareComponent` is a verbatim CycloneDX component (purl, hashes, licenses, evidence, properties) from a merged software SBOM, kept under the agent via `dependsOn`.

### 3.16 Derived: `Flag`, `Finding`
`Flag = {flag: FlagName, subject_ref, value: true \| false \| unknown, inputs: [ref], assurance}`; `FlagName ∈ {lethal-trifecta, rule-of-two-violation, unpinned-tool, floating-model-alias, destructive-open-world-ungated, unsigned-model, unsafe-serialization, unauthenticated-tool-server, static-long-lived-credential, undeclared-component-observed}`.
`Finding = {check_id, severity: critical \| high \| medium \| low \| info, state: fail \| indeterminate, subject_refs: [ref], inputs: [ref], message, mappings: [ThreatRef], evidence: [EvidenceRef]}` (`checks.md`).

## 4. Edges
`Edge = {type, from, to, scope: design \| build \| runtime \| test, qualifiers: {}, assurance, validity?, evidence: [EvidenceRef], observed_count?, first_seen?, last_seen?, declared_by?}`.

| type | from → to | qualifiers | why enforcement needs it |
|---|---|---|---|
| `usesModel` | Agent → Model | `role: primary \| router \| embedding \| judge \| fallback`, `routing_rule?` | model routing changes are deltas |
| `invokesTool` | Agent → ToolDefinition | `declared \| observed`, `args_schema_digest?` | declared callable set vs tools actually called |
| `providesTool` | ToolServer → ToolDefinition | `served_at?` | the set a gateway allowlists |
| `delegatesTo` | Agent → Agent \| ToolServer(a2a) | `constraints`, `audience`, `scopes`, `expires`, `grant_ref` | A2A chain; compromise propagation |
| `spawns` | Agent → Agent | `dynamic: bool`, `count?` | runtime sub-agent discovery |
| `loadsInstruction` | Agent → Instruction/PromptTemplate/Skill | `precedence` | ordered instruction stack |
| `readsContextFrom` | Agent → DataSource | `trust_tier`, `instruction_bearing` | untrusted-input leg of the trifecta |
| `readsMemoryFrom` / `writesMemoryTo` | Agent/ToolDefinition → DataSource(memory) | `writer_identity?` | memory poisoning blast radius |
| `actsAs` | Agent/Deployment → Identity | `issuer?` | identity binding |
| `holdsCredential` | Agent/ToolDefinition/ToolServer → CredentialBinding | `kind` | "which agents hold credentials this server can use?" |
| `grantedBy` | Grant → Party/Identity | | authority source |
| `enforcedAt` | Grant → Policy/EnforcementPoint | `attested` | where deny actually happens |
| `approvedUnder` | Snapshot → Approval | | approval covers a digest, not a name |
| `resolvedFrom` | ToolServer/Model/Skill → RegistryResolution | | name-resolution record |
| `derivedFrom` | Model → Model; DataSource(index) → DataSource(corpus) | `kind`, `parameters_digest` | lineage with parameters |
| `embeds` | DataSource(index) → Model(embedding) | | embedding coupling |
| `evaluatedBy` | Agent/Model/ToolDefinition → Evaluation | `config_digest` | evidence bound to the exact configuration |
| `observedBy` | any → Collector | `at` | provenance of observed facts |
| `dependsOn` | Agent → SoftwareComponent; generic | `purl?` | software layer |
| `sendsDataTo` | Agent/ToolDefinition → ToolServer/external | `data_classes`, `destination` | egress edge |

## 5. Assurance level definitions (per claim)
- **declared** — asserted by the owner/supplier or read from configuration the owner controls.
- **observed** — corroborated by a collector against the deployed system within a stated window and scope
  (live `tools/list`, OTel spans, Kubernetes API, registry API, provider API).
- **verified** — evidence authenticated (signature over the exact digest) and evaluated against an explicit
  trust policy with a constrained signer and documented coverage.

Unsigned k8s-aibom imports retain the producer's confidence and locators as source evidence.
Both inferred and verified producer labels remain declared. An unresolved claim stays unknown.
A component SHA-256 may populate `artifactDigest`; a weights-directory manifest requires independent
manifest evidence. Without an explicit hosting declaration, the model kind stays unknown. Matching
primary-model argv and environment declarations within one Kubernetes workload and container can share
a declaration while preserving both original component references.

## 6. Invariants (tested; cited by id in code)
- **I1** every contestable fact is a `Claim` with assurance and state.
- **I2** unknown ≠ absence: a failed/unauthorized query is `unknown` + coverage status, never an empty list.
- **I3** no laundering of signatures: `verified` requires chain → trust root, log inclusion, satisfied identity
  constraint, and no contradicted digest binding; anything else is a recorded fact at assurance ≤ `observed`.
- **I4** snapshot kinds never merge silently.
- **I5** fail-closed digests (ADR-0004).
- **I6** redaction is recorded at document level and on the affected entity.
- **I7** determinism: identical inputs produce byte-identical companion/CDX/SPDX output under
  `--deterministic`.
- **I8** name is locator, digest is identity: equality, diff and allowlists operate on digests; a name match
  never upgrades assurance.
