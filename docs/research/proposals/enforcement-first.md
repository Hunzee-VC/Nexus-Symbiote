# Symbiote — Architecture Proposal: Enforcement-First AgentBOM

**Proposal variant:** security-enforcement-first (design backwards from the gateway, the policy engine and the incident responder).
**Date:** 2026-11-01. **Target repo:** `/home/user/symbiote` (not modified by this proposal). **Status:** independent proposal for Phase 2 selection; decisions marked **D-**, assumptions marked **A-**, verified facts marked **V-** (Appendix A lists how each was verified).
**Inputs consulted:** DESIGN-BRIEF.md (R1–R12, ADR-001), the source gap analysis (SymBiote.md), k8s-aibom Design 002 / security-model / schema-divergences, in-toto Statement v1 and DSSE envelope specs, bom-1.7 JSON schema + XSD, SPDX 3.0.1 model JSON-LD and the official 3.0.1 JSON schema (fetched from spdx-spec gh-pages), MCP schema 2025-06-18 and `mcp` 2.3.0 types, MCP registry server.json 2025-12-11 samples, MITRE ATLAS v5.6 data, and API probes of `sigstore` 4.5.1, `in-toto-attestation` 0.9.3, `model-signing` 1.1.1, `rfc8785` 0.1.4, `cyclonedx-python-lib` 11.12.0 and `spdx-python-model` 0.0.6 in the probe venv. Phase 1's `gaps-attack.json` (22 `ATTACK-*` gaps with verification notes) appeared while this was being drafted and is reconciled in §16; `verified-*.json` and `landscape-*.json` were not yet present. Every fact below was re-verified directly or is flagged as an assumption.

---

## 0. The distinctive choices in one page

1. **Three consumer contracts drive the schema.** Every entity and field earns its place by appearing in at least one of: the **Gateway Allowlist Bundle (GAB)** that a tool gateway or agent runtime enforces; the **Policy Input Document (PID)** that OPA/Rego or the built-in checker evaluates; or the **Incident Index** that answers the three incident questions. Fields that serve none of them are documentation and live in free-text slots, never in the enforced core.
2. **Facts in the BOM, judgments in policy output.** The BOM never says "safe"; it says *what was declared, what was approved, what was deployed, what was observed, with what evidence, at what assurance*. The computed flags (Rule-of-Two, least-privilege gap, unpinned, unsafe serialization, destructive+open-world without gate) are emitted as **derived findings with inputs cited**, so a consumer can recompute them.
3. **Signer identity constraints are load-bearing; nothing else is.** We adopt k8s-aibom Design 002 verbatim as invariant **I3**: `verified` requires chain → trust root, transparency-log inclusion, an operator-configured identity constraint (or non-public trust root), and no contradicted binding. "Valid signature, unconstrained signer" is recorded as the fact `signature-valid-unconstrained` and stays at assurance `observed`. Subject *names* in signatures are never load-bearing; digests are.
4. **Content addressing with fail-closed canonicalization.** Tool definitions, prompts, policy bundles and manifests are identified by SHA-256 over RFC 8785 (JCS) of a **typed digest envelope** (`{"_type": <digest-type URI>, ...}`), which prevents cross-type collisions. A definition that cannot be canonicalized (NaN, integers outside ±2^53, non-UTF-8) is **not** given a best-effort digest — it is marked undigestable and treated by policy as unpinned.
5. **Four states, one diff algebra.** `declared`, `approved`, `deployed`, `observed` are four `Snapshot.kind` values over the same entity graph. `symbiote diff` produces a `Delta` document; the delta *is* the finding list for drift. Observed snapshots come from live MCP `tools/list` and OTel GenAI traces, and traces cite the active snapshot digest via a resource attribute.
6. **Anti-rollback and revocation are first-class.** Snapshots carry a monotone `serial` and `prev` digest; trust-status lists (allowlisted / quarantined / revoked, keyed on identity digests) carry their own serial and short expiry; the GAB verifier keeps a last-seen state file and refuses regressions. A stale revocation list fails closed by default.
7. **No format fork.** CycloneDX 1.7 and SPDX 3.0.1 are exporters of one Pydantic model. CycloneDX extension points used: `properties` under the registered namespace `symbiote:` (versioned taxonomy, divergence register), `externalReferences`, `declarations`, `compositions`, `formulation` (as the coverage/collection recipe), `annotations`, `citations`, `dependencies`, `services`, `metadata.lifecycles`, `definitions.standards` (conformance levels as a CycloneDX standard), `vulnerabilities` (AI-VEX keyed to ATLAS/OWASP IDs). SPDX uses `ai_AIPackage`, `dataset_DatasetPackage`, `software_Package/File`, Core `SoftwareAgent/Tool/Organization`, `LifecycleScopedRelationship(runtime)`, `hasEvidence`, `NoAssertionElement`/`NoneElement` for unknown vs verified-absence, `CdxPropertiesExtension` for the lossless property bridge, and **typed Symbiote extension classes under `https://symbiote.dev/spdx/3.0.1/terms/`** — verified to pass the official 3.0.1 JSON schema (V-12).
8. **Merkle-committed BOM.** An RFC 6962-style tree over canonical entity leaves gives a signed root; a redacted view replaces leaves with `{redacted, class, leafHash}` and still verifies. Redaction is recorded (`symbiote:redaction:applied`), never silent.
9. **Everything is self-writing.** Eleven collectors generate the declared/observed layers from the files and endpoints that already exist; the human writes approvals, trust decisions and identity constraints — nothing else.

---

## 1. Enforcement-first stance

### 1.1 Consumer contracts

| Consumer | Question it must answer | Input it receives from Symbiote | Decision rule it runs | What the BOM must therefore guarantee |
|---|---|---|---|---|
| **Tool gateway / agent runtime** | "May this served tool definition be exposed to the model, and may this call proceed?" | **GAB** = `allowlist.json` (derived) + signed `agentbom-snapshot/v1` + `tool-definition-set/v1` + `trust-status/v1` DSSE envelopes + verification policy | Serve a tool iff `sha256(JCS(served def))` ∈ `allowed.tools[server].digests` ∧ server identity (endpoint origin / package digest / signer) matches ∧ snapshot `validity.notAfter` > now ∧ snapshot `serial` ≥ last-seen ∧ no `revoked`/`quarantined` status on tool, server, publisher or model ∧ (for destructive+open-world tools) approval-gate flag honored | Tool-definition digests are exact, canonical and fail-closed; snapshot has serial/prev/validity; trust status is signed and expiring; server identity is recorded as a verifiable binding, not a display name |
| **Policy engine (OPA/Rego, built-in checker)** | "Does this agent violate least privilege, Rule-of-Two, pinning, serialization, approval-gate policy?" | **PID** = the companion AgentBOM JSON (full graph) + `derived.flags[]` with cited inputs | Rego over `input.grants`, `input.edges`, `input.tools`, `input.models`, `input.data_sources`, `input.coverage` | Grants are structured (capability class, scope, credential binding, gate, enforcement point); every tool has side-effect facts with provenance (`declared` by server vs `observed`); every input source has a trust tier; coverage says which surfaces were actually examined |
| **Incident responder** | Q1 "Which agents hold credentials this compromised MCP server can use?" Q2 "Which deployments ran under snapshot X when the poisoned memory write happened?" Q3 "Which agents still trust the revoked publisher?" | **Incident Index** = SQLite built by `symbiote index` over a store of snapshots, deltas, attestations, resolutions and trace summaries | Graph traversal over `holdsCredential`, `delegatesTo`, `writesMemoryTo`, `resolvedFrom`, `approvedUnder` edges with validity windows | Credential bindings are by reference with lifetime class; deployments carry snapshot digests + validity windows; registry resolutions record publisher identity and signer; approvals name the covered snapshot digest |

### 1.2 Verification-first invariants (tested as unit/property tests, cited by ID in code)

- **I1 Evidence-bearing claims.** Every field value above the identity level is wrapped in a `Claim[T]` carrying `assurance ∈ {declared, observed, verified}`, `state ∈ {present, absent-verified, unknown}`, `evidence[]` (digest references), `method`, `collector`, `observedAt`.
- **I2 Unknown ≠ absence.** `state: unknown` is the only legal result of a failed/unauthorized/untried query. A collector that cannot reach a surface writes `coverage.surfaces[x].status = permission-denied|unreachable|not-attempted`, never an empty list.
- **I3 No laundering of signatures (Design 002).** `verified` ⇐ chain valid ∧ inclusion proven ∧ identity constraint satisfied (or non-public root) ∧ declared digest binding not contradicted. Any other outcome is a recorded fact (`signature-valid-unconstrained`, `identity-mismatch`, `digest-mismatch`, `subject-name-mismatch`, `failed: <reason>`, `error: <class>`) at assurance ≤ `observed`.
- **I4 Four states never merge silently.** Exporters refuse to combine snapshots of different `kind` into one document unless `--merge-kinds` is given, and then every component carries `symbiote:snapshot:kind`.
- **I5 Fail-closed digests.** No digest is emitted for input that violates JCS domain rules; the entity is marked `digest.status = undigestable` with reason, and `SYM-TOOL-004` fires.
- **I6 Redaction recorded.** Every redaction class applied is listed at document level and on the affected entity.
- **I7 Determinism.** Identical inputs produce byte-identical CDX/SPDX/companion output under `--deterministic` (timestamp pinned to snapshot time; `serialNumber` = UUIDv5 of the snapshot digest; all arrays sorted by stable keys).
- **I8 Name is locator, digest is identity.** `name`, `purl`, alias, URL are locators. Equality, diff and allowlists operate on digests; a name match never upgrades assurance.

---

## 2. Semantic model (R3, R4, R5, R6, R7)

### 2.1 Conventions

- **Identity.** Every entity has `id` (stable, deterministic, string) and `digest` (`sha256:<64 hex>`). `id` formats: `agent:<slug>`, `deploy:<uuid5>`, `snap:<serial>:<digest12>`, `tool:<server-id>/<tool-name>`, `mcp:<reverse-dns-or-slug>`, `instr:<path-slug>`, `prompt:<slug>`, `skill:<slug>`, `model:<slug>`, `data:<slug>`, `ident:<slug>`, `grant:<uuid5>`, `appr:<uuid5>`, `res:<uuid5>`, `ev:<digest12>`, `eval:<uuid5>`, `ts:<serial>`. `uuid5` uses namespace `urn:uuid:6f9b2d3e-5c1a-4f0e-9b7a-2e1c3d4f5a6b` (**D-01**, project constant) over the entity's canonical identity fields.
- **Digest encoding.** Internal and companion: `sha256:<hex>` (OCI style). in-toto `DigestSet`: `{"sha256": "<hex>"}`. CycloneDX `hashes[]`: `{"alg":"SHA-256","content":"<hex>"}`. SPDX: `Hash{algorithm: sha256, hashValue}`. Only SHA-256 is mandatory; BLAKE3 optional for large model shards (model-signing supports it).
- **Time.** RFC 3339 UTC with `Z`; validity windows are half-open `[notBefore, notAfter)`.
- **Claim envelope.** `Claim[T] = {value: T|null, state, assurance, confidence?: 0..1, method, evidence: [EvidenceRef], locator?: string, collector: CollectorRef, observedAt}`. `locator` follows k8s-aibom's evidence-locator idea (exact source path, e.g. `.mcp.json#/mcpServers/github/args/2`).
- **Pydantic.** All entities are `pydantic.BaseModel` with `model_config = ConfigDict(extra="forbid", frozen=True)`; unknown importer fields are preserved in `foreign: dict` to avoid silent loss.

### 2.2 Entities

**Agent** (the definition; one per agent product/version)

| Field | Type | Req | Description |
|---|---|---|---|
| id, digest | str | yes | Identity; digest over canonical definition (name, version, framework, instruction digests, declared tool/model refs) |
| name, version | str | yes | Locators |
| framework | `Claim[FrameworkRef]` | no | e.g. `langgraph@0.6.x`, `claude-agent-sdk`, `openai-agents`, `crewai`, `autogen`, `semantic-kernel`, `custom` |
| purpose | str | no | Intended purpose (EU AI Act Art. 13 system-level) |
| owner, operator | `PartyRef` | yes/no | Organization/person refs |
| autonomy | `Claim[AutonomyProfile]` | yes | **Action-specific**: list of `{capabilityClass, mode: autonomous|approval-required|forbidden}` plus a coarse `level: L0..L4` (maps to SPDX 3.1 `isoAutomationLevel` when verified) |
| instructions | `[InstructionRef{id, precedence}]` | yes | Ordered by loading precedence |
| models, tools, dataSources, subAgents | `[Ref]` | yes | Declared composition (edges carry the semantics) |
| identities | `[IdentityRef]` | no | Workload identities the agent may act as |
| policyBundle | `Claim[DigestRef]` | no | Digest of the policy bundle the runtime enforces |

**Deployment** — `id, agentRef, snapshotRefs[] (with validity windows), environment{kind: k8s|serverless|desktop|ci|other, cluster?, namespace?, host?}, tenant, workloadIdentity: IdentityRef, startedAt, endedAt?, collector, observedBy[]`.

**Snapshot** — `id, kind ∈ {declared, approved, deployed, observed}, digest (Merkle root of entity leaves), serial: int (monotone per agentRef+kind), prev: digest|null, agentRef, deploymentRef?, validity{notBefore, notAfter}, producedAt, producer: CollectorRef|PartyRef, entities: [entity refs + leaf digests], edges: [Edge], coverage: CoverageRef, approvals: [ApprovalRef] (kind=approved), observationWindow?{start,end}, redactions: [RedactionRecord]`.

**Delta** (signed append-only change record) — `id, fromSnapshot, toSnapshot, producedAt, events: [DeltaEvent]`, where `DeltaEvent = {type ∈ {tool-registered, tool-removed, tool-definition-changed, server-added, server-endpoint-changed, model-routed, model-alias-resolved, sub-agent-spawned, memory-writer-added, instruction-changed, grant-added, grant-removed, identity-changed, registry-status-changed, signer-changed}, subject: Ref, before: digest|null, after: digest|null, evidence: [EvidenceRef], assurance, severityHint}`.

**ToolServer** (MCP server or A2A peer or OpenAPI tool provider)

| Field | Type | Req | Description |
|---|---|---|---|
| id, digest | str | yes | Digest over `{name, transport, endpointOrigin|packageRef, serverInfo{name,version}, instructionsDigest, capabilities}` |
| kind | enum `mcp`, `a2a`, `openapi`, `builtin` | yes | |
| transport | `Claim[enum stdio, streamable-http, sse, websocket]` | yes | |
| endpoint | `Claim[URL]` | cond | Remote servers; origin (scheme+host+port) is the identity-bearing part |
| package | `Claim[PackageRef{purl, digest?, floating: bool, launcher: npx|uvx|docker|binary}]` | cond | stdio servers; `floating=true` when version unpinned (`@latest`, `-y pkg` with no version) |
| serverInfo | `Claim[{name, version, title}]` | no | From `initialize` |
| instructionsDigest | `Claim[digest]` | no | MCP `InitializeResult.instructions` is model-visible → digested as an Instruction |
| authentication | `Claim[AuthMode{mode: none|oauth2|api-key|mtls|other, issuer?, scopesRequested?[]}]` | yes | |
| trustZone, crossesTrustBoundary | `Claim[str]`, `Claim[bool]` | yes | Map to CDX service fields |
| registryResolution | `RegistryResolutionRef` | no | How the name was resolved |
| tools | `[ToolDefinitionRef]` | yes | Declared or served |
| toolListMeta | `{ttlMs?, cacheScope?}` | no | From `ListToolsResult` (protocol 2026-07-28) |
| implementation | `Claim[{packageDigest?, lockfileDigest?, imageDigest?, deploymentAttestationRef?, tlsIdentity?, spiffeId?}]` | no | Binds the served interface to an implementation artifact (local servers: package + lockfile + launcher resolution record) or to a provider deployment attestation / TLS-SPIFFE identity (remote servers) — the ToolContract of ATTACK-22 |

**ToolDefinition** (the model-visible contract — the primary enforcement object)

| Field | Type | Req | Description |
|---|---|---|---|
| id | str | yes | `tool:<server-id>/<name>` |
| digest | `Digest{algo: sym-tooldef/v1, value, status: ok|undigestable, reason?}` | yes | §7.2 |
| fullDigest | `Digest{algo: sym-tooldef-full/v1}` | no | Includes `_meta`, `icons`, `execution` |
| name, title, description | str | yes/no/no | As served |
| inputSchema, outputSchema | JSON | yes/no | As served, **not** `$ref`-expanded |
| annotations | `Claim[{readOnlyHint?, destructiveHint?, idempotentHint?, openWorldHint?, title?}]` | no | `assurance=declared`, source=server; absent hints recorded as absent (policy applies MCP defaults: destructive=true, openWorld=true) |
| sideEffects | `Claim[SideEffectProfile{read, write, destructive, openWorld, egressDestinations[], financial}]` | no | Independent assessment (`observed` from traces or `verified` from evaluation) kept separate from server-declared `annotations` |
| requiredScopes | `Claim[[str]]` | no | Scopes the tool needs (from docs/config/OAuth PRM) |
| textFlags | `[enum hidden-unicode, external-ref, cross-tool-directive, secret-shaped-token]` | no | Lint facts over model-visible text (§7.2) |
| source | enum `declared-config`, `registry`, `served-live`, `trace` | yes | Where this definition came from |

**Instruction** — `id, digest (sha256 of exact bytes), kind ∈ {system-prompt, developer-prompt, agents-md, claude-md, cursor-rules, skill-md, mcp-instructions, hook, rules-file, other}, path|uri, mediaType, size, lineEndings ∈ {lf, crlf, mixed}, precedence, editors: Claim[[PartyRef|IdentityRef]] (who may modify), loadsRemote: Claim[[URL]], frontmatter? (SKILL.md: name, description, allowed-tools)`.

**PromptTemplate** — `id, digest (sym-prompt/v1), engine ∈ {none, jinja2, f-string, mustache, handlebars, other}, role ∈ {system, developer, user, tool}, template (optional inclusion), variablesSchema (JSON Schema), source`.

**Skill** — `id, digest (sym-dirmanifest/v1 root), manifest: DirManifest, skillMd: InstructionRef, allowedTools: Claim[[str]], referencedServers[], scripts[] (with code-execution flag)`.

**Model** (local artifact, hosted alias, or both)

| Field | Type | Req | Description |
|---|---|---|---|
| id | str | yes | |
| kind | enum `weights`, `hosted`, `adapter`, `tokenizer`, `chat-template`, `embedding` | yes | |
| identity | `Claim[ModelIdentity]` | yes | weights: `{manifestRoot (OMS root digest), manifestRef, purl: pkg:huggingface/ns/name@commit, files: n}`; hosted: `{provider, requestedAlias, resolvedSnapshot: Claim[str] (state may be unknown), endpointOrigin, providerEvidence: [EvidenceRef], fingerprint?: BehavioralFingerprint}` |
| serialization | `Claim[{formats: [safetensors|onnx|gguf|pickle|torch-zip|tf-savedmodel|keras-h5|other], riskClass: none|low|code-exec-on-load, trustRemoteCode: bool|unknown, chatTemplateExecutable: bool|unknown, scanner?: {name, version, resultDigest}}]` | weights:yes | |
| derivation | `[DerivationEdge]` | no | `{kind: fineTuneOf|adapterOf|quantizationOf|mergeOf|distillationOf|conversionOf, parentRef, parameters{method?, bits?, mergeMethod?, dataRefs[]}, assurance}` |
| signature | `SignatureFacts` | no | `{status: unsigned|claimed|verified, outcome, reason?, identity?, issuer?, rekorEntry?, subjectNameMismatch?: bool, bundleDigest}` — k8s-aibom field set |
| aliasPinned | `Claim[bool]` | hosted:yes | `false` when alias may move |
| tokenizer, chatTemplate | `ModelRef` | no | Treated as separate executable-adjacent artifacts |
| card | `ModelCardRef` | no | Free-text card fields pass through to CDX `modelCard`/SPDX AI fields |

**DataSource** — `id, kind ∈ {dataset, rag-index, memory-store, knowledge-plugin, live-feed}, trustTier ∈ {0-internal-verified, 1-internal, 2-partner, 3-untrusted-public, unknown}, instructionBearing: Claim[bool], classification: [str] (PII, confidential, source-code, credentials...), snapshot: Claim[{digest|merkleRoot, at}] | live: {unbounded: true, refreshPolicy}, embeddingModelRef?, chunking?{strategy, size, overlap}, ingestionFilters[], acl: {mode: document-level|index-level|none}, writers: Claim[[IdentityRef|AgentRef]], retention?, quarantine?: {status, since}, invalidationDependents[], sources: [{uri, fetchedAt, digest, license?, consent?, ownershipSnapshot?}] (per-source fetch evidence for training/RAG corpora, ATTACK-21), poisonScans: [EvidenceRef]`.

**Identity** — `id, kind ∈ {spiffe, oauth-client, service-account, k8s-sa, iam-role, github-app, azure-managed-identity, api-key-ref, human, other}, ref (SPIFFE ID / client id / ARN / email — never secrets), issuer, tenant, evidence`.

**CredentialBinding** — `id, subjectRef (agent|tool|server), identityRef, kind ∈ {static-long-lived, ephemeral-task-scoped, obo-token, service-account, unauthenticated}, lifetime?: duration, scopesGranted: Claim[[str]], storage: {kind: env|file|secret-manager|keychain|unknown, locator}` — **values never recorded**.

**Grant** (authorization record; R5)

| Field | Type | Req | Description |
|---|---|---|---|
| id | str | yes | |
| layer | enum `declared`, `effective`, `observed` | yes | Declared by config; policy-derived effective; observed from traces/IdP |
| subject | Ref (agent, tool, server, sub-agent) | yes | |
| capability | enum `read`, `write`, `execute`, `network-egress`, `filesystem`, `credentials`, `payment`, `communicate`, `delegate`, `memory-write` | yes | |
| scope | `{resources: [pattern], egress: [host-pattern], dataClasses: [str], spendCeiling?: {amount, currency, period}, rateLimit?}` | yes | Patterns are glob/CIDR/regex-tagged strings |
| granter, delegationChain | PartyRef|IdentityRef, `[DelegationHop{from, to, constraints, expires, evidence}]` | yes/no | A2A chains |
| conditions | `[Condition{kind: time|tenant|input-trust|approval, expr}]` | no | |
| approvalGate | enum `none`, `conditional`, `required` + `gateRef` | yes | Human-in-the-loop |
| validity | `{notBefore, notAfter}` | no | |
| policyRef | `DigestRef` | no | Digest of policy bundle granting this |
| enforcementPoint | `Ref` to EnforcementPoint `{kind: gateway|authz-service|sandbox|network-policy|idp|none, locator, attested: bool}` | yes | `none` is a finding |
| credentialBinding | CredentialBindingRef | no | |
| assurance, evidence | Claim fields | yes | |

**Approval** — `id, approver: PartyRef|IdentityRef, approvedSnapshotDigest, covers: {toolDigests[], modelIds[], grantIds[], deploymentSelector}, policyRef, issuedAt, expires, revocationRef?, attestationRef`.

**RegistryResolution** — §7.5 (requested → resolved → signer → log inclusion).

**Evidence** — `id (= digest), kind ∈ {attestation-dsse, sigstore-bundle, tools-list-capture, trace-summary, scan-report, config-file, api-response, screenshot, human-attestation}, mediaType, digest, uri?, created, expires?, author: PartyRef|CollectorRef, redactionClass?`.

**Evaluation** (R7) — `id, subjectConfig: {modelDigests[], promptDigests[], toolSetDigest, dataSourceDigests[], policyDigest}, threatModel: [OWASP ASI id | LLM Top10 id | ATLAS technique id], harness: {name, version, digest}, dataset: {name, digest, size}, attackConditions: {attackerKnowledge, channels[], budget}, results: [{metric, numerator, denominator, ci?}], assessor: PartyRef, thirdParty: bool, validity: {expires, invalidatedBy: [configField]}, evidence: [EvidenceRef]`.

**VexStatement** (AI-VEX) — `id, weakness: {source: ATLAS|OWASP-ASI|OWASP-LLM|CWE, id}, subject: {agentRef|toolRef|modelRef, configDigest}, status ∈ {affected, not-affected, under-investigation, fixed}, justification ∈ {tool-disabled, guardrail-enforced, approval-required, scope-restricted, input-untrusted-blocked, component-not-present, other}, evidence[], statementTime, expires`.

**Coverage** — `surfaces: {code, registry, identity, model-gateway, tools, data, runtime, network: {status: queried|partial|permission-denied|unreachable|not-attempted|truncated, sources: [str], itemsSeen: int, truncatedAt?: int, errors[]}}, exclusions: [{pattern, reason}], window: {start, end}, collectors: [CollectorRef{name, version, digest}], textIncluded: bool`.

**TrustStatus** — `id, subjectKind ∈ {tool-digest, server-identity, publisher-identity, model-manifest, skill-digest, instruction-digest}, subjectDigestOrIdentity, status ∈ {allowlisted, quarantined, revoked}, reason, decidedBy, decidedAt, expires, serial, supersedes?`.

**Collector/Observation** — `Collector{name, version, digest, mode: declared|observed}`, `Observation{collectorRef, at, surface, locator}`.

### 2.3 Edge types (relationship vocabulary with qualifiers)

Every edge: `{type, from, to, qualifiers: {assurance, scope ∈ {design, build, runtime}, validity?, evidence[], observedCount?, firstSeen?, lastSeen?, declaredBy?}}`.

| Edge type | from → to | Extra qualifiers | Meaning / why enforcement needs it |
|---|---|---|---|
| `usesModel` | Agent → Model | `role: primary|router|embedding|judge`, `routingRule?` | Model routing changes are deltas |
| `invokesTool` | Agent → ToolDefinition | `declared|observed`, `argsSchemaDigest?` | Declared callable set vs tools actually called |
| `providesTool` | ToolServer → ToolDefinition | `servedAt` | The set the gateway allowlists |
| `delegatesTo` | Agent → Agent/ToolServer(a2a) | `constraints`, `audience`, `scopes[]`, `expires` | A2A chain; compromise propagation |
| `spawns` | Agent → Agent | `dynamic: bool` | Sub-agent discovery at runtime |
| `loadsInstruction` | Agent → Instruction | `precedence`, `loadedAt` | Ordered instruction stack |
| `readsContextFrom` | Agent → DataSource | `trustTier`, `instructionBearing` | Untrusted-input leg of the trifecta |
| `readsMemoryFrom` / `writesMemoryTo` | Agent → DataSource(memory) | `writerIdentity` | Q2 incident query; memory poisoning blast radius |
| `actsAs` | Agent/Deployment → Identity | `issuer` | Identity binding |
| `holdsCredential` | Agent/Tool/Server → CredentialBinding | `kind` | Q1 incident query |
| `grantedBy` | Grant → Party/Identity | | Authority source |
| `enforcedAt` | Grant → EnforcementPoint | `attested` | Where "deny" actually happens |
| `approvedUnder` | Snapshot → Approval → Policy digest | | Approval covers a digest, not a name |
| `resolvedFrom` | ToolServer/Model/Skill → RegistryResolution | | Name resolution record |
| `derivedFrom` | Model → Model; DataSource → DataSource | `kind` (models: fineTuneOf…; datasets: filteredFrom, dedupedFrom, augmentedFrom, sampledFrom), `parameters` | Lineage with parameters |
| `evaluatedBy` | Agent/Model/Tool → Evaluation | `configDigest` | Evidence binding to the exact configuration |
| `observedBy` | any → Collector | `at` | Provenance of observed facts |
| `dependsOn` | Agent → software component | `purl` | Software layer (merged SBOM) |
| `embeds` | DataSource(rag) → Model(embedding) | | Embedding coupling of indexes |

### 2.4 Enumerations (closed; additions are MINOR taxonomy bumps)

`AssuranceLevel = declared | observed | verified`; `ValueState = present | absent-verified | unknown`; `SnapshotKind = declared | approved | deployed | observed`; `CapabilityClass` (10 values, §2.2 Grant); `CredentialKind` (5); `TrustTier` (0–3, unknown); `SerializationRisk = none | low | code-exec-on-load`; `SignatureStatus = unsigned | claimed | verified`; `SignatureOutcome = verified | signature-valid-unconstrained | identity-mismatch | digest-mismatch | subject-name-mismatch | failed | error`; `TrustState = allowlisted | quarantined | revoked`; `ApprovalGate = none | conditional | required`; `DeltaEventType` (15, §2.2); `CoverageStatus` (6); `DigestStatus = ok | undigestable`; `Autonomy L0..L4` (L0 chatbot, L1 copilot/suggest, L2 bounded autonomy with approval on writes, L3 autonomous within policy, L4 self-directed incl. delegation).

### 2.5 Snapshot and delta semantics

- A snapshot's `digest` is the Merkle root over leaves `L_i = SHA-256(0x00 ‖ JCS({"_type":"https://symbiote.dev/digest/leaf/v1","salt":<32 random bytes, hex>,"kind":<entity kind>,"id":<id>,"body":<canonical entity>}))`, leaves sorted by `(kind, id)`, internal nodes `SHA-256(0x01 ‖ left ‖ right)` (RFC 6962 shape; odd node promoted). Edges and claims are leaves too (`kind: edge`, `kind: grant`, …). Per-leaf salts are generated once at snapshot creation, stored with the snapshot and disclosed only together with the leaf body, so a redacted leaf cannot be dictionary-guessed from the root (SD-JWT-style selective disclosure; ATTACK-12). Determinism (I7) holds because re-exports reuse the stored salts; the test suite derives salts from a fixed seed via HKDF.
- `serial` is assigned by the producer: `max(prev.serial)+1` per `(agentRef, kind)`. Verifiers persist `last-seen[(agentRef, kind)]` and reject `serial ≤ last-seen` unless `--allow-rollback` (never in gateway mode).
- `prev` links form a hash chain; a snapshot whose `prev` is not the last-seen digest is accepted only with `chain-gap: true` recorded (fork detection for IR).
- A `Delta` is derived (`symbiote diff`) and may be independently signed (`observed-delta/v1`), which lets a runtime publish "tool X description changed at T" without re-publishing the whole snapshot.
- Observed snapshots have `observationWindow`; staleness = `now − window.end`; GAB verifiers require `staleness < policy.maxStaleness`.

### 2.6 Assurance levels, k8s-aibom mapping, and what each level requires

| Symbiote | Meaning | Minimum evidence | k8s-aibom import mapping | Export to k8s-aibom-compatible property |
|---|---|---|---|---|
| `declared` | Owner/supplier/config says so | Locator into the source file/config | `aibom.confidence=declared` → `declared` | `declared` |
| `observed` | A collector corroborated the deployed state at a time within a scope | Capture digest (tools/list response, trace, API response) | `inferred` → `observed` with `method=heuristic`, `confidence≤0.5`, locator preserved | `inferred` |
| `verified` | Evidence authenticated and evaluated against an explicit trust policy with coverage | Signature facts `status=verified` with identity constraint recorded; or digest equality against a verified manifest | `verified` → `verified` **only if** the imported document also carries `signature.identity` and a non-empty constraint record; otherwise `observed` + note `imported-verified-without-constraint` | `verified` |
| state `unknown` | Could not determine | Coverage status | `unresolved` → `state=unknown` | `unresolved` |

The reverse mapping is exported only in the k8s-aibom compatibility profile (`--profile k8s-aibom-compat`), using the dotted names k8s-aibom emits today and the colon form announced for its 1.7 taxonomy rename (both accepted on import).

---

## 3. CycloneDX 1.7 mapping (R1)

### 3.1 Library decision

**D-02.** CycloneDX JSON is emitted by Symbiote's own serializer and validated against the vendored official `bom-1.7.schema.json` (with `jsf-0.82` and `spdx` sub-schemas) on every export (V-05). `cyclonedx-python-lib` 11.12.0 is used only for (a) `JsonStrictValidator(SchemaVersion.V1_7)` as a second validator and (b) best-effort XML output in v0.2. Reason (V-06): the library's object model has no `modelCard`, `declarations`, `formulation`, `citations` or `annotations` classes, so it cannot carry our core constructs; emitting JSON directly avoids a lossy detour. XML export emits the same constructs via the XSD (the 1.7 XSD *does* contain `modelCard/properties`, V-07 — the JSON/XML divergence quoted in the source analysis does not reproduce against the fetched 1.7 XSD; we nonetheless never write `modelCard.properties`, see D-05).

### 3.2 Construct mapping

| Symbiote entity/field | CycloneDX 1.7 construct | Notes |
|---|---|---|
| Agent | `metadata.component` (`type: application`) with `bom-ref=agent:<slug>`; `tags: ["agent"]` | Nested sub-agents as `components[]` of type `application` with `symbiote:agent:role=sub-agent` |
| Snapshot kind | `metadata.lifecycles[]`: predefined phase (`declared→design`, `approved→post-build`, `deployed→operations`, `observed→discovery`) **plus** named lifecycle `{name: "symbiote:snapshot:<kind>"}` | Phase alone is ambiguous; the named lifecycle is the authoritative marker |
| Snapshot serial/prev/digest/validity | `metadata.properties`: `symbiote:snapshot:serial`, `symbiote:snapshot:prev`, `symbiote:snapshot:digest`, `symbiote:snapshot:not-before`, `symbiote:snapshot:not-after`; `serialNumber` = `urn:uuid:` UUIDv5(snapshot digest); `version` = serial | `serialNumber`/`version` give native BOM-Link addressing `urn:cdx:<uuid>/<serial>#<bom-ref>` |
| ToolServer | `services[]` with `name`, `group` (reverse-DNS registry name), `version`, `provider`, `endpoints[]`, `authenticated`, `x-trust-boundary`, `trustZone`, `data[]` (flows), `externalReferences[]` (`distribution-intake` → registry entry URL; `distribution` → package; `vcs`; `attestation`; `documentation`) | stdio servers have no endpoint; package identity goes to a `components[]` entry (`type: application`, `purl`) linked by `dependencies[].dependsOn` |
| ToolDefinition | `components[]` `type: data`, `data[0].type: definition`, `name` = tool name, `group` = server id, `hashes[{SHA-256: tooldef digest}]`, `tags: ["mcp-tool"]`, `data[0].contents.attachment` only with `--include-text` | `data.type=definition` is the closest native semantics ("data that defines something"); registered divergence D-S03 |
| server → tools | `dependencies[]`: `{ref: <service>, provides: [<tool bom-refs>]}` | `provides` is defined for implemented specifications; a tool contract is a specification implemented by the server (divergence D-S04) |
| Instruction / PromptTemplate / Skill | `components[]` `type: file` (`name` = path, `hashes`, `mimeType`), skill directory as `type: file` with `symbiote:skill:manifest-root` and nested `components[]` for files | Exact-bytes artifacts are files |
| Model (weights) | `components[]` `type: machine-learning-model`, `purl: pkg:huggingface/...@<commit>`, `hashes[{SHA-256: OMS root digest}]`, `modelCard` (native fields only), `pedigree.ancestors[]` for parents, `externalReferences`: `model-card`, `attestation` (model-signing bundle), `distribution` | Typed derivation kind cannot be expressed in `pedigree` → property `symbiote:model:derivation` (JSON) + companion |
| Model (hosted) | `services[]` `type` service (`endpoints`, `authenticated`, `provider`) **and** `components[]` `type: machine-learning-model` with `isExternal: true`, `version` = resolved snapshot or absent, `symbiote:model:alias`, `symbiote:model:resolved-snapshot`, `symbiote:model:alias-pinned` | Two objects: the endpoint (service) and the model identity (component) |
| DataSource (dataset) | `components[]` `type: data`, `data[].type: dataset`, `classification`, `sensitiveData[]`, `governance` | Native |
| DataSource (rag-index/memory-store) | `components[]` `type: data`, `data[].type: dataset`, `data[].contents.properties` for `chunking`/`embedding-model-ref`, `symbiote:data:*` properties | Mutable stores are not native; `symbiote:data:kind=memory-store` |
| Identity / CredentialBinding | `components[]` `type: cryptographic-asset`? **No** (D-06: identities are not crypto assets). Encoded as `services[]`/component `properties` `symbiote:identity:*` and `symbiote:credential:*` on the subject, plus companion | No native identity object in 1.7 |
| Grant | `properties[]` on the subject: one `symbiote:authz:grant` per grant, value = JCS JSON of the Grant record | Property values are strings; JSON-in-value is the established pattern (cdxgen, k8s-aibom); the companion holds the structured form |
| Computed flags | `metadata.properties`: `symbiote:flag:lethal-trifecta`, `symbiote:flag:rule-of-two-violation`, `symbiote:flag:unpinned-tools`, `symbiote:flag:floating-model-alias`, `symbiote:flag:destructive-open-world-ungated`, `symbiote:flag:unsigned-models`, `symbiote:flag:unsafe-serialization` (values `true|false|unknown`) | Also as `declarations.claims` with reasoning |
| Evidence | `declarations.evidence[]` (`propertyName`, `data[].contents.url` = evidence URI, `created`, `expires`, `author`) + `externalReferences[type=evidence|attestation, hashes]` | Evidence referenced by digest |
| Claim/assurance per entity | `annotations[]` with `subjects=[bom-ref]`, `annotator.component=symbiote`, `text="assurance=<level>; state=<state>; method=<m>; evidence=<digest…>"` **and** per-entity `symbiote:assurance`, `symbiote:evidence:locator`, `symbiote:evidence:source` | Both forms; properties are grep-able (k8s-aibom precedent) |
| Field-level attribution | `citations[]` with JSON Pointer `pointers` to the field, `attributedTo` = collector tool `bom-ref` or `process` = formulation task, `signature` optional | Native 1.7 |
| Coverage | `formulation[0].workflows[0]` (`uid` = collection run id, `tasks[]` one per collector with `taskTypes: ["other"]`, `inputs/outputs` with `resource.ref`, `properties` `symbiote:coverage:surface|status|items-seen|truncated-at|permission-failure`), plus `compositions[]` (`aggregate` per assembly: `complete|incomplete|unknown`) | Formulation = "how this BOM was assembled"; compositions = completeness assertion |
| Evaluation | `declarations.claims[]` + `declarations.evidence[]` + `declarations.assessors[]`; `externalReferences[type=dynamic-analysis-report|pentest-report]` | Structured results in companion |
| AI-VEX | `vulnerabilities[]`: `id` = ATLAS/OWASP id, `source: {name: "MITRE ATLAS"|"OWASP Agentic Top 10"}`, `affects[].ref`, `analysis.state` (`not_affected`…), `analysis.justification` ∈ {`protected_by_mitigating_control`, `requires_configuration`, `protected_at_runtime`, `protected_at_perimeter`, `code_not_reachable`}, `analysis.detail` = justification text, `properties`: `symbiote:vex:config-digest`, `symbiote:vex:justification` | Scoped to (model, config) tuple through the digest property |
| Trust status | `symbiote:trust:status`, `symbiote:trust:serial`, `symbiote:trust:expires` on the subject; revoked publishers via `symbiote:trust:revoked-publisher` at metadata | Separate signed `trust-status/v1` attestation |
| Conformance level | `definitions.standards[]` = "AgentBOM Conformance 1.0.0" with `requirements[]` (`identifier: AB-MIN-01…`) and `levels[]` (minimal/standard/verified); `declarations.attestations[].map[]` with `conformance.score` and `confidence.score` | Native CDXA; verified by probe (V-05) |
| Registry resolution | `externalReferences[type=distribution-intake]` with `properties` `symbiote:registry:status|published-at|is-latest|publisher|signer-status|rekor-log-index` on the service/component | Companion holds full record |
| Software layer | Imported cdxgen/syft components verbatim; `dependencies` merged under the agent | |
| Merkle root / redaction | `properties`: `symbiote:bom:merkle-root`, `symbiote:bom:leaf-count`, `symbiote:redaction:applied` (one per class) | |
| Signature | DSSE/Sigstore externally (R8); optional JSF `signature` (ES256) on the whole document | JSF signer fields verified (V-08) |
| Companion linkage | `metadata.component.externalReferences[]` `{type: bom, url: <companion URI>, hashes:[SHA-256], comment: "symbiote-agentbom-companion"}` + `metadata.properties.symbiote:bom:companion-digest`; companion `links.cyclonedx = {serialNumber, version, bomLink, digest}` | Bidirectional by digest |

### 3.3 Property taxonomy (namespace `symbiote`, version 1)

**D-03 Namespace.** `symbiote` is registered as a CycloneDX top-level namespace (the taxonomy registry has no `agentbom`, `agent` or `symbiote` entry; registration is an issue on cyclonedx-property-taxonomy and requires public documentation, V-09). Rationale against `agentbom:`: a generic name would imply a standard that does not exist and would collide with OWASP's AgBOM vocabulary; against `cdx:`: reserved for the core working group. Names use lower-kebab-case ASCII per the taxonomy ABNF; sub-namespaces are colon-separated. Every property is defined in `taxonomy/symbiote-cdx-taxonomy.md` with type, cardinality, since-version, upstream candidate (`cdx:ai:agent:*` proposals tracked under property-taxonomy#175 and the CycloneDX 2.0 RFC #990, both cited by k8s-aibom).

| Property (exact) | Where | Value | Cardinality |
|---|---|---|---|
| `symbiote:bom:taxonomy-version` | metadata | `1` | 1 |
| `symbiote:bom:profile` | metadata | `agentbom-minimal|standard|verified|k8s-aibom-compat` | 1 |
| `symbiote:bom:companion-digest`, `symbiote:bom:merkle-root`, `symbiote:bom:leaf-count`, `symbiote:bom:model-digest` | metadata | digest / int | 0..1 |
| `symbiote:snapshot:kind`, `:serial`, `:prev`, `:digest`, `:not-before`, `:not-after`, `:observation-start`, `:observation-end` | metadata | enum/int/digest/time | 1 each (kind, serial, digest) |
| `symbiote:assurance` | any entity | `declared|observed|verified` | 1 |
| `symbiote:state` | any entity | `present|absent-verified|unknown` | 0..1 |
| `symbiote:evidence:source`, `symbiote:evidence:locator`, `symbiote:evidence:ref` | any entity | source kind / locator / digest | 0..n |
| `symbiote:agent:role`, `symbiote:agent:framework`, `symbiote:agent:autonomy-level`, `symbiote:agent:autonomy-profile` (JSON) | agent components | | |
| `symbiote:tool:digest`, `symbiote:tool:digest-status`, `symbiote:tool:digest-algo`, `symbiote:tool:full-digest`, `symbiote:tool:source`, `symbiote:tool:read-only-hint`, `symbiote:tool:destructive-hint`, `symbiote:tool:idempotent-hint`, `symbiote:tool:open-world-hint`, `symbiote:tool:annotations-present`, `symbiote:tool:required-scopes` (JSON), `symbiote:tool:text-flags` (CSV), `symbiote:tool:side-effects` (JSON) | tool components | | |
| `symbiote:mcp:transport`, `symbiote:mcp:protocol-version`, `symbiote:mcp:server-name`, `symbiote:mcp:server-version`, `symbiote:mcp:instructions-digest`, `symbiote:mcp:package-floating`, `symbiote:mcp:launcher`, `symbiote:mcp:tool-count`, `symbiote:mcp:tools-list-ttl-ms`, `symbiote:mcp:auth-mode` | services | | |
| `symbiote:instruction:kind`, `:precedence`, `:line-endings`, `:editors` (JSON), `:loads-remote` (CSV) | file components | | |
| `symbiote:prompt:engine`, `:role`, `:variables-schema-digest` | file components | | |
| `symbiote:skill:manifest-root`, `:allowed-tools` (JSON), `:has-scripts` | file components | | |
| `symbiote:model:kind`, `:manifest-root`, `:manifest-ref`, `:serialization-formats` (CSV), `:serialization-risk`, `:trust-remote-code`, `:chat-template-executable`, `:alias`, `:alias-pinned`, `:resolved-snapshot`, `:provider`, `:derivation` (JSON), `:signature-status`, `:signature-outcome`, `:signature-identity`, `:signature-issuer`, `:signature-rekor-entry`, `:signature-subject-name-mismatch`, `:fingerprint` (JSON) | ML components | | |
| `symbiote:data:kind`, `:trust-tier`, `:instruction-bearing`, `:snapshot-digest`, `:live-unbounded`, `:embedding-model-ref`, `:chunking` (JSON), `:acl-mode`, `:writers` (JSON), `:retention`, `:quarantine-status` | data components | | |
| `symbiote:identity:kind`, `:ref`, `:issuer`, `:tenant`; `symbiote:credential:kind`, `:lifetime`, `:storage-kind`, `:scopes-granted` (JSON) | subject entity | never secret values | |
| `symbiote:authz:grant` (JSON Grant), `symbiote:authz:layer` | subject entity | | 0..n |
| `symbiote:flag:*` (7 flags, §3.2) | metadata | `true|false|unknown` | 1 each |
| `symbiote:registry:url`, `:entry-id`, `:version`, `:status`, `:published-at`, `:is-latest`, `:publisher`, `:publisher-verification`, `:signer-status`, `:rekor-log-index`, `:alias-policy` | externalReference / service | | |
| `symbiote:coverage:surface`, `:status`, `:items-seen`, `:truncated-at`, `:permission-failure`, `:source` | formulation tasks | | |
| `symbiote:trust:status`, `:serial`, `:expires`, `:decided-by`, `:revoked-publisher` | subject / metadata | | |
| `symbiote:vex:config-digest`, `:justification`, `:expires` | vulnerabilities | | |
| `symbiote:redaction:applied` | metadata + entity | redaction class | 0..n |
| `symbiote:import:source`, `:source-digest`, `:foreign-property` (`name=value` verbatim) | imported entities | lossless preservation of foreign properties | |
| `symbiote:check:id` | definitions.standards requirements | `SYM-…` | |

### 3.4 Companion AgentBOM document

`$id: https://symbiote.dev/schemas/agentbom/1.0.0/agentbom.schema.json`, media type `application/vnd.symbiote.agentbom+json`, top-level keys: `agentbomVersion, documentDigest, snapshot, agent, deployments[], toolServers[], tools[], instructions[], prompts[], skills[], models[], dataSources[], identities[], credentialBindings[], grants[], approvals[], resolutions[], evidence[], evaluations[], vex[], coverage, trustStatus[], edges[], derived{flags[], findings[]}, merkle{root, leafCount, leaves[]?}, redactions[], links{cyclonedx, spdx}, lossReport?`. It is generated from the same Pydantic model (`model_json_schema()` + hand-written `$comment`s), validated on export, and is the **PID** for policy engines.

### 3.5 Not natively representable in CycloneDX 1.7 (companion only; mirrored as properties)

Structured grants and delegation chains; edge semantics beyond `dependsOn/provides` (invokes, delegatesTo, readsContextFrom, writesMemoryTo, actsAs); typed model derivation parameters; identity objects; trust tiers on inputs; registry resolution records; snapshot serial/prev chain and validity; per-claim assurance as a typed field; Merkle leaf manifest; evaluation result denominators; AI-VEX scoping to a configuration tuple. Each is a numbered entry in `docs/divergences.md` (format from k8s-aibom: status active/rescinded/upstreamed, spec section, rationale, upstream tracking, example fragment). Initial entries: **D-S01** `symbiote:*` assurance/evidence properties; **D-S02** JSON-in-property for grants; **D-S03** tool definitions as `type: data / definition`; **D-S04** `dependencies.provides` for server→tool; **D-S05** named lifecycle for snapshot kind; **D-S06** `vulnerabilities[]` keyed to ATLAS/OWASP ids; **D-S07** formulation as collection recipe; **D-S08** hosted model as service+external component pair; **D-S09** `modelCard.properties` deliberately not used (component properties instead, for 1.6-consumer parity).

---

## 4. SPDX 3.0.1 mapping (R2)

### 4.1 Namespace and IRI scheme

- Document namespace: `https://symbiote.dev/spdx/doc/<agent-slug>/<snapshot-digest12>/` ; element `spdxId` = namespace + `<kind>/<id-slug>`. Deterministic, so re-exports of the same snapshot produce identical IRIs.
- Extension vocabulary: `https://symbiote.dev/spdx/3.0.1/terms/<ClassName>` for classes and `https://symbiote.dev/spdx/3.0.1/terms/<propertyName>` for properties (versioned with the SPDX minor; a 3.1 vocabulary will be `.../3.1/terms/`). Published as a JSON-LD context + SHACL shapes at that URL (`schemas/spdx/symbiote-ext.shacl.ttl`, `symbiote-ext.context.jsonld`).
- **V-12 / D-04.** `spdx-python-model` 0.0.6 can emit custom extension objects via `extension_Extension(typ=<IRI>)` with `_ext_data` IRI-keyed properties; the output round-trips through `JSONLDDeserializer` and validates with **zero errors** against the official 3.0.1 JSON schema (`extension_Extension` permits `unevaluatedProperties: true` and requires `type` to be an IRI other than `extension_Extension`). `_ext_data` is a private attribute, so Symbiote wraps it in `symbiote.export.spdx.ext.ExtensionBuilder` and will propose a public API upstream (risk R-7).
- `profileConformance = [core, software, ai, dataset, extension]` (+ `security` when VEX present). Conformance is per profile; the document states all it uses (the source analysis' "profile fragmentation" point).

### 4.2 Class and relationship mapping

| Symbiote entity | SPDX 3.0.1 class | Key properties / identifiers | Relationships emitted |
|---|---|---|---|
| Agent (as artifact) | `ai_AIPackage` (`software_primaryPurpose=application`, `software_packageVersion`, `suppliedBy`, `releaseTime`, `software_downloadLocation` = repo or `NOASSERTION`) | `ai_autonomyType` from autonomy profile (yes/no/noAssertion); `ai_informationAboutApplication` summary; ext `AgentProfile{autonomyLevel, autonomyProfile[], framework, purpose, policyBundleDigest}` | `describes` from `software_Sbom` root |
| Agent (as principal) | `SoftwareAgent` | `name`; ext `AgentIdentity{principalOf: <AIPackage IRI>, spiffeId?, issuer?}` | `invokedBy` (tool → SoftwareAgent); `delegatedTo` (SoftwareAgent → invokedBy-Relationship) exactly as 3.0.1 defines |
| Deployment | `software_Package` (`primaryPurpose=other`) with ext `Deployment{environment, tenant, workloadIdentity, startedAt, endedAt}` | `externalIdentifier(urlScheme)` for cluster/namespace locators | `LifecycleScopedRelationship(dependsOn, scope=runtime)` Deployment→AIPackage; `hasEvidence` → snapshot attestation File |
| Snapshot | `software_Sbom` with `software_sbomType` ∈ {`design` (declared), `build` (approved), `deployed`, `runtime` (observed)} + ext `Snapshot{kind, serial, prev, merkleRoot, notBefore, notAfter}`; `verifiedUsing Hash(sha256=snapshot digest)` | `rootElement` = AIPackage | `describes` |
| ToolServer | `software_Package` (`primaryPurpose=application`); `externalIdentifier(packageUrl)` for the package; `externalRef(other, locator=registry URL, comment="mcp-registry-entry")`; ext `ToolServer{kind, transport, endpointOrigin, authMode, trustZone, crossesTrustBoundary, instructionsDigest, protocolVersion}` | `verifiedUsing Hash` (server digest) | `LifecycleScopedRelationship(usesTool, runtime)` AIPackage→ToolServer; `contains` ToolServer→ToolDefinition |
| ToolDefinition | `software_Package` (`primaryPurpose=specification`) with `verifiedUsing Hash(sha256 = tooldef digest)` + ext `ToolDefinition{digestAlgo, digestStatus, fullDigest, readOnlyHint…, annotationsPresent, requiredScopes[], textFlags[], source}` + `extension_CdxPropertiesExtension` mirror of all `symbiote:tool:*` properties | `software_contentIdentifier` not used (gitoid/swhid semantics differ) | `usesTool(runtime)` AIPackage→ToolDefinition; `invokedBy` ToolDefinition→SoftwareAgent (observed invocations: `startTime/endTime`) |
| Instruction / PromptTemplate | `software_File` (`primaryPurpose=configuration`, `contentType`), `verifiedUsing Hash` + ext `Instruction{kind, precedence, lineEndings, editors[], loadsRemote[]}` / `PromptTemplate{engine, role, variablesSchemaDigest}` | | `LifecycleScopedRelationship(configures, runtime)` Instruction→AIPackage |
| Skill | `software_Package` (`primaryPurpose=module`) + ext `Skill{manifestRoot, allowedTools[], hasScripts}`; files as `software_File` | | `contains`; `configures` |
| Model (weights) | `ai_AIPackage` (`primaryPurpose=model`, `software_packageUrl=pkg:huggingface/...@commit`), `verifiedUsing Hash(sha256 = OMS root)` + ext `ModelIdentity{manifestRoot, manifestRef, serializationFormats[], serializationRisk, trustRemoteCode, chatTemplateExecutable, signatureStatus, signatureOutcome, signatureIdentity, signatureIssuer, rekorEntry}` | native `ai_*` card fields pass through | `ancestorOf`/`descendantOf` + ext `Derivation{kind, parameters}` **on the Relationship element**; `trainedOn`/`testedOn` to DatasetPackage; `hasDataFile` for tokenizer/chat-template Files |
| Model (hosted) | `ai_AIPackage` (`software_downloadLocation` = endpoint origin) + ext `HostedModel{provider, requestedAlias, resolvedSnapshot, aliasPinned, providerEvidence[], fingerprint}` | state `unknown` encoded as `resolvedSnapshot` absent + `resolvedSnapshotState: "unknown"` | `usesTool(runtime)`? No — `dependsOn(runtime)` with ext `EdgeQualifiers{role}` |
| DataSource | `dataset_DatasetPackage` (`dataset_datasetType`, `dataset_confidentialityLevel`, `dataset_datasetUpdateMechanism` = refresh policy text, `dataset_intendedUse`) + ext `MutableStore{kind, trustTier, instructionBearing, snapshotDigest, liveUnbounded, embeddingModelRef, chunking, aclMode, writers[], retention, quarantineStatus}` | | `dependsOn(runtime)` AIPackage→Dataset with ext `EdgeQualifiers{edgeType: readsContextFrom|readsMemoryFrom|writesMemoryTo}`; `generates` ingestion Build? (not in v0.1) |
| Identity | `SoftwareAgent` (non-human principal) or `Person`/`Organization` + ext `Identity{kind, ref, issuer, tenant}` | | `invokedBy` chains; ext `CredentialBinding` attached to the subject element |
| Grant | ext `CapabilityGrant{layer, capability, scope{…}, granter, delegationChain[], conditions[], approvalGate, notBefore, notAfter, policyDigest, enforcementPoint{kind, locator, attested}, credentialBindingRef, assurance, evidence[]}` attached to the subject element | one extension object per grant | — |
| Approval | `software_File` (the signed approval attestation) + ext `Approval{approver, approvedSnapshotDigest, covers{…}, policyDigest, expires}` | | `hasEvidence` Snapshot→Approval; `amendedBy` on supersession |
| RegistryResolution | ext `RegistryResolution{requestedRef, resolvedRef, registryUrl, entryId, status, publishedAt, isLatest, publisher, publisherVerification, signerStatus, signerIdentity, rekorLogIndex, aliasPolicy}` on the resolved element | | `availableFrom` Element→Organization (registry operator) |
| Evidence | `software_File` (`primaryPurpose=evidence`, `verifiedUsing Hash`), `externalRef(secureSoftwareAttestation|runtimeAnalysisReport|securityThreatModel|riskAssessment)` | | `hasEvidence` subject→Evidence |
| Evaluation | `software_File` (`primaryPurpose=evidence`) + ext `Evaluation{subjectConfig, threatModel[], harness, dataset, attackConditions, results[], assessor, thirdParty, validity}` | | `testedOn` Model→Dataset(eval set); `hasEvidence` AIPackage→Evaluation |
| AI-VEX | `security_Vulnerability` with `externalIdentifier(securityOther, identifier=AML.T0110)` + `security_VexNotAffectedVulnAssessmentRelationship(doesNotAffect, justificationType=inlineMitigationsAlreadyExist|vulnerableCodeCannotBeControlledByAdversary|componentNotPresent, impactStatement)` / `VexAffected…` ; ext `VexScope{configDigest, justification}` on the relationship | | native Security profile |
| Coverage | ext `Coverage{surfaces{…}, exclusions[], window, collectors[], textIncluded}` on the `software_Sbom`; **plus** per relationship `completeness` (`complete|incomplete|noAssertion`) and `to=[NoneElement]` for verified absence / `to=[NoAssertionElement]` for unknown | native SPDX idiom (V-12 probe emitted `NoAssertionElement` with `completeness=noAssertion`) | |
| TrustStatus | ext `TrustStatus{status, reason, decidedBy, decidedAt, expires, serial}` on subject; revoked publisher as `Organization`/`SoftwareAgent` with ext | | `hasEvidence` → trust-status attestation File |
| Collector | `Tool` (`version`) in `CreationInfo.createdUsing`; also `Organization` creator | | `usesTool(build)` Sbom→Tool |
| Property bridge | `extension_CdxPropertiesExtension` on every element that has `symbiote:*` properties in the CDX export | lossless CDX↔SPDX round-trip of properties | |

### 4.3 SPDX 3.1 forward notes (verified against the fetched `develop` model, 2026-11-01)

- **Verified present in 3.1-dev:** Core `isoAutomationLevel` (replaces deprecated `ai_autonomyType`), Core `intendedUse`, `ElementMap`, `software_artifactSize`, new profiles `Service`, `Operations`, `SupplyChain`, `Hardware`, and relationship types incl. `finetunedOn`, `pretrainedOn`, `evaluatedOn`, `validatedOn`, `verifiedBy`, `performedBy`, `createdBy`, `runsOn`, `hasInstall/hasUninstall`, `resolved/hasResolution`, `conformsTo`, `implementedBy`, `locatedAt` (RelationshipType: 59 in 3.0.1; the 3.1 changelog text says 76, Phase 1 counted 77 at tag `3.1-rc1` and 83 on `develop`). Symbiote's 3.1 exporter will: emit `isoAutomationLevel` from `Autonomy L0..L4`; replace `ancestorOf`+`Derivation{fineTuneOf}` with `finetunedOn`/`pretrainedOn`; use `evaluatedOn` for Evaluation; `verifiedBy` for signature verification facts; `runsOn` for Deployment→environment; `Service` profile for ToolServer endpoints.
- **Not verified:** `AIAgent`, `Prompt`, `RAG` classes are **absent** from the fetched 3.1-dev model files; the source analysis' RC1 reading agrees. They remain a watch item (A-03); no mapping is promised until Phase 1 verifies them.

---

## 5. Conversion loss model and round-trip strategy (R3)

- Every exporter/importer returns `(document, LossReport)`. `LossReport = {direction: model→cdx|cdx→model|model→spdx|spdx→model|cdx→spdx, items: [{path (JSON Pointer into the model), reason ∈ {no-native-field, enum-narrowed, cardinality, precision, string-flattened, unsupported-by-library, redacted, foreign-unmapped}, preservedIn ∈ {companion, property, extension, dropped}, severity ∈ {none, info, security-relevant}}], roundTripSafe: bool, modelDigest}`. Security-relevant items (grants, digests, assurance, trust status, coverage) must be `preservedIn ≠ dropped` for the export to succeed under `--strict`.
- **Round-trip definition.** `import(export(M)) ≡ M` is tested on the canonical model digest (`symbiote:bom:model-digest`), not on bytes. CDX+companion is lossless by construction; CDX alone is lossless for everything mirrored into properties (JSON-in-value) and lossy for free-text evidence bodies; SPDX alone is lossless when extensions are emitted and lossy when `--no-extensions` is used (then `CdxPropertiesExtension` carries the property mirror and `LossReport` lists the structured records as `string-flattened`).
- **Triangulation.** CDX, SPDX and companion all carry `modelDigest`; `symbiote validate --cross` recomputes it from each and reports divergence (detects post-export tampering of one representation).
- **Importers.** CycloneDX 1.5–1.7 (direct JSON; `modelCard`, `declarations`, `formulation`, `services`, `properties` read; k8s-aibom `aibom.*`/`k8s-aibom:*`, cdxgen and agent-harness-aibom `harness-aibom:*` properties mapped where semantics are known, else preserved as `symbiote:import:foreign-property`), SPDX 3.0.1 JSON-LD (via `spdx-python-model` `JSONLDDeserializer`; Symbiote extensions decoded from `_ext_data`; `CdxPropertiesExtension` → properties → model). Imported documents are tagged `assurance=declared` unless they carry verifiable evidence (k8s-aibom `inferred/verified` mapping per §2.6) and `symbiote:import:source-digest` records the input digest.

---

## 6. Collectors (R9)

Each collector implements `Collector.collect(ctx) -> CollectionResult{entities, edges, claims, coverage: SurfaceCoverage, evidence}`; every produced value is a `Claim` with `locator`. Collectors never write secrets: values of env vars / headers are replaced by `storage.locator` references and a `secret-shaped-token` redaction class is applied to any string that matches known token shapes (recorded via `symbiote:redaction:applied`).

| # | Collector | Inputs | Outputs (entities/edges) | Assurance | Evidence locator examples | Failure → coverage |
|---|---|---|---|---|---|---|
| C1 | `mcp-client-config` | `.mcp.json`, `claude_desktop_config.json`, `~/.cursor/mcp.json`, `.vscode/mcp.json`, Windsurf `mcp_config.json`, Codex `config.toml` (`[mcp_servers.*]`), Gemini CLI `settings.json` (`mcpServers`) | ToolServer (transport, package/launcher, floating flag, env var *names*), edges Agent→ToolServer | declared | `.mcp.json#/mcpServers/github/command`, `config.toml#mcp_servers.github.args[1]` | file unreadable → `tools: permission-denied` |
| C2 | `mcp-live` | server from C1 or `--server`; `mcp` SDK `stdio`/`streamable-http` client: `initialize`, `tools/list` (paginate `nextCursor`), optionally `prompts/list`, `resources/list`; `--watch` keeps the session open and re-lists on `notifications/tools/list_changed`, emitting `tool-definition-changed` deltas (Deadbugz-style runtime-gated poisoning) | ToolDefinition (served; `source=served-live`, digests), ToolServer.serverInfo/instructions/protocolVersion/toolListMeta, Evidence (`tools-list-capture` digest), edges providesTool | observed | `mcp://<server-id>/tools/list@<time>#/tools/3` | connect/auth failure → `tools: unreachable`; truncation after `--max-tools` → `truncated` |
| C3 | `instructions` | `AGENTS.md`, `CLAUDE.md`, `.cursor/rules/*`, `.windsurfrules`, `GEMINI.md`, `.github/copilot-instructions.md`, system prompt files named in `symbiote.yaml`, hooks | Instruction (exact-bytes digest, kind, precedence, line endings, remote includes) | declared | path + git blob id when available | — |
| C4 | `skills` | `SKILL.md` directories (frontmatter `name/description/allowed-tools`), scripts | Skill (dir-manifest root), Instruction, flags `has-scripts` | declared | `skills/foo/SKILL.md#frontmatter.allowed-tools` | — |
| C5 | `a2a-cards` | `/.well-known/agent-card.json` or `agent.json` (URL or file) | Agent (peer), ToolServer(kind=a2a) with `skills[]`, auth schemes, edges delegatesTo, card digest (`sym-jsondoc/v1`), signature facts if JWS present | declared (observed when fetched live) | `https://peer/.well-known/agent-card.json#/skills/0` | fetch failure → `network: unreachable` |
| C6 | `mcp-registry` | `GET https://registry.modelcontextprotocol.io/v0/servers?search=<name>` and `/v0/servers/<name>/versions/<v>`; server.json 2025-12-11 | RegistryResolution (status active/deprecated/deleted, publishedAt, updatedAt, isLatest, packages incl. optional `packages[].fileSha256` recorded as a *declared* digest — remotes carry no digest —, remotes, publisher namespace), typosquat distance to top-N names | observed (registry is a locator, not an authority) | `registry:<name>@<version>#/_meta/io.modelcontextprotocol.registry~1official/status` | unreachable → `registry: unreachable`, resolution `state=unknown` (never "not registered") |
| C7 | `hf-model` | Hugging Face API (`/api/models/<id>?revision=`) when reachable; offline: local snapshot dir hashed with `model_signing.hashing.Config().use_file_serialization()` | Model (purl with commit, OMS manifest + root, file list, serialization formats detected by extension + magic bytes + `config.json.auto_map`/`trust_remote_code`, chat template presence), signature facts via `model_signing.verifying` when a bundle is present | declared (API) / observed (local hash) / verified (signature with identity constraint) | `hf://org/name@<sha>#/siblings/3/rfilename`, `file:///models/x/model-00001-of-00004.safetensors` | API unreachable → `model-gateway: unreachable` |
| C8 | `hosted-models` | Framework/provider configs (OpenAI/Anthropic/Bedrock/Vertex model strings), optional live probe (`--probe` sends a minimal request and records `response.model`/`system_fingerprint`-like fields as provider evidence) | Model(hosted) with `requestedAlias`, `resolvedSnapshot` (state `unknown` if provider does not disclose), `aliasPinned` heuristic (date-suffixed or digest-like ids = pinned), fingerprint claim (`--fingerprint`) | declared / observed | `agent.py:42 model="claude-sonnet-4-5"` | — |
| C9 | `framework-config` | LangGraph (`langgraph.json`, graph definitions), CrewAI (`agents.yaml`, `tasks.yaml`), OpenAI Agents SDK, Claude Agent SDK options, AutoGen team configs, Semantic Kernel plugin manifests | Agent, sub-agents, `spawns`/`delegatesTo` edges, tool bindings, model refs, memory configuration | declared | `langgraph.json#/graphs/main`, `agents.yaml#/triager/tools/2` | unknown framework → `code: not-attempted` |
| C10 | `sbom-merge` | cdxgen/syft CycloneDX 1.5–1.7 | software components + dependencies (software layer), merged under the agent | declared | `sbom.cdx.json#/components/17` | — |
| C11 | `k8s-aibom-import` | k8s-aibom CDX 1.6 ML-BOM documents or `AIBOM` CR (**A-04**: the CR embeds the CycloneDX document; exact status field path to be confirmed in Phase 1) | Deployment (workload identity from `aibom.workload.*`), Models with confidence mapping §2.6, signature facts, redaction records | observed | `aibom.evidence.locator` preserved verbatim | — |
| C12 | `otel-traces` | OTLP/JSON files or JSONL spans (`gen_ai.operation.name ∈ {execute_tool, chat, generate_content, text_completion, embeddings, invoke_agent, create_agent}`; `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.tool.type`, `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.provider.name` or legacy `gen_ai.system`, `gen_ai.agent.id/name`; resource attributes `symbiote.snapshot.digest`, `symbiote.deployment.id` — **A-05**: attribute names per OTel GenAI semconv, currently *Development* stability) | Observed invocations (`invokesTool` with counts, first/last seen), observed models (requested vs resolved), sub-agent spawns, Deployment↔Snapshot binding from the resource attribute, Delta events | observed | `otlp:<file>#/resourceSpans/0/scopeSpans/0/spans/12` | — |
| C13 | `identity-config` | k8s ServiceAccount/Workload Identity annotations, SPIFFE IDs in config, OAuth client registrations, GitHub App manifests, cloud IAM role ARNs referenced by config | Identity, CredentialBinding (kind, lifetime class, storage locator), `actsAs`/`holdsCredential` edges, granted scopes where discoverable (`gh auth status`-style outputs are **not** executed; only files/manifests) | declared | `deployment.yaml#/spec/template/spec/serviceAccountName` | — |

**D-07.** Collectors are pure (no network) unless the surface is inherently live (C2, C5 fetch, C6, C7 API, C8 probe); live collectors are gated behind `--live` and record `window` and `sources` in coverage. Tests run every collector against fixtures, including a fixture MCP server (stdio, built with the `mcp` SDK) that can be started in "drifted" mode to change one description.

---

## 7. Digests, canonicalization, model identity, name resolution, Merkle commitment (R4, R11)

### 7.1 General rule: typed digest envelopes over JCS

`digest = "sha256:" + hex(SHA-256(JCS(E)))` where `E = {"_type": <digest-type URI>, ...payload}` and JCS is RFC 8785 as implemented by `rfc8785` 0.1.4 (V-10: sorts keys by UTF-16 code units, serializes `1.0` as `1`, `1e21` as `1e+21`, raises `FloatDomainError` on NaN/±Inf and `IntegerDomainError` for integers outside ±2^53). The `_type` tag gives domain separation between artifact kinds. Raw file artifacts (instructions, policy files, model shards) use plain `SHA-256(bytes)` so that `sha256sum` and model-signing agree with us.

| Digest type URI | Payload fields (exact) | Encoding notes |
|---|---|---|
| `https://symbiote.dev/digest/tooldef/v1` | `name` (string), `title` (string|absent), `description` (string|absent), `inputSchema` (JSON as served), `outputSchema` (JSON|absent), `annotations` (object as served|absent) | Absent ≠ null ≠ `{}`: keys are omitted when the server omitted them. No whitespace, Unicode or case normalization. No `$ref` resolution. Objects taken from the raw JSON-RPC result, **not** from `mcp.types.Tool` round-tripping (pydantic may drop unknown keys or re-order) |
| `https://symbiote.dev/digest/tooldef-full/v1` | tooldef/v1 fields + `_meta`, `icons`, `execution` | Detects non-model-visible changes (e.g. `execution.taskSupport`) |
| `https://symbiote.dev/digest/toolset/v1` | `server` (server identity digest), `protocolVersion`, `tools`: sorted array of `{name, digest}` by `name` (UTF-16 order) | The allowlist unit; identical sets ⇒ identical digest regardless of list order/pagination |
| `https://symbiote.dev/digest/server/v1` | `kind`, `transport`, `endpointOrigin` (lowercased scheme+host+explicit port; path **included** for streamable-http since different paths are different servers), or `package: {purl, digest}` for stdio; `serverInfo: {name, version}`; `instructionsDigest` | Instructions are model-visible text ⇒ part of server identity |
| `https://symbiote.dev/digest/prompt/v1` | `engine`, `role`, `template` (exact string), `variablesSchema` (JSON|null) | |
| `https://symbiote.dev/digest/jsondoc/v1` | `mediaType`, `body` (parsed JSON) | A2A cards, server.json, OpenAPI docs, policy JSON |
| `https://symbiote.dev/digest/dirmanifest/v1` | `method: "files"`, `hashType: "sha256"`, `allowSymlinks: false`, `ignore: [".git/**", ...]`, `resources: [{name: <POSIX relpath>, algorithm, digest}]` sorted by `name` | Skills, policy bundles, rules directories, local model snapshots. `rootDigest` = `SHA-256(concat(digest bytes in sorted order))` **exactly as OpenSSF model-signing computes its subject digest** (V-11), so Symbiote's directory roots are byte-compatible with OMS v1.0 subjects |
| `https://symbiote.dev/digest/grant/v1`, `/approval/v1`, `/resolution/v1`, `/leaf/v1` | canonical entity body | For Merkle leaves and attestation subjects |

**D-08 (reconciled with ATTACK-01).** The gap register recommends including `title`, `outputSchema`, `icons` and `_meta` in the canonical form. `title` and `outputSchema` are in `tooldef/v1`; `icons` and `_meta` are confined to `tooldef-full/v1` because `_meta` legitimately carries volatile per-session/registry metadata that would produce false drift; a GAB `policy.enforceFullDigest: true` switches enforcement to the full digest for operators who prefer that trade-off. Because Deadbugz-style poisoning is runtime-gated (benign for the first calls, hostile afterwards), digests are re-verified at every session start/reconnect, on every `tools/list` response, on every `notifications/tools/list_changed`, and in GAB mode against a per-session cache on every `tools/call`; approval-time hashing alone is explicitly insufficient.

**Instruction digest:** `sha256(bytes)` of the file exactly as stored (CRLF preserved; BOM preserved). Recorded alongside: `size`, `lineEndings`, `encodingDeclared`, and an optional `normalizedDigest` (`sha256(NFC(UTF-8 decode, LF-normalized, trailing-whitespace-stripped))`) used **only** for drift triage ("cosmetic" vs "semantic" change), never for allowlisting.

### 7.2 Adversarial robustness of digests (what each rule defends against)

| Pitfall | Attack it enables if mishandled | Symbiote rule |
|---|---|---|
| Unicode normalization (NFC/NFD), homoglyphs, zero-width/bidi/tag characters (U+200B–U+200F, U+202A–U+202E, U+2066–U+2069, U+E0000–U+E007F, Cf/Co/Cn) | A description visually identical to the approved one but carrying hidden instructions; or a benign-looking replacement that "looks the same" to a reviewer | No normalization in the digest (any byte change is a change). Separately, `textFlags.hidden-unicode` fires on any model-visible string containing those classes ⇒ `SYM-TOOL-006` (high). Diff output shows escaped code points |
| JSON number forms (`1` vs `1.0` vs `1e0`, `-0`, big ints, NaN) | Two schemas semantically equal but digest-different (false drift) or a digest that one implementation can compute and another cannot (desync between gateway and BOM) | JCS normalizes doubles; ints beyond ±2^53 or non-finite ⇒ **undigestable** (fail closed, `SYM-TOOL-004` critical). JSON Schema `maximum: 9223372036854775807` therefore makes a tool unpinnable until the server fixes it — intentionally |
| Key ordering / duplicate keys | Reordered JSON evading naive string comparison; duplicate keys parsed differently by different parsers (last-wins vs first-wins) | JCS fixes order; duplicate keys in the raw JSON-RPC text ⇒ reject as undigestable (`json.loads` hook `object_pairs_hook` detects duplicates) |
| `$ref` / `$defs` / remote refs in `inputSchema` | Moving semantics behind a remote `$ref` lets the model-visible schema change without any digest change | Never expand. `textFlags.external-ref` on any `$ref` not starting with `#` ⇒ `SYM-TOOL-005` (high); gateways should strip or refuse remote refs |
| Description whitespace / trailing newline / CRLF | Reviewer approves "same text", attacker relies on tooling that trims | Exact bytes in the digest; triage digest separately (above) |
| Absent vs explicit default annotations (`destructiveHint` default true) | Server removes `readOnlyHint: true` ⇒ tool becomes destructive by default without "changing" anything semantically visible | Absence is encoded as absence (digest changes); policy evaluates MCP defaults for absent hints and `SYM-TOOL-007` flags tools with no annotations |
| Pagination / order of `tools/list` | Reordering or splitting pages to evade set comparison | `toolset/v1` sorts by name; all pages fetched until `nextCursor` absent; truncation recorded |
| Same tool name on two servers (shadowing) | Rug-pull via a second server publishing `get_issue` with a poisoned description | Tool ids include the server id; `SYM-TOOL-008` flags cross-server name collisions with different digests |
| Pydantic/SDK re-serialization | SDK drops unknown fields or reorders ⇒ gateway (which sees raw JSON) and BOM disagree | Digest the raw JSON-RPC `result.tools[i]` object; `mcp.types` used only for typing |
| Schema `$ref` to `#/definitions` moved to `#/$defs` | Semantically identical, digest differs | Accepted as drift (false positive preferred); triage shows "schema-restructure" category |

### 7.3 Model identity manifest and serialization risk

- **Manifest** = model-signing `Manifest` from `hashing.Config().use_file_serialization(hashing_algorithm="sha256", allow_symlinks=False)` (shards via `use_shard_serialization(shard_size=1_000_000_000)` for files > 1 GiB when `--shards`); `rootDigest` as in §7.1; recorded `serialization = {method, hash_type, allow_symlinks, shard_size?}` so a verifier can re-hash identically. The in-toto subject `{name: <model dir name>, digest: {sha256: root}}` and predicate `https://model_signing/signature/v1.0` are produced by model-signing itself when Symbiote signs a model (`symbiote model sign` delegates to `model_signing.signing.Config().use_sigstore_signer()|use_elliptic_key_signer()`); verification uses `model_signing.verifying.Config().use_sigstore_verifier(identity=, oidc_issuer=)` — identity **required** (I3).
- **Per-tensor manifest (D-09, ATTACK-05).** For safetensors files Symbiote parses the 8-byte little-endian header length and the JSON header (`{tensor: {dtype, shape, data_offsets}}`) and computes `sha256` per tensor byte range, producing `https://symbiote.dev/digest/tensormanifest/v1 = {file, tensors: [{name, dtype, shape, digest}]}` and its RFC 6962 root. This localises a poisoned LoRA layer or a single swapped tensor behind an unchanged file name and corroborates adapter/merge lineage with no external tooling (`symbiote model manifest --tensors`). GGUF per-tensor digests use the GGUF v3 tensor-info table (**A-11**: parser to be validated against the reference implementation).
- **Serialization risk class** (per file, aggregated per model): `safetensors|onnx|gguf|npz-without-pickle → none`; `tf-savedmodel|keras-h5 → low` (graph ops); `pickle|torch-zip (pytorch .bin/.pt/.pth)|joblib|dill|numpy .npy allow_pickle → code-exec-on-load`; `config.json auto_map` or `trust_remote_code=True` in loading config ⇒ `code-exec-on-load`; `tokenizer_config.json chat_template` present ⇒ `chatTemplateExecutable=true` (Jinja); SentencePiece/custom tokenizer code ⇒ flagged. Optional scanner integration (`picklescan`/`modelscan` as `[models]` extras) attaches a `scan-report` Evidence by digest.
- **Derivation edges** with parameters: `fineTuneOf{method: sft|dpo|rlhf|lora-merged, dataRefs[]}`, `adapterOf{adapterType: lora|qlora|ia3, rank, targetModules[]}`, `quantizationOf{method: gptq|awq|fp8|int8|gguf-qN, bits}`, `mergeOf{method: slerp|ties|dare|linear, parents[], weights[]}`, `distillationOf{teacherRef}`, `conversionOf{from, to}` — assurance per edge (`declared` from model card, `observed` from file inspection e.g. `adapter_config.json`).
- **Hosted models.** Identity = `(provider, endpointOrigin, requestedAlias, resolvedSnapshot)`. `resolvedSnapshot` comes from a provider response field when disclosed; otherwise `state=unknown` with an optional `BehavioralFingerprint{suiteDigest, n, responseDigest, temperature: 0, sampledAt, expires}` (**A-06**: fingerprints are heuristics; assurance never exceeds `observed`; a changed fingerprint at re-probe is a `model-routed` delta event).

### 7.4 Policy bundle digest

`dirmanifest/v1` over the enforced policy directory (Rego files, gateway config, approval-gate rules). The Grant's `policyRef` and the Snapshot's `policyBundle` cite this root; a gateway includes its loaded bundle root in GAB verification output so drift between "approved policy" and "running policy" is itself a delta.

### 7.5 Name-resolution record (requested → resolved → signer → inclusion)

```json
{"_type":"https://symbiote.dev/digest/resolution/v1",
 "requested":{"kind":"mcp-registry|npm|pypi|oci|huggingface|a2a-card|url|hosted-alias","ref":"io.github.github/github-mcp-server@latest"},
 "resolvedAt":"2026-11-01T10:12:03Z","resolver":{"name":"symbiote","version":"0.1.0","digest":"sha256:..."},
 "resolved":{"immutableRef":"pkg:npm/%40github/mcp-server@0.9.1?checksum=sha256:ab12...","digest":"sha256:ab12...","declaredDigest":"<packages[].fileSha256 or null>","state":"present|unknown"},
 "registry":{"url":"https://registry.modelcontextprotocol.io","entryId":"io.github.github/github-mcp-server","version":"0.9.1","status":"active|deprecated|deleted|unknown","publishedAt":"...","updatedAt":"...","isLatest":true,"schema":"2025-12-11"},
 "publisher":{"namespace":"io.github.github","identity":"github.com/github","verification":"github-oidc|dns|http|none|unknown"},
 "signer":{"status":"unsigned|claimed|verified","outcome":"verified|signature-valid-unconstrained|identity-mismatch|digest-mismatch|subject-name-mismatch|failed|error","identity":"https://github.com/github/github-mcp-server/.github/workflows/release.yml@refs/tags/v0.9.1","issuer":"https://token.actions.githubusercontent.com","bundleDigest":"sha256:..."},
 "transparencyLog":{"type":"rekor","logId":"...","logIndex":123456789,"integratedTime":"...","inclusionProofVerified":true},
 "aliasPolicy":"pinned|floating","typosquatDistance":{"nearest":"io.github.github/github-mcp-sever","levenshtein":1},
 "warnings":["registry-status-deprecated"]}
```
The MCP registry has no signature/attestation fields (V-13), so `signer` is populated from package-ecosystem attestations (npm provenance / PyPI attestations / Sigstore bundles for OCI) when present, otherwise `unsigned`. The record is the subject of the `registry-resolution/v1` attestation.

### 7.6 Merkle commitment and verifiable redaction

- Leaves and tree per §2.5. The companion carries `merkle.leaves[] = {kind, id, salt, leafHash}` for disclosed leaves and `{kind, leafHash}` for redacted ones (never bodies or salts of redacted leaves) and `merkle.root`.
- `symbiote redact --class <c>` replaces entity bodies with `{"redacted": true, "class": c, "leafHash": "..."}`, appends `RedactionRecord{class, count, appliedBy, at}` and `symbiote:redaction:applied` properties. `symbiote merkle verify` recomputes the root from (unredacted bodies ∪ redacted leaf hashes) and compares with the signed root; `symbiote merkle prove --id tool:x` emits an inclusion proof so a partner can verify one tool definition against the signed root without seeing the rest.
- Redaction classes: `credential-shaped-token`, `endpoint-internal-host`, `tool-text`, `prompt-text`, `identity-ref`, `grant-detail`, `data-source-detail`, `custom:<name>`.

---

## 8. Policy and conformance (R5 computed flags, R10)

### 8.1 Built-in checks

Severity ∈ {critical, high, medium, low, info}. Each check cites inputs (entity ids, claim assurance) in its finding; a finding over `unknown` inputs is emitted as `state: indeterminate` (never silently passed). Mapping columns: OWASP Agentic Top 10 (Dec 2025; ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents — **A-07**: ASI03/05/07/08 titles from secondary sources), MITRE ATLAS technique ids (V-14).

| ID | Severity | Inputs | Logic (fires when) | Maps to |
|---|---|---|---|---|
| SYM-TOOL-001 unpinned tool | high | ToolDefinition.digest | digest absent or `status=undigestable`, or tool present only in `declared` with no served digest | ASI04; AML.T0109, AML.T0110 |
| SYM-TOOL-002 served ≠ approved | critical | approved toolset digest vs observed | any tool digest in observed set ∉ approved set, or approved tool missing | ASI04; AML.T0109 |
| SYM-TOOL-003 destructive + open-world without gate | high | annotations/sideEffects, Grant.approvalGate | (`destructiveHint≠false` ∨ sideEffects.destructive) ∧ (`openWorldHint≠false`) ∧ no grant with `approvalGate≠none` | ASI02; AML.T0101, AML.T0086 |
| SYM-TOOL-004 non-canonicalizable definition | critical | digest.status | `undigestable` | ASI04 |
| SYM-TOOL-005 external `$ref` | high | inputSchema/outputSchema | any `$ref` not fragment-local | ASI04; AML.T0110 |
| SYM-TOOL-006 hidden Unicode in model-visible text | high | name/title/description/schema descriptions | Cf/Co/Cn or bidi/tag code points present | ASI01; AML.T0051 |
| SYM-TOOL-007 annotations absent | medium | annotations | no `annotations` object or all hints absent | ASI02 |
| SYM-TOOL-008 tool-name shadowing | medium | all ToolDefinitions | same `name` on ≥2 servers with different digests | ASI04; AML.T0110 |
| SYM-TOOL-009 cross-tool directive (heuristic) | info | description | patterns like "before using <other tool>", "ignore previous", "do not tell the user" | ASI01; AML.T0051 |
| SYM-MCP-001 unauthenticated across boundary | high | authentication, crossesTrustBoundary | `mode=none` ∧ boundary crossed ∧ any grant capability ∈ {write, execute, credentials, payment} | ASI03 |
| SYM-MCP-002 floating package | high | package.floating | launcher without pinned version/digest (`npx -y pkg`, `pkg@latest`, `uvx pkg`) | ASI04; AML.T0010.005 |
| SYM-MCP-003 insecure transport | medium | endpoint | scheme ≠ https for remote | ASI07 |
| SYM-MCP-004 registry status | high/medium | RegistryResolution.status | `deleted` (high), `deprecated` (medium), `unknown` (indeterminate) | ASI04 |
| SYM-MCP-005 name/package mismatch or typosquat | high | resolution.typosquatDistance, publisher | distance ≤ 2 to a more popular name, or registry package identity ≠ configured package | ASI04; AML.T0060, AML.T0111 |
| SYM-MCP-006 mixed-trust session composition | high | server trust tiers, tool capabilities, isolation controls | a trust-tier ≥ 2 server co-loaded with a destructive or credential-bearing tool from another server, with no declared isolation control (context partitioning, description sanitisation) | ASI01, ASI04; AML.T0110, AML.T0051.001 |
| SYM-AUTHZ-001 lethal trifecta / Rule-of-Two | critical | edges readsContextFrom(trustTier ≥ 3 or unknown-as-untrusted), grants (read on confidential/PII/credentials), grants (network-egress/communicate/payment/write-external or open-world non-read-only tools), approvalGate | A ∧ B ∧ C without `approvalGate=required` on every C-leg grant; Rule-of-Two variant: count{A,B,C} > 2 without human gate | ASI01, ASI02; AML.T0086, AML.T0051 |
| SYM-AUTHZ-002 least-privilege gap | high | granted scopes vs required scopes | `granted − required ≠ ∅` (over-privilege) or `required − granted ≠ ∅` (misconfiguration, medium) | ASI03 |
| SYM-AUTHZ-003 long-lived credential for destructive capability | high | CredentialBinding.kind, capability | `static-long-lived` ∧ capability ∈ {write, execute, payment, credentials} | ASI03; AML.T0098, AML.T0083 |
| SYM-AUTHZ-004 unauthenticated write | high | auth, capability | `unauthenticated` binding ∧ non-read capability | ASI03 |
| SYM-AUTHZ-005 unconstrained delegation | high | delegationChain | hop without `constraints`/`expires`/`scopes` | ASI07, ASI03 |
| SYM-AUTHZ-006 no enforcement point | high | Grant.enforcementPoint | `kind=none` for any non-read grant | ASI10 |
| SYM-AUTHZ-007 observed egress outside allowlist | high | observed destinations (OTel `server.address`/`url.full`, gateway logs) vs `Grant.scope.egress` / `sideEffects.egressDestinations` | any observed destination ∉ declared allowlist | ASI02; AML.T0086, AML.T0025 |
| SYM-MODEL-001 floating model alias | medium | Model.aliasPinned | hosted model with `aliasPinned=false` or `resolvedSnapshot unknown` and no fingerprint | ASI04; AML.T0010.003 |
| SYM-MODEL-002 unsafe serialization | critical | serialization.riskClass | `code-exec-on-load` ∨ `trustRemoteCode=true`; `chatTemplateExecutable` → medium | ASI05; AML.T0010.003, AML.T0058 |
| SYM-MODEL-003 model not verified | high | signature.status | status ≠ `verified` (outcome shown; `signature-valid-unconstrained` reported explicitly) | ASI04; AML.T0058 |
| SYM-MODEL-004 unknown parent in derivation | medium | derivation | any parentRef with `state=unknown` | AML.T0018 |
| SYM-INSTR-001 instruction editable by untrusted principal | high | Instruction.editors, trustTier | editor is an agent with untrusted inputs, or `editors` unknown for system prompt | ASI06; AML.T0081 |
| SYM-INSTR-002 instruction loads remote content | high | loadsRemote | any non-empty | ASI01; AML.T0051 |
| SYM-DATA-001 untrusted input feeding privileged agent | high | readsContextFrom.trustTier, grants | trustTier ≥ 3 ∧ any write/egress grant (also feeds AUTHZ-001) | ASI01, ASI06; AML.T0070, AML.T0071 |
| SYM-MEM-001 memory writers unknown | high | writesMemoryTo, writers | memory store with `writers` state unknown | ASI06; AML.T0080.000 |
| SYM-MEM-002 untrusted memory writer | critical | writers | a writer whose inputs are untrusted (tier ≥ 3) without quarantine | ASI06; AML.T0080 |
| SYM-SNAP-001 serial regression | critical | serial, last-seen | serial ≤ last-seen | — (anti-rollback) |
| SYM-SNAP-002 snapshot expired/stale | high | validity, observationWindow | `now ≥ notAfter` or staleness > policy | — |
| SYM-SNAP-003 chain gap | medium | prev | prev ≠ last-seen digest | — |
| SYM-COV-001 surface not covered | high (blocks `verified` conformance) | coverage | any required surface `≠ queried` | — |
| SYM-TRUST-001 revoked/quarantined component in use | critical | TrustStatus | current snapshot contains subject with `revoked` (critical) / `quarantined` (high) | ASI04 |
| SYM-TRUST-002 revoked publisher | critical | TrustStatus(publisher), resolutions | any component resolved from a revoked publisher identity | ASI04 |
| SYM-ATT-001 unconstrained signer | medium | signature facts | outcome `signature-valid-unconstrained` anywhere (fact surfaced so no one reads it as verified) | — |
| SYM-ATT-002 evidence expired | medium | Evidence.expires | expired evidence still cited | — |
| SYM-EVAL-001 stale evaluation | high | Evaluation.subjectConfig vs current digests | any cited digest differs from the deployed configuration | ASI01 |
| SYM-A2A-001 unpinned agent card | medium | A2A card digest/signature | card fetched without digest pin or signature | ASI07 |
| SYM-SUB-001 undeclared sub-agent | high | observed spawns vs declared | observed `spawns` edge ∉ declared | ASI10, ASI08 |
| SYM-REG-001 resolution without log inclusion | low | transparencyLog | signer present but no inclusion proof | ASI04 |

### 8.2 OPA/Rego export

`symbiote policy export-rego` writes `policy/rego/symbiote/*.rego` with `package symbiote.agentbom` and one rule per check over `input` = the companion document (PID), e.g.:

```rego
deny contains msg if {
  some t in input.tools
  t.digest.status != "ok"
  msg := sprintf("SYM-TOOL-004 %s undigestable: %s", [t.id, t.digest.reason])
}
lethal_trifecta if { untrusted_input; private_data_read; external_effect; not every_external_effect_gated }
```
Rego is generated from the same check definitions (a `CheckSpec` dataclass with `rego_body`), so the built-in evaluator and OPA agree; a conformance test runs both over the fixtures and asserts identical finding sets (OPA invoked via subprocess when available; skipped otherwise).

### 8.3 Conformance levels (validated by `symbiote conformance`)

| Level | Requirements (identifiers in `definitions.standards`) |
|---|---|
| **AgentBOM-Minimal** | AB-MIN-01 agent identity (name, version, owner); AB-MIN-02 every model has identity or explicit `unknown`; AB-MIN-03 every tool server listed with transport and package/endpoint; AB-MIN-04 every tool has a digest or `undigestable` reason; AB-MIN-05 every instruction file digested; AB-MIN-06 coverage statement present; AB-MIN-07 validates against official CDX 1.7 (and SPDX 3.0.1 when exported) |
| **AgentBOM-Standard** | all Minimal + AB-STD-01 companion document linked by digest; AB-STD-02 at least one Grant per tool/server (declared layer) with capability, scope, enforcement point; AB-STD-03 identities and credential bindings for every grant; AB-STD-04 registry resolution record for every registry-sourced component; AB-STD-05 snapshot serial + prev + validity; AB-STD-06 computed flags present (`true|false|unknown`); AB-STD-07 loss report attached; AB-STD-08 data sources have trust tier and writers for memory stores; AB-STD-09 the Rule-of-Two/trifecta analysis is evaluable with no `indeterminate` inputs (trust tier on every input source, capability class on every grant) |
| **AgentBOM-Verified** | all Standard + AB-VER-01 signed `agentbom-snapshot/v1` verified under an identity constraint; AB-VER-02 `tool-definition-set/v1` from live observation within `maxStaleness` (default 24 h) matches approved set or the delta is signed; AB-VER-03 every model `signature.status=verified` or explicit `unknown` with fingerprint claim and expiry; AB-VER-04 trust-status attestation present and unexpired; AB-VER-05 Merkle root present and matches; AB-VER-06 evaluation evidence bound to current config digests for every tool with destructive/open-world capability; AB-VER-07 all required surfaces `queried` |

Results per requirement: `pass | fail | unknown` with reasons; level attained = highest level with no `fail` and no `unknown` on required items.

### 8.4 Completeness/quality score (a BOM-quality number, never a trust score)

0–100 = Σ weights × field presence over surfaces (tools 25, authorization 20, models 15, data/memory 10, identity 10, instructions 10, coverage 5, evidence linkage 5), each with per-field reasons (`missing`, `unknown`, `present-declared`, `present-observed`, `present-verified`). Reported alongside the assurance distribution (`% claims declared/observed/verified`) so nobody reads the score as safety.

---

## 9. Attestation (R8)

### 9.1 Predicate types and payload schemas

All statements are in-toto Statement v1 (`_type: https://in-toto.io/Statement/v1`), built with `sigstore.dsse.StatementBuilder(subjects, predicate_type, predicate).build()` (V-15) and validated against JSON Schemas vendored under `schemas/predicates/`. Subjects are matched by digest only (in-toto rule); `name` is informative. `payloadType` is `application/vnd.in-toto+json`.

| predicateType (exact URI) | subject[] | predicate (exact keys) |
|---|---|---|
| `https://symbiote.dev/attestation/agentbom-snapshot/v1` | `{name: "snapshot:<agent-id>", digest: {sha256: <merkle root>}}`, plus `{name: "companion", digest}` and `{name: "cyclonedx", digest}` when exported | `{agent: {id, name, version}, kind, serial, prev, validity{notBefore, notAfter}, producedAt, producer{name, version, digest}, leafCount, leaves: [{kind, id, leafHash}], coverageDigest, policyBundleDigest, toolsetDigests: {<server-id>: <toolset digest>}, modelIds: [{id, manifestRoot|resolvedSnapshot|unknown}], grantsDigest, redactions: [{class, count}]}` |
| `https://symbiote.dev/attestation/tool-definition-set/v1` | one subject per tool `{name: "tool:<server>/<name>", digest: {sha256}}` + `{name: "toolset:<server>", digest}` | `{server: {id, digest, kind, transport, endpointOrigin?, package?: {purl, digest}, serverInfo, protocolVersion, instructionsDigest}, observedAt, method: "mcp.tools/list" | "declared-config" | "registry", capture: {digest, mediaType}, tools: [{name, digest, fullDigest, annotations?, textFlags[]}], truncated: bool, nextCursorSeen: bool}` |
| `https://symbiote.dev/attestation/coverage/v1` | `{name: "snapshot:<id>", digest}` | `Coverage` object (§2.2) + `{collectors: [{name, version, digest}], window, textIncluded}` |
| `https://symbiote.dev/attestation/evaluation/v1` | subjects = every digest in `subjectConfig` (model manifest roots, prompt digests, toolset digests, policy root) | `Evaluation` object (§2.2) with `results[].denominator` mandatory |
| `https://symbiote.dev/attestation/registry-resolution/v1` | `{name: "resolution:<requested ref>", digest: {sha256: resolution record digest}}` + resolved artifact digest when known | the §7.5 record |
| `https://symbiote.dev/attestation/observed-delta/v1` | `{name: "delta", digest}` + `from`/`to` snapshot digests as subjects | `{fromSnapshot, toSnapshot, producedAt, producer, events: [DeltaEvent]}` |
| `https://symbiote.dev/attestation/trust-status/v1` | `{name: "trust-status:<org>", digest: {sha256: JCS(list)}}` | `{serial, supersedes, issuedAt, expires, decidedBy, entries: [TrustStatus]}` |
| `https://symbiote.dev/attestation/approval/v1` | `{name: "snapshot:<id>", digest: {sha256: approved root}}` | `Approval` object (§2.2) |
| (reused) `https://model_signing/signature/v1.0` | model manifest root | produced/verified by model-signing (V-11) |
| (reused) `https://slsa.dev/provenance/v1`, `https://in-toto.io/attestation/vulns/v0.2` | consumed as Evidence for software components | not produced by Symbiote |

### 9.2 Signing flows

- **Keyless (default in CI):** `SigningContext.from_trust_config(ClientTrustConfig.production()|staging())` → `with ctx.signer(IdentityToken(detect_credential() or Issuer(url).identity_token())) as s: bundle = s.sign_dsse(statement)` → write `<name>.sigstore.json` (Sigstore bundle v0.3, includes the DSSE envelope, certificate and Rekor entry; `bundle.log_entry` present when the log accepted it) (V-15).
- **Key-based (air-gapped / enterprise PKI):** `symbiote.attest.dsse` implements DSSE v1 PAE (`DSSEv1 <len(type)> <type> <len(payload)> <payload>`) and multi-signature envelopes with `keyid = sha256(SPKI DER)`; signers ECDSA P-256 (ES256) and Ed25519 via `cryptography`; verification by keyring. Needed because `sigstore.dsse.Envelope` accepts exactly one signature (V-15) and offers no key-based path.
- **Optional CycloneDX JSF** (`--jsf`): ES256 enveloped signature over the JSON document, `keyId` = same SPKI digest. Documented as "for CycloneDX-native consumers only"; DSSE remains authoritative.
- **Rekor inclusion** is automatic in keyless mode; key-based envelopes may be logged via `sigstore.sign.RekorLogSubmitter`-compatible submission in v0.2 (**A-08**). Consumers with network access may run `symbiote verify --rekor-search` to look for newer `agentbom-snapshot/v1` entries for the same agent id and flag a withheld newer snapshot (split-view detection, ATTACK-13).

### 9.3 Verification flow and identity constraints (Design 002 as code)

`symbiote verify <bundle|envelope> --policy policy.yaml`:
1. Parse bundle (`Bundle.from_json`), verify with `Verifier.production()|staging()|Verifier(trusted_root=TrustedRoot.from_file())` and `verify_dsse(bundle, policy)` where `policy = AllOf([Identity(identity=<regex-anchored SAN>, issuer=<issuer>), ...])` built from `policy.yaml identities[]`; `UnsafeNoOp` is refused unless `--insecure-unconstrained`, and then the result outcome is `signature-valid-unconstrained` and assurance stays `observed` (I3).
2. Parse the returned payload, check `predicateType` against the expected set, validate the predicate schema, check `subject` digests against the artifact being verified (snapshot root, toolset digest, model manifest root).
3. Bindings: for snapshots, recompute the Merkle root from the companion/CDX; for toolsets, recompute `toolset/v1` from live `tools/list` (`--live`) or from the captured evidence; for models, compare the declared manifest root with the signed subject. Digest contradictions always block (`digest-mismatch`); subject-name mismatch is recorded, never load-bearing.
4. Anti-rollback: read `~/.symbiote/trust-state.json` (or `--state-file`) `last-seen[(agent, kind)] = {serial, digest}`; `serial ≤ last-seen` ⇒ `SYM-SNAP-001` and exit 7; `prev ≠ last-seen.digest` ⇒ record `chain-gap`.
5. Trust status: load the latest unexpired `trust-status/v1` (same identity policy); an expired list ⇒ `fail-closed` (exit 4) unless `--trust-status-stale-ok`.
6. Emit `VerificationResult{outcome, identity, issuer, logIndex, integratedTime, bindings[], warnings[]}` as JSON; `verified` only when every step passed.

### 9.4 Where evidence lives in the BOM

Every `Evidence.id` is the SHA-256 of the evidence bytes (bundle, capture, report). CDX cites it via `declarations.evidence[].data[].contents.url` (as `sha256:` URN or URL) and `externalReferences[type=attestation|evidence].hashes`; SPDX via `software_File.verifiedUsing Hash` and `hasEvidence`. The companion `evidence[]` array holds the full records; `--evidence-dir` writes the raw files next to the BOM as `evidence/<sha256>.<ext>`.

---

## 10. Enforcement and incident-response consumers

### 10.1 Gateway Allowlist Bundle (GAB) — `symbiote allowlist export --format gab`

```json
{"gabVersion":"1","agent":{"id":"agent:issue-triager","name":"issue-triager","version":"2.3.1"},
 "snapshot":{"kind":"approved","digest":"sha256:…","serial":42,"prev":"sha256:…","notBefore":"…","notAfter":"…"},
 "lastKnownGood":{"snapshotDigest":"sha256:…","serial":41},
 "policy":{"maxStaleness":"PT24H","failClosedOnExpiredTrustStatus":true,"requireAnnotationsForDestructive":true,"enforceFullDigest":false,"reverifyOn":["session-start","tools/list","list_changed","tools/call"]},
 "servers":{"mcp:io.github.github/github-mcp-server":{
    "identity":{"digest":"sha256:…","transport":"streamable-http","endpointOrigin":"https://api.githubcopilot.com/mcp/","package":null,"instructionsDigest":"sha256:…","signer":{"identity":"…","issuer":"…"}},
    "toolset":"sha256:…",
    "tools":{"get_issue":{"digest":"sha256:…","gate":"none","capabilities":["read"]},
             "create_pull_request":{"digest":"sha256:…","gate":"required","capabilities":["write"]}},
    "deniedTools":["delete_repository"]}},
 "models":{"model:claude-sonnet-4-5":{"provider":"anthropic","alias":"claude-sonnet-4-5","resolvedSnapshot":"claude-sonnet-4-5-20250929","aliasPinned":true}},
 "instructions":{"instr:system-prompt":"sha256:…"},
 "trustStatus":{"serial":7,"expires":"…","revoked":["sha256:…"],"quarantined":[],"revokedPublishers":["io.github.evil"]},
 "attestations":["snapshot.sigstore.json","toolset.sigstore.json","trust-status.sigstore.json"]}
```
Rules the gateway applies: (1) verify all three attestations under its identity policy (library `symbiote.enforce.verify_gab()` provided; also `symbiote verify gab`); (2) at session start/reconnect, on every `tools/list` response and on every `notifications/tools/list_changed`, compute `tooldef/v1` for each served tool from the raw JSON (and check the per-session cached digest on every `tools/call`); drop or block any tool whose digest ∉ `tools[name].digest` (block and alert when a known name has a new digest = **rug-pull signal**, drop silently-with-log when unknown name); (3) refuse the whole server if `serverIdentity` differs (endpoint origin, package digest, instructions digest); (4) at `tools/call` time enforce `gate`; (5) refuse if snapshot expired, serial regressed, or trust status expired/revoked. Formats also exported: `--format envoy-ext-authz-json`, `--format opa-data` (as `data.symbiote.allowlist`), `--format mcp-gateway-generic` (name/digest pairs). Implementing a gateway is a non-goal (brief §5); we ship the verifier library and the formats.

### 10.2 Policy Input Document

The companion document plus `derived.flags[]` and `derived.findings[]` (§8). The PID is what both `symbiote policy check` and exported Rego consume; it is also what CI uploads as an artifact.

### 10.3 Incident Index and the three questions — `symbiote index build --store ./agentbom-store` then `symbiote query …`

The store is a directory of snapshots, deltas, attestations, resolutions, trust-status lists and trace summaries (as written by `symbiote collect/attest/observe --store`). `index build` loads them into SQLite tables `snapshot, entity, edge, grant, credential_binding, identity, deployment, resolution, trust_status, delta_event, trace_summary` with validity columns. Queries are SQL over edges with time predicates; every answer row carries `assurance` and `evidence` columns.

| Question | Command | Traversal |
|---|---|---|
| Q1 credentials usable by a compromised server | `symbiote query who-holds-credential --server mcp:<id> [--at <time>]` | server → `holdsCredential` bindings → identities; all agents/deployments with `holdsCredential`/`actsAs` on the same identity or binding; agents with `delegatesTo`/`invokesTool` edges to that server whose grants bind credentials the server executes under (`obo-token` ⇒ the *user's* identity is exposed; flagged). Output: agents, deployments, identities (refs), grant ids, credential kind/lifetime, assurance |
| Q2 deployments under snapshot X during the poisoned write | `symbiote query ran-under --snapshot sha256:X --between T1 T2 [--memory data:<id>]` | deployments whose `snapshotRefs` validity ∩ [T1,T2) ≠ ∅ and whose snapshot digest = X (or chain-descendant when `--include-descendants`); join `writesMemoryTo` edges and `memory-writer-added` delta events in the window; trace summaries with `symbiote.snapshot.digest = X` |
| Q3 agents still trusting a revoked publisher | `symbiote query trusts-publisher --publisher <identity> [--only-current]` | resolutions with `publisher.identity` = P (or signer identity = P) → components → snapshots (latest approved/deployed per agent) → agents; minus those whose local trust-status marks the component revoked; reports `last-seen deployed` time |

Also: `symbiote query blast-radius --tool tool:<id>` (agents, sub-agents via `delegatesTo`, memory stores via `writesMemoryTo`), `symbiote query drift --agent <id> --since <time>` (delta events).

---

## 11. CLI specification and Python API (R12)

### 11.1 Global conventions

Typer app `symbiote`; every command accepts `--json` (machine output on stdout; human output via rich on stderr when a TTY), `--quiet`, `--store PATH`, `--deterministic`, `--config symbiote.yaml`. Exit codes (stable, documented in `docs/cli/exit-codes.md`): **0** success/no findings ≥ threshold; **1** policy/conformance findings at or above `--fail-on` (default `high`); **2** usage error; **3** schema validation failure (input or output); **4** verification failure (signature, digest binding, identity constraint, expired trust status); **5** coverage insufficient for the requested conformance level (`unknown` blocking); **6** collector/I-O error (unreadable source, network when `--live`); **7** anti-rollback/conflict (serial regression, chain gap under `--strict`); **8** loss report contains dropped security-relevant fields under `--strict`.

### 11.2 Commands

| Command | Purpose | Key flags | JSON output |
|---|---|---|---|
| `symbiote init` | Write `symbiote.yaml` (agent name/version/owner, sources, identities policy) by scanning the cwd | `--from-cwd`, `--framework` | config |
| `symbiote collect [--source NAME…] [--live]` | Run collectors; write a `declared` (and `observed` when live) snapshot into the store | `--include-text`, `--max-tools`, `--timeout` | `CollectionResult` + coverage |
| `symbiote observe mcp --server ID|--all`, `symbiote observe otel FILE…` | Produce `observed` snapshots/deltas from live `tools/list` or traces | `--window`, `--attest` | snapshot + delta |
| `symbiote generate [--kind declared|approved|deployed|observed] -o bom.cdx.json --spdx bom.spdx.json --companion bom.agentbom.json` | Compose exports from the store (or from a one-shot collect) | `--profile minimal|standard|verified|k8s-aibom-compat`, `--merge-kinds`, `--redact CLASS…`, `--jsf`, `--xml` | paths + loss report + model digest |
| `symbiote validate FILE…` | Validate CDX 1.7 / SPDX 3.0.1 / companion / predicate files against official + Symbiote schemas; `--cross` triangulates model digests | `--schema-dir` | per-file results |
| `symbiote import FILE --format cdx|spdx|k8s-aibom|cdxgen|syft|harness-aibom` | Import into the model/store with loss report; assurance tagging per §2.6 | `--as observed|declared` | model digest + loss report |
| `symbiote diff A B` | Diff two snapshots/documents of any kind → `Delta` (events, severity hints) | `--kinds declared,observed`, `--fail-on-change tool-definition-changed,…` | Delta |
| `symbiote digest tooldef FILE|- `, `symbiote digest file PATH`, `symbiote digest dir PATH`, `symbiote digest prompt FILE --engine jinja2 --role system` | Compute digests exactly as the BOM does | `--full` | `{algo, digest, status, reason}` |
| `symbiote model manifest DIR`, `symbiote model sign DIR`, `symbiote model verify DIR --bundle B --identity I --issuer U`, `symbiote model risk DIR` | Model identity, signing via model-signing, serialization risk | `--shards` | manifest / signature facts |
| `symbiote registry resolve REF [--live]`, `symbiote registry watch [--interval]` | Produce a name-resolution record; re-resolve periodically and emit `registry-status-changed` / `publisher-changed` / `approval-expiring` delta events | `--pin` writes the immutable ref back into config | resolution record / deltas |
| `symbiote policy check [--rego DIR] [--fail-on SEV]`, `symbiote policy export-rego DIR`, `symbiote policy explain ID` | Built-in checks, Rego export, check documentation | | findings |
| `symbiote conformance --level minimal|standard|verified` | Per-requirement pass/fail/unknown | | conformance report |
| `symbiote score` | Completeness score with per-field reasons | | score report |
| `symbiote attest snapshot|toolset|coverage|evaluation|resolution|delta|trust-status|approval … --out X.sigstore.json` | Build statement and sign (keyless or `--key`) | `--staging`, `--identity-token`, `--key`, `--rekor/--no-rekor` | statement + bundle path |
| `symbiote verify FILE… --policy policy.yaml [--live] [--state-file]` | §9.3 flow incl. anti-rollback and trust status | `--insecure-unconstrained` | `VerificationResult` |
| `symbiote trust allow|quarantine|revoke SUBJECT --reason R --expires D`, `symbiote trust list`, `symbiote trust publish --sign` | Maintain and sign trust-status lists | | list |
| `symbiote allowlist export --format gab|opa-data|envoy-ext-authz-json|mcp-gateway-generic` | §10.1 | `--snapshot approved` | GAB |
| `symbiote redact --class C… IN -o OUT`, `symbiote merkle verify FILE --root R`, `symbiote merkle prove FILE --id ID` | R11 | | proofs |
| `symbiote index build`, `symbiote query who-holds-credential|ran-under|trusts-publisher|blast-radius|drift …` | §10.3 | `--at`, `--between` | rows |
| `symbiote schema export [companion|predicates|taxonomy]`, `symbiote version` | Introspection | | |

### 11.3 Python API shape

```python
from symbiote import AgentBOM, Snapshot, collect, export, verify, policy, digest
bom: AgentBOM = collect.run(config="symbiote.yaml", live=False)          # declared snapshot in memory
cdx, loss = export.cyclonedx(bom.snapshot, profile="standard")            # dict + LossReport
spdx, loss2 = export.spdx(bom.snapshot, extensions=True)                  # JSON-LD dict + LossReport
companion = export.companion(bom.snapshot)
findings = policy.check(companion, fail_on="high")                        # list[Finding]
d = digest.tooldef(raw_tool_json)                                         # Digest(algo, value, status, reason)
res = verify.bundle("snapshot.sigstore.json", policy=verify.Policy.from_yaml("policy.yaml"), state_file=...)
delta = Snapshot.diff(approved, observed)                                 # Delta
gab = export.allowlist(approved, trust_status=ts, fmt="gab")
```
All public types are re-exported from `symbiote.api`; everything else is private (`symbiote._internal`).

---

## 12. Repository layout, module boundaries, testing, CI/release, docs (R12)

### 12.1 Layout (`uv` workspace, `src` layout, Python ≥ 3.11)

```
symbiote/
  pyproject.toml            # extras: [sign] sigstore,in-toto-attestation,cryptography; [models] model-signing,pyopenssl,picklescan; [mcp] mcp,httpx; [spdx] spdx-python-model; [all]
  src/symbiote/
    api.py                  # public re-exports
    model/                  # WP1: entities.py edges.py enums.py claims.py snapshot.py ids.py (Pydantic v2, frozen)
    digest/                 # WP2: jcs.py tooldef.py prompt.py dirmanifest.py instruction.py merkle.py textflags.py
    models_identity/        # WP3: manifest.py serialization_risk.py derivation.py hosted.py fingerprint.py
    authz/                  # WP4: grants.py flags.py (trifecta, least-privilege) identity.py
    snapshot/               # WP5: builder.py diff.py delta.py serial.py state_file.py
    export/cdx/             # WP6: emitter.py taxonomy.py lifecycles.py declarations.py formulation.py vex.py validate.py xml.py
    export/spdx/            # WP7: emitter.py ext.py (ExtensionBuilder) iris.py validate.py
    export/companion/       # WP8: schema.py emitter.py loss.py links.py
    imp/                    # WP6/7/10: cdx.py spdx.py k8s_aibom.py cdxgen.py harness_aibom.py syft.py
    collect/                # WP9/10: base.py mcp_config.py mcp_live.py instructions.py skills.py a2a.py registry.py hf_model.py hosted_models.py frameworks/*.py sbom_merge.py otel.py identity.py
    attest/                 # WP11: statements.py predicates/*.py dsse.py sigstore_backend.py key_backend.py verify.py policy.py trust_status.py
    policy/                 # WP12: checks/*.py (CheckSpec) engine.py rego_export.py conformance.py score.py
    enforce/                # WP13: gab.py formats.py verify_gab.py
    index/                  # WP13: sqlite_store.py queries.py
    cli/                    # WP14: app.py commands/*.py exit_codes.py render.py
  schemas/                  # companion JSON Schema, predicate schemas, taxonomy.json, spdx symbiote-ext context + SHACL
  taxonomy/symbiote-cdx-taxonomy.md ; docs/divergences.md
  policy/rego/              # generated Rego (checked in; regenerated in CI, diff must be empty)
  tests/ (unit/ property/ golden/ fixtures/ e2e/)  tests/schemas/ (vendored official schemas with LICENSE notes)
  examples/triager-agent/   # realistic agent: 3 MCP servers (one stdio floating, one remote), 2 skills, prompts, HF model dir (tiny safetensors + one pickle), hosted model, RAG index, memory store, sub-agent, A2A card, OTLP trace fixture
  action/ (action.yml composite)  .pre-commit-hooks.yaml  docs/ (mkdocs-material: concepts, cli, taxonomy, predicates, threat-model, adr/)  SECURITY.md  THREAT-MODEL.md
```

### 12.2 Module boundaries (interfaces frozen at the end of WP1/WP2 so other packages can proceed in parallel)

`Collector` protocol (`name, version, surfaces, collect(ctx) -> CollectionResult`); `Exporter` (`export(snapshot, opts) -> (dict, LossReport)`); `Importer` (`load(bytes) -> (Snapshot, LossReport)`); `Check` (`CheckSpec{id, severity, inputs, run(pid) -> [Finding], rego_body}`); `Signer`/`Verifier` protocols; `Store` (`put/get/list` over typed records); `DigestFn` (`(obj) -> Digest`). No package imports from `cli/`; `export/*` and `collect/*` depend only on `model/`, `digest/`, `authz/`; `attest/` depends on `model/` + `digest/`; `enforce/` depends on `attest/` + `export/companion`.

### 12.3 Testing strategy (offline; no network)

- **Unit** per module; **golden files** for CDX/SPDX/companion of `examples/triager-agent` (byte-identical under `--deterministic`; updated only via `make golden` with reviewed diff).
- **Official-schema validation** on every golden and every property-generated document: CDX 1.7 (jsonschema Draft 7 + `cyclonedx-python-lib` strict validator), SPDX 3.0.1 JSON schema (draft 2020-12), companion/predicate schemas.
- **Hypothesis properties:** JCS invariance under key reordering and number re-spelling; `digest(x) ≠ digest(y)` for any single code-point change in model-visible text; big-int/NaN ⇒ `undigestable`; Merkle root stability under leaf permutation + proof verification; redaction preserves root; diff algebra (`diff(a,a)=∅`, `apply(a, diff(a,b)) ≡ b`); serial monotonicity; loss-report completeness (every model field appears either in the export or in `LossReport`).
- **Fixture MCP server** (stdio, `mcp` SDK) with `--drift description|schema|annotations|order|pagination|unicode` modes; **OTLP fixtures**; **k8s-aibom** sample BOM; **cdxgen** AI-BOM sample; **registry** `servers.json` samples (active/deprecated/deleted); **HF snapshot** fixture with safetensors + pickle + chat template.
- **Signing tests:** key-based DSSE end-to-end offline; keyless path exercised against fixture Sigstore bundles (verification only) and a nightly staging e2e behind `SYMBIOTE_E2E_SIGSTORE=staging` (as k8s-aibom does in CI).
- **Design 002 outcome table** reproduced as a parametrized test (every row ⇒ expected status/outcome).
- **Cross-engine policy test:** built-in findings == OPA findings over fixtures (skipped if `opa` absent).

### 12.4 CI and release

GitHub Actions: `ruff` (lint+format), `mypy --strict` on `src/`, `pyright` basic, `pytest -q` with coverage gate 85 %, schema validation job, Rego regeneration diff job, `symbiote` self-BOM job (the repo's own agent-less BOM + SLSA provenance), docs build. Release: tag → build sdist/wheel with `uv build` → PyPI trusted publishing (OIDC) → SLSA L3 provenance via `slsa-framework/slsa-github-generator` → Sigstore-signed artifacts (`sigstore-python` `sign` action) → GitHub release with `SBOM` (cdxgen) and `AgentBOM` of the example. Versioning: SemVer; the property taxonomy, companion schema and predicate URIs each carry their own version and a changelog section; divergence register updated in the same PR as any emitted field change (k8s-aibom convention).

### 12.5 Docs (mkdocs-material)

`index` (thesis, four planes), `quickstart`, `concepts/` (assurance, snapshots, digests, grants, coverage), `formats/` (CDX mapping, SPDX mapping, companion, loss model), `taxonomy/`, `predicates/`, `policy/` (checks, Rego, conformance), `enforcement/` (GAB, gateway integration guide, incident queries), `collectors/`, `cli/`, `threat-model` (§13), `adr/` (ADR-001 stack; ADR-002 namespace `symbiote:`; ADR-003 direct CDX JSON emission; ADR-004 typed digest envelopes & fail-closed; ADR-005 Design-002 identity rule; ADR-006 companion document; ADR-007 SPDX custom extensions; ADR-008 anti-rollback state file; ADR-009 OMS-compatible directory roots), `divergences` register, `SECURITY.md` (reporting, supported versions, what the BOM never contains).

---

## 13. Threat model per feature

| Feature | Detects / prevents | How an attacker evades it | Residual risk & compensating control |
|---|---|---|---|
| Tool-definition pinning (`tooldef/v1`) + GAB enforcement | Rug-pull / tool poisoning after approval (AML.T0109/T0110): any change to model-visible name, description, schema, annotations is blocked or alerted at `tools/list` | Time-gated poisoning (Deadbugz: benign for the first calls, hostile later) defeats approval-time-only hashing — closed by per-session, per-`tools/list`, `list_changed` and per-call re-verification; change backend behaviour while keeping the interface identical; move semantics behind a remote `$ref` (flagged by SYM-TOOL-005); exploit a gateway that digests SDK-normalized JSON rather than raw JSON (we document raw-JSON digesting and ship a reference implementation) | Interface-identical backend compromise is invisible to any schema hash — enforcement of effects belongs to grants/enforcement points/network policy; observed side-effect profile from traces narrows the gap |
| Server identity binding (endpoint origin / package digest / instructions digest / signer) | Server substitution, instructions-field injection, dependency confusion on stdio launchers | DNS/registry takeover of the same origin; a mirror serving the same package digest but poisoned at runtime (needs identical digest ⇒ not possible for the package itself) | Origin takeover is outside the BOM; TLS identity and signer identity constraints mitigate; floating launchers are flagged (SYM-MCP-002) |
| Declared vs approved vs deployed vs observed diff | Shadow tools, undeclared sub-agents, model rerouting, memory writer additions (ASI10, ASI04) | Act only between observation windows; suppress telemetry; present a clean `tools/list` to the collector but a different one to the agent (split view) | Observed snapshots carry window/staleness; GAB enforcement at the agent's own gateway removes the split-view gap; coverage states when runtime surface was not observed |
| Rule-of-Two / lethal-trifecta flag | Architecture-level exfiltration paths (AML.T0086) before deployment | Mislabel an input source as trusted; declare a destructive tool read-only (declared annotations) | Trust tiers and annotations are assurance-tagged; `observed` side effects override `declared` when they conflict; absent annotations default to worst case; check reports `indeterminate` on unknown inputs rather than passing |
| Least-privilege gap | Over-scoped tokens, service accounts with broad roles (ASI03) | Hide required scopes (undocumented); grants split across identities | `required` is itself a Claim with assurance; IdP-sourced `effective` grants (future collector) tighten it; Q1 query shows identity fan-out |
| Floating/unpinned dependency flags | Silent model swaps behind aliases, `npx -y pkg@latest` servers (AML.T0010.003/.005) | Provider-side swap with the same snapshot id (provider misbehaviour) | Behavioural fingerprint claim with expiry gives a weak detection; provider evidence/attestations when they exist |
| Unsafe serialization & trust_remote_code | Code execution on load (ASI05, AML.T0010.003) | Polyglot files, safetensors with malicious metadata parsed by a vulnerable loader, Jinja chat-template injection | Scanner evidence (picklescan/modelscan) by digest; chat template flagged executable; residual: loader CVEs out of scope |
| Signature verification with identity constraints (I3) | Forged or self-signed "verified" claims; name-only bindings (Design 002 §3 attack) | Compromise the trusted signer's OIDC identity or CI workflow; Rekor unavailability to force fail-open | Identity constraints are operator-owned; fail-closed on verification errors in gateway mode; `signature-valid-unconstrained` can never be read as verified |
| Registry name-resolution record | Typosquatting/slopsquatting (AML.T0060), deleted/deprecated entries, re-registered namespaces, ownership transfer | Publish under a legitimately-owned similar namespace; compromise the publisher's account (then signer identity is genuine) | Trust-status revocation of publisher identity propagates (Q3); typosquat distance is heuristic; registry has no attestation fields (V-13) so signer facts come from package ecosystems |
| Revocation (`trust-status/v1`) and anti-rollback | Replaying an old approved snapshot/allowlist after revocation; serving a stale revocation list | Block distribution of the new list (DoS) to keep a gateway on the old state; roll back the gateway's state file | Lists expire ⇒ fail closed; state file integrity is the gateway's responsibility (documented; recommend signed/immutable storage, k8s-aibom-style sole-writer) |
| Merkle redaction | Attack-map leakage from full BOMs while keeping verifiability (R11) | Infer redacted content from leaf count/kinds; correlate leaf hashes across documents | Every leaf carries its own random salt, disclosed only with the leaf body, so redacted leaves cannot be dictionary-guessed from the root; redaction classes documented |
| Coverage & unknown-vs-absent | "No shadow tools found" claims made without having looked | None needed — the design refuses to assert absence without coverage | Human readers may still over-trust; conformance `verified` level requires all surfaces queried |
| OTel observed layer | Undeclared invocations, routing, spawns (ASI10) | Disable/alter instrumentation; forge spans | Spans are `observed` evidence, never `verified`; snapshot-digest resource attribute ties traces to a signed snapshot; forged traces can only add noise, not upgrade assurance |
| Memory-writer tracking | Memory/context poisoning blast radius (ASI06, AML.T0080) | Write memory through a channel not modelled (e.g. a shared DB used by another system) | Coverage lists data surfaces examined; Q2 answers only within modelled writers |
| Evaluation binding to config digests | Stale "passed red-team" claims applied after model/prompt/tool changes | Re-run evaluation on a benign config then swap | Subjects are digests; SYM-EVAL-001 invalidates on any digest change; third-party assessor flag |
| Determinism & content-addressed serialNumber | Tampered re-exports; duplicate serials | Change timestamps to force new ids | `--deterministic` pins timestamp to snapshot time; UUIDv5 of root; cross-format model digest triangulation |

---

## 14. Work breakdown (16 parallelizable packages) and integration order

Each WP: scope, files, interfaces it depends on, tests, acceptance criteria. All WPs build against the frozen `model/` and `digest/` interfaces published at the end of **Milestone M0** (WP1 + WP2 API freeze, day 3; stub implementations acceptable).

| WP | Title | Scope & files | Depends on | Tests & acceptance criteria |
|---|---|---|---|---|
| **WP1** | Core semantic model & identity rules | `model/*` (entities, edges, enums, Claim envelope, Snapshot/Delta, ids incl. UUIDv5 constant), `schemas/companion` generation hook | — | Pydantic models for all §2 entities; `extra=forbid`; JSON Schema emitted deterministically; 100 % of enums covered by tests; `model_digest()` stable across key order |
| **WP2** | Canonicalization & digest engine | `digest/jcs.py` (rfc8785 wrapper + duplicate-key detection), `tooldef.py`, `toolset`, `server`, `prompt.py`, `jsondoc`, `dirmanifest.py` (OMS-compatible root), `instruction.py`, `textflags.py`, `merkle.py` | WP1 types | Property tests §12.3; digests match `sha256sum`/model-signing for files/dirs; §7.2 pitfalls each have a regression test; `undigestable` on NaN/big-int/duplicate keys; Merkle proofs verify; redaction preserves root |
| **WP3** | Model identity & serialization risk | `models_identity/*`: model-signing manifest wrapper, serialization risk classifier (magic bytes + config), derivation edges, hosted-model resolution + fingerprint, `pkg:huggingface` purl builder | WP1, WP2 | Fixture HF dir ⇒ manifest root equals model-signing CLI output; pickle fixture ⇒ `code-exec-on-load`; chat template ⇒ executable flag; hosted alias heuristics table-tested |
| **WP4** | Authorization model & computed flags | `authz/grants.py`, `identity.py`, `flags.py` (trifecta, Rule-of-Two, least-privilege, destructive+open-world, unpinned, floating alias, unsigned, unsafe serialization) with cited inputs | WP1 | Truth-table tests incl. `indeterminate` on unknown inputs; flags reproducible from PID alone |
| **WP5** | Snapshot builder, diff & delta, anti-rollback state | `snapshot/*` | WP1, WP2 | Diff algebra properties; delta event taxonomy complete; serial/prev chain tests; state-file regression ⇒ exit 7 path |
| **WP6** | CycloneDX 1.7 exporter/importer + taxonomy + divergence register | `export/cdx/*`, `imp/cdx.py`, `taxonomy/`, `docs/divergences.md` | WP1, WP2, WP4, WP5 | Golden CDX validates against official schema + lib strict validator; every property in taxonomy doc; import(export(M)) model-digest equality with companion; XML best-effort with loss report |
| **WP7** | SPDX 3.0.1 exporter/importer + Symbiote extension vocabulary | `export/spdx/*`, `imp/spdx.py`, `schemas/spdx/*` (context + SHACL) | WP1, WP2, WP4, WP5 | Golden JSON-LD validates against official 3.0.1 JSON schema; round-trip through `JSONLDDeserializer`; `NoAssertionElement`/`NoneElement` idiom tests; 3.1 forward mapping documented |
| **WP8** | Companion document, loss model, cross-format linkage | `export/companion/*`, `LossReport`, BOM-Link/digest linkage, `validate --cross` | WP1, WP5 | Schema validates goldens; loss-report completeness property; triangulation detects a tampered CDX |
| **WP9** | Static collectors | `collect/mcp_config.py`, `instructions.py`, `skills.py`, `a2a.py`, `registry.py` (fixture mode), `hosted_models.py`, `frameworks/*`, `sbom_merge.py`, `identity.py` | WP1, WP2, WP3 | Each collector has fixtures for every supported file format; locators exact; secrets never emitted (negative tests with planted tokens); coverage statuses on unreadable inputs |
| **WP10** | Live/observed collectors & observed importers | `collect/mcp_live.py` (stdio + streamable-http, pagination, raw-JSON digesting), `collect/otel.py`, `imp/k8s_aibom.py`, `imp/cdxgen.py`, `imp/harness_aibom.py`, fixture MCP server with drift modes | WP1, WP2, WP5 | Drift modes each produce the expected delta event; k8s-aibom confidence mapping table-tested incl. `verified` downgrade without constraint; OTel attribute aliases (`gen_ai.system`/`gen_ai.provider.name`) |
| **WP11** | Attestation: predicates, DSSE, Sigstore, verification, trust status | `attest/*`, `schemas/predicates/*` | WP1, WP2, WP5 | Predicate schemas validate goldens; key-based DSSE e2e offline; Design 002 outcome table parametrized; `UnsafeNoOp` refused by default; trust-status expiry fail-closed; staging keyless e2e nightly |
| **WP12** | Policy engine, Rego export, conformance, score | `policy/*`, `policy/rego/` | WP1, WP4, WP8 | Every check has positive/negative/indeterminate fixtures; Rego regeneration is deterministic; OPA parity test; conformance levels on the example reach minimal/standard/verified under the three profiles |
| **WP13** | Enforcement exports & incident index | `enforce/*` (GAB + formats + `verify_gab`), `index/*` (SQLite, queries Q1–Q3, blast-radius, drift) | WP5, WP11, WP8 | GAB golden; reference enforcement test: fixture server drift ⇒ tool blocked; Q1–Q3 return expected rows on the example store incl. assurance columns |
| **WP14** | CLI & Python API | `cli/*`, `api.py`, exit codes, rich rendering, `--json` everywhere | all above (thin layer) | Typer CLI tests (CliRunner) for every command; exit-code matrix; `--deterministic` byte-identical reruns |
| **WP15** | Docs, examples, GitHub Action, pre-commit, CI/release, SECURITY/THREAT-MODEL/ADRs | `docs/`, `examples/triager-agent`, `action/`, `.pre-commit-hooks.yaml`, workflows | WP14 for commands; content from all | mkdocs builds without warnings; example runs end-to-end in CI producing all three documents + attestations (key-based); Action used by the repo itself |
| **WP16** | Test infrastructure & fixtures | `tests/fixtures/*` (fixture MCP server skeleton, OTLP, HF dir, registry samples, k8s-aibom/cdxgen BOMs, agent configs for 7 clients + 6 frameworks), hypothesis strategies, vendored official schemas, golden tooling | WP1 types only | Fixtures load; strategies generate valid models; schema vendoring documented with licenses |

**Integration order.** M0 (day 1–3): WP1 + WP2 interface freeze; WP16 fixtures skeleton. M1: WP3, WP4, WP5, WP8 in parallel against the frozen model. M2: WP6, WP7 (exporters) and WP9, WP10 (collectors) in parallel; first golden documents. M3: WP11 (attestation) and WP12 (policy) in parallel; WP13 after WP11's verifier API lands. M4: WP14 CLI wiring; WP15 docs/CI/example end-to-end; release 0.1.0. File overlap is limited to `api.py` and `pyproject.toml` (owned by WP14/WP15) and the divergence register (append-only, owned by WP6 with sections contributed by WP7).

---

## 15. Risks and open questions

| # | Risk / question | Impact | Mitigation / decision needed |
|---|---|---|---|
| R-1 | `cyclonedx-python-lib` lacks `modelCard`/`declarations`/`formulation`/`citations` (V-06) | Cannot rely on it for emission | **Decided (D-02):** direct JSON emission; lib for validation; contribute upstream later |
| R-2 | `rfc8785` integer domain (±2^53) makes some schemas undigestable | Tools with 64-bit `maximum` become unpinnable | **Decided (I5):** fail closed and flag; document the workaround (server-side schema fix); evaluate an `ext-bigint` digest type only if demand appears |
| R-3 | `sigstore.dsse.Envelope` single-signature; no key-based signing in sigstore-python | Multi-party and air-gapped signing | **Decided:** own DSSE implementation for key-based/multi-sig; sigstore bundles for keyless |
| R-4 | MCP protocol churn (2026-07-28 adds `execution`, `icons`, `ttlMs`, `cacheScope`) | Digest field set stability | Primary digest frozen to model-visible fields; `tooldef-full/v1` for the rest; new fields need a `/v2` URI, never silent inclusion |
| R-5 | OTel GenAI conventions are *Development* stability; attribute renames (`gen_ai.system`→`gen_ai.provider.name`) | Observed collector breakage | Alias table in `collect/otel.py`; Phase 1 to pin a semconv version (A-05) |
| R-6 | No purl type for MCP servers; registry entries have no attestation fields (V-13) | Weak native identity for servers | Server digest (`server/v1`) is the identity; registry name is a locator; propose a `pkg:mcp` type upstream (open question) |
| R-7 | SPDX custom extensions rely on `spdx-python-model` private `_ext_data` | Breakage on library update | Wrapper + pin `spdx-python-model==0.0.6`; upstream a public API; fallback to `CdxPropertiesExtension`-only export |
| R-8 | SPDX 3.1 `AIAgent/Prompt/RAG` not present in fetched develop model (A-03) | Forward mapping uncertain | Promise only verified 3.1 features (`isoAutomationLevel`, new relationship types) |
| R-9 | k8s-aibom `AIBOM` CR field path for the embedded BOM unverified (A-04) | Importer shape | Phase 1 to fetch the CRD; importer accepts both raw CDX and CR wrapper |
| R-10 | OWASP ASI03/05/07/08 titles taken from secondary sources (A-07) | Mapping labels | Confirm against the official PDF; ids are stable, titles are display-only |
| R-11 | Behavioural fingerprints for hosted models are heuristics (A-06) | False drift alarms or missed swaps | Never above `observed`; configurable tolerance; documented limits |
| R-12 | Property-value JSON (`symbiote:authz:grant`) is opaque to generic CDX tools | Interop friction | Companion is the structured source; propose `cdx:ai:agent:*` names upstream (property-taxonomy#175 context) |
| R-13 | Gateway implementers may digest SDK-normalized JSON | False mismatches | Publish conformance vectors (`tests/vectors/tooldef/*.json` with expected digests) and the reference `verify_gab` |
| R-14 | Store/index is local SQLite | Fleet-scale IR | Non-goal for v0.1; schema designed for export to a warehouse |
| Q-1 | Should `approved` snapshots require a human signer identity distinct from the CI identity that produces `declared`? | Separation of duties | Proposed default: yes for `AgentBOM-Verified` (policy `requireDistinctApprover`) |
| Q-2 | Default `maxStaleness` for observed toolsets in GAB (24 h proposed) | Availability vs drift window | Decide with first gateway integrator |
| Q-3 | Should tool text be included in BOMs by default? | Attack-map leakage vs auditability | Proposed: digests only by default; `--include-text` plus Merkle redaction classes for sharing |
| Q-4 | Register `symbiote` namespace immediately or after 0.1.0? | Taxonomy review requires public docs | File the issue at 0.1.0 with `taxonomy/` published |

---

---

## 16. Phase 1 gap-register coverage (`gaps-attack.json`, ATTACK-01…22)

Conformance-level vocabulary: the register's L0–L3 map to non-conformant / AgentBOM-Minimal / Standard / Verified.

| Gap | Symbiote feature(s) | Checks / predicates | Residual noted |
|---|---|---|---|
| ATTACK-01 tool poisoning / rug pull (incl. runtime-gated) | `tooldef/v1` + `toolset/v1` digests (§7.1), GAB enforcement with re-verification on session start, `tools/list`, `list_changed`, `tools/call` (§10.1, D-08), C2 `--watch`, `tool-definition-set/v1` | SYM-TOOL-001/002/004/005/006/007 | split view between verifier and agent unless enforced in the agent's own gateway path |
| ATTACK-02 model swap behind alias | Hosted model identity (provider, alias, resolvedSnapshot, aliasPinned), fingerprint claim with expiry, `model-routed` delta from OTel `gen_ai.response.model` | SYM-MODEL-001 | provider-side swap with unchanged snapshot id |
| ATTACK-03 namespace reuse / typosquat / slopsquat | RegistryResolution record + `registry-resolution/v1`, I8 (digest is identity), typosquat distance, publisher verification | SYM-MCP-005, SYM-REG-001 | legitimately-owned look-alike namespaces |
| ATTACK-04 unsafe deserialization | serialization risk class, trust_remote_code, chat-template executable flag, scanner evidence by digest | SYM-MODEL-002 | loader CVEs |
| ATTACK-05 poisoned adapter / layer, merge DAG | OMS-compatible per-file manifest, per-tensor manifest (D-09), typed derivation edges with parameters | SYM-MODEL-004 | GGUF parser validation (A-11) |
| ATTACK-06 RAG / memory poisoning | DataSource writers, trust tiers, snapshot digests, `memory-writer-added` deltas, Q2 query | SYM-MEM-001/002, SYM-DATA-001 | writes through unmodelled channels |
| ATTACK-07 indirect injection → tool call | `readsContextFrom` trust tiers, Rule-of-Two/trifecta flag with cited inputs, AB-STD-09 | SYM-AUTHZ-001, SYM-DATA-001, SYM-INSTR-002 | mislabelled trust tiers (assurance-tagged) |
| ATTACK-08 delegation / identity spoofing | `delegatesTo` qualifiers, Identity refs by reference, A2A card digest + signature facts, Q1 blast radius | SYM-AUTHZ-005, SYM-A2A-001 | identity provider compromise |
| ATTACK-09 registry compromise / approvals bound to names | Approval covers digests + capability sets, `approval/v1`, registry status in resolution, `registry watch` deltas, trust status | SYM-MCP-004, SYM-TRUST-001/002 | registry operator compromise |
| ATTACK-10 credential / scope over-grant | Grant (declared/effective/observed), CredentialBinding kinds, enforcement points, policy-bundle digest, Q1 | SYM-AUTHZ-002/003/004/006 | undocumented required scopes |
| ATTACK-11 exfiltration via open-world tools | sideEffects.egressDestinations, Grant.scope.egress, observed egress from OTel/gateway | SYM-TOOL-003, SYM-AUTHZ-007 | covert channels inside allowed destinations |
| ATTACK-12 redacted BOM as attack map | salted Merkle leaves, inclusion proofs, redaction classes recorded | — (I6) | leaf count/kind inference |
| ATTACK-13 rollback / replay / stale BOM | serial + prev + validity, state file, trust-status expiry, Rekor split-view search | SYM-SNAP-001/002/003 | state-file integrity on the gateway host |
| ATTACK-14 instruction / skill poisoning | Instruction exact-bytes digests + editors + remote includes, Skill dirmanifest root, hidden-Unicode lint | SYM-INSTR-001/002, SYM-TOOL-006 | semantic injection in approved text |
| ATTACK-15 cross-server shadowing / mixed trust | tool ids scoped by server, server trust zones, mixed-trust check | SYM-TOOL-008, SYM-MCP-006 | — |
| ATTACK-16 shadow components at runtime | observed snapshots (C2, C12), `diff`, `observed-delta/v1`, GAB prescriptive mode, lastKnownGood | SYM-SUB-001, SYM-TOOL-002 | telemetry suppression |
| ATTACK-17 unbound / stale evaluations | Evaluation bound to config digests, `evaluation/v1`, AI-VEX scoped by config digest | SYM-EVAL-001, SYM-ATT-002 | evaluation quality itself |
| ATTACK-18 forged / unverifiable claims | per-claim assurance (I1), Design 002 rule (I3), DSSE/Sigstore predicates, JCS everywhere | SYM-ATT-001, SYM-MODEL-003 | trusted-signer compromise |
| ATTACK-19 coverage laundering | Coverage statement (I2), `coverage/v1`, SPDX NoAssertion/None idiom, AB-VER-07 | SYM-COV-001/002 | human over-trust |
| ATTACK-20 lossy conversion / fragmentation | one model, LossReport, `CdxPropertiesExtension` bridge, taxonomy + divergence register, model-digest triangulation, exit code 8 | — | generic tools ignoring JSON-in-property |
| ATTACK-21 training-data poisoning via mutable sources | DataSource.sources fetch evidence, dataset derivation kinds, poison-scan evidence, `trainedOn` edges | SYM-MODEL-004 (extended to datasets) | upstream sources never snapshotted |
| ATTACK-22 implementation drift behind stable interface | ToolServer.implementation (package/lockfile/image digest, deployment attestation, TLS/SPIFFE identity), observed side-effect profile | SYM-AUTHZ-007, SYM-MCP-002 | explicitly residual: effects must be enforced at gateway/sandbox/network |

## Appendix A — Verified facts (how)

V-01 CDX 1.7 schema: `component.type` enum (no agent/tool), `externalReference.type` enum incl. `attestation|evidence|formulation|configuration|distribution-intake|model-card`, hash algorithms, `declarations` sub-structure (`assessors, attestations[map{requirement, claims, counterClaims, conformance{score,rationale,mitigationStrategies}, confidence{score,rationale}}], claims, evidence, targets, affirmation`), `definitions.standards[requirements, levels]`, `formulation` task output types `[artifact, attestation, log, evidence, metrics, other]`, `compositions.aggregate` enum, lifecycles phases, `citations[pointers|expressions, attributedTo|process, signature]`, `annotations[subjects, annotator]`, `componentData.type` enum incl. `definition`, `evidence.identity.methods[].technique` enum, `vulnerability.analysis.justification` enum — via `jq` over `refs/cyclonedx/bom-1.7.schema.json`. V-05 A skeleton document using all planned constructs validated with 0 errors (after correcting `outputs[].type` and dropping `affirmation.signatories`) with both `jsonschema` and `cyclonedx-python-lib` `JsonStrictValidator(V1_7)`. V-06 `cyclonedx-python-lib` 11.12.0 module inventory: no `ModelCard`, no declarations/formulation/citations/annotation modules; has `definition` (Standard/Requirement/Level), lifecycles, services, vulnerabilities. V-07 `bom-1.7.xsd` `modelCardType` sequence contains `properties` (lines ~3225–3650). V-08 JSF 0.82 `signer` fields: `algorithm, keyId, publicKey, certificatePath, excludes, value`. V-09 CycloneDX property-taxonomy README: registered namespaces list (no `symbiote`/`agentbom`), ABNF, registration via GitHub issue. V-10 `rfc8785` 0.1.4 behaviour (probe). V-11 `model-signing` 1.1.1: predicate `https://model_signing/signature/v1.0` (compat `https://model_signing/Digests/v0.1`), subject digest = SHA-256 over concatenated resource digests, `hashing.Config` and `signing/verifying.Config` APIs (probe + source). V-12 `spdx-python-model` 0.0.6 `v3_0_1` bindings: 59 `RelationshipType` members incl. `usesTool, invokedBy, delegatedTo, trainedOn, testedOn, hasEvidence, ancestorOf, descendantOf, hasVariant, configures`; `LifecycleScopeType.runtime`; `extension_CdxPropertiesExtension/CdxPropertyEntry`; custom extension via `extension_Extension(typ)`; output validated against the official 3.0.1 JSON schema (`spdx-spec` gh-pages `v3.0.1/rdf/schema.json`) with 0 errors; `extension_Extension` schema allows `unevaluatedProperties: true`. V-13 MCP registry: `server.json` 2025-12-11 fields; `_meta["io.modelcontextprotocol.registry/official"] = {status, publishedAt, updatedAt, statusChangedAt, isLatest}`; status values `active|deprecated|deleted`; no signature fields. V-14 MITRE ATLAS v5.6 ids listed in §8.1 (from `ATLAS.yaml`). V-15 `sigstore` 4.5.1 APIs: `StatementBuilder`, `Subject`, `DigestSet` (sha256/384/512/sha3), `SigningContext.from_trust_config`, `ClientTrustConfig.production()/staging()/from_json/from_tuf`, `Signer.sign_dsse -> Bundle`, `Verifier.production()/staging()/verify_dsse -> (payload_type, payload)`, `policy.Identity(identity=, issuer=)`, `AllOf/AnyOf`, `UnsafeNoOp`, `Envelope` single-signature rule, `oidc.detect_credential`, `Issuer(base_url).identity_token()`. V-16 `mcp` 2.3.0: `Tool{name, title, description, inputSchema, outputSchema, annotations{title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint}, icons, execution{taskSupport}, _meta}`, `ListToolsResult{tools, nextCursor, ttlMs, cacheScope}`, `LATEST_PROTOCOL_VERSION = 2026-07-28`. V-17 k8s-aibom conventions and Design 002 outcome table (local refs). V-18 SPDX 3.1-dev changelog and develop model files (local refs). V-19 From Phase 1 `gaps-attack.json` verification notes (2026-11-01): the 1.7 XSD declares version 1.7.2 and includes `modelCard/properties`; SPDX tag `3.1-rc1` has no AIAgent/Prompt/RAG classes and 77 RelationshipType entries (develop 83) incl. `finetunedOn, pretrainedOn, evaluatedOn, validatedOn, implementedBy, runsOn, hasInstance, verifiedBy`; MCP registry server.json has optional `packages[].fileSha256`, no digest for remotes and no attestation reference; no `pkg:mcp` purl type exists; Deadbugz (Pillar Security, Aug 2026) is runtime-gated tool-metadata poisoning (hostile on the third call).

## Appendix B — Assumptions

A-01 Phase 1 `verified-*.json`/`landscape-*.json` absent at writing; `gaps-attack.json` reconciled in §16. A-02 OWASP AIBOM guide and Medium article as framing only. A-03 SPDX 3.1 `AIAgent/Prompt/RAG` unverified. A-04 k8s-aibom CR embedding path unverified. A-05 OTel GenAI attribute names and stability (Development) — collector built with alias table. A-06 Behavioural fingerprints are heuristics. A-07 OWASP ASI03/05/07/08 titles from secondary sources. A-08 Rekor logging of key-based envelopes deferred to v0.2. A-09 cdxgen/agent-harness-aibom property names handled generically (foreign-property preservation) until Phase 1 lists them. A-10 CycloneDX #973 (discussion, zero replies), #895 (Agent BOM proposal, open) and #1015 (tool-manifest/policy-bundle digest anchors, open, unadopted) status is taken from the Phase 1 register notes, not re-verified here; a CycloneDX 2.0 declared-behaviour model for agents could not be confirmed by Phase 1 and is not relied upon. A-11 GGUF per-tensor parsing to be validated.
