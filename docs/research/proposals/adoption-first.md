# Symbiote — Architecture Proposal (Adoption-first / Developer-experience emphasis)

**Status:** independent proposal, Phase 2. **Date:** 2026-11-01. **Author role:** developer-tools architect / OSS product lead. **Target:** `aisecnomad/symbiote`, branch `claude/symbiote-foundation`.
**Scope:** satisfies R1–R12 of the shared Design Brief; emphasises the path from `pip install symbiote` to a signed, CI-enforced AgentBOM in one working session.

> Reading guide. §0 is the pitch and the decisions that make this proposal different. §1–§8 are the normative design (model, mappings, collectors, digests, policy, attestation). §9–§10 are the product surface (CLI, API, repo, docs). §11 is the work breakdown for parallel implementation agents. §12 lists risks. Appendix A is the assumptions register (every `A-n` tag in the text points there); Appendix B lists facts verified by probing the real libraries and schemas during this design.

---

## 0. Executive summary and distinctive choices

Symbiote is a Python toolkit (`uv`, Pydantic v2, Typer + rich) that generates, validates, diffs, verifies, attests and enforces **AgentBOMs**: bills of materials for AI agents that cover the four planes in the brief — composition, authorization, observability, assurance. It emits **CycloneDX 1.7** and **SPDX 3.0.1** documents that validate against the official schemas without forking either standard, and it carries agent-specific semantics through the sanctioned extension points plus a **companion AgentBOM document** with its own JSON Schema.

The adoption thesis is simple: an optional field nobody fills is security theatre, so the product must *write itself*. The first screen of the README shows three commands and the table they produce:

```bash
pipx install symbiote                 # or: uv tool install symbiote
symbiote scan .                       # zero-config: finds MCP configs, skills, CLAUDE.md/AGENTS.md, prompts, models, SBOMs
symbiote policy check agentbom.json   # exit 1 on findings; --sarif for GitHub code scanning
```

Distinctive choices in this proposal (each justified in the body):

1. **Progressive disclosure through conformance levels.** `symbiote scan .` always succeeds and always produces a *useful* **AgentBOM-Minimal** from static files in under a minute, offline. **Standard** adds served tool-definition digests, authorization records and a companion document; **Verified** adds signed attestations, observed-vs-declared diffs and evaluation evidence. The validator tells you exactly which fields stand between you and the next level (§7).
2. **One tool-neutral property namespace, `agentbom:`**, designed for upstreaming to the CycloneDX property taxonomy, plus a tiny `symbiote:` namespace strictly for generator provenance. The spec is not the tool (§2.1).
3. **Direct, deterministic JSON emission for CycloneDX, validated against the official `bom-1.7` schema; `cyclonedx-python-lib` is *not* on the export path.** Probing showed the library (11.12.0) has no object model for `declarations`, `citations`, `compositions`, `formulation`, `annotations` or `modelCard`, and that `Bom.from_json` silently drops `modelCard` on import (Appendix B). Those constructs are load-bearing for us, so we own the emitter and importer at the JSON level and use the library only for XML output behind an explicit loss report (§2, §4).
4. **`spdx-python-model` bindings on the SPDX path, with `CdxPropertiesExtension` as the lossless carrier of every `agentbom:*` fact.** A probe document using `ai_AIPackage`, `LifecycleScopedRelationship(scope=runtime)` and `CdxPropertiesExtension` validated against the official SPDX 3.0.1 JSON schema with zero errors and round-tripped through the deserializer (Appendix B).
5. **Evidence locators go into native CycloneDX 1.7 `citations` *and* into grep-able properties** (the k8s-aibom precedent). `citations[].pointers` carry a JSON Pointer to the fact, `attributedTo` names the collector, `note` carries the source locator (e.g. `.mcp.json#/mcpServers/github/args/1`).
6. **The diff is the finding.** `symbiote diff declared.json observed.json` emits SARIF; an undeclared tool observed via live `tools/list` or an OTel `execute_tool` span is a `critical` result, not a log line.
7. **Integrate, don't rebuild.** cdxgen/syft own the software layer (merged as components with their own evidence intact); k8s-aibom output is imported as an *observed* source with a defined confidence→assurance mapping; Dependency-Track and GUAC are sinks (CDX 1.6 downgrade profile for Dependency-Track until it ingests 1.7); OTel GenAI traces are the observed-behaviour source; Sigstore signs; OPA consumes exported Rego with the BOM as input document.
8. **A self-writing demo.** `examples/triage-agent/` is a realistic issue-triage agent (MCP servers over stdio and HTTP, skills, prompts, a Hugging Face reranker with an OpenSSF model-signing manifest, a hosted Claude model behind a floating alias, a RAG index, a memory store and an A2A sub-agent). It is the golden fixture for tests, the documentation walkthrough, and the first thing a visitor runs.

Everything below is decided unless tagged `A-n` (assumption) or listed in §12 (open question).

---

## 1. Semantic model (source of truth)

The model is a Pydantic v2 package, `symbiote.model`. Exporters and importers are pure functions over it. Every entity has an **identity** (content digest where content exists, otherwise a stable `id`), a `kind` enum, a `state` enum (`declared | approved | deployed | observed`), and a list of **claims**: a claim is `(field, value, assurance, evidence[])` where `assurance ∈ {declared, observed, verified}` and `value` may be the sentinel `unknown` (distinct from absent, distinct from verified-absent).

### 1.1 Document and snapshot

| Entity | Field | Type | Req | Description |
|---|---|---|---|---|
| `AgentBOM` | `id` | `urn:uuid` | yes | Document serial; new UUID per emission. |
| | `spec_version` | const `"0.1"` | yes | AgentBOM profile version. |
| | `subject` | ref→`Agent` | yes | Root agent. |
| | `snapshot` | `Snapshot` | yes | Content digest + validity + chain (below). |
| | `entities` | list | yes | All entities (§1.2–§1.10). |
| | `edges` | list[`Edge`] | yes | Typed relationships (§1.11). |
| | `authorizations` | list[`Authorization`] | no | §1.7. |
| | `evidence`, `evaluations`, `risk_statements`, `trust_statuses` | lists | no | §1.8–§1.9. |
| | `coverage` | `Coverage` | yes | §1.10; may be all-`unknown`, never absent. |
| | `redactions` | list[`Redaction`] | yes (may be empty) | `{class, paths[], applied_at}`; never silent (R11). |
| | `merkle_root` | `sha256:` | Standard+ | Root over entity leaves (§6.5). |
| | `producer` | `Producer` | yes | `{name:"symbiote", version, collectors[{name, version, status}]}`. |
| | `links` | `Links` | no | `{cyclonedx:{serialNumber, version, digest}, spdx:{document_iri, digest}}` — bidirectional linkage (R1). |
| `Snapshot` | `digest` | `sha256:` | yes | JCS digest of the document with `snapshot.digest`, `merkle_root`, `links`, `id` nulled (§6.1). |
| | `serial` | int ≥ 1 | yes | Monotone per agent lineage. |
| | `prior` | `sha256:` or null | yes | Previous snapshot digest (append-only chain). |
| | `state` | enum | yes | `declared | approved | deployed | observed`. |
| | `valid_from`, `valid_until` | RFC 3339 | yes | Validity window; expiry is a finding. |
| | `observed_at`, `observer` | timestamp, ref | observed only | Collector identity. |

### 1.2 Agent

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | string (bom-ref) | yes | `agent:<slug>`. |
| `name`, `version`, `purpose` | str | name yes | Stable definition id, release, intended purpose (EU AI Act system-level purpose lives here). |
| `owner`, `operator` | ref→`Party` | Standard+ | Organization/person. |
| `framework` | `{name, version}` | no | langgraph, crewai, openai-agents, claude-agent-sdk, autogen, semantic-kernel, custom. |
| `automation_level` | enum (ISO/IEC 22989 7 levels, same names as SPDX 3.1 `IsoAutomationLevel`) | no | Agent-wide default; **action-specific autonomy is expressed by `Authorization.approval_gate`**, not here. |
| `deployment` | `{environment, tenant, instance_id, deployed_at, workload_ref}` | deployed/observed | `workload_ref` carries k8s `group/kind/namespace/name/uid` when imported from k8s-aibom. |
| `identities` | list ref→`Identity` | Standard+ | Workload principals the agent acts as. |
| `entrypoint` | str | no | Path/module/command that starts the agent. |
| `is_subagent`, `parent` | bool, ref | no | Delegation tree. |

### 1.3 Model (local or hosted)

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | `model:<slug>` | yes | |
| `kind` | `local | hosted` | yes | |
| `provider` | str | hosted yes | anthropic, openai, bedrock, vertex, azure-openai, huggingface, ollama, vllm, … |
| `requested_ref` | str | yes | Exactly what the config says (`claude-sonnet-4-5`, `meta-llama/Llama-3.1-8B-Instruct`, `gpt-4o`). |
| `resolved_ref` | str or `unknown` | yes | Immutable snapshot/revision (`claude-sonnet-4-5-20250929`, HF commit SHA, OCI digest). |
| `alias_pinning` | `pinned | floating | unknown` | yes | Computed from `resolved_ref` and provider rules (§6.4). |
| `purl` | str | local | `pkg:huggingface/<ns>/<name>@<commit>` (purl type verified; version = git commit), `pkg:oci/...`, `pkg:mlflow/...`. |
| `manifest` | `ModelManifest` | local | Per-file `{path, sha256}` + `merkle_root`, format `oms-v1` compatible with OpenSSF model-signing (§6.3). |
| `serialization` | list[`{format, risk_class, files[]}`] | local | `format ∈ {safetensors, onnx, gguf, pickle, torch-pt, tf-savedmodel, keras-h5, joblib, other}`; `risk_class ∈ {inert, code-execution-on-load, template-execution, unknown}`. |
| `trust_remote_code` | bool or unknown | local | From `config.json`/loader code. |
| `chat_template_digest`, `tokenizer_digest`, `generation_config_digest` | `sha256:` | local | Separately compromisable artefacts. |
| `derivations` | list[`Derivation`] | no | `{type ∈ {fineTuneOf, adapterOf, quantizationOf, mergeOf, distillationOf, conversionOf}, parent: ref|purl, parameters: dict, parameters_digest}`. |
| `resolution` | `ResolutionRecord` | Standard+ | §6.4: requested → resolved → signer → log inclusion. |
| `signature` | `{status ∈ {unsigned, claimed, verified}, outcome, identity, issuer, rekor_entry, reason, subject_name_mismatch}` | local | Mirrors k8s-aibom `security:signing:*`; `signature-valid-unconstrained` never maps to `verified`. |
| `fingerprint` | `{method, digest, expires}` | hosted when `resolved_ref=unknown` | Behavioural fingerprint claim with expiry. |
| `endpoint` | ref→`Service` | hosted | Provider API service entity. |
| `modality`, `task` | str | no | Feeds CDX `modelCard.modelParameters.task`. |

### 1.4 Tool server, tool definition, skill, instruction, prompt template

| Entity | Field | Type | Req | Description |
|---|---|---|---|---|
| `ToolServer` (MCP) | `id` | `mcp:<client>:<name>` | yes | |
| | `name`, `client` | str, enum | yes | `client ∈ {claude-code, claude-desktop, cursor, vscode, windsurf, codex, gemini-cli, generic}`. |
| | `transport` | `stdio | streamable-http | sse` | yes | |
| | `target` | `{command, args[], cwd}` or `{url}` | yes | Secrets never stored; see `env_var_names`. |
| | `package` | `{purl, pinned: bool}` | no | Derived from `npx`/`uvx`/`docker` args (§5.1). |
| | `env_var_names`, `header_names` | list[str] | yes | Names only, values redacted → `redactions[]`. |
| | `auth_mode` | `none | env-token | header-token | oauth | unknown` | yes | |
| | `registry_entry` | ref→`RegistryEntry` | no | |
| | `served` | `{protocol_version, server_info{name,version}, instructions_digest, toolset_digest, observed_at}` | observed | From live `initialize` + `tools/list`. |
| | `trust_zone` | `local-process | loopback | internal | external | unknown` | yes | |
| | `client_trust_flags` | dict | no | e.g. Gemini `trust`, `includeTools`/`excludeTools`. |
| `Tool` | `id` | `tool:<server>:<name>` | yes | |
| | `server` | ref | yes | |
| | `name`, `title`, `description`, `input_schema`, `output_schema`, `annotations` | per MCP `Tool` | name yes | `annotations` = `{readOnlyHint, destructiveHint, idempotentHint, openWorldHint, title}` (fields verified in `mcp` 2.3.0). |
| | `definition_digest` | `sha256:` | Standard+ | §6.2; `digest_source ∈ {served, approved-file, registry, config}`. |
| | `description_digest`, `input_schema_digest` | `sha256:` | no | Finer drift attribution. |
| | `side_effect_class` | `read-only | state-modifying | destructive | financial | communicate | unknown` | yes | Derived (§5.1 rules). |
| | `capabilities` | set of `CapabilityClass` | yes | `read, write, execute, network-egress, filesystem, credentials, payment, communicate`. |
| | `approval_gate` | `required | conditional | none | unknown` | yes | From client config (Claude Code permissions, Gemini `trust`, Codex `approval_policy`) or declared. |
| | `state` | `declared | served | invoked` | yes | |
| `Skill` | `id`, `name`, `path` | | yes | `skill:<name>`; name must equal directory name (Agent Skills spec). |
| | `description`, `license`, `compatibility`, `allowed_tools[]`, `metadata{}` | from frontmatter | | |
| | `skill_md_digest`, `dir_digest`, `file_count`, `files[]` | | yes | §6.2 directory manifest. |
| | `scripts[]` | list `{path, digest, interpreter}` | no | Executable surface. |
| `Instruction` | `id`, `kind` | | yes | `kind ∈ {system-prompt, agents-md, claude-md, rules, cursor-rules, copilot-instructions, gemini-md, skill-body, mcp-server-instructions, hook, other}`. |
| | `path`, `digest`, `bytes` | | yes | Digest over exact bytes. |
| | `precedence` | int | no | Load order (user > project > directory). |
| | `editable_by` | list ref→`Identity` | no | Modification authority. |
| | `contains_secret_like` | bool | yes | Redacted content never emitted; flag recorded. |
| `PromptTemplate` | `id`, `name`, `path`, `template_digest`, `variables_schema_digest`, `role`, `engine` | | id, digest yes | `engine ∈ {jinja2, f-string, mustache, other}`; Jinja → `risk_class template-execution`. |

### 1.5 Data: datasets, RAG indexes, memory, retrieval connectors

| Field | Type | Req | Description |
|---|---|---|---|
| `id`, `kind` | | yes | `kind ∈ {dataset, rag-index, memory-store, retrieval-connector, tool-output-channel}`. |
| `name`, `location` | str | yes | URI or path; secrets stripped. |
| `trust_tier` | `trusted | internal | partner | untrusted-public | unknown` | yes | Policy input for the trifecta flag. |
| `instruction_bearing` | bool or unknown | yes | Can content become instructions (web pages, issues, emails = true). |
| `sanitization` | list[`{name, digest}`] | yes (may be empty) | Filters applied before the context window. |
| `snapshot` | `{commitment, method ∈ {merkle, hash, etag, timestamp, none}, at}` | no | Content commitment where possible. |
| `live` | bool | yes | Unbounded/mutable source. |
| `embedding_model`, `chunking` | ref, `{strategy, size, overlap, digest}` | rag-index | |
| `sources` | list ref→`DataSource` | rag-index | Lineage: source → chunk → index. |
| `writers` | list ref→`Identity` | memory-store | Who may write memory. |
| `retention`, `isolation`, `acl_mode` | str, `tenant|shared|unknown`, `document|index|none|unknown` | memory/rag | |
| `classification` | `public | internal | confidential | restricted | unknown` | yes | Maps to CDX `data.classification`. |

### 1.6 Identity and service

| Entity | Field | Description |
|---|---|---|
| `Identity` | `id`, `kind ∈ {spiffe, oauth-client, service-account, api-key-ref, user-obo, unauthenticated}`, `issuer`, `principal`, `binding ∈ {static-long-lived, ephemeral, obo, unauthenticated}`, `lifetime` | By reference only; never secret values. |
| `Service` | `id`, `name`, `endpoints[]`, `authenticated`, `trust_boundary_crossed`, `trust_zone`, `data_flows[{direction, classification}]`, `provider` | External APIs, model endpoints, remote MCP, A2A peers. |
| `Party` | `id`, `kind ∈ {organization, person}`, `name`, `contact` | Owners, operators, assessors, registries. |

### 1.7 Authorization record (R5)

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | `authz:<n>` | yes | |
| `subject` | ref→Agent/Tool/Service | yes | |
| `capability` | `CapabilityClass` | yes | `read | write | execute | network-egress | filesystem | credentials | payment | communicate`. |
| `scope` | `{resources[], egress_destinations[], data_classes[], spend_ceiling{amount,currency,period}}` | yes | Patterns; globs allowed. |
| `granter` | ref→Party/Identity | Standard+ | |
| `delegation_chain` | list ref→Agent/Identity | no | A2A: A → B → tool. |
| `conditions` | list[str] | no | CEL-like or prose; digest recorded. |
| `approval_gate` | `required | conditional | none | unknown` | yes | Human-in-the-loop. |
| `valid_from`, `valid_until` | timestamps | no | Expiry is a finding. |
| `policy_ref` | `{uri, digest}` | Standard+ | Policy bundle actually enforced. |
| `enforcement_point` | `gateway | runtime | sandbox | network | none | unknown` | yes | |
| `credential_binding` | `static-long-lived | ephemeral | obo | service-account | unauthenticated` | yes | |
| `identity` | ref→`Identity` | no | |
| `source` | `declared | effective | observed` | yes | Kept distinguishable; three records may exist for one subject. |

**Computed flags** (`AgentBOM.flags`, each `{flag, subject, inputs[], assurance}`): `lethal-trifecta` (any path: data source with `instruction_bearing=true ∧ trust_tier ∈ {untrusted-public, partner, unknown}` → agent → tool with `communicate ∨ network-egress` capability, and agent reads any source with `classification ∉ {public}`), `unpinned-tool`, `floating-model-alias`, `destructive-open-world-no-gate`, `unsigned-model`, `unsafe-serialization`, `static-credential`, `unauthenticated-remote-mcp`.

### 1.8 Evidence, evaluation, risk statement, trust status (R7)

| Entity | Fields |
|---|---|
| `Evidence` | `id`, `kind ∈ {tools-list, config-file, registry-record, signature-verification, otel-span, k8s-aibom, sbom, attestation, evaluation-report, human-review}`, `digest`, `uri`, `locator` (source path / JSON Pointer), `collector{name, version}`, `created`, `expires`, `author`, `assurance`. |
| `Evaluation` | `id`, `configuration{model_digest, prompt_digest, toolset_digest, data_digest, policy_digest}`, `threat_model`, `harness{name, version, digest}`, `dataset{name, digest}`, `attack_conditions[]`, `results[{metric, numerator, denominator, threshold, pass}]`, `assessor` (ref→Party, `third_party: bool`), `valid_until`, `validity_conditions[]`, `mappings{owasp_asi[], owasp_llm[], atlas[]}`. |
| `RiskStatement` (AI-VEX) | `id`, `threat{framework ∈ {owasp-asi-2025, owasp-llm-2025, mitre-atlas}, id}`, `scope{model_digest, config_digest}`, `status ∈ {affected, not_affected, under_investigation, fixed}`, `justification ∈ {tool-disabled, guardrail-enforced, approval-required, not-reachable, evaluated-resistant, component-not-present}`, `evidence[]`, `statement`, `expires`. |
| `TrustStatus` | `subject_key` (identity: digest, purl, server name+version, registry entry), `status ∈ {allowlisted, quarantined, revoked, unknown}`, `issuer`, `since`, `reason`, `evidence[]`. |

### 1.9 Registry entry and resolution

`RegistryEntry`: `id`, `registry ∈ {mcp-official, huggingface, npm, pypi, oci, a2a-catalog, enterprise, other}`, `registry_url`, `entry_name`, `entry_version`, `publisher`, `publisher_verification ∈ {dns, http, github-oidc, github-oauth, none, unknown}`, `status ∈ {active, deprecated, deleted, unknown}`, `published_at`, `updated_at`, `is_latest`, `record_digest` (JCS of the record), `resolution` → `ResolutionRecord` (§6.4). The official MCP registry carries no attestation fields (verified), so `attestation_ref` is `unknown` there by construction.

### 1.10 Coverage (R7)

`Coverage`: `window{from,to}`, `surfaces{code, registry, identity, model-gateway, tools, data, runtime, network}` each `{status ∈ {covered, partial, not-covered, unknown}, sources_queried[], permission_failures[], truncation{applied, dropped}, exclusions[]}`, `collectors[{name, status ∈ {ok, partial, failed, skipped}, reason}]`. A failed registry query yields `registry: unknown`, never "no shadow tools".

### 1.11 Edges

`Edge`: `from`, `to`, `type`, `scope ∈ {design, build, runtime}`, `state`, `assurance`, `evidence[]`, `authorization` (ref), `valid_from/valid_until`.

| Edge type | Meaning | SPDX 3.0.1 relationship | CDX carrier |
|---|---|---|---|
| `uses-tool` | agent may call tool | `usesTool` (runtime) | `dependencies.dependsOn` + `agentbom:edge:*` |
| `invokes` | observed call | `usesTool` + evidence | `formulation` event + `annotations` |
| `serves` | server exposes tool | `contains` | nested `components` / `dependsOn` |
| `delegates-to` | agent → sub-agent | `delegatedTo` on `invokedBy` | `dependsOn` + authz record |
| `acts-as` | agent → identity | `invokedBy` | properties `agentbom:identity:*` |
| `routes-to-model` | agent → model | `dependsOn` | `dependsOn` |
| `retrieves-from` / `writes-memory-to` / `reads-context-from` | agent ↔ data | `dependsOn` / `modifiedBy` / `hasDataFile` | `dependsOn` + `services.data` flows |
| `configures` | instruction/prompt/policy → agent | `configures` | `dependsOn` |
| `derived-from(type)` | model lineage | `descendantOf` + `hasVariant` (+3.1 `finetunedOn`) | `pedigree` + props |
| `registered-as` | component → registry entry | `availableFrom` | `externalReferences[distribution-intake]` |
| `approved-under` | deployment → policy | `hasSpecification` | `declarations.claims` |
| `has-evidence` | claim → evidence | `hasEvidence` | `declarations.evidence` |
| `depends-on` | software dependency | `dependsOn` | `dependsOn` |

### 1.12 Assurance levels and the k8s-aibom mapping

Per claim, never per agent: `declared` (owner/supplier said so, or a static file was parsed), `observed` (a collector corroborated deployed state within a stated window), `verified` (evidence authenticated against an explicit trust policy with documented coverage). Import mapping from k8s-aibom `aibom.confidence` / `k8s-aibom:confidence`: `declared → declared`; `inferred → observed` with `method: heuristic` and the pattern recorded as evidence; `verified → verified` only when `security:signing:outcome` shows a constrained identity match, otherwise `observed` with `signature.outcome` preserved; `unresolved → value unknown`. Export back to k8s-aibom vocabulary is the inverse, with `observed(method=heuristic) → inferred`.

---

## 2. CycloneDX 1.7 mapping (R1)

### 2.1 Namespace decision: `agentbom:` for facts, `symbiote:` for generator provenance

Registered top-level namespaces in the CycloneDX property taxonomy are tool- or vendor-named (`k8s-aibom`, `cdx`, `snyk`, …), and the taxonomy grammar is `namespace[:sub-namespace]*:name`, colon-delimited, lowercase namespaces, names restricted to `[A-Za-z0-9_- ]` (verified from the taxonomy README; k8s-aibom is renaming its dotted `aibom.*` names to `k8s-aibom:*` in v1.7 for exactly this reason). We register **`agentbom`** as a tool-neutral namespace (A-1: registration via a taxonomy issue, with `spec/taxonomy.md` published first as the README requires) because cdxgen, k8s-aibom or an enterprise registry should be able to emit `agentbom:tool:definition-digest` without implying they ran Symbiote. **`symbiote`** holds only what is inherently about this generator (`symbiote:version`, `symbiote:collector:<name>:status`). Facts the core model expresses natively are never duplicated as properties: digests go in `hashes[]`, purls in `purl`, lifecycle in `metadata.lifecycles`, endpoints in `services[].endpoints`.

Property values are strings. Multi-valued facts use indexed sub-namespaces (`agentbom:authz:0:capability`), the k8s-aibom `scrape:<i>` pattern. Every emitted property name appears in `spec/taxonomy.md` with type, allowed values and the entity field it mirrors; every deviation from native CycloneDX semantics gets a `D-NNN` entry in `spec/divergences.md` (status `active | rescinded | upstreamed`, spec section, rationale, upstream tracking: CycloneDX/specification#990, property-taxonomy#175).

### 2.2 Construct mapping

| Model entity | CDX 1.7 construct | Notes |
|---|---|---|
| `AgentBOM` header | `serialNumber` (= `id`), `version` (= `snapshot.serial`), `metadata.timestamp`, `metadata.lifecycles[{phase}]` (`design/build` → declared, `post-build` → approved, `operations` → deployed/observed), `metadata.tools.components[]` (symbiote + each collector as a component) | Prior snapshot: `externalReferences[{type:"bom", url:"urn:cdx:<prior-serial>/<version>"}]`. |
| `Agent` | `metadata.component` (`type: application`, `agentbom:kind=agent`); sub-agents: `components[]` `type: application`, `agentbom:kind=sub-agent` | `supplier`/`manufacturer` = owner/operator. |
| `ToolServer` | `services[]` (`endpoints` = url, or `stdio:<command>` URI for stdio; `authenticated`; `x-trust-boundary`; `trustZone`; `data[]` flows) + `agentbom:mcp:*` | Nested `services[].services` only for remote servers that proxy others. |
| `Tool` | `components[]` `type: data`, `data[0].type: "definition"`, `data[0].contents.attachment` = base64 JCS canonical definition (Standard+, optional `--no-embed`), `hashes[{alg:"SHA-256", content}]` = definition digest; `dependencies[{ref: tool, dependsOn:[server]}]` | `data` is the right type: the definition is model-visible data, not code. |
| `Skill` | `components[]` `type: library`, `group: "skills"`, nested `components[]` `type: file` (SKILL.md, scripts) with `hashes` | `hashes` of the library = `dir_digest`. |
| `Instruction`, `PromptTemplate`, policy bundle | `components[]` `type: file` with `hashes`, `agentbom:instruction:*` / `agentbom:prompt:*`; prompt variable schema as nested `type: data` (`definition`) | Content never embedded; digest only. |
| `Model` (local) | `components[]` `type: machine-learning-model`, `purl`, `hashes` (manifest Merkle root as `SHA-256` with `agentbom:model:manifest-format=oms-v1`), `modelCard{modelParameters{task, approach}, properties[]}`, `pedigree.ancestors/variants` for derivations, nested `type: file` components for weights/tokenizer/chat template | `modelCard.properties` validates in JSON (verified) but not XML — recorded as D-002 and flagged in XML loss report. |
| `Model` (hosted) | `components[]` `type: machine-learning-model` (identity: `name` = requested ref, `version` = resolved snapshot or absent, `isExternal: true`) **plus** `services[]` for the provider endpoint; `dependencies[{ref: model, dependsOn:[endpoint-service]}]` | `agentbom:model:alias-pinning`, `agentbom:model:resolution:*`. |
| `DataSource` | `components[]` `type: data`, `data[{type: dataset|other, classification, governance{owners,custodians}}]`, `agentbom:data:*` | RAG lineage: `dependencies` index → sources, index → embedding model. |
| `Identity` | `agentbom:identity:<i>:*` properties on the subject + companion record | No native construct (D-003). |
| `Authorization` | `agentbom:authz:<i>:*` on subject; `declarations.claims[]` for *effective* permissions (`predicate`, `evidence`), `services[].data[]` for egress flows | Full record in companion / embedded record (§4). |
| `Evidence` | `declarations.evidence[{bom-ref, propertyName, description, data[{name, contents{url|attachment}}], created, expires, author}]` + `externalReferences[{type: evidence|attestation|log}]` | |
| Evidence locator | `citations[{pointers:["/components/3/hashes/0"], attributedTo:<collector bom-ref>, process:<scan task bom-ref>, timestamp, note:"<locator>"}]` **and** `agentbom:evidence:locator` / `agentbom:evidence:source` / `agentbom:assurance` on the component | Dual emission mirrors k8s-aibom D-004 (grep-ability) while using the native 1.7 construct. |
| `Evaluation` | `declarations.evidence` + `externalReferences[{type: dynamic-analysis-report|pentest-report}]`; mapped through `definitions.standards[]` (OWASP ASI 2025, OWASP LLM Top 10 2025, MITRE ATLAS as standards with `requirements[].identifier`) and `declarations.attestations[].map[{requirement, claims, conformance{score, rationale}, confidence{score, rationale}}]` | Standards shipped as JSON fixtures in `symbiote/schemas/standards/`. |
| `RiskStatement` (AI-VEX) | `vulnerabilities[{id:"ASI04"|"AML.T0051", source{name:"OWASP Agentic Top 10 2025"|"MITRE ATLAS", url}, ratings[{method:"other", severity}], analysis{state: not_affected|exploitable|in_triage, justification: protected_at_runtime|protected_by_mitigating_control|requires_configuration|code_not_reachable, detail}, affects[{ref}], properties: agentbom:vex:justification, agentbom:vex:scope:model-digest, agentbom:vex:scope:config-digest}]` | Justification mapping table in `spec/vex.md`: `tool-disabled → requires_configuration`, `guardrail-enforced → protected_by_mitigating_control`, `approval-required → protected_at_runtime`, `not-reachable → code_not_reachable`, `component-not-present → code_not_present`. |
| `TrustStatus` | `agentbom:trust:status|issuer|since` + `annotations[]` for human review text | |
| `Coverage` | `compositions[]` (one per surface: `aggregate ∈ complete|incomplete|unknown`, `assemblies`/`dependencies` listing what was inspected) + `agentbom:coverage:<surface>` + `agentbom:coverage:window` | `unknown` aggregate is the honest default. |
| `Snapshot`, deltas | `agentbom:snapshot:*` on `metadata.properties`; runtime assembly events as `formulation[{workflows[{uid, taskTypes:["other"], tasks[{name:"tool-registered", properties, timeStart}]}]}]` | The formulation block is the 1.7 hook for runtime assembly the source document calls for. |
| `Redaction` | `agentbom:redaction:applied=<class>` per affected element, `metadata.distributionConstraints`, `agentbom:merkle:root` | Verified against the signed root (§6.5). |
| Registry entry | `externalReferences[{type:"distribution-intake", url, hashes:[record digest]}]` + `agentbom:registry:*` | `distribution-intake` is the native 1.6+ type for intake sources. |
| Signature | DSSE envelope out-of-band (primary); optional JSF `signature` via `--jsf-sign` | JSF is bytes-level and single-party; DSSE composes multi-party claims. |

### 2.3 Property taxonomy (exact names, v0.1)

| Property | Values / type | Attaches to |
|---|---|---|
| `agentbom:spec-version` | `0.1` | metadata.properties |
| `agentbom:kind` | `agent, sub-agent, mcp-server, tool, skill, instruction, prompt-template, model, dataset, rag-index, memory-store, retrieval-connector, identity, registry-entry, policy-bundle, guardrail, a2a-agent` | any component/service |
| `agentbom:state` | `declared, approved, deployed, observed` | any |
| `agentbom:assurance` | `declared, observed, verified` | any (component-level aggregate; per-field in citations/companion) |
| `agentbom:evidence:source`, `agentbom:evidence:locator`, `agentbom:evidence:collector`, `agentbom:evidence:collected-at` | source kind (`mcp-config, skill-md, instruction-file, framework-config, tools-list, registry, otel-span, k8s-aibom, sbom, model-manifest, agent-card`), path/JSON Pointer, collector name@version, RFC 3339 | any |
| `agentbom:snapshot:digest`, `:serial`, `:prior`, `:state`, `:valid-from`, `:valid-until` | `sha256:…`, int, `sha256:…`, state, timestamps | metadata.properties |
| `agentbom:merkle:root` / `agentbom:merkle:leaf` | `sha256:…` | metadata.properties / each component |
| `agentbom:companion:ref`, `agentbom:companion:digest` | `urn:uuid`, `sha256:` | metadata.properties |
| `agentbom:coverage:<surface>`, `agentbom:coverage:window`, `agentbom:coverage:truncation` | `covered, partial, not-covered, unknown`; `from/to`; `components-dropped:<n>` | metadata.properties |
| `agentbom:redaction:applied` | redaction class (`env-secret, header-secret, instruction-body, url-credential`) | any |
| `agentbom:trust:status`, `:issuer`, `:since`, `:reason` | `allowlisted, quarantined, revoked, unknown` | any |
| `agentbom:agent:framework`, `:framework-version`, `:purpose`, `:owner`, `:operator`, `:automation-level`, `:entrypoint`, `:deployment:environment`, `:deployment:tenant`, `:deployment:instance-id`, `:deployment:deployed-at` | str; automation = ISO 22989 names (`notAutomated … autonomous`) | agent |
| `agentbom:mcp:client`, `:transport`, `:command`, `:args-digest`, `:url`, `:env-var-names`, `:header-names`, `:auth-mode`, `:pinned`, `:config-path`, `:protocol-version`, `:server-name`, `:server-version`, `:toolset-digest`, `:instructions-digest`, `:trust-zone`, `:client-trust` | see §1.4 | mcp-server service |
| `agentbom:tool:server-ref`, `:definition-digest`, `:definition-digest-source`, `:description-digest`, `:input-schema-digest`, `:annotation:read-only`, `:annotation:destructive`, `:annotation:idempotent`, `:annotation:open-world`, `:side-effect-class`, `:capability:<i>`, `:approval-gate`, `:state` | bom-ref; `sha256:`; `served, approved-file, registry, config`; `true/false/unspecified`; enums §1.4 | tool |
| `agentbom:skill:name`, `:skill-md-digest`, `:dir-digest`, `:allowed-tools`, `:compatibility`, `:file-count`, `:script-count` | | skill |
| `agentbom:instruction:kind`, `:path`, `:bytes`, `:precedence`, `:editable-by:<i>`, `:secret-like-redacted` | | instruction |
| `agentbom:prompt:engine`, `:role`, `:variables-schema-digest` | | prompt-template |
| `agentbom:model:kind`, `:provider`, `:requested-ref`, `:resolved-ref`, `:alias-pinning`, `:resolution:method`, `:resolution:resolved-at`, `:resolution:signer`, `:resolution:log-entry`, `:manifest-format`, `:manifest-root`, `:serialization:format:<i>`, `:serialization:risk`, `:trust-remote-code`, `:chat-template-digest`, `:tokenizer-digest`, `:generation-config-digest`, `:derivation:<i>:type`, `:derivation:<i>:parent`, `:derivation:<i>:parameters-digest`, `:signature:status`, `:signature:outcome`, `:signature:identity`, `:signature:issuer`, `:signature:rekor-entry`, `:signature:reason`, `:fingerprint:method`, `:fingerprint:digest`, `:fingerprint:expires` | enums §1.3 | model |
| `agentbom:data:kind`, `:trust-tier`, `:instruction-bearing`, `:sanitization:<i>`, `:snapshot:commitment`, `:snapshot:method`, `:snapshot:at`, `:live`, `:embedding-model`, `:chunking-digest`, `:writers:<i>`, `:retention`, `:isolation`, `:acl-mode` | enums §1.5 | data |
| `agentbom:identity:<i>:kind`, `:issuer`, `:principal`, `:binding`, `:lifetime` | enums §1.6 | agent/tool/service |
| `agentbom:authz:<i>:subject`, `:capability`, `:scope`, `:granter`, `:delegation-chain`, `:approval-gate`, `:valid-until`, `:policy-digest`, `:enforcement-point`, `:credential-binding`, `:source` | enums §1.7 | subject |
| `agentbom:flag:<name>` | `true` + `agentbom:flag:<name>:inputs` (bom-refs) | agent |
| `agentbom:registry:name`, `:url`, `:entry-name`, `:entry-version`, `:publisher`, `:publisher-verification`, `:status`, `:published-at`, `:is-latest`, `:record-digest`, `:resolved-at` | §1.9 | component/service |
| `agentbom:vex:justification`, `agentbom:vex:scope:model-digest`, `agentbom:vex:scope:config-digest`, `agentbom:vex:expires` | §1.8 | vulnerabilities[].properties |
| `agentbom:edge:<i>:type`, `:to`, `:scope`, `:state`, `:assurance` | §1.11 (only for edge types `dependsOn` cannot express: `delegates-to, acts-as, writes-memory-to, reads-context-from, configures`) | from-component |
| `symbiote:version`, `symbiote:scan:started-at`, `symbiote:scan:root`, `symbiote:collector:<name>:version`, `symbiote:collector:<name>:status`, `symbiote:level:claimed`, `symbiote:level:validated`, `symbiote:score` | | metadata.properties |

### 2.4 Companion AgentBOM document

Media type `application/vnd.agentbom+json`, `$schema: https://agentbom.dev/schema/agentbom-0.1.schema.json` (A-2: `agentbom.dev` to be registered; the schema is also served from the repo and vendored in the wheel so validation is offline). It is the JSON serialization of §1 generated from the Pydantic models (`AgentBOM.model_json_schema()` post-processed to Draft 2020-12). Linkage: CDX `externalReferences[{type:"bom", url:"urn:uuid:<companion-id>", hashes:[sha256]}]` + `agentbom:companion:*`; companion `links.cyclonedx={serialNumber, version, digest}`. **Embedded fallback:** with `--embed-records` (default at Standard+), every structured record that has no native CDX home (authorization, identity, coverage detail, evaluation, resolution) is also carried inside the CDX document as `declarations.evidence[].data[].contents.attachment` (`contentType: application/vnd.agentbom.record+json`, base64 of the JCS bytes, `propertyName` = record kind). A CDX file is then self-contained and round-trips losslessly without the companion.

### 2.5 What cannot be represented natively (divergence register seed)

D-001 agent/tool/instruction kinds via `agentbom:kind` (no component types); D-002 `modelCard.properties` JSON/XML asymmetry; D-003 identities and authorizations have no native object (properties + records); D-004 edge semantics beyond `dependsOn/provides` (`agentbom:edge:*`); D-005 per-attribute assurance (citations + properties); D-006 AI threats in `vulnerabilities[]` with `source` = OWASP/ATLAS and `ratings.method=other`; D-007 `stdio:` URI scheme for stdio endpoints; D-008 runtime assembly events in `formulation` with `taskTypes: ["other"]`; D-009 `data.type: definition` for tool definitions. Each links CycloneDX/specification#990 (2.0 declared-behaviour model) as upstream path.

---

## 3. SPDX 3.0.1 mapping (R2)

### 3.1 Mapping table

| Model entity | SPDX 3.0.1 class | Relationships | Facts carrier |
|---|---|---|---|
| Document | `SpdxDocument` (`profileConformance: core, software, ai, dataset, extension, security`), `CreationInfo{createdBy: SoftwareAgent "symbiote", createdUsing: Tool "symbiote@<ver>"}` (the bindings enforce `createdBy` is an `Agent`; verified) | `describes`/`rootElement` → agent | `CdxPropertiesExtension` with `agentbom:snapshot:*`, `agentbom:coverage:*`, `agentbom:companion:*` |
| `Agent` | `software_Package` (`primaryPurpose: application`) | `invokedBy` → identity `SoftwareAgent`/`Person`; `delegatedTo` from granter `Agent` to that `invokedBy` relationship (A2A) | `agentbom:kind=agent`, `agentbom:agent:*` |
| `ToolServer` | `software_Package` (`primaryPurpose: application`, `downloadLocation` = url or purl location) + `ExternalIdentifier(urlScheme)` for endpoint; 3.0.1 has no Service class | `contains` → tools | `agentbom:mcp:*` |
| `Tool` | `software_Package` (`primaryPurpose: other`), `verifiedUsing: Hash(sha256 = definition digest, comment "agentbom:tool:definition-digest")` | agent `usesTool` tool, `LifecycleScopedRelationship(scope=runtime)` | `agentbom:tool:*` |
| `Skill` | `software_Package` `contains` `software_File` (SKILL.md, scripts) | agent `dependsOn` skill (runtime) | `agentbom:skill:*` |
| `Instruction`, `PromptTemplate`, policy | `software_File` with `verifiedUsing` hash | file `configures` agent (runtime) | `agentbom:instruction:*` |
| `Model` | `ai_AIPackage` (`primaryPurpose: model`; hosted: `downloadLocation` = provider endpoint, `packageVersion` = resolved snapshot or requested alias with `agentbom:model:alias-pinning=floating`; `suppliedBy` provider `Organization`; `releaseTime`) + `software_packageUrl` for HF purl; `ai_autonomyType: noAssertion` (kept for 3.0.1 validity; see 3.1 notes) | agent `dependsOn` model (runtime); derivations `descendantOf`/`hasVariant` + `agentbom:model:derivation:*` | `agentbom:model:*`; AI profile fields filled where known (`typeOfModel`, `domain`, `safetyRiskAssessment` from evaluations) |
| `DataSource` | `dataset_DatasetPackage` (`datasetType`, `datasetUpdateMechanism` for live sources, `confidentialityLevel`, `datasetAvailability`, `hasSensitivePersonalInformation`) | agent `dependsOn` (runtime); index `descendantOf` source; index `dependsOn` embedding model (build); memory `modifiedBy` writer `Agent` | `agentbom:data:*` |
| `Identity` | `SoftwareAgent` (workload/service account), `Person` (OBO user), `Organization` | as above | `agentbom:identity:*` |
| `RegistryEntry` | `Organization` (registry operator) + `ExternalRef(type: altDownloadLocation|other)` | component `availableFrom` registry | `agentbom:registry:*` |
| `Evidence`, `Evaluation` | `Annotation` (`annotationType: review`, statement) + `ExternalRef` (`securityThreatModel`, `dynamicAnalysisReport`, `securityPenTestReport`, `riskAssessment`, `runtimeAnalysisReport`) | element `hasEvidence` evidence element | |
| `RiskStatement` | `security_Vulnerability` (`externalIdentifier type: securityOther`, id = ATLAS/ASI id) + `security_VexNotAffectedVulnAssessmentRelationship` (`justificationType` ∈ `inlineMitigationsAlreadyExist` (guardrail), `vulnerableCodeNotInExecutePath` (tool disabled / approval), `vulnerableCodeCannotBeControlledByAdversary` (not reachable), `componentNotPresent`; `impactStatement`) or `VexAffected…` | `doesNotAffect` / `affects` | `agentbom:vex:*` |
| `Coverage` | `RelationshipCompleteness` on each relationship (`complete | incomplete | noAssertion`) + extension properties | | |
| `TrustStatus`, `Redaction`, flags | extension properties; `Annotation` for human statements | | |
| Signature | none native; DSSE over emitted bytes (subject digest = sha256 of the serialized JSON-LD) | | |

**IRI scheme.** `https://agentbom.dev/ns/<document-uuid>/<kind>/<slug>` (A-2), overridable with `--spdx-namespace`. The slug equals the CDX `bom-ref`, so `bom-ref ↔ spdxId` conversion is a pure function and needs no mapping table. `CreationInfo` is a blank node (`_:CreationInfo0`), as the bindings emit.

**Custom extension class.** A dedicated `AgentBomRecordExtension` (IRI `https://agentbom.dev/spdx/ext/0.1/AgentBomRecordExtension`, fields `recordType`, `recordDigest`, `record` JSON string) is specified in `spec/spdx-extension.md` but **disabled by default** until WP04 proves the official JSON schema accepts non-SPDX extension types via `SHACLExtensibleObject`; v0.1 carries structured records through the companion document and `CdxPropertiesExtension` scalars only (open question Q3).

### 3.2 SPDX 3.1 forward notes (verified against the `develop` branch model files)

Verified: IRIs change to two-level versioning (`https://spdx.org/rdf/3.1/terms/`); `ai_autonomyType` is deprecated in favour of Core `isoAutomationLevel` with the 7-level ISO/IEC 22989 vocabulary (`notAutomated, assistiveAutomation, partialAutomation, conditionalAutomation, highAutomation, fullAutomation, autonomous`) — our `agentbom:agent:automation-level` uses the same names so the 3.1 exporter maps it 1:1; `AIPackage`/`DatasetPackage` required-field constraints are relaxed (hosted models lose the awkward mandatory `downloadLocation`); `RelationshipType` grows from 59 to 76 with `finetunedOn`, `pretrainedOn`, `evaluatedOn`, `validatedOn`, `verifiedBy`, `performedBy`, `runsOn`, `hasInstance`, `conformsTo`, `implementedBy`, `locatedAt`, `resolved`/`hasResolution`, `createdBy`, `assumes`, `follows`/`followsProcess`, `hasRoleIn`, `tracedToDetail`; new profiles `Operations`, `Service`, `Hardware`, `SupplyChain`; a Core `Action` class (abstract, `startTime/endTime`). Forward map: `derived-from(fineTuneOf) → finetunedOn`; `Evaluation → evaluatedOn/validatedOn/verifiedBy`; `approved-under → conformsTo`; `ResolutionRecord → resolved/hasResolution`; `ToolServer → Service profile class`; deployment instance → `hasInstance`/`runsOn`; observed invocation → `Action` subclass. **Not verified** (404 in `develop` at design time): `AIAgent`, `Prompt`, `RAG` classes — Phase 1 must confirm before any mapping claims them (Q2).

---

## 4. Conversion loss model and round-trip strategy (R3)

Every exporter and importer returns `(document, LossReport)`. `LossReport = {direction, source_format, target_format, items[{path, entity, field, reason, fallback, severity}], lossless: bool, retained_ratio}` with `reason ∈ {no-native-construct, enum-narrowed, precision-lost, cardinality-collapsed, unsupported-in-target-version, redacted, library-limitation}` and `fallback ∈ {property, companion, embedded-record, dropped}`. `symbiote convert --loss-report` prints it as a table and writes `<out>.loss.json`; `severity ≥ high` items (anything under the authorization or assurance planes) make the CLI exit 1 unless `--allow-lossy`.

Strategy: the Pydantic model is canonical; **model → CDX → model** is lossless when the companion is present or records are embedded (golden tests assert equality modulo ordering); **model → SPDX → model** is lossless for every scalar (via `CdxPropertiesExtension`, whose entries are byte-identical to CDX properties) and for relationships, and lossy for `services` endpoint semantics, `compositions` detail and `declarations.attestations` structure unless the companion is linked (reported). **CDX 1.5/1.6 import** (k8s-aibom, cdxgen AI-BOMs) parses raw JSON validated against the vendored schema for its `specVersion`, maps known property namespaces (`aibom.*`, `k8s-aibom:*`, `cdx:*`, `harness-aibom:*`) through a translation table, and keeps unknown properties verbatim under `foreign_properties` so re-export never silently drops them — the library-level import path was rejected after `Bom.from_json` dropped `modelCard` in a probe. **Downgrade profiles** for sinks: `--cdx-version 1.6` for Dependency-Track (drops `citations`, `patentAssertions`; reports them), keeping `declarations` (1.6 has them).

---

## 5. Collectors (R9) — the self-writing layer

Collectors implement `symbiote.collectors.base.Collector` (`name`, `version`, `surfaces`, `detect(root) -> bool`, `collect(ctx) -> CollectorResult{entities, edges, evidence, coverage_fragment, redactions}`) and are registered through the `symbiote.collectors` entry-point group so third parties can ship plugins. `symbiote scan` runs every collector whose `detect()` fires, in parallel, with a per-collector time budget (default 20 s; whole scan target < 60 s on a typical repo) and writes `symbiote:collector:<name>:status`. Every fact a collector emits carries `assurance`, `evidence.source` and `evidence.locator` (file path + JSON Pointer / TOML key path / line number). Secrets are never read into entities: env-var and header *names* are kept, values replaced and recorded in `redactions[]`.

| Collector | Inputs (exact) | Parsing rules | Output / assurance |
|---|---|---|---|
| `mcp-config` | Claude Code `.mcp.json` (project), `~/.claude.json` (user scope), Claude Desktop `claude_desktop_config.json`; Cursor `.cursor/mcp.json`, `~/.cursor/mcp.json`; VS Code `.vscode/mcp.json` (`servers`, `inputs`), user `mcp.json`; Windsurf `~/.codeium/windsurf/mcp_config.json`; Codex `~/.codex/config.toml`, `.codex/config.toml`; Gemini CLI `.gemini/settings.json`, `~/.gemini/settings.json` | JSON (`json`), TOML (`tomllib`). Server maps: `mcpServers` (Claude/Cursor/Windsurf/Gemini), `servers` (VS Code), `[mcp_servers.<name>]` (Codex). Transport: `command` present → `stdio`; else `type` if present (`http|sse|stdio`), else `httpUrl` → `streamable-http`, `url`/`serverUrl` ending `/sse` → `sse`, otherwise `streamable-http`. Package purl from first positional after `npx [-y]` (`pkg:npm/<name>@<ver>`), `uvx` (`pkg:pypi`), `docker run … <image>` (`pkg:oci`), `dnx` (`pkg:nuget`); `pinned = version/tag/digest present` (`@1.2.3`, `==1.2.3`, `@sha256:`); `${VAR}`/`${input:id}`/`${env:VAR}` placeholders kept as names. Gemini `trust`, `includeTools`, `excludeTools`, `timeout`, `cwd`; Codex `bearer_token_env_var`, `approval_policy`, `sandbox_mode` → `approval_gate`/sandbox facts. Verified by sample parsing of all six formats (Appendix B); VS Code/Codex/Windsurf field lists beyond those confirmed are A-7. | `ToolServer` (declared), `Tool` only when the client config enumerates tools (`includeTools`); `edges uses-tool` declared; `Identity(api-key-ref)` from env/header names. |
| `mcp-live` (`--live`) | Servers from `mcp-config` or `symbiote observe --mcp <config|url>`; `mcp` SDK 2.3.0 `stdio_client(StdioServerParameters)` / `streamable_http_client(url)` / `sse_client(url)`; `ClientSession.initialize()` + `list_tools()` (paginated) | Builds `Tool` from `types.Tool` using wire aliases (`model_dump(by_alias=True, exclude_none=True)`), computes definition digests (§6.2) and the toolset digest; records `protocol_version`, `server_info`, `instructions`. Timeout 15 s/server; failures → coverage `tools: partial` with reason. Live probe verified end-to-end against a local `MCPServer` in 1.2 s (Appendix B). Opt-in because it executes server commands (documented risk; `--live-allow <name>` allowlist). | `ToolServer.served`, `Tool` (observed, `state=served`), evidence kind `tools-list`. |
| `skills` | Any `*/SKILL.md` under `.claude/skills/`, `skills/`, `.agents/skills/`, plugin dirs; Agent Skills spec frontmatter `name, description, license, compatibility, metadata, allowed-tools` | Regex split `^---\n(.*?)\n---\n` + `yaml.safe_load`; `name` must match directory (finding `AB-SKILL-001` otherwise); directory manifest = sorted `{path, sha256}` over all files (respecting `.gitignore` via `pathspec`, excluding `.git`); `allowed-tools` tokenized by whitespace into capability hints (`Bash(...)` → `execute`). | `Skill`, nested `Instruction(kind=skill-body)`, scripts as files; declared. |
| `instructions` | `CLAUDE.md`, `.claude/CLAUDE.md`, `~/.claude/CLAUDE.md`, `AGENTS.md`, `.cursor/rules/*.mdc`, `.cursorrules`, `.github/copilot-instructions.md`, `.windsurfrules`, `GEMINI.md`, `.codex/AGENTS.md`, `.claude/settings.json` hooks, `prompts/**/*.{md,txt,j2,jinja,yaml}`, framework-declared system prompts | Exact-bytes SHA-256; `precedence` from scope (user=3, project=2, directory=1); Jinja templates (`{{ … }}`/`{% %}`) → `PromptTemplate(engine=jinja2)` with sibling `*.schema.json` as variable schema; secret-like patterns (`sk-`, `AKIA`, `-----BEGIN`) set `contains_secret_like` and are never echoed. | `Instruction`, `PromptTemplate`; declared. |
| `a2a-cards` | `/.well-known/agent-card.json` (fetched only with `--live`), local `agent-card.json`/`agent.json` | Fields: `name, description, url/supportedInterfaces[{url, protocolBinding, protocolVersion}], provider, capabilities{streaming, pushNotifications, extendedAgentCard, extensions[]}, securitySchemes, security, skills[{id, name, description, tags, inputModes, outputModes}], signatures[]` (verified from spec text). Card digest = JCS over card minus `signatures`; JWS signatures recorded (`signature.status=claimed`, verified only with a configured JWKS). | remote `Agent(is_subagent)` + `Service` + `Authorization(delegation_chain)`; declared/observed. |
| `mcp-registry` (`--registry`) | `GET https://registry.modelcontextprotocol.io/v0.1/servers/{name}/versions/latest` and `/versions` (API path verified); `server.json` (`$schema 2025-12-11`: `name, title, description, version, remotes[{type,url}], packages[{registryType, identifier, version, transport, environmentVariables[]}]`, `_meta["io.modelcontextprotocol.registry/official"]{status, publishedAt, updatedAt, isLatest}`) | Match by `packages[].identifier` or `remotes[].url` against configured servers; `record_digest` = JCS of `server` object; `publisher_verification` inferred from namespace (`io.github.*` → github-oauth/oidc, reverse-DNS → dns/http) else `unknown`; no attestation fields exist → `attestation_ref=unknown`. | `RegistryEntry`, `ResolutionRecord`; observed. |
| `models-local` (`[models]` extra) | Model directories (`config.json`, `*.safetensors`, `*.bin`, `*.pt`, `*.gguf`, `*.onnx`, `tokenizer.json`, `tokenizer_config.json` → `chat_template`, `generation_config.json`, `adapter_config.json`), existing `model.sig` OMS bundles | Per-file SHA-256 → OMS-compatible manifest (`model_signing.hashing` for sharded files); Merkle root §6.3; serialization by extension + magic bytes (`\x80\x04` pickle, `GGUF`, `ONNX` protobuf, safetensors header); `trust_remote_code` from `config.json.auto_map`; `adapter_config.json.base_model_name_or_path` → `adapterOf`; quantization from `quantization_config`; `model.sig` → verify with `model_signing.verifying` when trust root configured else `claimed`. | `Model(local)`; declared→verified. |
| `models-hosted` | Framework configs, `.env*` names, code constants: provider SDK model strings (`anthropic.*`, `openai.*`, `bedrock` model ids `anthropic.claude-…-v1:0`, Vertex `publishers/*/models/*`, Azure deployment names) | Provider rule table (`symbiote/collectors/providers.yaml`): regex for alias vs dated snapshot (`claude-sonnet-4-5` floating vs `claude-sonnet-4-5-20250929` pinned; `gpt-4o` vs `gpt-4o-2024-08-06`; Bedrock ids pinned by `:0` suffix) → `alias_pinning`; with `--live` and credentials, provider list-models endpoints fill `resolved_ref` (A-8). | `Model(hosted)` + `Service`; declared/observed. |
| `frameworks` | LangGraph `langgraph.json` (`graphs`, `dependencies`, `env`), CrewAI `agents.yaml`/`tasks.yaml` (`role, goal, llm, tools`), OpenAI Agents SDK (`Agent(name=, instructions=, tools=, handoffs=, model=)` via AST), Claude Agent SDK (`ClaudeAgentOptions(system_prompt=, allowed_tools=, mcp_servers=, permission_mode=)` via AST), AutoGen (`config_list`, `AssistantAgent(system_message=)`), Semantic Kernel (`*.yaml` prompt templates with `execution_settings`, plugin dirs) | YAML/JSON/TOML parsers plus a conservative Python AST visitor (no execution) for literal kwargs; non-literal values → `unknown` with locator. Extracts agents, sub-agents (`handoffs`), tool lists, model refs, system prompts (digest of literal), permission modes → `approval_gate`. | `Agent`, `Instruction`, `uses-tool`, `delegates-to`; declared. |
| `sbom-merge` | `--sbom <cdxgen|syft CycloneDX JSON>` or auto-detected `bom.json`/`sbom.cdx.json`; optionally shells out to `cdxgen -o` / `syft -o cyclonedx-json` when installed and `--run-sbom` | Imported through the CDX importer; components kept verbatim (purl, hashes, evidence, `cdx:*` properties) under `agentbom:kind` absent (= software), linked `agent dependsOn` top-level components; cdxgen AI-BOM `ai`/`mcp` components (`cdx:ai:*`, `cdx:mcp:*` namespaces exist in cdxgen docs) are mapped to our kinds via the translation table. | software layer; assurance from source evidence. |
| `k8s-aibom` | `symbiote import k8s-aibom <bom.json>` or `--kubectl` (`kubectl get aibom -n <ns> -o json` → `status.bomDocument.inline.data` base64, `status.bomHash`, `status.summary.confidence`, `status.conditions`; CRD shape verified) | CDX 1.6 import + §1.12 confidence mapping; `k8s-aibom:workload:*`/`aibom.workload.*` → `Agent.deployment.workload_ref`; `security:signing:*` → `Model.signature`; `redaction.applied`/`truncation.applied` → `redactions`/coverage. | observed snapshot (`state=deployed`). |
| `otel-traces` | OTLP/JSON span files (`ResourceSpans`), Jaeger/Tempo JSON exports; GenAI semconv attributes `gen_ai.operation.name ∈ {execute_tool, invoke_agent, chat, …}`, `gen_ai.tool.name`, `gen_ai.tool.type`, `gen_ai.tool.call.id`, `gen_ai.tool.definitions`, `gen_ai.agent.name/id`, `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.provider.name`, `gen_ai.conversation.id`, `gen_ai.data_source.id`, `gen_ai.memory.store.id`, `gen_ai.skill.name`, `gen_ai.skill.source.uri`, `gen_ai.system_instructions`; MCP semconv `mcp.method.name`, `mcp.session.id`, `mcp.protocol.version`, `server.address`, `network.transport` (attribute names verified) | `execute_tool` spans → `Tool(state=invoked)` + `invokes` edges with counts and time window; `gen_ai.tool.definitions` → served definition digests when present; `gen_ai.response.model` ≠ `gen_ai.request.model` → `Model.resolved_ref` evidence (and `routes-to-model` observed); memory/data-source ids → `DataSource(observed)`; `gen_ai.system_instructions` hashed, never stored. | observed snapshot; evidence kind `otel-span`. |

Zero-config `symbiote scan .` runs `mcp-config, skills, instructions, frameworks, models-hosted, models-local, sbom-merge` (all offline) and reports the rest as `not-covered` with the flag that enables them.

---

## 6. Digests, canonicalization, identity (R4)

### 6.1 Canonical JSON

All structural digests are `sha256:` + hex over **RFC 8785 (JCS)** bytes produced by `rfc8785.dumps` (0.1.4; verified sorting and number formatting). Rules: strip `null` members before canonicalizing; never include generated identifiers (`id`, timestamps of emission, `snapshot.digest`, `merkle_root`, `links`) in the digest input; strings are NFC-normalized **only** where the upstream format is text we author (prompt templates); everything collected from the wire or disk is hashed as received. Document snapshot digest = JCS over the companion document with the excluded members nulled.

### 6.2 Tool-definition, instruction, skill and policy digests

`tool_definition_digest = sha256(JCS({name, title?, description?, inputSchema, outputSchema?, annotations?}))` using MCP wire field names (camelCase), `exclude_none`, and **excluding** `_meta`, `icons` and `execution` (presentation/runtime hints the model does not read; recorded as D-010). Sub-digests: `description_digest = sha256(utf8(description))`, `input_schema_digest = sha256(JCS(inputSchema))`. `toolset_digest = sha256(JCS(sorted(definition digests)))`. Live probe: `get_issue` → `sha256:99b79a66…`, toolset `sha256:42bf32a4…` (Appendix B). **Instruction digest** = SHA-256 of exact bytes (no newline or encoding normalization), recorded with `bytes`. **Skill/directory digest** = `sha256(JCS([{path, sha256}…]))` over files sorted by POSIX path (UTF-8, byte order), symlinks hashed as their target path string, `.git` excluded. **Prompt template digest** = SHA-256 of template bytes; `variables_schema_digest` = JCS of the JSON Schema. **Policy bundle digest** = directory digest of the Rego/OPA bundle or `sha256` of a single policy file; **agent card digest** = JCS of the card minus `signatures`.

### 6.3 Model identity manifest

`ModelManifest = {format: "oms-v1", items: [{path, digest: {sha256}, size?, shard?}…] sorted by path, merkle_root}`. Items are byte-compatible with OpenSSF model-signing `FileManifestItem` (and `ShardedFileManifestItem` for `file_shard` hashing, 1 GiB shards by default) so an existing `model.sig` DSSE bundle's in-toto subjects (`name=path`, `digest.sha256`) can be compared item-for-item (format verified from the model-transparency docs). `merkle_root` = RFC 6962-style binary tree over leaves `sha256(0x00 || JCS(item))`, pairs hashed as `sha256(0x01 || L || R)`, odd node promoted — identical construction to §6.5 so one verifier serves both. Behavioural derivation edges carry `parameters_digest = sha256(JCS(parameters))` (e.g. `{method:"lora", r:16, alpha:32, target_modules:[…]}`).

### 6.4 Name-resolution record

`ResolutionRecord = {requested_ref, registry/provider, resolved_ref, resolved_digest, resolved_at, method ∈ {registry-api, provider-api, local-manifest, lockfile, config-literal, unknown}, signer{identity, issuer} | null, transparency{log, entry, inclusion_verified: bool} | null, verifier{name, version, trust_root}}`. Recorded for every externally sourced component (models, MCP packages, skills from marketplaces, registry entries). `alias_pinning = pinned` iff `resolved_ref` is immutable (commit SHA, dated snapshot, OCI digest, registry version with `isLatest` irrelevant); `floating` when only a mutable name is known; `unknown` when the provider offers no snapshot identity, in which case Verified level requires a `fingerprint` claim with `expires ≤ 30 days` (A-9).

### 6.5 Merkle-committed BOM and verifiable redaction (R11)

Leaves are `sha256(0x00 || JCS(entity_without_emission_ids))` for every entity, authorization, evidence, evaluation, risk statement, trust status and the coverage object, ordered by `(kind, id)`; the root is published as `merkle_root` / `agentbom:merkle:root` and is the primary signed subject. `symbiote redact --profile external` removes or masks entities (classes: `env-secret`, `instruction-body`, `internal-endpoint`, `identity-principal`, `tool-schema`) and replaces each removed leaf with `{redacted: true, class, leaf_hash, proof: [sibling hashes]}` in `redactions[]`; `symbiote verify --against-root <sha256|signed-attestation>` recomputes the root from retained entities plus redacted leaf hashes and fails on mismatch. Redaction is therefore recorded, never silent, and a consumer with only the public view can still verify it against the signed root.
