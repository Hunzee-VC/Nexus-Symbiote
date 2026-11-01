# CycloneDX 1.7 mapping

Symbiote emits CycloneDX 1.7 JSON directly (ADR-0003) using **only** sanctioned constructs. Every fact is
encoded at the highest rung of this ladder that fits: (1) a native field with matching semantics; (2) a native
structure narrowed by a property qualifier; (3) an `agentbom:` property with a closed vocabulary
(`taxonomy.md`); (4) the companion document (`companion.md`), linked by digest. Rungs 3–4 always have an
entry in `divergences.md`. Output MUST validate against the vendored official `bom-1.7.schema.json`.

## 1. Document header
| Model | CycloneDX 1.7 | Notes |
|---|---|---|
| `snapshot.digest` | `serialNumber` = `urn:uuid:` UUIDv5(`6f9b2d3e-5c1a-4f0e-9b7a-2e1c3d4f5a6b`, `snapshot.digest`) | content-addressed BOM identity; BOM-Link `urn:cdx:<uuid>/<version>#<bom-ref>` works natively |
| `snapshot.serial` | `version` | monotone |
| `snapshot.produced_at` | `metadata.timestamp` | pinned under `--deterministic` |
| `snapshot.kind` | `metadata.lifecycles[]`: `{"phase":"design"}` (declared), `{"phase":"post-build"}` (approved), `{"phase":"operations"}` (deployed), `{"phase":"discovery"}` (observed) **plus** `{"name":"agentbom:snapshot:<kind>","description":...}` | the named lifecycle is authoritative; phases are the closest native approximation |
| `snapshot.*` | `metadata.properties`: `agentbom:snapshot:kind`, `:serial`, `:prev`, `:digest`, `:not-before`, `:not-after`, `:observation-start`, `:observation-end` | |
| `snapshot.prev` | `externalReferences[]{type:"bom", url:"urn:cdx:<prior uuid>/<prior serial>", hashes:[prior digest], comment:"agentbom:prior-snapshot"}` | native BOM-Link |
| `producer`, `coverage.collectors` | `metadata.tools.components[]` (`type:"application"`, `name`, `version`, `hashes?`) | symbiote + each collector |
| `subject` (root agent) | `metadata.component` (`type:"application"`, `bom-ref: agent:<slug>`) | §2 |
| `merkle` | `metadata.properties`: `agentbom:merkle:root`, `agentbom:merkle:leaf-count`, `agentbom:merkle:algorithm = rfc6962-sha256-salted` | |
| companion link | `metadata.component.externalReferences[]{type:"other", url:<companion uri or urn:uuid>, hashes:[sha256], comment:"agentbom-companion"}` + `metadata.properties` `agentbom:companion:ref`, `agentbom:companion:digest`, `agentbom:companion:schema` | bidirectional by digest |
| derived flags | `metadata.properties` `agentbom:flag:<name>` (`true|false|unknown`) and repeated `agentbom:flag:<name>:input` (bom-refs); `declarations.claims[]{target: <subject>, predicate: "agentbom:flag:<name>=<value>", reasoning, evidence[]}` | consumers can recompute from cited inputs |
| coverage | `compositions[]` one per surface (`aggregate: complete|incomplete|unknown`, `assemblies: [bom-refs in that surface]`) + one document-level entry; `metadata.properties` `agentbom:coverage:<surface>` and `agentbom:coverage:window-start|window-end`; `formulation[0].workflows[0]` = the collection run (one task per collector with `taskTypes:["other"]`, `inputs/outputs`, properties `agentbom:coverage:surface|status|items-seen|truncated-at|permission-failure|source`) | formulation = "how this BOM was assembled" |
| redactions | `metadata.properties` `agentbom:redaction:applied` (one per class) | plus on each affected element |
| provenance of generator | `symbiote:version`, `symbiote:scan:root`, `symbiote:collector:<name>:status|version` | never semantic facts |

## 2. Entities
| Entity | Construct | Native fields | Properties (see `taxonomy.md`) |
|---|---|---|---|
| Agent (root) | `metadata.component` `type:"application"` | `name`, `version`, `description` (purpose), `supplier` (owner), `manufacturer` (operator), `externalReferences` (`vcs`, `documentation`, `other` for A2A card with hashes) | `agentbom:kind=agent`, `agentbom:agent:*` |
| Agent (sub/external) | `components[]` `type:"application"` | same | `agentbom:kind=sub-agent|external-agent` |
| Deployment | properties on the agent | — | `agentbom:deployment:*` |
| ToolServer | `services[]` | `bom-ref`, `name`, `group` (registry namespace or client), `version` (server_info), `provider`, `endpoints[]` (URL; none for stdio), `authenticated`, `x-trust-boundary`, `trustZone`, `data[]{flow, classification, source[], destination[]}`, `externalReferences`: `configuration` (`file://.mcp.json#/mcpServers/<name>`), `distribution` (package), `distribution-intake` (registry record URL, `hashes` = record digest), `documentation`, `attestation` | `agentbom:kind=mcp-server|a2a-agent|openapi-service|builtin`, `agentbom:mcp:*`, `agentbom:registry:*`, `agentbom:resolution:*` |
| ToolServer stdio package | `components[]` `type:"application"` with `purl`, `hashes` | linked `dependencies[]{ref:<service>, dependsOn:[<package>]}` | `agentbom:kind=mcp-package`, `agentbom:mcp:pinned` |
| ToolDefinition | `components[]` `type:"data"`, `data[0].type:"definition"` | `bom-ref: tool:<server>/<name>`, `name` = tool name, `group` = server id, `hashes[{alg:"SHA-256", content:<tooldef digest>}]`; `description` and `data[0].contents.attachment` (base64 JCS envelope, `contentType: application/json`) only with `--include-text` | `agentbom:kind=tool`, `agentbom:tool:*` |
| server → tools | `dependencies[]{ref:<service bom-ref>, provides:[<tool bom-refs>]}` | a tool contract is a specification the server implements | D-004 |
| Instruction | `components[]` `type:"file"` | `name` = basename, `hashes` (exact bytes), `mime-type`, `externalReferences[vcs]`; `data[]{type:"configuration", classification:"instruction-bearing"}` | `agentbom:kind=instruction`, `agentbom:instruction:*` |
| PromptTemplate | `components[]` `type:"file"` | `hashes` (template bytes); variable schema as nested `type:"data"/definition` component | `agentbom:kind=prompt-template`, `agentbom:prompt:*` |
| Skill | `components[]` `type:"library"`, `group:"skills"` | `hashes` = dirmanifest root; nested `components[]` `type:"file"` for `SKILL.md` and scripts (`hashes`) | `agentbom:kind=skill`, `agentbom:skill:*` |
| Model (weights) | `components[]` `type:"machine-learning-model"` | `purl` (`pkg:huggingface/<ns>/<name>@<commit>`, `pkg:oci/...`, `pkg:mlflow/...`), `hashes` = manifest root, `supplier`, `modelCard.modelParameters{task, architectureFamily, modelArchitecture, approach, datasets[]}`, `modelCard.considerations.*`, `modelCard.quantitativeAnalysis.performanceMetrics[]`, `pedigree.ancestors[]` (parents as `machine-learning-model` components carrying `agentbom:derivation:*`), `externalReferences`: `model-card`, `attestation` (model-signing bundle, `hashes`), `distribution`; nested `type:"file"` components per weight/tokenizer/template file with `--model-files` | `agentbom:kind=model`, `agentbom:model:*`; **never** `modelCard.properties` |
| Model (hosted) | `components[]` `type:"machine-learning-model"`, `isExternal:true` | `name` = requested alias, `version` = resolved snapshot (absent if unknown), `supplier` = provider; endpoint as `services[]` (`endpoints`, `authenticated`, `x-trust-boundary`, `trustZone`, `provider`, `data[]`); `dependencies[]{ref:<model>, dependsOn:[<endpoint service>]}` | `agentbom:kind=model`, `agentbom:model:kind=hosted`, `agentbom:model:alias-pinning`, `agentbom:model:resolution:*`, `agentbom:model:fingerprint:*` |
| DataSource | `components[]` `type:"data"` | `data[]{type: dataset|configuration|other, name, classification, governance{owners,custodians,stewards}, sensitiveData[], contents.url}`, `hashes` = snapshot commitment | `agentbom:kind=dataset|rag-index|memory-store|retrieval-connector|knowledge-plugin|live-feed`, `agentbom:data:*` |
| Policy | `components[]` `type:"data"`, `data[].type:"configuration"` | `hashes` = bundle digest | `agentbom:kind=policy-bundle`, `agentbom:policy:*` |
| Identity / CredentialBinding | properties on the subject + companion | — (no native object) | `agentbom:identity:<i>:*`, `agentbom:credential:<i>:*` — never secret values |
| Grant | properties on the subject (summary) + companion (full) + `declarations.claims[]` for `effective` grants | `services[].authenticated`, `x-trust-boundary`, `trustZone`, `data[].flow` where they apply | `agentbom:authz:<i>:*` |
| Evidence | `declarations.evidence[]{bom-ref:"ev:<digest12>", propertyName:<kind>, description, data[{name, contents{url}}], created, expires, author}` + `externalReferences[]{type: evidence|attestation|log, url, hashes}` | contents.url is a URL or `sha256:` URN | |
| Per-element assurance | `citations[]{pointers:[JSON Pointers], timestamp, attributedTo:<collector tool bom-ref>, process:<formulation task bom-ref>, note:<locator>}` one per collector run **and** element properties | dual emission (k8s-aibom precedent) | `agentbom:assurance`, `agentbom:state`, `agentbom:evidence:source|locator|collector|collected-at|ref` |
| Evaluation | `declarations.assessors[]`, `declarations.claims[]`, `declarations.evidence[]`, `declarations.attestations[]{assessor, map[{requirement, claims, conformance{score, rationale}, confidence{score, rationale}}]}` against `definitions.standards[]` (OWASP ASI 2025, OWASP LLM Top 10 2025, MITRE ATLAS shipped as standards with `requirements[].identifier`); `externalReferences[dynamic-analysis-report|pentest-report|threat-model|adversary-model]` | | `agentbom:eval:*` on the evidence |
| VexStatement | `vulnerabilities[]{id:"AML.T0110"|"ASI04", source{name:"MITRE ATLAS"|"OWASP Top 10 for Agentic Applications", url}, ratings[{method:"other", severity}], affects[{ref}], analysis{state, justification, detail, firstIssued, lastUpdated}}` | state: affected→`exploitable`, not-affected→`not_affected`, under-investigation→`in_triage`, fixed→`resolved`; justification: tool-disabled→`code_not_present`, guardrail-enforced→`protected_by_mitigating_control`, approval-required→`protected_at_runtime`, egress-denied→`protected_at_perimeter`, not-reachable→`code_not_reachable`, scope-restricted→`requires_configuration`, component-not-present→`code_not_present`, evaluated-resistant→`protected_by_mitigating_control` | `agentbom:vex:justification`, `agentbom:vex:scope:config-digest`, `agentbom:vex:expires` |
| TrustStatus | properties on the subject; `annotations[]` for the human statement | | `agentbom:trust:*`; revoked publishers at `metadata.properties` `agentbom:trust:revoked-publisher` |
| Conformance | `definitions.standards[]` "AgentBOM Conformance 0.1" (`requirements[].identifier` = `AB-MIN-01`…, `levels[]` minimal/standard/verified) + `declarations.attestations[]` map with per-requirement conformance | native CDXA | `symbiote:level:claimed`, `symbiote:level:validated` |
| Delta / runtime assembly | `formulation[]{workflows[{uid, name:"runtime-assembly", trigger{type:"api"|"scheduled", event{timeReceived, source}}, steps[{name:<event type>, properties}]}]}` | one step per delta event | `agentbom:delta:*` |
| Software layer | imported components and `dependencies` verbatim | cdxgen/syft evidence intact | foreign properties preserved verbatim + `agentbom:import:dialect`, `agentbom:import:source-digest` |
| Edges | `dependencies[]{ref, dependsOn, provides}` for composition (`agent dependsOn servers, models, instructions, skills, data, software`; `server provides tools`; `index dependsOn embedding model`) | edge **kind** is not expressible natively → repeated `agentbom:edge:<type>` property on the source whose value is the target bom-ref, qualifiers only in the companion | D-002 |
| Redaction | element kept schema-valid with minimal fields | | `agentbom:redaction:applied=<class>`, `agentbom:merkle:leaf` |
| Signature | optional JSF `signature` (ES256) via `--jsf-sign`; DSSE/Sigstore bundle referenced via `externalReferences[]{type:"attestation"|"digital-signature", url, hashes}` | DSSE is authoritative | |

## 3. Determinism
Arrays are sorted by stable keys (`bom-ref`, then `name`); properties by `name` then `value`; `metadata.timestamp`
pinned to `snapshot.produced_at`; `serialNumber` content-addressed. Two runs over identical inputs (and the same
Merkle nonce) produce byte-identical JSON.

## 4. Profiles
- `standard` (default) — everything above.
- `minimal` — no companion, no declarations beyond flags, digests only.
- `k8s-aibom-compat` — additionally mirrors assurance/signature facts under the k8s-aibom names (`k8s-aibom:confidence`, `k8s-aibom:security:signing:*`, and the legacy dotted forms on request).
- `--cdx-version 1.6` — downgrade for sinks that do not accept 1.7 yet: drops `citations`, `patentAssertions`, `isExternal` (→ `agentbom:model:external=true`), reported in the loss report.

## 5. Validation
`symbiote validate` runs: official JSON Schema (Draft 7, with `jsf-0.82` and `spdx` sub-schemas resolved
locally), `cyclonedx-python-lib` `JsonStrictValidator(V1_7)` when installed, taxonomy check (every
`agentbom:*` name exists in `taxonomy.md`), and divergence check (every rung-3/4 encoding has a register entry).
