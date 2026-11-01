# The supply chain of agency

**What CycloneDX 1.7 and SPDX 3.0.1 cannot say about an AI agent, and how to say it anyway.**

On 17 February 2026 an unauthorised `cline@2.3.0` was published to npm with one change: a `postinstall` script
that installed a second AI agent on every system that ran it, roughly 4,000 downloads in eight hours. The npm
publish token had been exposed through
a chain that started with a GitHub issue title: Cline's Claude-powered issue triager, running in GitHub Actions
with shell access, read the title as instructions, ran `npm install` against an attacker's fork named
`glthub-actions/cline`, and the fork's `preinstall` poisoned the Actions cache that the release workflow shared
([Khan, 2026](https://adnanthekhan.com/posts/clinejection/); [GHSA-9ppg-jx86-fqw7](https://github.com/cline/cline/security/advisories/GHSA-9ppg-jx86-fqw7);
[CSA, 2026](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_clinejection_prompt_injection_cicd_cache_poisoning_20260310-csa-styled-1.pdf)).
No package in Cline's dependency tree changed. A software bill of materials would have shown nothing, before or
after. The compromised component was an *agent's authority*: what it could read, what it could run, and whose
token it held.

That is the thesis of this document, and of the Medium article it revises
([*The Supply Chain of Agency*](https://medium.com/@EmmanuelDahunsi/the-supply-chain-of-agency-c73667e08162)):
no business-critical agent should run in production without a **signed AgentBOM** that covers models, datasets,
RAG corpora, memory, instruction files, MCP and A2A servers, and the tool schemas the model actually reads. The
two standards everyone would build it on, [CycloneDX 1.7](https://cyclonedx.org/schema/bom-1.7.schema.json) and
[SPDX 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/), are the right foundation and are not sufficient. This
document says precisely where they fall short, field by field, what attack each gap enables, what the minimum
viable AgentBOM must carry, and how [Symbiote](index.md) implements each fix without forking either standard. It
closes with corrections to the earlier drafts of this analysis, because an argument about verification should
survive being verified.

## 1. Composition is not authority: the four planes

A software SBOM answers one question well: *what is this built from?* An agent raises four, and the last three
are where the incidents live.

| Plane | Question | What has to be recorded |
|---|---|---|
| **Composition** | What was built or declared? | agents and sub-agents; tool servers and the **tool definitions** the model reads; instructions (system prompts, `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, rules files); prompt templates; models (weights by manifest, hosted models by provider + alias + resolved snapshot); datasets, RAG indexes and memory stores; the software layer |
| **Authorization** | What is the agent permitted to do? | grants: capability class (read, write, execute, egress, filesystem, credentials, payment, communicate, delegate, memory write), scope, granter, delegation chain, human approval gate, validity, policy digest, enforcement point; identities and credential bindings by reference; declared vs effective vs observed permissions kept distinct |
| **Observability** | What is deployed and what has it actually done? | declared, approved, deployed and observed snapshots over one graph; live `tools/list`, OpenTelemetry GenAI spans and runtime inventories as observed sources; a serial, a hash chain and a validity window per snapshot; typed deltas |
| **Assurance** | Why should each claim be trusted? | per-claim assurance (declared / observed / verified), explicit unknowns and coverage, evidence by digest, evaluations bound to configuration digests, VEX-style statements scoped to (model, configuration), trust status keyed on identity |

The reason a package inventory fails is not that agents have exotic dependencies. It is that the dependencies
that matter are **text the model reads** (a tool description, a rules file, a retrieved document, a memory entry),
**authority the agent holds** (an OAuth token, an open-world tool, a delegation), and **state that changes without
a release** (a hosted alias, a served `tools/list`, a vector index). None of these has a version number, none is
covered by a package hash, and all of them have been attacked in the wild: tool descriptions rewritten after
approval ([Invariant Labs, 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks);
[Deadbugz, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-deadbugz-mcp-metadata-poisoning-20260902-c/)),
rules files with instructions hidden in zero-width characters ([ATLAS AML.CS0041](https://atlas.mitre.org/studies/AML.CS0041)),
a wiper prompt committed to a coding assistant through an over-scoped token
([GHSA-7g7f-ff96-5gcw](https://github.com/aws/aws-toolkit-vscode/security/advisories/GHSA-7g7f-ff96-5gcw)), an email
tool that silently BCC'd every message after fifteen clean releases ([ATLAS AML.CS0053](https://atlas.mitre.org/studies/AML.CS0053)),
and model names re-registered after their owners deleted them ([Unit 42, 2025](https://unit42.paloaltonetworks.com/model-namespace-reuse/)).
The [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
(December 2025) names the two categories this document is about: **ASI04 Agentic Supply Chain Vulnerabilities**
and **ASI06 Memory and Context Poisoning**.

## 2. CycloneDX 1.7: what it can and cannot express

CycloneDX 1.7 (released 21 October 2025, ECMA-424 2nd edition; current patch 1.7.2) is the stronger base for agent
work because so much of what an AgentBOM needs already has a native home.

**What it can express.** `components[]` with `type` in `{application, framework, library, container, platform,
operating-system, device, device-driver, firmware, file, machine-learning-model, data, cryptographic-asset}`,
each with `hashes[]`, `purl`, `supplier`, `pedigree`, `evidence` and nested components. `services[]` with
`endpoints`, `authenticated`, `x-trust-boundary`, `trustZone` and `data[].flow`. `dependencies[]` with
`dependsOn` and `provides`. `metadata.lifecycles[]` with predefined phases (`design … operations, discovery`) or a
named lifecycle. `compositions[]` with `aggregate` completeness. `formulation[]` for workflows and tasks.
`declarations` (claims, evidence with `expires`, assessors, attestations against `definitions.standards[]`).
`citations[]`, new in 1.7, attributing BOM data to a source, a process and a timestamp, with an optional
signature. `vulnerabilities[]` with VEX `analysis` states and justifications. `externalReferences[]` with
nearly fifty types including `attestation`, `evidence`, `configuration`, `distribution-intake` and
`digital-signature`. `properties[]` everywhere, and `signature` (JSF). The `modelCard` object carries
`modelParameters`, `considerations` and `quantitativeAnalysis`
([schema](https://cyclonedx.org/schema/bom-1.7.schema.json); [release notes](https://cyclonedx.org/news/cyclonedx-v1.7-released)).

**What it cannot.**

- *No agent-native subjects.* `component.type` is unchanged from 1.6: there is no agent, tool, MCP server, prompt,
  skill, index or memory-store type. Generators improvise with `application`/`library`/`data` plus vendor
  properties; cdxgen's `cdx:mcp:*`, `cdx:skill:*` and `cdx:agent:*` names are one dialect
  ([cdxgen#4593](https://github.com/cdxgen/cdxgen/issues/4593)), k8s-aibom's `aibom.*` another, and the result
  is non-interoperable by construction.
- *Services are endpoint-centric.* A `service` has no tool description, no input or output schema, no
  MCP-style annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`) and no definition digest. The text
  that is the injection surface, and the only thing a rug pull changes, has no field.
- *Dependencies are flat and static.* `dependsOn`/`provides` carry no edge kind (`invokes`, `delegatesTo`,
  `readsContextFrom`, `writesMemoryTo`, `actsAs`), no trust label and no runtime-resolved marker.
- *No authority model.* `authenticated` and `x-trust-boundary` are booleans and `trustZone` a label; nothing
  records scopes, egress destinations, spend ceilings, credential lifetime, approval gates or delegation.
  Autonomy is not expressible at all.
- *Vulnerabilities are CVE-shaped.* `analysis.justification` offers `code_not_present … protected_by_mitigating_control`;
  there is no vocabulary for "not affected: tool disabled / guardrail enforced / human approval required", and
  exploitability is a property of (weights × prompt × tools × guardrails), a tuple VEX cannot express.
- *No validity window, no anti-rollback.* `serialNumber` plus an integer `version` that SHOULD increment; no
  expiry, no link to the prior snapshot, no delta semantics. `declarations.evidence[].expires` applies to
  evidence items only.
- *Completeness has no scope.* `compositions[].aggregate` says `complete` or `incomplete` for assemblies and
  dependencies; it cannot say which surfaces were examined, which queries failed, which tenant or window applies.
- *Attribution is not verification.* `citations` say where a fact came from; they do not require the source to be
  signed or checked. JSF signing is rarely used; the ecosystem signs with DSSE and Sigstore, which the spec does
  not define.

Two signals that the project knows this: discussion
[#973](https://github.com/CycloneDX/specification/discussions/973) proposes a runtime assertion record linking
ML-BOM artefacts to AI-supported decisions (no replies at the time of writing), and issue
[#1015](https://github.com/CycloneDX/specification/issues/1015) proposes `toolManifestDigest` and
`policyBundleDigest` on the agent component (open, milestoned for 2.1). The
[CycloneDX 2.0 announcement](https://cyclonedx.org/news/cyclonedx-v2.0-coming-soon/) (5 August 2026, not yet
released) describes a declared-versus-observed agent behaviour model, a VEX rework with attached evidence and an
eight-point exploitability scale, and per-determination attribution. Until it ships, 2.0 field names are
provisional.

## 3. SPDX 3.0.1: what it can and cannot express, and what 3.1-rc1 actually changes

SPDX 3.0.1 has the stronger graph. Every element and relationship carries its own `creationInfo`;
`Relationship` is typed and may be scoped to a lifecycle (`LifecycleScopedRelationship` with `scope: runtime`,
which CycloneDX has nothing comparable to); `usesTool`, `invokedBy`, `delegatedTo`, `configures`, `trainedOn`,
`testedOn`, `dependsOn` and `contains` are native among the **59** relationship types of 3.0.1. The
[AI profile](https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/) gives `ai_AIPackage` twenty fields
(five required); the Dataset profile gives [`dataset_DatasetPackage`](https://spdx.github.io/spdx-spec/v3.0.1/model/Dataset/Classes/DatasetPackage/)
eighteen (six required). `software_Sbom.sbomType` includes `design`, `build`, `deployed` and `runtime`.
`NoneElement` and `NoAssertionElement` let a relationship say "verified nothing" and "unknown" as different
things, and `Relationship.completeness` records it per edge. The Extension profile ships
`extension_CdxPropertiesExtension`, a built-in bridge for CycloneDX properties, so the two formats can carry
one property vocabulary losslessly.

**What it cannot.**

- *The AI profile is documentary.* Of the fifteen AI-specific `AIPackage` properties, eight are plain strings
  (`informationAboutTraining`, `limitation`, `modelExplainability`, `modelDataPreprocessing`, …), three are
  string dictionaries, three are coarse enums and one (energy consumption) is structured. `autonomyType` is
  `yes | no | noAssertion`; it cannot
  distinguish "may draft a payment" from "may execute one". Nothing describes a served snapshot, a serialization
  format, a tokenizer or a chat template.
- *Package inheritance is a straitjacket.* `AIPackage` and `DatasetPackage` inherit `software_Package`, so weights
  and corpora must carry `packageVersion` and `downloadLocation`, which mean nothing for a model behind an API
  alias.
- *Relationships carry no qualifiers.* `usesTool` has no digest, `delegatedTo` has no audience, scopes or
  expiry; a `Relationship` has only `completeness`, `startTime` and `endTime`.
- *Agent is an actor, not an artefact.* Core `Agent` (Person, Organization, SoftwareAgent, Tool) is whoever
  creates elements. An AI agent is simultaneously a principal and an artefact, and 3.0.1 offers no dual typing.
- *No service, no runtime record.* There is no Service class in 3.0.1; MCP servers, inference endpoints and vector
  databases become generic packages without endpoint, authentication or trust-boundary facts. There is no
  observation record (collector, method, window) and no delta.
- *Integrity is a file hash.* `IntegrityMethod` is `Hash`, `PackageVerificationCode` or `ContentIdentifier`; there
  is no Merkle or content-defined hashing for multi-gigabyte weights, no canonicalization for prompts or tool
  schemas, and no in-document signature.
- *Conformance is per profile and non-composable.* "SPDX 3 support" says nothing about AI + Dataset + Security +
  Extension together ([conformance](https://spdx.github.io/spdx-spec/v3.0.1/conformance/)).
- *Operational weight.* JSON-LD plus SHACL validation is heavy for CI, and a full-distribution Yocto SPDX 3 document
  runs to roughly 250 MB compressed / 2 GB uncompressed ([Watt, 2026](https://sbomify.com/2026/05/19/yocto-spdx-3-0-overview/)).

**What 3.1-rc1 actually changes.** The release candidate was published on 24 January 2026
([tag](https://github.com/spdx/spdx-3-model/releases/tag/3.1-rc1); [changelog](https://raw.githubusercontent.com/spdx/spdx-3-model/3.1-rc1/CHANGELOG.md)).
Verified against the model files at that tag:

- `ai_autonomyType` is **deprecated** in favour of a Core property **`isoAutomationLevel`** with the seven
  ISO/IEC 22989 levels (`notAutomated … fullAutomation, autonomous`)
  ([autonomyType.md](https://raw.githubusercontent.com/spdx/spdx-3-model/3.1-rc1/model/AI/Properties/autonomyType.md);
  [isoAutomationLevel.md](https://raw.githubusercontent.com/spdx/spdx-3-model/3.1-rc1/model/Core/Properties/isoAutomationLevel.md)).
  Still per package, not per action.
- `RelationshipType` grows from 59 to **76** entries according to the project's own changelog; our two independent
  counts of the vocabulary file at the tag gave 76 and 77, a one-entry difference that does not change the point,
  and the `develop` branch has kept growing (83 at the time of writing). The additions include `finetunedOn`,
  `pretrainedOn`, `evaluatedOn`, `validatedOn`, `verifiedBy`, `implementedBy`, `runsOn`, `hasInstance`,
  `conformsTo` and `hasResolution`
  ([3.0.1 vocabulary](https://raw.githubusercontent.com/spdx/spdx-3-model/3.0.1/model/Core/Vocabularies/RelationshipType.md);
  [3.1-rc1 vocabulary](https://raw.githubusercontent.com/spdx/spdx-3-model/3.1-rc1/model/Core/Vocabularies/RelationshipType.md)).
- `AIPackage` and `DatasetPackage` requirements were relaxed; new profile material appears for Service
  (software-as-a-service, a stub at the tag), Operations (business operations, not runtime observation),
  SupplyChain and Hardware; `AI/InteractionTemplate`, an `Artifact` subclass for prompt-like templates, exists on
  the post-rc1 `develop` branch.
- **It does not add `AIAgent`, `Prompt` or `RAG` classes.** No such files exist under `model/AI/Classes` at the tag
  or on `develop`. They remain open AI-working-group pull requests
  ([#1257](https://github.com/spdx/spdx-3-model/pull/1257) AIAgent v2, [#1249](https://github.com/spdx/spdx-3-model/pull/1249)
  Prompt v2, [#1115](https://github.com/spdx/spdx-3-model/pull/1115) RAG, tracked in
  [#1091](https://github.com/spdx/spdx-3-model/issues/1091)), unmerged as of 1 November 2026, with no 3.1-rc2 or
  final 3.1 published.

So an AgentBOM designed today must target 3.0.1 plus typed extensions and carry a mechanical upgrade path for
3.1 (`automation_level → isoAutomationLevel`, fine-tune lineage → `finetunedOn`/`pretrainedOn`, evaluations →
`evaluatedOn`/`validatedOn`, prompt templates → `InteractionTemplate`). It must not promise a mapping to
classes that do not exist.

## 4. The shared structural gaps

The register below merges the attack-lens analysis (22 gaps, each traced to incidents and to
[OWASP ASI](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
and [MITRE ATLAS v5.6](https://atlas.mitre.org/) identifiers) with the structural and operational points of the
earlier drafts. "Fix" is what an AgentBOM must carry; section 6 maps each fix to Symbiote.

| # | Gap | Attack it enables (exemplar) | ASI / ATLAS | Fix |
|---|---|---|---|---|
| G1 | **Tool definition not covered by any hash.** Name, description, schema and annotations are served live by the MCP server and have no field in either standard | tool poisoning and rug pull, including delayed variants: Invariant Labs' poisoned descriptions (Apr 2025); Deadbugz, benign for the first calls then rewritten (Aug 2026) | ASI04, ASI01; AML.T0110, AML.T0109, AML.T0094 | canonical digest (RFC 8785) over the model-visible surface; per-server toolset digest; signed allowlist; re-verify per session, per `tools/list`, on `list_changed` and per call |
| G2 | **Hosted model behind an alias cannot be pinned.** A version string is not an identity; nothing distinguishes a pinned snapshot from a floating alias | silent model swap behind `claude-sonnet-4-5` or `gpt-4o`; evaluations carry over to weights nobody evaluated | ASI04; AML.T0010.003 | provider + requested alias + resolved snapshot + provider evidence; `alias_pinning` state; behavioural-fingerprint claim with expiry when the provider discloses nothing; `gen_ai.response.model` as observed evidence |
| G3 | **Identity is a name, not content.** Content identifiers are optional and nothing records how a name resolved to bytes | namespace reuse on Hugging Face propagating into Vertex AI and Azure AI Foundry ([Unit 42](https://unit42.paloaltonetworks.com/model-namespace-reuse/)); typosquats; slopsquatting of hallucinated packages ([Spracklen et al.](https://arxiv.org/abs/2406.10279): 205,474 unique hallucinated names) | ASI04; AML.T0010.001/.003, AML.T0060, AML.T0074 | digest as primary key, name as locator; a name-resolution record (requested → resolved immutable ref → signer → log inclusion); unresolvable ⇒ `unknown`, never ok |
| G4 | **No load-time code-execution risk field.** Pickle, `trust_remote_code`, Jinja chat templates, GGUF parsers | nullifAI's broken pickles that scanners could not parse ([ReversingLabs](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face)); Sleepy Pickle ([Trail of Bits](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)); [CVE-2024-34359](https://github.com/advisories/GHSA-56xg-wfcc-g829) SSTI through a GGUF chat template in llama-cpp-python | ASI05, ASI04; AML.T0011.000, AML.T0018.002 | serialization profile per file (format, risk class, `trust_remote_code`, executable chat template), scanner evidence by digest, admission policy that can gate on it |
| G5 | **Whole-blob hashes hide adapters and layers; lineage is untyped.** Fine-tune, LoRA, quantize, merge and distil change behaviour without a version; format conversion breaks file hashing | poisoned adapter behind an unchanged file name; merge smuggling a poisoned parent | ASI04; AML.T0018.000/.001, AML.T0043.004 | per-file manifest compatible with [OpenSSF model-signing](https://github.com/sigstore/model-transparency) plus per-tensor manifest; typed derivation edges with parameters (`fineTuneOf`, `adapterOf`, `quantizationOf`, `mergeOf`, `distillationOf`, `conversionOf`) |
| G6 | **RAG indexes and memory are static datasets with prose provenance.** No embedding model, chunking, writers, write policy, tenant isolation, trust tier or poison-scan | Copilot RAG store poisoned by one email ([ATLAS AML.CS0026](https://atlas.mitre.org/studies/AML.CS0026)); PoisonedRAG, 5 texts per query for ~90 % success ([Zou et al.](https://arxiv.org/abs/2402.07867)); ChatGPT memory hijack ([AML.CS0040](https://atlas.mitre.org/studies/AML.CS0040)) | ASI06, ASI01; AML.T0070, AML.T0071, AML.T0080 | mutable stores as first-class components: trust tier, instruction-bearing flag, snapshot commitment, writers, ACL mode, tenant isolation, retention, quarantine, invalidation dependents, sanitisers, poison-scan evidence |
| G7 | **No data-flow edges with trust labels.** `dependsOn` cannot say "instruction-bearing, untrusted, reaches a destructive tool" | the Clinejection pattern: untrusted text → agent → privileged tool; Invariant's GitHub MCP toxic flow; EchoLeak | ASI01, ASI02, ASI06; AML.T0051.001, AML.T0086 | typed edges (`readsContextFrom`, `invokesTool`, `writesMemoryTo`, `delegatesTo`, `sendsDataTo`) with trust tier; a computed lethal-trifecta / Rule-of-Two flag that cites its inputs |
| G8 | **Delegation and agent identity are unmodelled.** No SPIFFE/DID binding; `delegatedTo` has no audience, scopes or expiry; Agent Cards are only optionally signed ([A2A](https://a2a-protocol.org/latest/specification/)) | agent-card poisoning diverting a booking agent's payment data; forged `/.well-known/agent.json` | ASI07, ASI03, ASI10; AML.T0073, AML.T0074 | identities by reference; delegation chains with protocol, audience, scopes, constraints, expiry and evidence; card digests and signature status; transitive-capability and blast-radius queries |
| G9 | **Registries and approvals are not modelled; approval binds to a display name.** The MCP registry has an optional `packages[].fileSha256`, no digest for remotes and no attestation reference ([server.json](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/generic-server-json.md); [smithmark](https://pkg.go.dev/github.com/sns45/smithmark)) | postmark-mcp impersonation ([AML.CS0053](https://atlas.mitre.org/studies/AML.CS0053)); malicious SKILL.md campaigns ([AML.CS0049](https://atlas.mitre.org/studies/AML.CS0049)); [CVE-2025-6514](https://github.com/advisories/GHSA-6xpm-ggf7-wc3p) in mcp-remote | ASI04; AML.T0111, AML.T0104 | registry resolution records (entry, version, status, publisher verification, signer, log inclusion); approvals keyed to definition digests and capability sets with approver, policy revision and expiry; revocation propagation |
| G10 | **Inventory without authority.** No capability object, no credential lifetime, no distinction between service account and OBO token, autonomy a yes/no flag | Amazon Q wiper prompt via an over-scoped token ([GHSA-7g7f-ff96-5gcw](https://github.com/aws/aws-toolkit-vscode/security/advisories/GHSA-7g7f-ff96-5gcw)); one token reading public and private repos | ASI03, ASI02; AML.T0083, AML.T0098, AML.T0055 | normative grant record (capability, scope, granter, chain, conditions, gate, validity, policy digest, enforcement point, credential binding); action-specific autonomy; declared vs effective vs observed kept distinct |
| G11 | **No egress allowlist or side-effect taxonomy.** MCP annotations are hints a client must not trust from an untrusted server ([MCP spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)) | postmark-mcp BCC exfiltration; Copilot Studio and Cursor MCP exfiltration ([AML.CS0037](https://atlas.mitre.org/studies/AML.CS0037), [AML.CS0045](https://atlas.mitre.org/studies/AML.CS0045)) | ASI02, ASI03; AML.T0086, AML.T0057 | side-effect class and egress scope per tool; declared vs observed effects distinguished; observed egress outside every grant is a finding |
| G12 | **A full BOM is an attack map; a redacted one cannot be verified.** Distribution labels only; signatures bind to bytes | reconnaissance from a forwarded BOM ([AML.T0084](https://atlas.mitre.org/techniques/AML.T0084)) | ASI04; AML.T0084, AML.T0002.002 | salted Merkle commitment: redacted views verify against the signed root; inclusion proofs; redaction recorded, never silent |
| G13 | **No validity window, serial or anti-rollback.** Approve-once-trust-forever | replay of an old approved BOM or allowlist; the fifteen clean postmark releases | ASI04, ASI08; AML.T0109, AML.T0081 | monotone serial, hash chain, validity window; verifier state; expired lists fail closed; re-attestation triggers |
| G14 | **Instructions are not a component type.** System prompts, rules files, SKILL.md, hooks, MCP `instructions` are unhashed behaviour-as-code | Rules File Backdoor with zero-width characters ([AML.CS0041](https://atlas.mitre.org/studies/AML.CS0041)); Amazon Q 1.84.0 | ASI04, ASI01, ASI05; AML.T0081, AML.T0051.001 | instruction component: exact-bytes digest, kind, loading precedence, editors, remote loads, hidden-Unicode scan; skills as directory manifests |
| G15 | **Cross-server shadowing and mixed-trust composition.** No per-server trust tier or session composition record | WhatsApp MCP shadowing ([Invariant Labs](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)) | ASI04, ASI01; AML.T0110 | per-server trust zone and identity; mixed-trust finding when an ungated external server is co-loaded with internal tools |
| G16 | **No observed BOM.** Static inventories cannot show tools discovered at runtime, sub-agents spawned, models routed, memory written | cline@2.3.0 installing OpenClaw with no declared dependency; adapters pulled from a hub with no deployment event | ASI04, ASI10, ASI08; AML.T0103 | observed snapshots from live `tools/list` and [OTel GenAI spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/); the diff between declared/approved and observed is the finding |
| G17 | **Evaluations are unattested numbers unbound to configuration.** `quantitativeAnalysis` has no harness, dataset digest or configuration; VEX justifications are CVE-shaped | "passed red team" surviving a model swap or a new open-world tool; MCPTox shows up to 72.8 % tool-poisoning success for the most susceptible model ([Wang et al.](https://arxiv.org/abs/2508.14925)) | ASI04, ASI09; AML.T0054, AML.T0051 | evaluation records bound to model, prompt, toolset, data and policy digests with harness, dataset digest, denominators, assessor and expiry; AI-VEX scoped to (subject, configuration) with agentic justifications; stale on any drift |
| G18 | **Self-assertion.** JSF rarely used; SPDX has no signature; attribution ≠ verification; no multi-party composition | a valid, false AgentBOM from a compromised producer; reputation inflation ([AML.T0111](https://atlas.mitre.org/techniques/AML.T0111)) | ASI04, ASI09; AML.T0111 | in-toto statements in DSSE, Sigstore keyless with **identity constraints**; `signature-valid-unconstrained` never equals `verified`; per-claim assurance |
| G19 | **Coverage laundering.** `complete` with no scope turns a failed query into a false negative | "no shadow agents found" after a registry timeout; scanners reporting clean on unparseable pickles | ASI04, ASI08 | coverage statement per surface (queried / partial / permission-denied / unreachable / not-attempted / truncated); unknown ≠ verified absence; privileged approval requires every surface queried |
| G20 | **Lossy conversion and vendor-property fragmentation.** Untyped properties; non-composable profiles; conversions drop VEX and flatten licences | security fields stripped in transit and never noticed (downgrade by conversion) | ASI04 | one semantic model, one registered property namespace, lossless mirror through `CdxPropertiesExtension`, a **loss report** from every converter, a divergence register, no third standard |
| G21 | **Datasets are named, not committed to.** No shard Merkle root, per-source fetch time, licence or opt-out, no transformation lineage | buying expired domains referenced by crawl datasets ([Carlini et al.](https://arxiv.org/abs/2302.10149)); 250 documents suffice to backdoor models from 600M to 13B parameters ([Anthropic / UK AISI / Turing](https://www.anthropic.com/research/small-samples-poison)) | ASI04; AML.T0020, AML.T0019 | dataset manifests with per-source digests and fetch evidence, typed derivation edges, consent and licence status, snapshot commitments |
| G22 | **Implementation drift behind a stable interface.** A definition digest misses a backend swap | postmark-mcp: identical interface, one added line | ASI04, ASI02; AML.T0109, AML.T0086 | bind each tool contract to server identity (package digest, endpoint origin, instructions digest, signer); re-approval on implementation change; observed egress corroboration; enforcement at the gateway, sandbox or network boundary |

Three operational gaps round out the register. **Optional fields are security theatre**: an attribute nobody fills
protects nobody, so generation must be automatic from the artefacts agents are actually built from (client
configs, SKILL.md, framework configs, model directories, traces). **A third standard is the real risk**: OWASP's
Agent Observability Standard already defines its own dynamic AgBOM ([AOS](https://aos.owasp.org/spec/inspect/)),
and vendor AI-BOM views diverge; the right move is to map these onto CycloneDX and SPDX. **Interoperability
decays when the base lags**: Dependency-Track ingested only CycloneDX ≤ 1.6 until mid-2026 (1.7 support landed in
v5.1.0, 27 August 2026, backported in v4.14.4 on 14 September; [releases](https://github.com/DependencyTrack/dependency-track/releases)),
so a 1.6 downgrade path and a loss report remain necessary.

## 5. The minimum viable AgentBOM and three assurance levels

The register implies a floor. Any AgentBOM that cannot answer the four questions for a deployed agent is an
SBOM with AI components attached.

| Category | Minimum information |
|---|---|
| Agent | stable definition id, owner, purpose, version, framework |
| Deployment | instance id, environment, tenant, deployment time, workload identity |
| Identity | workload principal and issuer, credential bindings by reference, binding evidence |
| Model | provider and endpoint, requested identifier, resolved version if available, or an explicit unknown; weights by manifest root; serialization risk |
| Tools | server identity, tool name, definition digest (or `undigestable` with a reason), declared capabilities, approval gate |
| Data | principal sources, indexes and memory stores with classification, trust tier, writers |
| Authorization | declared grants with capability, scope and enforcement point; evidence of effective permissions where obtainable |
| Registry | registry identity, entry and version, approval state and deployment binding, or explicit absence or unknown |
| Evidence | source, collection method, observation time, freshness, verification status |
| Coverage | surfaces included, exclusions, collection failures, unknowns |
| Changes | snapshot serial and links to the prior snapshot or to change evidence |

Three assurance levels apply **per claim**, never to the agent as a whole; a single score would conceal exactly the
differences that matter:

1. **Declared** — the owner, supplier or a configuration the owner controls says so.
2. **Observed** — a collector corroborated the deployed state within a stated scope and window: a live
   `tools/list`, an OpenTelemetry span, a registry or provider API, a runtime inventory.
3. **Verified** — the evidence is authenticated (a signature over the exact digest) and evaluated against an
   explicit trust policy with a **constrained signer** and documented coverage. A valid signature from a signer
   nobody constrained is a recorded fact, not verification; Google's k8s-aibom states this rule as its Design 002
   and it is adopted here verbatim ([k8s-aibom](https://github.com/GoogleCloudPlatform/k8s-aibom)).

Two further distinctions are non-negotiable. **Unknown is not absence**: a failed registry query yields `unknown`
with a reason, never "not registered", and a claim of absence requires that the surface was examined.
**Snapshot kinds never merge**: *declared* (configuration), *approved* (signed by a reviewer, bound to digests),
*deployed* (bound to a workload identity and environment) and *observed* (what the runtime served, called,
routed and spawned) are four documents over one graph, and the diff between them is the detection primitive.

## 6. How Symbiote implements each fix

Symbiote keeps one semantic model (the companion document, `application/vnd.agentbom+json`, with a generated
JSON Schema) and projects it onto CycloneDX 1.7 and SPDX 3.0.1 using only their sanctioned extension points, under
one tool-neutral property namespace, `agentbom:`. Every projection is validated against the official schema
before it is written, every conversion emits a loss report, and every extension or narrowing has an entry in the
divergence register. The mapping from register entry to implementation:

| Gap | Specification | Implementation and command |
|---|---|---|
| G1 tool definitions | [`digests.md §3.1–3.3`](spec/digests.md), [`attestation.md §5`](spec/attestation.md) | `tooldef/v1` = `sha256(JCS({_type, name, title, description, inputSchema, outputSchema, annotations}))` over the raw JSON-RPC object, fail-closed on non-canonical input; `toolset/v1` per server; `symbiote digest tooldef`, `symbiote allowlist export --format gab`, `symbiote allowlist check` (a known name with a new digest is `block: rug-pull-signal`) |
| G2 hosted models | [`agentbom-profile.md §3.8`](spec/agentbom-profile.md), [`checks.md`](spec/checks.md) | hosted identity tuple with `alias_pinning`; `SYM-MODEL-001`; OTel `gen_ai.response.model` ≠ request ⇒ `model-routed` delta |
| G3 name resolution | [`digests.md §4`](spec/digests.md) | `RegistryResolution` records; the `mcp-registry` collector (unreachable ⇒ `unknown`); `SYM-MCP-004/005`, `SYM-REG-001` |
| G4, G5 model identity | [`digests.md §3.6, §3.10, §6`](spec/digests.md) | OpenSSF model-signing compatible directory manifests (`symbiote digest dir`), per-tensor safetensors manifests, serialization risk classes, typed derivations; `SYM-MODEL-002…006` |
| G6 mutable data | [`agentbom-profile.md §3.9`](spec/agentbom-profile.md) | `DataSource` with trust tier, writers, snapshot commitment, ACL mode, quarantine; `SYM-MEM-001/002`, `SYM-DATA-001` |
| G7 data-flow edges | [`agentbom-profile.md §4`](spec/agentbom-profile.md), [`checks.md §2`](spec/checks.md) | 20 typed edge kinds with qualifiers; `SYM-AUTHZ-001` lethal trifecta / Rule of Two with cited inputs and `indeterminate` on unknown legs |
| G8 delegation and identity | [`agentbom-profile.md §3.10–3.11`](spec/agentbom-profile.md) | `Identity`, `CredentialBinding`, `delegation_chain`, A2A card facts; `SYM-AUTHZ-005`, `SYM-A2A-001`, `SYM-SUB-001` |
| G9 registries and approvals | [`agentbom-profile.md §3.12`](spec/agentbom-profile.md), [`attestation.md §1`](spec/attestation.md) | `Approval` keyed to the snapshot digest and covered tool digests; `approval/v1` and `trust-status/v1` predicates; `SYM-TRUST-001/002` |
| G10, G11 authority and effects | [`agentbom-profile.md §3.4, §3.11`](spec/agentbom-profile.md) | `Grant` records (declared / effective / observed), `side_effect_class`, `approval_gate`, enforcement point; `SYM-AUTHZ-002…007`, `SYM-TOOL-003`, `SYM-MCP-001` |
| G12 redaction | [`digests.md §5`](spec/digests.md) | salted RFC 6962 Merkle commitment; `symbiote merkle verify` on redacted documents; redaction records |
| G13 anti-rollback | [`attestation.md §3`](spec/attestation.md) | serial, `prev`, validity; chain store (`--store`); `SYM-SNAP-001…003`; `symbiote verify --store` exits 7 on regression |
| G14, G15 instructions and composition | [`collectors.md`](spec/collectors.md), [`checks.md §2.1`](spec/checks.md) | exact-bytes digests, hidden-Unicode and remote-load lints (`SYM-INSTR-001…005`, `SYM-TOOL-006`), skill manifests (`SYM-SKILL-001/002`), `SYM-MCP-006` mixed trust; the Clinejection CI checks `SYM-CI-001…003` |
| G16 observed BOM | [`agentbom-profile.md §1.4, §2.2`](spec/agentbom-profile.md), [`collectors.md`](spec/collectors.md) | `mcp-live` (raw JSON-RPC, all pages), `otel-traces`, k8s-aibom import; `symbiote diff --fail-on-change …`; `observed-delta/v1` |
| G17 evaluations and AI-VEX | [`agentbom-profile.md §3.13`](spec/agentbom-profile.md), [`cyclonedx-mapping.md §2`](spec/cyclonedx-mapping.md) | `Evaluation.subject_config` digests, `SYM-EVAL-001` stale on drift; `VexStatement` keyed to ATLAS / ASI ids with agentic justifications mapped onto CycloneDX `vulnerabilities[]` and SPDX VEX relationships |
| G18 attestation | [`attestation.md §1–3`](spec/attestation.md) | in-toto v1 statements, key-based DSSE and Sigstore keyless; `symbiote attest snapshot`, `symbiote verify --policy` with identity constraints; `UnsafeNoOp` refused |
| G19 coverage | [`agentbom-profile.md §3.14`](spec/agentbom-profile.md), [`conformance.md`](spec/conformance.md) | ten-surface coverage in every document, `compositions[]` per surface in CycloneDX, `NoAssertionElement` in SPDX; `SYM-COV-001/002`; conformance `unknown` blocks a level |
| G20 interoperability | [`taxonomy.md`](spec/taxonomy.md), [`divergences.md`](spec/divergences.md), [`companion.md §4`](spec/companion.md) | `agentbom:` taxonomy (add-only), `CdxPropertiesExtension` mirror, loss reports (`agentbom.cdx.loss.json`), k8s-aibom and cdxgen dialect import, divergence register D-001…D-020 |
| G21 datasets | [`agentbom-profile.md §3.9`](spec/agentbom-profile.md) | `sources[]` with digest, fetch time, licence and consent; derivation edges with parameters |
| G22 implementation drift | [`digests.md §3.4`](spec/digests.md) | `server/v1` identity (kind, transport, normalised endpoint, package purl + digest, server info, instructions digest) in every allowlist; `server-identity-changed` delta; `SYM-MCP-002` floating launchers |

Conformance makes the floor testable: **AgentBOM-Minimal** (`AB-MIN-01…08`, what a static scan can reach),
**Standard** (`AB-STD-01…10`, authority, resolution and runtime binding) and **Verified** (`AB-VER-01…08`,
authenticated evidence) are evaluated by `symbiote conformance`, and each requirement reports `pass`, `fail` or
`unknown`, so a document cannot claim a level with blocking unknowns ([`conformance.md`](spec/conformance.md)).
Everything is generated rather than hand-filled: `symbiote scan` reads the MCP client configurations of Claude
Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex and Gemini CLI today, with instruction, skill, framework,
model, A2A and identity collectors specified and landing in parallel ([collectors guide](guides/collectors.md)).

## 7. Corrections to the original analysis

The earlier drafts of this analysis were compiled from several passes and carried claims that were later
checked against primary sources (64 claims, 1 November 2026; the full record is in
[`docs/research/verified-claims-ihvm.json`](https://github.com/aisecnomad/symbiote/blob/main/docs/research/verified-claims-ihvm.json)).
What changes:

| Original claim | Status | Correction |
|---|---|---|
| `modelCard.properties` exists in the CycloneDX 1.7 JSON schema but not the XML schema, so conversion loses data | **outdated** | True for the initial 1.7 schemas and back to 1.5 (XML *and* Protobuf), confirmed as a bug in [CycloneDX/specification#726](https://github.com/CycloneDX/specification/issues/726); fixed in the 1.7.1 / 1.6.2 / 1.5.1 patch releases of 2 June 2026. The current 1.7.2 XSD declares `properties` on `modelCardType`. Symbiote still avoids `modelCard.properties` for parity with consumers pinned to earlier schemas (D-005) |
| SPDX 3.1-rc1 "adds AI Agent, Prompt and RAG classes" (one passage) versus "I saw no agent, tool or prompt classes in the RC1 changelog" (another) | **contradiction resolved** | The second passage is correct. 3.1-rc1 (24 Jan 2026) deprecates `autonomyType` for `isoAutomationLevel`, relaxes AIPackage/DatasetPackage requirements and grows the relationship vocabulary; AIAgent, Prompt and RAG remain open pull requests (section 3) |
| "Relationship types grow from 59 to 76 in 3.1" | **confirmed, with a footnote** | The changelog says 76; independent counts at the tag give 76–77; `develop` has 83 |
| "SPDX 3.0 has no service concept; 3.1 adds a Services profile" | **refined** | 3.1-rc1 adds a *Service* (singular) profile oriented to software-as-a-service, a stub at the tag; it does not model tool endpoints or trust boundaries |
| Dependency-Track "still ingests only CycloneDX ≤ 1.6" | **outdated** | 1.7 ingestion landed in v5.1.0 (27 Aug 2026) and v4.14.4 (14 Sep 2026) ([release notes](https://docs.dependencytrack.org/2026/09/14/v4.14.4/)) |
| Microsoft's sbom-tool "exposes SPDX 3.0 as a flag but can't produce valid output" | **outdated** | SPDX 3.0 generation and validation shipped in sbom-tool v4.0.2 (May 2025); redaction remains 2.2-only ([releases](https://github.com/microsoft/sbom-tool/releases)) |
| "brox encodes MCP servers in its own brox.* properties" | **unverifiable** | No such tool was found. The behaviour is real in the genre: use cdxgen's `cdx:mcp:*` / `cdx:agent:*` namespaces or agent-harness-aibom's `harness-aibom:*` as the example |
| "A March 2026 Oxford/Cisco paper proposed schema extensions to both standards" | **confirmed, now cited** | Radanliev, Maple, Santos and Atefi, *SBOMs into Agentic AIBOMs* ([arXiv:2603.10057](https://arxiv.org/abs/2603.10057); [DOI 10.1145/3798285](https://doi.org/10.1145/3798285)), covered by [Dark Reading](https://www.darkreading.com/cyber-risk/how-cisos-should-prep-for-agentic-ready-ai-boms) |
| CycloneDX 2.0 "declared-behaviour model" | **confirmed as a plan** | Present in the [2.0 announcement](https://cyclonedx.org/news/cyclonedx-v2.0-coming-soon/) (5 Aug 2026); 2.0 is not released, so field names are provisional |
| Deadbugz as a rug pull detectable by an approval-time hash | **refined** | Deadbugz is *runtime-gated*: benign for the first calls, hostile afterwards ([CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-deadbugz-mcp-supply-chain-20260830-csa-sty/)). Hashing at approval is necessary and insufficient; re-verification per session, per `tools/list`, on `list_changed` and per call is required |
| The MCP registry "has no digest or attestation fields" | **refined** | `server.json` has an optional `packages[].fileSha256`; there is no digest for `remotes[]` and no attestation reference, which is why `signer` facts come from package ecosystems. No `pkg:mcp` purl type exists |
| Clinejection: the fork was `glthub-actions`, "missing the i" | **wrong detail** | The `i` is *replaced* by a lowercase `l` (g-l-t-h-u-b), mimicking the `github-actions` service account |
| Clinejection: "CVE-2026-25253" identifies the compromise | **wrong** | The Cline advisory lists no CVE. CVE-2026-25253 is an unrelated OpenClaw one-click RCE patched in January 2026 ([GHSA-g8p2-7wf7-98mq](https://github.com/advisories/GHSA-g8p2-7wf7-98mq)) |
| Clinejection: victims "received an agent with full system access and a WebSocket channel for remote commands" | **overstated** | The `postinstall` only installed OpenClaw globally; it was not configured or launched, and no attacker channel was established ([advisory](https://github.com/cline/cline/security/advisories/GHSA-9ppg-jx86-fqw7)). Timeline: triage workflow added 21 Dec 2025; private report 1 Jan 2026; public disclosure 9 Feb; publish 17 Feb; fix 2.4.0 and OIDC trusted publishing |
| "The first documented prompt-injection-to-supply-chain cascade" | **inference, not a sourced fact** | No authoritative source makes the superlative; no earlier counter-example is known. State it as a judgement |
| Amazon Q: "964,000 installations over 48 hours, halted by a syntax error" | **three errors** | 964,000 is the extension's cumulative install count; the window was about 31.5 hours (1.84.0 on 17 July 2025, 1.85.0 on 19 July); the syntax error made the payload inert but AWS halted distribution by shipping 1.85.0 ([AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)) |
| MCPTox "72.8 % attack success against leading models" | **refined** | 72.8 % is the single highest per-model rate (o1-mini); the average over 20 models was 36.5 % ([arXiv:2508.14925](https://arxiv.org/abs/2508.14925)) |
| Package hallucination "up to 21.7 %"; "~440k unique hallucinated packages" | **refined** | 21.7 % is the *average* for open-source models (5.2 % commercial); 440,445 is the total count of hallucinated references and 205,474 the number of unique names ([USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen)) |
| Safetensors "loads roughly 100× faster than pickle" | **overstated** | Hugging Face's benchmark reports about 76× on CPU and about 2× on GPU for one small model ([docs](https://huggingface.co/docs/safetensors/speed)); the audit was commissioned by Hugging Face, EleutherAI and Stability AI ([blog](https://huggingface.co/blog/safetensors-security-audit)) |
| "Over 100 malicious pickle models on Hugging Face" | **confirmed, dated** | JFrog's February 2024 wording is "around 100"; its 2026 report counts 495 ([JFrog](https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/)) |
| CVE-2024-34359 "in GGUF models" | **refined** | The flaw is in the llama-cpp-python loader (unsandboxed Jinja2 over the model's chat template), CVSS 9.6, fixed in 0.2.72 |
| "Anthropic and UK AISI showed 250 documents implant a persistent backdoor" under "PEFT poisoning" | **refined** | Three institutions (Anthropic, UK AISI, Alan Turing Institute); the demonstrated backdoor is a gibberish denial-of-service trigger; clean fine-tuning degraded it, so "persistent" is unsupported; the work covers pretraining and ordinary fine-tuning, not PEFT ([Anthropic](https://www.anthropic.com/research/small-samples-poison)) |
| "Google released K8s-AISBOM" | **naming** | The project is **k8s-aibom** (CycloneDX 1.6 ML-BOMs, open-sourced 13 July 2026, [repo](https://github.com/GoogleCloudPlatform/k8s-aibom)) |
| The OWASP AIBOM Foundations Guide is "the first comprehensive framework for implementing" AIBOMs | **superlative removed** | v1.0 (September 2026) is OWASP's first dedicated AIBOM implementation guide ([owaspaibom.org](https://owaspaibom.org/)); CycloneDX ML-BOM, the SPDX AI profile and the G7 *SBOM for AI – Minimum Elements* (12 May 2026, [BSI](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html)) predate it |
| EU AI Act Articles 11 and 15 apply to high-risk systems | **confirmed, dated** | Article 15(5) names data poisoning, model poisoning, adversarial examples and confidentiality attacks ([text](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-15)); after the July 2026 Digital Omnibus the high-risk obligations apply from 2 December 2027 (Annex III) and 2 August 2028 (Annex I) |
| Cisco's Model Provenance Kit does "per-tensor" fingerprinting | **refined** | Per-layer weight statistics plus architecture and tokenizer signals, a lineage detector, not mandated by any standard ([repo](https://github.com/cisco-ai-defense/model-provenance-kit)) |
| Yocto produces "~250 MB / ~2 GB" SPDX 3 documents | **scoped** | For a full distribution build; a `core-image-minimal` build is about 260 MB uncompressed |
| Hyphenated identifiers in the published article (`CVE-2025–8217`) | **typography** | Medium converts hyphens to en-dashes in prose; put identifiers in code spans |

Nothing in the table weakens the argument. The structural gaps stand; what changes is that the standards' own
bug tracker, release notes and model files, not a secondary summary, are now the evidence for each of them.

## 8. Three changes, if only three

1. **Content addresses as identity, everywhere, with the resolution recorded and signed.** Names locate; digests
   identify. A model is its manifest root, a tool is its canonical definition digest, an instruction is its bytes,
   and every externally sourced component carries a record of how its name became those bytes.
2. **First-class instruction and tool-definition components.** The two most privileged inputs an agent has are
   text the model reads. Hash them, version them, record who may edit them and in which order they load, and a
   poisoned prompt or a rewritten tool shows up as a diff instead of an incident.
3. **A runtime binding.** Declared capabilities, a policy-bundle digest and a snapshot digest that every agent
   action references, with signed deltas when any of them changes, so that "what is this agent authorised to do
   right now" is a query over evidence rather than a design review.

Symbiote exists to show that all three fit inside CycloneDX 1.7 and SPDX 3.0.1 today, that the proposals already
open against both standards point the same way, and that the right outcome is an upstreamed profile, not a third
format.

## References

- CycloneDX 1.7 JSON Schema: <https://cyclonedx.org/schema/bom-1.7.schema.json>; release notes:
  <https://cyclonedx.org/news/cyclonedx-v1.7-released>; releases: <https://github.com/CycloneDX/specification/releases>
- CycloneDX/specification#726 (modelCard properties in XML/Protobuf): <https://github.com/CycloneDX/specification/issues/726>;
  discussion #973: <https://github.com/CycloneDX/specification/discussions/973>; issue #1015:
  <https://github.com/CycloneDX/specification/issues/1015>; 2.0 announcement: <https://cyclonedx.org/news/cyclonedx-v2.0-coming-soon/>
- cdxgen #4593: <https://github.com/cdxgen/cdxgen/issues/4593>; CycloneDX property taxonomy:
  <https://github.com/CycloneDX/cyclonedx-property-taxonomy>
- SPDX 3.0.1: <https://spdx.github.io/spdx-spec/v3.0.1/>; AI profile: <https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/>;
  conformance: <https://spdx.github.io/spdx-spec/v3.0.1/conformance/>; 3.1-rc1 tag and changelog:
  <https://github.com/spdx/spdx-3-model/releases/tag/3.1-rc1>, <https://raw.githubusercontent.com/spdx/spdx-3-model/3.1-rc1/CHANGELOG.md>;
  AIAgent/Prompt/RAG proposals: <https://github.com/spdx/spdx-3-model/issues/1091>
- MCP tools specification (2025-06-18): <https://modelcontextprotocol.io/specification/2025-06-18/server/tools>;
  MCP Registry preview: <https://blog.modelcontextprotocol.io/posts/2025-09-08-mcp-registry-preview/>; roadmap:
  <https://modelcontextprotocol.io/development/roadmap>
- OWASP Top 10 for Agentic Applications (9 Dec 2025):
  <https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/>;
  OWASP AIBOM Foundations Guide v1.0: <https://owaspaibom.org/>; OWASP AOS AgBOM: <https://aos.owasp.org/spec/inspect/>
- MITRE ATLAS v5.6: <https://atlas.mitre.org/>
- Google k8s-aibom: <https://github.com/GoogleCloudPlatform/k8s-aibom>;
  <https://cloud.google.com/blog/products/identity-security/introducing-k8s-aibom-on-gke-for-automated-ai-bills-of-materials>
- G7 Cybersecurity Working Group / CISA, *SBOM for AI – Minimum Elements* (12 May 2026):
  <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html>
- Clinejection: <https://adnanthekhan.com/posts/clinejection/>; <https://github.com/cline/cline/security/advisories/GHSA-9ppg-jx86-fqw7>;
  <https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/>
- Deadbugz: <https://labs.cloudsecurityalliance.org/research/csa-research-note-deadbugz-mcp-supply-chain-20260830-csa-sty/>
- Invariant Labs tool poisoning and WhatsApp shadowing: <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>,
  <https://invariantlabs.ai/blog/whatsapp-mcp-exploited>
- Amazon Q extension: <https://github.com/aws/aws-toolkit-vscode/security/advisories/GHSA-7g7f-ff96-5gcw>;
  mcp-remote CVE-2025-6514: <https://github.com/advisories/GHSA-6xpm-ggf7-wc3p>
- Unit 42, Model Namespace Reuse: <https://unit42.paloaltonetworks.com/model-namespace-reuse/>
- Spracklen et al., package hallucinations (USENIX Security 2025): <https://arxiv.org/abs/2406.10279>
- nullifAI: <https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face>; Sleepy Pickle:
  <https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/>; CVE-2024-34359:
  <https://github.com/advisories/GHSA-56xg-wfcc-g829>; safetensors audit: <https://huggingface.co/blog/safetensors-security-audit>
- OpenSSF Model Signing v1.0: <https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/>;
  sigstore/model-transparency: <https://github.com/sigstore/model-transparency>
- PoisonedRAG: <https://arxiv.org/abs/2402.07867>; MCPTox: <https://arxiv.org/abs/2508.14925>; Anthropic/UK AISI/Turing poisoning study:
  <https://www.anthropic.com/research/small-samples-poison>; Carlini et al., web-scale dataset poisoning: <https://arxiv.org/abs/2302.10149>
- Radanliev et al., *SBOMs into Agentic AIBOMs*: <https://arxiv.org/abs/2603.10057>; AIRS: <https://arxiv.org/abs/2511.12668>;
  TAIBOM: <https://arxiv.org/abs/2510.02169>; Cisco Model Provenance Kit: <https://github.com/cisco-ai-defense/model-provenance-kit>
- Dependency-Track releases: <https://github.com/DependencyTrack/dependency-track/releases>; Microsoft sbom-tool:
  <https://github.com/microsoft/sbom-tool/releases>; Yocto SPDX 3 sizes: <https://sbomify.com/2026/05/19/yocto-spdx-3-0-overview/>
- ECMA-427 Package-URL: <https://ecma-international.org/publications-and-standards/standards/ecma-427/>
- EU AI Act Article 15: <https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-15>; NIST AI RMF Playbook (GOVERN 1.6):
  <https://www.nist.gov/itl/ai-risk-management-framework/ai-rmf-playbook>
- RFC 8785 (JCS): <https://www.rfc-editor.org/rfc/rfc8785>; RFC 6962 (Merkle trees): <https://www.rfc-editor.org/rfc/rfc6962>;
  in-toto attestation: <https://github.com/in-toto/attestation>; DSSE: <https://github.com/secure-systems-lab/dsse>;
  OpenTelemetry GenAI semantic conventions: <https://opentelemetry.io/docs/specs/semconv/gen-ai/>
- The original article: <https://medium.com/@EmmanuelDahunsi/the-supply-chain-of-agency-c73667e08162>
