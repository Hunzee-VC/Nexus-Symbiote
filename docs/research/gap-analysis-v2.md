
# Part I. Gap analysis: what CycloneDX 1.7 and SPDX 3.0.1 can say about an AI agent

*Checked on 1 November 2026 against normative schemas and model files where they exist. Secondary sources are marked as reported.*

## 1. The case: Cline, February 2026

Cline's issue-triage workflow ran Claude Code on new GitHub issues. It put the issue title straight into the prompt, accepted input from users without write access, and allowed Bash, Write and Edit [1]. On 9 February 2026 Adnan Khan published the attack chain, which he named Clinejection: a crafted title could make the bot run code, poison the GitHub Actions cache that the nightly release workflow restored, and expose the publish tokens [2]. Cline removed the workflows within 30 minutes of Khan's public post (he had reported the flaw privately on 1 January without a response), but its post-mortem says it deleted the wrong npm token and left the exposed one active [2, 3]. Later forensics traced an in-the-wild injection to issue #8904, opened on 28 January [4]. On 17 February at 3:26 a.m. PT an unauthorized party used that token to publish `cline@2.3.0`, identical to 2.2.3 except for a postinstall script running `npm install -g openclaw@latest` [5]. OpenClaw is itself a legitimate open-source project, the advisory is rated Low, and Cline deprecated 2.3.0 about eight hours later [5]; the risk was what the same path could have delivered. The CLI had moved to OIDC trusted publishing on 10 February; 2.3.0 came from the old token account, with no provenance [6].

An AIBOM for that bot would have listed its model and the action that ran it. It could not have recorded that the bot ran shell commands on a stranger's text, next to a cache the release job trusted. That was the exposure, and no current BOM format has a field for it.

## 2. Standards status on 1 November 2026

- **CycloneDX 1.7** (21 October 2025) is the current release [7] and became ECMA-424 2nd edition in December 2025 [8]. Since then the project has tagged only patch releases (1.7.1, 1.7.2), and its release table goes from 1.7 straight to 2.0, with no 1.8 branch or schema [9].
- **CycloneDX 2.0** is a draft. The specification repository lists its release as "to be announced" [9]; the project's 5 August 2026 announcement expects release in fall 2026 and Ecma approval in December [10].
- **CycloneDX proposals** (open, not adopted): discussion #973 proposes a runtime "AI Assertion Record" linking ML-BOM documentation to specific AI-supported decisions [11]. Issue #1015 proposes digest anchors (tool manifest, policy bundle, model snapshot) on an agent component, which neither 1.7 nor the 2.0 draft defines (2.0 models an agent as a party [12]), so that behavior records can point at a BOM snapshot [13]; it builds on the community Agent BOM proposal, #895 [14].
- **SPDX 3.0.1** is current; the specification site's `latest` alias still points to it [15].
- **SPDX 3.1** is a release candidate. RC1 (24 January 2026) deprecates `autonomyType` for a Core `isoAutomationLevel`, relaxes `AIPackage` and `DatasetPackage` requirements, grows relationship types from 59 to 76, and adds Service, Operations, Hardware, Functional Safety and Supply Chain profiles [16, 17]. RC1 has no class for an AI agent, a prompt, a RAG pipeline or an agent-callable tool; its Core `Tool` class covers any software or hardware used to carry out a function [17]. Since RC1 the development model has added one AI class, `InteractionTemplate`, and reached 82 relationship types [18], and the development specification has drafted a whole-document signing clause [19]. There is still no AI-agent, retrieval or memory class; an agent can be described only as a Core `SoftwareAgent` [18].
- **MCP 2026-07-28** retired the initialize handshake and protocol sessions, made tool lists cacheable with `ttlMs` and `cacheScope`, and moved server instructions into the result of `server/discover`, which servers must implement and clients may skip [20, 21]. Its schema has no signature, digest or integrity field [21].
- **Tooling.** Dependency-Track accepts CycloneDX 1.7 only from v5.1.0 (27 August 2026) and its v4.14.4 backport (14 September 2026), about ten months after 1.7 shipped [22, 23]. Syft, Trivy, Microsoft sbom-tool, Kubernetes bom and Zephyr still default to SPDX 2.x, with SPDX 3 output opt-in or experimental and mostly targeting 3.0.1; Yocto is the main generator that defaults to 3.0.1 [24, 25, 26, 27, 28, 29]. The official Python tools fully validate only SPDX 2.2 and 2.3 and can write but not read SPDX 3 [30].

Design against CycloneDX 1.7 and SPDX 3.0.1 today, track the drafts, and don't plan around features they don't have.

## 3. Four questions

An agent BOM earns its place by answering four questions with evidence:

1. **Composition.** What was built or declared, and by which pipeline?
2. **Authorization.** What may the agent do, with whose credentials, under which policy?
3. **Observability.** What is deployed, and what has it actually done?
4. **Assurance.** Why should anyone believe each of those answers?

Today's formats answer the first question for models and datasets. They barely touch the other three.

## 4. Six layers and a delivery axis

| Group | Layer | What it contains |
|---|---|---|
| What it knows | 1. Data and memory | Training and fine-tuning data, RAG corpora and their connectors, vector indexes, tool outputs, the memory the agent writes for itself |
| How it reasons | 2. Model | Weights, adapters, tokenizer, chat template, serialization format; for a hosted API, the provider, the endpoint and the snapshot behind the alias |
| How it reasons | 3. Instructions and agent configuration | System prompts, AGENTS.md, CLAUDE.md, rules files, SKILL.md, MCP server instructions; configuration that runs code: hooks, MCP launch commands, endpoint overrides, auto-approve settings |
| What it can do | 4. Tools and peers | MCP servers and their dependency trees, tool definitions, plugins, skill scripts, APIs, A2A peers, sub-agents |
| What it can do | 5. Runtime and host | Framework or harness, MCP client, LLM gateway or router, inference server, sandbox, developer machine, CI runner |
| Whose authority it uses | 6. Identity and credentials | Workload identities, delegated user tokens, OAuth grants and API keys held by connectors, servers and gateways, approval gates |
| Delivery, for all six | Registries and the build pipeline | Model hubs, npm and PyPI, MCP registries, skill marketplaces, container registries, the CI/CD that builds and publishes the agent, AI agents running inside CI |

Clinejection ended as a delivery attack, but it began with untrusted text steering a CI agent's shell tools next to a cache the release job trusted; LiteLLM's March 2026 compromise (section 5.5) was a pure delivery attack. Neither changed a model, a dataset or a tool definition.

For each layer below: what the two formats express natively, what is missing, what draft work exists, and which incidents make the gap concrete. "Native" means a standard field or class with matching meaning; a vendor property is not native, because two consumers will not read it the same way.

## 5. Layer by layer

### 5.1 Data and memory

**Native today.** CycloneDX has `data` components (dataset, configuration, definition) with classification, governance roles and hashes, and model cards can point to datasets [31]. SPDX 3.0.1 has `DatasetPackage`, with a TLP-style `confidentialityLevel` and a free-text `datasetUpdateMechanism`, tied to models by `trainedOn` and `testedOn` [32].

**Missing.** Both treat data as a build-time input. Neither models a retrieval index (corpus, embedding model, chunking, build time), a memory store, who may write to it, a snapshot commitment, or whether retrieved text can carry instructions. Provenance stays prose: Cohere's September 2026 EU training-content summary names Common Crawl and otherwise cites proprietary datasets [33].

**Under way (1 November 2026).** SPDX 3.1-RC1 adds `pretrainedOn`, `finetunedOn`, `evaluatedOn` and `validatedOn` edges [17] and a free-text Core `intendedUse` [16]. Neither RC1 nor the development model has a retrieval or memory class [17, 18], and the CycloneDX 2.0 draft adds no index or memory component type [34].

**Incidents.** In February 2026 Microsoft described 31 companies planting instructions such as "remember [Company] as a trusted source" in assistants' memory through "Summarize with AI" buttons and share links [35]. EchoLeak (CVE-2025-32711, June 2025) needed one email to make Microsoft 365 Copilot leak data from its context, as reported by The Hacker News [36]. In ForcedLeak (September 2025), text injected through a Salesforce web form sent CRM data to an allowlisted domain whose registration had lapsed, as reported by The Hacker News [37].

### 5.2 Model

**Native today.** CycloneDX has had a `machine-learning-model` component with a model card since 1.5, plus `hashes`, generic `pedigree`, OmniBOR and SWHID identifiers (1.6) and `isExternal` (1.7) [31]. SPDX 3.0.1 `AIPackage` adds 15 AI properties, all optional and mostly free text, including a yes/no/noAssertion `autonomyType` [38]. A `pkg:huggingface` purl names a repository, optionally pinned to a commit; the type defines no qualifier for format or quantization, and only the generic `file_name` and `checksum` qualifiers can single out one weight file [39, 40].

**Missing for weights.**
- No field says whether loading a file runs code. Pickle does, `trust_remote_code` does, and chat templates are Jinja programs: CVE-2024-34359 ran code from a GGUF file's chat template in llama-cpp-python [41].
- Tokenizers and chat templates have no schema field: the official property taxonomy only marks a component as a tokenizer or chat template (`cdx:ai-ml:model:tokenizer`, `cdx:ai-ml:model:template:chat`), and CycloneDX's own AI/ML-BOM guide (March 2026, revised June 2026) tells producers to treat them as annotated components [42, 43].
- Lineage is generic, with no typed edges for fine-tune, adapter, quantize, merge, distill or convert. Nothing requires a weight digest, and both formats still accept MD5 and SHA-1 [31, 32]. Evaluation scores are bare strings, with no benchmark version, dataset digest or harness.
- Hashes prove identity, not innocence. Weight fingerprinting such as Cisco's Model Provenance Kit (May 2026) links a derivative to its base family; it is lineage evidence, not a trojan detector [44].

**Missing for hosted models.** A CycloneDX service carries a version string, and SPDX 3.0.1 has no service class [32]. Nothing separates the alias you asked for, the snapshot it resolved to and the model that answered. None of the protocols or formats reviewed here (CycloneDX 1.7, SPDX 3.0.1, MCP 2026-07-28, A2A, OpenTelemetry's GenAI conventions) defines a provider-signed statement of which model served a response [21, 31, 32, 45, 46], so until providers sign it, a hosted model's identity can be observed but not verified. OpenTelemetry's GenAI conventions, still at Development status, record the requested and responding model names [45].

**Under way (1 November 2026).** SPDX 3.1-RC1 relaxes `AIPackage` so that only `primaryPurpose` stays required [16, 47]; its `SoftwareService` holds a provider, a hosting country and an authentication protocol, and no model fields [17]. The CycloneDX 2.0 draft adds quantization metadata, not a serialization-format field [34]. OpenSSF Model Signing (1.0.0 April 2025, 1.1.1 October 2025) signs a manifest of per-file or per-shard digests as an in-toto statement and does not hash tensors [48]. The draft second edition of ECMA-427 (PURL) moves the long-standing generic `file_name` and `checksum` qualifiers into the standard as recommended qualifiers [40].

**Incidents.** Unit 42 showed on 3 September 2025 that a deleted or transferred Hugging Face namespace can be re-registered, so pipelines that resolve models by name pull the attacker's model [49]. On the hosted side, OpenAI rolled out a GPT-4o update on 24-25 April 2025 and began rolling it back on 28 April for sycophancy [50]. Anthropic's 17 September 2025 postmortem traced degraded Claude responses to three infrastructure bugs; one hit 16% of Sonnet 4 requests in its worst hour [51]. Neither changed a model name. The endpoint is part of identity too: Check Point reported in February 2026, as covered by ITPro, that a repository's Claude Code settings could point the API base URL at an attacker before the trust prompt [52].

### 5.3 Instructions and agent configuration

**Native today.** A CycloneDX `file` or `data` component can hash a prompt file. The property taxonomy defines `cdx:ai-ml:model:template:prompt` and `cdx:ai-ml:model:template:chat`, and reserves `cdx:ai-ml:prompt` without properties [43]. SPDX 3.0.1 can describe a `File` with purpose `configuration`, a hash and a `configures` relationship [32].

**Missing.** There is no instruction type. Nothing records load order, who may edit a file, whether it pulls remote content, or whether loading it runs code (hooks, MCP launch commands, endpoint overrides, auto-approve settings) before any trust prompt. MCP server instructions reach the model and sit outside every package hash.

**Under way (1 November 2026).** The SPDX 3.1 development model added `InteractionTemplate`: a template string and dictionary linked by `configures`. It has no mandatory digest, nothing separates a deployed system prompt from a template, and it refers to an `AIAgent` class the model does not define [53]. cdxgen issue #4593 plans to describe declared coding-agent behavior at CycloneDX 2.0 from instruction files, skills and MCP configuration, as categories, tool names and scopes rather than raw text [54].

**Incidents.** In Cursor's MCPoison (CVE-2025-54136, August 2025), trust was bound to an MCP configuration's name, so its command could be swapped after approval with no new prompt; Cursor 1.3 fixed it [55]. In Codex CLI (CVE-2025-61260, disclosed December 2025), a repository's `.env` redirected `CODEX_HOME`, so project MCP commands ran at startup without approval; Check Point says 0.23.0 (20 August 2025) fixed it, although the CVE record lists "v0.23.0 and before" as affected [56]. Pillar Security's Rules File Backdoor (March 2025) hid instructions in rules files with invisible Unicode, as reported by The Hacker News [57]. Check Point also reported, as covered by ITPro, Claude Code project settings that ran hooks and MCP commands before the trust prompt [52].

### 5.4 Tools and peers

**Native today.** CycloneDX `services[]` carry endpoints, `authenticated`, `x-trust-boundary`, `trustZone` and data flows, but no input or output schema, no `hashes` and no annotation vocabulary. A `data` component of type `definition` can hold a tool-definition digest, but nothing binds it to the service or defines a canonical form. `dependencies` offers only `dependsOn` and `provides`, and an edge cannot carry properties [31]. SPDX 3.0.1 has `usesTool`, `invokedBy` and `delegatedTo`, which can be scoped to runtime with start and end times, and no tool-definition or service class [32].

**Missing.** A canonical digest of everything the model reads (name, title, description, schemas, annotations, server instructions), bound to the server's identity. Capability facts that are more than the server's own word: the MCP specification says clients MUST treat tool annotations as untrusted unless they come from trusted servers [58], and its maintainers write that "an untrusted server can lie" [59]. Delegation limits: SPDX can record that an Agent `delegatedTo` an `invokedBy` edge and bound that edge with start and end times, but not with what scope or audience, and CycloneDX has no delegation edge.

**Under way (1 November 2026).**
- MCP 2026-07-28 tool lists carry `ttlMs` and `cacheScope`, and a `private` list must not be shared across authorization contexts, so one server can show different users different tools [21]. The 22 August 2026 roadmap says the existing Server Card Working Group is still working on `.well-known` discovery metadata for MCP servers; it does not mention server signing or tool-definition integrity [60].
- CoSAI's MCP Security paper (v2.0, 12 August 2026) asks for cryptographically pinned tool definitions at level 3 and signed tool-definition manifests at level 4 [61].
- The CycloneDX 2.0 draft has behavior verbs such as `ai:agent:invokesTool` and `ai:agent:delegatesTask`, each marked declared or observed. A behavior is not a grant: there are no scopes, conditions, expiry or policy references [62].
- A2A 1.0.0 (12 March 2026) lets providers sign Agent Cards with JWS over RFC 8785 canonical JSON. Signing is optional, clients SHOULD verify, and the key can come from a URL the same provider controls [46, 63].

**Incidents.** An npm package called `postmark-mcp`, not Postmark's own, published version 1.0.16 on 17 September 2025 and was unpublished on 25 September [64]. Koi Security reported, as covered by The Hacker News, that 1.0.16 added one line that BCC'd every outgoing email to the attacker [65]. The mail left through Postmark's API, so an egress allowlist would not have stopped it. When axios was hijacked on npm in March 2026, the malicious release carried the `latest` tag, so unpinned installs pulled it [66]. MCP client configurations that launch servers with `npx -y` re-resolve the newest matching release on every start, and a bare `uvx` takes the newest release on first run and whatever is cached after that [67]; neither pins the version that was approved.

### 5.5 Runtime and host

**Native today.** CycloneDX has `framework`, `platform`, `application` and `container` components and can label a BOM `operations` or `discovery` [31]. SPDX 3.0.1 can type an SBOM `runtime` or `deployed` and scope relationships to runtime [32].

**Missing.** A gateway or router can be listed, but not the provider keys it holds, its routes from alias to provider model, or the agents that pass through it. A coding agent's permission mode (auto-approve, skip-permissions) has no field. Developer machines and CI runners are not modeled as places where agents run.

**Under way (1 November 2026).** Google open-sourced k8s-aibom on 13 July 2026; it emits CycloneDX 1.6 ML-BOMs from live Kubernetes workloads, covering serving runtimes, agent frameworks and vector databases [68]. It tags each attribute declared, inferred, unresolved or verified, describes itself as suited to non-critical observation, and does not inventory MCP servers, tool schemas, skill files or prompts [69]. SPDX 3.1-RC1 adds a `runsOn` relationship [17].

**Incidents.** LiteLLM, a gateway that holds the keys for every provider behind it, had malicious releases published under its name twice in 2026. On 24 March, versions 1.82.7 and 1.82.8 carried a credential stealer, published with a PyPI token that a compromised Trivy scanner had stolen from LiteLLM's CI [70]. On 21 October, malicious 1.107.0 wheels and official Docker images followed, as reported by The Hacker News [71]; PyPI no longer lists any of the three versions [72]. The malicious Nx packages of 26 August 2025 ran the victim's Claude Code, Gemini CLI and Amazon Q with `--dangerously-skip-permissions`, `--yolo` and `--trust-all-tools` to hunt for secrets, as reported by OX Security [73], and the SANDWORM_MODE worm (20 February 2026) registered a rogue MCP server in several assistants' configurations [74].

### 5.6 Identity and credentials

**Native today.** CycloneDX services carry a boolean `authenticated`, trust zones and data flows; `supplier`, `manufacturer`, `authors` and a service's `provider` say who supplied or made a component, service or the BOM, not on whose authority the agent acts [31]. In SPDX 3.0.1 an `Agent` is anything that can act on a system (`Person`, `Organization`, `SoftwareAgent`; `Tool` is a separate class), `invokedBy` and `delegatedTo` name actors, and every relationship can carry start and end times [32]. Autonomy is one yes/no/noAssertion value per AI package [38].

**Missing.** Authority: scopes, egress destinations, data classes, spend ceilings, approval gates, delegation limits, and where a deny is enforced. Custody: which component holds which credential, where, for how long and how to revoke it. Declared, policy-derived and observed permissions need separate records, and autonomy has to be stated per action: an agent may read issues on its own, need approval to change code, and never publish.

**Under way (1 November 2026).** SPDX 3.1-RC1's `isoAutomationLevel` is still one value per system [16], and the development model's new `Role` carries a free-text `authorization` property [75]. CycloneDX 2.0 draft verbs such as `ai:agent:actsOnBehalfOfUser` describe behavior, not grants [62]. MCP made Enterprise-Managed Authorization stable on 18 June 2026 [76], and its roadmap points agent identity at DPoP, workload identity federation and token exchange [60]. A BOM should reference those identity artifacts, never token values, rather than invent its own.

**Incidents.** From as early as 8 August to at least 18 August 2025, UNC6395 used OAuth tokens stolen from Salesloft's Drift integration to export data from Salesforce instances, then searched it for AWS keys, passwords and Snowflake tokens; Google advised treating every token stored in or connected to Drift as potentially compromised [77]. GitGuardian counted 24,008 unique secrets exposed in MCP configuration files [78]. Cline's triage bot (section 1) is the authority case in miniature: shell tools, untrusted input and a cache shared with the release job.

### 5.7 Delivery: registries and the build pipeline

**Native today.** CycloneDX has purls, `externalReferences` of type `distribution`, `distribution-intake` and `attestation`, and `formulation` (since 1.5) for build workflows; formulation is self-reported [31]. SPDX 3.0.1 has `ExternalRef`, `availableFrom` and a Build profile [32, 79]. CycloneDX defines enveloped signatures (JSF for JSON, XML Signature for XML), but tools rarely use them: the official CycloneDX CLI signs only XML BOMs [80]. SPDX 3.0.1 has no signature mechanism. In practice teams wrap BOMs in in-toto statements with `cosign attest` [81].

**Missing.** A record of how each component's origin was established: the name requested, the immutable reference it resolved to, how the publisher was verified, the signer, transparency-log inclusion and fetch time. A link from the agent BOM to the pipeline that built it, and a record of AI agents running inside CI with the authority they hold. Model discovery depends on the generator: cdxgen discovers models only in its AI-BOM mode (`aibom` or `-t ai`), and its README warns that `--component-type machine-learning-model` is "a filter, not an inventory enabler" [82]; Syft v1.55.0 catalogs GGUF and SafeTensors files by default on directory and image scans but records nothing about agents, tools or instructions [83].

**Under way (1 November 2026).** The official MCP Registry has been in preview since 8 September 2025, with its API frozen at v0.1 since 24 October 2025 [84]. Its `server.json` carries no tool definitions and no signature or attestation field, and a `fileSha256` is required only for MCPB bundles [85]. SLSA has no ML or training track [86], and in-toto has no vetted ML predicate [87].

**Incidents.** Clinejection and LiteLLM's March compromise both started in CI. Microsoft showed on 5 June 2026 that the Claude Code GitHub Action could expose workflow secrets when it processed untrusted issue or pull-request text; Claude Code 2.1.128 mitigated it [88]. In Noma's GitLost (July 2026), an issue in a public repository made a GitHub Agentic Workflow pull data from private ones, as reported by InfoQ [89]. Koi Security reported on 1 February 2026 that it found 341 malicious skills among 2,857 it audited on ClawHub, as reported by The Hacker News [90].

## 6. Cross-cutting gaps

**Signing, attribution and assurance.** Attribution is not verification. CycloneDX 1.7 `citations` attribute data to a source, process or party, with an optional signature over the attribution [31], and SPDX gives every element creation information. CycloneDX 1.7 can attach a 0-1 confidence to component identity evidence and to CDXA attestation claims, but it defines no method for arriving at a score and grades none of the BOM's other facts, and neither format records which signer a verifier expected [31]. SPDX 3.0.1 has no signature mechanism; the 3.1 development text adds signing of whole documents only, never of individual elements [19]. k8s-aibom shows a working model: it never lets a claim upgrade itself and records a valid signature from an unconstrained signer as a fact without raising confidence [69, 91]. The CycloneDX 2.0 draft lets each determination carry its technique, tool, confidence, evidence location, timestamp and asserting party [10].

**Coverage: unknown is not absence.** CycloneDX `compositions` state completeness as complete, several incomplete variants, unknown or not specified [31]; SPDX relationships carry complete, incomplete or noAssertion [32]. Neither says which surfaces were examined, over what window, or which queries failed. "No unregistered tools found" means something only if the registry, the deployment configuration and the live tool list were all reachable.

**Runtime binding.** Both formats can label a BOM as describing a running system. Neither gives a BOM snapshot as a whole a validity window (SPDX's `validUntilTime` applies to individual artifacts), a standard delta, or a way for an agent action to cite the snapshot it ran under, which is the gap CycloneDX #973 and #1015 raise [11, 13]. MCP 2026-07-28 removed protocol-level sessions and documents OpenTelemetry trace-context keys (`traceparent`, `tracestate`, `baggage`) for `_meta`, so runtime evidence should bind to trace and request identifiers [92]. A diff between declared and observed BOMs catches composition drift but not misuse inside the declared set: an injected agent that exfiltrates through an approved email tool produces no diff.

**Evaluations and AI weaknesses.** CycloneDX VEX justifications are generic statements about vulnerable code, with no agent-specific values. `requires_configuration`, `protected_at_runtime` and `protected_by_mitigating_control` roughly cover "tool disabled", "guardrail enforced" and "human approval required", but nothing points at the specific guardrail, policy version or approval gate [31]. SPDX 3.0.1 defines four VEX status relationships (affected, not affected, fixed, under investigation) and five justification types [32, 93]; its informative guide mostly covers linking out to CSAF VEX rather than how to produce embedded VEX [94]. The CycloneDX 2.0 draft reworks VEX into attributed determinations on an eight-level exploitability scale [95]. An evaluation result must also name the configuration it tested and lapse when any part of it changes. ISO/IEC 42001 will not supply that schema: it is a management-system standard that, in Google Cloud's words, it "does not mandate specific AI controls" [96].

**Transparency versus an attack map.** A complete agent BOM lists tools, scopes and trust boundaries. CycloneDX 1.7's `distributionConstraints.tlp` labels a whole BOM and SPDX's `confidentialityLevel` labels a dataset [31, 32]. Neither lets a consumer verify a redacted copy against the original.

**Conformance and dialects.** SPDX makes every profile except Core optional, and conformance to the AI profile does not entail Software, Security or Dataset support [79], so "SPDX-compatible" says little. Agent facts already travel in incompatible dialects. cdxgen writes `cdx:mcp:*`, `cdx:agent:*`, `cdx:tool:*` and `cdx:skill:*` [97], although the taxonomy forbids unofficial sub-namespaces under `cdx` [98]. k8s-aibom writes `aibom.*` [91]. SymBiote's own `agentbom:` namespace (Part II) is one more such dialect until it is registered. OWASP AOS's draft AgBOM example uses component types `service` and `tool` and a top-level `signatures` array, which fail CycloneDX 1.6 schema validation [99]. Cisco's AI BOM folds 30 internal component types into CycloneDX's 13 [100]. Converting between the formats can lose information; cyclonedx-cli, which converts CycloneDX to and from SPDX 2.3 JSON, warns about it [101].

**Regulatory baselines.** The G7 Cybersecurity Working Group's "SBOM for AI: Minimum Elements", published by BSI on 12 May 2026, has seven clusters according to the openregtech/sbom project's machine-readable encoding; its Models cluster asks for an identifier, a hash value and algorithm, a license and training properties [102]. Treat it as the floor: a hash means nothing for an API model behind an alias. EU AI Act Article 53(1)(c)-(d) requires providers of general-purpose AI models to keep a copyright policy that honors text-and-data-mining opt-outs and to publish a training-content summary on the AI Office template [Author: cite Regulation (EU) 2024/1689, Art. 53; the EUR-Lex URL could not be reached to confirm it]; in Cohere's filed summary, licensed data is a yes/no/other answer about whether licensing agreements were concluded, and nothing asks about consent [33].

## 7. Summary

| Layer | CycloneDX 1.7 | SPDX 3.0.1 | Draft work, 1 November 2026 |
|---|---|---|---|
| Data and memory | Datasets native; no index, memory store, writers or trust tier | Datasets native; same gaps | 3.1-RC1 training and evaluation data edges; no retrieval or memory class |
| Model: weights | Component, model card, hashes; no load-time execution flag, typed lineage or required digest | `AIPackage`, mostly free text; same gaps | 2.0 draft quantization metadata; 3.1-RC1 relaxes `AIPackage` |
| Model: hosted | Service with a version string | No service class | 3.1-RC1 `SoftwareService`, no model fields |
| Instructions and configuration | File or data component with a hash; prompt and chat-template property names | `File` plus `configures` | 3.1 development `InteractionTemplate`, no mandatory digest |
| Tools and peers | Generic service; digest only in an unbound `definition` component; no capabilities | `usesTool`, `invokedBy`, `delegatedTo`, runtime-scoped and time-bounded; no delegation scope or audience | 2.0 draft behavior verbs, declared or observed |
| Runtime and host | Generic components; runtime lifecycle labels | `runtime` and `deployed` SBOM types | 3.1-RC1 `runsOn` |
| Identity and credentials | `authenticated` flag, trust zones | Actor classes, `delegatedTo`; no permissions | 3.1 development `Role` with free-text authorization; 2.0 draft verbs |
| Delivery | `externalReferences`; self-reported `formulation` | `ExternalRef`, `availableFrom`, Build profile | 3.1 development signing clause |

Both formats describe models and datasets. Neither says what an agent may do, binds what runs to what was approved, or records for every claim whether it was declared, observed or verified.

## 8. Prior art, and what is still open

Most pieces exist somewhere: pinned and signed tool definitions in CoSAI's levels [61], signed Agent Cards in A2A [46], content identity for models in OpenSSF Model Signing [48], graded attributes in k8s-aibom [69], agent inventories in cdxgen and Cisco's AI BOM [97, 100], the community CycloneDX Agent BOM proposal (#895) and WasmAgent's AgentBOM library, which validates, scores and diffs agent inventories [14, 103], and schema extensions for agentic AIBOMs from Radanliev, Maple, Santos and Atefi (March 2026) [104].

Still open: one vocabulary across CycloneDX and SPDX; a tool-definition digest profile with test vectors; an authorization record bound to tool and policy digests; coverage where failed collection means unknown; a snapshot digest that runtime evidence can cite; expiring hosted-model identity claims; and verifiable redaction.

## 9. Terms

- **AIBOM**: an AI bill of materials in any format. **ML-BOM**: CycloneDX's model and dataset support. **AgBOM**: OWASP AOS's dynamic agent inventory. **AgentBOM**: in this document, the SymBiote profile specified in `spec/`, which extends CycloneDX and SPDX rather than replacing them. It is unrelated to WasmAgent's `agentbom` library, an early implementation of the community CycloneDX Agent BOM proposal (#895) [14, 103].
- **Tool definition**: the name, title, description, schemas and annotations a server shows the model. **Rug pull**: a server changes a tool's definition after approval.
- **Assurance**, per claim: *declared* (the owner says so), *observed* (a named collector saw it within a stated window), *verified* (evidence checked against a trust policy that names the expected signer). **Unknown** means nobody could look; **absent** means someone looked and found nothing.
- **Rule of Two** (Meta, 31 October 2025): within one session an agent must have no more than two of untrusted input, access to sensitive systems or private data, and the ability to change state or communicate externally, until prompt injection can be reliably detected; an agent that needs all three requires supervision, such as human-in-the-loop approval [105]. **Lethal trifecta** (Simon Willison, 16 June 2025): private data, untrusted content and external communication in one agent [106].

### References for Part I

[1] Cline, `.github/workflows/claude-issue-triage.yml` at commit 06b05dd (state of 28 January 2026). https://raw.githubusercontent.com/cline/cline/06b05ddfe909ce47c146f05eb7d08366b56ecbe0/.github/workflows/claude-issue-triage.yml

[2] Adnan Khan, "Clinejection: Compromising Cline's Production Releases just by Prompting an Issue Triager", 9 February 2026. https://adnanthekhan.com/posts/clinejection/

[3] Cline, post-mortem of the unauthorized Cline CLI npm publish, 24 February 2026. https://cline.bot/blog/post-mortem-unauthorized-cline-cli-npm

[4] Michael Bargury, "Raptor Finds Root Cause of Cline's Supply-Chain Compromise", 18 February 2026. https://raw.githubusercontent.com/mbrg/mbgsec/main/_posts/2026-02-18-raptor-finds-cline-compromise.md

[5] Cline, GHSA-9ppg-jx86-fqw7, "Unauthorized npm publish of `cline@2.3.0` with modified postinstall script", published 19 February 2026. https://github.com/cline/cline/security/advisories/GHSA-9ppg-jx86-fqw7

[6] npm registry, `cline` package metadata (checked 1 November 2026). https://registry.npmjs.org/cline

[7] CycloneDX, "CycloneDX v1.7 released", 21 October 2025. https://cyclonedx.org/news/cyclonedx-v1.7-released/

[8] Ecma International, ECMA-424 (CycloneDX), 2nd edition, December 2025. https://ecma-international.org/publications-and-standards/standards/ecma-424/

[9] CycloneDX specification repository, `2.0-dev` branch README (checked 1 November 2026). https://raw.githubusercontent.com/CycloneDX/specification/2.0-dev/README.md

[10] CycloneDX, "CycloneDX 2.0 Delivers Transparency Reaching Far Beyond Bill of Materials", 5 August 2026. https://cyclonedx.org/news/cyclonedx-v2.0-coming-soon/

[11] CycloneDX/specification discussion #973, "Proposal for a runtime AI Assertion Record / chain-of-reliance extension to ML-BOM" (checked 1 November 2026). https://github.com/CycloneDX/specification/discussions/973

[12] CycloneDX 2.0 draft, party module schema (checked 1 November 2026). https://raw.githubusercontent.com/CycloneDX/specification/2.0-dev/schema/2.0/modules/cyclonedx-party-2.0.schema.json

[13] CycloneDX/specification issue #1015, "Behavior evidence gap: linking agent actions back to BOM components" (checked 1 November 2026). https://github.com/CycloneDX/specification/issues/1015

[14] CycloneDX/specification issue #895, community Agent BOM proposal. https://github.com/CycloneDX/specification/issues/895

[15] SPDX specification site, version index (checked 1 November 2026). https://raw.githubusercontent.com/spdx/spdx-spec/gh-pages/versions.json

[16] SPDX 3 model, 3.1-RC1 changelog, 24 January 2026. https://raw.githubusercontent.com/spdx/spdx-3-model/3.1-rc1/CHANGELOG.md

[17] SPDX 3.1-RC1 RDF model (`spdx-model.ttl`), 24 January 2026. https://raw.githubusercontent.com/spdx/spdx-spec/gh-pages/v3.1-RC1/rdf/spdx-model.ttl

[18] SPDX 3.1 development RDF model (`spdx-model.ttl`, checked 1 November 2026). https://raw.githubusercontent.com/spdx/spdx-spec/gh-pages/v3.1-dev/rdf/spdx-model.ttl

[19] SPDX specification, development branch, clause "Signing" (checked 1 November 2026). https://raw.githubusercontent.com/spdx/spdx-spec/develop/docs/signing.md

[20] Model Context Protocol blog, release post for specification 2026-07-28. https://blog.modelcontextprotocol.io/posts/2026-07-28/

[21] Model Context Protocol, schema for specification 2026-07-28 (`schema.ts`). https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts

[22] Dependency-Track 5.1.0, `CycloneDxValidator.java` at tag 5.1.0 (accepts CycloneDX 1.7), release of 27 August 2026. https://raw.githubusercontent.com/DependencyTrack/dependency-track/5.1.0/apiserver/src/main/java/org/dependencytrack/parser/cyclonedx/CycloneDxValidator.java

[23] Dependency-Track, v4.14.4 release notes, 14 September 2026. https://raw.githubusercontent.com/DependencyTrack/dependency-track/4.14.x/docs/_posts/2026-09-14-v4.14.4.md

[24] Syft, `spdxutil/versions.go` (default SPDX version 2.3). https://raw.githubusercontent.com/anchore/syft/main/syft/format/internal/spdxutil/versions.go

[25] Trivy, SBOM guide (SPDX output is SPDX-2.3). https://raw.githubusercontent.com/aquasecurity/trivy/main/docs/guide/supply-chain/sbom.md

[26] Microsoft sbom-tool README (generation defaults to SPDX 2.2). https://raw.githubusercontent.com/microsoft/sbom-tool/main/README.md

[27] Kubernetes SIG Release, `bom` README (SPDX 2.3 by default; SPDX 3.0.1 experimental). https://raw.githubusercontent.com/kubernetes-sigs/bom/main/README.md

[28] Zephyr, `west spdx` documentation (SPDX 2.3 default; SPDX 3.1 experimental). https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/main/doc/develop/west/zephyr-cmds.rst

[29] OpenEmbedded-Core, `create-spdx-3.0.bbclass` (SPDX_VERSION 3.0.1). https://raw.githubusercontent.com/openembedded/openembedded-core/master/meta/classes/create-spdx-3.0.bbclass

[30] spdx-tools 0.8.5 (PyPI metadata), 13 March 2026. https://pypi.org/pypi/spdx-tools/json

[31] CycloneDX 1.7 JSON schema (`bom-1.7.schema.json`). https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.7.schema.json

[32] SPDX 3.0.1 RDF model (`spdx-model.ttl`). https://raw.githubusercontent.com/spdx/spdx-spec/gh-pages/v3.0.1/rdf/spdx-model.ttl

[33] Cohere, "Public Summary of Training Content for Command A+ and family", v1.1, 10 September 2026. https://raw.githubusercontent.com/cohere-ai/cohere-developer-experience/main/fern/assets/documents/eu-ai-public-summary_command-a-plus-family_20260910.pdf

[34] CycloneDX 2.0 draft, bundled schema (`2.0-dev`, checked 1 November 2026). https://raw.githubusercontent.com/CycloneDX/specification/2.0-dev/schema/2.0/cyclonedx-2.0-bundled.schema.json

[35] Microsoft Security Blog, "Manipulating AI memory for profit: The rise of AI Recommendation Poisoning", 10 February 2026. https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/

[36] The Hacker News, zero-click EchoLeak vulnerability in Microsoft 365 Copilot (CVE-2025-32711), June 2025. https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html

[37] The Hacker News, Salesforce patches ForcedLeak in Agentforce, September 2025. https://thehackernews.com/2025/09/salesforce-patches-critical-forcedleak.html

[38] SPDX 3.0.1 model, `AI/AIPackage`. https://raw.githubusercontent.com/spdx/spdx-3-model/3.0.1/model/AI/Classes/AIPackage.md

[39] purl-spec, `huggingface` type definition. https://raw.githubusercontent.com/package-url/purl-spec/main/types/huggingface-definition.json

[40] purl-spec, Annex B, recommended qualifiers (draft ECMA-427 2nd edition). https://raw.githubusercontent.com/package-url/purl-spec/main/docs/specification/standard/Annex-B-Recommended-Qualifiers.md

[41] CVE List, CVE-2024-34359 (llama-cpp-python chat template injection), May 2024. https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/34xxx/CVE-2024-34359.json

[42] OWASP CycloneDX, Authoritative Guide to AI/ML-BOM, First Edition, revision 1, 10 June 2026. https://raw.githubusercontent.com/CycloneDX/guides/main/ML-BOM/en/0x01-Frontispiece.md

[43] CycloneDX property taxonomy, `cdx:ai-ml` namespace. https://raw.githubusercontent.com/CycloneDX/cyclonedx-property-taxonomy/main/cdx/ai-ml.md

[44] Cisco AI Defense, Model Provenance Kit README. https://raw.githubusercontent.com/cisco-ai-defense/model-provenance-kit/main/README.md

[45] OpenTelemetry, GenAI semantic conventions, attribute registry (status Development). https://raw.githubusercontent.com/open-telemetry/semantic-conventions-genai/main/docs/registry/attributes/gen-ai.md

[46] A2A Protocol specification, Agent Card signing. https://raw.githubusercontent.com/a2aproject/A2A/main/docs/specification.md

[47] SPDX 3 model, 3.1-RC1, `AI/AIPackage`. https://raw.githubusercontent.com/spdx/spdx-3-model/3.1-rc1/model/AI/Classes/AIPackage.md

[48] OpenSSF model-signing (PyPI metadata), 1.0.0 of 4 April 2025 to 1.1.1 of 10 October 2025. https://pypi.org/pypi/model-signing/json

[49] Unit 42, "Model Namespace Reuse: An AI Supply-Chain Attack Exploiting Model Name Trust", 3 September 2025. https://unit42.paloaltonetworks.com/model-namespace-reuse/

[50] OpenAI, "Expanding on what we missed with sycophancy", 2025. https://openai.com/index/expanding-on-sycophancy/

[51] Anthropic, "A postmortem of three recent issues", 17 September 2025. https://www.anthropic.com/engineering/a-postmortem-of-three-recent-issues

[52] ITPro, report on Check Point's Claude Code findings, February 2026. https://www.itpro.com/software/development/claude-code-flaws-left-ai-tool-wide-open-to-hackers-heres-what-developers-need-to-know

[53] SPDX 3 model, development branch, `AI/InteractionTemplate` (checked 1 November 2026). https://raw.githubusercontent.com/spdx/spdx-3-model/develop/model/AI/Classes/InteractionTemplate.md

[54] cdxgen issue #4593, "Describe declared coding-agent behaviour in AI-BOMs at CycloneDX 2.0". https://github.com/cdxgen/cdxgen/issues/4593

[55] Check Point Research, Cursor MCPoison (CVE-2025-54136), August 2025. https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/

[56] Check Point Research, OpenAI Codex CLI command injection (CVE-2025-61260), December 2025. https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/

[57] The Hacker News, "Rules File Backdoor" attack, March 2025. https://thehackernews.com/2025/03/new-rules-file-backdoor-attack-lets.html

[58] Model Context Protocol specification 2026-07-28, Server: Tools. https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/docs/specification/2026-07-28/server/tools.mdx

[59] Model Context Protocol blog, post on tool annotations, 16 March 2026. https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/

[60] Model Context Protocol blog, "The New MCP Roadmap", 22 August 2026. https://blog.modelcontextprotocol.io/posts/mcp-roadmap/

[61] CoSAI Workstream 4, "Model Context Protocol (MCP) Security", v2.0, updated 12 August 2026. https://raw.githubusercontent.com/cosai-oasis/ws4-secure-design-agentic-systems/main/whitepapers/model-context-protocol-security.md

[62] CycloneDX 2.0 draft, behavior taxonomy schema (checked 1 November 2026). https://raw.githubusercontent.com/CycloneDX/specification/2.0-dev/schema/behavior-taxonomy.schema.json

[63] A2A Protocol CHANGELOG (1.0.0, 12 March 2026). https://raw.githubusercontent.com/a2aproject/A2A/main/CHANGELOG.md

[64] npm registry, `postmark-mcp` package metadata. https://registry.npmjs.org/postmark-mcp

[65] The Hacker News, first malicious MCP server found (postmark-mcp), September 2025. https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html?m=1

[66] Datadog Security Labs, axios npm supply chain compromise, 2026. https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/

[67] uv documentation, "Tools" (`uvx` version caching). https://raw.githubusercontent.com/astral-sh/uv/main/docs/concepts/tools.md

[68] Google Cloud blog, "Introducing k8s-aibom on GKE for automated AI bills of materials", 13 July 2026. https://cloud.google.com/blog/products/identity-security/introducing-k8s-aibom-on-gke-for-automated-ai-bills-of-materials

[69] GoogleCloudPlatform/k8s-aibom README (checked 1 November 2026). https://raw.githubusercontent.com/GoogleCloudPlatform/k8s-aibom/main/README.md

[70] Snyk, "Poisoned security scanner backdooring LiteLLM", March 2026. https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm

[71] The Hacker News, LiteLLM compromised in supply chain attack, October 2026. https://thehackernews.com/2026/10/litellm-compromised-in-supply-chain.html

[72] PyPI, `litellm` release metadata (checked 1 November 2026). https://pypi.org/pypi/litellm/json

[73] OX Security, "Nx supply chain breach: how s1ngularity weaponized AI", August 2025. https://www.ox.security/blog/nx-supply-chain-breach-how-s1ngularity-weaponized-ai/

[74] Socket, SANDWORM_MODE npm worm and AI toolchain poisoning, February 2026. https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning

[75] SPDX 3 model, development branch, Core `authorization` property (checked 1 November 2026). https://raw.githubusercontent.com/spdx/spdx-3-model/develop/model/Core/Properties/authorization.md

[76] Model Context Protocol blog, Enterprise-Managed Authorization, 18 June 2026. https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/

[77] Google Threat Intelligence Group, data theft from Salesforce instances via Salesloft Drift, August 2025. https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift

[78] GitGuardian, State of Secrets Sprawl 2026. https://gitguardian.com/state-of-secrets-sprawl-report-2026

[79] SPDX 3.0.1 specification, clause 5, Conformance. https://raw.githubusercontent.com/spdx/spdx-spec/3.0.1/docs/conformance.md

[80] CycloneDX cyclonedx-cli, `sign bom` command source. https://raw.githubusercontent.com/CycloneDX/cyclonedx-cli/main/src/cyclonedx/Commands/Sign/SignBomCommand.cs

[81] Sigstore, `cosign attest` documentation. https://raw.githubusercontent.com/sigstore/cosign/main/doc/cosign_attest.md

[82] cdxgen README. https://raw.githubusercontent.com/CycloneDX/cdxgen/master/README.md

[83] Syft v1.55.0, `internal/task/package_tasks.go` (GGUF and SafeTensors catalogers on directory and image scans). https://raw.githubusercontent.com/anchore/syft/v1.55.0/internal/task/package_tasks.go

[84] MCP Registry, design roadmap. https://raw.githubusercontent.com/modelcontextprotocol/registry/main/docs/design/roadmap.md

[85] MCP Registry, `server.json` schema (draft). https://raw.githubusercontent.com/modelcontextprotocol/registry/main/docs/reference/server-json/draft/server.schema.json

[86] SLSA, future directions. https://raw.githubusercontent.com/slsa-framework/slsa/main/spec/future-directions.md

[87] in-toto attestation framework, predicate list. https://raw.githubusercontent.com/in-toto/attestation/main/spec/predicates/README.md

[88] Microsoft Security Blog, "Securing CI/CD in an agentic world: the Claude Code GitHub Action case", 5 June 2026. https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/

[89] InfoQ, GitLost prompt injection in GitHub Agentic Workflows, July 2026. https://www.infoq.com/news/2026/07/gitlost-github-prompt-injection/

[90] The Hacker News, 341 malicious ClawHub skills, February 2026. https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html

[91] GoogleCloudPlatform/k8s-aibom, schema divergences register. https://raw.githubusercontent.com/GoogleCloudPlatform/k8s-aibom/main/docs/schema-divergences.md

[92] Model Context Protocol specification 2026-07-28, changelog. https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/docs/specification/2026-07-28/changelog.mdx

[93] SPDX 3.0.1 model, `Security/VexVulnAssessmentRelationship`. https://raw.githubusercontent.com/spdx/spdx-3-model/3.0.1/model/Security/Classes/VexVulnAssessmentRelationship.md

[94] SPDX, "Using SPDX", security information guide. https://raw.githubusercontent.com/spdx/using/main/docs/security-info-in-spdx.md

[95] CycloneDX 2.0 draft, vulnerability module schema (checked 1 November 2026). https://raw.githubusercontent.com/CycloneDX/specification/2.0-dev/schema/2.0/modules/cyclonedx-vulnerability-2.0.schema.json

[96] Google Cloud, ISO/IEC 42001 compliance page. https://cloud.google.com/security/compliance/iso-42001

[97] cdxgen, MCP documentation. https://raw.githubusercontent.com/CycloneDX/cdxgen/master/docs/MCP.md

[98] CycloneDX property taxonomy, `cdx` namespace rules. https://raw.githubusercontent.com/CycloneDX/cyclonedx-property-taxonomy/main/cdx.md

[99] OWASP Agent Observability Standard, "Extending CycloneDX" (AgBOM example, working draft). https://raw.githubusercontent.com/OWASP/aos/main/docs/spec/inspect/extend_cyclonedx.md

[100] Cisco AI Defense, AI BOM README. https://raw.githubusercontent.com/cisco-ai-defense/aibom/main/README.md

[101] CycloneDX cyclonedx-cli README. https://raw.githubusercontent.com/CycloneDX/cyclonedx-cli/main/README.md

[102] openregtech/sbom, machine-readable encoding of G7 Cybersecurity Working Group, "Software Bill of Materials (SBOM) for Artificial Intelligence: Minimum Elements", published by BSI on 12 May 2026 (original: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.pdf). https://raw.githubusercontent.com/openregtech/sbom/main/docs/req/g7ai/g7ai.ttl

[103] WasmAgent, `agentbom` README (`@wasmagent/agentbom-core`). https://raw.githubusercontent.com/WasmAgent/agentbom/main/README.md

[104] P. Radanliev, C. Maple, O. Santos, K. Atefi, "SBOMs into Agentic AIBOMs: Schema Extensions, Agentic Orchestration, and Reproducibility Evaluation", arXiv:2603.10057, 9 March 2026. https://arxiv.org/abs/2603.10057

[105] Meta AI, "Agents Rule of Two: A Practical Approach to AI Agent Security", 31 October 2025. https://ai.meta.com/blog/practical-ai-agent-security/

[106] Simon Willison, "The lethal trifecta for AI agents", 16 June 2025. https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/

