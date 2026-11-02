# Agent and AI BOM tools landscape, 1 November 2026

This is a companion to Part I of the SymBiote gap analysis. It asks a narrow question: for each gap area the analysis names, which existing tools cover it today, and how well? It covers 31 third-party tools, specifications and services, plus SymBiote itself for comparison.

**Method.** Each entry rests on the claim register (ids such as B6-04 in parentheses), the gap-analysis lenses, or a primary source fetched on 1 or 2 November 2026: the project's README or source, its PyPI, npm or Go module proxy record, or its specification. Versions and dates come from those registries. Where only secondary sources exist, the entry is marked partially verified and capabilities are marked unknown rather than guessed.

**Reading the matrix.** F means the tool addresses the gap area for the artifacts in its scope without a material caveat. P means it covers part of the area, or covers it with a caveat stated in landscape.json. N means it does not address the area. ? means we could not establish it. A scope limit alone is not a caveat; early-stage status (alpha, or pre-1.0 with self-reported adoption) and known unreleased fixes are. A tool that only consumes or signs what others produce gets N for the inventory gaps (G1 to G4 and G8); it can earn P elsewhere where it records or verifies build provenance, attestations, signatures or policy. Coverage describes documented capability, not tested behavior: we ran none of these tools. A P or F means a tool records the area, not that the record is trustworthy. An inventory reports what the scanned host or server discloses, a signature proves who signed a BOM, not that it is complete or true, and no tool here can identify the weights behind a hosted model API. An AIBOM is not a control until a gate, review or query reads it (A7-08).

**Two corrections to earlier drafts.** smithmark exists as a Go module at v0.2.1, and Syft v1.55.0 ships GGUF and SafeTensors model catalogers; the sources are in their entries below.

## Gap areas

- **G1** Tool definitions and digests
- **G2** Instructions and executable agent configuration
- **G3** Hosted model identity
- **G4** Identity and credentials
- **G5** CI and build agents
- **G6** Runtime observation and drift
- **G7** Registry and provenance
- **G8** Data and memory provenance
- **G9** Attestation and signing
- **G10** Policy and enforcement

## Capability matrix

| Tool | G1 | G2 | G3 | G4 | G5 | G6 | G7 | G8 | G9 | G10 |
|---|---|---|---|---|---|---|---|---|---|---|
| cdxgen | P | P | P | P | P | P | P | P | P | P |
| OWASP AIBOM Generator | N | N | N | N | N | N | P | P | N | P |
| k8s-aibom | N | N | P | N | N | P | P | P | P | N |
| agent-harness-aibom | P | P | P | P | N | P | P | ? | P | P |
| smithmark | P | P | N | P | P | N | P | N | P | P |
| Snyk CLI: snyk aibom and snyk aibom test | P | ? | P | ? | N | N | N | P | N | P |
| Snyk Agent Scan | P | P | N | P | N | P | N | N | N | P |
| Cisco AI BOM | P | P | P | P | ? | P | P | P | N | P |
| Cisco Model Provenance Kit | N | N | N | N | N | N | P | N | N | N |
| OWASP Dependency-Track | N | N | N | N | N | N | P | N | ? | P |
| GUAC | N | N | N | N | P | N | P | N | P | P |
| OWASP Agent Observability Standard | P | N | P | N | N | P | N | P | N | P |
| Protect AI ModelScan | N | N | N | N | N | N | P | N | N | P |
| Protect AI Guardian | ? | ? | ? | ? | ? | ? | P | ? | ? | ? |
| HiddenLayer Model Scanner | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| OpenSSF Model Signing | N | N | N | N | N | N | P | N | P | N |
| Sigstore cosign | N | N | N | N | P | N | P | N | F | P |
| in-toto | N | N | N | N | P | P | P | N | F | P |
| SLSA | N | N | N | N | P | N | P | N | P | P |
| TAIBOM | N | ? | N | N | N | N | P | ? | P | P |
| Syft | N | N | N | N | N | N | P | N | P | N |
| Microsoft sbom-tool | N | N | N | N | N | N | P | N | ? | N |
| brox | P | P | P | P | N | N | N | N | N | P |
| Official MCP Registry | N | N | N | N | N | N | P | N | N | N |
| agent-bom | P | P | ? | ? | ? | P | ? | ? | ? | P |
| Trusera ai-bom | P | ? | P | ? | N | P | N | ? | N | P |
| mcplock | P | N | N | N | N | P | N | N | N | P |
| mcp-pin | P | P | N | N | N | P | N | N | P | P |
| aibom-scanner | P | ? | P | ? | N | N | N | ? | N | P |
| picklescan | N | N | N | N | N | N | P | N | N | P |
| fickling | N | N | N | N | N | N | P | N | N | P |
| SymBiote (author's project, self-assessed) | P | P | P | P | P | P | P | P | P | P |

F full, P partial, N none, ? unknown. Each tool's section below gives the sources behind its row; the one-line reason for every cell is in landscape.json, which accompanies this document. The SymBiote row is the author's own assessment of an alpha implementation in a private repository, so readers cannot check it; G1 and G9 are P because approvals are not yet keyed by authorization context and the trust-status signing CLI is still in progress.

## What the matrix shows

- **No tool, including the author's alpha SymBiote, fully covers any agent-specific gap (G1 to G6, G8).** The only F cells are general-purpose signing (cosign, in-toto) under G9.
- **Tool-definition digests (G1) exist only in small, independent tools.** agent-harness-aibom and mcplock hash different parts of each tool definition (agent-harness-aibom digests name, description and inputSchema together; mcplock's content hash covers description and inputSchema, with separate description, schema and annotations hashes), so their digests do not compare (B6-09). mcp-pin also pins tool definitions and publishes its digest format, but we did not review what that digest covers. The large generators (cdxgen, Snyk, Cisco) list MCP servers and tools without digesting what the model reads.
- **Identity and credentials, CI agents, and data and memory provenance (G4, G5, G8) are the weakest areas:** in each, 25 of 31 tools have N or ?. For CI, cdxgen's GitHub Actions properties, SLSA provenance, in-toto layouts and smithmark's provenance for skills and MCP packages come closest, and none records which AI agents run in CI or what they may publish.
- **Runtime observation (G6) is mostly separate from inventory.** k8s-aibom observes workloads but not tools; Snyk Agent Scan rescans endpoints; Trusera's SDK intercepts calls; mcp-pin's guard refuses tool calls whose digest drifted from an approved, but unsigned, lockfile. None ties an observation back to a signed, approved snapshot.
- **Signing mechanisms are mature; signed agent BOMs are not.** cosign and in-toto are mature. OMS is usable for model weights, but its latest release (1.1.1, October 2025) predates unreleased verification fixes, including certificate EKU checks, and model-card signing is still planned. Among inventory tools, cdxgen (JSF through cdx-sign, which few verifiers implement), agent-harness-aibom (cosign keys), smithmark (Sigstore, in-toto) and Syft (`syft attest`, which needs cosign installed) can sign what they produce; mcp-pin can seal its runtime guard log with an external signing command, but its lockfile is unsigned. TAIBOM, a trust layer rather than an inventory tool, expresses its claims as W3C verifiable credentials. k8s-aibom verifies model signatures but leaves its own BOMs unsigned.
- **The official MCP Registry gives a namespace, not evidence (G7, G9).** server.json has no attestation, signature or provenance field, and the only mandatory hash, fileSha256 for MCPB bundles, is checked by MCP clients at install time, not by the registry.
- **Every producer uses its own dialect.** cdxgen (`cdx:mcp:*`, `cdx:agent:*`), k8s-aibom (`aibom.*`), agent-harness-aibom (`harness-aibom:*`), Cisco (`cisco-aibom:type`) and brox (`brox.*`) each encode agent facts differently, and even model metadata diverges (the OWASP AIBOM Generator uses `genai:aibom:modelcard:*`, `owasp:aibom:distribution:*` and bare property names); brox and OWASP AOS examples fail CycloneDX schema validation. A consumer such as Dependency-Track cannot write one query across them.

## Tools

### cdxgen (incl. aibom, tracebom, cdx-sign)

*cdxgen project (formerly published under the @cyclonedx npm scope). Open source: yes. Status: 13.6.0 as @cdxgen/cdxgen (npm, 2026-10-31); 12.9.0 as @cyclonedx/cdxgen (npm, 2026-10-22). Verification: verified.*

Of the open-source generators reviewed here, cdxgen covers the most layers. Its `aibom` command and `-t ai` project type catalog models (GGUF, safetensors, ONNX, pickle checkpoints), Hugging Face purls with revisions, inference providers, agent frameworks, instruction and skill files, and MCP configurations, MCP Registry manifests and MCPB bundles [1][2]. It deliberately emits derived signals (counts, flags, tool names, scopes) rather than raw instruction text, so secrets in rules files do not leak into the BOM (B2-07). Two cautions. Its `cdx:mcp:*`, `cdx:agent:*`, `cdx:tool:*` and `cdx:skill:*` properties sit under the `cdx` namespace, which the CycloneDX taxonomy reserves for registered sub-namespaces [3]. Its MCP pinning flag, experimental and off by default, records whether a server package carries a hash; it does not digest tool definitions [2]. Releases currently ship under two npm names: @cdxgen/cdxgen 13.6.0 (31 Oct 2026) and @cyclonedx/cdxgen 12.9.0 (22 Oct 2026) [4][5]. CycloneDX 2.0 agent-behavior output is planned in issue #4593, not shipped (B2-06) [6]. cdxgen also records GitHub Actions properties such as SHA pinning and id-token permissions [7], signs BOMs with JSF through `cdx-sign` [8], and traces a running process with `tracebom` [9].

### OWASP AIBOM Generator

*OWASP GenAI Security Project (AIBOM Initiative). Open source: yes (Apache-2.0). Status: owasp-aibom-generator 1.0.2 (pyproject); moved under the GenAI Security Project, blog dated 2025-12-18. Verification: verified.* [13]

The OWASP AIBOM Generator builds CycloneDX 1.6 AIBOMs for open models on Hugging Face and scores how complete each one is [10]. It lives under the OWASP GenAI Security Project, not the separate OWASP AIBOM Project at owaspaibom.org (A7-03) [11]. Native CycloneDX fields carry what they can (model card parameters, considerations, licenses, supplier); SPDX-AI-style fields such as autonomyType and safetyRiskAssessment go into bare metadata properties, and GGUF and tokenizer details into `genai:aibom:modelcard:*` (B6-05) [12]. It is a build-time complement to runtime inventory and says nothing about agents, tools or instructions.

### k8s-aibom

*Google Cloud (GoogleCloudPlatform; README: not an officially supported Google product). Open source: yes (Apache-2.0). Status: v1.6.2 (2026-10-22); announced 2026-07-13; v1.0.0 2026-08-17; v1.5.0 added signature verification 2026-09-22. Verification: verified.*

k8s-aibom is an unprivileged Kubernetes controller that writes a CycloneDX 1.6 ML-BOM for each AI workload it detects: serving runtimes, agent frameworks, vector databases, training jobs and evaluation harnesses [14]. Google open-sourced it on 13 July 2026; the latest release is v1.6.2 (22 Oct 2026) [15][16]. Its best idea is the confidence model: every attribute is declared, inferred, verified or unresolved, with an evidence locator, and 'verified' requires an OMS/Sigstore signature that matches an operator-configured signer (A7-01). Its limits matter for agents. It does not see MCP servers, tool schemas, skills or prompts, and it does not sign its own BOMs (A7-01); models downloaded at runtime are invisible [17]; and its README warns that zero matches is never proof of absence (A7-08) [14]. NVIDIA's AI Cluster Runtime adopted it under ADR-019 and notes that signing runtime observations still needs a separate design [18].

### agent-harness-aibom

*Ajay Kumar Yegireddi (individual maintainer). Open source: yes (MIT). Status: 1.0.0 (PyPI, 2026-09-10); first release 0.1.0 on 2026-09-08. Verification: verified.*

agent-harness-aibom inventories a running Hermes or OpenClaw installation: the harness binary, models behind its endpoint, MCP servers, tools, skills, hooks, prompt surfaces and credential files (locations and permissions only) [19]. It stays inside the CycloneDX 1.6 schema where a native field exists and puts the rest under a `harness-aibom:` namespace, validated in its tests (B6-04) [20]. It is the clearest published example of tool-definition digests in a BOM: once a server is probed, `definitionSha256` covers name, description and inputSchema, and unprobed tools are flagged `mcp_tool_not_pinned` (B6-09) [21]. Probing is opt-in and HTTP-only, and the hash uses sorted-key JSON rather than RFC 8785, so digests are not comparable with other tools. It signs BOMs with cosign keys and gates CI with its policy command.

### smithmark

*sns45 (individual maintainer; 'trust as code' tool family). Open source: yes (Apache-2.0). Status: v0.2.1 (Go module proxy, 2026-07-26); README states v0.2.0 released. Verification: verified.*

The claim register could not find smithmark (B6-03, unverifiable). A follow-up search located it as a Go module, github.com/sns45/smithmark, at v0.2.1 (26 Jul 2026), Apache-2.0 [22]. Its README describes signed capability attestations for MCP servers and SKILL.md bundles: a manifest of tools, egress, filesystem, exec, env and secrets, wrapped in in-toto DSSE and signed keyless through Sigstore or with a key, plus a static lint for undeclared capabilities [23]. Its `registry check` command reports whether an MCP Registry entry carries the attestation reference field proposed in the project's own registry-provenance RFC; the README says no real entry does today, which matches the registry schema (B6-03) [24]. Adoption figures (two servers) are self-reported.

### Snyk CLI: snyk aibom and snyk aibom test

*Snyk. Open source: CLI source is public; analysis requires a Snyk account (commercial). Status: snyk CLI 1.1308.3 (npm, 2026-10-23); aibom needs 1.1298.3+ (2025-08-14); aibom test needs 1.1304.0+ (2026-04-09). Verification: verified.*

`snyk aibom` analyzes Python, Java, JavaScript or Go source and emits a CycloneDX 1.6 AI-BOM covering models, datasets, agents, tools and MCP, where MCP servers are identified through the official SDK and drawn as a client -> server -> tool chain [25]. `snyk aibom test` (CLI 1.1304.0+, 9 Apr 2026) checks the result against the tenant's Evo policies (B6-07) [26][27]. It is static and source-based: it will not see a server's served tool definitions or their drift.

### Snyk Agent Scan (formerly Invariant Labs mcp-scan)

*Snyk (originally Invariant Labs). Open source: yes (Apache-2.0); analysis calls a Snyk API and needs SNYK_TOKEN. Status: snyk-agent-scan 0.6.10 (PyPI, 2026-10-30); mcp-scan 0.4.3 (2026-03-02) is a redirect package; first mcp-scan release 2025-04-07. Verification: verified.*

Invariant Labs released mcp-scan in April 2025 after its tool-poisoning disclosure; version 0.3.0 'detects changes to MCP tools via hashing' to catch rug pulls [28][29]. Snyk renamed it Snyk Agent Scan, and the PyPI mcp-scan package is now a redirect (A3-04, B6-07) [30]. Version 0.6.10 (30 Oct 2026) discovers MCP servers and skills across agent clients including Claude Code, Cursor, GitHub Copilot, Windsurf and Gemini CLI, retrieves tool descriptions and reports scored risks such as prompt injection, destructive capabilities and malicious skills [31]. Three cautions for production use: it starts stdio MCP servers to read their tools, so its README says to scan untrusted configs in a sandbox; analysis sends MCP server configurations, tool names and descriptions, and skill content (secrets redacted) to Snyk's Agent Scan API under a SNYK_TOKEN, which matters if agent configuration may not leave the network; and its JSON output is marked experimental [32]. The current README no longer describes hash-based pinning, so confirm before relying on it for rug-pull detection.

### Cisco AI BOM

*Cisco AI Defense. Open source: yes (Apache-2.0). Status: cisco-aibom 1.10.0 (PyPI, 2026-08-17); on PyPI since 2026-02-11. Verification: verified.* [35]

Cisco AI BOM scans source, container images and cloud environments with 23 scanners and classifies findings into 30 AI component types, including agent, tool, mcp_server, mcp_client, mcp_gateway, prompt, memory, guardrail and skill [33]. Its type vocabulary is among the largest here, but CycloneDX has no native component types for most of it: the reporter maps agents and MCP servers to `application`, tools to `library` and skills to `file`, and keeps the real type in a `cisco-aibom:type` property (B6-11) [34]. It also writes SPDX 3.0 with the AI and Dataset profiles and SARIF. The `analyze` command requires an LLM provider for agentic classification, which matters if code may not leave the network.

### Cisco Model Provenance Kit

*Cisco AI Defense. Open source: yes (Apache-2.0). Status: cisco-ai-provenance-kit 1.0.0 (PyPI, 2026-05-04); main branch at 1.1.0. Verification: verified.*

The Model Provenance Kit answers one question: does this model derive from a known base family? It compares eight fingerprints, from architecture metadata and tokenizer to weight statistics, against about 150 base models from 45+ families [36][37]. It produces similarity statistics for lineage, not per-tensor content digests, and is not built to detect a trojaned layer (B5-05). Use it to check a supplier's lineage claim, and use OMS digests for integrity.

### OWASP Dependency-Track

*OWASP. Open source: yes. Status: v5.2.1 and v4.14.6 (release notes 2026-10-25); v5.1.0 added CycloneDX 1.7 ingestion (2026-08-27); v4 reaches end-of-life December 2026. Verification: verified.* [44]

Dependency-Track is where many teams will load AI-BOMs. Since v5.1.0 (GitHub release 27 Aug 2026, announced 31 Aug) and its v4.14.4 backport (release notes 14 Sep 2026) it ingests CycloneDX 1.7; the validator accepts 1.2 to 1.7, although the v5 docs say all versions (B2-08) [38][39][40][41][42]. The v4 line reaches end-of-life in December 2026 [43]. It has no agent semantics of its own. Its policy engine can only query agent facts consistently if producers use the same property names, which today they do not (cdxgen uses unregistered `cdx:` sub-namespaces, while k8s-aibom, Cisco and agent-harness-aibom each use their own namespace).

### GUAC (Graph for Understanding Artifact Composition)

*OpenSSF (incubating project, Supply Chain Integrity WG). Open source: yes. Status: v1.1.0 (Go module proxy, 2026-03-13). Verification: verified.*

GUAC is not an AI tool. It aggregates SBOMs, SLSA and in-toto attestations, Scorecard and vulnerability data into a graph you can query [45][46]. It belongs in the landscape as the place where agent BOMs and their attestations could be joined with conventional supply-chain evidence. Its README documents no AI-BOM or agent-specific handling.

### OWASP Agent Observability Standard (AOS) and AgBOM

*OWASP (originated with Zenity). Open source: yes (Apache-2.0; specification). Status: Specification; CycloneDX mapping 'Working draft' (example dated 2025-05-19); SPDX and SWID mappings 'Help wanted'. Verification: verified.*

OWASP AOS defines AgBOM as 'a structured, dynamic inventory' of an agent's tools, models, capabilities and dependencies, updated whenever a component is discovered, removed or changed (B6-06) [47]. It also has Instrument (hooks) and Trace (OpenTelemetry and OCSF) sections [48]. It is a specification, not a tool. Its CycloneDX example is a working draft and uses component types `service` and `tool`, neither valid in CycloneDX 1.6 or 1.7, so it fails schema validation (B6-06) [49][50][51].

### Protect AI ModelScan

*Protect AI (reported acquired by Palo Alto Networks). Open source: yes (Apache-2.0). Status: modelscan 0.8.8 (PyPI, 2026-02-18). Verification: verified.*

ModelScan is Protect AI's open-source scanner for unsafe operations in serialized models: pickle-family formats, H5, Keras v3 and SavedModel [52][53]. Treat it as triage at model intake, not proof of safety. Signature-style scanners keep getting bypassed (see picklescan below), and no scanner reveals a backdoor trained into the weights (A5-05).

### Protect AI Guardian (now part of Palo Alto Networks Prisma AIRS)

*Palo Alto Networks (via Protect AI acquisition). Open source: no (commercial). Status: Commercial service; acquisition completion reported by press release reprints (date not confirmed from a primary source). Verification: partially verified.*

Guardian is Protect AI's commercial model scanner and a Hugging Face scanning partner. By 1 April 2025 it had scanned 4.47 million model versions and flagged 352,000 unsafe or suspicious issues across 51,700 models; these are risky constructs, not confirmed malware (A5-01) [54]. Palo Alto Networks is reported to have completed its acquisition of Protect AI and folded the technology into Prisma AIRS [55]. We reviewed no primary product documentation, so agent-related capabilities are marked unknown.

### HiddenLayer Model Scanner (AISec Platform)

*HiddenLayer. Open source: no (commercial). Status: Commercial; current version not verified (vendor site not reachable from this environment). Verification: partially verified.*

HiddenLayer sells a commercial AI security platform that, according to a third-party review, includes a pre-production Model Scanner and generates an AIBOM for each scanned model [56]. We could not reach HiddenLayer's own documentation, so every cell is unknown and the entry is partially verified. HiddenLayer's 2024 research showed that Hugging Face's pickle-to-safetensors conversion service could be hijacked, because conversion itself loads the pickle (A5-05) [57].

### OpenSSF Model Signing (sigstore/model-transparency, model_signing)

*OpenSSF AI/ML Working Group (Model Signing project), hosted in sigstore/model-transparency. Open source: yes. Status: model-signing 1.1.1 (PyPI, 2025-10-10); 1.0.0 first stable 2025-04-04; main branch lists unreleased verification fixes. Verification: verified.* [62]

OMS signs a manifest of per-file or per-shard digests for a model directory, as an in-toto Statement v1 in a DSSE envelope inside a Sigstore bundle [58][59][60]. Keyless Sigstore is the default, but the spec is PKI-agnostic, and only Sigstore-signed bundles land in a transparency log (A5-08, A5-10). The latest release is 1.1.1 (10 Oct 2025); the main-branch changelog lists unreleased verification fixes for symlinks, empty files and certificate EKU checks [61]. Model-card signing is a stated plan, not a feature (B5-04). OMS gives you content identity for weights you hold; it cannot identify a model behind a provider API.

### Sigstore cosign

*Sigstore project. Open source: yes. Status: v3.1.4 (Go module proxy, 2026-10-20); v2 line at v2.6.5 (2026-08-05). Verification: verified.* [67]

cosign is a common way to sign BOMs outside the BOM format itself. `cosign attest --type cyclonedx` attaches a CycloneDX BOM as an in-toto predicate in a DSSE envelope whose subject is a container image digest, avoiding CycloneDX's rarely implemented JSF signatures; for a BOM that describes no image, such as an agent snapshot, `cosign attest-blob` attests to a file you name instead [63]. For SPDX 3.0.1, which has no in-document signing, pass the custom predicate type `--type https://spdx.dev/Document/v3` [64], because cosign's built-in `spdx` type labels the predicate as SPDX 2 (A7-09, B1-04) [65][66]. Every statement `cosign attest` builds is labelled in-toto Statement v0.1, not v1 [65]. It is the mechanism, not the inventory: it proves who signed which bytes, not that the BOM is complete or true.

### in-toto (framework and attestation specification)

*in-toto project. Open source: yes. Status: in-toto Python 3.1.0 (PyPI, 2026-04-25); attestation spec with vetted predicates. Verification: verified.* [71]

in-toto supplies the statement format almost everyone else uses [68]. OMS and SymBiote emit in-toto Statement v1 in DSSE envelopes (B5-04) [60], and SLSA Provenance is defined as an in-toto predicate type [69]; `cosign attest` also wraps its predicates in DSSE but still labels the statement `https://in-toto.io/Statement/v0.1` [65]. Verifiers therefore have to accept both statement versions. None of the vetted predicates is ML- or agent-specific (B5-14) [70]. A tool-definition-set or agent-snapshot predicate would have to be defined by a profile and, ideally, proposed upstream.

### SLSA (Supply-chain Levels for Software Artifacts)

*SLSA project (slsa-framework). Open source: yes (specification). Status: Released versions on release branches (v1.0, v1.2 named in the README); active workstreams: Build L4, Attested Build Environments, Dependency Ingestion, Tooling Modernization. Verification: verified.*

SLSA is the build-provenance baseline. The Cline incident shows its value: `cline@2.3.0` had no provenance while its neighbors were published through trusted publishing with SLSA provenance, an anomaly a consumer could have caught (A1-01) [72]. The project's active workstreams are Build L4, attested build environments, dependency ingestion and tooling modernization [73]. SLSA has no ML or training track as of November 2026; the OpenSSF AI/ML working group's model-lifecycle provenance work is still in development (B5-14) [74][75].

### TAIBOM (Trustable AI Bill of Materials)

*Techworks working group (led by NquiringMinds; founder members include Copper Horse, BSI and BAE). Open source: unknown (the public repository nqminds/Trusted-AI-BOM holds the project website and states no license). Status: No release version identified; seed-funded by the UKRI Technology Missions Fund, now a standalone Techworks working group. Verification: partially verified.* [79]

TAIBOM adds a trust layer on top of AI BOMs: identity, dependencies, annotations and inferencing, expressed as W3C verifiable credentials, with transitive risk propagation [76]. It stresses that the T means 'trustable (not trustworthy)' (B6-08) [77]. It has no agent-specific component types. All evidence comes from the project homepage source; the working-docs pages were not reachable and no implementation or license was identified, so the entry is partially verified (B6-08) [78].

### Syft

*Anchore. Open source: yes. Status: v1.55.0 (Go module proxy, 2026-10-19). Verification: verified.* [84]

Syft is a mainstream software SBOM generator; when asked for SPDX it writes 2.3 by default, with 3.0 available only in JSON (B4-09) [80]. With cosign installed, `syft attest` signs its SBOM as an in-toto attestation [81][82]. Its README lists no AI ecosystem, which the register took as weak evidence of no model support (B7-05). The v1.55.0 source shows otherwise: it ships GGUF and SafeTensors catalogers that read model headers, including Docker Model Runner OCI layers [83]. It still knows nothing about agents, tools or instructions.

### Microsoft sbom-tool

*Microsoft. Open source: yes (MIT); does not accept outside contributions. Status: Tag v4.1.13 (tracked by Homebrew because the last GitHub release no longer builds). Verification: verified.*

sbom-tool generates SPDX 2.2 by default; SPDX 3.0 is opt-in and hard-codes specVersion '3.0', which does not match the 3.0.1 SemVer pattern (B4-07) [85][86]. Homebrew tracks tag v4.1.13 because the last GitHub release no longer builds [87]. It has no AI or agent coverage.

### brox

*'brox Contributors' (repository links are an unfilled placeholder). Open source: yes (Apache-2.0, per PyPI metadata). Status: 0.1.0, the only release (PyPI, 2026-02-13). Verification: verified.*

brox is real, though thin: one PyPI release, 0.1.0 (13 Feb 2026), that turns agent, tool and model changes into a pull-request capability diff (B6-01) [88]. Its repository links point to a template placeholder, and its README sample declares CycloneDX 1.5 but gives an MCP server the component type 'service', which no CycloneDX schema from 1.5 to 1.7 allows (B6-01) [89]. With a single release, placeholder links and a schema-invalid sample, brox reads as an early prototype of a pull-request capability diff rather than a production tool.

### Official MCP Registry

*Model Context Protocol project. Open source: yes. Status: Preview since 2025-09-08; v0.1 API freeze since 2025-10-24; latest dated server.json schema 2025-12-11; repository tag v1.8.7 (2026-10-30). Verification: verified.* [96]

The official MCP Registry launched in preview on 8 Sep 2025 and froze its v0.1 API on 24 Oct 2025 [90][91]. It verifies namespace ownership [91], and published version metadata cannot be changed [92]. It does not verify that a publisher controls a remote server's URL, does not itself validate the hash it requires for MCPB bundles (MCP clients check it at install time), and tells consumers to 'assume minimal-to-no moderation' [93][94][95]. server.json has no attestation, signature or provenance field and no tool definitions (B6-03) [24]. Treat a registry entry as a pointer, not as evidence.

### agent-bom

*koda-ai-studio (PyPI author: Wagdy Saad). Open source: yes (Apache-2.0, per PyPI license_expression; repository github.com/koda-ai-studio/agent-bom). Status: 0.112.1 (PyPI, 2026-11-01); 177 releases since 2026-02-19. Verification: partially verified.*

agent-bom (koda-ai-studio) scans MCP clients, servers and tools plus rules and skill files (B6-11). It outputs CycloneDX, SPDX, SARIF and OCSF, and its description claims an MCP proxy/gateway with inline firewall enforcement [97]. It reports coverage, warning that 'incomplete evidence is not clean'. It releases very often (177 releases since February 2026). Only its PyPI description was reviewed, so it is partially verified and its runtime and enforcement claims are untested.

### Trusera ai-bom

*Trusera. Open source: yes (Apache-2.0). Status: ai-bom 3.6.0 (PyPI, 2026-03-15). Verification: partially verified.*

Trusera's ai-bom inventories LLM integrations, agent frameworks and MCP server configurations and writes CycloneDX 1.6, SPDX 3.0 and SARIF (A7-05) [98]. A companion SDK intercepts HTTP calls at runtime and evaluates Cedar policies. Only the PyPI description was reviewed.

### mcplock

*Yashrajsinh Rathod (individual maintainer). Open source: yes (MIT). Status: 1.0.3 (PyPI, 2026-07-29). Verification: verified.*

mcplock is 'npm audit / SRI for MCP tools': it pins each tool with separate content, description, schema and annotations hashes, so a flipped destructiveHint shows up as its own finding, and it treats a missing baseline as a failure (B6-09) [99]. It is a CI lockfile tool, not a BOM.

### mcp-pin

*Rufat Mahmudov (individual maintainer). Open source: yes (Apache-2.0). Status: 0.1.8 (PyPI, 2026-09-23). Verification: verified.*

mcp-pin is a zero-dependency 'approve once, refuse what changed' pin for MCP servers and skills [100]. Its own README states the limit every pinning tool shares: pinning detects change, not initial honesty, so a tool poisoned from its first approved version passes (B6-02). Its guard log can be sealed with an external signing command, but the lockfile itself is unsigned: the README notes that guard 'cannot tell your lock from someone else's'.

### aibom-scanner

*SaaSVista (Mike Carroll). Open source: yes (Apache-2.0). Status: 1.3.5 (PyPI, 2026-10-24); coverage accounting since 1.1.0 (2026-07-21). Verification: verified.*

aibom-scanner matters for one idea: every scan reports what it actually read (coverage_pct, incomplete_inputs), and `--fail-on-incomplete-coverage` fails the build when it could not parse something. 'An AI Bill of Materials that silently omits what it could not parse is not incomplete, it is wrong' (B6-09) [101]. Its output is not a CycloneDX BOM.

### picklescan

*Matthieu Maitre. Open source: yes. Status: 1.0.5 (PyPI, 2026-07-01). Verification: verified.*

picklescan is an open-source blocklist scanner for pickle files; the Hugging Face Hub runs a similar import scan on every uploaded pickle and highlights suspicious imports [102]. picklescan has had 59 security advisories (58 CVEs) against v0.0.20, almost all detection bypasses, fixed between v0.0.21 (Feb 2025) and v1.0.4 (Mar 2026) [103][104]. Use it for triage; the robust control is not to load untrusted pickles at all (see fickling below).

### fickling

*Trail of Bits. Open source: yes (LGPL). Status: 0.1.12 (PyPI, 2026-06-26). Verification: verified.*

fickling's `activate_safe_ml_environment()` checks pickle imports against an allowlist of ML-library imports and blocks everything else, which is sturdier than a blocklist scan but is not a sandbox (lens controls-06) [105]. fickling itself has fixed 16 security advisories between 0.1.6 and 0.1.12 [106]. The robust control is not to load pickles from untrusted sources at all: prefer safetensors, which does not execute code on load [107], or `torch.load(weights_only=True)` [108], and keep scanners for triage.

### SymBiote (AgentBOM toolkit; author's project)

*Emmanuel Dahunsi (author's project). Open source: not yet (private repository; the README declares an MIT license for release). Status: Alpha; specification v0.1; status as of 2026-11-01 per Part II.13 of the SymBiote document. Verification: partially verified.*

SymBiote is the author's AgentBOM toolkit and is listed for comparison, with its status taken from the specification and the SymBiote document's implementation table, not from an independent test; its row is a self-assessment. AgentBOM is the name of SymBiote's profile; it is unrelated to the agent-bom tool from koda-ai-studio reviewed above. It computes a typed SHA-256 digest (tooldef/v1) over the RFC 8785 canonical JSON of each tool's model-visible fields, taken from the raw `tools/list` JSON-RPC result, exports CycloneDX 1.7 and SPDX 3.0.1 that validate against the official schemas, signs snapshots as in-toto statements with Sigstore or keys, and exports a Gateway Allowlist Bundle that a reference check enforces (SymBiote spec: digests.md, attestation.md, collectors.md). The specification defines 14 collectors. MCP configuration and ShadowScan import run from the CLI; live `tools/list`, OpenTelemetry traces, MCP registry resolution and k8s-aibom import exist as Python APIs not yet wired into the CLI; a hosted-models module exists, but the README still lists hosted models as in progress; instructions, skills, frameworks, local models, Agent Cards, identity configuration and SBOM merge are in progress. Approvals are not yet keyed by authorization context, and the trust-status signing CLI is in progress, which is why G1 and G9 are rated P. It is alpha software in a private repository.

## References

1. cdxgen AI-BOM Guide, fetched 2026-11-01. https://raw.githubusercontent.com/cdxgen/cdxgen/master/docs/AI_BOM.md
2. cdxgen: MCP inventory for JavaScript and dedicated MCP project scans, fetched 2026-11-01. https://raw.githubusercontent.com/cdxgen/cdxgen/master/docs/MCP.md
3. CycloneDX property taxonomy: cdx namespace. https://raw.githubusercontent.com/CycloneDX/cyclonedx-property-taxonomy/main/cdx.md
4. npm registry: @cdxgen/cdxgen (13.6.0), 2026-10-31. https://registry.npmjs.org/@cdxgen/cdxgen
5. npm registry: @cyclonedx/cdxgen (12.9.0), 2026-10-22. https://registry.npmjs.org/@cyclonedx/cdxgen
6. cdxgen issue #4593: Describe declared coding-agent behaviour in AI-BOMs at CycloneDX 2.0. https://github.com/cdxgen/cdxgen/issues/4593
7. cdxgen custom properties reference, fetched 2026-11-01. https://raw.githubusercontent.com/cdxgen/cdxgen/master/docs/CUSTOM_PROPERTIES.md
8. cdxgen README, fetched 2026-11-01. https://raw.githubusercontent.com/cdxgen/cdxgen/master/README.md
9. cdxgen: tracebom, dynamic SBOM CLI, fetched 2026-11-01. https://raw.githubusercontent.com/cdxgen/cdxgen/master/docs/TRACEBOM.md
10. OWASP GenAI Security Project: AIBOM Generator README, fetched 2026-11-01. https://raw.githubusercontent.com/GenAI-Security-Project/aibom-generator/main/README.md
11. OWASP GenAI: The journey of the AIBOM Generator and its new home at OWASP, 2025-12-18. https://genai.owasp.org/2025/12/18/evolving-ai-transparency-the-journey-of-the-aibom-generator-and-its-new-home-at-owasp/
12. owasp-aibom-generator field registry (source), fetched 2026-11-02. https://raw.githubusercontent.com/GenAI-Security-Project/aibom-generator/main/src/models/field_registry.json
13. owasp-aibom-generator pyproject.toml (v1.0.2). https://raw.githubusercontent.com/GenAI-Security-Project/aibom-generator/main/pyproject.toml
14. k8s-aibom README, fetched 2026-11-01. https://raw.githubusercontent.com/GoogleCloudPlatform/k8s-aibom/main/README.md
15. Google Cloud: Introducing k8s-aibom on GKE for automated AI bills of materials, 2026-07-13. https://cloud.google.com/blog/products/identity-security/introducing-k8s-aibom-on-gke-for-automated-ai-bills-of-materials
16. k8s-aibom CHANGELOG (v1.6.2), 2026-10-22. https://raw.githubusercontent.com/GoogleCloudPlatform/k8s-aibom/main/CHANGELOG.md
17. k8s-aibom security model. https://raw.githubusercontent.com/GoogleCloudPlatform/k8s-aibom/main/docs/security-model.md
18. NVIDIA AICR ADR-019: k8s-aibom runtime inventory. https://raw.githubusercontent.com/NVIDIA/aicr/main/docs/design/019-k8s-aibom-runtime-inventory.md
19. agent-harness-aibom README, fetched 2026-11-01. https://raw.githubusercontent.com/Aj7Ay/agent-harness-aibom/main/README.md
20. PyPI: agent-harness-aibom 1.0.0, 2026-09-10. https://pypi.org/pypi/agent-harness-aibom/json
21. agent-harness-aibom SPEC. https://raw.githubusercontent.com/Aj7Ay/agent-harness-aibom/main/SPEC.md
22. Go module proxy: github.com/sns45/smithmark v0.2.1, 2026-07-26. https://proxy.golang.org/github.com/sns45/smithmark/@latest
23. smithmark README, fetched 2026-11-02. https://raw.githubusercontent.com/sns45/smithmark/main/README.md
24. MCP Registry server.json schema (draft). https://raw.githubusercontent.com/modelcontextprotocol/registry/main/docs/reference/server-json/draft/server.schema.json
25. Snyk CLI help: snyk aibom. https://raw.githubusercontent.com/snyk/cli/main/help/cli-commands/aibom.md
26. Snyk CLI help: snyk aibom test. https://raw.githubusercontent.com/snyk/cli/main/help/cli-commands/aibom-test.md
27. npm registry: snyk (1.1308.3), 2026-10-23. https://registry.npmjs.org/snyk
28. PyPI: mcp-scan 0.3.0, 2025-07-18. https://pypi.org/pypi/mcp-scan/0.3.0/json
29. Invariant Labs: MCP injection experiments. https://raw.githubusercontent.com/invariantlabs-ai/mcp-injection-experiments/main/README.md
30. PyPI: mcp-scan 0.4.3 (redirect to snyk-agent-scan), 2026-03-02. https://pypi.org/pypi/mcp-scan/json
31. PyPI: snyk-agent-scan 0.6.10, 2026-10-30. https://pypi.org/pypi/snyk-agent-scan/json
32. Snyk Agent Scan README, fetched 2026-11-02. https://raw.githubusercontent.com/snyk/agent-scan/main/README.md
33. Cisco AI BOM README, fetched 2026-11-02. https://raw.githubusercontent.com/cisco-ai-defense/aibom/main/README.md
34. Cisco AI BOM CycloneDX reporter source. https://raw.githubusercontent.com/cisco-ai-defense/aibom/main/aibom/src/aibom/reporters/cyclonedx_reporter.py
35. PyPI: cisco-aibom 1.10.0, 2026-08-17. https://pypi.org/pypi/cisco-aibom/json
36. Cisco Model Provenance Kit README. https://raw.githubusercontent.com/cisco-ai-defense/model-provenance-kit/main/README.md
37. PyPI: cisco-ai-provenance-kit 1.0.0, 2026-05-04. https://pypi.org/pypi/cisco-ai-provenance-kit/json
38. Dependency-Track 5.1.0 GitHub release (adds CycloneDX 1.7 support), 2026-08-27. https://github.com/DependencyTrack/dependency-track/releases/tag/5.1.0
39. Dependency-Track 5.1 announcement, 2026-08-31. https://dependencytrack.org/news/dependency-track-5-1/
40. Dependency-Track v4.14.4 release notes, 2026-09-14. https://raw.githubusercontent.com/DependencyTrack/dependency-track/4.14.x/docs/_posts/2026-09-14-v4.14.4.md
41. Dependency-Track CycloneDxValidator (main). https://raw.githubusercontent.com/DependencyTrack/dependency-track/main/apiserver/src/main/java/org/dependencytrack/parser/cyclonedx/CycloneDxValidator.java
42. Dependency-Track v5 docs: file formats. https://raw.githubusercontent.com/DependencyTrack/docs/main/docs/reference/file-formats.md
43. Dependency-Track README (v4 end-of-life), fetched 2026-11-02. https://raw.githubusercontent.com/DependencyTrack/dependency-track/main/README.md
44. Dependency-Track v4.14.6 release notes, 2026-10-25. https://raw.githubusercontent.com/DependencyTrack/dependency-track/4.14.x/docs/_posts/2026-10-25-v4.14.6.md
45. GUAC README, fetched 2026-11-02. https://raw.githubusercontent.com/guacsec/guac/main/README.md
46. Go module proxy: github.com/guacsec/guac v1.1.0, 2026-03-13. https://proxy.golang.org/github.com/guacsec/guac/@latest
47. OWASP AOS: Inspect with AgBOM. https://raw.githubusercontent.com/OWASP/aos/main/docs/spec/inspect/README.md
48. OWASP AOS documentation configuration. https://raw.githubusercontent.com/OWASP/aos/main/mkdocs.yml
49. OWASP AOS: AgBOM with CycloneDX (working draft), 2025-05-19. https://raw.githubusercontent.com/OWASP/aos/main/docs/spec/inspect/extend_cyclonedx.md
50. CycloneDX 1.6 JSON schema. https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json
51. CycloneDX 1.7 JSON schema. https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.7.schema.json
52. Protect AI ModelScan README. https://raw.githubusercontent.com/protectai/modelscan/main/README.md
53. PyPI: modelscan 0.8.8, 2026-02-18. https://pypi.org/pypi/modelscan/json
54. Hugging Face: 4M models scanned, Protect AI six-month update, 2025-04-14. https://huggingface.co/blog/pai-6-month
55. Palo Alto Networks Completes Acquisition of Protect AI (press release reprint) (secondary source). https://www.securityinfowatch.com/ai/press-release/55305712/palo-alto-networks-palo-alto-networks-completes-acquisition-of-protect-ai
56. AppSec Santa: HiddenLayer review (secondary source). https://appsecsanta.com/hiddenlayer
57. HiddenLayer: Silent Sabotage (Hugging Face conversion service), 2024-02. https://hiddenlayer.com/research/silent-sabotage
58. sigstore/model-transparency README. https://raw.githubusercontent.com/sigstore/model-transparency/main/README.md
59. OpenSSF Model Signing specification README. https://raw.githubusercontent.com/ossf/model-signing-spec/main/README.md
60. model_signing source: in-toto Statement v1 type. https://raw.githubusercontent.com/sigstore/model-transparency/main/src/model_signing/_signing/signing.py
61. sigstore/model-transparency CHANGELOG. https://raw.githubusercontent.com/sigstore/model-transparency/main/CHANGELOG.md
62. PyPI: model-signing (1.0.0 2025-04-04; 1.1.1 2025-10-10), 2025-10-10. https://pypi.org/pypi/model-signing/json
63. cosign attest-blob command reference. https://raw.githubusercontent.com/sigstore/cosign/main/doc/cosign_attest-blob.md
64. in-toto attestation: SPDX 3 predicate type (https://spdx.dev/Document/v3). https://raw.githubusercontent.com/in-toto/attestation/main/spec/predicates/spdx3.md
65. cosign attestation predicate types (source). https://raw.githubusercontent.com/sigstore/cosign/main/pkg/cosign/attestation/attestation.go
66. Sigstore cosign README. https://raw.githubusercontent.com/sigstore/cosign/main/README.md
67. Go module proxy: github.com/sigstore/cosign/v3 v3.1.4, 2026-10-20. https://proxy.golang.org/github.com/sigstore/cosign/v3/@latest
68. in-toto attestation: Statement v1. https://raw.githubusercontent.com/in-toto/attestation/main/spec/v1/statement.md
69. in-toto attestation: SLSA Provenance predicate type. https://raw.githubusercontent.com/in-toto/attestation/main/spec/predicates/provenance.md
70. in-toto attestation: vetted predicates. https://raw.githubusercontent.com/in-toto/attestation/main/spec/predicates/README.md
71. PyPI: in-toto 3.1.0, 2026-04-25. https://pypi.org/pypi/in-toto/json
72. npm registry: cline (2.3.0 published without provenance), 2026-02-17. https://registry.npmjs.org/cline
73. SLSA repository README. https://raw.githubusercontent.com/slsa-framework/slsa/main/README.md
74. SLSA: future directions. https://raw.githubusercontent.com/slsa-framework/slsa/main/spec/future-directions.md
75. OpenSSF AI/ML Security Working Group README. https://raw.githubusercontent.com/ossf/ai-ml-security/main/README.md
76. TAIBOM site source: technical details. https://raw.githubusercontent.com/nqminds/trusted-ai-bom/main/packages/docusaurus/src/partials/home/technical-details.jsx
77. TAIBOM site source: why TAIBOM. https://raw.githubusercontent.com/nqminds/trusted-ai-bom/main/packages/docusaurus/src/partials/home/why.jsx
78. nqminds/Trusted-AI-BOM README (website build instructions; no LICENSE file at root), fetched 2026-11-02. https://raw.githubusercontent.com/nqminds/trusted-ai-bom/main/README.md
79. TAIBOM site source: contributors. https://raw.githubusercontent.com/nqminds/trusted-ai-bom/main/packages/docusaurus/src/partials/home/contributors.jsx
80. Syft SPDX version defaults (source). https://raw.githubusercontent.com/anchore/syft/main/syft/format/internal/spdxutil/versions.go
81. Syft README. https://raw.githubusercontent.com/anchore/syft/main/README.md
82. Syft attest command (source; requires cosign on PATH). https://raw.githubusercontent.com/anchore/syft/main/cmd/syft/internal/commands/attest.go
83. Syft v1.55.0: GGUF and SafeTensors catalogers (source). https://raw.githubusercontent.com/anchore/syft/v1.55.0/syft/pkg/cataloger/ai/cataloger.go
84. Go module proxy: github.com/anchore/syft v1.55.0, 2026-10-19. https://proxy.golang.org/github.com/anchore/syft/@latest
85. Microsoft sbom-tool README. https://raw.githubusercontent.com/microsoft/sbom-tool/main/README.md
86. sbom-tool SPDX 3.0 generator constants (source). https://raw.githubusercontent.com/microsoft/sbom-tool/main/src/Microsoft.Sbom.Parsers.Spdx30SbomParser/Constants.cs
87. Homebrew formula: sbom-tool (tracks tag v4.1.13). https://raw.githubusercontent.com/Homebrew/homebrew-core/main/Formula/s/sbom-tool.rb
88. PyPI: brox 0.1.0, 2026-02-13. https://pypi.org/pypi/brox/json
89. CycloneDX 1.5 JSON schema. https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json
90. MCP Registry roadmap. https://raw.githubusercontent.com/modelcontextprotocol/registry/main/docs/design/roadmap.md
91. MCP Registry README. https://raw.githubusercontent.com/modelcontextprotocol/registry/main/README.md
92. MCP Registry FAQ. https://raw.githubusercontent.com/modelcontextprotocol/registry/main/docs/modelcontextprotocol-io/faq.mdx
93. MCP Registry remote servers. https://raw.githubusercontent.com/modelcontextprotocol/registry/main/docs/modelcontextprotocol-io/remote-servers.mdx
94. MCP Registry package types. https://raw.githubusercontent.com/modelcontextprotocol/registry/main/docs/modelcontextprotocol-io/package-types.mdx
95. MCP Registry moderation policy. https://raw.githubusercontent.com/modelcontextprotocol/registry/main/docs/modelcontextprotocol-io/moderation-policy.mdx
96. Go module proxy: github.com/modelcontextprotocol/registry v1.8.7, 2026-10-30. https://proxy.golang.org/github.com/modelcontextprotocol/registry/@latest
97. PyPI: agent-bom 0.112.1, 2026-11-01. https://pypi.org/pypi/agent-bom/json
98. PyPI: ai-bom (Trusera) 3.6.0, 2026-03-15. https://pypi.org/pypi/ai-bom/json
99. PyPI: mcplock 1.0.3, 2026-07-29. https://pypi.org/pypi/mcplock/json
100. PyPI: mcp-pin 0.1.8, 2026-09-23. https://pypi.org/pypi/mcp-pin/json
101. PyPI: aibom-scanner 1.3.5, 2026-10-24. https://pypi.org/pypi/aibom-scanner/json
102. Hugging Face Hub docs: Pickle Scanning (source), fetched 2026-11-02. https://raw.githubusercontent.com/huggingface/hub-docs/main/docs/hub/security-pickle.md
103. PyPI: picklescan 0.0.20 (advisory baseline), 2025-02. https://pypi.org/pypi/picklescan/0.0.20/json
104. PyPI: picklescan 1.0.5, 2026-07-01. https://pypi.org/pypi/picklescan/json
105. PyPI: fickling 0.1.12 (Trail of Bits), 2026-06-26. https://pypi.org/project/fickling/
106. PyPI: fickling 0.1.4 (advisory baseline: 16 GHSA advisories fixed in 0.1.6 to 0.1.12), fetched 2026-11-02. https://pypi.org/pypi/fickling/0.1.4/json
107. safetensors README. https://raw.githubusercontent.com/huggingface/safetensors/main/README.md
108. PyTorch torch.load source (weights_only). https://raw.githubusercontent.com/pytorch/pytorch/main/torch/serialization.py
