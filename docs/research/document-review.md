# Review and Verification Report

**Documents reviewed:** "The Supply Chain of Agency: Why Your Production AI Agent Requires an AI-BOM" (Medium article) and "SymBiote (Agent Bill of Materials - AgentBOM)" (working document, v1)

**Prepared for:** Emmanuel Dahunsi

**Sources retrieved:** November 1, 2026

**Status:** Narrative for review. The claim-by-claim tables are in Appendix A. A second adversarial pass on high-impact claims was still running when this was written; where its results differ from the figures below, the final register wins.

## 1. Executive summary

- **The argument holds in both documents.** The article's thesis is that components you didn't write decide what a production agent does, so you need an inventory of them. Its anchor facts check out against primary records: the `cline@2.3.0` publish time and postinstall script (A1-01, A1-02) [1][2], and OWASP's agentic Top 10, which assigns agentic supply-chain risk to ASI04 (A6-01) [16][41]. The MCP Registry's September 8, 2025 preview launch and metadata-only design hold too, though the article's list of code sources is incomplete (A3-01) [42]. The document's schema analysis is the strongest material in either piece, and its central finding stands: neither CycloneDX nor SPDX has a native field for what an agent is allowed to do; today that lives only in tool-specific property namespaces such as cdxgen's experimental `cdx:mcp:*` [35].
- **Neither document is ready to publish as written.** Of 149 checked claims, 43 need a correction or must be qualified: 18 in the article and 25 in the document. Another 58 are mostly correct. Most need only wording changes, but a few carry a wrong lesson or a mis-scoped number (A1-10, A1-03). Three corrections are critical and 21 are major.
- **The article's opener carries its most consequential errors.** It ties CVE-2026-25253 to the Cline incident, but that CVE affects OpenClaw versions before 2026.1.29, and the hook installed 2026.2.15 without starting any daemon (A1-04) [3][4][38][39]. It also presents Amazon Q's lifetime Marketplace installs as the exposure of one bad release (A2-03) [8][10]. Expert readers check the opener first.
- **The document's most consequential error is about SPDX 3.1.** It says 3.1 adds AI Agent, Prompt and RAG classes. 3.1 is still a release candidate. Neither RC1 nor the development branch has an agent or RAG class, and the only prompt-related addition is the development branch's prompt-template class, InteractionTemplate (B4-01, B4-10) [17][18][32]. The document also contradicts itself on this point.
- **The two documents contradict each other on the central claim.** The article tells CISOs to require a "CycloneDX 1.6+ ML-BOM or SPDX 3.0 AI profile" AIBOM covering MCP servers, tool schemas and SKILL.md files. The document explains, correctly, that neither format can express those natively (editorial-01, standards-01, controls-08).
- **Several of the article's controls are mis-mapped.** The Cline lesson is wrong: Cline had already moved to trusted publishing on February 10, a week before the unauthorized February 17 publish, but a legacy token it had not revoked still published the bad release (A1-10, controls-03) [1][5][6]. The data-poisoning controls stop neither attack described (controls-04), the signing rule is unworkable (A5-10), and nothing contains an injection that succeeds (controls-02).
- **Structural verdict on the article: revise, don't rewrite.** Keep the story, the voice and the CISO framing. Replace the three-layer model with six layers plus a delivery axis, retell Cline in two sourced acts, reorder the action steps by risk removed per unit of effort, and fix the regulatory framing.
- **Structural verdict on the document: consolidate.** It is more than a dozen drafts stacked end to end. It has at least 17 internal contradictions and 40 orphaned source labels, and several of its citations could not be traced in this review (editorial-03 to editorial-06, standards-04). Version 2 rebuilds it as one gap analysis, one profile summary tied to the implemented specification and one upstream roadmap.

## 2. How the review was done

**Claim extraction.** Every checkable statement (facts, numbers, dates, attributions, standards claims and recommendations resting on a factual premise) was extracted: 61 from the article (A IDs) and 88 from the document (B IDs).

**Stage 1: first-pass fact-check.** A checker researched each claim against sources retrieved on November 1, 2026 and recorded a verdict, severity, what the sources show, a suggested rewrite and evidence. The register holds 744 evidence entries across 534 distinct URLs. 621 of the entries are labeled primary, such as advisories, CVE records, registry metadata, normative schemas and spec model files; several dozen of those were read only through search-result excerpts because their hosts were blocked. The Official Journal text of Regulation (EU) 2026/1744 could not be fetched, so the Omnibus dates rest on legal summaries and should be confirmed on EUR-Lex before publication. The checkers also logged 145 related findings, such as Cline's own post-mortem [5].

**Stage 2: adversarial skeptic.** Claims whose first-pass verdict was partially correct, outdated, incorrect or unverifiable, or whose severity was major or critical, went to a second, independent researcher who started from scratch and tried to refute the first pass. In the register used for this report, 42 claims went through this stage (25 article, 17 document). The skeptic amended 26 verdicts or texts, upheld 13, overturned 2 and left 1 uncertain. Both overturns found a source the first pass had missed (A5-02, B2-09). Eleven document claims that met the criteria had not yet been challenged when this register was generated (B5-05, B5-07, B6-02, B6-03, B6-10, B7-02, B7-03, B7-04, B7-06, B7-08, B7-09).

**Reconciliation.** Results for the 42 challenged claims were compared with an independent register produced in another session (verified-claims-ihvm.json). It covered 23 of them, agreeing on 17 and disagreeing on 6, and did not cover the other 19. Where they disagreed, the challenge decided. Claims outside the challenged set were not reconciled. On three of them (Deadbugz, smithmark and the G7 model cluster: B6-02, B6-03, B5-07) the independent register or this register's own G7 record (A7-04) found sources the first pass missed, and those verdicts have been amended to mostly correct; Appendix A shows them as unverifiable. Points that rest only on the independent register are labeled, such as the open SPDX proposal PRs behind B4-01 and B4-10.

**Who did the work.** Every stage (first-pass checking, the adversarial skeptic, the four gap lenses and the reconciliation register) was run by AI research agents working from sources retrieved on the dates given. "Independent" means a separate run that started without the earlier verdicts, not a separate human reviewer, and runs of the same tooling may share blind spots. Each verdict lists its evidence URLs in Appendix A so a human can re-check it.

**Gap analysis.** Four lenses read both documents against the 2024-2026 record:

| Lens | Question it asked | Gaps (P0 / P1 / P2) |
|---|---|---|
| Coverage | Which parts of the agent supply chain, and which real incidents, are missing? | 15 (5 / 8 / 2) |
| Controls | Do the recommended controls stop the attacks described, and are they workable? | 18 (8 / 7 / 3) |
| Standards | Are the statements about CycloneDX, SPDX, MCP and A2A accurate, and what is novel? | 16 (4 / 11 / 1) |
| Editorial | Structure, sourcing, consistency, voice and copy hygiene | 19 (8 / 8 / 3) |

That is 68 gaps in total: 25 P0, 34 P1 and 9 P2. Each lens also produced exact line edits and a proposed outline.

**Limitations.**

- Several primary-source hosts were not directly reachable from the sandbox, including medium.com, nvd.nist.gov, owasp.org, arxiv.org, eur-lex.europa.eu and many github.com pages. Their content was checked through search results, or through raw.githubusercontent.com copies where they existed. Four article claims rest only on secondary sources and are marked so in Appendix A.
- The lenses ran after the web-search budget was spent and verified new facts by direct fetches from permitted hosts. NIST/NCCoE agent-identity work could not be verified because its host was blocked. The G7 "SBOM for AI" minimum elements were checked through the openregtech/sbom machine-readable encoding, not the BSI PDF. Several first-pass checks, including those for Deadbugz and smithmark, ran after the web-search budget was spent, so a "not found" verdict from them is not evidence that a source doesn't exist.
- The article's images were not available, only their captions. The MCP vulnerabilities figure can't be checked (A3-09).
- Eight claims are marked unverifiable in the register, one in the article and seven in the document. Three more (B5-07, B6-02, B6-03) were unverifiable in the first pass; follow-up checks found their sources and the register now records them as mostly correct. Version 2 cites the G7 encoding in the body, records smithmark and Deadbugz with their sources in its Appendix A, and drops or qualifies the rest.
- Severity reflects the damage a claim would do to credibility or to a reader's decisions, not how wrong it is in absolute terms.

## 3. Verification results in numbers

| Verdict | Article (61) | Document (88) |
|---|---|---|
| Correct | 14 | 34 |
| Mostly correct | 29 | 29 |
| Partially correct | 12 | 14 |
| Outdated | 3 | 2 |
| Incorrect | 2 | 2 |
| Unverifiable | 1 | 7 |
| **Needs correction or qualification** | **18 (30%)** | **25 (28%)** |

| Severity | Article | Document |
|---|---|---|
| Critical | 2 (A1-04, A2-03) | 1 (B4-01) |
| Major | 6 | 15 |
| Minor | 40 | 41 |
| None | 13 | 31 |

| How each claim was checked | Article | Document |
|---|---|---|
| Single pass, primary source | 32 | 63 |
| Single pass, no source found (unverifiable) | 0 | 5 |
| Follow-up check, source found after the first pass | 0 | 3 |
| Single pass, secondary only | 4 | 0 |
| Challenged by the skeptic | 25 (18 amended, 6 upheld, 1 overturned) | 17 (8 amended, 7 upheld, 1 overturned, 1 uncertain) |

Two patterns matter more than the totals.

**The article's errors cluster in its numbers and its incident details.** Six of the 18 article claims that need changes concern a statistic or an incident detail: the CVE link, 964,000 installs over 48 hours, 437,000 downloads, 72.8%, 100x and "multi-week to instantaneous" (A1-04, A2-03, A2-06, A3-05, A5-07, A7-08). The same scoping error recurs below the threshold for correction: downloads are reported as developers (A1-03, mostly correct). Among the larger errors, one model's maximum is presented as a general rate (A3-05) and a lifetime install count as exposure (A2-03).

**The document's errors cluster in standards status and lost sources.** Its "correct" rate is higher, because its schema-level claims mostly hold. But 7 of its 25 problem claims are marked unverifiable. Most rest on sources this review could not trace (the AIRS categories, a TEE package, a Hugging Face AIBOM measurement and others), and web search was unavailable for most of those checks. Three more, Deadbugz, smithmark and the G7 hash elements (B6-02, B6-03, B5-07), were found on follow-up and are now counted as mostly correct. Most of the rest misstate what the standards and their tooling contain: SPDX 3.0.1 and 3.1, CycloneDX 1.7 and 2.0, and Dependency-Track. Several of these are moving targets that the drafts described differently at different times.

## 4. The most consequential corrections

These are the 15 corrections that would do the most damage if published, ranked by that judgment rather than by register severity: item 9 is rated minor in the register but carries a P0 control gap, and three other major corrections (B3-03, B4-09, B5-05) are listed after the ranking. The version 2 drafts address all 15. Two leftovers were fixed after the fact-check: the article's Amazon Q paragraph no longer ends "Only a syntax error stopped the wipe, not any control," which the A2-03 challenge struck as unsupported, and the document's Appendix A no longer lists Deadbugz as unsourced (item 14).

**1. CVE-2026-25253 and the "persistent daemon" (A1-04, article, critical).** *Original:* victims got "an autonomous AI agent with full system access, a persistent daemon, and a WebSocket channel for remote commands (CVE-2026-25253)." *Sources:* the hook installed OpenClaw 2026.2.15. CVE-2026-25253 affects versions before 2026.1.29. The installed version has no install-time scripts, and its gateway daemon needs a separate onboarding step. That version does fall within a later critical gateway flaw, CVE-2026-22172 (fixed in 2026.3.12), but exploiting it needs a running gateway and a client that already holds the shared token or password, so the bare install was not a remote-command channel. Cline rates the incident Low and calls OpenClaw "non-malicious"; the incident has no CVE of its own. *Fix:* the hook installed an unapproved agent globally without configuring or starting it. Whoever held the token could have shipped any install-time code. *Sources:* [1][2][3][4][38][39][53]

**2. Amazon Q: "964,000 installations over a 48-hour window" (A2-03, article, critical).** *Sources:* 964,000 is the extension's lifetime Marketplace count [52], and AWS never said how many machines took v1.84.0. That version was current for about 31.5 hours, from July 17, 2025 at 20:29 UTC until 1.85.0 on July 19 at 03:58 UTC [51]. Per CVE-2025-8217, the injected code ran when the extension launched, but a syntax error kept it from making a successful call to the Q Developer CLI [9]. AWS's revert and new release stopped the distribution. AWS says no customer resources were affected. *Fix:* use the A2-03 rewrite. *Sources:* [8][9][10][51][52]

**3. SPDX 3.1 "adds AI Agent, Prompt and RAG classes" (B4-01, document, critical; also B4-06, B4-10).** *Sources:* 3.1-RC1 (January 24, 2026) is not GA, and `latest` still points to 3.0.1. RC1 deprecates `autonomyType` in favor of `isoAutomationLevel` and adds ML relationship types, but no agent, prompt or RAG class. The development branch has since added one AI class, `InteractionTemplate`, which refers to an `AIAgent` class that doesn't exist. Nothing in RC1 or on the development branch corresponds to the `toolsAvailable`/`toolType`/`toolScope` debate, and no class is named Prompt. The nearest thing is the development branch's `InteractionTemplate`, a prompt-template class with optional hashes and nothing that distinguishes a deployed system prompt from a template (B4-10). *Fix:* one dated status paragraph, with agent and RAG classes described as proposals. *Sources:* [17][18][32]

**4. EU AI Act duties described as binding now, and "mandatory" convergence (A6-03, A6-06, article, major).** *Sources:* the Act is binding but applies in phases. Regulation (EU) 2026/1744, in force since July 27, 2026, moved the Article 11, 15 and 25 high-risk duties to December 2, 2027 (Annex III) and August 2, 2028 (Annex I). None of them applied when the article appeared. What already applies includes the prohibitions and the AI-literacy duty (since February 2, 2025), the obligations on general-purpose AI model providers, including documentation for downstream integrators (since August 2, 2025), and most Article 50 transparency duties and Commission enforcement of GPAI obligations (since August 2, 2026; generative systems already on the market have until December 2, 2026 for output marking). NIST and OWASP are voluntary, as the article's own labels say. *Fix:* "only the EU AI Act is law," followed by the dated schedule. *Sources:* [15][16]

**5. SafeTensors as "the definitive defense," "written in Rust," "100x faster" (A5-05 major, A5-07 minor; article).** *Sources:* the format removes code execution on weight load. It can't reveal backdoored weights, and it doesn't cover the configs, templates and code that ship beside the weights. Rust is the reference library, not the format. Hugging Face's own GPT-2 benchmark shows about 77x on CPU and about 2x on GPU [43]. *Fix:* "the standard fix for deserialization attacks, not a complete defense." *Sources:* [13][43]

**6. Blocking models that lack transparency-log signatures (A5-10, article, major; controls-07).** *Sources:* OpenSSF Model Signing supports keys, certificates and Sigstore, and only Sigstore writes to a log. NVIDIA, which has signed every model it publishes on NGC with OMS since March 2025, has users verify against its own certificate rather than a log [49]; certificate- and key-signed bundles carry no log entry [50]. The rule would block almost every open model, yet accept anyone's logged signature. *Fix:* verify against pinned signer identities, admit unsigned models through scan, sandboxed conversion and evaluation, re-sign internally, and pin by digest. *Sources:* [14][49][50]

**7. MCPTox "72.8% against leading models" (A3-05, article, major).** *Sources:* 72.8% is the highest per-model rate (o1-mini). The paper reports an average attack success rate of 36.5% across all model settings, and no model refused even 3% of attacks. Confirm 36.5% against the paper's results table before publishing; it was read here only through search excerpts. *Fix:* give the average and the maximum. *Source:* [12]

**8. mcp-remote: 437,000 downloads "exposed to full RCE" (A2-06, article, major).** *Sources:* CVE-2025-6514 (CVSS 9.6) affects versions 0.0.5 to 0.1.15 when the client connects to an untrusted server. 437,000 counts downloads of every version. The target is the user's own machine: arbitrary OS commands with full parameter control on Windows, and arbitrary executables with limited parameter control on macOS and Linux. The fix shipped three weeks before disclosure. *Fix:* the A2-06 rewrite. *Source:* [11]

**9. The Cline lesson (A1-10, article, minor; P0 impact via controls-03).** *Sources:* Cline moved to trusted publishing on February 10, 2026, a week before the incident. Its post-mortem says the wrong token was deleted, and the old token published 2.3.0. npm accepts tokens alongside trusted publishing until a maintainer disallows them. *Fix:* "publish through trusted publishing, then disallow tokens and revoke the old ones." *Sources:* [1][5][6]

**10. "SPDX 3.0 is ISO/IEC 5962" (B3-01, document, major).** *Sources:* ISO/IEC 5962:2021 is SPDX 2.2.1, and no 3.x edition is an ISO standard. *Sources:* [19][20]

**11. CycloneDX dependencies as a "flat list," and VEX vocabulary (B1-13, B1-16, document, major).** *Sources:* CycloneDX has a directed dependency graph, serialized flat. Its two edge types carry no order, role or condition. VEX justifications roughly cover "tool disabled," "guardrail enforced" and "approval required," but no field names the guardrail or the policy. *Fix:* "coarse graph relationships" and "generic not-affected justifications." *Sources:* [21][22]

**12. SPDX 3.0 VEX and "no formal documentation" (B3-13, document, major).** *Sources:* SPDX 3.0.1 defines four normative VEX relationship classes, with examples. What is thin is implementation guidance. *Source:* [23]

**13. "Dependency-Track still ingests only CDX ≤ 1.6" (B2-08, document, major).** *Sources:* 1.7 ingestion arrived in v5.1.0 (August 27, 2026) and was backported in v4.14.4 (September 14, 2026). *Sources:* [24][25]

**14. Sources the document doesn't name (B6-10, B7-02, B7-03 major; B4-08, B7-04, B7-09 minor; B5-07, B6-02, B6-03 since found).** *Sources:* this review could not locate the "AIRS" categories, the TEE governance package, the Hugging Face AIBOM measurement, or the "safeguard" and "anchor-defense" sources. Web search was unavailable for most of these checks, so that does not prove they don't exist. Three references do check out, and the register now records them as mostly correct. Deadbugz is a runtime-gated MCP metadata-poisoning campaign that Pillar Security disclosed in August 2026 [46][54]; CSA treats its call-count gating as distinct from the plain rug pull that mcp-scan detects by hashing [26]. smithmark is a Go tool whose `registry check` reports that no real MCP Registry entry carries the proposed attestation-reference field [47]. The G7 "SBOM for AI" Models cluster lists a model hash value and hash algorithm, per the openregtech/sbom encoding [48]. Other points hold on primary evidence: the MCP Registry schema has no attestation field [27], and neither spec has fields for serialization safety or probe results, since CycloneDX 1.7 offers only generic hooks and SPDX 3.0.1 `AIPackage` has no such property [22][44]. *Fix:* cite Pillar, smithmark and the G7 document for those three. For Deadbugz, say the tool hash must be re-checked at runtime, because a one-time scan sees only the benign first state. Restate the other points on verified evidence. The Yocto size figure (B4-08) can stay only as "reported."

**15. Regulatory and audit overreach in the document (B7-06, B7-08, document, major).** *Sources:* Article 53 requires technical documentation that describes the type, provenance and curation of training data (Annex XI) [55], a copyright policy that honors text-and-data-mining opt-outs, and a public training-content summary. It requires no consent and no per-source licensing, and real summaries are coarse [28]. ISO/IEC 42001 sets requirements for an AI management system; in Google Cloud's words, it "does not mandate specific AI controls" [29]. It defines no evidence schema for evaluations or provenance records, and mentions data provenance only briefly [56]. *Fix:* present structured provenance and evaluation records as evidence an auditor will welcome, not as a legal requirement.

Other corrections a reviewer will look for, all in Appendix A (the first three are rated major):
- SPDX `Agent` is not `Tool` (B3-03).
- SPDX generators still default to 2.x (B4-09).
- Cisco's Model Provenance Kit tracks lineage; it doesn't detect trojans (B5-05).
- `torch.load` has defaulted to `weights_only=True` since PyTorch 2.6 (A5-09) [33].
- OWASP's 2026 LLM Top 10 renumbered its entries (A6-07) [16].
- The incident is "Clinejection," not "Clineinjection" (A1-11) [7].

## 5. Structural and editorial findings

### The article

**What works.** A strong cold open, a memorable title phrase, the right CISO register, and an action list readers will forward.

**What doesn't.**

- *The layer model can't place the article's own lead incident* (coverage-01, editorial-12). Clinejection was a CI compromise: its decisive steps (a triage bot with Bash, a cache shared with the release job, a publish token that was never revoked) sit outside Data, Models and Tools and Registries.
- *The opener states a chain its sources don't* (editorial-02). The advisory says only "compromised npm publish token"; the link from issue #8904 to the token needs attribution. "glthub" replaces the "i" with an "l"; it isn't "missing the i" (A1-06).
- *About 25 statistics and sweeping claims have no source* (editorial-07). Examples: "ten distinct dimensions" (never listed), "Thousands of developers install," "Over 100 malicious models," "instantaneous database queries" (A7-08). Four attack scenarios read as reports but are hypotheticals (editorial-11).
- *Copy errors a security reader notices first* (editorial-08). Two sentences are unfinished ("it is shaped by." and "framework for implementing."). En dashes inside CVE and GHSA IDs break copy-paste into scanners.
- *Controls don't match the examples* (controls-01, controls-04, controls-15, editorial-10). Case studies stop at impact, and the data section prescribes storage controls against ingestion attacks.
- *Images.* Two of nine have no caption, and none is explained in the text (editorial-14). The reference list and the body don't match (editorial-15).

### The document

**What works.** The opening questions and four headings (composition, authorization, observability, assurance) are the right spine. The schema analysis is the document's most accurate material; across all 88 document claims, 34 are correct and 26 mostly correct. Lines such as "A spec nobody emits protects nobody" are worth keeping (editorial-19). The standards lens names five real contributions: one validated cross-format vocabulary, a coverage statement, an authorization record bound to tool and policy digests, trace-to-snapshot binding, and verifiable redaction.

**What doesn't.**

- *More than a dozen drafts stacked end to end* (editorial-03, standards-04). About 10,400 words, roughly twice its content; the standards lens found "no agent-native types" in 11 of the 13 drafts it counted.
- *Lost citations and conversion debris* (editorial-05). There are 40 one-word source labels ("github," "pypi," "arxiv," "anchor-defense," "+2") and five `utm_source=chatgpt.com` links. Three tables broke in conversion. The leftovers undercut the paper's own thesis that attribution isn't verification.
- *Two incompatible design approaches* (editorial-06). One section asks for "first-class types, not extensions or properties." Another says to follow the `cryptoProperties` pattern instead of adding types. Relationship names vary (`delegatesTo`, `delegatedTo`, `delegatesAuthorityTo`, `actsOnBehalfOf`), and there are four trust vocabularies.
- *Private references and notes-to-self* (editorial-16). Examples: "Shadow Scan" autonomy levels, "This is what I have to patch manually for clients," and an unnamed "March 2026 Oxford/Cisco paper." A comparison to TAIBOM, a public Trusted AI Bill of Materials project [57], appears without a citation or explanation. The lead generator example, brox, has placeholder project URLs on PyPI.
- *Absolutes that invite rebuttal* (editorial-19). Examples: "Kills the 'same model name, different weights' class of attack," "the only SBOM-level defense against MCP rug pulls," "security theater."
- *Controls the spec says are untrusted* (controls-13, controls-14). The authority model builds on MCP tool annotations, which the MCP spec calls untrusted hints. The document also implies that per-tensor fingerprinting would catch a poisoned adapter or layer ("Whole-blob hashes miss single-layer trojans"), but no hash, whole-file or per-tensor, can tell whether the reference weights were poisoned.

## 6. Gap analysis summary

### The 25 P0 gaps in seven themes

| Theme | Gaps | Why it matters |
|---|---|---|
| **A. The scope model misses where attacks land** | coverage-01, coverage-03, coverage-04 | Three layers misfile instruction files (SKILL.md sits under Data) and leave out rules files, the config that runs code, the runtime, identity and the build pipeline. That is where Cline, Nx s1ngularity and the 2025-2026 agent-tool vulnerabilities in Cursor, Copilot, Codex CLI, Gemini CLI and Claude Code landed. |
| **B. Two missing components that hold the keys** | coverage-02, coverage-05 | LLM gateways hold every provider key and choose the model. Attackers published malicious LiteLLM releases twice in 2026: 1.82.7 and 1.82.8 in March, using a PyPI token stolen by a compromised Trivy scanner in its CI [36], and 1.107.0 wheels and Docker images on October 21, according to press reports [40]. Hosted models change behind the same model ID, and the article gives a GPT, Claude or Gemini agent no model controls at all. |
| **C. Controls that are mis-mapped or unworkable** | controls-01, controls-03, controls-04, controls-06, controls-07 | Several items fail as written: the step order, the Cline lesson, storage controls offered against ingestion attacks, the blanket pickle ban with no migration path, and signing as a log-presence test. A CISO who forwards the list funds the wrong work. |
| **D. No containment when injection succeeds** | controls-02, controls-05 | The article concedes that injection can't be eliminated, then gives no containment. The document defines the right fields (egress domains, approval gates, execution isolation, human-in-the-loop and a trifecta flag), but treats the Rule of Two as a design-time query and never says these fields cut risk only when a runtime enforces them in each session. Meta's Agents Rule of Two says an agent should combine at most two of untrusted input, sensitive systems or private data, and the ability to change state or communicate externally in one session [45]. An agent that never holds untrusted input, private data and an outbound channel in one session can't be made to leak that data [34]; approval gates on destructive actions cover what the trifecta doesn't. Tool pinning is checked once at deploy time, and its hash leaves out server instructions and output schemas. |
| **E. AIBOM standards oversold as the control** | controls-08, standards-01, editorial-01 | A signed AIBOM is evidence, not a control. A "CycloneDX 1.6+ ML-BOM or SPDX 3.0 AI profile" mandate accepts documents that validate yet have no native types for tools, instruction files or permissions. Tools and instruction files appear only as generic components with vendor-namespaced properties, such as cdxgen's experimental `cdx:mcp:` fields [35], and permissions not at all; k8s-aibom doesn't inventory MCP servers or tool definitions [30]. |
| **F. The document's standards status and consolidation** | standards-02, standards-03, standards-04, editorial-03, editorial-04, editorial-06 | SPDX 3.1 is described three ways. CycloneDX 2.0 features are presented as shipped, though the release is still "to be announced" [31]. More than a dozen drafts and two design approaches leave a maintainer unable to tell what SymBiote is asking for. |
| **G. Sourcing and copy hygiene** | editorial-02, editorial-05, editorial-07, editorial-08 | Unsourced numbers, lost citations, tracking links and broken IDs are the first things an expert reader checks, and each one is an excuse to discount the rest. |

### P1 and P2 themes

**P1 (34 gaps):**
- *Identity and credentials:* neither document inventories credential custody (coverage-06, controls-09, standards-14).
- *Launch path, registries and skills:* unpinned `npx -y`/`uvx` launches, real malicious servers, skill-marketplace malware, and what registry signatures prove (coverage-07, coverage-09, controls-11, controls-12, standards-16).
- *Runtime targets:* hijacked local coding agents, exploited frameworks and MCP hosts, memory and connector attacks, model-hub risks beyond pickle (coverage-08, coverage-10 to coverage-13).
- *Detection and response:* one sentence in each document (controls-10).
- *Case studies:* each should end with the control that would have broken the chain (controls-15).
- *MCP 2026-07-28:* no handshake or sessions, and tool lists cacheable per authorization context, which changes tool digests and runtime binding [37] (standards-08).
- *Digests and assurance:* digest canonicalization, per-claim assurance with a named signer, declared-vs-observed semantics, model identity, untrusted MCP annotations (standards-07, standards-09 to standards-13, controls-13, controls-14).
- *Prior art:* credit cdxgen, k8s-aibom, OWASP AOS, CoSAI, A2A and OMS; don't add a fourth dialect (standards-05, standards-06).
- *Editorial:* label hypotheticals, add Nx, settle names, fix images and references (editorial-09 to editorial-16).

**P2 (9 gaps):** self-hosted inference servers (coverage-14); the A2A channel (coverage-15, controls-18); practicality tiers for TEE, Merkle redaction and fingerprints (controls-16, controls-17, standards-15); hype words, headline and absolutes (editorial-17 to editorial-19).

## 7. Contradictions

### Between the article and the document

| Topic | Article says | Document says | Resolution in v2 |
|---|---|---|---|
| What AIBOM standards cover | CycloneDX/SPDX AIBOMs cover MCP servers, tool schemas and SKILL.md files; k8s-aibom is "a reference implementation" | Neither standard has native types for agents, tools, prompts or memory, or records what an agent may do | The document is right. The article adds "Where today's AIBOM standards stop." k8s-aibom's README doesn't list MCP servers or tool definitions [30] |
| What a signature proves | A "signed AIBOM" is the executive control | "A signature authenticates the statement and its origin; it does not establish that the statement is true" | The document is right. The article calls the AIBOM evidence, generated from the pipeline and the runtime and checked against behavior |
| Supply chain model | Three layers: Data, Models, Tools and Registries | Four questions and many component types | Both use six layers (data and memory, model, instructions and config, tools and peers, runtime, identity) plus a delivery axis (coverage-01) |
| SafeTensors | "The definitive defense" | Content addressing and load-time safety are partial controls | The document's framing wins (A5-05) |
| Hosted models | Not covered | Covered as a gap ("can't be pinned") | Both add requested vs resolved model identity and dated snapshots (coverage-05) |
| Names | AI-BOM, AIBOM | AgentBOM, AgBOM, SymBiote, ML-BOM | One set of names: the article uses AIBOM throughout and introduces AgentBOM once; the document defines every term in Part I, section 9 (editorial-13) |

### Within the document

The standards lens resolved 12 contradictions against spec text. The editorial lens adds five more, items 13 to 17.

1. **SPDX 3.1 agent, prompt and RAG classes:** asserted in at least seven places and denied in one. None exists (B4-01).
2. **SPDX runtime and service:** "no runtime concept" vs. "has one." `sbomType` runtime and deployed, and `LifecycleScopeType` runtime, exist in 3.0.1. SoftwareService arrives in 3.1-RC1.
3. **CycloneDX 2.0:** treated as planned in some sections and as shipped in others. It is a draft: the repository lists its release as "to be announced" [31], though the project's August 5, 2026 announcement expects release this fall and Ecma approval in December.
4. **Citations:** one section says CycloneDX 1.7 citations "already carry an optional signature"; others say they aren't bound to "cryptographic evidence." Resolution: the schema has an optional signature over the attribution.
5. **SPDX delegation and tool edges:** "SPDX gives you DEPENDS_ON, CONTAINS" (SPDX 2.x names) vs. `usesTool`, `invokedBy` and `delegatedTo`. The verbs exist, without qualifiers.
6. **`autonomyType`:** given the wrong values and attributed to CycloneDX in one place. It is an SPDX field, deprecated in 3.1-RC1.
7. **CycloneDX graph:** "flat list" vs. "dependency graph." A heading says "flat model card" over a paragraph that says nested (B1-13).
8. **Static vs. runtime BOMs:** both formats can label runtime BOMs; neither binds actions to snapshots.
9. **SPDX VEX:** "undocumented" vs. described elsewhere (B3-13).
10. **Hosted models:** "invisible" vs. "a service can carry a version string."
11. **Tool-definition hash:** "no way to pin one" vs. sections that show how.
12. **ISO 5962 and Core Tool:** ISO applies to SPDX 2.2.1 (B3-01), and Core `Tool` is not an `Agent` (B3-03).
13. **Design approach:** new first-class component types vs. "follow the `cryptoProperties` pattern instead of exploding type" (editorial-06).
14. **Trust scores:** one section gives components different numeric trust scores; another grades individual claims with assurance levels and warns that a single score for the whole agent "would conceal important differences." Resolution: per-claim assurance levels, no scores.
15. **Rug-pull defense:** "the only SBOM-level defense" vs. the document's own point that a schema hash can't see a backend change behind the same interface.
16. **SPDX profile dependence:** `AIPackage` and `DatasetPackage` are said to subclass Software/Package, yet AI-profile conformance "doesn't entail Software profile."
17. **Naming the project:** the title says "Agent Bill of Materials - AgentBOM," while the text warns against letting "agent BOM" become "its own island." Resolution: AgentBOM is a profile of CycloneDX and SPDX, not a new format.

## 8. What changes in version 2

### Article (version 2)

| Section in v2 | Change | Why |
|---|---|---|
| Title and subtitle | Subtitle now promises the inventory and "what to do while the standards catch up" | Sets up the hand-off to SymBiote; drops "AI-BOM" for AIBOM (editorial-18) |
| One line in package.json / Act two | Cline told in two acts. Act one: the publish, the eight-hour window, about 4,000 downloads per StepSecurity, OpenClaw not malicious, no provenance. Act two: the triage workflow, Khan's disclosure and attributed forensics. The CVE link is removed | A1-03 to A1-07, A1-04, editorial-02 |
| Executive summary | Adds a containment line and scopes the AIBOM decision as evidence generated from the pipeline and the runtime | controls-02, controls-08 |
| Layers 1-6 | Six layers replace three; new sections on instructions and config, runtime (including gateways, LiteLLM and the developer laptop) and identity | coverage-01 to coverage-05 |
| How it all arrives | New section on registries and pipelines, with Nx s1ngularity, Amazon Q and Cline as one pattern | coverage-03, editorial-11 |
| Assume the injection lands | New containment section: Rule of Two, egress, sandboxes, approvals | controls-02 |
| The AI Bill of Materials | Corrected pillars, completeness wording, one signing method for both formats (an in-toto attestation), and regulation with "binding vs voluntary" and Omnibus dates fixed | A6-03, A6-06, A7-07, A7-09 |
| Where today's AIBOM standards stop | New: five gaps, what an AIBOM would and wouldn't have shown for Cline, the interim practice, the hand-off | editorial-01, standards-01 |
| Steps you can take now | Ten steps grouped this week / this month / this quarter, cheapest high-impact items first | controls-01, controls-03, controls-06, controls-07 |
| Conclusion, corrections note, references | A one-agent, 30-day ask; a corrections note (keep it if the piece goes out as an update, see Decision 1); 96 numbered references | editorial-15, editorial-18 |

The body is now about 4,800 words, including the corrections note. The editorial lens targeted about 2,450; the extra length comes from the coverage and controls additions (see Section 9).

### Document (version 2)

| Part in v2 | Change | Why |
|---|---|---|
| Title, abstract, how to read this | New title; the document is a profile of CycloneDX and SPDX, not a new format | editorial-06, editorial-13 |
| Part I, sections 1-2 | Opens on the Cline case. One dated "Standards status on 1 November 2026" box replaces every scattered status claim | standards-02, standards-03, editorial-04, B2-08, B2-10, B4-01, B4-09 |
| Part I, sections 3-7 | The four questions and the same six layers as the article, with each gap stated once, tagged by version and tied to an incident | editorial-03, standards-04, coverage-01 |
| Part I, sections 8-9 | Prior art credited, the novel parts named, and a glossary | standards-05, standards-06, editorial-13 |
| Part II | The AgentBOM profile summarized from the implemented specification. Proposals that aren't implemented are listed separately in II.12 | Separates what exists from what is proposed; resolves the design-approach contradiction in favor of extension |
| Part III | Upstream asks: register one CycloneDX property namespace, shape CycloneDX 2.1 (v2 treats 2.0's AI/ML content as settled), bring agent semantics to SPDX 3.2 | standards-03, standards-02 |
| Appendix A (in the document) | What changed from v1, including the claims cut for lack of a source | B6-02, B6-03, B6-10, B7-02, B7-03 and others |

The editorial lens targeted about 5,250 words for the whole document; v2 runs about 11,600 words including references (about 10,300 without), up from about 10,400, because Part I (about 5,100 words) now carries the incident evidence and Parts II and III add the implemented profile and the roadmap. Decide whether to keep that length. All 40 orphaned labels and five tracking links are gone, and the private repository is not linked anywhere.

## 9. Decisions for the author

1. **New post or update?** An update should keep the corrections note, since readers may have cited the CVE link and the 964,000 figure.
2. **Article length.** The v2 body is about 4,800 words. Keep it, or cut to about 3,000 by moving Layers 5-6 and the pipeline section into SymBiote?
3. **Headline.** Keep "The Supply Chain of Agency," or take a story-led or CISO-led option (editorial-18)?
4. **Recent incidents with secondary sourcing.** The October 21, 2026 LiteLLM compromise rests on press and vendor reports, and its vector was still being traced when the lenses ran. Both v2 drafts already present it as a second incident (the article cites BleepingComputer, the document The Hacker News). Confirm, or cut it to the March incident until a maintainer post-mortem appears.
5. **How strongly to tie issue #8904 to the stolen token.** Version 2 attributes the chain to Khan, Cline's post-mortem and Bargury's forensics. Comfortable, or softer?
6. **The untraceable references.** Do you have sources for the AIRS categories, the TEE governance package, the Hugging Face AIBOM measurement, and the "safeguard" and "anchor-defense" sources? Version 2 cuts or restates each; any sourced claim can return. Deadbugz, smithmark and the G7 Models cluster are now sourced (item 14). "Shadow Scan" is Nexus ShadowScan; confirm you want it cited. brox is on PyPI but has placeholder project URLs: keep it as the lead generator example, or replace it?
7. **Extension or native types.** Version 2 commits SymBiote to extending CycloneDX and SPDX without forking either, and makes native types a separate upstream request. Confirm, because maintainers will hold you to it.
8. **Names.** Confirm "SymBiote" for the project and "AgentBOM" for the profile, and how you want to position it against OWASP AOS's "AgBOM."
9. **Client work.** v1 says "This is what I have to patch manually for clients." State your consulting experience as evidence, or stay neutral?
10. **Repository visibility.** Both drafts carry "[Author: add the SymBiote repository link if and when it is public]." Public at publication? If not, do Part II's file citations stay?
11. **Implementation status.** Part II.13 describes what SymBiote implements as of November 1, 2026. Confirm it against the code on publication day.
12. **Figures.** The six-layer diagram needs drawing, and the MCP vulnerabilities figure can't be checked without its contents (A3-09). Send it, or rebuild it from the CVE records.
13. **Upstream timing.** Part III proposes engaging CycloneDX on 2.1 now, ahead of 2.0's expected Ecma approval in December 2026. File the namespace and RFC comments before or after publishing?

## References

[1] npm registry metadata for `cline` (version times, publishers, attestations), retrieved November 1, 2026. https://registry.npmjs.org/cline

[2] Cline, "Unauthorized npm publish of Cline CLI `cline@2.3.0`," GHSA-9ppg-jx86-fqw7, February 2026. https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/02/GHSA-9ppg-jx86-fqw7/GHSA-9ppg-jx86-fqw7.json

[3] CVE-2026-25253 record, published February 1, 2026. https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/25xxx/CVE-2026-25253.json

[4] GitHub advisory GHSA-g8p2-7wf7-98mq (OpenClaw/clawdbot Control UI), February 2, 2026. https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/02/GHSA-g8p2-7wf7-98mq/GHSA-g8p2-7wf7-98mq.json

[5] Cline, "Post-mortem: unauthorized Cline CLI npm publish," February 24, 2026. https://cline.bot/blog/post-mortem-unauthorized-cline-cli-npm

[6] npm documentation, "Trusted publishers." https://raw.githubusercontent.com/npm/documentation/main/content/packages-and-modules/securing-your-code/trusted-publishers.mdx

[7] Adnan Khan, "Clinejection: Compromising Cline's Production Releases just by Prompting an Issue Triager," February 9, 2026. https://adnanthekhan.com/posts/clinejection/

[8] AWS Security Bulletin AWS-2025-015, July 23, 2025. https://aws.amazon.com/security/security-bulletins/AWS-2025-015/

[9] CVE-2025-8217 record, July 30, 2025. https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/8xxx/CVE-2025-8217.json

[10] aws-toolkit-vscode, Amazon Q v1.85.0 CHANGELOG. https://raw.githubusercontent.com/aws/aws-toolkit-vscode/refs/tags/amazonq/v1.85.0/packages/amazonq/CHANGELOG.md

[11] CVE-2025-6514 record (mcp-remote), July 2025. https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/6xxx/CVE-2025-6514.json

[12] Wang et al., "MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers," arXiv:2508.14925, August 19, 2025 (AAAI-26). https://arxiv.org/abs/2508.14925

[13] Hugging Face, safetensors README. https://raw.githubusercontent.com/huggingface/safetensors/main/README.md

[14] OpenSSF, Model Signing specification README. https://raw.githubusercontent.com/ossf/model-signing-spec/main/README.md

[15] Regulation (EU) 2026/1744 (Digital Omnibus on AI), Official Journal, July 24, 2026 (host blocked; not fetched, dates taken from legal summaries). https://eur-lex.europa.eu/eli/reg/2026/1744

[16] OWASP GenAI Security Project, LLM Top 10 2026, August 4, 2026. https://raw.githubusercontent.com/GenAI-Security-Project/GenAI-LLM-Top10/main/2026/README.md

[17] SPDX 3 model, develop branch CHANGELOG. https://raw.githubusercontent.com/spdx/spdx-3-model/develop/CHANGELOG.md

[18] SPDX specification site, versions.json. https://raw.githubusercontent.com/spdx/spdx-spec/gh-pages/versions.json

[19] SPDX 3 model README. https://raw.githubusercontent.com/spdx/spdx-3-model/main/README.md

[20] SPDX specification v2.2.1, foreword. https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/chapters/foreword.md

[21] CycloneDX SBOM guide, "Relationships." https://raw.githubusercontent.com/CycloneDX/guides/main/SBOM/en/0x50-Relationships.md

[22] CycloneDX 1.7 JSON schema. https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.7.schema.json

[23] SPDX 3.0.1, VexNotAffectedVulnAssessmentRelationship. https://raw.githubusercontent.com/spdx/spdx-3-model/3.0.1/model/Security/Classes/VexNotAffectedVulnAssessmentRelationship.md

[24] Dependency-Track v5.1.0 release, August 27, 2026. https://github.com/DependencyTrack/dependency-track/releases/tag/5.1.0

[25] Dependency-Track v4.14.4 release notes, September 14, 2026. https://raw.githubusercontent.com/DependencyTrack/dependency-track/4.14.x/docs/_posts/2026-09-14-v4.14.4.md

[26] mcp-scan 0.3.0 on PyPI, July 18, 2025. https://pypi.org/pypi/mcp-scan/0.3.0/json

[27] MCP Registry, server.json schema (draft). https://raw.githubusercontent.com/modelcontextprotocol/registry/main/docs/reference/server-json/draft/server.schema.json

[28] Cohere, EU AI Act public summary of training content, Command A+ family, September 10, 2026. https://raw.githubusercontent.com/cohere-ai/cohere-developer-experience/main/fern/assets/documents/eu-ai-public-summary_command-a-plus-family_20260910.pdf

[29] Google Cloud, ISO/IEC 42001 compliance page. https://cloud.google.com/security/compliance/iso-42001

[30] Google Cloud Platform, k8s-aibom README. https://raw.githubusercontent.com/GoogleCloudPlatform/k8s-aibom/main/README.md

[31] CycloneDX specification, 2.0-dev branch README. https://raw.githubusercontent.com/CycloneDX/specification/2.0-dev/README.md

[32] SPDX 3 model, develop branch, AI/InteractionTemplate. https://raw.githubusercontent.com/spdx/spdx-3-model/develop/model/AI/Classes/InteractionTemplate.md

[33] PyTorch v2.6.0, torch/serialization.py. https://raw.githubusercontent.com/pytorch/pytorch/v2.6.0/torch/serialization.py

[34] Simon Willison, "The lethal trifecta," June 16, 2025. https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/

[35] cdxgen, MCP documentation. https://raw.githubusercontent.com/CycloneDX/cdxgen/master/docs/MCP.md

[36] Snyk, analysis of the poisoned Trivy scanner that backdoored LiteLLM, March 2026 (secondary). https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm

[37] Model Context Protocol, 2026-07-28 specification changelog. https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/docs/specification/2026-07-28/changelog.mdx

[38] npm registry metadata for `openclaw` (release times and the 2026.2.15 manifest), retrieved November 1, 2026. https://registry.npmjs.org/openclaw

[39] OpenClaw v2026.2.15 README. https://raw.githubusercontent.com/openclaw/openclaw/v2026.2.15/README.md

[40] BleepingComputer, "LiteLLM release pipeline hacked to distribute info-stealer malware," October 2026 (secondary). https://www.bleepingcomputer.com/news/security/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/

[41] OWASP GenAI Security Project, LLM Top 10 2026, Appendix A, "Related Framework Mappings" (OWASP Top 10 for Agentic Applications for 2026). https://raw.githubusercontent.com/GenAI-Security-Project/GenAI-LLM-Top10/main/2026/final/Appendix_A_Related_Framework_Mappings.md

[42] Model Context Protocol blog, "Introducing the MCP Registry," September 8, 2025. https://blog.modelcontextprotocol.io/posts/2025-09-08-mcp-registry-preview/

[43] Hugging Face, safetensors documentation, "Speed Comparison." https://raw.githubusercontent.com/huggingface/safetensors/main/docs/source/speed.mdx

[44] SPDX 3.0.1 model, AI/AIPackage. https://raw.githubusercontent.com/spdx/spdx-3-model/3.0.1/model/AI/Classes/AIPackage.md

[45] Meta AI, "Agents Rule of Two: A Practical Approach to AI Agent Security," October 31, 2025. https://ai.meta.com/blog/practical-ai-agent-security/

[46] Pillar Security, "Deadbugz: currently active MCP supply chain campaign," August 2026. https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign

[47] smithmark (Go module `github.com/sns45/smithmark`, v0.2.1), package documentation. https://pkg.go.dev/github.com/sns45/smithmark

[48] openregtech/sbom, machine-readable encoding of the G7 Cybersecurity Working Group's "SBOM for AI: Minimum Elements" (original published by BSI, May 12, 2026). https://raw.githubusercontent.com/openregtech/sbom/main/docs/req/g7ai/g7ai.ttl

[49] NVIDIA Technical Blog, "Bringing Verifiable Trust to AI Models: Model Signing in NGC" (read through the register's extract; host blocked here). https://developer.nvidia.com/blog/bringing-verifiable-trust-to-ai-models-model-signing-in-ngc

[50] sigstore/model-transparency, certificate signer (`sign_certificate.py`). https://raw.githubusercontent.com/sigstore/model-transparency/main/src/model_signing/_signing/sign_certificate.py

[51] Michael Bargury, "Constructing a timeline for Amazon Q prompt infection," July 24, 2025 (secondary). https://raw.githubusercontent.com/mbrg/mbgsec/main/_posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection.md

[52] SC Media, "Amazon Q extension for VS Code reportedly injected with wiper prompt," July 2025 (secondary). https://www.scworld.com/news/amazon-q-extension-for-vs-code-reportedly-injected-with-wiper-prompt

[53] GitHub advisory GHSA-rqpp-rjj8-7wv8 (CVE-2026-22172, OpenClaw gateway), March 2026. https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/03/GHSA-rqpp-rjj8-7wv8/GHSA-rqpp-rjj8-7wv8.json

[54] Cloud Security Alliance, research note "Deadbugz: Runtime-Gated MCP Metadata Poisoning as Supply-Chain Attack," September 2, 2026. https://labs.cloudsecurityalliance.org/research/csa-research-note-deadbugz-mcp-metadata-poisoning-20260902-c/

[55] Regulation (EU) 2024/1689 (AI Act), Annex XI, section 1(2)(c), consolidated text as mirrored by SpringLex (EUR-Lex blocked here). https://www.springlex.eu/en/packages/ai-act/ai-act-regulation/annex-11/

[56] OWASP AI Exchange, "Development-time threats" (ISO/IEC 42001 and data provenance, B.7.5). https://raw.githubusercontent.com/OWASP/www-project-ai-security-and-privacy-guide/main/content/ai_exchange/content/docs/3_development_time_threats.md

[57] Safronov, McCaigue, Allott and Martin, "TAIBOM: Bringing Trustworthiness to AI-Enabled Systems," arXiv:2510.02169, October 2025. https://arxiv.org/abs/2510.02169


*The claim-by-claim tables generated from the register are in [claim-register.md](claim-register.md).*
