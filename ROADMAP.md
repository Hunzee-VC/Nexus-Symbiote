# Roadmap

Nexus SymBiote is not related to Symbiote, the Linux malware of the same name reported in 2022.

This is the project's single roadmap. It consolidates seven external reviews written between
9 and 10 November 2026 ("Road to #1", "Competitive Review and Path to #1", "The path to #1:
consolidated recommendations", "SymBiote Path to #1", "Blueprint to Undisputed #1", "Fixes, moves
and roadmap" and the end-to-end audit of v0.1.0), checks every recommendation against the code,
and turns what survives into one plan with acceptance tests.

- **Checked against:** `main` at 3ad53a2 (12 November 2026, native format 1.1.0), plus the changes
  delivered with this roadmap. `main` has since merged #131 (fd20305: shell startup-code bypasses
  in MCP launchers, bounded launch-argument expansion), #132 (9cb6a47: the P0 audit findings
  SEC-F1, SEC-C1, ARCH-F1 and DOC-F3/F7) and #133 to #137 (through c792872: suppressions bound to
  findings, launcher classification gaps, collector bookkeeping, workflow gate checks and the
  cached Sigstore trust root); #138 merged `main` through c792872, and the rows below that
  #131 and #132 changed say so. Measurements in [where it stands](#where-it-stands) are still those
  taken at 3ad53a2.
- **How:** every recommendation was located in the code, and most were reproduced by running the
  tool on synthetic fixtures. External facts (standards, other tools, identifiers) were read from
  primary sources on 12 November 2026; the few that could only be checked through secondary sources
  are marked. Rankings in the reviews were not reproduced: they contradicted each other and none was
  a measurement.
- **Contents:** [the lane](#the-lane) · [where it stands](#where-it-stands) ·
  [delivered with this roadmap](#delivered-with-this-roadmap) · [plan](#plan) ·
  [acceptance tests](#acceptance-tests) · [scorecard](#scorecard) ·
  [decisions and non-goals](#decisions-and-non-goals) ·
  [corrections to the reviews](#corrections-to-the-reviews) · [landscape](#landscape) ·
  [risks](#risks-and-watch-items) · [traceability](#traceability)

## The lane

Nexus SymBiote is the **verifiable AgentBOM**: an inventory of what an AI agent is assembled from —
MCP servers and tools, models, instructions and skills, retrieval sources, A2A endpoints, coding-agent
settings, packages and images — in which every claim carries its evidence, every gap is reported,
and every gate fails closed. It reads a project without running it and works offline by default.

The reviews agree on where SymBiote can be first: not as the broadest scanner (cdxgen, Cisco AI BOM,
agent-bom and the companion Nexus-ShadowScan read more surfaces), but as the layer whose claims an
auditor can rely on, which other tools' discovery feeds and which a CI gate can enforce. Every item
in this roadmap is judged by whether it makes that claim stronger:

1. **Airtight evidence.** No gate passes over a change the collectors did not read.
2. **Declared versus actual.** Compare what the repository declares with what the agent reports
   doing at run time, without executing anything.
3. **Verifiable artifacts.** Inventories are reproducible, content-addressed and signed.
4. **Standards-native.** What SymBiote knows reaches the standard fields and frameworks consumers
   already read.
5. **Trust that code cannot supply.** Independent review, a second maintainer, benchmarks others
   can rerun.

## Where it stands

Measured at 3ad53a2:

| Measure | Value |
| --- | --- |
| Source | 39,476 lines of Python in 74 files (16,864 in 61 files at v0.1.0) |
| Tests | 2,507 test functions, 6,228 collected cases; full suite 6 minutes on 4 cores; 2 expected host file-system skips |
| Collectors | 8: `mcp`, `model`, `prompt`, `rag`, `registry`, `a2a`, `ide_agents`, `shadowscan` |
| Exports | native JSON (format 1.1.0), CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0, CycloneDX VEX; each validated before it is written (CycloneDX, SPDX and VEX against the vendored official schemas, SARIF by a structural validator) |
| Gates | `scan`, `validate`, `risk`, `diff --fail-on-alert`, the GitHub Action, pre-commit hooks |
| Release | nexus-symbiote 0.1.0 on PyPI since 8 November 2026 through trusted publishing, with PEP 740 publish attestations on both files |
| Platforms | Linux qualified (Python 3.11–3.14); a macOS smoke job outside Verified CI; Windows refused |
| People | one maintainer; no independent human review of any release (`GOVERNANCE.md`) |
| Time to first inventory | 4.6 s for the bundled demo agent |

**Strengths to protect.** All seven strengths the reviews name still hold at 3ad53a2: offline by
default with an audit hook that refuses sockets and process creation; declared, observed and
verified evidence kept distinct; integrity binding (file digests, RFC 8785 tool fingerprints,
SafeTensors header fingerprints, operator signer policy, keyed source binding); drift gating that
compares every field by default; A2A 0.3 and 1.0 security schemes, coding-agent permissions and MCP
launcher identity; signed runtime contracts for a reference gateway; and release discipline (hash
locks, CodeQL, trusted publishing, a 24-hour soak before publication).

**What the 3ad53a2 remediation already closed.** The v0.1.0 audit and the reviews were written
against v0.1.0. Since then, collection reads Claude Code hooks, deny and ask rules, `apiKeyHelper`,
subagents, skill scripts, nested `CLAUDE.md` and `AGENTS.md`, `.github/instructions`,
`.cursor/rules` and eleven MCP client files; MCP launchers behind wrappers are classified or become
a high finding and a gap; inventories record root-relative paths, so the same project gives the same
inventory at any checkout path; collection limits are operator settings; every gate prints its
reasons; CI log commands cannot be forged through inventory text; GGUF chat templates that reach
Python internals are critical; and 23 of the 44 finding categories have a SARIF rule of their own,
19 of them with CWE or OWASP tags.

**What still undermined the central claim** (reproduced at 3ad53a2, closed by this change unless
stated): marker-only IDE settings files (`.cursor/cli.json` widened from `Shell(ls)` to `Shell(*)`)
and Codex settings other than three keys passed `diff --fail-on-alert`; hidden text in unassigned
default-ignorable code points produced no finding; MCP servers in `.js`, `.mjs`, `.cjs`, `.mts`,
`.cts` and `.tsx` files, servers launched from application code and agent files inside directories
named `venv` or `node_modules` left no coverage gap; the ShadowScan bridge still maps 3 of
ShadowScan's 18 finding kinds (open); and ShadowScan refuses the native inventory SymBiote writes, so
an approved SymBiote inventory cannot become ShadowScan's approved list.

**What `main` closed after 3ad53a2.** #131 treats as unknown launchers the shell startup code that
can replace a pinned MCP runner (`--rcfile` and `--init-file`, exported bash functions, a relative
or `/proc` `BASH_ENV`, `ENV` with an interactive shell, `PS4` expansions while tracing) and bounds
launch-argument expansion in time and memory. #132 closes four P0 findings of a separate audit:
SEC-F1 (a ShadowScan import records its producer verification in the inventory, and unverified
discovery evidence fails `import-shadowscan`, `validate` and `risk` in CI unless explicitly
allowed), SEC-C1 (offline Sigstore verification checks the cached trust root before trusting it, or
uses an explicit, optionally pinned one), ARCH-F1 (deterministic output: no wall-clock timestamp,
components and dependencies sorted, a content-derived serial number) and DOC-F3/F7 (stale roadmap
and repository-controls rows). #133 binds each `risk.suppressions` entry to the fingerprint of the
finding it accepted, so a changed finding counts again. #134 treats more package installs
(`pip3.12`, `gem i`, `pip install` after options) as unknown launchers, reads `cmd /c` quoting as
`cmd` does, and redacts a token inside a name and an MCP server or tool name that is a token. #135
makes the prompt collector's import lookups the operator limit `import-lookups`, keeps a refused
file distinct from an absent one past the failure listing bound, and reads a native document without
a `metadata` object as format 1.0.0 everywhere. #136 makes the workflow gate checks structural and
requires the publishing environment to admit only `main` and the PyPI soak to start from a push run.
#137 verifies the cached Sigstore trust root from the bytes that were checked, closing the window in
which a same-user process could replace it between the check and the load.

## Delivered with this roadmap

Each entry names the review items it closes ([traceability](#traceability)) and the guide that
documents it.

| # | Delivered | Closes | Guide |
| --- | --- | --- | --- |
| D1 | **Coverage honesty.** Every IDE settings file the collector recognizes is bound by a digest, now including `.cursor/cli.json`, the Antigravity, xAI and Copilot files and `.codex/config.toml` as a whole (these are digested after redaction, so their digests cannot confirm a guess of a value the redaction removes, such as a token, and without the binding key a change only to such a value does not alert; with the key an HMAC covers every value as read); unassigned default-ignorable code points are hidden-character findings and are neutralized in output; Hugging Face chat templates get the template-escape check GGUF templates get; nested `GEMINI.md` and `.cursorrules` files are collected; agent files inside default-excluded directory names, JavaScript-family MCP servers, namespace and `require` imports, dynamic imports with literal module names and servers that application code starts or reaches through the SDK and framework classes the collector knows are inventoried or reported as coverage gaps | the 0.1.0 limitations on default exclusions inside agent directories and on JavaScript-family, namespace-import and `require` MCP servers; G fixes 1–3; c R3.d–f; audit related mediums | [known limitations](docs/known-limitations.md), [TypeScript inventory](docs/typescript-inventory.md), [source binding](docs/verification-source-binding.md) |
| D2 | **Reproducible inventories.** On top of ARCH-F1 (#132 on `main`), which makes native JSON and CycloneDX byte-identical by default by recording no collection time, sorting components and dependencies and deriving the serial number from the content: a published content digest (`nexus-symbiote/inventory-content/v1`, with known-answer vectors) that is equal for equal content whenever and wherever it was collected and that `digest` prints beside the file digest and the canonical digest signed runtime snapshots bind; the serial number derived from that digest, so anyone can recompute it from the native file; and `SOURCE_DATE_EPOCH`, which makes `scan`, `baseline` and `import-shadowscan` record that instant as the collection time, so native JSON, CycloneDX and SPDX are byte-identical for identical input with a recorded time (SARIF when both scans run from the same place relative to the scanned directory) | the P1 acceptance test "same agent, same inputs, same build-time BOM hash"; c R2.d | [reproducible inventories](docs/reproducible-inventories.md) |
| D3 | **Inventory attestation.** `attest` signs an inventory (or any export) as a DSSE envelope carrying an in-toto Statement bound to the file's SHA-256 and, for native inventories, to its content digest, for a stated purpose (`generated` or `reviewed`); `verify-attestation` checks it against operator-held Ed25519 keys with a threshold, purpose, age and either byte or content matching. Offline | A gap 6; B Now 4; c R7.a; d P0 6; e fix 6 | [inventory attestation](docs/inventory-attestation.md) |
| D4 | **Runtime telemetry versus the inventory.** `trace-diff` reads OpenTelemetry traces the operator exported (GenAI and MCP semantic conventions, OTLP/JSON), never the content they may carry, and reports the tools, models, agents and MCP endpoints that the traces report but the inventory does not declare (exit 1), declarations that no span mentions (which does not show they went unused), and ambiguities; optional SARIF. Telemetry is recorded as `reported` evidence and never raises assurance | A gap 2 ("the diff is the product"); B Now 8; c R2.a–b; d P0 3; e fix 2 | [trace evidence](docs/trace-evidence.md) |
| D5 | **Framework crosswalk.** Every finding category has a SARIF rule; SARIF tags add MITRE ATLAS 2026.10, OWASP LLM Top 10 2026 and NIST AI RMF identifiers beside the existing CWE, OWASP LLM 2025 and OWASP Agentic ones; `crosswalk` reports findings per framework entry, including EU AI Act articles and ISO/IEC 42001 controls | A compliance table; B gap 10; c 7.2.c; d P1 2; e 4.4; G fix 16 | [framework crosswalk](docs/framework-crosswalk.md) |
| D6 | **G7 minimum-element coverage.** `minimum-elements` evaluates an inventory and its CycloneDX export against the 50 elements of the G7 "Software Bill of Materials for AI – Minimum Elements" (12 May 2026): present, missing, explicitly unknown, not applicable or needing producer input, with a field-level list of what to supply; coverage with its denominator, never a compliance verdict | A gap/requirement "G7 completeness"; B Now 6; c R10.b–c; d P0 7; e 4.3 | [minimum elements](docs/minimum-elements.md) |
| D7 | **Graph view and risk classes.** `graph` writes a self-contained, script-hashed `graph.html` (and a JSON model) of components, relationships, findings and the shortest recorded exposure paths from agents to components whose recorded evidence gives a code-exec, write-capable, exfil-capable or secret-access risk class, or that carry a high or critical finding; risk classes restate recorded evidence, not what a component does at run time, and components with none are shown as unclassified, never as safe | A gap 7 and DevEx graph; B Next 7; c R8.a, R8.d; d P1 7; e fix 7 | [graph view](docs/graph-view.md) |
| D8 | **Approve in SymBiote, reconcile in ShadowScan.** `export-inventory --format shadowscan-simple` writes ShadowScan's documented simple inventory list from a reviewed inventory, so the repository agent approved in SymBiote review becomes an approved agent in ShadowScan, bound only to the repository's root project (checked against ShadowScan 999bef1) | G fix 9 (P0) and move 2.a; A ShadowScan target state 5 | [ShadowScan inventory export](docs/shadowscan-inventory-export.md) |
| D9 | **Positioning.** The disambiguation line in `README.md` and `SECURITY.md`; this roadmap | A gap 1; B Now 1; c R13.a; d P0 1; e fix 1 | this page |
| D10 | **No gate failures for reasons no operator can act on.** The Python MCP source cap (a hidden, fixed 20,000 syntax nodes that the repository's own `registry.py` exceeded) is the operator limit `python-nodes`, and reaching it is a collection failure that names it; the helper analysis and the MCP origin-label scan run in linear time; another spelling of an instruction file the `prompt` collector reads at any depth, such as `pkg/claude.md`, is a collection failure, also beside the exact name; the registry collector records the project settings that redirect an inventoried npm or PyPI package to another registry or index, by origin only, with a low `registry_origin` finding and no package URL; `action.yml` says that its `scanners` input makes coverage partial. Symbolic links out of the project stay failures ([decisions](#decisions-and-non-goals)) | audit H5 residue, M4; the self-scan | [collection limits](docs/collection-limits.md), [registry collector](docs/registry-collector.md#registry-and-index-settings), [known limitations](docs/known-limitations.md) |

## Plan

Effort: S under a day, M days, L weeks, XL depends on other people or repositories. Every item keeps
the [principles](docs/security-model.md#design-principles): nothing executes what it inventories,
nothing reaches the network unless the operator asks, and an import or report never raises
assurance.

### Now — next release (after 0.2.0)

| # | Item | Why | Acceptance test | Effort |
| --- | --- | --- | --- | --- |
| N1 | **Require an attestation in the gates.** `validate` and `risk` accept `--require-attestation ENVELOPE` with operator-held keys and fail closed on a missing, altered, wrongly purposed or unsigned inventory; the GitHub Action gains an input for a reviewed-baseline attestation | "unsigned BOMs are rejected by default in verification mode" (A, B, c R7.b, d, e) | an unsigned or altered baseline fails `validate` under the CI policy; a signed one passes and its signer is printed | M |
| N2 | **Attest in the GitHub Action.** Optional `attest: true` input adding a pinned `actions/attest-build-provenance` step over the uploaded inventory and an `aibom-digest` output; document the caller permissions and `gh attestation verify` | G fix 17; B Now 4 | a third party verifies the Action's inventory with `gh attestation verify` | M |
| N3 | **ShadowScan bridge depth.** Map `framework-usage` and `agent-config` findings (projection profile v5), keep every other kind an explicit gap, and carry readable names when the report verifies under the operator signer policy. (The producer check is recorded in the inventory since SEC-F1, #132.) | G fixes 7–8; c R1.a, R1.c, R7.c | a ShadowScan code report from an agent-framework repository imports with no unmapped entries | M |
| N4 | **CycloneDX projection 3.** Remote MCP servers and A2A servers as `services` (endpoints, authentication); MCP launcher packages with their purl; model licenses and a minimal `modelCard` from local model-card front matter, as declared evidence; a `--spec-version 1.6` option with the vendored 1.6 schema; projection 2 kept for recovery | G fix 13; c R5.a, R6.a; G7 elements that only standard fields satisfy | a consumer using only cyclonedx-python-lib recovers MCP services and model licenses; both versions validate | L |
| N5 | **Operator VEX decisions.** `vex --decisions FILE` (operator-owned, outside the checkout) records `not_affected`, `exploitable`, `resolved` with justification, owner and expiry; `--advisories REPORT` links OSV results | G fix 15; c R8.e | an expired decision reverts to `in_triage` with a warning | M |
| N6 | **Autonomy vocabulary.** Accept ISO/IEC 22989 automation names in `agent.yaml`, export them, and publish one mapping table between SymBiote's L0–L4, ShadowScan's 0–5 and the ISO names (SPDX 3.1's `isoAutomationLevel` uses the ISO ladder) | G fix 12; G standards row (SPDX 3.1) | the table is tested against both enumerations | M |
| N7 | **Release and governance controls.** Apply the release-tag ruleset, which must now also protect the existing `v0.1.0` tag, and turn off administrator bypass on the `testpypi` and `pypi` environments (the publication preflight already refuses without them), and record the date; add the OpenSSF Scorecard badge (the workflow exists) and register for the Best Practices badge; publish the v0.1.0 audit and its remediation map under `docs/audits/` | G fix 18, move 5.a; c R11.c | `scripts/check_repository_controls.py --verify-bypass-actors` passes and is recorded | S |
| N8 | **Supported surface.** Decide which collectors, exports and runtime adapters 0.2.x supports and which stay experimental (open since 0.1.0) | single maintainer; the code grew 2.3 times since v0.1.0 | the decision is in `GOVERNANCE.md` and the README | S |
| N9 | **Verification regressions.** Add `model_drift` and `a2a_scope_drift` kinds (a flipped weight byte, a widened OAuth scope) to the security regression corpus, with negative controls, and map every remaining known limitation to a fixture | G move 5.d; c R3 acceptance, R12.a | the corpus fails if either alert disappears | M |
| N10 | **SARIF against the official schema** in tests, beside the structural validator | c correction to "already done"; audit M9 | an invalid document fails the suite | S |
| N12 | **Integrity that means what it says.** A re-hash of the checkout an inventory was just built from no longer counts as verified integrity; operator digest pins verify any model format, not only SafeTensors | audit M3 | an MCP-only repository does not move from UNKNOWN to PASS by adding an instruction file | M |

### Next — lead

| # | Item | Why | Acceptance test | Effort |
| --- | --- | --- | --- | --- |
| X1 | **Import any CycloneDX or SPDX BOM as declared evidence** (cdxgen, Syft, Cisco AI BOM, agent-bom, OWASP AIBOM Generator, k8s-aibom): source digest per document, per-entry digests, hashed names by default, claims bound to local artifacts only when digests match, and a `source_conflict` finding when sources disagree, never a winner | G move 3; c R4.a, R4.c; A, B, d, e (merge with SBOMs) | merging a cdxgen SBOM into the demo inventory yields a valid CycloneDX 1.7 document with every conflict listed, and a rerun gives the same content digest | L |
| X2 | **More runtime evidence for `trace-diff`.** k8s-aibom ML-BOMs and the reference gateway's decision records as further `reported` sources; a documented record schema for the gateway sink; the graph view overlays trace evidence | c R2.a, R2.c; G borrow 5 (in principled form); the P0 test's "graph shows the new edge" | an image running in a cluster that the reviewed inventory does not declare is reported | M |
| X3 | **Workload identity and delegation.** Declared SPIFFE IDs and delegation edges in `agent.yaml` and the deployment profile (validated against the SPIFFE ID format), an identity component type for OAuth grants and service identities imported from ShadowScan, blast radius over identities. Needs a native format minor version | A gap 5; d P0 5; e fix 5; c R1.b | `blast-radius` from a compromised tool lists the identities that can reach it | L |
| X4 | **Model integrity depth.** Opcode-level analysis of pickle-family files against an allow-list of safe globals, without loading; OpenSSF Model Signing (DSSE bundle) verification under the operator signer policy | A gap 8; c R7.d; e fix 8 | a pickle that imports `os.system` is reported with the opcode evidence; an OMS-signed model verifies offline | L |
| X5 | **Memory, retrieval and guardrail provenance.** Guardrail configuration digests (the `config_hash` field exists unused), memory store declarations, dataset → embedding → index lineage from declared configuration | A gap 4; c gap 4; e fix 4 | a changed guardrail policy file is a high drift alert | L |
| X6 | **Vulnerability prioritization.** EPSS and KEV for advisories found in live mode, joined into `risk`, SARIF and VEX | c R8.b | a KEV-listed package raises the finding's severity with its source named | M |
| X7 | **Consumer interoperability.** Scheduled, report-only jobs that load the demo exports into a pinned Dependency-Track and GUAC, and validate the SPDX export against the SPDX SHACL shapes | B Now 9; c R6.b; G move 4.d | the jobs record the tested versions in the docs | M |
| X8 | **SPDX AI and Dataset profiles** once N4 and X1 supply the mandatory fields; never fill a field with a placeholder | G fix 14; c R5.c | the export claims the profiles and passes SHACL | M |
| X9 | **Per-component evidence profile** in the JSON views and the graph: which evidence each component has (pinned, digest-bound, signed under policy, observed by a collector, reported at run time, findings), instead of a single trust score | A and e TrustScore (see [decisions](#decisions-and-non-goals)) | every component shows the evidence it lacks | M |
| X10 | **External policy engines.** Document and test the JSON contract (`risk --json-output`, the native inventory, the crosswalk report) that OPA or Cedar policies consume, with example policies for the default denials the reviews list | A, B, c R9, d, e (policy language) | the example policies pass and fail their fixtures in CI | M |

### Later — stay best

| # | Item | Depends on |
| --- | --- | --- |
| L1 | CycloneDX 2.0 mapping (agents as parties, declared and observed behaviors) once Ecma ratifies the standard | the standard |
| L2 | Offer the SPDX mapping to the OWASP Agent Observability Standard (AgBOM), whose SPDX extension is unowned | other people |
| L3 | Independent review of a tagged release; a second maintainer; schema 1.0 with a deprecation policy and a cross-release compatibility suite | other people |
| L4 | A pre-registered, third-party benchmark round on public repositories, with every tool run in its supported mode | other people |
| L5 | Training-time provenance: consume in-toto, SLSA and dataset attestations as declared evidence | X1 |
| L6 | A documented Windows decision; the full macOS suite in Verified CI | — |
| L7 | An MCP server mode so coding assistants can query an approved inventory | N8 |

## Acceptance tests

The reviews' acceptance tests, restated so that they can pass or fail:

| Test | Status |
| --- | --- |
| **P0.** An agent calls an MCP tool its repository does not declare. The static scan does not contain it; the agent's exported traces reach `trace-diff`, which reports the tool as undeclared and exits 1; CI fails; the SARIF result carries the crosswalk tags. | Delivered (D4, D5), with the [walk-through](docs/trace-evidence.md). The reviews' "graph shows the new edge" needs the graph to read trace evidence (X2). |
| **P1.** Same agent, same inputs: same build-time inventory hash; the runtime evidence shows only the delta, each item tagged with its evidence source. | Delivered (ARCH-F1 on `main`, D2, D4): byte-identical native JSON and CycloneDX by default, SPDX too with `SOURCE_DATE_EPOCH`, and an equal content digest and serial number whatever time is recorded; trace evidence is a separate `reported` document that lists undeclared and unobserved items apart from matched ones. |
| **P2.** An independent evaluator reruns the published benchmark and reproduces its numbers; two external reviewers have reviewed the security model; three or more maintainers. | Open (L3, L4). |
| An unsigned or altered baseline fails the CI gate; a signed one passes and names its signer. | Partly delivered: D3 verifies; N1 puts it in the gates. |
| Every known limitation in `SECURITY.md` has a regression fixture, and the list shrinks to items reported as gaps. | Partly delivered (D1); the fixture mapping is part of N9. |
| A new user produces a signed, validated inventory and graph for a public agent in under five minutes. | Partly delivered: each step works on the demo agent (`validate` with the README's signer policy, D3, D7), but no guide runs them end to end and nothing has timed it; the public-agent tutorial follows with N8. |

## Scorecard

What "first in this lane" means, as measures anyone can check. Values are at the head of this change.

| Measure | Target | Now |
| --- | --- | --- |
| Coverage honesty | No documented surface passes every gate without a gap | D1 closed the bypasses reproduced at 3ad53a2 that [where it stands](#where-it-stands) lists, #131 the shell startup-code bypasses and D10 the audit residue; the remaining exceptions are listed in [known limitations](docs/known-limitations.md) |
| Evidence grading | Every component and claim carries its assurance and a locator | Met for collected components; telemetry is a separate `reported` document |
| Reproducibility | Identical input gives byte-identical output | Met by default for native JSON and CycloneDX (ARCH-F1, #132); with `SOURCE_DATE_EPOCH`, also for SPDX, whose schema requires a creation time; for SARIF when both scans run from the same place relative to the scanned directory; equal content digest and serial number whatever time is recorded (D2) |
| Integrity | Every exported inventory can be signed and verified offline, one command each | Met (D3); gate enforcement is N1. Offline Sigstore verification checks the trust root it uses (SEC-C1, #132) |
| Standards fidelity | CycloneDX and SPDX exports validate with the official schemas and load in Dependency-Track with properties intact | Schemas met; Dependency-Track untested (X7) |
| Completeness | G7 minimum-element coverage reported for every inventory, with the missing fields | Met (D6) |
| Runtime truth | Declared versus reported use, gated in CI | Met for OpenTelemetry GenAI and MCP traces (D4); more sources in X2 |
| Framework mapping | Every finding mapped, where defensible, to OWASP (LLM 2025 and 2026, Agentic), MITRE ATLAS, NIST AI RMF, EU AI Act and ISO/IEC 42001 | Met (D5) |
| Time to first inventory | Under five minutes from install on Linux and macOS | 4.6 s scan on Linux; macOS smoke only (L6) |
| Governance | Two or more maintainers; externally reviewed security model; schema 1.0 | One maintainer; no external review (L3) |

## Decisions and non-goals

| Recommendation | Decision | Why |
| --- | --- | --- |
| `observe --agent ./my_agent.py` runs the agent and captures its runtime BOM | **Replaced by `trace-diff`** | SymBiote never executes what it inventories; the operator's own telemetry, read offline, gives the declared-versus-actual comparison without that risk |
| Import telemetry, k8s-aibom or other reports as `observed` evidence | **Declined; recorded as `reported`** | `observed` means a SymBiote collector measured bytes ([security model](docs/security-model.md)); runtime metadata emitted by the agent has a different trust basis, and an import never raises assurance |
| A 0–100 TrustScore ("100 only if signed, scanned, pinned and observed"; "unsigned scores 0") | **Replaced by risk classes and an evidence profile (D7, X9)** | a single high number reads as "trustworthy", which no inventory can establish (a stated non-goal); evidence per component is actionable without that implication |
| OPA or Cedar embedded in the tool | **Declined; a documented JSON contract instead (X10)** | a second policy runtime in the trusted path is attack surface; external engines already consume JSON |
| An `nsb` console alias | **Declined** | `nsb` is an unrelated distribution on PyPI; a second command name would collide on `PATH` and split documentation |
| Emit AgentBOM 0.1 so ShadowScan can read it | **Declined; ShadowScan's simple list instead (D8)** | AgentBOM 0.1 is the retired experimental format described below |
| In-process ShadowScan as a `[discovery]` extra | **Declined** | its dependencies would enter the hash locks, and discovery runs best as a separate least-privilege process |
| Optional LLM classification | **Not planned** | deterministic collectors are the trusted path; if ever added, advisory only and never changing a finding or a gate |
| eBPF capture | **Not planned here** | privileged and host-specific; exported telemetry covers the declared-versus-actual comparison |
| A private registry proxy with typosquat detection | **Out of scope** | a network service, not an inventory; typosquat heuristics would add false positives to a fail-closed gate |
| Envelope encryption of inventories | **Not planned** | inventories carry no secret values (names only; known secret patterns redacted); encryption at rest is a storage concern |
| The broadest scanner, a CVE database, a production MCP firewall | **Non-goals** | other projects do these well; SymBiote imports their output (X1) and publishes the contract gateways enforce ([runtime contract reference](docs/runtime-contract-reference.md)) |
| Claiming that an inventory or a low score proves an agent or model benign | **Non-goal** | absence of evidence is unknown, not safe |
| Default execution of project code, MCP launchers or model loaders | **Non-goal** | `verify-live` is the only explicit, operator-pinned exception |
| Stop failing the walking collectors on a symbolic link out of the project that none of them would read (audit residue) | **Declined; confinement unchanged** | a link's name cannot show whether it names a directory, and all six walking collectors read names at any depth below directories of any name; finding out would mean examining a path outside the project chosen by the checkout, and the answer would hold only on the scanning machine, not on the one that later opens the checkout. Replace the link with the file or a relative link inside the project ([known limitations](docs/known-limitations.md#every-collector)) |

**Historical experimental work.** The [closed-PR audit](docs/audits/closed-pr-review-2026-11-02.md)
records what reached the supported package and what remains separate. The experimental foundation's
salted Merkle disclosure protocol, full snapshot chain format, OPA/Rego export and parity suite, and
Kubernetes/trace import contracts are not supported interfaces on `main`. Evaluate any future port
against the current threat model and version its wire format; a merge into an experimental branch
does not establish shipped compatibility. Discovery expansion continues through Nexus-ShadowScan.

## Corrections to the reviews

Statements in the reviews that were wrong or had become stale by 12 November 2026, with what is true.

| Statement | Correction |
| --- | --- |
| "OWASP LLM Top 10 2025" as the current edition; LLM03 is Supply Chain | The 2026 edition was published on 4 August 2026 and renumbered the list (LLM03:2026 Excessive Agency, LLM04:2026 Supply Chain). Identifiers are meaningful only with their edition; SymBiote now tags both. |
| "50 G7 elements" could not be confirmed, or "roughly 50" | Exactly 50 elements in 7 clusters (10/9/13/10/2/4/2), non-binding, with no official identifiers and no required or optional tiers. Report coverage, not compliance. |
| "No CI gate, no SARIF, no pre-commit hook, no pickle detection, no self-validation" | All existed at v0.1.0 (SARIF validation is structural, not the official schema). |
| "Sigstore is only an optional extra; signing must become the default path" | Sigstore *verification* of model files and ShadowScan reports exists under an operator signer policy, and since #132 unverified ShadowScan discovery evidence fails in CI unless explicitly allowed (SEC-F1); inventory signing did not exist (D3 adds it; enforcing it in the gates is N1). |
| Claude hooks, deny rules, subagents, skill scripts, nested instruction files, `.vscode/mcp.json` are not read | Read or digest-bound since 3ad53a2; the reproduced residue (marker files, Codex keys, JavaScript-family servers, excluded directory names) is D1. |
| "Fixed list of hidden characters, instruction files only" | Every format character (Unicode category Cf) on every text file the prompt collector reads; the unassigned default-ignorable ranges were the remaining hole (D1). |
| "No GGUF template-injection assignment" | Assigned since 3ad53a2; Hugging Face chat templates were the remaining hole (D1). |
| "SymBiote 0.1.0 writes AIBOM 1.0.0; ShadowScan reads AgentBOM 0.1" | `main` writes format 1.1.0, which ShadowScan also refuses; ShadowScan additionally reads Capability Cards, a simple list and CSV, and the simple list is the target (D8). |
| "Symbiote records only what a repository declares" | `discover-mcp --record` and `verify-live --record` already record live MCP observations with observed assurance. |
| "The reference gateway should start writing observation records" | It already emits a decision record for every admitted or denied call (`on_decision`); a built-in sink is X2. |
| "Unpinned `latest` fails CI" | It raises a high finding; the built-in gate fails on critical findings, so it passes unless the policy lowers the cutoff. |
| "Capability classes inferred for MCP servers" | Only for tools listed in a configuration's `tools` array, a SymBiote convention; D7's risk classes say "unclassified" where no evidence exists. |
| "Freeze the schema at 1.0" | The native format is already 1.1.0; schema 1.0 is the stability label to aim for (L3), with a migration path from formats 1.0 and 1.1. |
| "Cisco AI BOM's LLM classification is optional" | Its `analyze` step requires an LLM since 1.0.0; `watch` is deterministic. |
| "k8s-aibom v1.2 / 1.7.0, a three-tier confidence model, immutable CRDs" | v1.6.2 (v1.7 planned for 24 November 2026); confidence values declared, verified, inferred and unresolved, each with an evidence locator; write-once objects in its storage sink. |
| "cdxgen 13.8.0 released" | 13.7.0 (7 November 2026) is the latest release; 13.8.0 is the development branch. |
| "agent-bom emits its own JSON; v0.108; 11 frameworks" | 0.114.0 (8 November 2026) exports CycloneDX 1.7, SPDX 3.0.1, SARIF, JSON and HTML; canonical repository koda-ai-studio/agent-bom. |
| "Runtime observation: nobody ships it" | k8s-aibom inventories running Kubernetes workloads and agent-bom proxies MCP traffic. SymBiote's addition is the declared-versus-reported comparison against a verified inventory. |
| "eBPF malware" (in the disambiguation line) | Unnecessary detail with an inaccurate label; "the Linux malware of the same name" is accurate. |
| Rankings (#1 on coverage; 3rd, 4th, 5th, 8th, 9th of 11 or 12) and head-to-head benchmark numbers | Dropped: they contradicted each other, were judgments rather than measurements, or compared tools run below their supported mode. L4 replaces them with a reproducible round. |
| "SymBiote itself has not been benchmarked" | Two self-authored regression corpora have run in CI since v0.1.0, with 18 security and 10 inventory cases then and 22 security cases now; what is missing is a comparative, third-party round. |

## Landscape

Dated facts, read from each project's own repository or registry entry on 12 November 2026. Counts
move between releases; read them as "per its README on that date".

| Tool | What it is good at | Relation to SymBiote |
| --- | --- | --- |
| [cdxgen](https://github.com/cdxgen/cdxgen) 13.7.0 (OWASP) | Polyglot SBOMs; CycloneDX 1.7 by default, 1.6 and draft 2.0 by option; SPDX 3.0.1; AI-BOM coverage of MCP configs, skills, Hugging Face model cards and formulation; JSF signing; `cdx-validate --benchmark cisa-ai` for the G7 elements | Import its SBOMs (X1); match its standard fields (N4) |
| [Cisco AI BOM](https://github.com/cisco-ai-defense/aibom) 1.10.1 | 23 scanners, 30 component types, seven languages (structural scanners Python-only); CycloneDX 1.6, SPDX 3.0 AI and Dataset, SARIF; `analyze` requires an LLM | Import as declared evidence (X1); keep the deterministic trusted path |
| [agent-bom](https://github.com/koda-ai-studio/agent-bom) 0.114.0 | Exposure graph, CVE context (OSV, GHSA, NVD, EPSS, KEV), MCP proxy and gateway; CycloneDX 1.7, SPDX 3.0.1, SARIF | Gateways can enforce SymBiote's signed contract; EPSS and KEV in X6 |
| [k8s-aibom](https://github.com/GoogleCloudPlatform/k8s-aibom) v1.6.2 (Google Cloud) | Runtime ML-BOMs of Kubernetes workloads with per-attribute confidence and evidence locators | A further `reported` source for `trace-diff` (X2) |
| [Trusera ai-bom](https://github.com/Trusera/ai-bom) 3.6.0 | 13 scanners, 25+ SDKs, n8n workflows, a Cedar gate; last release March 2026 | Import as declared evidence (X1) |
| [OWASP AIBOM Generator](https://github.com/GenAI-Security-Project/aibom-generator) | Hugging Face model card to CycloneDX 1.6 with a completeness score | Link its model AIBOMs (N4, X1) |
| [AIsbom](https://github.com/Lab700xOrg/aisbom) 1.7.0 | Static analysis of Pickle, Keras, GGUF, ONNX and SafeTensors files | Opcode-level depth in X4 |
| [model-signing](https://github.com/sigstore/model-transparency) 1.1.1 | OpenSSF Model Signing, stable since 1.0.0 (April 2025) | Verification in X4 |
| [Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) 0.1.4 | Nine discovery surfaces, 38 connectors, reconciliation against an approved inventory | Discovery engine; D8 and N3 deepen the bridge |
| [Dependency-Track](https://dependencytrack.org/) | CycloneDX-native store with policies; accepts CycloneDX 1.7 from 4.14.4 and 5.1.0 | Destination; ingestion tests in X7 |

Standards to track: CycloneDX 2.0 (draft; agents as parties with declared and observed behaviors),
SPDX 3.1 (development draft; `isoAutomationLevel`), the OWASP Agent Observability Standard (AgBOM),
the OpenTelemetry GenAI and MCP semantic conventions (now in
[their own repository](https://github.com/open-telemetry/semantic-conventions-genai), all at
Development stability), MITRE ATLAS (release 2026.10 renamed several techniques), and the G7 minimum
elements.

## Risks and watch items

- **One maintainer.** Every privilege has no backup (`MAINTAINERS.md`). The 24-hour soak and the review
  record compensate only partly; L3 is the fix.
- **Scope growth.** The code grew 2.3 times between v0.1.0 and 3ad53a2, and this change adds more. N8
  decides what is supported; each new importer is new hostile-input parsing.
- **Convergence.** Microsoft's Agent Governance Toolkit ships a discover, inventory, reconcile and
  govern loop; cdxgen ships agent and MCP coverage and draft CycloneDX 2.0. SymBiote's answer is
  evidence quality and verification, not breadth.
- **Standards drift.** Agent semantics in CycloneDX and SPDX are unsettled; the native format and the
  digest-bound extension carry them until L1 and L2.
- **Telemetry is self-reported.** `trace-diff` can show undeclared use; it cannot prove absence, and
  an agent that controls its own instrumentation can hide activity. The documentation says so.

## Traceability

Every recommendation in the seven reviews, by theme, with its status after this change. Review keys:
A "Road to #1", B "Competitive Review and Path to #1", c "The path to #1", d "SymBiote Path to #1",
e "Blueprint to Undisputed #1", G "Fixes, moves and roadmap", audit "end-to-end audit of v0.1.0".

| Theme | Recommendations | Status | Roadmap |
| --- | --- | --- | --- |
| Name collision | A gap 1; B gap 1; c gap 1, R13.a; d P0 1; e fix 1 | Done (one name everywhere; disambiguation line added); `nsb` declined | D9 |
| Static only / runtime layer | A gap 2, Layer 2; B gap 2, Now 8; c gap 2, R2; d P0 3; e fix 2 | Done for exported telemetry; more sources next | D4, X2 |
| Reproducibility | A ALOHA row; B 7.1 determinism; c R2.d; e P1 test | Done (ARCH-F1 on `main`, #132; content digest, recomputable serial and `SOURCE_DATE_EPOCH` here) | D2 |
| Tool permission model and risk classes | A gap 3; B gap 3, Now 5; c gap 3, R8.a; d P0 4; e fix 3 | Risk classes done; per-tool egress has no source in a repository | D7, X9 |
| Data, memory, RAG and guardrail provenance | A gap 4; B Next 1; c gap 4; d P1 1; e fix 4 | Open | X5 |
| Identity and delegation graph | A gap 5; B Next 2; c gap 5, R1.b; d P0 5; e fix 5 | Open (needs a format minor version) | X3 |
| Verifiable BOM | A gap 6; B gap 6, Now 4; c gap 6, R7.a–b; d P0 6; e fix 6; G fix 17 | Signing and verification done; gate and Action next | D3, N1, N2 |
| Enforcement, policy language, graph | A gap 7; B gap 7, Next 6–7; c gap 7, R8.d, R9; d P0 9, P1 6–7; e fix 7 | Graph done; default denials exist as findings and gates; external engines next | D7, X10 |
| Model security | A gap 8; B gap 8, Next 5; c gap 8, R7.d; d P1 5; e fix 8; G borrow 2 | Pickle and loaders critical, GGUF and HF templates checked; opcode depth and OMS next | D1, X4 |
| Hardening and offline | A gap 9; e fix 8; c 7.2.d | Done (offline default, redaction); envelope encryption declined | — |
| Maturity and governance | A gap 10; B gaps 11–12; c R11–R12; d P2 5; G move 5 | Open; depends on people | N7, N8, L3, L4 |
| Coverage honesty | G fixes 1–3, move 1; c R3; audit H1–H5 and related mediums | Done for the bypasses reproduced at 3ad53a2, the shell startup-code bypasses (#131 on `main`) and the audit residue; out-of-project links stay failures by decision; remaining limits documented | D1, D10 |
| ShadowScan bridge | A integration 1–5; B Now 2; c R1; d discovery row; G fixes 7–12, move 2 | Inventory export done; producer verification recorded and unsigned discovery failing in CI (SEC-F1, #132 on `main`); kind mapping, names and autonomy next | D8, N3, N6 |
| Compliance crosswalk | A table; B gap 10; c 7.2.c; d P1 2; e 4.4; G fix 16 | Done | D5 |
| G7 minimum elements | A; B; c R10; d; e; G standards row | Coverage report done; standard fields that would satisfy more elements in N4 | D6, N4 |
| Standard fields (services, modelCard, SPDX AI, CycloneDX 1.6) | A data model; B 7.1; c R5–R6; d P0 8; e 4.1; G fixes 13–14 | Open | N4, X8 |
| VEX states | c R8.e; G fix 15 | Open | N5 |
| CVE context | B Next; c R8.b; d P1 3 | OSV lookups exist; EPSS and KEV next | X6 |
| BOM import and SBOM merge | A AIBoMGen row; B 7.3; c R4; d; e; G move 3 | Open | X1 |
| Dependency-Track and GUAC | B Now 9; c R6.b; G borrow 7 | Open | X7 |
| Breadth (containers, IaC, workflows, frameworks) | A Layer 1; B gap 9; c gap 13; d P1 4; e P1 | Through ShadowScan and imports, not new collectors | N3, X1 |
| Platforms | B gap 11; G fix 19 | macOS smoke only | L6 |
| Developer experience (one command, graph, quickstart) | A DevEx; B 7.4; c R13; d P0 10; e 5 | Graph and digest done; one-command tutorial with N8 | D2, D7, N8 |
| Audit order of work (19 items) | audit section 5 | See the audit status note below | — |

**Audit status.** Every item of the v0.1.0 audit's main body and order of work (52 in all) was
re-checked at 3ad53a2, most by running the tool: 29 done, 22 partial, 1 open. All high findings
(H1–H7) are fixed and were reproduced as fixed, as were M1, M2, M6 and M8 and the demo numbers;
the audit's three section-6 checks now give: the two-path scans compare clean, the README
quickstart matches exactly, and the self-scan still fails, correctly, on the deliberately hostile
regression fixtures. Since then D10 closed the residue on the Python MCP source-size cap, nested
case variants, registry redirects and the `scanners` input note in `action.yml`, and out-of-scope
symlinks stay failures by [decision](#decisions-and-non-goals). The rest maps to this roadmap:
integrity semantics for non-SafeTensors pins and self-re-hashes (N12), operator-side suppressions
and signed baselines (N1), SARIF schema validation (N10), a library scan pipeline with typed
coverage records (N8), and the second maintainer (L3). The P0 findings of the separate audit that
#132 names (SEC-F1, SEC-C1, ARCH-F1, DOC-F3/F7), the shell startup-code bypasses #131 closes and
the fixes of #133 to #137 are closed on `main` and merged here.
