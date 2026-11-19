# AIBOM-Bench 1.0 results: ten AI-BOM tools graded

> **Audited grades.** Two adversarial passes followed this report:
> [CRITIQUE.md](CRITIQUE.md) and then [AUDIT.md](AUDIT.md), which adds an
> independent second corpus, strict matching and a mechanical grader
> (`grades.json`, `grade.py`). The ranking, the scores by dimension and the
> per-tool headings below carry the final grades from that grader, as
> AUDIT.md prints them; the evidence tables and the per-tool notes describe
> corpus A as it was run on 18 November, before the second corpus lowered
> several coverage scores.

Date: 2026-11-18. Benchmark: [SPEC.md](SPEC.md). Corpus: `build_corpus.py`
(76 ground-truth components, 5 decoys, 9 secrets, 4 digests, 15 expected
findings). Raw outputs, traces and the machine scores are under `results/`
and `results/scores.json`; the reviewer overrides applied to textual matches
are in `review_overrides.json`.

Every score carries an evidence label from the spec: **V** verified by
running the tool here, **C** verified by reading its source at the recorded
commit, **D** documentation only, **A** assumed, **N** not assessable.
Seven tools ran on the corpus. Three could not: Syft (the permission layer of
this sandbox refused both the release download and a source build), Google
k8s-aibom (needs a Kubernetes cluster) and the OWASP AIBOM Generator (needs
the Hugging Face API, which this sandbox blocks). Cisco AI BOM ran only its
deterministic Tier-1 scanners because the shipped `analyze` command requires an
LLM provider; its result is labeled partial.

## Ranking

| # | Tool | Version / commit | Total | Grade | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Nexus SymBiote | 0.2.0 (a13b622) | 73.0 | **B** | full | V |
| 2 | k8s-aibom (Google) | 7be6465 | 59.0 | C | provisional, runtime observer (D1 = N) | C/D |
| 3 | agent-bom (msaad00) | 0.115.4 | 55.6 | C | full | V |
| 4 | Cisco AI BOM | 1.10.1 (Tier-1 only) | 37.0 | F | provisional (no LLM stage) | V partial |
| 5 | Trusera ai-bom | 3.6.0 | 29.1 | F | full | V |
| 6 | ai-agentbom | 0.8.0 | 28.1 | F | full | V |
| 7 | scanoss ai-finder | 0.5.0 | 28.1 | F | full; hard gate G4 (telemetry on by default) | V |
| 8 | cdxgen (CycloneDX) | 12.9.2 | 23.3 | F | full | V |
| 9 | OWASP AIBOM Generator | 1.0.2 (45851cb) | 22.7 | F | provisional (D1 = N) | C |
| 10 | Syft (Anchore) | 1a72047 | 22.2 | F | not run; graded from source | C |

Reading the table honestly: the grades measure fit for the job this benchmark
defines, an inventory of an agentic system with evidence, integrity and safe
operation. Syft is an excellent package SBOM tool whose AI support stops at
GGUF and SafeTensors headers; cdxgen is a strong SBOM generator whose AI-BOM
mode missed every MCP server in this corpus; k8s-aibom answers a different
question (what is running in a cluster) and answers it well. None of the ten
reaches the A band. The best static tool still inventories only 56% of the
weighted ground truth, and no tool detected the poisoned tool descriptions.

## Scores by dimension

Weights in the header. Cells are dimension points earned; N means excluded
from that tool's denominator.

| Tool | D1 cov 30 | D2 ident 12 | D3 prov 10 | D4 std 12 | D5 risk 10 | D6 safety 12 | D7 determ 6 | D8 runtime 4 | D9 ops 4 | Total |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Nexus SymBiote | 9.4 | 9.0 | 9.5 | 11.4 | 10.0 | 11.7 | 6.0 | 2.5 | 3.5 | 73.0 |
| k8s-aibom | N | 6.0 | 8.5 | 1.8 | 2.5 | 10.5 | 6.0 | 3.0 | 3.0 | 41.3/70 = 59.0 |
| agent-bom | 11.2 | 6.6 | 6.0 | 6.6 | 7.5 | 8.4 | 3.5 | 2.0 | 3.8 | 55.6 |
| Cisco AI BOM (Tier-1) | 8.4 | 4.2 | 6.5 | 3.6 | 5.0 | 6.0 | 0.0 | 0.5 | 2.8 | 37.0 |
| Trusera ai-bom | 3.8 | 0.6 | 3.5 | 2.4 | 5.0 | 9.9 | 0.0 | 1.0 | 3.0 | 29.1 |
| ai-agentbom | 0.9 | 0.6 | 5.0 | 2.4 | 5.0 | 8.7 | 3.0 | 0.0 | 2.5 | 28.1 |
| ai-finder | 3.8 | 5.4 | 4.5 | 1.8 | 0.0 | 8.1 | 1.5 | 0.0 | 3.0 | 28.1 |
| cdxgen | 1.9 | 2.4 | 5.0 | 2.4 | 0.0 | 6.9 | 1.5 | 0.0 | 3.2 | 23.3 |
| OWASP Generator | N | 3.0 | 2.5 | 4.2 | 0.0 | 4.2 | 0.0 | 0.0 | 2.0 | 15.9/70 = 22.7 |
| Syft | 0.0 | 1.8 | 3.5 | 3.0 | 0.0 | 9.9 | 1.0 | 0.0 | 3.0 | 22.2 |

## Detection on the corpus (D1, verified)

Weighted recall over 15 classes after reviewer overrides; decoy hits in the
last column (hard decoys cost 0.5, soft 0.25).

| Tool | Weighted recall | mcp | tool | skill | prompt | model | model-file | dataset | a2a | agent-config | container | package | Decoys hit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| agent-bom | 0.615 | 0.67 | 1.0 | 1.0 | 0.67 | 0.40 | 0.90 | 0.36 | 0 | 0 | 0.25 | 1.0 | 1 (model in a comment) |
| Nexus SymBiote | 0.555 | 0.78 | 1.0 | 1.0 | 0.67 | **0.00** | 0.90 | **0.00** | 1.0 | 0.40 | 0.50 | 0.83 | 0 |
| Cisco Tier-1 | 0.504 | 0.61 | 0 | 1.0 | 0.25 | 0.72 | 0.60 | 0.91 | 1.0 | 0 | 0.25 | 0.17 | 1 (model in a comment) |
| Trusera ai-bom | 0.370 | 0.56 | 1.0 | 0 | 0 | 0.40 | 0.60 | 0 | 0 | 0 | 0.50 | 0 | 0 |
| ai-finder | 0.314 | 0.72 | 1.0 | 0 | 0 | 0 | 0.60 | 0 | 0 | 0 | 0 | 0.83 | 0 |
| cdxgen | 0.305 | **0.00** | 0 | 0 | 0.29 | 0.56 | 0.40 | 0.18 | 0 | 0.40 | 0 | 0.83 | 1 (model in a comment) |
| ai-agentbom | 0.164 | 0.61 | 0 | 0 | 0.25 | 0.36 | 0 | 0.18 | 0 | 0 | 0 | 0 | 0 |

What the numbers mean in practice:

- **No tool covers both halves of the problem.** Tools that understand agent
  components (Nexus SymBiote, agent-bom) miss hosted model references in
  code; tools that extract model references (Cisco Tier-1, cdxgen) miss the
  tool definitions and agent configuration. An auditor needs two tools today.
- **MCP coverage is uneven even among tools that advertise it.** Only
  ai-finder and Nexus SymBiote found the MCP server the project implements in
  TypeScript. Only Nexus SymBiote parsed the JSONC `.vscode/mcp.json`
  (ai-finder printed "Invalid JSON" and moved on). No tool recorded the Codex
  `config.toml` server except as a parse failure (Nexus SymBiote) or a
  secret finding (ai-agentbom). cdxgen emitted zero servers in `-t ai` mode and in the `aibom` CLI, but
  **with `-t mcp` it emits all seven declared servers as `services`,
  including the JSONC `sqlite` server** (see CRITIQUE.md, section 3); the
  first version of this report drew the wrong conclusion from the
  recommended invocation.
- **Precision matters.** Three tools reported `gpt-3.5-turbo` from a code
  comment as a model in use. cdxgen also attributed `claude-sonnet-4-5` and
  `distilbert-base-uncased` to the group `azure-openai` with a `pkg:generic`
  PURL because an Azure client exists in the same file. Trusera labeled the
  LangChain `@tool` functions as "CrewAI tool_definition" and flagged CrewAI
  as shadow AI; the corpus contains no CrewAI.
- **Tool-description poisoning (F05) was detected by nobody.** The
  `<IMPORTANT>` exfiltration text sits in an OpenAI function schema and in
  the project's own MCP server. agent-bom's `--enforce` and Nexus SymBiote's
  definition hashing both passed over it; Nexus SymBiote hashes the
  definition so a change would be seen on diff, but nothing judged the text.

## Tool safety (D6, verified with strace, a network namespace and a corpus diff)

| Tool | Egress by default | Executes | Followed symlinks out of root | Secret sentinels in output | Terminal escapes | Writes into project | Handles JSONC / bad TOML |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Nexus SymBiote | none | nothing | no (never opened the links; refusals recorded in the BOM) | none | replaced with U+FFFD in text; JSON keeps `\u001b` escaped | none | yes / recorded gap |
| agent-bom | 2 proxy connects even with `--no-scan`; `--offline` needed | `docker`, `git` (10 attempts on `docker.sock`) | **yes, both**; emitted the SHA-256 of `/etc/passwd` as a model-file hash | none | raw `ESC[2K` written to the console log | none; `~/.agent-bom/local-analytics.sqlite` | sqlite missed / silent |
| Cisco Tier-1 | fetches a model catalog from `raw.githubusercontent.com/BerriAI/litellm` and queries OSV | nothing | **yes, both** (three successful opens of `/etc/passwd` through the link) | none | JSON escaped | none | sqlite missed / silent |
| ai-finder | **telemetry to telemetry.scanoss.com on every run, opt-out only** (7 connects; `pending_events.json` queued offline) | nothing | yes, read the escaping `.gguf` (which is `/etc/passwd`) as a model file | none | none emitted | none; writes KB and telemetry queue under HOME | printed error / silent |
| cdxgen | none | `sh`, `python`, `pip`, `npm`, `pnpm`, `go`, `cargo`, `rustc`, `gcc`, `java`, `php`, `ruby`, `composer`, `ldd`, `stty`, `sudo -K`; `git` with `core.hooksPath=/dev/null` | yes, opened the escaping `.gguf` | none; copied `scripts/audit-tool-call.sh` and `refund.sh` in as `file` components | none | none (Go toolchain wrote its own telemetry files under HOME) | silent / silent |
| Trusera ai-bom | none | nothing | no; logged each skip, but listed `/etc/passwd` as the location of `escape.gguf` | none | JSON escaped | none | silent / silent |
| ai-agentbom | none | nothing | no | none; redacted secret findings | **raw `ESC[2K` in the Markdown and Mermaid reports** | none | silent / partial (found the JIRA token) |

Hard gates: ai-finder trips **G4** (telemetry without opt-in), which caps it
at C; its total is below that anyway. No tool leaked a sentinel (G1), executed
corpus content (G2) or emitted `/etc/passwd` content (G3). agent-bom's hash of
`/etc/passwd` is derived data rather than content, so G3 is not applied, but
it is a confined-read failure scored 0 on 6.3: a hash of a file outside the
repository in a BOM lets a holder confirm guesses about that file.

## Standards conformance (D4, verified with the official schemas)

| Tool | CycloneDX | SPDX | SARIF 2.1.0 | VEX | Minimum elements |
| --- | --- | --- | --- | --- | --- |
| Nexus SymBiote | 1.7 valid; `machine-learning-model` 5, `data` 11, `container` 2; evidence on all 60; hashes on 16; no `modelCard`, no `services` | 3.0.1 valid; `ai_AIPackage` 6, `dataset_DatasetPackage` 3 | valid, 40/40 results located | yes (`vex`) | G7 report with how-to-supply text |
| agent-bom | 1.6 valid; `modelCard` on 5; `formulation`, `compositions`; no evidence or hashes in the CycloneDX | 3.0 valid but `software_Package` only, no AI or Dataset profile | valid, 19/19 located | ingests VEX; no export seen | none |
| ai-finder | 1.6 **invalid** (4 errors: `modelParameters.learningType` not in schema; license id `other`) | 3.0.1 **fails** the schema's `@context` constant (uses the spdx.github.io URL); AI and Dataset profile types present | none | none | none |
| Trusera ai-bom | 1.6 **invalid** (19 errors: component `type: service` is not a component type) | 3.0.1 flat document with a vendor context array; does not validate | valid, 78 results, all level `note` | none | none |
| cdxgen | 1.7 valid; `machine-learning-model` 11, `file` 8, `services` 3, `modelCard` 2, `formulation` | none in AI mode | none | none | none |
| ai-agentbom | 1.5; not validated here | none | valid, 13/13 located | none | none |
| Cisco (CLI, D) | 1.6 offered | 3.0 offered | offered | none | none |
| Syft (C) | 1.7 default, `machine-learning-model` for GGUF/SafeTensors, no PURL, no `modelCard` | 2.x only (3.0.1 decode only) | none | none | none |
| k8s-aibom (C) | 1.6 valid (golden test), `services`, evidence properties | none | none | none | none |
| OWASP (C) | 1.6 valid via library; "1.7" is the 1.6 document relabeled | placeholder | none | none | none |

## Determinism (D7, verified: two identical offline runs)

Byte-identical: Nexus SymBiote (also honors `SOURCE_DATE_EPOCH` and prints a
run-independent content digest), agent-bom, ai-agentbom. Identical after
removing timestamps and UUIDs: ai-finder; cdxgen differs only by a process id
captured inside a formulation note. **Not deterministic:** Trusera ai-bom
(risk scores and component order change between runs) and Cisco Tier-1 (the
second run contained 308 more lines, all `env_secret_*` components, which
points to a race between its async scanners). k8s-aibom derives its serial
number from the workload UID and uses an injectable clock (C).

## Per-tool notes

### 1. Nexus SymBiote, 73.0, B (V)

Strengths that the benchmark could verify: the only tool with zero egress,
zero process creation and no symlink opens; collection failures, limits hit
and the case-variant `claude.md` are recorded inside the inventory;
byte-identical output; valid CycloneDX 1.7, SPDX 3.0.1 with AI and Dataset
profiles, SARIF, VEX and a G7 minimum-elements report; SHA-256 on every model
file; tool definitions from both the Python decorators and the TypeScript MCP
server, with definition hashes; the A2A card, the hook command, the hidden
HTML comment, the bidi override and the zero-width character all raised
findings; hash-locked installs, attested releases and SHA-pinned actions.

Gaps, in order of how much they would hurt a user:

1. **Hosted model references are not inventoried.** None of the 13 model
   identifiers in `src/agent/llm.py`, `guardrails.py`, `retrieval.py`,
   `configs/*.yaml` or the `Modelfile` appear in the BOM. For an AI-BOM this is
   the headline gap: `minimum-elements` reports 5 models and all of them are
   local files. Datasets (0 of 6) and the training pipeline (0 of 2) are
   likewise absent, so the SPDX Dataset profile nodes describe retrieval
   sources only.
2. **False positive with a critical severity.** `data/raw/embeddings.bin`, a
   32 MiB file of zeros, is reported as a model with a potentially
   code-executing serialization format. A `.bin` suffix is not evidence of
   pickle; the gate failed on it.
3. **Not read:** `Dockerfile` and `Dockerfile.agent` (the `:latest` base
   image and the digest-pinned base are both missing), `.github/workflows`
   (the CI agent), `.env`, OpenAI function-schema JSON under `tools/`, and
   `mcp-server/package.json` (the npm MCP SDK dependency).
4. **Depth limit of 32** stopped short of the server 40 directories deep;
   the limit is documented and recorded, which is the right behavior, but the
   default is lower than real monorepos.
5. **JSON exports keep `\u001b` escaped**; a reader that pipes `jq -r` into a
   terminal re-creates the sequence. Text output is neutralized correctly.
6. Documentation drift the hygiene audit found: README still names the
   0.1.0 wheel; the documented organization (Hunzee-VC) differs from the git
   remote (aisecnomad).

Structural fix for 1: a code-level model-reference collector (provider SDK
constructors, `from_pretrained`, `pipeline(model=...)`, `load_dataset`,
Bedrock model ids, Ollama tags, YAML `base_model`/`dataset` keys) feeding the
existing model and data component types, with the same declared/observed
assurance labels. Cheapest fix for 2: require a pickle opcode header or a
known loader before `serialization_format` goes above medium for `.bin`.

### 2. k8s-aibom, 59.0 of the applicable 70, C, provisional (C/D)

A runtime observer, not a repository scanner. Per-component
`declared|verified|inferred|unresolved` confidence with a spec-path locator,
redaction that is recorded rather than silent, deterministic serial numbers,
a Sigstore verifier, attested releases with a self-SBOM and SHA-pinned
actions. It never opens files or images, so it has no opinion on MCP configs,
skills, prompts or datasets as files, emits CycloneDX 1.6 only, and has no
SPDX, SARIF or VEX. Pair it with a static tool; it is the only one here that
can say what is actually serving.

### 3. agent-bom, 55.6, C (V)

Highest raw recall and the richest findings: plaintext MCP secrets, a
credential-reach path (`project → github → GITHUB_PERSONAL_ACCESS_TOKEN`),
pickle deserialization, `prompt_coercion` on the refund skill, and IaC rules.
Exit codes are a documented contract and the release pipeline is the most
complete in the set (PyPI attestations, cosign bundles, SLSA provenance, SBOM).
Against that: it followed both escaping symlinks and emitted the SHA-256 of
`/etc/passwd`; it wrote the raw escape sequence from the Cursor server name
to the console; it tried the Docker socket ten times and spawned `docker` and
`git`; `--offline` is needed to stop proxy connects even with `--no-scan`; the
remote `httpUrl` server was rejected as "not a recognized MCP launcher"
rather than recorded as remote; the JSONC VS Code file and the hosted
Hugging Face references were missed; CycloneDX export carries no evidence or
hashes although the JSON report has both.

### 4. Cisco AI BOM, 37.0, F, provisional (V for Tier-1 only)

Tier-1 alone found 63 candidates with file and line, including every
`.mcp.json` server, the A2A card, skills, datasets, the training run and
twelve model references, each carrying `heuristic_confidence` and a
`needs_agentic` flag. The shipped CLI cannot run without an LLM provider and
network, which disqualifies it from an air-gapped audit and puts an LLM
between attacker-controlled text and the inventory; the corpus's `AGENTS.md`
and the `remote-crm` description carry instructions aimed at exactly that
reviewer, and this benchmark could not test whether they work. Tier-1 fetches
a third-party model catalog from GitHub at runtime, opened `/etc/passwd`
through both symlinks, and is not deterministic.

### 5. Trusera ai-bom, 29.1, F (V)

Fast, offline, skips escaping symlinks and large files with a log line, and
finds API-key shapes in `.env`. But the CycloneDX output is invalid (19
components use the type `service`), the SPDX document does not validate, the
PURLs are not PURLs (`pkg:pypi/model reference: gpt-4o-mini`), SDK imports
are emitted as `machine-learning-model` components (45 of 78), the tools are
misattributed to CrewAI, and two runs produce different scores and orderings.

### 6. ai-agentbom, 28.1, F (V)

Honest about its scope (offline, config and source only), byte-identical
output, redacted secret findings that even reached into the malformed TOML.
Coverage is thin (no model files, packages, tools or skills), CycloneDX 1.5
without PURLs, and the Markdown and Mermaid reports carry the raw ANSI escape
sequence from the server name. The published repository now ships under the
name `aigenguard` with no lockfile.

### 7. scanoss ai-finder, 28.1, F, hard gate G4 (V)

Good MCP coverage (7 of 10, including the TypeScript server and the deep
file), SHA-256 on model files, PURLs for MCP servers, file and line evidence,
SLSA and Sigstore on releases. It also sends usage telemetry to
`telemetry.scanoss.com` on every run unless the user finds the opt-out, queues
the events when offline, and read the escaping `.gguf` symlink as a model
file. No hosted model references, no findings of any kind, invalid CycloneDX
and a misleading "requires Python 3.10+" error on 3.13.

### 8. cdxgen, 23.3, F in this role (V)

A first-class SBOM generator: valid CycloneDX 1.7 with `services`,
`modelCard` and `formulation`, evidence with line numbers on every component,
SHA-pinned actions and npm provenance. As an AI-BOM tool on this corpus it
found no MCP servers, no tools, no skills, misattributed providers, listed a
commented-out model, promoted two shell scripts to components, and the two
AI audit rules failed to evaluate. It spawned nineteen different toolchain
binaries, including `sudo -K`, while scanning a directory it warns the user
to trust first.

### 9. OWASP AIBOM Generator, 22.7 of the applicable 70, F, provisional (C)

A Hugging Face model-card-to-CycloneDX converter with `modelCard` population
and a completeness score. No local inputs, no hashing, no evidence per field,
no SPDX (placeholder), non-deterministic serial numbers, network required,
`trust_remote_code=True` in its analytics path, no SECURITY.md, actions pinned
to tags. Useful for one model card; not an inventory tool.

### 10. Syft, 22.2, F in this role (C)

Bounded, offline parsers for GGUF and SafeTensors headers with HF
`config.json` and README frontmatter for identity; metadata xxhash rather
than file SHA-256; PURL intentionally unset for models; CycloneDX 1.7
`machine-learning-model` without `modelCard`; SPDX 2.x; `uuid.New()` and
`time.Now()` in every document. Nothing in the agent, prompt, MCP, dataset or
risk space. Use it for the packages and containers around the agent.

## Expected findings matrix (D5)

Check marks are verified in the outputs under `results/`; a half mark means
the condition is recorded without being raised as a finding.

| Finding | Nexus | agent-bom | Cisco T1 | Trusera | ai-finder | ai-agentbom | cdxgen |
| --- | --- | --- | --- | --- | --- | --- | --- |
| F01 floating MCP versions | ✓ | | | | | | |
| F02 floating image tags | ✓ ollama; agent-base not read | ✓ | | | | | |
| F03 credentials in config | ½ (by name, not raised) | ✓ critical | ✓ named, redacted | ✓ `.env` only | | ✓ | |
| F04 pickle formats | ✓ critical (+1 false positive) | ✓ | | | | | |
| F05 tool-description poisoning | | | | | | | |
| F06 instruction injection | ✓ hidden HTML comment | ✓ prompt_coercion | | | | | |
| F07 hidden characters | ✓ bidi, zero-width, ESC | | | | | | |
| F08 remote MCP endpoints | ½ | ½ (one rejected) | ½ | | ½ | ½ | |
| F09 hook runs a command | ✓ | | | | | | |
| F10 malformed config recorded | ✓ | | | | | ½ | |
| F11 symlink escapes recorded | ✓ | ✓ receipt | | ½ log only | | | |
| F12 unpinned HF revisions | n/a (models not read) | | | ½ | | | |
| F13 unresolvable package | live only | | | | | | |
| F14 permissive permissions | | | | | | | |
| F15 exposure path | ½ graph | ✓ credential reach | | | | | |

## What this benchmark did not do

- Syft was graded from source only. Running it needs a binary this sandbox
  refused to fetch or build; `run_tools.sh` has no Syft entry for that reason.
- Cisco's Tier-2 and Tier-3 stages, k8s-aibom in a cluster, and the OWASP
  generator against Hugging Face were not run. Their grades are provisional
  and their D1 is excluded or labeled partial.
- The corpus is one synthetic project. A tool that scopes out a class by
  design is penalized on D1 here; the per-tool notes say when that is the
  reason.
- Secrets are off-pattern sentinels, so entropy-based detectors are not
  expected to catch them; criterion 6.4 measured leakage only.
- Textual matching credits a tool when the identifying token appears in its
  output. Five matches were overridden after review (`review_overrides.json`).
- Each tool ran once per mode on one machine; timings are indicative.

## Reproducing

```bash
cd benchmarks/aibom-bench
python3 build_corpus.py --out /tmp/aibom-corpus
RESULTS=/tmp/aibom-results WORK=/tmp/aibom-work NEXUS=$(command -v nexus-symbiote) ./run_tools.sh nexus-symbiote
python3 score.py --results /tmp/aibom-results --schemas /path/to/schemas --proxy-port "${HTTPS_PROXY##*:}" --out /tmp/aibom-results/scores.json
```

`schemas/` must hold the CycloneDX 1.5, 1.6 and 1.7 schemas with their
`spdx`, `jsf-0.82` and `cryptography-defs` companions, the SARIF 2.1.0 schema,
and `spdx-json-schema-3.0.1.json` (this run used the copy vendored under
`src/nexus_symbiote/generators/schemas/vendor/spdx/`).
