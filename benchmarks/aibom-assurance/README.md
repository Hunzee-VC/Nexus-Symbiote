# AI-BOM Assurance Benchmark (AAB) v1.0

A measured benchmark for AI bill-of-materials tools across data, models, tools and agent
components (instruction files, skills, MCP servers and tools, A2A cards, coding-agent
settings, workflows), plus the properties a BOM needs to be worth trusting: evidence,
standards conformance, determinism, signing, and whether the scanner itself is safe to point
at a hostile repository. The specification is in [BENCHMARK.md](BENCHMARK.md); this page
summarizes the rerun of 17 November 2026 after the skeptic's review in
[CRITIQUE.md](CRITIQUE.md), which removed a fixture file only the host tool reads and
tightened two scoring rules. The first run's scores are kept in `results/first-run/`.

| File | Purpose |
| --- | --- |
| `BENCHMARK.md` | Dimensions, weights, criteria, matching rules, protocol, threats to validity |
| `build_fixture.py` | Generates the `acme-support-agent` fixture and `ground_truth.json` (76 items, 11 risks, 3 decoys, 3 canaries, 2 sentinels) |
| `run_tools.py` | Runs every tool under `strace`, records exit codes, timing, canary hits, fixture changes and egress |
| `cisco_deterministic.py`, `wasmagent_check.mjs` | Helpers for tools that have no plain CLI path for the benchmark |
| `score.py` | Matches outputs against the ground truth, validates schemas, checks determinism, applies rubrics |
| `rubric/<tool>.yaml` | Manual criteria with an evidence label and a one-line justification each |
| `results/RESULTS.md`, `results/scores.json` | Scoreboard, per-criterion detail and weight sensitivity for the rerun; `results/first-run/` holds the first run |
| `CRITIQUE.md` | The skeptic's review: challenges, what changed, what remains unresolved |
| `results/evidence/<tool>/<run>/` | Commands, outputs, stdout, stderr and `meta.json` for every run (strace logs and private keys left out) |

## Scoreboard

Full-stack scores weight all eight dimensions. In-scope scores renormalize over the
dimensions a tool claims. Evidence labels: M measured here, D documentation only (capped at
60 percent of the points), U unverifiable (zero).

| Rank | Tool | Full-stack | Grade | In-scope | Evidence M/D/U |
| --- | --- | ---: | --- | ---: | --- |
| 1 | Nexus SymBiote 0.2.0 (this repository) | 70.8 | B | 70.8 | 34/1/0 |
| 2 | agent-bom 0.115.3 | 62.2 | C | 62.2 | 32/3/0 |
| 3 | cdxgen 13.8.0 (OWASP) | 54.0 | D | 54.0 | 30/5/0 |
| 4 | Cisco AI BOM 1.10.1, deterministic tiers only | 52.0 | D | 52.0 | 30/5/0 |
| 5 | Trusera ai-bom 3.6.0 | 36.5 | F | 36.5 | 30/5/0 |
| 6 | AIsbom 1.7.0, model-file scanner | 36.2 | F | 38.1 | 29/6/0 |
| 7 | OWASP AIBOM Generator, Hugging Face models | 24.3 | F | 30.0 | 28/6/1 |
| 8 | k8s-aibom, Kubernetes controller | 20.2 | F | 56.1 | 2/14/19 |
| 9 | WasmAgent agentbom-core 0.4.0, library | 5.0 | F | 20.0 | 7/8/20 |
| 10 | Snyk `snyk aibom` | 4.4 | F | 33.8 | 2/9/24 |

The last three could not be run here: k8s-aibom needs a Kubernetes cluster, Snyk needs an
account and a hosted analysis, and WasmAgent is a validation library with no scanner. Their
rows say how far documentation gets a tool on this benchmark, not how well they work.

## What the fixture showed

**Discovery (D1).** Items found per family, out of 12 agent, 21 MCP, 14 model, 8 data and 21
tools items.

| Tool | agent | mcp | model | data | tools | Planted risks surfaced |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Nexus SymBiote | 10 | 20 | 4 | 0 | 13 | K1 K4 K5 K8 K10 |
| agent-bom | 6 | 18 | 7 | 0 | 19 | K1 K2 K3 K4 K8 K10 K11 |
| cdxgen (`aibom` plus plain `cdxgen`) | 8 | 1 | 8 | 1 | 15 | K7 K11 |
| Cisco AI BOM (deterministic) | 7 | 14 | 9 | 2 | 16 | none |
| Trusera ai-bom | 2 | 6 | 5 | 0 | 14 | none |
| AIsbom | 0 | 0 | 4 | 0 | 11 | K5 |
| OWASP AIBOM Generator | 0 | 0 | 1 | 0 | 0 | none |

No tool reported a decoy. Nobody found more than two of the eight data items: datasets named
in training and evaluation code, local CSV and JSONL files, a datasheet, the knowledge-base
directory, the S3 source and the Chroma collection are close to invisible to this generation
of tools. Hosted model references in code (`gpt-4o-2024-08-06`, `claude-sonnet-4-5`, the
Hugging Face identifiers) were found by cdxgen, Cisco and agent-bom and missed by Nexus
SymBiote, whose model collector covers local weight files only. MCP configuration was the
reverse: Nexus SymBiote and agent-bom read every client layout in the fixture, Cisco read most,
and the cdxgen `aibom` command read none (its MCP overlay lives behind `-t mcp`; an
informational run with `-t ai -t mcp -t ai-skill` reaches 34 of 76 items and 10 of 21 MCP
items, and is not scored because it needs the user to pick types).

**Risks (D3).** agent-bom surfaced seven of the eleven planted risks, Nexus SymBiote five,
cdxgen two, AIsbom one. The Cisco deterministic tiers surfaced none: their risk flags were
`hardcoded_api_key` on the empty placeholders in `.env.example` and on a `${{ secrets }}`
reference in the workflow, both false positives, plus two `unpinned_model` notes. No tool
flagged the destructive `delete_ticket` and SQL-executing `run_report_sql` tools (K9), and
only agent-bom flagged the plaintext token in `.cursor/mcp.json` (K2) and the filesystem
server rooted at `/` (K3).

**Evidence (D2).** Nexus SymBiote carried an evidence occurrence on every component and a
correct SHA-256 on every local model file; cdxgen populated `modelCard`, licenses and
pedigree for GGUF and Hugging Face models; AIsbom hashed all four local models and parsed
their headers; agent-bom and Cisco carry versions and file locations but no hashes; Trusera
carries almost no versions. Confidence labelling exists in Nexus SymBiote (trust tier,
assurance level), agent-bom (discovery-provenance confidence) and cdxgen (`cdx:ai:confidence`).

**Standards (D4).** CycloneDX output validated strictly for Nexus SymBiote and cdxgen (1.7),
Cisco and the OWASP generator (1.6) and AIsbom (1.7). It failed for agent-bom (a license
`id` of `SEE LICENSE IN LICENSE`, which is not an SPDX identifier) and Trusera (component type
`service`, which the 1.6 schema does not allow). SARIF validated for Nexus SymBiote,
agent-bom, Cisco and Trusera. SPDX 3.0.1 JSON-LD was well formed from five tools, but only
Cisco (12 elements), Nexus SymBiote (5) and AIsbom (4) used the AI or Dataset profiles;
agent-bom and cdxgen emitted software-only SPDX.

**Trust in the artifact (D5).** No tool gave byte-identical output on two default runs in the
rerun. Nexus SymBiote did in the first run, but in the rerun its first run hit a 0.25 second
TypeScript parse deadline under `strace` and dropped the notes server's two tools, which its
inventory recorded as a collection failure; coverage that depends on machine speed is not
reproducible, and `docs/collection-limits.md` says the limits are not wall-clock deadlines.
agent-bom, cdxgen, Trusera and AIsbom were identical after removing timestamps, UUIDs and
process ids. Cisco differed only in randomly generated `bom-ref`
values on its vulnerability entries. The OWASP generator differed in content because it
names its metadata component after the run time. Signing was exercised and worked in Nexus
SymBiote (DSSE attestation, verified) and cdxgen (JSON Signature Format); nothing else signs
a BOM. Diff was exercised in Nexus SymBiote and Cisco.

**Scanner safety (D6).** No tool read through the symbolic link to the file outside the
repository, and no tool copied the credential sentinel into any output. One tool executed
repository code: plain `cdxgen <dir>` ran the fixture's `setup.py` while resolving Python
metadata with its default install-deps behaviour (cdxgen prints a warning about exactly this);
the `aibom` command and `--no-install-deps` did not. Default-mode network use: none from
Nexus SymBiote, cdxgen or Trusera; advisory lookups to api.osv.dev, api.github.com and
www.cisa.gov from agent-bom; api.osv.dev, huggingface.co and raw.githubusercontent.com from
Cisco, which has no offline flag; huggingface.co from the OWASP generator by design; and a
default-on telemetry and version check to api.aisbom.io from AIsbom, which `--offline` or
`AISBOM_NO_TELEMETRY` suppresses. agent-bom's `--offline` run was silent but exits 1 until a
local vulnerability database is downloaded.

**Runtime reconciliation (D7).** Only Nexus SymBiote ingests runtime evidence: `trace-diff`
read the fixture's OTLP export and reported both undeclared items (`gpt-4.1-mini` and
`export_customers`). It also reported the declared primary model as undeclared, because its
inventory does not hold hosted models, which costs it a point.
agent-bom's MCP proxy and k8s-aibom's controller are runtime capabilities the harness could
not exercise.

## Verdicts

- **Nexus SymBiote** is the only tool that treats the BOM as evidence: verified attestation,
  correct hashes, confinement, offline by default, and runtime reconciliation. Its discovery
  gaps are hosted model references and datasets in code (0 of 8 data items once its own
  configuration convention was removed from the fixture), infrastructure outside the
  repository root and nested package manifests; it does not flag plaintext credentials or
  destructive tools in scan findings; and a wall-clock parse deadline makes its coverage,
  and therefore its output, depend on machine speed. Conflict of interest: the benchmark
  lives in its repository (BENCHMARK.md, section 8, and CRITIQUE.md).
- **agent-bom** has the widest risk coverage and the richest agent, MCP and dependency
  inventory, with a tool-level inventory in its native JSON. Fix the CycloneDX license
  encoding, carry models and tools into the standard export, and make offline mode usable
  without a one-gigabyte download.
- **cdxgen** produces the most standards-faithful CycloneDX (model cards, formulation,
  signing) but its AI-BOM entry point ignores MCP configuration, and its plain default
  executes repository code on a Python project. Run it with `--no-install-deps` and `-t mcp`.
- **Cisco AI BOM** found the most components after Nexus SymBiote without its LLM stage, and
  its SPDX export is the most complete, but the deterministic tiers surfaced none of the
  planted risks and the full pipeline requires sending candidates to an LLM.
- **Trusera ai-bom** covers containers, n8n and MCP servers but emits invalid CycloneDX,
  surfaces none of the planted risks and has not shipped since March 2026.
- **AIsbom** is a good model-file scanner (pickle flagged, headers parsed, hashes correct) that
  phones home by default; it is not an application inventory.
- **OWASP AIBOM Generator** writes a clean, valid model card BOM for one Hugging Face model
  and nothing else.
- **k8s-aibom**, **Snyk** and **WasmAgent** need a cluster, an account and a document the
  user writes, respectively. WasmAgent's README examples do not run on 0.4.0.

## Caveats

One synthetic fixture, token matching, and an author who maintains one of the graded
tools. Treat the ranking as a reproducible starting point, re-run it, and read the raw
evidence before quoting a number. Section 8 of BENCHMARK.md lists the threats to validity;
section 9 has the commands.
