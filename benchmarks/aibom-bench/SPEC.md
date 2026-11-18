# AIBOM-Bench 1.0 specification

AIBOM-Bench measures how well a tool inventories the AI supply chain of a repository
(data, models, tools, and agent components) and how safely it does so when the
repository is hostile. It is executable: every point comes from running the tool in a
sandbox and comparing its output with machine-readable ground truth. No points come
from a tool's documentation or feature list.

## Why an AI-BOM exists, and what the benchmark therefore rewards

An AI-BOM earns its keep in four moments, and the benchmark weights what each one needs.

1. **Before shipping**, to see the attack surface: which MCP servers will start, with
   which launch command and credentials; which skills, rules and hooks steer the agent;
   which weights load through a format that executes code.
2. **On every change**, to catch drift: a tool description that changed after review is
   new instructions to the model ("rug pull"); a floating package or image tag is a
   change nobody reviewed.
3. **During an incident**, to answer "where else is this?" with identities precise
   enough to search for: versions, digests, revisions, content hashes.
4. **For compliance and exchange**, as a document other tools can read: valid
   CycloneDX or SPDX, valid package URLs, a dependency graph that resolves.

A scanner is pointed at untrusted repositories by design, in CI on pull requests from
strangers. A scanner that deserializes a pickle, starts an MCP server, runs `npm
install`, follows a symlink out of the checkout, or copies a token into its report
turns the inventory step into the breach. Scanner safety is therefore a scored domain
**and** a set of grade caps.

## Design principles

| Principle | How it is implemented |
|---|---|
| Executable, not a checklist | Every item is scored from tool output on generated fixtures. |
| Ungameable identifiers | Every name a scorer matches is a random token derived from the seed (`kestrel7c41`). Publish results for the public seed; run a private seed for holdout verification. |
| Precision as well as recall | Negative controls (Django `models.py`, an MCP example inside README prose, a team `SKILLS.md`, a pinned server that deserves no high finding) subtract points when reported. |
| Findings must name the problem | A finding counts only if it references the component **and** its text names the right class of issue (keyword set per case), and it is not informational. Emitting a note for every component earns nothing. |
| Identity, not just presence | Many items carry attribute checks: SHA-256 of the file, pinned revision, container digest, version, licence, credential *reference* (not value), lineage to base model or dataset. |
| Drift is measured, not asserted | The same MCP server is scanned before and after one tool description changes. The inventory must change for that tool and stay identical for an unchanged tool. |
| Hostile by construction | Canary payloads that write a file only if executed; symlinks out of the root; a 3 GiB decompression bomb; a 2^62-byte SafeTensors header; 200 000-deep JSON; OSC 52 / title-set escape sequences; literal credentials. |
| Same sandbox for everyone | Fresh network namespace, unprivileged user, read-only corpus, fresh HOME, 300 s per command, `strace` of `connect()`, peak RSS from `wait4()`. |
| Best configuration per tool | Each tool runs its documented, most complete repository-scan configuration (all formats it offers). Configuration and rationale are in `tools.json`. |
| Tool-neutral readers | CycloneDX, SPDX 3, SPDX 2, SARIF and native JSON are read by generic rules in `score.py`; no per-tool adapters, so no tool gets bespoke interpretation. |
| Reproducible | Seeded generator, corpus digest, tool versions, raw outputs and per-item evidence are kept. |

## Scope

In scope (v1.0): repository content on disk, scanned offline.

| Domain | Weight | What is covered |
|---|---:|---|
| MCP servers and launch provenance (`mcp`) | 16 | Config dialects (Claude Code `.mcp.json`, Cursor, VS Code `servers`, Codex TOML, Gemini, Kiro, SDK client code); npm/uvx/docker launchers; exact pins vs floating versions and `:latest`; container digests; remote HTTP servers; credential references vs literal credentials; shell-wrapped launch commands. |
| Tool definitions and drift (`tooldefs`) | 10 | Tools declared in in-repo MCP servers (Python FastMCP, TypeScript `registerTool`); tool-poisoning text; before/after drift of a single description. |
| Skills, instructions, hooks, plugins (`skills`) | 12 | `SKILL.md` skills and bundled scripts (with digests); a skill whose script exfiltrates credentials; `AGENTS.md`, `CLAUDE.md` and its `@path` imports, Cursor rules, Copilot instructions, prompt files, slash commands; Claude Code hooks; plugin manifests; invisible Unicode tag text. |
| Agents, A2A, multi-agent (`agents`) | 8 | OpenAI Agents SDK (tools, handoffs), LangGraph, CrewAI YAML, Google ADK, AutoGen, Claude Code subagents, A2A agent cards and remote A2A clients. |
| Model artifacts and references (`models`) | 16 | SafeTensors, GGUF, ONNX, PyTorch zip pickle, disguised pickle, Keras v3 Lambda, LoRA adapter lineage, model-card lineage, Ollama Modelfile; Hugging Face references pinned/unpinned, embedding models, hosted fine-tune IDs, Bedrock ARNs, TypeScript and YAML references; GGUF chat-template injection. |
| Datasets and retrieval stores (`data`) | 8 | Hugging Face datasets (pinned), local training files with dataset cards and digests, CSV datasets, Chroma collections, Pinecone indexes. |
| AI frameworks and SDK dependencies (`packages`) | 4 | Python and npm AI/MCP SDKs with versions; a typosquat-like name. |
| Standards conformance and integrity (`standards`) | 12 | CycloneDX schema validity (official schemas), SPDX 3 with AI/Dataset profile, ML-BOM component types, package URL validity and `pkg:huggingface`, dependency graph references, determinism across two runs, producer metadata. |
| Scanner safety on hostile input (`safety`) | 14 | No execution of pickles, MCP launch commands or project build scripts; no reads through escaping symlinks; no raw terminal escape sequences from input; bounded time and memory on bombs; graceful degradation (benign siblings still inventoried); credentials redacted from every output; no network attempts in default mode. |

Weights favour the agentic surface (46 of 100 across `mcp`, `tooldefs`, `skills`,
`agents`) because that is where AI-BOM tooling is youngest and where a missed entry
most directly becomes an exploitable path. They are a judgement, published so a
reader can re-weight `results.json`.

Out of scope for v1.0, deliberately: live MCP enumeration (`tools/list`) and remote
registry metadata; CVE and advisory matching (time-varying and network-bound);
container images, Kubernetes and cloud accounts; runtime traces; signature and
attestation verification; SPDX SHACL validation (SPDX is checked structurally only).
Each is a candidate for a later version with its own fixtures.

## Scoring

**Records.** Each output file is parsed by a format reader:

- CycloneDX: components and services, nested, plus `formulation`. Findings come from
  `vulnerabilities` (affected refs resolved), `annotations`, and risk-named component
  properties.
- SPDX 3: graph elements other than relationships, creation info and agents.
  Annotations and vulnerability assessments become findings.
- SARIF: results, joined to their rule.
- Native JSON: every object in a list becomes a record. Lists under a key naming
  findings (`risk`, `finding`, `issue`, `vuln`, …) become findings carrying the identity
  of their parent object. Bookkeeping lists (stats, framework catalogues, control
  mappings, scanned-file lists) are skipped.

**Component items.** Detected when any component record contains the item's token
(case-insensitive). Points = weight, plus each attribute check that also appears in a
matched record.

**Finding items.** Detected when a finding record (a) contains the token, (b)
contains one of the case's keywords, and (c) is not informational (`note`, `info`,
`none`). Unknown severity is accepted. A finding that names more than three of the
scenario's components is treated as repository-level ("no human oversight: A, B, C,
…"): it earns no per-component credit and cannot be a false positive either.

**Negative items.** A component record containing a negative token, or a high or
critical finding on a benign control, subtracts the weight from the domain. Negatives
are penalties, never free points.

**Drift items.** Component records containing the tool token are taken from the v1
and v2 scans. Volatile fields (timestamps, UUIDs, run IDs, durations) and the scenario
name are normalised away before comparison. T07 needs a difference for the changed
tool; T08 needs equality for the unchanged one.

**Standards items** are computed across all outputs (see `score.py:standards`). CycloneDX
documents are validated with the official schemas bundled in `cyclonedx-python-lib`.
Determinism compares two runs of the same input after removing volatile fields.

**Safety items** use runner evidence: canary files, output bytes, timeouts, peak RSS
and `strace` connect attempts. Network attempts are judged on a separate run that uses
the tool's plain invocation with no offline flags (`default_commands`). A safety item
earns points only when the tool also inventoried the benign sentinel in that scenario
(`requires` in the ground truth): a tool that never parsed the hostile directory has
not shown it is safe there. A failed check triggers its gate either way. Likewise, an
empty CycloneDX document conforms trivially, so standards checks look only at
documents that inventory something.

**Calibration.** A synthetic oracle that emits exactly the ground truth as one
CycloneDX file plus one SARIF file scores 97.0 (it omits SPDX, `pkg:huggingface` URLs
and dependency edges); an empty tool scores 0.0. `calibrate.py` reproduces both, and
a scorer change that moves either number needs an explanation.

**Domain score** = max(0, earned − penalties) / possible.
**Overall score** = Σ domain weight × domain score (0–100).
**In-scope score** = the same, restricted to the domains the tool's own documentation
claims (`declared_scope` in `tools.json`). It shows quality within the tool's chosen
scope, while the overall score shows coverage of the whole AI supply chain.

**Grades.** A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, F < 40. The bar is set for a tool you would
deploy in CI on untrusted pull requests with no other AI-BOM tooling beside it.

**Gates** cap the grade regardless of score:

| Gate | Cap | Why |
|---|---|---|
| X01, X02, X09: executes a pickle, an MCP launch command, or a project build script | F | Remote code execution in CI from a pull request. |
| X07: a literal credential appears in any output | D | The BOM becomes a secret-distribution channel (artifacts, PR comments, dashboards). |
| X03: reads through a symlink that leaves the scan root | C | Information disclosure from the CI host into a published artifact. |

## Sandbox and run protocol

`run.py` executes each command as:

```
unshare -n -- strace -f -e trace=connect -- setpriv --reuid=bench ... -- env -i HOME=<fresh> PATH=<tool> <tool argv>
```

- The network namespace has no interfaces up, so no request leaves the machine. Every
  `connect()` attempt is still recorded.
- The corpus is owned by root and not writable by the sandbox user; the canary
  directory is world-writable so an executed payload can prove it ran.
- Each scenario gets a fresh output directory and HOME; caches cannot carry over.
- `s01-models` and `s04-mcp` are scanned twice for determinism.

## Fairness rules

1. Use the tool's most complete documented configuration for repository scanning.
   Ask the tool's maintainers to correct `tools.json` when a better one exists.
2. Do not write per-tool adapters. If a valid output shape is not read correctly, fix
   the generic reader for every tool and re-score all of them.
3. Report a tool that cannot run in the sandbox as N/R with the reason, not as F.
4. Report both the overall and the in-scope score, so a specialist tool is not presented
   as a failed generalist.
5. Publish the seed, corpus digest, tool versions, raw outputs and per-item evidence.

## Threats to validity

- **Synthetic corpus.** Fixtures are small and regular. Real repositories are larger and
  messier, so recall on real code may be lower and false positives higher.
- **Token matching is lenient about type.** A record containing the token earns
  detection even if the tool mistyped the component. Attribute checks and ML-BOM
  semantics only partly compensate.
- **Keyword-based finding classes.** Keyword sets are broad on purpose; a finding phrased
  with none of them is missed. Sets are published per case.
- **Weights and grade bands are judgement.** Re-weighting changes ranks between close
  tools; `results.json` has everything needed to do so.
- **Offline-only.** Tools whose value comes from network enrichment (Hugging Face
  metadata, OSV, an LLM classifier) score lower here than online. That is intended for
  the CI threat model, but it is still a limitation.
- **Point in time.** Tools in this space ship weekly. Results describe the listed
  versions only.
- **Author conflict of interest.** v1.0 was written inside the Nexus SymBiote repository,
  by the assistant working on it. Mitigations: cases derive from the threat model and
  from public formats, not from Nexus collectors; no adapters; all raw outputs kept.
  Independent replication with a private seed is the proper check.
