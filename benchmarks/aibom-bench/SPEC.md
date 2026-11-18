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
| Seeded identifiers | Almost every name a scorer matches is a random token derived from the seed (`kestrel7c41`); the exceptions are standard file names (`AGENTS.md`, `CLAUDE.md`) and real package names in `s08`. Publish results for the public seed; run a private seed for holdout verification. |
| Understanding, not echoing | A component counts only as a typed inventory entry: its token must sit in a short field such as a name, command or URL, and the kind of component must be stated by another field. Synthetic tools that dump every file or list every path stay at the floor (see Calibration). |
| Precision as well as recall | Negative controls (Django `models.py`, a UI `*.model.json`, an MCP example inside README prose, a team `SKILLS.md`, an exact-pinned server called "unpinned", a plain rule file called "hidden text") subtract points when reported. |
| Findings must name the problem | A finding counts only if it references the component **and** its text names the right class of issue (keyword set per case), and it is not informational. Emitting a note for every component earns nothing. |
| Identity, not just presence | Many items carry attribute checks: SHA-256 of the file, pinned revision, container digest, version, licence, credential *reference* (not value), lineage to base model or dataset. |
| Drift is measured, not asserted | The same MCP server is scanned before and after one tool description changes. The inventory must change for that tool and stay identical for an unchanged tool. |
| Hostile by construction | Canary payloads that write a file only if executed; symlinks out of the root; a 3 GiB decompression bomb; a 2^62-byte SafeTensors header; 200 000-deep JSON; OSC 52 / title-set escape sequences; literal credentials. |
| Same sandbox for everyone | Fresh network namespace, unprivileged user, a fresh writable copy of each scenario (as in a CI checkout), fresh HOME, 300 s per command, `strace` of `connect()` and `execve()`, peak RSS from `wait4()`. |
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

**Records.** Each output file (and JSON printed on standard output) is parsed by a
format reader. No reader knows any tool.

- CycloneDX: components and services, nested; `metadata.component` when it is a model,
  dataset or library rather than the scanned project; `formulation`. Findings come from
  `vulnerabilities` (affected refs resolved), `annotations` that name a severity or a
  component, and risk-named component properties.
- SPDX 3: elements of `@graph`, `element` or `elements` other than relationships,
  creation info, agents and licences. Annotations and vulnerability assessments are
  findings, attributed through `subject`, `from` and `to`.
- SPDX 2: packages and files.
- SARIF 2.1: results, joined to their rule by `ruleId`, `ruleIndex` or tool extensions.
  Results of kind `pass`, `notApplicable` or `informational` are informational.
- Native JSON: every object in a list, and every entry of an object keyed by name,
  becomes a record. Lists under a key naming findings (`risk`, `finding`, `issue`,
  `vuln`, …) become findings carrying the identity of their parent object. An inventory
  object with a non-informational `severity` also yields a finding. Bookkeeping keys
  (statistics, framework catalogues, control mappings, failure and skip lists) are not read.

**Component items.** An item is detected when some record (a) holds the item's token in
a short single-line value (at most 300 characters) that names fewer than three of the
scenario's components, and (b) states the item's kind (model, server, skill, dataset,
agent, package, …) in a different field that is not a path, a key, or the name of the
list that holds it. A file path says where a file is, not what it is, so it never
supplies the kind. For files with generic names (`model.safetensors`, `train.jsonl`) the
file's SHA-256 is an alternative identity. Points = weight, plus each attribute check
found in a single qualifying record that names at most three of the scenario's
components (never in a union of records).

**Finding items.** A finding record earns the item when (a) it contains the token,
(b) its own message text (message, title, description, rule text; not keys, evidence
lists or attribution context) contains one of the case's keywords at a word boundary,
and (c) its severity is not informational. Unknown severity is accepted. A finding that
names more than three of the scenario's components is repository-level ("no human
oversight: A, B, C, …"): it earns no per-component credit and is never a false positive.

**Negative items** subtract their weight and are never free points. A negative
component is reported when a record qualifies as in (a) and (b) above. A negative
finding is reported when a medium or higher finding names the benign control and makes
the specific wrong claim (keywords such as "unpinned" for an exact-pinned server).

**Drift items.** Both versions of the drift scenario are scanned at the same path, as
successive commits would be. Qualifying records for the changed tool must differ (T07).
A record specific to the unchanged tool must be identical, or must keep a per-tool
fingerprint (a digest not shared with the changed tool's records) so a reviewer can
tell which tool changed (T08). Volatile fields (timestamps, UUIDs, run IDs, durations)
are removed before comparison.

**Standards items.** F01 validates every non-empty CycloneDX document with the official
schemas bundled in `cyclonedx-python-lib`; scoring stops if the validator is missing.
F02 checks SPDX 3 structurally (typed elements with IDs) and requires the ground-truth
models and datasets to be typed `ai_AIPackage` and `dataset_DatasetPackage`; there is
no SPDX 3 JSON-schema or SHACL validation in v1.0. F03 is the fraction of ground-truth
models typed `machine-learning-model` and datasets typed `data`. F04 parses every value
of a package-URL field with `packageurl-python` and needs a `pkg:huggingface` URL naming
a ground-truth model. F05 needs unique bom-refs, resolving references, and dependency
edges in every multi-component document. F06 compares two runs after removing volatile
fields, ignoring array order. F07 needs the producing tool and version in metadata. A
document that inventories nothing conforms trivially and is not counted.

**Safety items** use runner evidence: canary files, `execve` records, output bytes,
timeouts, peak RSS and `connect` attempts. Canary and build-command checks cover the
benchmark configuration and the tool's plain invocation (`default_commands`, run on
every scenario). X09 also fails when, in any scenario, the tool runs or tries to run a
package manager or build on the scanned project (`npm install` without
`--ignore-scripts`, `pip install -e .` or `-r <project file>`, `python setup.py`, `uv
sync`, `poetry install`): offline that fails before anything is downloaded, but in a CI
job with network access an attacker-controlled manifest (a source distribution with a
build script, a git or URL dependency, a custom index) executes code.
Network attempts are judged on the default-mode runs. A safety item earns points only
when the tool also inventoried one of the scenario's benign sentinels (`requires`): a
tool that never parsed the hostile directory has not shown it is safe there. A failed
check triggers its gate either way. X06 fails when a command timed out, because peak
memory was not observed.

**Calibration.** `calibrate.py` scores four synthetic tools:

| Synthetic tool | What it emits | Score |
|---|---|---:|
| oracle | Exactly the ground truth, as CycloneDX plus SARIF | 96.5 (no SPDX, package URLs or dependency edges) |
| cat | Every file's path, SHA-256 and full contents | 7.4 (F; X07 gate) |
| positive control | Executes every payload and echoes every file (`executor.py`, run in the sandbox) | F; trips all seven safety probes and the F, D and C gates |
| lister | Every file's path and SHA-256 | 0.0 |
| empty | Valid, empty documents | 0.0 |

The cat tool's residue comes from one-line files (a SafeTensors header, single-line
JSON) whose contents pass as short values. A scorer change that moves any of these
numbers needs an explanation here.

**Domain score** = max(0, earned − penalties) / possible.
**Overall score** = Σ domain weight × domain score (0–100).
**In-scope score** = the same, restricted to the domains the tool's own documentation
claims (`declared_scope` in `tools.json`). It shows quality within the tool's chosen
scope, while the overall score shows coverage of the whole AI supply chain.
**Risk findings** = the share of finding-item points earned across all domains. Only
about 25 of the 100 points are findings, so a tool can reach a C or better on inventory
alone; read this column with the grade.

**Grades.** A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, F < 40, on the score rounded to one
decimal. Tools are ranked by grade after gates, then by score.

**Gates** cap the grade regardless of score:

| Gate | Cap | Why |
|---|---|---|
| X01, X02, X09: executes a pickle, an MCP launch command, or a project build script | F | Remote code execution in CI from a pull request. |
| X07: a literal credential appears in any output | D | The BOM becomes a secret-distribution channel (artifacts, PR comments, dashboards). |
| X03: reads through a symlink that leaves the scan root | C | Information disclosure from the CI host into a published artifact. |

## Sandbox and run protocol

`run.py` executes each command as:

```
unshare -n -p -f --kill-child -m -- sh -c '<private /tmp, /var/tmp, /dev/shm; loopback up>; exec "$@"' \
  strace -f -s 256 -e trace=connect,execve -- \
  setpriv --no-new-privs --reuid=bench --regid=bench --clear-groups -- \
  sh -c '"$@"; kill -KILL -1' env -i HOME=<fresh> TMPDIR=<fresh> CI=true PATH=<tool> <tool argv>
```

- Network, PID and mount namespaces: only loopback is up, so no request leaves the
  machine, and every `connect()` attempt is recorded. Processes the tool leaves behind
  are killed when its main process exits, and nothing survives the namespace.
- The tool's working directory is a fresh copy of the scenario, owned by the sandbox
  user and writable, as in a CI checkout. A new copy is made for every command. The copy
  sits next to a copy of the directory its escaping symlinks reach. The corpus stays
  root-owned, and its ground truth is readable only by root.
- Evidence the runner records (stdout, stderr, strace, `_run.json`) lives in a root-owned
  directory; the tool can write only its `out/` subdirectory, its HOME and the checkout.
- `CI=true` is set, as in a CI job. Each command gets a fresh HOME and TMPDIR.
- `s01-models` and `s04-mcp` are scanned twice for determinism. The plain invocation
  (`default_commands`) runs on every scenario, without the tool's environment overrides.
- The runner refuses a corpus generated for another directory (the canary path is baked
  into the payloads) and holds a lock on the canary directory for the whole run.
- A positive control (`executor.py`) runs through the same sandbox. It deserializes
  the pickles, starts the shell-wrapped MCP server, builds the project with pip and npm,
  connects out, reads through the escaping symlinks and echoes everything. Scoring warns
  if any of X01, X02, X03, X04, X07, X08 or X09 does not catch it. In v1.0 all seven do.

## Fairness rules

1. Use the tool's most complete documented configuration for scanning an untrusted
   repository, in its safe mode where it documents one (for cdxgen,
   `--no-install-deps`). The tool's plain documented invocation also runs on every
   scenario, and its execution gates apply to both. Ask the tool's maintainers to
   correct `tools.json` when a better configuration exists.
2. Do not write per-tool adapters. If a valid output shape is not read correctly, fix
   the generic reader for every tool and re-score all of them.
3. Report a tool that cannot run in the sandbox as N/R with the reason, not as F.
4. Report both the overall and the in-scope score, so a specialist tool is not presented
   as a failed generalist.
5. Publish the seed, corpus digest, tool versions, raw outputs and per-item evidence.

## Threats to validity

- **Synthetic corpus.** Fixtures are small and regular. Real repositories are larger and
  messier, so recall on real code may be lower and false positives higher.
- **Kind evidence is a word list.** A typed record earns detection even if its type is
  wrong within the family (a dataset recorded as a model file). F03 and F02 measure exact
  typing separately. Conversely, a record whose only kind evidence is an unusual word
  is missed.
- **Residual echo credit.** A tool that dumps one-line files can still match a few
  items (7.4 points in calibration).
- **Keyword-based finding classes.** Keyword sets are broad on purpose and matched at word
  boundaries in the finding's own text; a finding phrased with none of them is missed.
  Sets are published per case in `generate.py`.
- **Weights and grade bands are judgement.** Re-weighting changes ranks between close
  tools; `results.json` has everything needed to do so.
- **Offline-only.** Tools whose value comes from network enrichment (Hugging Face
  metadata, OSV, an LLM classifier) score lower here than online. That is intended for
  the CI threat model, but it is still a limitation.
- **Peak memory is per process.** `wait4()` reports the largest single process, not the
  process tree; a tool that spreads work over many processes can stay under the X06
  bound while the tree does not. No memory limit is enforced (cgroups were not
  available).
- **Safety weight for specialists.** About half of the safety points need an MCP or skill
  sentinel, so a model-only tool cannot earn them even when it behaves safely. The
  in-scope score does not correct for this.
- **Point in time.** Tools in this space ship weekly. Results describe the listed
  versions only.
- **Author conflict of interest.** v1.0 was written inside the Nexus SymBiote repository,
  by the assistant working on it. Mitigations: cases derive from the threat model and
  from public formats, not from Nexus collectors; no adapters; all raw outputs kept.
  Independent replication with a private seed is the proper check.

## Roadmap for v1.1

From the independent design review, ranked by how much a silent miss would hurt a real
deployment:

1. Remote-code model loading: `trust_remote_code`, `auto_map` custom code, `torch.hub`,
   dataset loading scripts.
2. Agent posture: auto-approved MCP servers, `bypassPermissions`, broad Bash allows,
   `apiKeyHelper` commands, base-URL overrides, folder-open tasks, CI agent actions.
3. Tool-poisoning breadth: poisoned parameter descriptions and tool names, cross-server
   shadowing and name collisions, MCP prompts and resources.
4. Scanner self-execution beyond the current canaries: importing in-repo server or agent
   modules, YAML unsafe load, local `npx ./pkg` or `uvx --from ./pkg` launches,
   zip-slip, in-repo scanner configuration that suppresses findings.
5. Remote MCP posture: plain `http://`, SSE, unauthenticated remotes, `mcp-remote`
   bridges, privileged container launches, filesystem servers rooted at `/`.
6. Model-format breadth with benign controls: `STACK_GLOBAL` and non-denylisted
   callables, joblib, NumPy object arrays, legacy torch, H5 Lambda, ONNX external data,
   tokenizer template injection.
7. Dataset and RAG provenance: unpinned datasets, URL data files, a FAISS `index.pkl`
   with `allow_dangerous_deserialization`, a poisoned document in a RAG corpus.
8. Instruction-file injection beyond tag characters: visible directives, HTML comments,
   zero-width and bidi variants, `@import` outside the repository.
9. Config-level drift pairs (pins, digests, skill scripts, weights) alongside the
   tool-description pair.
10. SPDX 3 JSON-schema and SHACL validation, SARIF and SPDX 2.3 validation, minimum
    elements from standard fields only.
11. A local mock Hugging Face Hub and a pinned local LLM inside the sandbox, so Hub- and
    LLM-dependent tools can be graded on equal terms.
12. Per-surface safety sub-scores, cgroup memory accounting, and an `openat` trace for
    symlink reads.

