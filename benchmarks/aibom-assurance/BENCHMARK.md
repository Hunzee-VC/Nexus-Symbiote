# AI-BOM Assurance Benchmark (AAB) v1.0

A measured, reproducible benchmark for tools that produce an AI bill of materials (AI-BOM,
ML-BOM, AgentBOM). It covers the four component families an AI system is assembled from:
**data**, **models**, **tools and libraries**, and **agent components** (instruction files,
skills, MCP servers and clients, A2A agent cards, coding-agent settings, workflows). It grades a
tool on what it finds, how well it proves it, what risks it surfaces, whether its output is
standard and trustworthy, and whether the scanner itself is safe to point at a hostile
repository.

## 1. Principles

1. **Ground truth first.** Every score comes from a synthetic fixture repository whose
   components, configuration risks, decoys and probes are enumerated in `ground_truth.json`
   before any tool runs. Nothing is scored by reading a tool's marketing.
2. **Measured beats described.** Each criterion carries an evidence label: **M** measured in
   this run, **D** taken from the tool's documentation because it could not be run here, or
   **U** unverified. Documentation-based criteria never earn full points.
3. **Benign fixtures.** The fixture holds configuration-level risks (unpinned packages, a
   plaintext token sentinel, an over-broad filesystem root, a cleartext remote transport, a
   permissive agent mode) and inert model files (a pickled dictionary, a zero-valued
   safetensors tensor, a GGUF header without tensors, an identity ONNX graph). Nothing in it
   is executable payload, and nothing is deserialized by the harness.
4. **Run as a user would.** Each tool runs with its default settings first, then in its own
   offline or safe mode when it has one. Default behaviour is what most users get.
5. **Hostile-input posture is scored.** A BOM generator reads attacker-controlled
   repositories. Whether it executes repository code, follows symbolic links out of the
   project, copies credentials into the BOM, or phones home by default is part of the grade.
6. **Two scores per tool.** The *full-stack* score weights every dimension, because the
   question is "which tool inventories a whole agentic system". The *in-scope* score
   renormalizes over the dimensions the tool claims, so a model-file scanner is also graded
   on its own terms.

## 2. Component universe

| Family | Category | Fixture examples |
| --- | --- | --- |
| Agent | `agent` | LangGraph agent in code, A2A agent card, Claude Code subagent, n8n agent workflow |
| Agent | `instruction` | `CLAUDE.md` with `@docs/agent-rules.md` import, `AGENTS.md`, `.github/copilot-instructions.md` |
| Agent | `skill` | `.claude/skills/*/SKILL.md`, `skills/*/SKILL.md` (open Agent Skills layout) |
| Agent | `mcp_server` | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` (JSONC), `.codex/config.toml`, `.gemini/settings.json`, server sources in Python and TypeScript, an MCP Registry `server.json` |
| Agent | `tool` | Tools registered by the two MCP servers, LangChain `@tool` functions |
| Agent | `permission` | `.claude/settings.json` allow and deny rules, default mode, hooks |
| Model | `model` | Hosted chat and embedding models in code, Hugging Face references pinned and unpinned, local safetensors, pickle, GGUF and ONNX files, an Ollama `Modelfile`, a vLLM served model |
| Model | `endpoint` | OpenAI-compatible base URL pointing at an internal vLLM service |
| Data | `dataset` | Hugging Face datasets in training and evaluation code, local CSV and JSONL, a datasheet |
| Data | `rag` | Knowledge-base directory, S3 source, Chroma vector store and collection |
| Tools | `library` | AI SDKs and frameworks in `requirements.txt`, `pyproject.toml`, `package.json` |
| Tools | `guardrail` | `llm-guard` input screening module |
| Tools | `infra` | Dockerfile, compose services for vLLM, Ollama and Chroma, a Kubernetes vLLM deployment, a CI workflow using an AI action |

## 3. Fixture: `acme-support-agent`

`build_fixture.py` generates a customer-support agent monorepo deterministically. The
ground-truth file lists every labelled item with the tokens that identify it in a BOM, the
attributes a complete record should carry, and the category it belongs to.

**Decoys (must not become components).** A commented-out MCP server inside JSONC, a model
name that appears only in blog prose, and a tool name that appears only in a test string.

**Risks (should become findings).** Unpinned MCP packages; a plaintext token in an MCP
config; an MCP filesystem server rooted at `/`; a remote MCP transport over cleartext HTTP
with no authentication; a pickle-format model; an unpinned Hugging Face model revision;
unpinned container image tags; unpinned Python dependencies; destructive and SQL-executing
tools exposed by an MCP server; a permissive coding-agent default mode; a CI workflow that
runs a third-party AI action from a mutable tag.

**Probes (scanner safety).**

| Probe | Mechanism | What a hit means |
| --- | --- | --- |
| Code execution | `setup.py`, an npm `postinstall` script and a Python package `__init__` each create a marker file when executed | The scanner ran repository code |
| Path confinement | A symbolic link inside the repository points to a file outside it holding a sentinel | The scanner read outside the project root |
| Credential handling | A sentinel token value inside an MCP config `env` block | The BOM copies credential values verbatim |
| Egress | `strace` records every non-loopback `connect()` during the run | The scanner contacted the network in that mode |
| Resource bounds | A 12 MiB Markdown file inside the knowledge base | Runtime and completion are recorded |

**Runtime evidence.** `telemetry/traces.json` is an OTLP/JSON trace export whose spans
report two declared items and two undeclared ones (a model and a tool). A tool with runtime
reconciliation should surface the two undeclared items.

## 4. Dimensions, weights and criteria

Scores are out of 100. Each dimension lists its criteria, points and the evidence label a
criterion can carry.

### D1. Discovery coverage, 30 points

Recall per category over labelled items, weighted by family; minus one point per decoy
reported as a component, floored at zero for the dimension.

| Criterion | Points | How |
| --- | ---: | --- |
| Agents, instructions, skills, permissions | 8 | recall x 8 |
| MCP servers, clients, tools | 10 | recall x 10 |
| Models and endpoints | 6 | recall x 6 |
| Datasets and retrieval | 4 | recall x 4 |
| Libraries, guardrails, infrastructure | 2 | recall x 2 |
| Decoys | penalty | -1 per decoy reported, max -3 |

### D2. Evidence and attribute quality, 15 points

Computed over the components that matched a labelled item.

| Criterion | Points | How |
| --- | ---: | --- |
| Locator (file path, line, or evidence occurrence) | 4 | fraction x 4 |
| Cryptographic hash on local artifacts | 3 | fraction over local files x 3 |
| Version or revision | 3 | fraction x 3 |
| License | 2 | fraction x 2 |
| Supplier, author or publisher | 1 | fraction x 1 |
| Confidence or tier labelling (declared, inferred, verified) | 2 | rubric 0-2 |

### D3. Risk and integrity analysis, 12 points

| Criterion | Points | How |
| --- | ---: | --- |
| Risk recall over the eleven planted risks | 10 | recall x 10 |
| Finding quality: severity, remediation text, stable rule identifiers | 2 | rubric 0-2 |

### D4. Standards conformance and interoperability, 12 points

| Criterion | Points | How |
| --- | ---: | --- |
| CycloneDX output validates against the official schema for its declared version | 3 | pass 3, emitted but invalid 1, none 0 |
| SPDX 3.0.1 output emitted and well-formed JSON-LD | 2 | emitted and well-formed 2, emitted 1, none 0 |
| SARIF 2.1.0 output validates | 2 | pass 2, emitted 1, none 0 |
| Uses standard ML-BOM structures (`modelCard`, `data`, `services`, `formulation`, typed components) rather than only custom properties | 3 | rubric 0-3 |
| G7 AI SBOM minimum-element clusters carried in output | 2 | clusters touched / 7 x 2 |

### D5. Trustworthiness of the BOM artifact, 10 points

| Criterion | Points | How |
| --- | ---: | --- |
| Determinism: two runs on identical input produce identical output after removing timestamps, serial numbers and UUIDs | 4 | identical 4, differs only in ordering 2, differs 0 |
| Signing or attestation of the BOM (DSSE, Sigstore, JSF) | 3 | built in 3, documented external step 1, none 0 |
| Content digest or reproducible serial number | 1 | yes 1 |
| Diff or drift detection between two BOMs | 2 | built in 2, none 0 |

### D6. Scanner safety and tool hygiene, 12 points

| Criterion | Points | How |
| --- | ---: | --- |
| No repository code executed in default mode | 3 | no canary 3, canary only outside safe mode 1, canary in safe mode 0 |
| Path confinement: outside sentinel absent from output | 2 | absent 2, present 0 |
| Credential redaction: token sentinel absent from output | 2 | absent 2, present 0 |
| Offline operation: an offline mode exists and makes no network attempt, and the default mode sends no telemetry or version check (connections that serve the scan itself, such as advisory or model-hub lookups, are allowed) | 2 | offline quiet and no default telemetry 2, offline quiet but default phones home 1, documented only 1, none 0 |
| Dependency pinning and release provenance (lockfile, signed or attested releases) | 2 | rubric 0-2 |
| Security policy and scorecard (SECURITY.md, OpenSSF Scorecard) | 1 | rubric 0-1 |

### D7. Runtime reconciliation, 5 points

| Criterion | Points | How |
| --- | ---: | --- |
| Ingests runtime evidence and reports undeclared use against the BOM | 3 | both undeclared items surfaced 3, one 2, capability documented only 1 |
| Runtime inventory or interception capability (controller, proxy, gateway) | 2 | rubric 0-2 |

### D8. Operability, 4 points

| Criterion | Points | How |
| --- | ---: | --- |
| Policy gate with meaningful exit codes | 1 | yes 1 |
| CI integration (SARIF upload, action, pre-commit) | 1 | yes 1 |
| Default scan completes in under 120 seconds on the fixture | 1 | yes 1 |
| Documentation commands reproduce as written | 1 | yes 1 |

## 5. Grades and evidence labels

| Band | Full-stack score |
| --- | --- |
| A | 85 to 100 |
| B | 70 to 84 |
| C | 55 to 69 |
| D | 40 to 54 |
| F | below 40 |

A criterion graded from documentation (**D**) earns at most 60 percent of its points. A
criterion that could not be assessed (**U**) earns zero in the full-stack score and is
excluded from the in-scope denominator. The in-scope score divides the points earned by the
points available in the dimensions the tool claims, as recorded in `rubric/<tool>.yaml`.

## 6. Protocol

1. Install each tool at a pinned version into its own environment. Record the version.
2. Build the fixture with `build_fixture.py`. Record the manifest of SHA-256 digests.
3. Run each tool against the fixture root under `strace -f -e trace=connect`, with `HOME`
   set to an empty directory, a 20-minute timeout, and the canary directory emptied first.
   Run the default command twice for the determinism check, then the tool's offline or safe
   mode once.
4. Collect every output format the tool offers from the same input: CycloneDX, SPDX, SARIF
   and the tool's native JSON.
5. Score with `score.py`, which applies the matching rules below and writes
   `results/scores.json` and `RESULTS.md`. Manual rubric items live in `rubric/<tool>.yaml`
   with a one-line justification and evidence label each.

## 7. Matching rules

A labelled item matches a component when any of the item's tokens occurs, case-insensitively,
in the component's name, group, version, purl, bom-ref, description, properties, evidence
occurrences, external references or hashes. Each component satisfies at most one item.
Items with unique tokens are matched first; items whose tokens are shared (two filesystem
servers from the same package) take leftover components. Tool-native JSON is flattened to the
same searchable text. A risk matches a finding when the finding text contains one of the
risk's subject tokens and one of its reason tokens. Findings are read from SARIF results,
CycloneDX `vulnerabilities`, risk-bearing component properties and native JSON findings.

Determinism compares outputs after removing `serialNumber`, `metadata.timestamp`,
`creationInfo.created`, UUID-shaped strings and the run directory, and after sorting
components by bom-ref.

## 8. Threats to validity

- One synthetic fixture cannot estimate field accuracy. Recall here is recall on these
  labelled items, not a population estimate.
- Matching is by token. A tool that names a component differently from every token is
  under-credited; the raw outputs are kept so a reader can check.
- The benchmark lives in the repository of one graded tool (Nexus SymBiote). Every
  criterion is written so that any tool can earn it from standard artifacts, and the
  fixture carries no tool-specific declaration file such as `agent.yaml` or `.aibom.yaml`.
  Readers should still treat the authorship as a conflict of interest and re-run the harness.
- Tools that need resources this harness lacks (a Kubernetes cluster, a SaaS account, an
  LLM API key) are graded from documentation with the **D** label and capped accordingly.
- Tools run at their default settings. A tool with a strong non-default mode is credited
  only where the protocol runs that mode.

## 9. Reproduce

Tool environments live under one root, one per tool, at the pinned versions recorded in
`results/RESULTS.md`:

```bash
TOOLS=/path/to/tools
uv venv $TOOLS/agent-bom && uv pip install --python $TOOLS/agent-bom/bin/python 'agent-bom==0.115.3'
uv venv $TOOLS/ai-bom    && uv pip install --python $TOOLS/ai-bom/bin/python 'ai-bom==3.6.0'
uv venv $TOOLS/aisbom    && uv pip install --python $TOOLS/aisbom/bin/python 'aisbom-cli==1.7.0'
uv venv $TOOLS/cisco     && uv pip install --python $TOOLS/cisco/bin/python 'cisco-aibom[analysis]==1.10.1'
uv venv $TOOLS/nexus     && uv pip install --python $TOOLS/nexus/bin/python -e '.[cyclonedx]'
uv venv $TOOLS/scorer    && uv pip install --python $TOOLS/scorer/bin/python 'cyclonedx-python-lib[validation]' jsonschema pyyaml onnx numpy
git clone --depth 1 https://github.com/GenAI-Security-Project/aibom-generator $TOOLS/owasp/src && uv venv $TOOLS/owasp/venv && uv pip install --python $TOOLS/owasp/venv/bin/python -r $TOOLS/owasp/src/requirements.txt
mkdir -p $TOOLS/npm && (cd $TOOLS/npm && npm init -y >/dev/null && npm install '@cdxgen/cdxgen@13.8.0' '@wasmagent/agentbom-core@0.4.0')
```

Then build, run and score. The SARIF schema comes from `https://json.schemastore.org/sarif-2.1.0.json`.

```bash
$TOOLS/scorer/bin/python -I benchmarks/aibom-assurance/build_fixture.py --out build --canary-dir build/canary
python3 benchmarks/aibom-assurance/run_tools.py --fixture build/acme-support-agent --tools-root $TOOLS --out results/raw --canary-dir build/canary
$TOOLS/scorer/bin/python benchmarks/aibom-assurance/score.py --ground-truth build/ground_truth.json --raw results/raw --rubric benchmarks/aibom-assurance/rubric --out results --fixture build/acme-support-agent --sarif-schema sarif-2.1.0.json
```

Every command the runner executes is recorded in `results/raw/<tool>/<run>/command.txt`, with
`meta.json` holding exit code, duration, canary hits, fixture modifications and the egress
parsed from `strace.txt`. `results/evidence/` keeps a copy of those files without the strace
logs and key material.
