<p align="center">
  <img src="https://raw.githubusercontent.com/Hunzee-VC/Nexus-Symbiote/main/docs/assets/nexus-symbiote-banner.jpg" alt="Nexus SymBiote: an Agent Bill of Materials for AI agent supply chains">
</p>

<h1 align="center">Nexus SymBiote</h1>

<p align="center">
  <strong>Know what your AI agents are built from, gate them on evidence, and catch drift before it ships.</strong>
</p>

<p align="center">
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/ci.yml"><img src="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/codeql.yml"><img src="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/pyproject.toml"><img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&amp;logoColor=white" alt="Python 3.11 | 3.12 | 3.13"></a>
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Hunzee-VC/Nexus-Symbiote" alt="MIT license"></a>
  <a href="#project-status"><img src="https://img.shields.io/badge/status-alpha-orange" alt="Status: alpha"></a>
  <a href="#what-it-produces"><img src="https://img.shields.io/badge/exports-CycloneDX%201.7%20%7C%20SPDX%203.0.1%20%7C%20SARIF%20%7C%20VEX-0B7285" alt="Exports: CycloneDX 1.7, SPDX 3.0.1, SARIF, VEX"></a>
</p>

<p align="center">
  <a href="#why"><b>Why</b></a> ·
  <a href="#what"><b>What</b></a> ·
  <a href="#how"><b>How</b></a> ·
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/README.md"><b>Docs</b></a> ·
  <a href="#project-status"><b>Status</b></a>
</p>

Nexus SymBiote generates an **Agent Bill of Materials (AgentBOM)**: an evidence-backed inventory of the MCP servers, models, instructions and skills, retrieval sources, A2A agent cards, IDE agent settings and container images that an AI agent is assembled from. It reads a project **without running it**, flags supply-chain risk, fails CI when a reviewed agent drifts, and exports CycloneDX 1.7, SPDX 3.0.1, SARIF and VEX.

```bash
nexus-symbiote scan ./my-agent --no-project-policy -o agentbom.json   # inventory, offline
nexus-symbiote risk agentbom.json --no-project-policy --threshold 50   # gate on risk
nexus-symbiote diff reviewed.json agentbom.json --fail-on-alert        # gate on drift
```

> [!NOTE]
> **Alpha.** Interfaces, formats and policy semantics may change, and no package has been published yet. Install from a reviewed commit, as shown under [How](#how).

## Contents

- **[Why](#why)**: [the agent supply chain](#the-agent-supply-chain-is-unaccounted-for) · [what goes wrong](#what-goes-wrong) · [design principles](#design-principles)
- **[What](#what)**: [what it inventories](#what-it-inventories) · [what it checks](#what-it-checks) · [what it produces](#what-it-produces) · [the demo agent](#see-it-on-the-demo-agent) · [what a scan does not prove](#what-a-scan-does-not-prove)
- **[How](#how)**: [install](#install-from-reviewed-source) · [try it](#try-it-in-60-seconds) · [scan your agent](#scan-your-own-agent) · [gate drift in CI](#gate-drift-in-ci) · [GitHub Action](#github-action) · [pre-commit](#pre-commit) · [policy](#configure-policy) · [offline and live modes](#offline-and-live-modes) · [how it works](#how-it-works) · [exit codes](#exit-codes)
- **[Documentation](#documentation)** · **[Project status](#project-status)** · **[Security](#security)** · **[Contributing](#contributing)** · **[Citation](#citation)** · **[License](#license)**

## Why

**AI agents are assembled from parts you did not write, and most of those parts never appear in a software bill of materials.**

### The agent supply chain is unaccounted for

An agent's behavior is set by its configuration as much as by its code: which MCP servers it launches and at what version, which tools those servers describe, which model weights it loads, which instruction and skill files steer it, which retrieval sources feed it, which agents it delegates to, and what its coding assistant may execute. Each of these is a supply-chain dependency, and each can change without a code review. A floating `@latest` tag, a repointed endpoint, a rewritten tool description or a swapped weight file changes what the agent does and whom it talks to.

Package SBOMs were built for libraries. They don't record tool descriptors, instruction files, model serialization formats, agent endpoints or delegated permissions, so the parts that decide what an agent *can do* go unreviewed. The [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) lists agentic supply chain vulnerabilities (ASI04) among the top risks for this reason.

### What goes wrong

| Risk | What it looks like in a repository | What Nexus SymBiote records |
| --- | --- | --- |
| Floating dependencies | An MCP server launched as `@latest`; a container image without a digest | Unpinned-version and missing-digest findings |
| Tool rug pulls | A tool's description or schema changes after it was reviewed | RFC 8785 tool fingerprints, and drift alerts in `diff` |
| Endpoint repointing | An MCP endpoint moves to another host, or an A2A card URL moves to plain HTTP | A drift alert: critical for the MCP endpoint, high for the A2A card |
| Executable model files | A pickle-based checkpoint, or a `.safetensors` file that is not one | Format classification without loading, and SafeTensors header validation |
| Unsigned weights | A model file with no artifact-bound signature | An `UNKNOWN` integrity verdict until your signer policy verifies it |
| Hidden instructions | Bidirectional or zero-width characters in `CLAUDE.md` or `AGENTS.md` | Invisible-character findings on the instruction file |
| Over-broad agent permissions | An IDE agent granted `Bash(*)` or a permissive default mode | Declared permissions, and a drift alert when they widen |
| Credential exposure | Tokens in MCP environment blocks or connection strings | Environment variables recorded by name, never by value; known secret patterns redacted from free text |

### Design principles

1. **Never runs what it inspects.** Collection is static. It does not execute project modules, model loaders, repository hooks or MCP launch commands.
2. **Offline by default, enforced at run time.** Every command refuses name resolution, network connections and process creation unless you opt into live mode for one of three commands.
3. **Unknown is not safe.** Missing evidence, failed reads and skipped collectors are recorded as gaps, and default gates fail on them instead of passing silently.
4. **Claims are not evidence.** Declared, observed, approved and mediated states stay separate. A supplier label or an adjacent signature file never upgrades trust by itself, and `--no-project-policy` stops an untrusted checkout from choosing its own gates.
5. **Standards first.** One native inventory exports to CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0 and VEX. Standard exports carry the full native inventory in a digest-bound extension, so a consumer that keeps it loses nothing.

## What

**An AgentBOM: one evidence-backed inventory of an agent, and the gates, drift checks and exports built on it.**

### What it inventories

Eight built-in collectors read declared configuration and artifacts from the project directory. Select a subset with a repeated `--scanner` option; collectors you leave out are recorded as unknown, not as clean.

| Collector | Reads | Records |
| --- | --- | --- |
| `mcp` | `.mcp.json`, `mcp.json`, `.claude/mcp.json`, `.cursor/mcp.json`, `claude_desktop_config.json`, and MCP server source in Python and TypeScript | MCP clients and servers, launchers and pinned versions, transports, endpoints, tool fingerprints |
| `model` | `.safetensors`, `.gguf`, `.ggml`, `.onnx` and pickle-family files (`.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.joblib`), with their configuration files | Whole-file SHA-256, serialization safety, SafeTensors structure, signature status |
| `prompt` | `CLAUDE.md`, `AGENTS.md`, `CODEX.md`, Copilot and Codex instructions, `system_prompt.*`, `.claude/skills/`, `.claude/commands/` | Instruction and skill digests, hidden-character findings |
| `rag` | `rag_config.*`, `retrieval_config.json`, `vector_store_config.json`, knowledge-base configuration | Declared retrieval sources and their controls |
| `registry` | `package.json` and `package-lock.json`, `requirements*.txt`, `pyproject.toml`, `Dockerfile`, `docker-compose.yml` | AI-related package identities, pins and lockfile integrity; container images and digest pins |
| `a2a` | `.well-known/agent.json`, `agent-card.json` and A2A client configuration | A2A agent cards, endpoints and declared authentication |
| `ide_agents` | Settings for Claude Code, Cursor, Codex, Windsurf, Cline, GitHub Copilot and others | Coding-agent configuration and declared permissions |
| `shadowscan` | A [Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) report (`shadowscan.json`, `.shadowscan/report.json`) | Imported discovery claims, kept separate from local evidence |

Dependency directories, virtual environments and Git metadata are out of scope and recorded as exclusions. Every inventory carries its own coverage record: which collectors ran, what each completed, and what failed.

### What it checks

| Command | Question it answers |
| --- | --- |
| `validate` | Is the inventory complete, and do hashes, signatures and MCP source bindings still match the project? |
| `risk` | What are the findings, and does the score or the worst severity cross your gate? |
| `diff` | What changed since the reviewed snapshot, and is any change security-relevant? |
| `verify-artifact`, `verify-discovery` | Do these exact bytes match a trusted digest, Sigstore identity or ShadowScan report? |
| `blast-radius` | Which agents and components are associated with a compromised component? |
| `runtime keygen`, `runtime sign`, `runtime verify` | Are signed snapshots, approvals and trust statements valid for a gateway that mediates tool calls? |
| `discover-mcp`, `verify-live`, `advisories` | What does a running MCP server actually serve, and do exact package versions have known advisories? (live mode) |

The [CLI reference](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/cli-reference.md) documents every command and option, and a test keeps it in sync with the CLI.

### What it produces

| Output | How to get it | Use it for |
| --- | --- | --- |
| Native AgentBOM JSON | `scan` (default) | The full-fidelity record, defined by the [AgentBOM schema](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/schemas/README.md) |
| CycloneDX 1.7 | `scan -f cyclonedx` | SBOM tooling; validated against the pinned official schema |
| SPDX 3.0.1 | `scan -f spdx` | SPDX tooling; validated against the pinned official schema |
| SARIF 2.1.0 | `scan -f sarif` | GitHub code scanning and other SARIF viewers |
| CycloneDX VEX | `vex` | Findings marked `in_triage`, with no exploitability claim |

The CycloneDX and SPDX exports embed the native inventory in a digest-bound extension, with a report of selected security-relevant fields that the standard format cannot carry. Keep that extension to recover full semantics.

### See it on the demo agent

The bundled [demo agent](https://github.com/Hunzee-VC/Nexus-Symbiote/tree/main/examples/demo-agent) is a small synthetic support assistant. Scanning it records 11 components across 9 types and six findings. The risk score of 33 is below the default fail threshold of 50, so the gate passes with a warning:

| Severity | Component | Finding |
| --- | --- | --- |
| high | `memory` MCP server | Unpinned package reference (`@latest`) |
| high | `models/intent-classifier.safetensors` | No verified, artifact-bound signature |
| high | `ollama/ollama:latest` container image | No immutable digest pin |
| medium | `notes` and `memory` MCP servers | stdio transport: each runs as a local process |
| medium | `product-notes` retrieval source | No declared content-filtering control |

Float the pinned `notes` server and repoint the `tickets` endpoint, and `diff --fail-on-alert` exits 1:

```text
Security Alerts:
  [CRITICAL] Critical change in 'tickets': MCP server endpoint changed. Review before execution. ...
  [HIGH] High change in 'notes': Version changed: 2025.8.21 → None; Version pin removed ...
```

The [examples walkthrough](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/examples/README.md) reproduces both results and adds validation, exports and a ShadowScan import, all offline.

### What a scan does not prove

A scan is an inventory, not a verdict. It does not show that a model is benign, that a tool's backend matches its description, or that every agent action was mediated. A command can write evidence and still fail its gate, and exit code `0` from report-only output or a skipped gate is not an approval. Read [what results do and do not establish](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/security-model.md#what-results-do-and-do-not-establish) before you use results in an approval process.

Treat exported BOMs as sensitive. They can reveal infrastructure, permissions, endpoints and instruction fingerprints.

## How

**Install from a reviewed commit, inventory the agent, then let CI hold the line.**

### Install from reviewed source

Requires Python 3.11 or later on Linux. CI covers Ubuntu with Python 3.11, 3.12, 3.13 and 3.14; confined file operations need POSIX primitives, and other platforms fail closed. No release has been published yet, so install a commit you have reviewed, with the hash-locked runtime:

```bash
git clone https://github.com/Hunzee-VC/Nexus-Symbiote.git
cd Nexus-Symbiote
git checkout --detach REVIEWED_COMMIT_SHA
python -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements-action.lock
python -m pip install --no-deps --no-build-isolation .
nexus-symbiote --version
```

Optional extras are `.[sigstore]` for Sigstore verification, `.[cyclonedx]` for CycloneDX library integration, and `.[all]`. For development, run `make install-locked` (see [CONTRIBUTING.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CONTRIBUTING.md)).

### Try it in 60 seconds

From the checkout, inventory the bundled demo agent. Nothing is executed and no network is used:

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote summary demo.aibom.json
nexus-symbiote risk demo.aibom.json --no-project-policy
nexus-symbiote validate demo.aibom.json --project examples/demo-agent --no-project-policy
```

`validate` exits 1 on purpose. Completeness passes, but the model's integrity stays unknown because no signer policy was supplied, and unknown evidence never passes. An inventory can be complete and still not be approvable.

### Scan your own agent

```bash
# Inventory; --no-project-policy stops an untrusted checkout from choosing your policy
nexus-symbiote scan /path/to/agent --no-project-policy -o agentbom.json

# Check completeness and integrity against the project, then apply the risk gate
nexus-symbiote validate agentbom.json --project /path/to/agent --no-project-policy
nexus-symbiote risk agentbom.json --project /path/to/agent --no-project-policy --threshold 50

# Export a standard format from a fresh collection
nexus-symbiote scan /path/to/agent --no-project-policy -f cyclonedx -o agentbom.cdx.json
```

With `--project`, `risk` collects fresh evidence from the checkout and refuses to score a supplied BOM that disagrees with it. The [public-agent tutorial](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/tutorials/scanning-a-public-agent.md) walks through a real repository end to end.

### Gate drift in CI

Record a reviewed snapshot once, then compare every new collection with it:

```bash
nexus-symbiote baseline /path/to/agent -o reviewed.json      # written only if the scan gate passes
nexus-symbiote scan /path/to/agent --no-project-policy -o agentbom.json
nexus-symbiote diff reviewed.json agentbom.json --fail-on-alert
```

`--fail-on-alert` fails on any security-relevant change rated medium or higher, such as a new endpoint, a removed version pin, a replaced tool, a same-version package swap or a widened agent permission. A baseline is unsigned: review and authenticate it before you treat it as an approval.

### GitHub Action

Pin the Action to a reviewed 40-character commit:

```yaml
name: Agent inventory
on: [push, pull_request]
permissions:
  contents: read
jobs:
  inventory:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          persist-credentials: false
      - uses: Hunzee-VC/Nexus-Symbiote@<reviewed-40-character-commit-sha>
        with:
          scan-path: .
          output-file: agentbom.json
          validate: 'true'
          risk-check: 'true'
          risk-threshold: '50'
          sarif-upload: 'false'
```

The Action installs its own hash-locked runtime, ignores policy files in the scanned checkout, collects once and fails on collection errors even when validation is disabled. A `risk-threshold` of `0` disables the risk gate. For SARIF upload, set `sarif-upload: 'true'` and add `security-events: write` to the job. Don't use `pull_request_target` to scan untrusted pull requests with credentials. Inputs and outputs are listed in [action.yml](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/action.yml).

### pre-commit

The repository ships two [pre-commit](https://pre-commit.com/) hooks: one collects an inventory, the next applies the risk gate to it.

```yaml
repos:
  - repo: https://github.com/Hunzee-VC/Nexus-Symbiote
    rev: <reviewed-40-character-commit-sha>
    hooks:
      - id: nexus-symbiote-scan
      - id: nexus-symbiote-risk
```

The hooks write `.nexus-symbiote-aibom.json` in your repository, so add it to `.gitignore`. pre-commit installs the hook environment from the package's declared version ranges rather than the hash-locked set; use the Action or a source install when you need locked dependencies.

### Configure policy

`nexus-symbiote init` writes this `.nexus-symbiote.yaml` for a trusted project:

```yaml
# Nexus SymBiote policy; malformed or unsupported settings fail closed.
version: "1.0"
scan:
  scanners: ["mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"]
  exclude_paths: ["node_modules", ".git", "__pycache__", ".venv"]
  failure_mode: "error"
risk:
  fail_threshold: 50.0
  warn_threshold: 25.0
  fail_on_severity: "critical"
  ignore_categories: []
validate:
  require_completeness: true
  require_integrity: true
  minimum_assurance_level: "declared"
output:
  default_format: "json"
```

`scan`, `validate` and `risk` read this file by default. Pass `--no-project-policy` whenever the checkout is not yours; the GitHub Action always does. The risk score is the uncapped sum of finding weights (critical 10, high 7, medium 4, low 1), and any critical finding fails the default gate regardless of the score.

### Offline and live modes

|  | Offline (default) | Live (`--live` before the command) |
| --- | --- | --- |
| Name resolution, connections, subprocesses | Refused | Allowed only for the three live commands |
| `discover-mcp`, `advisories`, `verify-live` | Refused with exit 2 and a hint | Run against fixed or operator-pinned targets, with deadlines and size limits |
| Every other command | Runs | Runs, and stays offline |

`NEXUS_SYMBIOTE_MODE=live` selects live mode for a CI job. A project's own policy file can never select the mode. The guard is a tripwire, not a sandbox, so add OS-level isolation where you need a hard boundary. Details are in [offline and live modes](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/offline-and-live-modes.md).

### How it works

```text
             ┌──────────────────────────────────────────────┐
  agent      │ 8 static collectors: nothing is executed     │
  project ──>│ mcp · model · prompt · rag · registry        │
 (read-only) │ a2a · ide_agents · shadowscan                │
             └──────────────────────┬───────────────────────┘
                                    v
             ┌──────────────────────────────────────────────┐
             │ AgentBOM (native JSON)                       │
             │ components · relationships · findings        │
             │ coverage, gaps and assurance for every claim │
             └──────┬───────────────┬───────────────┬───────┘
                    v               v               v
             validate · risk       diff          exports
             gates, exit 0/1   drift alerts   CycloneDX · SPDX
                                               SARIF · VEX
```

1. **Collect.** Each collector reads its surfaces through confined, size-bounded, no-follow file reads and returns components, findings and its own coverage status.
2. **Assemble.** Results merge into one AgentBOM with typed components, relationships, findings and a completeness record. Every claim keeps its assurance level: declared, observed or verified.
3. **Gate.** `validate` checks completeness and integrity, re-collecting evidence when you pass `--project`; `risk` scores findings against your policy. Unknown evidence fails closed.
4. **Compare.** `diff` compares two snapshots semantically and rates each change, so CI can fail on drift.
5. **Export.** Standard formats are generated from the same collection, so the native inventory and every export describe the same evidence.

### Exit codes

| Exit | Meaning |
| --- | --- |
| `0` | The command completed and every requested gate passed |
| `1` | A gate or check failed: risk, integrity, digest or signature mismatch, `diff --fail-on-alert`, incomplete collection, or unreadable input |
| `2` | Usage error, including a live command run in offline mode |

## Documentation

The [documentation hub](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/README.md) organizes every guide by Why, What and How. Start here:

| If you want to… | Read |
| --- | --- |
| Understand the trust model and what results establish | [Security model](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/security-model.md) |
| Run the full offline demo | [Examples walkthrough](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/examples/README.md) |
| Scan a real project end to end | [Scanning a public agent](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/tutorials/scanning-a-public-agent.md) |
| Look up a command or option | [CLI reference](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/cli-reference.md) |
| Import Nexus-ShadowScan discovery | [ShadowScan integration](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/shadowscan-integration.md) |
| Mediate tool calls with signed contracts | [Runtime assurance](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/runtime-assurance.md) |
| Release or verify a release | [Releasing](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/releasing.md) · [Repository controls](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/repository-controls.md) |

## Project status

Nexus SymBiote is **alpha** with a single maintainer: APIs, formats and policy semantics may change, and there is no SLA. Hosted CI, including CodeQL, runs on every push and pull request. Branch protection and PyPI trusted publishing remain open in [issue #74](https://github.com/Hunzee-VC/Nexus-Symbiote/issues/74). Planned work is in the [roadmap](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/ROADMAP.md) and changes are in the [changelog](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CHANGELOG.md).

[Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) is the companion discovery engine. It finds agents across many surfaces, and Nexus SymBiote turns its reports into AgentBOMs and adds local artifact and supply-chain verification.

## Security

Report vulnerabilities privately as described in [SECURITY.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SECURITY.md), never in a public issue. Keep credentials, private inventories and customer data out of reports.

## Contributing

Contributions are welcome, especially tested collector coverage, regression fixtures and documentation.

- **Development setup and review contract:** [CONTRIBUTING.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CONTRIBUTING.md)
- **Bugs and feature requests:** [GitHub Issues](https://github.com/Hunzee-VC/Nexus-Symbiote/issues)
- **Questions and troubleshooting:** [SUPPORT.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SUPPORT.md)
- **Decisions and maintainers:** [GOVERNANCE.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/GOVERNANCE.md) · [MAINTAINERS.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/MAINTAINERS.md)
- **Code of conduct:** [CODE_OF_CONDUCT.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CODE_OF_CONDUCT.md)

## Citation

If you use Nexus SymBiote in research or tooling, cite it with the metadata in [CITATION.cff](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CITATION.cff), or use **Cite this repository** on GitHub.

## License

[MIT](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/LICENSE). Copyright (c) 2026 Emmanuel Dahunsi (AISecNomad).
