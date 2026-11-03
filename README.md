<p align="center">
  <img src="Symbiote.jpeg" alt="Nexus SymBiote — Agent Bill of Materials for AI supply chains" width="700">
</p>

<h1 align="center">Nexus SymBiote</h1>

<p align="center">
  <strong>Know what your AI agent is built from — before you trust it.</strong>
</p>

<p align="center">
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/ci.yml"><img src="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/codeql.yml"><img src="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Hunzee-VC/Nexus-Symbiote" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+">
</p>

---

## Why

AI agents are assembled from MCP servers, foundation models, system prompts, retrieval sources, A2A agent cards, IDE extensions, and container images. Together these form a **supply chain** — but unlike traditional software, no one inventories it. A single unpinned MCP server, a swapped model weight file, or a drifted endpoint can silently change what your agent does and who it talks to.

Traditional SBOMs track packages and libraries. They don't cover agent-specific surfaces: tool definitions, prompt instructions, model provenance, or the trust boundaries between components. **You can't secure what you can't see.**

Nexus SymBiote generates an **Agent Bill of Materials (AgentBOM)** — a complete, verifiable inventory of everything an AI agent is built from — so you can review it, gate it, and catch when it changes.

## What

Nexus SymBiote reads an agent project **without running it**, lists what the agent is built from, flags supply-chain risks, catches drift between reviewed snapshots, and exports standard formats:

- **Inventories** MCP servers, models, prompts, retrieval sources, A2A cards, IDE agent settings, container images, and package dependencies
- **Scores risk** with configurable policy gates (completeness, integrity, risk threshold)
- **Detects drift** between snapshots — catches endpoint swaps, version unpinning, capability escalation, and dependency substitution
- **Exports** CycloneDX 1.7, SPDX 3.0.1, SARIF, VEX, or native JSON
- **Runs offline** by default — no network, no subprocess execution, no trust in the scanned project

## See it in action

The bundled [demo agent](examples/demo-agent) is a small synthetic support assistant. Scanning it records 11 components across 9 types with these findings (risk score 33, below the default fail threshold of 50):

| Severity | Component | Finding |
|----------|-----------|---------|
| high | `memory` MCP server | Unpinned package reference (`@latest`) |
| high | `models/intent-classifier.safetensors` | No verified, artifact-bound signature |
| high | `ollama/ollama:latest` container image | No immutable digest pin |
| medium | `notes` and `memory` MCP servers | stdio transport: each runs as a local process |
| medium | `product-notes` retrieval source | No declared content-filtering control |

Float a pinned server and repoint an endpoint, and `diff --fail-on-alert` exits 1:

```text
[CRITICAL] Critical change in 'tickets': MCP server endpoint changed. Review before execution. ...
[HIGH] High change in 'notes': Version changed: 2025.8.21 → None; Version pin removed ...
```

The full walkthrough, including validation, exports, and ShadowScan import, is in [examples/README.md](examples/README.md).

---

## Table of contents

- [Getting started](#getting-started)
- [How it works](#how-it-works)
- [Coverage](#coverage)
- [GitHub Action](#github-action)
- [What a scan does not prove](#what-a-scan-does-not-prove)
- [Documentation](#documentation)
- [Project status](#project-status)
- [Contributing](#contributing)
- [License](#license)

## Getting started

### Prerequisites

- Python 3.11+ on Linux (CI covers Ubuntu with Python 3.11–3.13)
- Git (for source installation)

### Install

No release has been published yet. Install from a reviewed checkout with hash-locked dependencies:

```bash
git clone https://github.com/Hunzee-VC/Nexus-Symbiote.git
cd Nexus-Symbiote
git checkout --detach REVIEWED_COMMIT_SHA
python -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements-action.lock
python -m pip install --no-deps --no-build-isolation .
nexus-symbiote --version
```

Optional extras: `.[sigstore]` for Sigstore verification, `.[cyclonedx]` for CycloneDX library integration, `.[all]` for both. For development, use `make install-locked` (see [CONTRIBUTING.md](CONTRIBUTING.md)).

### Quick start

```bash
# Inventory a project (--no-project-policy prevents an untrusted checkout from choosing your policy)
nexus-symbiote scan /path/to/agent-project --no-project-policy -o agentbom.json
nexus-symbiote summary agentbom.json

# Check completeness and integrity, then apply the risk gate
nexus-symbiote validate agentbom.json --project /path/to/agent-project --no-project-policy
nexus-symbiote risk agentbom.json --threshold 50 --no-project-policy

# Fail CI when a new snapshot drifts from a reviewed one
nexus-symbiote diff reviewed.json agentbom.json --fail-on-alert

# Import a Nexus-ShadowScan discovery report
nexus-symbiote import-shadowscan shadowscan-report.json -o imported-agentbom.json --report-only
```

Every command is offline by default: no network, no name resolution, no subprocesses. Only `discover-mcp`, `advisories`, and `verify-live` reach outside local files, and only with `--live`. Exit codes: `0` = success, `1` = gate/verification failed, `2` = usage error.

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│                        nexus-symbiote scan                      │
│                                                                 │
│   Agent Project          Collectors              Output         │
│  ┌──────────────┐    ┌───────────────┐    ┌──────────────────┐  │
│  │ .mcp.json    │───▶│ mcp           │───▶│                  │  │
│  │ models/      │───▶│ model         │    │  AgentBOM        │  │
│  │ prompts/     │───▶│ prompt        │    │  (native JSON)   │  │
│  │ rag configs  │───▶│ rag           │    │                  │  │
│  │ agent cards  │───▶│ a2a           │    │  → CycloneDX 1.7 │  │
│  │ IDE settings │───▶│ ide_agents    │    │  → SPDX 3.0.1    │  │
│  │ registries   │───▶│ registry      │    │  → SARIF          │  │
│  │ shadowscan   │───▶│ shadowscan    │    │  → VEX            │  │
│  └──────────────┘    └───────────────┘    └──────────────────┘  │
│                                                                 │
│   validate ──▶ completeness + integrity                         │
│   risk     ──▶ finding scores + policy gate                     │
│   diff     ──▶ snapshot comparison + drift alerts               │
└─────────────────────────────────────────────────────────────────┘
```

1. **Collect** — Eight built-in collectors read project files without executing anything. Each extracts component identities, versions, hashes, endpoints, and trust metadata.
2. **Assemble** — Results merge into an AgentBOM: a structured inventory with component types, relationships, risk findings, and completeness metadata.
3. **Verify** — `validate` checks completeness and integrity against the source project. `risk` scores findings and applies a configurable threshold gate.
4. **Compare** — `diff` compares two snapshots and flags security-relevant changes: endpoint swaps, version unpinning, capability changes, and dependency substitution.
5. **Export** — Native JSON, CycloneDX 1.7, SPDX 3.0.1, SARIF, or VEX. Standard formats integrate with existing security toolchains.

## Coverage

| Area | What is recorded |
|------|-----------------|
| **Collectors** | `mcp`, `model`, `prompt`, `rag`, `registry`, `a2a`, `ide_agents`, and `shadowscan` (select with `--scanner`) |
| **Model files** | Whole-file hashes, SafeTensors structure checks, pickle detection without loading, optional Sigstore verification |
| **MCP** | Client and server references, pinned versions, transports, endpoints, and tool fingerprints |
| **Drift** | Component, capability, endpoint, integrity, and dependency changes between snapshots |
| **Policy gates** | Completeness, integrity, and risk decisions under a policy you choose |
| **Exports** | Native JSON, CycloneDX 1.7, SPDX 3.0.1, and SARIF (`-f`), plus VEX via `vex` |
| **Runtime** | Ed25519-signed snapshots, approvals, and trust status for a reference gateway (`runtime`) |

All commands are listed in the [CLI reference](docs/cli-reference.md).

## GitHub Action

Pin the Action to a reviewed 40-character commit SHA:

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

The Action ignores policy files in the scanned checkout and fails on collection errors even when validation is disabled. A `risk-threshold` of `0` disables the risk gate. For SARIF upload, add `security-events: write` to the job. Don't use `pull_request_target` to scan untrusted PRs with credentials. Inputs and outputs are listed in [action.yml](action.yml).

## What a scan does not prove

A scan is an inventory, not a verdict. It does not show that a model is benign, that a tool's backend matches its description, or that every agent action was mediated. Unknown evidence never passes a gate, and failed or skipped collection is reported as a gap rather than as absence.

Read [what results do and do not establish](docs/security-model.md#what-results-do-and-do-not-establish) before using results in an approval process. Treat exported BOMs as sensitive: they can reveal infrastructure, permissions, and endpoints.

## Documentation

| Topic | Link |
|-------|------|
| Security model and result limits | [Security model](docs/security-model.md) · [SECURITY.md](SECURITY.md) |
| CLI commands and options | [CLI reference](docs/cli-reference.md) |
| Runtime and deployment evidence | [Runtime assurance](docs/runtime-assurance.md) · [Deployment evidence](docs/deployment-evidence.md) |
| Discovery and source inventory | [ShadowScan integration](docs/shadowscan-integration.md) · [TypeScript inventory](docs/typescript-inventory.md) · [Source binding](docs/verification-source-binding.md) |
| Offline and live modes | [Offline and live modes](docs/offline-and-live-modes.md) |
| npm lockfile evidence | [npm lockfile evidence](docs/npm-lockfile-evidence.md) |
| Development and controls | [CONTRIBUTING.md](CONTRIBUTING.md) · [Repository controls](docs/repository-controls.md) |
| Releases and changes | [Releasing](docs/releasing.md) · [CHANGELOG.md](CHANGELOG.md) · [ROADMAP.md](ROADMAP.md) |
| Benchmarks | [Security corpus](benchmarks/README.md) · [Inventory corpus](benchmarks/inventory/README.md) |
| Tutorials | [Scanning a public agent](docs/tutorials/scanning-a-public-agent.md) |

## Project status

Nexus SymBiote is **alpha** — APIs, formats, and policy semantics may change. There is no SLA.

[Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) is the companion discovery engine; SymBiote adds local artifact and supply-chain verification. Open hosted-verification and publication prerequisites are tracked in [issue #74](https://github.com/Hunzee-VC/Nexus-Symbiote/issues/74).

See the [ROADMAP](ROADMAP.md) for planned work.

## Contributing

Contributions are welcome — especially tested scanner coverage, documentation, and regression fixtures.

- **Bugs and features:** [GitHub Issues](https://github.com/Hunzee-VC/Nexus-Symbiote/issues)
- **Security vulnerabilities:** See [SECURITY.md](SECURITY.md)
- **Development setup and review contract:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Governance and decisions:** [GOVERNANCE.md](GOVERNANCE.md)
- **Code of conduct:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- **Support and troubleshooting:** [SUPPORT.md](SUPPORT.md)

## License

[MIT](LICENSE) — Copyright (c) 2026 AISecNomad.
