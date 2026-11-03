# Nexus SymBiote

[![CI](https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/codeql.yml/badge.svg)](https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/Hunzee-VC/Nexus-Symbiote)](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/LICENSE)

**An Agent Bill of Materials (AgentBOM) for AI agent supply chains.** Nexus SymBiote reads an agent project without running it, lists what the agent is built from — MCP servers, models, prompts and skills, retrieval sources, A2A cards, IDE agent settings and container images — flags supply-chain risks, catches drift between reviewed snapshots, and exports CycloneDX 1.7, SPDX 3.0.1, SARIF or native JSON.

## What a scan finds

The bundled [demo agent](https://github.com/Hunzee-VC/Nexus-Symbiote/tree/main/examples/demo-agent) is a small synthetic support assistant. Scanning it records 11 components across 9 types and these findings (risk score 33, below the default fail threshold of 50):

| Severity | Component | Finding |
| --- | --- | --- |
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

The full walkthrough, including validation, exports and ShadowScan import, is in [examples/README.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/examples/README.md).

## Install

Python 3.11+ on Linux is required (the CI matrix covers Ubuntu with Python 3.11–3.13). No release has been published yet, so install from a reviewed checkout with the hash-locked runtime:

```bash
git clone https://github.com/Hunzee-VC/Nexus-Symbiote.git
cd Nexus-Symbiote
git checkout --detach REVIEWED_COMMIT_SHA
python -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements-action.lock
python -m pip install --no-deps --no-build-isolation .
nexus-symbiote --version
```

Optional extras are `.[sigstore]`, `.[cyclonedx]` and `.[all]`. For development, use `make install-locked` (see [CONTRIBUTING.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CONTRIBUTING.md)).

## Quick start

```bash
# Inventory a project; --no-project-policy stops an untrusted checkout from choosing your policy
nexus-symbiote scan /path/to/agent-project --no-project-policy -o agentbom.json
nexus-symbiote summary agentbom.json

# Check completeness and integrity against the project, then apply the risk gate
nexus-symbiote validate agentbom.json --project /path/to/agent-project --no-project-policy
nexus-symbiote risk agentbom.json --threshold 50 --no-project-policy

# Fail CI when a new snapshot drifts from a reviewed one
nexus-symbiote diff reviewed.json agentbom.json --fail-on-alert

# Import a Nexus-ShadowScan discovery report
nexus-symbiote import-shadowscan shadowscan-report.json -o imported-agentbom.json --report-only
```

Every command is offline by default: no network, name resolution or subprocesses. Only `discover-mcp`, `advisories` and `verify-live` reach outside local files, and only with `--live`. Exit code `0` means the command completed in its selected mode, `1` means a gate or verification failed, and `2` is a usage error.

## What it covers

| Area | What is recorded |
| --- | --- |
| Collectors | `mcp`, `model`, `prompt`, `rag`, `registry`, `a2a`, `ide_agents` and `shadowscan` (select with `--scanner`) |
| Model files | Whole-file hashes, SafeTensors structure checks, pickle detection without loading, optional Sigstore verification |
| MCP | Client and server references, pinned versions, transports, endpoints and tool fingerprints |
| Drift | Component, capability, endpoint, integrity and dependency changes between snapshots |
| Policy gates | Completeness, integrity and risk decisions under a policy you choose |
| Exports | Native JSON, CycloneDX 1.7, SPDX 3.0.1 and SARIF (`-f`), plus VEX via `vex` |
| Runtime | Ed25519-signed snapshots, approvals and trust status for a reference gateway (`runtime`) |

All commands are listed in the [CLI reference](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/cli-reference.md).

## What a scan does not prove

A scan is an inventory. It does not show that a model is benign, that a tool's backend matches its description, or that every agent action was mediated. Unknown evidence never passes a gate, and failed or skipped collection is reported as a gap rather than as absence. Read [what results do and do not establish](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/security-model.md#what-results-do-and-do-not-establish) before using results in an approval process, and treat exported BOMs as sensitive: they can reveal infrastructure, permissions and endpoints.

## GitHub Action

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

The Action ignores policy files in the scanned checkout and fails on collection errors even when validation is disabled. A `risk-threshold` of `0` disables the risk gate. For SARIF upload, add `security-events: write` to the job. Don't use `pull_request_target` to scan untrusted PRs with credentials. Inputs and outputs are listed in [action.yml](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/action.yml).

## Documentation

| Topic | Link |
| --- | --- |
| Tutorial | [Scanning a public agent project](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/tutorials/scanning-a-public-agent.md) |
| Security model and result limits | [Security model](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/security-model.md) · [SECURITY.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SECURITY.md) |
| Runtime and deployment evidence | [Runtime assurance](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/runtime-assurance.md) · [Deployment evidence](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/deployment-evidence.md) |
| Discovery and source inventory | [ShadowScan integration](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/shadowscan-integration.md) · [TypeScript inventory](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/typescript-inventory.md) · [Source binding](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/verification-source-binding.md) |
| Offline and live modes | [Offline and live modes](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/offline-and-live-modes.md) |
| Development and controls | [CONTRIBUTING.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CONTRIBUTING.md) · [Repository controls](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/repository-controls.md) |
| Releases and changes | [Releasing](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/releasing.md) · [CHANGELOG.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CHANGELOG.md) · [ROADMAP.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/ROADMAP.md) |
| Benchmarks | [Security corpus](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/benchmarks/README.md) · [Inventory corpus](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/benchmarks/inventory/README.md) |

## Project status

Nexus SymBiote is **alpha**: APIs, formats and policy semantics may change, and there is no SLA. [Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) is the companion discovery engine; SymBiote adds local artifact and supply-chain verification. Open hosted-verification and publication prerequisites are tracked in [issue #74](https://github.com/Hunzee-VC/Nexus-Symbiote/issues/74).

To report a security issue, see [SECURITY.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SECURITY.md). For bugs and feature requests, use [GitHub Issues](https://github.com/Hunzee-VC/Nexus-Symbiote/issues). Governance is described in [GOVERNANCE.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/GOVERNANCE.md).

## License

[MIT](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/LICENSE) — Copyright (c) 2026 AISecNomad.
