<h1 align="center">
  Nexus SymBiote
</h1>

<p align="center">
  <a href="https://github.com/aisecnomad/nexus-symbiote/actions/workflows/ci.yml"><img src="https://github.com/aisecnomad/nexus-symbiote/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/aisecnomad/nexus-symbiote/actions/workflows/codeql.yml"><img src="https://github.com/aisecnomad/nexus-symbiote/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://pypi.org/project/nexus-symbiote/"><img src="https://img.shields.io/pypi/v/nexus-symbiote?color=blue" alt="PyPI version"></a>
  <a href="https://pypi.org/project/nexus-symbiote/"><img src="https://img.shields.io/pypi/pyversions/nexus-symbiote" alt="Python versions"></a>
  <a href="https://github.com/aisecnomad/nexus-symbiote/blob/main/LICENSE"><img src="https://img.shields.io/github/license/aisecnomad/nexus-symbiote" alt="License"></a>
</p>

<p align="center">
  <b>Agent Bill of Materials (AgentBOM) — inventory, verify, and govern the AI agent supply chain.</b>
</p>

Nexus SymBiote generates, validates, and manages Agent Bills of Materials for production AI agent systems. It inventories MCP servers and tools, model artifacts, prompt and skill files, retrieval configurations, A2A agent cards, IDE extensions, and package dependencies — then checks integrity, scores supply-chain risk, enforces policy, and exports standard BOMs (CycloneDX 1.7, SPDX 3.0.1, SARIF).

---

## Install

```bash
# Recommended: isolated install
pipx install nexus-symbiote

# Or with pip
pip install nexus-symbiote

# With all optional extras (Sigstore signatures, CycloneDX validation)
pip install "nexus-symbiote[all]"
```

The distribution is named `nexus-symbiote`; the Python import package is `nexus_symbiote`. Requires **Python 3.11+**.

For development or review from source:

```bash
git clone https://github.com/aisecnomad/nexus-symbiote.git
cd nexus-symbiote
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Quick start

```bash
# Scan a project and generate an AgentBOM
nexus-symbiote scan /path/to/agent-project -o agentbom.json

# Validate completeness and integrity
nexus-symbiote validate agentbom.json --project /path/to/agent-project

# Score supply-chain risk
nexus-symbiote risk agentbom.json --threshold 50

# Compare snapshots for drift
nexus-symbiote diff previous.json agentbom.json --fail-on-alert

# Import a Nexus-ShadowScan discovery report
nexus-symbiote import-shadowscan shadowscan-report.json -o agentbom.json --report-only
```

Exit codes: `0` = gate passed, `1` = gate failed, incomplete collection, or verification mismatch, `2` = usage error or invalid configuration.

## Why Nexus SymBiote

AI agents are composite software systems built from dozens of independently maintained components — MCP servers, model weights, prompt templates, retrieval indexes, skill registries, and package dependencies. Each component carries its own supply-chain risk, and **no single tool existed to inventory the full agent stack and ask: what changed, what is unsigned, and what is risky?**

| Problem | What happens today |
| --- | --- |
| **No agent-level SBOM** | Traditional SBOMs cover packages but miss MCP tools, model artifacts, prompts, and A2A cards. |
| **Invisible drift** | A renamed MCP server, a swapped model file, or an expanded tool definition slips through unnoticed. |
| **Trust assumptions** | A model file's extension or a tool descriptor's label is treated as proof of safety. |
| **Fragmented evidence** | Discovery reports, integrity hashes, signatures, and risk scores live in separate workflows. |
| **No policy enforcement** | Teams lack a single gate to block a deployment when the agent inventory fails review. |

Nexus SymBiote closes these gaps by combining static inventory, integrity verification, risk scoring, drift detection, and standard BOM export into a single CLI and CI pipeline — consuming [Nexus-ShadowScan](https://github.com/aisecnomad/Nexus-ShadowScan) discovery reports as its primary multi-surface input.

## How it works

```
┌──────────────────┐     ┌──────────────────────────────────────────────┐     ┌───────────────────┐
│                  │     │            Nexus SymBiote                    │     │                   │
│  Agent Project   │────▶│                                              │────▶│  AgentBOM Output  │
│                  │     │  ┌────────┐  ┌──────────┐  ┌─────────────┐  │     │                   │
│  MCP configs     │     │  │Scanners│─▶│Validators│─▶│ Generators  │  │     │  Native JSON      │
│  Model files     │     │  │        │  │          │  │             │  │     │  CycloneDX 1.7    │
│  Prompts/skills  │     │  │ MCP    │  │Complete- │  │ CycloneDX   │  │     │  SPDX 3.0.1       │
│  RAG configs     │     │  │ Model  │  │ness      │  │ SPDX        │  │     │  SARIF             │
│  A2A cards       │     │  │ Prompt │  │Integrity │  │ SARIF       │  │     │  VEX               │
│  IDE extensions  │     │  │ RAG    │  │Risk      │  │ VEX         │  │     │                   │
│  Package deps    │     │  │ A2A    │  │Policy    │  │             │  │     │  + Risk report    │
│                  │     │  │ IDE    │  │          │  │             │  │     │  + Drift alerts   │
│  ShadowScan      │     │  │ Reg.   │  │          │  │             │  │     │  + Policy verdict │
│  report (opt.)   │     │  └────────┘  └──────────┘  └─────────────┘  │     │                   │
└──────────────────┘     └──────────────────────────────────────────────┘     └───────────────────┘
```

1. **Scan** — eight pluggable scanners inventory declared components: MCP servers and tools, model artifacts, prompts, retrieval configurations, registries, A2A agent cards, IDE agent extensions. An optional ShadowScan importer consumes external discovery reports.
2. **Validate** — completeness and integrity validators cross-reference the inventory against the project, verify file hashes, and check Sigstore signatures where available.
3. **Score** — the risk scorer evaluates every component against configurable severity rules, category weights, and trust tiers. A policy gate passes or fails the pipeline.
4. **Export** — generators emit standard BOMs (CycloneDX 1.7, SPDX 3.0.1, SARIF, VEX) alongside the native agent-specific model.

Collection is **static by default** — configuration files, manifests, and local artifacts provide evidence of declared composition. A configuration entry does not prove a server is running or that its live tools match the declaration. Use `verify-live` for explicit runtime observations under an operator-provisioned launch policy.

## Key capabilities

| Capability | Description |
| --- | --- |
| **Multi-surface inventory** | MCP servers/tools, model weights, prompts/skills, RAG configs, registries, A2A cards, IDE agents, package deps |
| **ShadowScan integration** | Import Nexus-ShadowScan discovery reports with full provenance tracking and coverage metadata |
| **Integrity verification** | SHA-256 file hashes, SafeTensors fingerprints, Sigstore bundle verification, RFC 8785 JCS digests for tool definitions |
| **Risk scoring** | Configurable severity rules, category weights, trust tiers (internal-verified → unknown), policy gates with thresholds |
| **Drift detection** | Snapshot comparison with security alerts for changed origins, transports, launchers, capabilities, and integrity evidence |
| **Standard BOM export** | CycloneDX 1.7, SPDX 3.0.1, SARIF, VEX — schema-validated against pinned official schemas |
| **Runtime contracts** | Ed25519 signing for snapshots, tool approvals, trust status, and hosted-model attestations |
| **Live observation** | Explicit opt-in MCP endpoint discovery and launcher verification under operator-provisioned policy |
| **Blast-radius analysis** | Graph-based impact analysis showing which agents and components are affected by a compromise |
| **Policy configuration** | Project-level `.nexus-symbiote.yaml` controlling scanners, thresholds, formats, and validation rules; pass `--no-project-policy` when evaluating untrusted checkouts |
| **GitHub Action** | First-party composite Action for CI inventory, validation, risk gating, and SARIF upload |
| **Pre-commit hooks** | Scan and risk-gate hooks for local development workflows |

## Commands and exit codes

| Command | Description |
| --- | --- |
| `scan` | Scan a project and generate an AgentBOM |
| `import-shadowscan` | Import a Nexus-ShadowScan report into an AgentBOM |
| `validate` | Check completeness and integrity of an AgentBOM |
| `risk` | Score supply-chain risks and apply the policy gate |
| `diff` | Compare two AgentBOM snapshots for drift and security alerts |
| `summary` | Print a human-readable AgentBOM summary |
| `blast-radius` | Show components affected by a potential compromise |
| `baseline` | Stage a reviewed snapshot after scan and risk gates pass |
| `vex` | Export schema-validated findings as VEX (in triage) |
| `advisories` | Query OSV for known vulnerabilities in declared packages |
| `verify-artifact` | Verify a local artifact's digest and optional Sigstore bundle |
| `verify-discovery` | Verify a ShadowScan report's bytes, projection, and producer |
| `verify-live` | Observe live MCP launchers under operator-provisioned policy |
| `discover-mcp` | Observe tools/list from an MCP endpoint without executing tools |
| `init` | Initialize a `.nexus-symbiote.yaml` policy configuration |
| `runtime keygen` | Generate Ed25519 signing keys for runtime contracts |
| `runtime sign` | Sign a snapshot, approval, trust status, or attestation |
| `runtime verify` | Verify a signed runtime contract |

| Exit code | Meaning |
| --- | --- |
| `0` | Success — gate passed, verification succeeded |
| `1` | Failure — gate failed, security alert, incomplete collection, verification mismatch, or `import-shadowscan` without `--report-only` |
| `2` | Usage error — invalid arguments, configuration, or missing required mode |

## Export formats

```bash
nexus-symbiote scan . -f cyclonedx -o agentbom.cdx.json    # CycloneDX 1.7
nexus-symbiote scan . -f spdx      -o agentbom.spdx.json   # SPDX 3.0.1
nexus-symbiote scan . -f sarif     -o results.sarif         # SARIF
nexus-symbiote scan . -f json      -o agentbom.json         # Native JSON (default)
```

Native JSON retains the full agent-specific model. CycloneDX and SPDX exports use supported native structures and documented extension points. Schema validity is necessary but does not establish equivalent semantics or completeness. SARIF carries reviewable findings rather than an admission decision. VEX is available via the `vex` command.

## GitHub Action

```yaml
name: Agent inventory
on: [push, pull_request]
permissions:
  contents: read
jobs:
  inventory:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          persist-credentials: false
      - uses: aisecnomad/nexus-symbiote@<commit-sha>
        with:
          scan-path: .
          output-file: agentbom.json
          validate: 'true'
          risk-check: 'true'
          risk-threshold: '50'
          sarif-upload: 'true'
```

The Action installs its own reviewed source, collects once, and derives the requested format and SARIF from that same native inventory. Use a reviewed immutable commit SHA in `uses:`. See the [Action reference](https://github.com/aisecnomad/nexus-symbiote/blob/main/action.yml) for all inputs and outputs.

## Data handling and safety

- **A successful scan is an inventory result.** It does not establish that a model is benign, a tool backend obeys its description, or that every agent action was mediated.
- Static collection does not execute project modules, model loaders, repository hooks, or MCP launch commands.
- Repositories, model files, tool metadata, and imported BOMs are treated as hostile input.
- Agent inventories can expose infrastructure details — restrict access to exported evidence.
- A risk score summarizes findings under a policy; it is not a probability of compromise.
- Signature verification proves bytes were signed under policy, not that content is safe.
- **Untrusted checkouts**: `scan`, `validate`, and `risk` read project policy (`.nexus-symbiote.yaml`) by default. A pull request can weaken the gate (e.g. set `report-only`). Pass `--no-project-policy` to those commands when evaluating an untrusted checkout.

Read the [security model](https://github.com/aisecnomad/nexus-symbiote/blob/main/docs/security-model.md) and [security policy](https://github.com/aisecnomad/nexus-symbiote/blob/main/SECURITY.md) before using results in an approval process.

## Documentation

| Topic | Link |
| --- | --- |
| Security model | [`docs/security-model.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/docs/security-model.md) |
| Runtime assurance | [`docs/runtime-assurance.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/docs/runtime-assurance.md) |
| ShadowScan integration | [`docs/shadowscan-integration.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/docs/shadowscan-integration.md) |
| Deployment evidence | [`docs/deployment-evidence.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/docs/deployment-evidence.md) |
| TypeScript inventory | [`docs/typescript-inventory.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/docs/typescript-inventory.md) |
| Releasing | [`docs/releasing.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/docs/releasing.md) |
| Repository controls | [`docs/repository-controls.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/docs/repository-controls.md) |
| Changelog | [`CHANGELOG.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/CHANGELOG.md) |
| Roadmap | [`ROADMAP.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/ROADMAP.md) |
| Contributing | [`CONTRIBUTING.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/CONTRIBUTING.md) |
| Security policy | [`SECURITY.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/SECURITY.md) |

## Benchmarks

The [security regression corpus](https://github.com/aisecnomad/nexus-symbiote/blob/main/benchmarks/README.md) contains inspectable hand-authored fixtures covering MCP configurations, model formats, prompt injection patterns, and tool drift scenarios. Run the benchmark suite:

```bash
PYTHONPATH=src python scripts/benchmark_security.py --out benchmark-results.json
```

The runner records corpus and source digests, tool version, confusion counts, unknowns, denominators, runtime, and Python allocation measurements. These are regression fixtures, not representative efficacy estimates.

## Project status

Nexus SymBiote is in **alpha**. The API, output formats, and policy semantics may change. There is one active maintainer. Until a published release's provenance has been verified, install from a reviewed checkout or use the CI-attested distributions.

**What alpha means:**
- The core inventory, validation, risk, and export pipeline is functional and CI-gated.
- Coverage is expanding across agent frameworks and MCP configurations.
- No long-term support commitment or production SLA while in alpha.

See [`ROADMAP.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/ROADMAP.md) for near-term goals.

## Community and contributing

| I want to... | Go to |
| --- | --- |
| Report a security issue | [`SECURITY.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/SECURITY.md) |
| Report a bug | [GitHub Issues](https://github.com/aisecnomad/nexus-symbiote/issues) |
| Request a feature | [GitHub Issues](https://github.com/aisecnomad/nexus-symbiote/issues) |
| Contribute code | [`CONTRIBUTING.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/CONTRIBUTING.md) |
| Read the governance model | [`GOVERNANCE.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/GOVERNANCE.md) |
| Understand support options | [`SUPPORT.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/SUPPORT.md) |
| See current maintainers | [`MAINTAINERS.md`](https://github.com/aisecnomad/nexus-symbiote/blob/main/MAINTAINERS.md) |

## License

[MIT](https://github.com/aisecnomad/nexus-symbiote/blob/main/LICENSE) — Copyright (c) 2026 AISecNomad
