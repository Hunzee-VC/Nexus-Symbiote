<h1 align="center">Nexus SymBiote</h1>

<p align="center">
  <a href="https://github.com/aisecnomad/Nexus-symbiote/actions/workflows/ci.yml"><img src="https://github.com/aisecnomad/Nexus-symbiote/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%E2%80%933.13-blue.svg" alt="Python 3.11-3.13"></a>
  <a href="https://github.com/aisecnomad/Nexus-symbiote/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <!-- Enable after the first PyPI release:
  <a href="https://pypi.org/project/nexus-symbiote/"><img src="https://img.shields.io/pypi/v/nexus-symbiote.svg" alt="PyPI"></a>
  Enable once the repository is public:
  <a href="https://github.com/aisecnomad/Nexus-symbiote/actions/workflows/codeql.yml"><img src="https://github.com/aisecnomad/Nexus-symbiote/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/aisecnomad/Nexus-symbiote"><img src="https://api.scorecard.dev/projects/github.com/aisecnomad/Nexus-symbiote/badge" alt="OpenSSF Scorecard"></a>
  -->
</p>

<p align="center"><strong>Build an Agent Bill of Materials (AgentBOM) for an AI agent: what it is made of, the evidence for each record, and what that evidence does and does not establish.</strong></p>

Nexus SymBiote inventories the models, prompts, MCP servers and tools, retrieval
sources, packages, A2A peers and IDE agents behind an agent, records integrity
and provenance evidence for each, exports standard BOM formats, checks the result
against a policy, and compares snapshots over time. It is the inventory and
verification companion to [Nexus ShadowScan](https://github.com/aisecnomad/Nexus-ShadowScan),
which discovers agents across an organization.

**A successful scan is an inventory result.** It does not establish that a model
is benign, that a tool backend obeys its description, or that every agent action
was mediated. Read the
[security model](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/concepts/security-model.md)
and the [security policy](https://github.com/aisecnomad/Nexus-symbiote/blob/main/SECURITY.md)
before using an inventory in an approval process.

| | |
| --- | --- |
| [Why](#why) | The problem an AgentBOM solves and what SymBiote can and cannot tell you |
| [What](#what) | What is collected, what is exported, and how evidence is graded |
| [How](#how) | [Install](#install) · [Quick start](#quick-start) · [Offline and live modes](#offline-and-live-modes) · [Commands and exit codes](#commands-and-exit-codes) · [Export formats](#export-formats) · [GitHub Action](#github-action) · [Policy and trust](#policy-and-trust) |
| [Documentation](#documentation) | Guides and references |
| [Project status](#project-status) · [Community](#community-and-contributing) · [License](#license) | How the project is run |

## Why

AI agents are assembled, not written. One customer-support agent can depend on
a hosted model alias, a locally cached SafeTensors checkpoint, a system prompt in
`CLAUDE.md`, three MCP servers started with `npx -y some-server@latest`, a vector
index built from an internal wiki, a Python package that unpickles on import, and
an A2A peer taken from an Agent Card. None of that appears in a conventional
software bill of materials, and every piece is a supply-chain surface: a tool
description can change under an unchanged name, an unpinned server can resolve
to a different package tomorrow, a model file can carry a loader that executes on
open, and a "verified" label in an extension manifest is a claim, not a
signature.

An AgentBOM makes that composition reviewable. Nexus SymBiote produces one from
the evidence a checkout and a discovery report contain, keeps every record
labeled with how it was obtained, and refuses to present a declaration as an
observation or an observation as approval.

| Question | What SymBiote gives you | What it does not establish |
| --- | --- | --- |
| Which models, prompts, tools, sources and packages does this agent use? | Typed components with source paths, digests, declared versions and the collector that found each | Completeness beyond the scanned surfaces; coverage gaps are recorded, not hidden |
| Are the tool definitions and model files the ones we reviewed? | RFC 8785 canonical fingerprints of tool definitions, SHA-256 digests, SafeTensors header fingerprints, Sigstore bundle verification against an explicit signer policy | That a tool backend behaves as its description says, or that a signed model is benign |
| Does the agent meet our policy? | Completeness and integrity validation and an explainable risk score with a gate | A probability of compromise or a safety certificate |
| What changed since the last review? | Snapshot diff and the blast radius of a changed component | That every runtime action was mediated |
| Can we hand it to auditors and other tools? | CycloneDX 1.7, SPDX 3.0.1, SARIF and VEX exports with documented conversion loss | Semantic equivalence of an export; the native JSON stays authoritative |

## What

**Collectors.** Eight collectors read a project checkout and, optionally, a
ShadowScan report. Static collection executes nothing, launches nothing and
contacts nothing: it reads files within the project root with bounded sizes and
counts, never follows symbolic links out of the root, and reports everything it
could not read as a coverage gap.

| Collector | Reads | Establishes | Does not establish |
| --- | --- | --- | --- |
| `shadowscan` | A ShadowScan native JSON or CycloneDX report at `.shadowscan/report.json` or given to `import-shadowscan` | Attributed discovery claims bound to the exact report digest | The producer's identity, a second observation of the deployment, or effective authorization |
| `mcp` | MCP client configuration, declared tool definitions, literal Python and TypeScript SDK registrations | Declared servers and tools, versions, transports, canonical descriptor fingerprints | That a server is running or that served tools match the declaration |
| `model` | Model files and configuration, Sigstore bundles next to them | Artifact identity, serialization format and loader-risk signals, SafeTensors metadata fingerprints, signer-policy results | Benignness; a file extension or a signature proves neither |
| `prompt` | Instruction, prompt and skill files | Content digests, source location, invisible-character and bidirectional-override signals | That the deployed agent uses this text unchanged |
| `rag` | Retrieval and memory configuration | Declared sources, indexes and lineage references | Source versions, effective reader and writer permissions, execution |
| `registry` | Python and npm manifests and lockfiles | Declared AI-related dependencies, requested ranges, lockfile versions and integrity declarations | Publisher identity, which artifacts were installed, or that bytes match the lockfile |
| `a2a` | Static Agent Cards, client configuration, code references | Declared peers, skills and endpoints | Endpoint identity or delegated authority |
| `ide_agents` | Coding-agent configuration and extension manifests | Configured agents and declared verification labels | Execution, or that a label is a validated signature |

**Component types.** `agent`, `mcp-server`, `mcp-client`, `tool`, `model`,
`prompt-template`, `guardrail-policy`, `memory-store`, `rag-source`,
`data-source`, `registry-entry`, `skill-package`, `a2a-client`, `a2a-server`,
`ide-agent` and `verified-extension`, linked by typed dependency edges.

**Evidence grades.** Every component carries an assurance level (`declared`,
`observed` or `verified`) and a trust tier from `internal-verified` down to
`unknown`. Missing evidence stays `unknown`; it is never defaulted to `false` or
to an empty permission. Imported discovery records keep `declared` assurance no
matter what the source report claims.

**Capabilities.**

| Capability | Details |
| --- | --- |
| **Native AgentBOM** | JSON validated by a [published schema](https://github.com/aisecnomad/Nexus-symbiote/blob/main/schemas/nexus-symbiote-aibom-1.0.schema.json), with a completeness claim recording collectors requested and completed, excluded surfaces, failures and unobserved surfaces |
| **Five export formats** | Native JSON, CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0 and VEX; CycloneDX, SPDX and VEX documents are validated against their pinned official schemas before they are written |
| **Validation** | Completeness against the collector universe and integrity of recorded digests against the checkout |
| **Risk scoring** | Additive, explainable 0-100 score with a threshold gate and a severity gate, configured in a policy file |
| **Drift detection** | `diff` between snapshots with an optional `--fail-on-change` gate, `blast-radius` for one component, unsigned reviewed baselines |
| **ShadowScan integration** | Imports discovery reports as attributed claims and verifies report bytes and producer signatures separately |
| **Offline by default** | Every command refuses network access and process execution unless `--live` is given, and the inventory records the mode it was collected in |
| **Live checks with offline counterparts** | `discover-mcp` observes served tool descriptors over an allowlisted HTTPS origin, `verify-live` launches operator-pinned stdio launchers, `advisories` queries OSV; each also analyzes a saved export offline with `--input` |
| **Signed runtime contracts** | Ed25519 DSSE contracts for approved snapshots, trust status, single-use action approvals and hosted-model attestations, with a reference gateway |
| **CI integration** | A composite GitHub Action that collects once, validates, gates and uploads SARIF; deterministic exit codes; pre-commit hooks |
| **Fail-closed design** | Unknown scanners, invalid policies, incomplete collection and unsupported export semantics fail visibly instead of shrinking the result |
| **Credential safety** | Connection secrets in MCP configuration are redacted before anything is written; tokens for live checks come from named environment variables and never enter evidence |

## How

### Install

Nexus SymBiote is not yet on PyPI; the first release (0.1.0) is prepared through
a TestPyPI rehearsal described in the
[release runbook](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/operations/releasing.md).
Until then, install from a reviewed checkout:

```bash
git clone https://github.com/aisecnomad/Nexus-symbiote && cd Nexus-symbiote
python -m venv .venv && . .venv/bin/activate
python -m pip install .            # add ".[sigstore]" for Sigstore bundle verification
nexus-symbiote --version
```

**Requirements:** CPython 3.11 to 3.13 on a POSIX system. CI runs the test suite
on Linux; macOS and Windows are untested. The distribution and command are
`nexus-symbiote`; the Python import package is `nexus_symbiote`. For a
hash-locked developer install see
[CONTRIBUTING.md](https://github.com/aisecnomad/Nexus-symbiote/blob/main/CONTRIBUTING.md),
and for the full options see the
[installation guide](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/getting-started/install.md).

Once published, `pipx install nexus-symbiote` will install a release whose wheel
and sdist carry GitHub build attestations you can check with
`gh attestation verify`.

### Quick start

No credentials or configuration are needed to inventory a checkout:

```bash
nexus-symbiote scan . --report-only -o agentbom.json   # collect; exploratory, never fails the shell
nexus-symbiote summary agentbom.json                   # read it
nexus-symbiote validate agentbom.json --project .      # completeness and integrity against the checkout
nexus-symbiote risk agentbom.json --threshold 50       # score and gate
nexus-symbiote diff previous.json agentbom.json        # what changed since the last review
```

Abridged output of the first three commands on a small synthetic project with
two MCP servers, a system prompt, a SafeTensors file and two package manifests:

```
$ nexus-symbiote scan . --report-only -o agentbom.json
Scanning /work/support-agent
  Running mcp scanner...        Found 3 components
  Running model scanner...      Found 1 components
  Running prompt scanner...     Found 1 components
  ...
Saved agentbom.json
Risk warning: score 26.0
Report only

$ nexus-symbiote summary agentbom.json
AIBOM Summary
  Components: 10
  Dependencies: 6
  Risks: 5
  Component types:
    agent: 1  ide-agent: 1  mcp-client: 1  mcp-server: 2  model: 1  prompt-template: 1  registry-entry: 3

$ nexus-symbiote risk agentbom.json --threshold 50
Risk Score: 26.0 (high)
  ticket-service          version_pinning   MCP server 'ticket-service' uses an unpinned package
  models/classifier...    signing_status    Model 'classifier.safetensors' has no verified artifact signer
  ...
Gate (threshold=50.0): FAILED: collection coverage is unknown or incomplete
```

The score summarizes findings under the policy. Here the gate failed because
coverage is partial (no ShadowScan report, retrieval configuration or A2A card was
found), not because of the threshold. `--report-only` writes the evidence and
exits 0 so that a first look never breaks a shell or a pipeline; without it, `scan`
exits 2 when the gate fails and 3 when a collector failed, and the inventory is
still written.

The recommended workflow runs discovery and inventory as separate steps with
separate permissions:

```bash
shadowscan code /path/to/repository --format json -o shadowscan.json            # discovery (Nexus ShadowScan)
nexus-symbiote import-shadowscan shadowscan.json -o agentbom.json --report-only   # attributed claims
nexus-symbiote scan /path/to/repository -o agentbom.json                          # local file-level evidence
nexus-symbiote verify-discovery agentbom.json shadowscan.json                     # exact report bytes
```

Imported records retain the source report's SHA-256, status and unmapped finding
indexes, and keep `declared` assurance; importing a report does not verify its
producer or observe the deployment again. The
[quick start guide](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/getting-started/quickstart.md)
walks through each step and the
[ShadowScan integration guide](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/operations/shadowscan-integration.md)
covers verification of a signed report.

### Offline and live modes

Every command runs **offline** unless you say otherwise: for the whole run the
process refuses to resolve host names, open connections or start processes, and
the inventory records `collection_mode: offline` and `offline_enforced: true`.
That holds in an air-gapped review, in CI without egress, and against a hostile
checkout, because no policy file can change the mode. **Live** mode, chosen with
`--live` before the command or `NEXUS_SYMBIOTE_MODE=live`, permits exactly three
observations, and each of them also has an offline counterpart that reads a saved
export, the way a ShadowScan connector reads an `input:` export:

| Command | Live (`--live`) | Offline counterpart (`--input`) |
| --- | --- | --- |
| `discover-mcp` | One HTTPS origin named with `--allowed-origin`; `tools/list` only; private addresses, redirects and proxies refused | A saved `tools/list` result, checked and hashed the same way |
| `advisories` | OSV API over pinned HTTPS for exact PyPI and npm package identities | A saved OSV export (`all.zip`, a directory or a JSON file), with OSV version ranges evaluated locally |
| `verify-live` | Private copies of launchers pinned by SHA-256 in an operator policy outside the project; no project arguments, environment or working directory | Descriptors recorded by a live run with `--save-descriptors` |

```bash
nexus-symbiote scan . -o agentbom.json                               # offline: the default
nexus-symbiote advisories agentbom.json --input PyPI-all.zip         # offline, from an OSV export
nexus-symbiote --live advisories agentbom.json                       # live OSV query
nexus-symbiote advisories agentbom.json                              # refused offline: exit 3
```

The guard is a tripwire for this package and its Python dependencies, not a
sandbox; use a network namespace or an egress policy where you need a hard
boundary. A served descriptor that matches the declared one does not establish
backend safety or authorization, so run live observations from an isolated
worker with restricted identity, filesystem and egress. See
[offline and live modes](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/operations/offline-and-live-modes.md).

### Commands and exit codes

Run `nexus-symbiote --help` or `nexus-symbiote <command> --help`; the
[CLI reference](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/reference/cli.md)
is generated from the same help text.

| Task | Command |
| --- | --- |
| Inventory a checkout and gate | `nexus-symbiote scan . -o agentbom.json` |
| Inventory without a gate | `nexus-symbiote scan . --report-only -o agentbom.json` |
| Select collectors | `nexus-symbiote scan . --scanner mcp --scanner model -o agentbom.json` |
| Import ShadowScan discovery | `nexus-symbiote import-shadowscan report.json -o agentbom.json --report-only` |
| Validate against the checkout | `nexus-symbiote validate agentbom.json --project .` |
| Score and gate | `nexus-symbiote risk agentbom.json --threshold 50 --json-output` |
| Compare snapshots | `nexus-symbiote diff previous.json agentbom.json --json-output` |
| Drift gate | `nexus-symbiote diff reviewed-baseline.json agentbom.json --fail-on-change` |
| Summarize | `nexus-symbiote summary agentbom.json` |
| Impact of one component | `nexus-symbiote blast-radius agentbom.json model:models/classifier.safetensors` |
| Export | `nexus-symbiote scan . -f cyclonedx -o agentbom.cdx.json` |
| Verify a local artifact | `nexus-symbiote verify-artifact model.safetensors --project . --sha256 "$EXPECTED"` |
| Verify imported report bytes | `nexus-symbiote verify-discovery agentbom.json shadowscan.json` |
| Stage a reviewed baseline | `nexus-symbiote baseline . -o reviewed-baseline.json` |
| Findings as VEX | `nexus-symbiote vex agentbom.json -o findings.vex.json` |
| Known advisories, offline | `nexus-symbiote advisories agentbom.json --input PyPI-all.zip -o advisories.json` |
| Known advisories, live | `nexus-symbiote --live advisories agentbom.json -o advisories.json` |
| Served descriptors, offline | `nexus-symbiote discover-mcp --input tools-list.json` |
| Served descriptors, live | `nexus-symbiote --live discover-mcp https://mcp.example.com/mcp --allowed-origin https://mcp.example.com` |
| Pinned launchers, live | `nexus-symbiote --live verify-live agentbom.json --project . --launch-policy /operator/launch-policy.json --save-descriptors descriptors.json` |
| Recorded descriptors, offline | `nexus-symbiote verify-live agentbom.json --input descriptors.json` |
| Signed runtime contracts | `nexus-symbiote runtime keygen --private-key approval.pem --public-key approval.pub` |
| Policy file | `nexus-symbiote init` |

Exit codes are deterministic and the same for every command:

| Exit | Meaning |
| --- | --- |
| 0 | Complete for the requested scope and within policy |
| 1 | Usage, configuration, input or output failure; no usable result was produced |
| 2 | Complete evidence, but a gate failed: the risk gate, validation, `diff --fail-on-change`, descriptor drift, or a digest or signature verification that did not match |
| 3 | Incomplete: a collector failed, a source report was incomplete, a live observation or export could not be completed, or a live step was refused in offline mode |

A command can write evidence and still exit 2 or 3; inspect both the exit code
and the inventory. See the
[exit code reference](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/reference/exit-codes.md).

### Export formats

```bash
nexus-symbiote scan . -f cyclonedx -o agentbom.cdx.json
nexus-symbiote scan . -f spdx -o agentbom.spdx.json
nexus-symbiote scan . -f sarif -o results.sarif
nexus-symbiote vex agentbom.json -o findings.vex.json
```

Native JSON retains the complete agent model. CycloneDX 1.7 and SPDX 3.0.1
exports use native structures plus documented extension points and embed a
digest-bound copy of the native inventory; schema validity is necessary but does
not establish equivalent semantics. SARIF carries reviewable findings, not an
admission decision, and is unavailable for imported discovery because a
finding-only projection cannot preserve coverage and provenance. VEX exports
findings as `in_triage` without asserting exploitability. The
[format reference](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/reference/output-formats.md)
lists what each export preserves and loses.

### GitHub Action

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
      - uses: aisecnomad/Nexus-symbiote@<reviewed 40-character commit SHA>
        with:
          scan-path: .
          output-file: agentbom.json
          validate: 'true'
          risk-check: 'true'
          risk-threshold: '50'
          sarif-upload: 'true'
```

Pin a reviewed immutable commit; treat Action source as executable code. The
Action installs its own checked-out source, runs every step with `--offline`, collects once, derives the
requested format and SARIF from that one native inventory, passes inputs as data
without shell evaluation, confines paths to the workspace, ignores policy files
in the scanned checkout, and fails on collection failures even when later gates
are disabled. SARIF upload is off by default; fork pull requests may have
restricted tokens, so use the evidence artifact when upload is unavailable. Do
not run an untrusted pull request's Action checkout with deployment credentials
or through `pull_request_target`. Details and all inputs are in the
[Action reference](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/reference/github-action.md).

### Policy and trust

`nexus-symbiote init` writes `.nexus-symbiote.yaml`. Review it as
security-relevant configuration: it selects collectors, output format,
exclusions, the risk thresholds and severity gate, and whether a scan is
report-only. Pass `--no-project-policy` when evaluating an untrusted checkout so
that its policy file is ignored, as the Action always does. Signature checks need
an explicit signer-identity and issuer policy supplied by the operator. Registry
membership, trust labels and model-visible hints never increase permissions.

Runtime approval integrations govern only the calls that pass through their
adapter; deployment identity, token scopes, sandboxing and network policy enforce
the surrounding boundary. See
[configuration](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/getting-started/configuration.md),
[risk scoring](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/concepts/risk-scoring.md)
and the
[runtime assurance guide](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/operations/runtime-assurance.md).

## Data handling and safety

* Static collection treats the repository, model files, tool metadata, registry
  records and imported reports as hostile input. It executes no project code,
  model loader, repository hook or MCP launch command, deserializes no pickle,
  and reads only regular files within the project root under byte and count
  limits.
* Inventories can expose infrastructure, permissions, endpoints and instruction
  fingerprints. Restrict access to exported evidence and uploaded artifacts.
  Known connection-secret fields are redacted before anything is written;
  redaction cannot identify every arbitrary secret, so review an inventory
  before sharing it.
* Nexus SymBiote sends no telemetry. Offline, the default, nothing connects at
  all; with `--live`, only the three live commands connect, and only where their
  operator inputs point.
* A regression corpus of synthetic fixtures with inspectable labels supports
  security regressions; it is not an efficacy estimate or a ranking. See
  [benchmarks/README.md](https://github.com/aisecnomad/Nexus-symbiote/blob/main/benchmarks/README.md).

See [SECURITY.md](https://github.com/aisecnomad/Nexus-symbiote/blob/main/SECURITY.md)
and the [threat model](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/security/threat-model.md).

## Documentation

| Topic | Reference |
| --- | --- |
| Start here | [Documentation index](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/index.md) |
| Installation and first inventory | [Installation](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/getting-started/install.md), [quick start](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/getting-started/quickstart.md), [configuration](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/getting-started/configuration.md) |
| Commands and behavior | [CLI reference](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/reference/cli.md), [exit codes](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/reference/exit-codes.md), [collectors](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/reference/scanners.md), [output formats](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/reference/output-formats.md), [GitHub Action](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/reference/github-action.md) |
| How it works | [Architecture](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/concepts/architecture.md), [security model](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/concepts/security-model.md), [risk scoring](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/concepts/risk-scoring.md), [deployment evidence](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/concepts/deployment-evidence.md) |
| Trust boundaries | [Threat model](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/security/threat-model.md), [offline and live modes](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/operations/offline-and-live-modes.md), [runtime assurance](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/operations/runtime-assurance.md) |
| Working with ShadowScan | [ShadowScan integration](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/operations/shadowscan-integration.md) |
| Releases | [Release runbook](https://github.com/aisecnomad/Nexus-symbiote/blob/main/docs/operations/releasing.md), [changelog](https://github.com/aisecnomad/Nexus-symbiote/blob/main/CHANGELOG.md) |

Documentation links open `main`, which can be newer than an installed version.
A release's documentation stays at its tag,
`https://github.com/aisecnomad/Nexus-symbiote/tree/v<version>`, where
`<version>` is what `nexus-symbiote --version` prints.

## Project status

* **Release state.** Alpha; the package classifier is
  `Development Status :: 3 - Alpha`. No version has been published yet. A
  version is published when it appears on PyPI and as a release tag; a version
  number in the source is not evidence of publication.
* **Single maintainer, AI-assisted development.** Every commit was written by
  one maintainer or generated with AI coding assistants. There has been no
  independent review of any revision. Review the revision yourself or have it
  reviewed, then pin that full commit SHA.
* **Compatibility baseline.** The `nexus_symbiote` package and `nexus-symbiote`
  command on `main`. Native JSON documents carry `spec_version: 1.0.0`;
  exporter and fingerprint changes ship with
  [migration notes](https://github.com/aisecnomad/Nexus-symbiote/tree/main/docs/migrations).
* **Roadmap.** See [ROADMAP.md](https://github.com/aisecnomad/Nexus-symbiote/blob/main/ROADMAP.md).

## Community and contributing

| I want to… | Start here |
| --- | --- |
| Ask a question or troubleshoot | [Support guide](https://github.com/aisecnomad/Nexus-symbiote/blob/main/SUPPORT.md) |
| Report a bug or request a feature | [Issue forms](https://github.com/aisecnomad/Nexus-symbiote/issues/new/choose) |
| Make a first contribution | [Contributor guide](https://github.com/aisecnomad/Nexus-symbiote/blob/main/CONTRIBUTING.md) |
| Report a vulnerability privately | [Security policy](https://github.com/aisecnomad/Nexus-symbiote/blob/main/SECURITY.md#reporting-a-vulnerability) |
| Understand decisions, review and release requirements | [Governance](https://github.com/aisecnomad/Nexus-symbiote/blob/main/GOVERNANCE.md), [Maintainers](https://github.com/aisecnomad/Nexus-symbiote/blob/main/MAINTAINERS.md), [Roadmap](https://github.com/aisecnomad/Nexus-symbiote/blob/main/ROADMAP.md) |
| Understand participation standards | [Code of conduct](https://github.com/aisecnomad/Nexus-symbiote/blob/main/CODE_OF_CONDUCT.md) |
| See what changed or cite the project | [Changelog](https://github.com/aisecnomad/Nexus-symbiote/blob/main/CHANGELOG.md), [CITATION.cff](https://github.com/aisecnomad/Nexus-symbiote/blob/main/CITATION.cff) |

Use synthetic, minimal examples in public reports. Inventories can contain
credentials, personal data and sensitive infrastructure detail even after
redaction.

## License

MIT. See [LICENSE](https://github.com/aisecnomad/Nexus-symbiote/blob/main/LICENSE).
