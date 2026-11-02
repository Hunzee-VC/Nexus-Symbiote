# Nexus SymBiote documentation

Nexus SymBiote creates and reviews an Agent Bill of Materials (AgentBOM). A scan reads a
project's MCP configuration and tool declarations, model artifacts, instruction files,
retrieval configuration, package manifests, A2A declarations and IDE agent settings; records
integrity and provenance evidence; exports standard BOM formats; and supports policy checks
and snapshot comparison. The distribution and command are `nexus-symbiote`, and the Python
import package is `nexus_symbiote`. [Nexus-ShadowScan](https://github.com/aisecnomad/Nexus-ShadowScan)
is the sibling discovery engine whose reports Nexus SymBiote imports.

A successful scan is an inventory result, not a safety certificate. Every command runs
offline by default and refuses network access and process execution; only `discover-mcp`,
`advisories` and `verify-live` do live work, only with `--live`, and each also analyzes a
saved export offline with `--input`. Missing evidence is recorded as unknown, and every
policy gate fails closed. Read the [security model](concepts/security-model.md) before using
a result in an approval process.

These pages describe the `main` branch of
[aisecnomad/Nexus-symbiote](https://github.com/aisecnomad/Nexus-symbiote) and can be newer
than an installed version. `nexus-symbiote --version` prints the installed version, and
`nexus-symbiote <command> --help` is authoritative for that version's options.

## Getting started

| Page | Description |
| --- | --- |
| [Installation](getting-started/install.md) | Requirements, installation from a reviewed checkout, optional extras, the hash-locked developer install, and the PyPI path once version 0.1.0 is published. |
| [Quick start](getting-started/quickstart.md) | A first scan, reading the inventory, validation, the risk gate, snapshot comparison, ShadowScan import and exports, with observed output. |
| [Configuration](getting-started/configuration.md) | The `.nexus-symbiote.yaml` policy file and every key the code reads, `--no-project-policy`, the signature policy JSON, and environment variables. |

## Reference

| Page | Description |
| --- | --- |
| [CLI reference](reference/cli.md) | Generated help text for every command and subcommand. |
| [Exit codes](reference/exit-codes.md) | The 0/1/2/3 contract every command follows, command by command, and how to use it in CI. |
| [Scanners](reference/scanners.md) | What each collector reads, its limits, what a record establishes, and the coverage gaps it reports. |
| [Output formats](reference/output-formats.md) | Native JSON, CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0 and VEX: the validation performed in code and the documented loss. |
| [GitHub Action](reference/github-action.md) | Inputs, outputs, the example workflow, the Action's security behavior, and pinning a reviewed commit. |
| [npm lockfile evidence](reference/npm-lockfile-evidence.md) | What the registry collector records from `package-lock.json` and what it does not prove. |
| [Static TypeScript MCP inventory](reference/typescript-inventory.md) | Literal tool registrations collected from TypeScript MCP servers, with limits and gaps. |

## Concepts

| Page | Description |
| --- | --- |
| [Architecture](concepts/architecture.md) | The collect, validate, score, export and compare pipeline, the package layout, the scanner and generator contracts, and a data-flow diagram. |
| [Security model](concepts/security-model.md) | Declared, observed, approved and mediated states, and what an inventory entry does not grant. |
| [Risk scoring](concepts/risk-scoring.md) | Severity weights, thresholds, gate reasons, and what a score is and is not. |
| [Deployment-scoped authority claims](concepts/deployment-evidence.md) | The optional deployment profile, its authority claims and evidence records. |

## Security

| Page | Description |
| --- | --- |
| [Threat model](security/threat-model.md) | Assets, trust boundaries, adversaries, the controls implemented in code, residual risks and out-of-scope items. |
| [Security policy](../SECURITY.md) | How to report a vulnerability, supported versions, and the project's security boundaries. |

## Operations

| Page | Description |
| --- | --- |
| [Offline and live modes](operations/offline-and-live-modes.md) | The offline guarantee and its limits, the three live observations, their `--input` counterparts, and how the mode is recorded. |
| [ShadowScan discovery and verification](operations/shadowscan-integration.md) | Importing ShadowScan reports, the import gate, and verifying report bytes, native projections and producers. |
| [Runtime assurance integration](operations/runtime-assurance.md) | Signed contracts, the reference gateway and its adapters, hosted model identity and lineage helpers. |
| [Releasing](operations/releasing.md) | Release candidates, attestations, the TestPyPI rehearsal, trusted publishing, and the maintainer's per-release steps. |

## Migrations

| Page | Description |
| --- | --- |
| [Tool fingerprint migration](migrations/fingerprint-migration.md) | Re-collecting and re-approving tool fingerprints after the canonical serializer correction. |
| [Security fields: unknown rather than invented defaults](migrations/security-defaults-migration.md) | Handling `null` security fields in native BOMs instead of coercing them to `false`. |

## Project files

| File | Description |
| --- | --- |
| [README](../README.md) | Project overview and the primary workflows. |
| [CONTRIBUTING](../CONTRIBUTING.md) | Development environment, the locked check sequence, architecture boundaries and pull request expectations. |
| [SECURITY](../SECURITY.md) | Vulnerability reporting and security boundaries. |
| [SUPPORT](../SUPPORT.md), [GOVERNANCE](../GOVERNANCE.md), [MAINTAINERS](../MAINTAINERS.md), [ROADMAP](../ROADMAP.md), [CODE_OF_CONDUCT](../CODE_OF_CONDUCT.md) | How to get help, how decisions and releases are made, who maintains the project, what is planned, and participation standards. |
| [CHANGELOG](../CHANGELOG.md) | Notable changes by release. |
| [Security regression corpus](../benchmarks/README.md) | The synthetic security corpus, how to run it and how to read its results. |
| [Inventory regression corpus](../benchmarks/inventory/README.md) | The inventory corpus, signing a result, and verifying a release candidate's benchmark evidence. |
| [Schemas](../schemas/) | [`nexus-symbiote-aibom-1.0.schema.json`](../schemas/nexus-symbiote-aibom-1.0.schema.json), [`deployment-profile-1.0.schema.json`](../schemas/deployment-profile-1.0.schema.json) and a [minimal example](../schemas/examples/minimal-aibom.json). |
| [Examples](../examples/) | [`customer-support-agent.json`](../examples/customer-support-agent.json), an illustrative hand-written native AgentBOM. |
