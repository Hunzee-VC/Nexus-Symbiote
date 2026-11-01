# Nexus SymBiote

**Agent Bill of Materials (AIBOM)** for exploring and verifying AI agent supply chains.

> **Alpha:** Nexus SymBiote is under active development. Do not use its output as the sole basis for production deployment, authorization, compliance, or a claim that an agent is safe. See [SECURITY.md](SECURITY.md).

## Architecture: Discovery + Verification

**Nexus-ShadowScan** is the primary multi-surface discovery engine. It inventories shadow AI agents and evidence across code, identity, LLM gateways, low-code, SaaS, cloud, endpoints, network, and runtime.

**Nexus SymBiote** is the verification, integrity, and bill-of-materials layer. It consumes ShadowScan reports (native JSON or CycloneDX), maps findings into an agent-native domain model, applies confined integrity checks, risk scoring, and policy evaluation, and emits standards-oriented AIBOMs (native, CycloneDX 1.7, SPDX 3.0, SARIF).

Recommended workflow:
1. Run ShadowScan for discovery (least-privilege, fail-closed).
2. Run `nexus-symbiote import-shadowscan report.json -o aibom.json`, or place the report at `.shadowscan/report.json` and run `nexus-symbiote scan`.
3. Run `nexus-symbiote validate` and `nexus-symbiote risk`, and emit the desired format.
4. Gate in CI on the risk gate, which requires complete coverage and no critical findings, and on `validate`.

Local project scanners (a2a, ide_agents, mcp, model, prompt, rag, registry) remain available for fine-grained, file-level verification that complements the broader discovery.

## Why

Production AI agents assemble capabilities from dozens of sources: MCP servers, model weights, system prompts, vector stores, and packages. A single poisoned tool definition or unsigned model weight can compromise the entire system.

Nexus SymBiote helps teams turn discovery evidence into a structured, verifiable AIBOM and apply explicit integrity and risk policies. A detection or digest alone does not establish runtime identity, provenance, completeness, or safety.

## Install

Install from a reviewed checkout of this repository. Verify published distributions independently before installing them.

For development:
```bash
git clone https://github.com/aisecnomad/nexus-symbiote.git
cd nexus-symbiote
pip install -e ".[dev,all]"
```

Python 3.11 or later is required. Policy files need PyYAML (the `yaml` extra), and `verify-signature` needs Sigstore (the `sigstore` extra). The `all` extra installs every optional dependency.

## Quick Start

```bash
# Create a policy file with the default settings. Only `scan` discovers it.
nexus-symbiote init

# Preferred: import a ShadowScan report
nexus-symbiote import-shadowscan path/to/shadowscan-report.json -o aibom.json

# Or scan a project with the local scanners, which also read a conventional ShadowScan report in it
nexus-symbiote scan /path/to/agent-project -o aibom.json

# CycloneDX 1.7 output
nexus-symbiote import-shadowscan report.json -f cyclonedx -o aibom.cdx.json

# SPDX 3.0 output (experimental)
nexus-symbiote scan . -f spdx -o aibom.spdx.json

# SARIF for the GitHub Security tab
nexus-symbiote scan . -f sarif -o results.sarif

# Validate, score, diff, and summarize
nexus-symbiote validate aibom.json --project /path/to/project
nexus-symbiote risk aibom.json --threshold 50
nexus-symbiote diff old-aibom.json new-aibom.json --fail-on high
nexus-symbiote summary aibom.json

# Check a Sigstore bundle against an explicit signer identity and OIDC issuer
nexus-symbiote verify-signature artifact.whl --bundle artifact.whl.sigstore.json --identity <signer-identity> --issuer <oidc-issuer>
```

## What It Scans / Imports

| Source | Role | Notes |
|--------|------|-------|
| **ShadowScan** | Primary discovery | Imports a native JSON or CycloneDX report. `scan` also reads a conventional report in the project: `.shadowscan/report.json`, `shadowscan-report.json`, or `shadowscan.json`. |
| **A2A** | Local verification | Agent cards (`.well-known/agent.json`), client configuration, and server endpoints |
| **IDE agents** | Local verification | Coding-agent configuration, instruction files, and permission settings (for example `.claude/` and `CLAUDE.md`) |
| **MCP** | Local verification | Server configuration (`.mcp.json`), tool definition fingerprints (RFC 8785 JCS), transport checks |
| **Model** | Local verification | Weight files: serialization format safety, signature presence, and streamed weight hashes |
| **Prompt** | Local verification | Instruction and skill files: content hashes and hidden Unicode |
| **RAG** | Local verification | Vector store and retrieval configuration |
| **Registry** | Local verification | Lock files and dependency manifests: AI packages and version pinning |

Scanner names are `a2a`, `ide_agents`, `mcp`, `model`, `prompt`, `rag`, `registry`, and `shadowscan`. Every built-in scanner is required for a complete claim (see [Coverage and the Gate](#coverage-and-the-gate)).

## Component Types

Nexus SymBiote defines agent-native component categories. CycloneDX and SPDX mappings are projections that require validation against official schemas:

- **Agent**, **MCP Server**, **MCP Client**, **Tool**, **Model**, **Prompt Template**, **Guardrail Policy**, **Memory Store**, **RAG Source**, **Data Source**, **Registry Entry**, **Skill Package**, **A2A Client/Server**, **IDE Agent**, **Verified Extension**

## Trust Tiers & Assurance

Trust tiers and assurance levels (declared / observed / verified) are claims until independently verified under an explicit policy. Completeness claims record what was scanned and what failed.

Signing evidence has three states: `signature-not-found`, `signature-present-unverified`, and `signature-verified`. Scanners report only the first two. `signature-verified` is reserved for a cryptographic verification against an explicit identity and issuer, which `verify-signature` performs. Older spellings (`unsigned`, `sigstore-signed`, `pgp-signed`) are read as the current states and never mean verified.

## Coverage and the Gate

Each scanner ends with one status: `complete`, `partial`, `failed`, or `unknown`. A scan's claim is:

- **failed** when a scanner failed or recorded a failure;
- **partial** when a required scanner is missing or not complete, or when any surface was excluded;
- **complete** otherwise. With no claim at all, coverage is **unknown**.

The rules behind those states:

- **Absence is recorded as scanned.** A location that was checked and found empty is complete for that location.
- **Exclusion is a real exclusion.** A `scan.exclude_paths` match, an unreadable or unsafe input, an unsupported platform, or an oversized input that was skipped makes the claim partial.
- **Every built-in scanner is required.** A scanner that did not run is `unknown`, which makes the claim partial. Running a subset with `--scanner` or `scan.scanners` therefore fails the gate.

`risk --json-output` reports `coverage_status` and `coverage_reasons`.

## Risk Scoring

Scanners attach findings to components. Findings cover:

- model serialization format and code execution, including `trust_remote_code` enabled in a model configuration
- model signing status (no verified signature)
- version pinning for MCP servers and registry entries
- transport and authentication settings for MCP and A2A
- capability scope for MCP tools, and permission scope, instruction layering, and attestation for IDE agents
- hidden Unicode in prompts and instruction files
- RAG data integrity and discovery
- ShadowScan heuristic and shadow-agent findings

The score sums per-finding severity weights and is advisory. The `risk` gate passes only when the score is below the threshold, no finding is critical, and coverage is complete. Review individual findings and coverage, and enforce policy separately.

Findings in a category listed under `risk.ignore_categories` are removed from the score. Critical findings are never removed.

## CI/CD Integration

Prefer importing a ShadowScan report produced in a prior, least-privilege job. Review permissions and artifact contents.

A BOM given to `risk` or `validate` is self-asserted: nothing in the file shows that a scan produced it. Run the gate in the same job as the scan, and load the policy from a trusted location, for example the base branch.

### GitHub Action

```yaml
# .github/workflows/aibom.yml
name: AI Supply Chain Security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write # only when sarif-upload is 'true'
jobs:
  aibom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aisecnomad/nexus-symbiote@<reviewed-commit-sha>
        with:
          risk-threshold: '50'
          sarif-upload: 'true'
```

The caller needs `contents: read`. It also needs `security-events: write` when `sarif-upload` is `true`. A token without that permission, such as the read-only token on pull requests from forks, cannot upload SARIF.

The action is alpha. It installs the revision you reference, and its Python dependencies are resolved from version ranges at install time. Pin the action to a reviewed commit, and review the workflow's permissions and artifact contents before using it. Validation failures fail the job unless `fail-on-validation-error` is `false`.

Inputs:

| Input | Default | Description |
|-------|---------|-------------|
| `scan-path` | `.` | Project to scan |
| `format` | `json` | Output format: `json`, `cyclonedx`, `spdx`, or `sarif` |
| `output-file` | `nexus-symbiote-aibom.json` | BOM output path |
| `scanners` | empty (all) | Comma-separated scanner names: `a2a`, `ide_agents`, `mcp`, `model`, `prompt`, `rag`, `registry`, `shadowscan`. Empty runs all of them. |
| `policy-file` | empty | Policy file in the workspace, passed as `--policy`. Empty passes `--policy none`, so the scanned repository cannot choose the gate. Use a file from a trusted location. |
| `validate` | `true` | Run completeness and integrity validation |
| `fail-on-validation-error` | `true` | Fail the job when validation fails |
| `risk-check` | `true` | Run the risk gate |
| `risk-threshold` | `50` | Risk threshold. `0` explicitly disables the gate. |
| `sarif-upload` | `true` | Upload SARIF to GitHub Security (needs `security-events: write`) |
| `upload-artifact` | `true` | Upload the AIBOM as a workflow artifact |
| `python-version` | `3.12` | Python version used to run the action |

Outputs: `aibom-path` (path to the BOM), `risk-score` (score when the gate ran), and `risk-passed` (whether the gate passed).

### Manual CI

```yaml
- name: Generate AIBOM
  run: nexus-symbiote scan . -o aibom.json --policy none

- name: Validate
  run: nexus-symbiote validate aibom.json --project . --policy none

- name: SARIF for Security tab
  run: nexus-symbiote scan . -f sarif -o results.sarif --policy none

- name: Risk gate
  run: nexus-symbiote risk aibom.json --threshold 50.0 --policy none

- name: Drift detection
  run: |
    nexus-symbiote scan . -o current-aibom.json --policy none
    nexus-symbiote diff aibom-baseline.json current-aibom.json --fail-on high
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/aisecnomad/nexus-symbiote
    rev: <reviewed-commit-sha>
    hooks:
      - id: nexus-symbiote-scan
      - id: nexus-symbiote-risk
```

Both hooks run with `--policy none`. Each writes only to a private temporary directory that is removed on exit, and nothing is written into the repository. The scan hook is installed by pre-commit. The risk hook runs the `nexus-symbiote` command found on `PATH` with a threshold of 50, so install the tool first.

## Policy Configuration

Policy files set scan, risk, validation, and output defaults. Create one with `nexus-symbiote init`:

```yaml
# .nexus-symbiote.yaml
version: "1.0"

scan:
  scanners: [a2a, ide_agents, mcp, model, prompt, rag, registry, shadowscan]
  exclude_paths: [node_modules, .git, __pycache__, .venv]

risk:
  fail_threshold: 50.0
  warn_threshold: 25.0
  ignore_categories: []

validate:
  require_completeness: true
  require_integrity: true
  minimum_assurance_level: declared

output:
  default_format: json
```

| Key | Default | Effect |
|-----|---------|--------|
| `version` | `"1.0"` | Policy schema version |
| `scan.scanners` | all eight | Scanners to run when `--scanner` is not given |
| `scan.exclude_paths` | `node_modules`, `.git`, `__pycache__`, `.venv` | Paths that scanners skip. Each match is recorded as an exclusion. |
| `risk.fail_threshold` | `50.0` | The gate fails at or above this score. Bounded to 0 through 100. |
| `risk.warn_threshold` | `25.0` | Score at which the risk level is labelled high. Advisory; the gate does not use it. Bounded to 0 through 100, and not above `fail_threshold`. |
| `risk.ignore_categories` | `[]` | Non-critical findings in these categories are removed from the score |
| `validate.require_completeness` | `true` | Whether an incomplete coverage claim fails `validate` |
| `validate.require_integrity` | `true` | Whether integrity findings fail `validate` |
| `validate.minimum_assurance_level` | `declared` | Minimum assurance level that `validate` requires: `declared`, `observed`, or `verified` |
| `output.default_format` | `json` | Output format for `scan` when `-f` is not given |

Every field is enforced, and unknown keys are rejected.

Discovery and loading:

- `scan` looks for `.nexus-symbiote.yaml`, then `.nexus-symbiote.yml`, in the scanned directory and up to 20 parent directories. Symbolic links are skipped.
- `scan --policy PATH` loads that file instead. `scan --policy none` disables discovery.
- `risk` and `validate` read a policy only with `--policy PATH`. They never discover one, and `--policy none` has no effect there.
- `risk --threshold` sets the gate. When it is omitted, `risk` uses `risk.fail_threshold` from a policy given with `--policy PATH`, and 50.0 otherwise.
- An invalid policy file fails the command. The error names the file and the failing locations, never the values, and nothing falls back to defaults.

A policy found in a scanned repository is controlled by that repository. In CI, pass `--policy` with a file from a trusted location, for example the base branch, or pass `--policy none`. Then the code under review cannot choose the gate.

## AIBOM Diff

`nexus-symbiote diff OLD NEW` compares two native AIBOM files. It reports added, removed, and modified components and dependency edges, with security alerts for:

- tool definition hash changes, which suggest a rug-pull (critical)
- trust tier downgrades
- version pin removals
- serialization safety changes
- signing status regressions
- file hash and prompt content hash changes
- new components

Fingerprints from an unknown or different canonicalization version are not compared. The diff asks for re-collection and re-approval instead.

`--fail-on` sets the lowest severity that fails the command: `critical`, `high` (the default), `medium`, `low`, `info`, or `none`. Use `--json-output` for machine-readable output.

## Output Formats

- **Native JSON**: the full Nexus SymBiote schema, with all agent-native fields. See [JSON Schema](#json-schema).
- **CycloneDX 1.7**: an experimental projection with `nexus-symbiote:` properties. CycloneDX 1.7 is the current published minor version. Validate generated documents against the official schema before use.
- **SPDX 3.0**: an experimental JSON-LD projection. Standards and profile conformance have not been established.
- **SARIF 2.1.0**: GitHub Security tab integration for risk findings.

Keep the native BOM as the authoritative record. The CycloneDX and SPDX exports do not carry the deployment profile, and they can omit explicit `false` values.

## Output Handling

- Output files are written with mode `0600`. Each is written to a temporary file that replaces the target atomically, and a symbolic link at the output path is refused.
- Credential-shaped values in component fields are redacted before output: private key blocks, token-shaped strings, `password=`-style assignments, values under secret-looking keys, and URL userinfo and query strings. Tool definition text, input schemas, annotations, names, references, and hashes are not changed, because they are fingerprinted.
- Set `SOURCE_DATE_EPOCH` for reproducible output. The timestamp comes from the epoch, and the serial number is derived from the content, so identical input produces identical output.
- Model weights are hashed as a stream. The 256 GiB limit is a sanity bound, not a memory limit.
- Scanner inputs are read without following symbolic links. They must be regular files, and text inputs are capped at 4 MiB.

## Platform Support

Windows is not supported. Scanners need no-follow, descriptor-relative file access. Where that access is unavailable, including on Windows, scanners fail closed and the claim is not complete.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Pass |
| `1` | Gate, validation, or diff-threshold failure |
| `2` | Usage or input error |
| `3` | Unexpected internal error |

## Architecture

```
src/nexus_symbiote/
  cli.py        — Click CLI (scan, import-shadowscan, validate, risk, diff, summary, init, verify-signature)
  policy.py     — .nexus-symbiote.yaml model, discovery, and loading
  core/         — Pydantic v2 domain models, enums, AIBOM container, vocabularies, redaction, text safety, RFC 8785 hashing
  scanners/     — Eight scanners (including the ShadowScan importer) and the scanner base class
  generators/   — Native JSON, CycloneDX 1.7, SPDX 3.0, SARIF 2.1.0
  validators/   — Coverage rule, completeness, integrity, risk scoring
  diff/         — AIBOM comparison with security alerts
  utils/        — Bounded no-follow reads and safe writes, project-confined hashing, Sigstore verification
```

## Development

```bash
pip install -e ".[dev,all]"
pytest
ruff check src/ tests/
mypy src/
```

CI runs the same checks: ruff (`ruff>=0.4,<1`), mypy, pytest on Python 3.11 through 3.13, and `pip-audit` against the `all` extra.

## Examples

See [`examples/customer-support-agent.json`](examples/customer-support-agent.json) for a realistic AIBOM showing a customer support agent with models, MCP servers, tools, prompts, RAG sources, and risk assessments.

See [`schemas/examples/minimal-aibom.json`](schemas/examples/minimal-aibom.json) for a minimal example.

## JSON Schema

The AIBOM schema is defined in [`schemas/nexus-symbiote-aibom-1.0.schema.json`](schemas/nexus-symbiote-aibom-1.0.schema.json).

## License

MIT. See [LICENSE](LICENSE).
