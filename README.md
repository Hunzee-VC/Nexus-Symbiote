# Nexus SymBiote

**Agent Bill of Materials (AIBOM)** for exploring and verifying AI agent supply chains.

> **Alpha:** Nexus SymBiote is under active development. Do not use its output as the sole basis for production deployment, authorization, compliance, or a claim that an agent is safe. See [SECURITY.md](SECURITY.md).

## Architecture: Discovery + Verification

**Nexus-ShadowScan** is the primary multi-surface discovery engine. It inventories shadow AI agents and evidence across code, identity, LLM gateways, low-code, SaaS, cloud, endpoints, network, and runtime.

**Nexus SymBiote** is the verification, integrity, and bill-of-materials layer. It consumes ShadowScan reports (native JSON or CycloneDX), maps findings into an agent-native domain model, applies confined integrity checks, risk scoring, policy evaluation, and emits standards-oriented AIBOMs (native, CycloneDX 1.7, SPDX 3.0, SARIF).

Recommended workflow:
1. Run ShadowScan for discovery (least-privilege, fail-closed).
2. `nexus-symbiote import-shadowscan report.json -o aibom.json` (or place report at `.shadowscan/report.json` and run `nexus-symbiote scan`).
3. `nexus-symbiote validate`, `nexus-symbiote risk`, and emit the desired format.
4. Gate in CI on critical findings and completeness claims.

Local project scanners (MCP, model, prompt, RAG, registry) remain available for fine-grained, file-level verification that complements the broader discovery.

## Why

Production AI agents assemble capabilities from dozens of sources: MCP servers, model weights, system prompts, vector stores, and packages. A single poisoned tool definition or unsigned model weight can compromise the entire system.

Nexus SymBiote helps teams turn discovery evidence into a structured, verifiable AIBOM and apply explicit integrity and risk policies. A detection or digest alone does not establish runtime identity, provenance, completeness, or safety.

## Install

Install from a reviewed checkout of this repository. Verify published distributions independently before installing them.

For development:
```bash
git clone https://github.com/aisecnomad/nexus-symbiote.git
cd nexus-symbiote
pip install -e ".[dev]"
```

## Quick Start

```bash
# Initialize a policy config
nexus-symbiote init

# Preferred: import a ShadowScan report
nexus-symbiote import-shadowscan path/to/shadowscan-report.json -o aibom.json

# Or scan a project (looks for .shadowscan/report.json and runs local scanners)
nexus-symbiote scan /path/to/agent-project -o aibom.json

# Generate CycloneDX 1.7 output
nexus-symbiote import-shadowscan report.json -f cyclonedx -o aibom.cdx.json

# Generate SPDX 3.0 output
nexus-symbiote scan . -f spdx -o aibom.spdx.json

# Generate SARIF for GitHub Security tab
nexus-symbiote scan . -f sarif -o results.sarif

# Validate, score, and diff
nexus-symbiote validate aibom.json --project /path/to/project
nexus-symbiote risk aibom.json
nexus-symbiote diff old-aibom.json new-aibom.json --fail-on high
nexus-symbiote summary aibom.json

# Cryptographically verify model signatures against an explicit signer policy
nexus-symbiote verify aibom.json --project /path/to/project \
  --identity you@example.com --issuer https://accounts.google.com
```

## What It Scans / Imports

| Source | Role | Notes |
|--------|------|-------|
| **ShadowScan** | Primary discovery | Multi-surface inventory; import JSON or CycloneDX |
| **MCP** | Local verification | Configs, tool definition hashes (JCS), transport checks |
| **Model** | Local verification | Serialization safety, signing presence, weight hashes |
| **Prompt** | Local verification | Content hashes, instruction files |
| **RAG** | Local verification | Vector store / embedding configs |
| **Registry** | Local verification | Package pins and registry entries |

## Component Types

Nexus SymBiote defines agent-native component categories. CycloneDX and SPDX mappings are projections that require validation against official schemas:

- **Agent**, **MCP Server**, **MCP Client**, **Tool**, **Model**, **Prompt Template**, **Guardrail Policy**, **Memory Store**, **RAG Source**, **Data Source**, **Registry Entry**, **Skill Package**, **A2A Client/Server**, **IDE Agent**, **Verified Extension**

## Trust Tiers & Assurance

Trust tiers and assurance levels (declared / observed / verified) are claims until independently verified under an explicit policy. Completeness claims record what was scanned and what failed.

## Risk Scoring

Risk findings cover serialization safety (including content-sniffed format mismatches), signing status, version pinning, tool definition mutations, trust_remote_code, and ShadowScan heuristic / shadow status. The numeric score is advisory. The gate fails on any critical finding, on a score at or above the fail threshold, and on collection coverage that is not "reported" (pass `--allow-partial-coverage` to gate on risk alone). The specific reason is reported as `gate_reason`.

## CI/CD Integration

Prefer importing a ShadowScan report produced in a prior, least-privilege job. Review permissions and artifact contents.

### GitHub Action

```yaml
# .github/workflows/aibom.yml
name: AI Supply Chain Security
on: [push, pull_request]
jobs:
  aibom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aisecnomad/nexus-symbiote@main # pin to a commit SHA in production
        with:
          risk-threshold: '50'
          sarif-upload: 'true'
```

The action installs this repository's checked-out revision and fails the job on validation errors and on a risk-gate failure. Pin the action to a commit SHA (not `@main`) in production, and review the workflow's permissions and artifact contents. The risk gate is evaluated from a trusted temporary directory and the threshold is passed explicitly, so a `.nexus-symbiote.yaml` placed inside a scanned (untrusted) repository cannot weaken it.

### Manual CI

```yaml
- name: Generate AIBOM
  run: nexus-symbiote scan . -o aibom.json

- name: SARIF for Security tab
  run: nexus-symbiote scan . -f sarif -o results.sarif

- name: Risk gate
  run: nexus-symbiote risk aibom.json --threshold 50.0

- name: Drift detection
  run: nexus-symbiote diff aibom-baseline.json <(nexus-symbiote scan . 2>/dev/null) --json-output
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/aisecnomad/nexus-symbiote
    rev: main
    hooks:
      - id: nexus-symbiote-scan
      - id: nexus-symbiote-risk
```

## Policy Configuration

Create a `.nexus-symbiote.yaml` to customize scan behavior, risk thresholds, and output format:

```bash
nexus-symbiote init
```

```yaml
# .nexus-symbiote.yaml
version: "1.0"

scan:
  scanners: ["mcp", "model", "prompt", "rag", "registry"]

risk:
  fail_threshold: 50.0
  warn_threshold: 25.0
  ignore_categories: []

output:
  default_format: "json"
```

The gating commands (`risk`, `validate`) load policy from a **trusted** location — an explicit `--policy` path, or a search upward from your current working directory — never from the scanned project or the BOM's own directory, so an untrusted repository cannot supply its own gate. `scan` reads scan configuration (scanner selection, output format) from the project being scanned. Enforced fields: `risk.fail_threshold`, `risk.warn_threshold`, `risk.ignore_categories`, and `validate.require_completeness` / `require_integrity` / `minimum_assurance_level`. `scan.exclude_paths` is not yet enforced by the scanners.

## AIBOM Diff

The `nexus-symbiote diff` command compares two AIBOM snapshots and detects:

- New/removed components in the supply chain
- Trust tier downgrades
- Tool definition hash mutations (rug-pull detection)
- Version pin removals
- Serialization safety changes
- Signing status regressions

## Output Formats

- **Native JSON** — Full Nexus SymBiote schema with all agent-native fields
- **CycloneDX 1.7** — Experimental projection with `nexus-symbiote:` properties; validate generated documents against the official schema before use.
- **SPDX 3.0** — Experimental JSON-LD projection; standards and profile conformance have not been established.
- **SARIF 2.1.0** — GitHub Security tab integration for risk findings

## Architecture

```
src/nexus_symbiote/
  core/        — Pydantic v2 domain models, enums, AIBOM container, canonicalization
  scanners/    — Local scanners + ShadowScanImporter (primary discovery)
  generators/  — native, CycloneDX 1.7, SPDX 3.0, SARIF
  validators/  — Completeness, integrity, risk scoring
  diff/        — AIBOM comparison with security alerts
  utils/       — Confined hashing, crypto helpers
  cli.py       — Click CLI (scan, import-shadowscan, validate, risk, diff, …)
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/
mypy src/
```

## Examples

See [`examples/customer-support-agent.json`](examples/customer-support-agent.json) for a realistic AIBOM showing a customer support agent with models, MCP servers, tools, prompts, RAG sources, and risk assessments.

See [`schemas/examples/minimal-aibom.json`](schemas/examples/minimal-aibom.json) for a minimal example.

## JSON Schema

The AIBOM schema is defined in [`schemas/nexus-symbiote-aibom-1.0.schema.json`](schemas/nexus-symbiote-aibom-1.0.schema.json).

## License

MIT. See [LICENSE](LICENSE).
