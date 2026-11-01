# SymBiote

**Agent Bill of Materials (AIBOM)** for exploring AI agent supply chains.

> **Alpha:** SymBiote is under active development. Do not use its output as the sole basis for production deployment, authorization, compliance, or a claim that an agent is safe. See [SECURITY.md](SECURITY.md).

SymBiote inspects supported local project files and produces an inventory of detected components, such as configured MCP servers, model files, instructions and RAG-related configuration. It can also generate risk findings and proposed CycloneDX, SPDX and SARIF output. Static discovery does not establish what is running, effective permissions, registry membership, or complete coverage.

## Why

Production AI agents assemble capabilities from dozens of sources: MCP servers installed via `npx`, model weights from Hugging Face, system prompts in version control, vector stores for RAG, and packages from npm/PyPI. A single poisoned tool definition or unsigned model weight can compromise the entire system.

SymBiote helps teams investigate what is declared in supported project files and where additional evidence is needed. A detection, digest or signature file alone does not establish runtime identity, provenance, completeness or safety.

## Install

Install from a reviewed checkout of this repository. Verify published distributions independently before installing them; this README does not assert that a package on a public index corresponds to this source.

For development:
```bash
git clone https://github.com/aisecnomad/SymBiote.git
cd SymBiote
pip install -e ".[dev]"
```

## Quick Start

```bash
# Initialize a policy config
symbote init

# Scan a project and generate an AIBOM
symbote scan /path/to/agent-project -o aibom.json

# Generate CycloneDX 1.7 output
symbote scan . -f cyclonedx -o aibom.cdx.json

# Generate SPDX 3.0 output
symbote scan . -f spdx -o aibom.spdx.json

# Generate SARIF for GitHub Security tab
symbote scan . -f sarif -o results.sarif

# Validate an existing AIBOM
symbote validate aibom.json --project /path/to/project

# Score supply chain risks
symbote risk aibom.json

# Compare two AIBOM snapshots
symbote diff old-aibom.json new-aibom.json

# Print a summary
symbote summary aibom.json
```

## What It Scans

| Scanner | Discovers | Config Files |
|---------|-----------|--------------|
| **MCP** | MCP servers, tool definitions, schema hashes | `.mcp.json`, `mcp.json`, `claude_desktop_config.json` |
| **Model** | Weight files, serialization safety, signing status | `.safetensors`, `.pt`, `.pkl`, `.gguf`, `config.json` |
| **Prompt** | System prompts, instruction files, skill packages | `CLAUDE.md`, `.cursorrules`, `.claude/skills/` |
| **RAG** | Vector stores, embedding configs, data sources | `rag_config.json`, `.env`, Python imports |
| **Registry** | AI package dependencies, version pinning | `package.json`, `requirements.txt`, `Dockerfile` |

## Component Types

SymBiote defines 11 component categories for its internal model. CycloneDX and SPDX already represent many AI and software supply-chain concepts; their mappings to agent-specific semantics require careful validation:

- **Agent** — An autonomous AI agent deployment with autonomy level (L0–L4)
- **MCP Server** — Tool provider with transport, version pinning, schema hash
- **Tool** — Individual tool definition with a definition fingerprint (cross-implementation JCS conformance is not yet established)
- **Model** — Weight file with serialization safety and signing status
- **Prompt Template** — System prompt or instruction file with content hash
- **Guardrail Policy** — Safety classifier or output validator
- **Memory Store** — Persistent agent memory with write authority
- **RAG Source** — Vector store or knowledge base with source URIs
- **Data Source** — Training or fine-tuning dataset
- **Registry Entry** — Package registry trust and attestation
- **Skill Package** — Plugin or extension with capability declaration

## Trust Tiers

The schema can represent the following trust tiers. Treat values as claims unless supporting evidence has been independently verified under an explicit trust policy:

| Tier | Meaning |
|------|---------|
| `internal-verified` | Owned and signed by your organization |
| `internal-unverified` | Owned but not cryptographically verified |
| `third-party-signed` | Intended to represent an external component with verified signing evidence |
| `third-party-unsigned` | External without signature |
| `untrusted-public` | Public source with no attestation |
| `unknown` | Trust status not determined |

## Risk Scoring

SymBiote assesses risks across categories:

- **Serialization format** — Pickle/PT files allow arbitrary code execution (critical)
- **Signing status** — Unsigned models lack provenance verification (high)
- **Version pinning** — Floating versions enable supply chain attacks (medium)
- **Tool definition hash** — Changed hashes indicate rug-pull attacks (critical)
- **trust_remote_code** — Arbitrary code execution from model repos (critical)
- **Data integrity** — Unencrypted RAG sources (high)

The current risk score is a sum of finding weights; a single critical finding can fall below the default threshold. It is not a sufficient production gate. Review individual findings and coverage, and enforce independently defined severity and evidence policies.

## CI/CD Integration

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
      - uses: aisecnomad/SymBiote@main
        with:
          risk-threshold: '50'
          sarif-upload: 'true'
```

The current action is experimental: it installs an unpinned package and does not fail the job on validation errors. Do not rely on it as a security gate until these issues are resolved. Review the workflow's permissions and artifact contents before using it.

### Manual CI

```yaml
- name: Generate AIBOM
  run: symbote scan . -o aibom.json

- name: SARIF for Security tab
  run: symbote scan . -f sarif -o results.sarif

- name: Risk gate
  run: symbote risk aibom.json --threshold 50.0

- name: Drift detection
  run: symbote diff aibom-baseline.json <(symbote scan . 2>/dev/null) --json-output
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/aisecnomad/SymBiote
    rev: main
    hooks:
      - id: symbote-scan
      - id: symbote-risk
```

## Policy Configuration

Create a `.symbote.yaml` to customize scan behavior, risk thresholds, and output format:

```bash
symbote init
```

```yaml
# .symbote.yaml
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

Policy files are discovered by searching the project directory and its parents. Not every field in the policy schema is enforced by every command; verify behavior against the implementation before relying on it.

## AIBOM Diff

The `symbote diff` command compares two AIBOM snapshots and detects:

- New/removed components in the supply chain
- Trust tier downgrades
- Tool definition hash mutations (rug-pull detection)
- Version pin removals
- Serialization safety changes
- Signing status regressions

## Output Formats

- **Native JSON** — Full SymBiote schema with all agent-native fields
- **CycloneDX 1.7** — Experimental projection with `symbote:` properties; validate generated documents against the official schema before use.
- **SPDX 3.0** — Experimental JSON-LD projection; standards and profile conformance have not been established.
- **SARIF 2.1.0** — GitHub Security tab integration for risk findings

## Architecture

```
src/symbote/
  core/        — Pydantic v2 domain models, enums, AIBOM container, canonicalization
  scanners/    — Component discovery (MCP, model, prompt, RAG, registry)
  generators/  — Output format generators (native, CycloneDX 1.7, SPDX 3.0, SARIF 2.1.0)
  validators/  — Completeness, integrity, and risk scoring
  diff/        — AIBOM version comparison with security alerts
  utils/       — Sigstore verification, file hash utilities
  cli.py       — Click CLI entrypoint
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

The AIBOM schema is defined in [`schemas/symbote-aibom-1.0.schema.json`](schemas/symbote-aibom-1.0.schema.json).

## License

Apache-2.0
