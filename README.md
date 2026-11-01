# SymBiote

**Agent Bill of Materials (AIBOM)** for production AI agent supply chain security.

SymBiote scans your AI agent project and generates a comprehensive inventory of every component in the supply chain — MCP servers, tools, models, prompts, RAG sources, registries, and skills — with integrity hashes, trust classification, and risk scoring. Output formats include native JSON, CycloneDX 1.7, and SPDX 3.0.

## Why

Production AI agents assemble capabilities from dozens of sources: MCP servers installed via `npx`, model weights from Hugging Face, system prompts in version control, vector stores for RAG, and packages from npm/PyPI. A single poisoned tool definition or unsigned model weight can compromise the entire system.

SymBiote provides the missing visibility. It answers: *What exactly is running in my agent, where did it come from, and should I trust it?*

## Install

```bash
pip install symbote
```

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

SymBiote defines 11 agent-native component types that neither CycloneDX nor SPDX provide:

- **Agent** — An autonomous AI agent deployment with autonomy level (L0–L4)
- **MCP Server** — Tool provider with transport, version pinning, schema hash
- **Tool** — Individual tool definition with JCS-canonical definition hash
- **Model** — Weight file with serialization safety and signing status
- **Prompt Template** — System prompt or instruction file with content hash
- **Guardrail Policy** — Safety classifier or output validator
- **Memory Store** — Persistent agent memory with write authority
- **RAG Source** — Vector store or knowledge base with source URIs
- **Data Source** — Training or fine-tuning dataset
- **Registry Entry** — Package registry trust and attestation
- **Skill Package** — Plugin or extension with capability declaration

## Trust Tiers

Every component is classified into a trust tier:

| Tier | Meaning |
|------|---------|
| `internal-verified` | Owned and signed by your organization |
| `internal-unverified` | Owned but not cryptographically verified |
| `third-party-signed` | External with Sigstore/PGP signature |
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

The `symbote risk` command scores all findings and applies a pass/fail gate for CI integration.

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

The action scans your project, runs validation and risk scoring, uploads SARIF findings to the GitHub Security tab, and saves the AIBOM as a build artifact.

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
  exclude_paths: ["node_modules", ".git", "__pycache__"]

risk:
  fail_threshold: 50.0
  warn_threshold: 25.0
  ignore_categories: []

output:
  default_format: "json"
```

Policy files are discovered by searching the project directory and its parents, so a monorepo can have one policy at the root.

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
- **CycloneDX 1.7** — Standard SBOM with `symbote:` property extensions
- **SPDX 3.0** — JSON-LD with AI/Dataset profiles and `symbote:` extensions
- **SARIF 2.1.0** — GitHub Security tab integration for risk findings

## Architecture

```
src/symbote/
  core/        — Pydantic v2 domain models, enums, AIBOM container, RFC 8785 JCS hashing
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

MIT. See [LICENSE](LICENSE).
