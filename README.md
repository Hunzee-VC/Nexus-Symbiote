# SymBiote

**Agent Bill of Materials (AIBOM)** for exploring and verifying AI agent supply chains.

> **Alpha:** SymBiote is under active development. Do not use its output as the sole basis for production deployment, authorization, compliance, or a claim that an agent is safe. See [SECURITY.md](SECURITY.md).

## Architecture: Discovery + Verification

**Nexus-ShadowScan** is the primary multi-surface discovery engine. It inventories shadow AI agents and evidence across code, identity, LLM gateways, low-code, SaaS, cloud, endpoints, network, and runtime.

**SymBiote** is the verification, integrity, and bill-of-materials layer. It consumes ShadowScan reports (native JSON or CycloneDX), maps findings into an agent-native domain model, applies confined integrity checks, risk scoring, policy evaluation, and emits standards-oriented AIBOMs (native, CycloneDX 1.7, SPDX 3.0, SARIF).

Recommended workflow:
1. Run ShadowScan for discovery (least-privilege, fail-closed).
2. `symbiote import-shadowscan report.json -o aibom.json` (or place report at `.shadowscan/report.json` and run `symbiote scan`).
3. `symbiote validate`, `symbiote risk`, and emit the desired format.
4. Gate in CI on critical findings and completeness claims.

Local project scanners (MCP, model, prompt, RAG, registry) remain available for fine-grained, file-level verification that complements the broader discovery.

## Why

Production AI agents assemble capabilities from dozens of sources: MCP servers, model weights, system prompts, vector stores, and packages. A single poisoned tool definition or unsigned model weight can compromise the entire system.

SymBiote helps teams turn discovery evidence into a structured, verifiable AIBOM and apply explicit integrity and risk policies. A detection or digest alone does not establish runtime identity, provenance, completeness, or safety.

## Install

Install from a reviewed checkout of this repository. Verify published distributions independently before installing them.

For development:
```bash
git clone https://github.com/aisecnomad/SymBiote.git
cd SymBiote
pip install -e ".[dev]"
```

## Quick Start

```bash
# Initialize a policy config
symbiote init

# Preferred: import a ShadowScan report
symbiote import-shadowscan path/to/shadowscan-report.json -o aibom.json

# Or scan a project (looks for .shadowscan/report.json and runs local scanners)
symbiote scan /path/to/agent-project -o aibom.json

# Generate CycloneDX 1.7 output
symbiote import-shadowscan report.json -f cyclonedx -o aibom.cdx.json

# Validate, score, and diff
symbiote validate aibom.json --project /path/to/project
symbiote risk aibom.json
symbiote diff old-aibom.json new-aibom.json
symbiote summary aibom.json
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

SymBiote defines agent-native component categories. CycloneDX and SPDX mappings are projections that require validation against official schemas:

- **Agent**, **MCP Server**, **MCP Client**, **Tool**, **Model**, **Prompt Template**, **Guardrail Policy**, **Memory Store**, **RAG Source**, **Data Source**, **Registry Entry**, **Skill Package**, **A2A Client/Server**, **IDE Agent**, **Verified Extension**

## Trust Tiers & Assurance

Trust tiers and assurance levels (declared / observed / verified) are claims until independently verified under an explicit policy. Completeness claims record what was scanned and what failed.

## Risk Scoring

Risk findings cover serialization safety, signing status, version pinning, tool definition mutations, trust_remote_code, and ShadowScan heuristic / shadow status. The numeric score is advisory. Any critical finding fails the gate. Review individual findings and coverage; enforce policy separately.

## CI/CD Integration

See the GitHub Action and pre-commit examples below. Prefer importing a ShadowScan report produced in a prior, least-privilege job. Review permissions and artifact contents.

## Architecture

```
src/symbiote/
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

## License

MIT. See [LICENSE](LICENSE).
