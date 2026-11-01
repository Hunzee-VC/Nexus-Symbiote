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
nexus-symbiote diff old-aibom.json new-aibom.json
nexus-symbiote summary aibom.json

# Create an approved baseline for drift gating in CI
nexus-symbiote baseline . -o .nexus-symbiote-baseline.json

# Verify descriptors from independently pinned local MCP launchers
nexus-symbiote verify-live aibom.json --project . --launch-policy "$TRUSTED_LAUNCH_POLICY"

# Emit a separate candidate inventory for review
nexus-symbiote verify-live aibom.json --project . --launch-policy "$TRUSTED_LAUNCH_POLICY" --record > candidate.json

# Generate CycloneDX VEX statements keyed to model digests and adaptation events
nexus-symbiote vex aibom.json -o vex.json

# Query OSV.dev for known vulnerabilities in discovered packages (network)
nexus-symbiote advisories aibom.json -o advisories.json
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

Nexus SymBiote defines 16 agent-native component categories. CycloneDX and SPDX mappings are projections that require validation against official schemas:

- **Agent**, **MCP Server**, **MCP Client**, **Tool**, **Model**, **Prompt Template**, **Guardrail Policy**, **Memory Store**, **RAG Source**, **Data Source**, **Registry Entry**, **Skill Package**, **A2A Client/Server**, **IDE Agent**, **Verified Extension**

## Trust Tiers & Assurance

Trust tiers and assurance levels (declared / observed / verified) are claims until independently verified under an explicit policy. Completeness claims record what was scanned and what failed.

## Risk Scoring

Risk findings cover serialization safety, signing status, version pinning, tool definition mutations, trust_remote_code, and ShadowScan heuristic / shadow status. The numeric score is advisory. Any critical finding fails the gate. Review individual findings and coverage; enforce policy separately.

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
      - uses: aisecnomad/nexus-symbiote@main
        with:
          risk-threshold: '50'
          sarif-upload: 'true'
```

The current action is experimental: it installs the checked-out revision of the
action itself (pinned by the `uses:` ref) rather than a published, attested
package, and its failure semantics have not been audited against every input
combination. Review the workflow's permissions and artifact contents before
using it as a gate.

### Manual CI

```yaml
- name: Generate AIBOM
  run: nexus-symbiote scan . -o aibom.json

- name: SARIF for Security tab
  run: nexus-symbiote scan . -f sarif -o results.sarif

- name: Risk gate
  run: nexus-symbiote risk aibom.json --threshold 50.0

- name: Drift detection against committed baseline
  run: |
    nexus-symbiote scan . -o current.json
    nexus-symbiote diff .nexus-symbiote-baseline.json current.json --json-output > drift.json
    python -c "import json,sys; d=json.load(open('drift.json')); sys.exit(1 if d.get('security_alerts') or d.get('total_changes',0)>0 else 0)"

- name: Rug-pull detection (runtime)
  run: nexus-symbiote verify-live aibom.json --project . --launch-policy "$TRUSTED_LAUNCH_POLICY"
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

Policy files are discovered by searching the project directory and its parents. Not every field in the policy schema is enforced by every command; verify behavior against the implementation before relying on it.

## AIBOM Diff

The `nexus-symbiote diff` command compares two AIBOM snapshots and detects:

- New/removed components in the supply chain
- Trust tier downgrades
- Tool definition hash mutations (rug-pull detection)
- Version pin removals
- Serialization safety changes
- Signing status regressions

## Rug-Pull Detection

SymBiote records a canonical fingerprint (RFC 8785 JCS) of every tool
definition it observes. Two enforcement modes are available:

1. **Snapshot diffing** — `symbiote diff baseline.json current.json` flags any
   tool whose definition hash changed between two scans.
2. **Live verification** — `nexus-symbiote verify-live` compares the observed
   name, description, input schema and annotations with the approved tool
   fingerprint. The current transport supports pinned standalone POSIX stdio
   launchers. An unreachable server, a missing tool, an unsupported descriptor,
   or an incomplete observation fails the verification gate.

Provision the launch policy outside the scanned checkout through a trusted
operator channel. Key each launcher by its exact BOM server reference. Obtain
the SHA-256 digest independently, for example from an approved release.

```json
{"mcp-server:weather":{"command":"/opt/operator-tools/weather","sha256":"sha256:<64 lowercase hex characters>"}}
```

The verifier stages the pinned file in a private directory and runs it without
arguments, with a minimal environment and one deadline across enumeration pages.
Run it under a disposable, isolated identity with restricted network and file
access. The pin covers the executable bytes. Its interpreter, linked libraries
and other host dependencies must also be trusted. `--record` emits a candidate
native BOM on stdout after complete collection. Review that file before adopting
it as a baseline. A descriptor match covers only the fields hashed by this
fingerprint version.

## Model Supply-Chain Integrity

Whole-file hashes cannot distinguish a legitimate reload from a poisoned
single tensor. SymBiote records two additional per-model digests for
safetensors artifacts:

- **`tensor_inventory_sha256`** — digest over the sorted tensor inventory
  (name, dtype, shape, byte offsets). Adding a backdoor tensor or swapping an
  adapter layer changes this even when a whole-file hash is fresh.
- **`safetensors_header_sha256`** — digest over the parsed safetensors header
  itself.

`symbiote validate --project` recomputes both and flags
`tensor_inventory_mismatch` on drift.

## Model VEX

`symbiote vex` emits a CycloneDX 1.7 VEX document where each finding is keyed
to the exact artifact digests it was observed on — including weight digest,
tensor inventory digest, derivation type (fine-tune, LoRA, quantization), and
base model reference. A model finding tracks the weight revision it applies
to, not a version string.

## OSV Advisory Lookups

`symbiote advisories` queries [OSV.dev](https://osv.dev) for the registry
packages discovered by the static scan, and maps known vulnerabilities back to
their AIBOM components. This is the only command that contacts the network;
`scan` never does.

## Output Formats

- **Native JSON** — Full Nexus SymBiote schema with all agent-native fields
- **CycloneDX 1.7** — Experimental projection with `nexus-symbiote:` properties; validate generated documents against the official schema before use.
- **SPDX 3.0** — Experimental JSON-LD projection; standards and profile conformance have not been established.
- **SARIF 2.1.0** — GitHub Security tab integration for risk findings

## Architecture

```
src/nexus_symbiote/
  core/        — Pydantic v2 domain models, enums, AIBOM container, canonicalization
  scanners/    — Component discovery (MCP, model, prompt, RAG, registry, A2A, IDE agents) + ShadowScanImporter (primary discovery)
  generators/  — Output formats (native, CycloneDX 1.7, SPDX 3.0, SARIF 2.1.0, VEX)
  validators/  — Completeness, integrity, and risk scoring
  diff/        — AIBOM version comparison with security alerts
  live/        — Live MCP server verification (runtime rug-pull detection)
  advisories.py — OSV.dev advisory lookups for discovered registry packages
  utils/       — Confined hashing, Sigstore verification, file hash utilities
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

The AIBOM schema is defined in [`schemas/nexus-symbiote-aibom-1.0.schema.json`](schemas/nexus-symbiote-aibom-1.0.schema.json).

## License

MIT. See [LICENSE](LICENSE).
