<p align="center">
  <strong>Symbiote</strong><br>
  <em>The Agent Bill of Materials (AgentBOM) toolkit for the agentic-AI supply chain.</em>
</p>

<p align="center">
  <a href="https://github.com/aisecnomad/symbiote/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/aisecnomad/symbiote/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-orange">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="CycloneDX 1.7" src="https://img.shields.io/badge/CycloneDX-1.7-success">
  <img alt="SPDX 3.0.1" src="https://img.shields.io/badge/SPDX-3.0.1-success">
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-lightgrey"></a>
</p>

Symbiote generates, validates, diffs, verifies, attests and enforces **AgentBOMs**: bills of materials for AI
agents that answer the questions a software SBOM cannot:

> **Which agent is running, what can it access or change, where did its dependencies come from, who authorized
> it, and has any of that changed since approval?**

It **supports and extends CycloneDX 1.7 and SPDX 3.0.1 without forking either standard**: every document it emits
validates against the official schemas, agent-specific semantics travel through the standards' own extension
points under one tool-neutral `agentbom:` vocabulary, and a companion document carries what neither format can
express. Nothing is invented at the top level of either format.

---

## Why an AgentBOM

A classic SBOM inventories packages. An agent's supply chain is different in kind, not degree:

| What an agent depends on | Why a package list misses it |
|---|---|
| **Tool definitions** (MCP servers, their names, descriptions and JSON schemas) | The text the model reads is the attack surface — tool poisoning and rug pulls change it *after* approval, and no package hash covers it |
| **Instructions** (system prompts, `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, rules files) | Behaviour-as-code that is neither hashed nor versioned by existing BOMs |
| **Models behind aliases** (`claude-sonnet-4-5`, `gpt-4o`) | A floating alias can be swapped server-side; a version string is not an identity |
| **Weights, adapters, tokenizers, chat templates** | Pickle executes on load; a poisoned LoRA layer hides behind an unchanged file name |
| **RAG indexes and memory stores** | Mutable, continuously poisonable dependencies with writers nobody records |
| **Authority** (OAuth scopes, egress, credentials, approval gates, delegation to other agents) | A BOM says what exists, not what it *may do* |
| **Runtime composition** (tools discovered live, sub-agents spawned, models re-routed) | Static inventories decay the day they are written |

Symbiote closes these gaps with four planes — **Composition** (what was declared), **Authorization** (what is
permitted), **Observability** (what is deployed and what it actually did) and **Assurance** (why each claim should
be trusted) — and with content addressing, per-claim assurance, declared-vs-observed diffs and signed evidence.

**Read the gap analysis:** [`docs/gap-analysis.md`](docs/gap-analysis.md) — why CycloneDX 1.7 and SPDX 3.0.1 are
not enough for agents (field-exact, citing the schemas), the 22-gap register mapped to OWASP ASI and MITRE ATLAS,
the minimum viable AgentBOM, how Symbiote closes each gap, and the corrections to the analysis it grew out of.
The design inputs behind it are in [`docs/research/`](docs/research/README.md).

## What works today

Every command below was run against [`examples/triage-agent`](examples/triage-agent) while writing this README;
the [CLI reference](docs/reference/cli.md) shows the real output of each one.

```bash
uv tool install symbiote            # or: pipx install symbiote   (from a checkout: uv pip install -e ".[dev]")

# Zero-config: collect from MCP client configs; write agentbom.json, agentbom.cdx.json (CycloneDX 1.7), agentbom.spdx.json (SPDX 3.0.1)
symbiote scan examples/triage-agent -o out/ --deterministic

# Policy, conformance and completeness over the companion document (SARIF for code scanning)
symbiote policy check out/agentbom.json --sarif out/agentbom.sarif        # exit 1 on `fail` findings at or above --fail-on
symbiote conformance out/agentbom.json --level minimal                      # pass / fail / unknown per requirement
symbiote score out/agentbom.json                                            # completeness, never a trust score

# Validate against the official schemas; recompute the salted Merkle root
symbiote validate out/agentbom.json out/agentbom.cdx.json out/agentbom.spdx.json
symbiote merkle verify out/agentbom.json

# Content-address the model-visible surface of an MCP tool exactly as a gateway would (fail-closed)
symbiote digest tooldef tool.json --json

# The diff is the finding: compare any two snapshots (declared vs observed, approved vs deployed)
symbiote diff v1/agentbom.json v2/agentbom.json --fail-on-change tool-definition-changed

# Sign the snapshot as an in-toto statement (key-based DSSE or Sigstore keyless) and verify the binding and the chain
symbiote attest snapshot out/agentbom.json --key key.pem -o snapshot.dsse.json
symbiote verify snapshot.dsse.json --public-key key.pub --companion out/agentbom.json --store .symbiote/store

# Export the Gateway Allowlist Bundle a tool gateway enforces, and check served tools against it
symbiote allowlist export approved.agentbom.json --format gab -o gab.json
symbiote allowlist check gab.json server:github served-tools.json          # allow / block (rug-pull signal) / drop
```

```python
from symbiote.digest import tooldef_digest, toolset_digest
from symbiote.model import AgentBOM
from symbiote.snapshot import diff, finalize, new_document, redact_entities, verify_document
```

| Capability | Status |
|---|---|
| Semantic model with per-claim assurance (`declared / observed / verified`) and explicit `unknown` | ✅ |
| Typed, fail-closed digests (RFC 8785) for tool definitions, tool sets, server identity, prompts, agents | ✅ |
| OpenSSF model-signing compatible directory manifests; per-tensor safetensors manifests | ✅ |
| Salted Merkle commitment, verifiable redaction (`merkle verify`); inclusion proofs (`merkle prove`) | ✅ · 🚧 |
| Companion document + generated JSON Schema (CI checks it is up to date) | ✅ |
| in-toto statements, key-based DSSE signing and verification | ✅ |
| Sigstore keyless signing and verification with identity-constraint policies (`[sign]` extra) | ✅ |
| Hidden-Unicode / external-`$ref` / cross-tool-directive lints over model-visible text | ✅ |
| Model identity: serialization-risk sniffing (pickle, torch, joblib, GGUF, safetensors, chat templates), Hugging Face directory analysis | ✅ |
| CycloneDX 1.7 exporter (direct JSON, validated against the official schema and cyclonedx-python-lib) | ✅ exporter · 🚧 importer |
| SPDX 3.0.1 JSON-LD exporter (native classes + typed extensions + `CdxPropertiesExtension` mirror, validated against the official schema, round-tripped through spdx-python-model) | ✅ exporter · 🚧 importer |
| Collector: MCP client configs (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex, Gemini CLI), launcher pinning, credential names, client trust settings | ✅ |
| Collectors: instructions, skills, frameworks, hosted and local models, A2A cards, identity, SBOM merge | 🚧 WP9 (specified; land as modules) |
| Observed layer: live `tools/list` over stdio (raw JSON-RPC), OpenTelemetry GenAI traces, MCP registry resolution, k8s-aibom import | ✅ Python API · 🚧 `scan --live/--registry` CLI wiring |
| Policy checks (60 `SYM-*`, incl. the Clinejection CI pattern), computed flags, conformance levels, completeness score, SARIF 2.1.0 | ✅ |
| Snapshot diff with typed deltas; chain store with monotone serials, `prev` links and anti-rollback (exit 7) | ✅ |
| Gateway Allowlist Bundle (`gab`, `opa-data`, `mcp-gateway-generic`) + reference served-tool check | ✅ |
| Nexus ShadowScan: import discovery reports as observed snapshots (autonomy interval, servers, identities, coverage), export the AgentBOM as the ShadowScan inventory, reconcile declared vs observed (`SYM-SS-*`), fold reports into `symbiote scan` | ✅ |
| GitHub Action (`action.yml`), pre-commit hooks, CodeQL and release workflows | ✅ |
| Trust-status lists (CLI), incident index, generic CycloneDX/SPDX importers, `attest` for the other predicates | 🚧 |
| `symbiote scan .` zero-config: companion + CycloneDX 1.7 + SPDX 3.0.1 + loss reports from a repository | ✅ (coverage grows with each collector; unexamined surfaces are reported `not-attempted`, never clean) |

Progress and ownership: [`docs/development/work-packages.md`](docs/development/work-packages.md).

## How it maps onto the standards

```
                 ┌────────────────────────────────────────────┐
  collectors ──► │  AgentBOM semantic model (Pydantic v2)     │ ──► companion document  (structured truth, JSON Schema)
  MCP configs    │  entities · claims · edges · snapshots      │ ──► CycloneDX 1.7        (native constructs + agentbom:* properties)
  live tools/list│  grants · evidence · coverage · Merkle root │ ──► SPDX 3.0.1 JSON-LD   (native classes + typed extensions)
  OTel traces    │                                            │ ──► in-toto / DSSE / Sigstore attestations
  k8s-aibom      └────────────────────────────────────────────┘ ──► Gateway Allowlist Bundle, OPA input, SARIF
```

- **CycloneDX 1.7** — agents, tools, instructions, models and data stores are `application`, `data`, `file`,
  `library` and `machine-learning-model` components plus `services`; claims, evidence and coverage use
  `declarations`, `citations`, `compositions` and `formulation`; AI weaknesses use `vulnerabilities[]` keyed to
  MITRE ATLAS / OWASP ASI ids; everything else is an `agentbom:` property with a closed vocabulary. Output is
  emitted directly as JSON and validated against the official `bom-1.7` schema. See
  [`docs/formats/cyclonedx.md`](docs/formats/cyclonedx.md), [`spec/cyclonedx-mapping.md`](spec/cyclonedx-mapping.md)
  and [`spec/taxonomy.md`](spec/taxonomy.md).
- **SPDX 3.0.1** — `ai_AIPackage`, `dataset_DatasetPackage`, `software_Package/File`, `SoftwareAgent`,
  `LifecycleScopedRelationship(runtime)`, `usesTool`/`invokedBy`/`delegatedTo`, VEX classes, and
  `NoneElement`/`NoAssertionElement` to distinguish verified absence from unknown; agent qualifiers are typed
  extension classes, mirrored into `CdxPropertiesExtension` for lossless round trips. See
  [`docs/formats/spdx.md`](docs/formats/spdx.md) and [`spec/spdx-mapping.md`](spec/spdx-mapping.md).
- **Interoperability** — Symbiote imports Google's [k8s-aibom](https://github.com/GoogleCloudPlatform/k8s-aibom)
  documents and `AIBOM` custom resources as an *observed* source, mapping its per-attribute confidence
  (`declared / inferred / unresolved / verified`) onto per-claim assurance and never laundering a `verified` that
  lacks a recorded signer constraint; it accepts cdxgen and agent-harness-aibom property dialects on import and
  keeps unknown properties verbatim. It follows the
  [OWASP AIBOM Foundations Guide](https://owaspaibom.org/) (September 2026) in building on CycloneDX ML-BOM and
  the SPDX AI profile rather than a third format, consumes OpenSSF model-signing manifests, signs with Sigstore,
  reads OpenTelemetry GenAI traces as the observed source, and exports Rego-ready policy input. Every
  conversion emits a **loss report**, and every extension is listed in the
  [divergence register](spec/divergences.md).

## Design principles

1. **Name is locator, digest is identity.** Equality, diffs and allowlists operate on content digests; a name
   match never upgrades assurance. Digests are RFC 8785 canonical, typed, and **fail closed**: a tool definition
   that cannot be canonicalized is marked `undigestable` and treated as unpinned, never guessed.
2. **Unknown is not absence.** A failed or unauthorized query yields `unknown` plus a coverage record. "No shadow
   tools found" is only ever claimed when the surface was actually examined.
3. **Facts in the BOM, judgments in policy.** The BOM never says "safe"; it says what was declared, approved,
   deployed and observed, with what evidence, at what assurance. Checks cite their inputs so anyone can recompute.
4. **No laundering of signatures.** `verified` requires a chain to a trust root, transparency-log inclusion and a
   satisfied signer identity constraint. A valid signature from an unconstrained signer is a recorded fact, not
   verification (adopted from Google k8s-aibom's Design 002).
5. **The diff is the finding.** Declared, approved, deployed and observed are four snapshot kinds over one graph;
   an undeclared tool observed at runtime is a critical result, not a log line.
6. **Transparency without an attack map.** Salted Merkle leaves let a redacted BOM be verified against the
   signed root; redaction is recorded, never silent.

## Documentation

| | |
|---|---|
| [`docs/gap-analysis.md`](docs/gap-analysis.md) | The gap analysis: four planes, CycloneDX 1.7 and SPDX 3.0.1 field by field, the 22-gap register, the minimum viable AgentBOM, the Symbiote mapping, corrections (also exported as [`docs/research/gap-analysis.docx`](docs/research/gap-analysis.docx)) |
| [`docs/`](docs/index.md) | Site: [quickstart](docs/quickstart.md), concepts (incl. the [trust model](docs/concepts/trust-model.md)), guides ([collectors](docs/guides/collectors.md), [policy and conformance](docs/guides/policy-and-conformance.md), [attestation and enforcement](docs/guides/attestation-and-enforcement.md), [CI](docs/guides/ci.md)), [formats](docs/formats/cyclonedx.md), [CLI reference](docs/reference/cli.md) |
| [`spec/`](spec/README.md) | Normative AgentBOM profile: semantic model, digests, CycloneDX/SPDX mappings, taxonomy, conformance levels, checks, attestation, collectors, CLI, divergence register, ADRs |
| [`docs/research/`](docs/research/README.md) | Design inputs: brief, three architecture proposals, 22-gap attack-lens register, 64 verified claims |
| [`docs/development/work-packages.md`](docs/development/work-packages.md) | Work packages, owners and integration order |
| [`CHANGELOG.md`](CHANGELOG.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`SECURITY.md`](SECURITY.md) · [`THREAT-MODEL.md`](THREAT-MODEL.md) | Project process and threat model |

## Development

```bash
git clone https://github.com/aisecnomad/symbiote && cd symbiote
uv venv .venv && source .venv/bin/activate && uv pip install -e ".[dev]"
ruff check src tests && pytest -q
symbiote version
mkdocs build --strict
```

Tests run offline. Every emitted field change touches the model, the taxonomy, the divergence register, the
generated companion schema and the goldens in the same pull request (`spec/versioning.md`).

## Status and roadmap

Symbiote is **alpha**. The model, digests, Merkle commitment, companion document, both exporters, the MCP
configuration collector, the observed-layer modules, the policy engine, the snapshot chain, attestation and the
enforcement exports are implemented and tested; the static collectors, the importers, the trust-status CLI and
the remaining `scan` options are being built in parallel work packages toward `0.1.0`. Interfaces under
`symbiote.model` and `symbiote.digest` are frozen for the 0.1 line; everything else may change before the first
release.

## Acknowledgements

Symbiote stands on OWASP CycloneDX, SPDX, the Model Context Protocol, OpenSSF model-signing, Sigstore, in-toto,
OpenTelemetry GenAI semantic conventions, MITRE ATLAS, the OWASP Top 10 for Agentic Applications, the OWASP AIBOM
project, and Google's k8s-aibom, whose confidence-and-evidence conventions it adopts. The gap analysis behind
the design is Emmanuel Dahunsi's *The Supply Chain of Agency*.

## License

MIT — see [`LICENSE`](LICENSE).
