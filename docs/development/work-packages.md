# Work packages and claim board

Several Claude sessions and people may build Symbiote in parallel. This file is the single claim board: edit
it (on your branch, merged quickly) or message the integrating session before starting a package, keep file
ownership disjoint, and build against the frozen contracts in `spec/`. Integration branch:
**`claude/symbiote-foundation`** (nothing is pushed to `main` until the review phase). Package branches:
`claude/wp-NN-<slug>`, opened as pull requests against the integration branch.

Protocol
1. Read `spec/README.md` and the documents for your package before writing code. The spec wins over proposals.
2. Claim a package by setting **Owner** below (session id or name) and pushing the change to the integration branch.
3. Public interfaces of WP1/WP2 are frozen at `symbiote.model` / `symbiote.digest`; propose changes by PR + spec edit in the same change.
4. Tests run offline. Every emitted field change touches the model, taxonomy, divergence register, generated companion schema, goldens and CHANGELOG.
5. Never put secret values, API keys or tokens in fixtures; use obviously fake shapes that the secret scanner test must still redact.

| WP | Title | Scope (files) | Depends on | Owner | Status |
|---|---|---|---|---|---|
| WP1 | Core semantic model and identity rules | `src/symbiote/model/*`, companion schema generation | — | session user-17 (session_01JYWyP4jNcEyLFGbtPFH5g1) | landed 5e031ef |
| WP2 | Canonicalization and digest engine | `src/symbiote/digest/*` (JCS wrapper, envelopes, tooldef/toolset/server/prompt/jsondoc/dirmanifest/tensormanifest, text flags, Merkle) | WP1 types | session user-17 | landed 5e031ef |
| WP3 | Model identity and serialization risk | `src/symbiote/models_identity/*` (model-signing manifest wrapper, risk classifier, derivations, hosted alias rules `providers.yaml`) | WP1, WP2 | session …VoM3 (session_01JYWyP1o2oTnLFJKas7VoM3) | claimed |
| WP4 | Authorization model and computed flags | `src/symbiote/authz/*` (grants, identities, flags with cited inputs) | WP1 | session …VoM3 (session_01JYWyP1o2oTnLFJKas7VoM3) | claimed |
| WP5 | Snapshot builder, diff, delta, anti-rollback state | `src/symbiote/snapshot/*` | WP1, WP2 | proposed: session …ihVM (session_01JYWyP51HKwrLeELgHFihVM) | proposed |
| WP6 | CycloneDX 1.7 exporter/importer + dialect adapters | `src/symbiote/export/cdx/*`, `src/symbiote/imp/cdx.py`, `imp/dialects/*` | WP1, WP2, WP4, WP5 | proposed: session …3J (session_01JYWyP2zgopDkVjZ9snEk3J) — port from feat/symbote-core | proposed |
| WP7 | SPDX 3.0.1 exporter/importer + extension vocabulary | `src/symbiote/export/spdx/*`, `src/symbiote/imp/spdx.py`, `src/symbiote/schemas/spdx/*` | WP1, WP2, WP4, WP5 | proposed: session …3J (session_01JYWyP2zgopDkVjZ9snEk3J) — port from feat/symbote-core | proposed |
| WP8 | Companion document, loss model, cross-format linkage | `src/symbiote/export/companion/*`, `LossReport`, `validate --cross` | WP1, WP5 | session user-17 | in progress |
| WP9 | Static collectors | `src/symbiote/collect/{base,mcp_config,instructions,skills,frameworks,models_hosted,sbom_merge,a2a,identity}.py` | WP1, WP2, WP3 | session …VoM3 (session_01JYWyP1o2oTnLFJKas7VoM3) | claimed |
| WP10 | Live and observed collectors + observed importers | `src/symbiote/collect/{mcp_live,otel,registry}.py`, `src/symbiote/imp/k8s_aibom.py`, fixture MCP server with drift modes | WP1, WP2, WP5 | proposed: session …ihVM (session_01JYWyP51HKwrLeELgHFihVM) | proposed |
| WP11 | Attestation: predicates, DSSE, Sigstore, verification, trust status | `src/symbiote/attest/*`, `src/symbiote/schemas/predicates/*` | WP1, WP2, WP5 | session user-17 | claimed |
| WP12 | Policy engine, Rego export, conformance, score, SARIF | `src/symbiote/policy/*`, `policy/rego/` | WP1, WP4, WP8 | session …VoM3 (session_01JYWyP1o2oTnLFJKas7VoM3) | claimed |
| WP13 | Enforcement exports (GAB) and incident index | `src/symbiote/enforce/*`, `src/symbiote/index/*` | WP5, WP11, WP8 | session user-17 | claimed |
| WP14 | CLI and Python API | `src/symbiote/cli/*`, `src/symbiote/api.py` | all (thin layer) | session user-17 | claimed |
| WP15 | Docs site, example agent, GitHub Action, pre-commit, CI/release, SECURITY/THREAT-MODEL | `docs/`, `examples/triage-agent/`, `action.yml`, `.github/workflows/*`, `mkdocs.yml` | WP14 for commands | session user-17 | claimed |
| WP16 | Test infrastructure, fixtures, golden tooling | `tests/fixtures/*`, hypothesis strategies, `tests/vectors/` | WP1 types | proposed: session …ihVM (session_01JYWyP51HKwrLeELgHFihVM) | proposed |
| WP17 | Source-document review: verified claims, corrections memo, optimized gap analysis (`docs/gap-analysis.md`), landscape matrix | `docs/gap-analysis.md`, `docs/research/verified-claims.json`, `docs/research/landscape.json`, `docs/research/document-review.md` | — | session …VoM3 (session_01JYWyP1o2oTnLFJKas7VoM3) | in progress (verification workflows running) |

Reference branches: `feat/symbote-core` (session …3J's pre-spec implementation; port, do not merge).

Integration order: M0 WP1+WP2 freeze → M1 WP3, WP4, WP5, WP8, WP16 → M2 WP6, WP7, WP9, WP10 → M3 WP11, WP12,
then WP13 → M4 WP14, WP15 → review and release 0.1.0.
