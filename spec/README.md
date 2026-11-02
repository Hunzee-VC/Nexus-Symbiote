# Symbiote specification

This directory is the normative specification of the **AgentBOM profile** that Symbiote implements, and
of the product decisions behind it. Implementation code must match these documents; when they disagree,
fix one or the other in the same change and record the decision as an ADR.

| Document | Contents |
|---|---|
| [`agentbom-profile.md`](agentbom-profile.md) | The semantic model: entities, fields, enumerations, edges, claims, snapshots, coverage, assurance levels |
| [`digests.md`](digests.md) | Canonicalization (RFC 8785), typed digest envelopes, Merkle commitment, directory manifests, model identity, name-resolution records |
| [`cyclonedx-mapping.md`](cyclonedx-mapping.md) | How every entity is encoded in CycloneDX 1.7 using only sanctioned extension points |
| [`taxonomy.md`](taxonomy.md) | The `agentbom:` property taxonomy (exact names, types, cardinality) and the `symbiote:` provenance names |
| [`spdx-mapping.md`](spdx-mapping.md) | How every entity is encoded in SPDX 3.0.1 JSON-LD, plus SPDX 3.1 forward notes |
| [`companion.md`](companion.md) | The companion AgentBOM document, its JSON Schema, linkage and loss reports |
| [`conformance.md`](conformance.md) | Conformance levels AgentBOM-Minimal / Standard / Verified and the completeness score |
| [`checks.md`](checks.md) | Built-in policy checks (`SYM-*`), computed flags, severity, OWASP ASI and MITRE ATLAS mappings |
| [`attestation.md`](attestation.md) | in-toto predicate types, DSSE/Sigstore signing and verification flows, anti-rollback, trust status |
| [`collectors.md`](collectors.md) | Collector contracts, inputs, parsing rules, evidence locators and coverage semantics |
- [`shadowscan-mapping.md`](shadowscan-mapping.md) — Nexus ShadowScan ↔ AgentBOM: report import, autonomy interval, inventory export, reconciliation checks
| [`cli.md`](cli.md) | Command surface, exit codes, JSON output contracts, Python API shape |
| [`divergences.md`](divergences.md) | Register of every place Symbiote extends or narrows CycloneDX/SPDX semantics (k8s-aibom format) |
| [`versioning.md`](versioning.md) | Versioning rules for the tool, the taxonomy, the companion schema and predicate types |
| [`adr/`](adr/) | Architecture decision records |

Conventions used throughout: **MUST / SHOULD / MAY** as in RFC 2119. Identifiers in `code` are exact.
Digests are written `sha256:<64 lowercase hex>`. Times are RFC 3339 in UTC with a `Z` suffix.
Validity windows are half-open `[not_before, not_after)`.
