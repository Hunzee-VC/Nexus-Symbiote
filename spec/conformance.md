# Conformance levels and completeness score

Conformance is a statement about **the document**, never about the safety of the agent. Levels are
validated by `symbiote conformance --level <minimal|standard|verified>`; each requirement yields
`pass | fail | unknown` with reasons. The level attained is the highest level with no `fail` and no `unknown`
on its required items. Requirement identifiers are stable and appear in CycloneDX
`definitions.standards[]` ("AgentBOM Conformance 0.1").

## AgentBOM-Minimal (static, offline, what `symbiote scan .` produces)
| ID | Requirement |
|---|---|
| AB-MIN-01 | Agent identity: name, version, owner (owner MAY be `unknown` with reason) |
| AB-MIN-02 | Every model has an identity (manifest root or hosted tuple) or an explicit `unknown` |
| AB-MIN-03 | Every tool server is listed with transport and package or endpoint |
| AB-MIN-04 | Every tool definition has a digest or an `undigestable` reason |
| AB-MIN-05 | Every instruction file and skill is digested (exact bytes / directory root) |
| AB-MIN-06 | A coverage statement is present for all ten surfaces |
| AB-MIN-07 | The CycloneDX document validates against the official 1.7 schema; the SPDX document (when emitted) against the official 3.0.1 schema |
| AB-MIN-08 | No secret values appear anywhere (negative scan over the emitted bytes) |

## AgentBOM-Standard (Minimal plus authority, resolution and runtime binding)
| ID | Requirement |
|---|---|
| AB-STD-01 | Companion document present and linked by digest in every emitted format |
| AB-STD-02 | At least one `declared` grant per tool server and per tool with capability, scope and enforcement point |
| AB-STD-03 | Identities and credential bindings recorded (by reference) for every grant |
| AB-STD-04 | A registry/name-resolution record for every registry-sourced component |
| AB-STD-05 | Snapshot serial, prev link and validity window present |
| AB-STD-06 | Computed flags present with values `true|false|unknown` and cited inputs |
| AB-STD-07 | Loss report attached with no `security-relevant` item dropped |
| AB-STD-08 | Every data source has a trust tier; every memory store has `writers` (or explicit `unknown`) |
| AB-STD-09 | Every tool has `approval_gate` and `side_effect_class` populated (or `unknown` with reason) |
| AB-STD-10 | Served tool-definition digests (`source = served-live`) exist for every reachable MCP server, or coverage records why not |

## AgentBOM-Verified (Standard plus authenticated evidence)
| ID | Requirement |
|---|---|
| AB-VER-01 | A signed `agentbom-snapshot/v1` statement verifies under an operator identity constraint (never `UnsafeNoOp`) |
| AB-VER-02 | `tool-definition-set/v1` from live observation within `max_staleness` (default 24 h) matches the approved set, or the delta is signed |
| AB-VER-03 | Every model has `signature.status = verified`, or an explicit `unknown` with a fingerprint claim and expiry |
| AB-VER-04 | A current (unexpired) `trust-status/v1` list is present and verified |
| AB-VER-05 | Merkle root present and recomputable from the companion |
| AB-VER-06 | Evaluation evidence bound to the current configuration digests for every tool with destructive or open-world capability |
| AB-VER-07 | All ten coverage surfaces are `queried` (no blocking unknowns) |
| AB-VER-08 | An `approval/v1` statement covers the deployed snapshot digest, signed by an identity distinct from the producer identity |

## Completeness score
`symbiote score` reports 0–100 = Σ weight × field presence over surfaces (tools 25, authorization 20, models 15,
data/memory 10, identity 10, instructions 10, coverage 5, evidence linkage 5) with per-field reasons
(`missing | unknown | present-declared | present-observed | present-verified`), **always** alongside the
assurance distribution (% of claims declared / observed / verified). The score is a BOM-quality number, never a
trust or safety score, and the CLI says so in its output.
