# ADR-0005: Per-claim assurance, explicit unknowns, four snapshot kinds

**Status:** accepted · **Date:** 2026-11-01

## Context
A BOM is a self-declared claim. The source analysis insists on three distinctions that existing formats
blur: declared vs observed vs verified; unknown vs verified absence; and declared vs approved vs deployed
vs observed configurations.

## Decision
- Assurance is a property of a **claim**, never of a whole agent: `declared` (owner/config says so),
  `observed` (a collector corroborated the deployed state within a stated window), `verified` (evidence is
  authenticated against an explicit trust policy with a constrained signer and documented coverage).
  `signature-valid-unconstrained` never qualifies as `verified` (k8s-aibom Design 002 adopted verbatim).
- Every claim has a `state`: `present`, `absent-verified`, or `unknown`. A failed or unauthorized query yields
  `unknown`, never an empty list.
- A document carries exactly one snapshot `kind`: `declared`, `approved`, `deployed`, `observed`. Exporters
  refuse to merge kinds unless asked, and then every element is tagged with its kind.
- The diff between kinds is the detection primitive: an undeclared component in an observed snapshot is a
  finding, not a log line.
- Import mapping from k8s-aibom confidence: `declared→declared`, `inferred→observed(method=heuristic)`,
  `unresolved→unknown`, `verified→verified` only when a signer identity constraint is recorded, else
  `observed` plus the fact `imported-verified-without-constraint`.

## Consequences
Policy checks that depend on an `unknown` input report `indeterminate` rather than passing silently; the
Verified conformance level cannot be reached with blocking unknowns.
