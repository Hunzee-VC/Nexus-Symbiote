# ADR-0003: CycloneDX 1.7 is emitted directly as JSON and validated against the official schema

**Status:** accepted · **Date:** 2026-11-01

## Context
Probing `cyclonedx-python-lib` 11.12.0 shows its object model has no `declarations`, `citations`,
`compositions`, `formulation`, `annotations` or `modelCard` classes, and `Bom.from_json` drops `modelCard`
on import. Those constructs are load-bearing for an AgentBOM (claims, evidence, coverage, runtime
assembly, field attribution). The initial 1.7 **XSD** `modelCardType` lacked the `properties` element that
the JSON schema has (fixed in the 1.7.2 XSD, which declares it), so `modelCard.properties` is not round-trip
safe for consumers pinned to earlier 1.7.x XML schemas, nor for 1.6 consumers.

## Decision
- The CycloneDX exporter emits JSON directly from the semantic model, deterministically (sorted keys where
  the schema allows, stable array ordering, `serialNumber` = UUIDv5 of the snapshot digest, timestamp pinned
  to the snapshot time).
- Every export is validated against the vendored official `bom-1.7.schema.json` (with its `jsf-0.82` and
  `spdx` sub-schemas) before it is written; `cyclonedx-python-lib`'s `JsonStrictValidator` is run as a
  second, independent validator when available.
- `modelCard.properties` is never written (XML round-trip safety across 1.7.x XSD revisions and 1.6 parity);
  model facts go on `component.properties`.
- `cyclonedx-python-lib` is used for XML output of the software layer and for its validators only.
- A `--cdx-version 1.6` downgrade profile exists for sinks that do not yet accept 1.7 (e.g. Dependency-Track);
  it drops `citations` and `patentAssertions` and reports the loss.

## Consequences
Symbiote owns a small, well-tested emitter instead of inheriting a lossy detour. Schema upgrades (1.8/2.0)
are a new emitter module plus golden files.
