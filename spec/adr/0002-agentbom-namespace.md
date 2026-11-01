# ADR-0002: `agentbom:` is the fact namespace; `symbiote:` is generator provenance only

**Status:** accepted · **Date:** 2026-11-01

## Context
CycloneDX permits arbitrary `properties` but asks producers to register a top-level namespace in the
property taxonomy registry (`cdx:` is reserved for the core working group; cdxgen's `cdx:mcp:*` family
violates this). Google's k8s-aibom emits `aibom.*` and is renaming to `k8s-aibom:*`. Three vocabularies
for the same facts is the fragmentation the source analysis warns about.

## Decision
- All agent-supply-chain **facts** are emitted under one registered, tool-neutral namespace: `agentbom`.
  Any generator (cdxgen, k8s-aibom, an enterprise registry) can emit `agentbom:tool:definition-digest`
  without implying it ran Symbiote. The taxonomy is published in `spec/taxonomy.md` and versioned
  (`agentbom:spec-version`).
- Facts inherent to **this generator** (tool version, collector status, scan root) use `symbiote:`.
- Facts with a native CycloneDX/SPDX home are never duplicated as properties (digests go in `hashes[]`,
  purls in `purl`, lifecycle in `metadata.lifecycles`, endpoints in `services[].endpoints`).
- Names: lower-kebab-case ASCII segments separated by `:`; add-only within a major version; renames are a
  new name plus a `rescinded` register entry for the old one.
- Multi-valued facts are **repeated properties with the same name** (CycloneDX allows duplicates), except
  ordered records, which use an index segment (`agentbom:authz:0:capability`).
- A JSON value is only ever stored under a name ending in `:json` and is RFC 8785 canonical.
- Registration: an issue on `CycloneDX/cyclonedx-property-taxonomy` after the first public release; until
  then the taxonomy is published in this repository, which the registry README accepts as prerequisite.

## Consequences
The upstream path (CycloneDX 2.0 declared-behaviour model, spec issue #1015, taxonomy PR #175) becomes a
rename table, exactly like k8s-aibom's `aibom.*` → `k8s-aibom:*` transition.
