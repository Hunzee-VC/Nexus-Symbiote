# Changelog

All notable changes to Symbiote are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/). The AgentBOM profile (property taxonomy, companion
schema, predicate types) is versioned independently of the tool; see `spec/versioning.md`.

## [Unreleased]

### Added
- Initial public foundation: semantic model, canonical digests, CycloneDX 1.7 and SPDX 3.0.1
  exporters, collectors, policy checks, conformance levels, attestations, and the `symbiote` CLI.
- WP5 snapshot engine (`symbiote.snapshot.state`/`.diff`/`.body`): `ChainStore` provides
  per-`(agent, kind)` serial allocation, hash chaining and anti-rollback verdicts aligned with
  `SYM-SNAP-001/002/003`; `seal_with_chain()` composes chain allocation with `finalize()`;
  `diff()` produces typed, deterministic `Delta` events from identity digests with
  claim-noise-immune body comparison (`entity/v1`, `spec/digests.md §3.8`);
  `stale_evaluation_ids()` backs `SYM-EVAL-001`.
