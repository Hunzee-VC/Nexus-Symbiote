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
- WP16 test infrastructure: shared hypothesis strategies for referentially consistent model
  documents (`tests/strategies.py`), byte-identical golden tooling with explicit regeneration
  (`tests/support/golden.py`, `UPDATE_GOLDENS=1`), a cross-cutting invariant property suite
  (seal→verify, determinism, redaction verifiability, diff reseal-immunity, JCS idempotence,
  chain-store rollback refusal), and the first two goldens: the sealed minimal companion document
  and the canonical rug-pull delta.
- WP10 observed layer: `mcp-live` collector (raw newline-delimited JSON-RPC stdio client — digests
  over the wire-exact objects, allowlist-gated execution, pagination, log-noise tolerance, honest
  coverage for remote transports), `otel-traces` collector (GenAI semconv spans → invoked tools
  with counts/windows, hosted-model alias routing, sub-agent spawns, data/memory sources, hashed
  system instructions, trace-summary evidence), `mcp-registry` collector (injectable transport,
  name-resolution records with publisher verification, typosquat distance, unreachable ⇒ unknown),
  the `k8s-aibom` importer (CR unwrapping via status.bomDocument, §5 confidence mapping, no
  signature laundering), and the drift-mode fixture MCP server
  (description|schema|annotations|order|pagination|unicode).
- Nexus ShadowScan native integration (WP19, `symbiote.shadowscan`, `spec/shadowscan-mapping.md`): strict
  reader for ShadowScan JSON reports and its CycloneDX 1.6 dialect; importer that turns findings into an
  **observed** snapshot (assurance follows the surface, every finding is `scan-report` evidence, `shadow: null`
  stays `unknown`, incomplete connectors stay `partial`); the L0-L5 autonomy interval as
  `Agent.autonomy_assessment` with a strictly increasing ISO/IEC 22989 projection and ShadowScan's merge
  semantics; inventory export (schema-v2 Capability Cards with `tooldef/v1` digests, `agents.yaml`, CSV —
  validated against ShadowScan 0.1.4, bindings aligned with ShadowScan's own AgentBOM loader); `reconcile`
  (declared vs observed servers, autonomy verdicts) and the `SYM-SS-001..007` checks; the `shadowscan-report`
  collector (`symbiote scan --shadowscan-report`, corroboration merge of duplicate ids); the `symbiote shadowscan
  levels|import|inventory|reconcile` commands. `export/shadowscan.py` and `imp/shadowscan.py` remain as façades.
- Fixed: SPDX `software_File.contentType` (crashed exports with evidence or instructions); SPDX schema validation
  skips the official `oneOf` schema above 400 graph elements (minutes per document) and says so; collector
  results can hand root-agent facts (`root_updates`), flags and foreign properties back to the scan runner.
