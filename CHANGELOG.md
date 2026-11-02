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
- WP15 documentation: `docs/gap-analysis.md`, the publishable gap analysis of CycloneDX 1.7 and
  SPDX 3.0.1 for agents (four planes, field-exact format review, the 22-gap register with OWASP ASI
  and MITRE ATLAS mappings, the minimum viable AgentBOM, the Symbiote mapping, and the corrections
  to the source analysis), exported as `docs/research/gap-analysis.docx`; a CLI reference generated
  from real `--help` output and verified runs (`docs/reference/cli.md`); format pages for CycloneDX
  and SPDX with real excerpts (`docs/formats/`); guides for collectors, policy and conformance,
  attestation and enforcement, and CI (`docs/guides/`); a trust-model concept page; the research
  proposals and ADRs in the site navigation.

### Changed
- `main` reconciled onto the foundation implementation; the `nexus_symbiote` package removed; `action.yml`,
  pre-commit hooks, CodeQL and release workflows ported to the `symbiote` CLI. The CI workflow pins actions
  by commit, adds `quality` (workflow linter, repository hygiene), `distribution` (wheel build and smoke
  test) and the `Verified CI` aggregate job; `main`'s small security fixtures live on as
  `tests/fixtures/security-corpus/` regression tests.
- `symbiote scan` now writes the companion last with `links` to the CycloneDX and SPDX documents (BOM-Link,
  document IRI, digests of the written bytes) and the loss report, writes `agentbom.validation.json`, accepts
  `--valid-for DAYS` and `--profile LEVEL` (conformance evaluated with the validation evidence; exit 5 when
  not attained), refuses a non-directory path (exit 6) and reports `cyclonedxValid`/`spdxValid` as `null` when
  the format was not exported. A zero-config scan of the example attains Minimal conformance.
- `symbiote conformance --evidence` reads validation evidence (default: the sibling `agentbom.validation.json`);
  `symbiote validate` recognises loss reports and validation evidence; `policy check` groups repeated flags;
  collectors whose module is missing are reported as scan warnings instead of being skipped silently.
- README: the status table now distinguishes the merged WP10 observed-layer modules (available
  through the Python API) from the pending WP9 static collectors and the CLI wiring, and links the
  gap analysis and the interoperability story (k8s-aibom import, OWASP AIBOM guide).
- Docs site: `docs/SECURITY.md`, `docs/THREAT-MODEL.md` and `docs/CODE_OF_CONDUCT.md` replace the
  lowercase symlinks so links from `CONTRIBUTING.md` and `SECURITY.md` resolve under
  `mkdocs build --strict`; the quickstart quotes verified output and uses `openssl genpkey`.
