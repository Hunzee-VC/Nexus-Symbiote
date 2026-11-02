# Changelog

## Unreleased

### Security

- Require successful canonical CI-workflow evidence for the exact publication source SHA, in addition to protected-branch settings.
- Enforce offline tracked-source hygiene and vendored schema provenance digests in the required quality job.
- Check trust-status signers against the previous tenant revocation list and recheck the accepted status when consuming a tool approval. Upgrading an existing gateway may require replaying its last accepted trust status.
- Reconcile supplied BOMs with the project's static inventory. A completed search can record zero matches. Skipped collectors, failed reads, and unmapped discovery evidence still block the default repository gate.
- Ignore report-supplied project policy during standalone ShadowScan import. Use `--report-only` explicitly for exploratory imports.
- Report changes to an MCP server's recorded origin, transport, or launcher as critical drift. Use `diff --fail-on-alert` in CI to enforce those alerts.
- Detect semantic snapshot changes, including removed integrity evidence, changed endpoints,
  expanded capabilities, remote-code settings, and dependency conditions or assurance.
- Preserve unknown autonomy when a native agent omits the field, and parse Python
  package pins consistently using ecosystem-aware requirements and versions.
- Treat GitHub Action inputs as data and invoke the scanner without shell evaluation.
- Preserve validation failures and malformed risk-report errors as failed Action runs.
- Install the Action's checked-out source instead of an independently moving package-index release.
- Generate requested exports and SARIF from one collected native inventory.
- Pin third-party Actions to verified commit references and disable persisted checkout credentials.
- Add a pinned CodeQL workflow for push, pull request, and weekly schedule; hosted analysis requires runner availability and code-scanning entitlement.
- Run every command offline by default: the CLI refuses name resolution, network connections and process creation. Only `discover-mcp`, `advisories` and `verify-live` can reach outside local files, and only in live mode (`--live` before the command, or `NEXUS_SYMBIOTE_MODE=live`); every other command stays offline even then. A project policy file cannot select the mode. **Breaking:** add `--live` to existing invocations of those three commands.
- Report a malformed or truncated inventory in `summary`, `validate`, `risk`, `blast-radius` and `diff` as a short error instead of a traceback, without echoing the file's contents to the terminal.
- Make `diff --fail-on-alert` fail on every in-place component change rated medium or above, as additions already did. Previously a version bump of an MCP server package, a swapped npm lockfile integrity value, a replaced MCP tool implementation, an A2A card URL moved to plaintext HTTP, or an IDE agent newly granted `Bash(*)` was reported as a change but passed the gate.
- Scan container image references in linear time. A `docker-compose.yml` ending in `image:` followed by a long run of whitespace took minutes, and over a day at the 4 MiB read limit.
- Index collected components during `scan` instead of searching the whole inventory for each one. A project declaring 10,000 MCP tools now scans in 4.3 s instead of 10.9 s, with identical output. Very large tool declarations still need a collection limit.
- Print inventory-derived text literally in human-readable output. Rich markup and terminal-control, bidirectional or invisible characters in a component name could add hyperlinks, conceal text or rewrite earlier lines, for example to hide a critical `diff` alert. As a result `validate` again shows which component each issue belongs to, and the `risk` findings table keeps its severity column in an 80-column terminal.

### Delivery

- Scope exported SPDX document and element identifiers to each inventory revision so different package versions can coexist in a combined graph.
- Run security regressions against the exact wheel built by CI and the release workflow.
- Emit standard package identifiers for portable BOM consumers while retaining
  native evidence and explicit projection limitations.
- Exercise supported Python versions, built-wheel installation, Action abuse cases, and exporter conformance in CI.
- Add manually requested release candidates, distribution checksums, release evidence, build attestations, and environment-gated OIDC publication.
- Align documentation with MIT licensing and the alpha support boundary.
- Document every command and option in `docs/cli-reference.md`, checked against the CLI by a test, and add help text to the 20 options that had none. Add `docs/offline-and-live-modes.md`.
- Add an offline demo project, `examples/demo-agent`, with a walkthrough in `examples/README.md`. Remove `examples/customer-support-agent.json`, whose legacy tool fingerprints current validation rejects.
