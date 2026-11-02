# Changelog

## Unreleased

### Security

- Check trust-status signers against the previous tenant revocation list and recheck the accepted status when consuming a tool approval. Upgrading an existing gateway may require replaying its last accepted trust status.
- Reconcile supplied BOMs with the project's static inventory. A completed search can record zero matches. Skipped collectors, failed reads, and unmapped discovery evidence still block the default repository gate.
- Ignore report-supplied project policy during standalone ShadowScan import. Use `--report-only` explicitly for exploratory imports.
- Report changes to an MCP server's recorded origin, transport, or launcher as critical drift. Use `diff --fail-on-alert` in CI to enforce those alerts.
- Treat GitHub Action inputs as data and invoke the scanner without shell evaluation.
- Preserve validation failures and malformed risk-report errors as failed Action runs.
- Install the Action's checked-out source instead of an independently moving package-index release.
- Generate requested exports and SARIF from one collected native inventory.
- Pin third-party Actions to verified commit references and disable persisted checkout credentials.

### Delivery

- Scope exported SPDX document and element identifiers to each inventory revision so different package versions can coexist in a combined graph.
- Run security regressions against the exact wheel built by CI and the release workflow.
- Exercise supported Python versions, built-wheel installation, Action abuse cases, and exporter conformance in CI.
- Add manually requested release candidates, distribution checksums, release evidence, build attestations, and environment-gated OIDC publication.
- Align documentation with MIT licensing and the alpha support boundary.
