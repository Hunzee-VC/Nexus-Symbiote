# Changelog

## [0.1.0] - 2026-11-02

Alpha release of the AgentBOM toolkit under the Hunzee-VC organization.

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

### Delivery

- Scope exported SPDX document and element identifiers to each inventory revision so different package versions can coexist in a combined graph.
- Run security regressions against the exact wheel built by CI and the release workflow.
- Emit standard package identifiers for portable BOM consumers while retaining
  native evidence and explicit projection limitations.
- Exercise supported Python versions, built-wheel installation, Action abuse cases, and exporter conformance in CI.
- Add manually requested release candidates, distribution checksums, release evidence, build attestations, and environment-gated OIDC publication.
- Align documentation with MIT licensing and the alpha support boundary.
- Canonical repository moved to Hunzee-VC/Nexus-Symbiote; documentation and package metadata updated accordingly.

## Unreleased

(empty for now)
