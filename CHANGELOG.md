# Changelog

All notable changes to Nexus SymBiote are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, a minor
version can change command behavior; each such change is listed under
**Changed** with its migration.

## [0.1.0] - Unreleased

The first release. It has not been published to PyPI yet; the
[release runbook](docs/operations/releasing.md) describes the TestPyPI rehearsal
and the publication gates.

### Added

- Offline and live operating modes. Every command runs offline by default: for the
  whole run the process refuses name resolution, outbound and listening sockets
  and process creation, and the live transport, OSV client and launcher check the
  mode again before acting. `--live` (before the command) or
  `NEXUS_SYMBIOTE_MODE=live` permits the live steps of `discover-mcp`,
  `advisories` and `verify-live`. No policy-file key can select the mode.
- Offline counterparts of the live commands, reading saved exports with `--input`:
  `discover-mcp --input` analyzes a saved `tools/list` result;
  `advisories --input` matches a saved OSV export (`all.zip`, a directory or a
  JSON file), evaluating `versions` lists and `ECOSYSTEM`/`SEMVER` ranges per the
  OSV schema with PEP 440 and SemVer 2.0.0 ordering; `verify-live --input`
  compares descriptors that a live run recorded with the new `--save-descriptors`.
- `metadata.completeness.collection_mode`, `offline_enforced` and
  `live_operations` in native inventories, and the matching
  `nexus-symbiote:collectionMode` and `nexus-symbiote:offlineEnforced`
  properties in CycloneDX, SPDX and SARIF exports.
- Deterministic exit codes shared by every command: 0 complete and within policy,
  1 usage, configuration, input or output failure, 2 a gate or verification
  failed on complete evidence, 3 incomplete collection or observation, or a live
  step refused offline.
- `diff --fail-on-change`, a drift gate that exits 2 when snapshots differ.
- `import-shadowscan --no-project-policy`.
- `-h` as a short form of `--help`.
- Documentation: a Why/What/How README, a documentation index, installation,
  quick start and configuration guides, a generated CLI reference, exit codes,
  collectors, output formats, GitHub Action, architecture, risk scoring, threat
  model, and offline and live modes.
- Community and governance files: code of conduct, support, governance,
  maintainers, roadmap, citation metadata, code owners, issue forms and a pull
  request template.
- Repository automation: CodeQL and OpenSSF Scorecard workflows (active once the
  repository is public), Dependabot for Actions and Python ranges, a
  `.pre-commit-config.yaml` for contributors, `.editorconfig`, `.gitattributes`
  and a `Makefile` for the documented check sequence.
- Consistency checks run by the test suite: Markdown links and anchors
  (`scripts/check_docs.py`), the generated CLI reference
  (`scripts/generate_cli_reference.py`) and the published JSON Schemas, which are
  now generated from the models (`scripts/generate_schemas.py`).
- A TestPyPI rehearsal in the release workflow: `publish` takes `none`,
  `testpypi` or `pypi`; the candidate must be the reviewed `expected_commit`; a
  token-less publication gate checks the attested files and, for PyPI, the
  `v<version>` tag on that commit; the upload job holds only the OIDC token and
  runs no shell steps.

### Changed

- `discover-mcp`, `advisories` and `verify-live` need `--live` to contact a
  server or start a launcher. Without it they exit 3 and name both remedies.
  Migration: put `--live` before the command in jobs dedicated to live
  observation, or set `NEXUS_SYMBIOTE_MODE=live` there.
- Exit codes: usage errors exit 1 instead of Click's 2; gate and verification
  failures exit 2 instead of 1; incomplete collection or observation exits 3
  instead of 1. Scripts that only test for a nonzero status are unaffected.
- `verify-live --launch-policy` is required only for live verification.
- The GitHub Action runs every step with `--offline`, treats risk exit 2 as a
  failed gate, and treats any other nonzero risk exit as a failure to run.
- The consumer pre-commit hooks run with `--offline`.
- Malformed inventories given to `summary`, `validate`, `risk`, `diff`, `vex`,
  `blast-radius` or `advisories` exit 1 with a bounded message instead of a
  traceback.
- The risk and scan gate messages name the gate reasons.
- A missing Sigstore extra exits 1 with the install hint instead of being
  reported as a failed signature verification.
- The version is defined once, in `nexus_symbiote.__version__`, and read by the
  build; `packaging` is a runtime dependency; the unreachable `tomli` marker and
  the redundant `yaml` extra are removed; project URLs, classifiers and license
  files are complete for PyPI.
- `requirements-ci.lock` is regenerated from `pyproject.toml`; it now includes
  the `jsonschema[format-nongpl]` packages that
  `cyclonedx-python-lib[json-validation]` requires, so CI checks schema formats
  as a full development install does.
- Documentation moved under `docs/getting-started`, `docs/reference`,
  `docs/concepts`, `docs/security`, `docs/operations` and `docs/migrations`.

### Security

- The SPDX export validator uses an explicit empty `referencing.Registry`, so a
  `$ref` it cannot resolve locally can never trigger a remote retrieval.
- Treat GitHub Action inputs as data and invoke the scanner without shell
  evaluation.
- Preserve validation failures and malformed risk-report errors as failed Action
  runs.
- Install the Action's checked-out source instead of an independently moving
  package-index release.
- Generate requested exports and SARIF from one collected native inventory.
- Pin third-party Actions to verified commit references and disable persisted
  checkout credentials.

### Delivery

- Exercise supported Python versions, built-wheel installation, Action abuse
  cases and exporter conformance in CI.
- Manually requested release candidates, distribution checksums, release evidence,
  build attestations and environment-gated OIDC publication.
- Align documentation with MIT licensing and the alpha support boundary.

[0.1.0]: https://github.com/aisecnomad/Nexus-symbiote/commits/main
