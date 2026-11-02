# Release procedure

The release workflow (`.github/workflows/release.yml`) is dispatched manually from `main`. Its default
(`publish=false`) builds a **candidate** and publishes nothing. The workflow does not configure GitHub
environments, PyPI ownership, trusted publishers or branch protection; an administrator does that once, as
described below and in [repository controls](repository-controls.md).

## What a candidate run produces

| Artifact | Contents |
|---|---|
| `release-distributions` | the sdist and wheel built by `python -m build`, checked with `twine check --strict` |
| `release-evidence` | `installed-distributions.json` (the smoke-test environment's `pip inspect`), `agentbom/` with the companion document, CycloneDX 1.7 SBOM, SPDX 3.0.1 document, loss reports, SARIF and policy findings of `examples/triage-agent` produced **by the installed wheel**, and `SHA256SUMS` over everything above |
| build attestations | GitHub build provenance for every distribution file and for `evidence/SHA256SUMS` |

The build job runs the full gate first: `ruff`, `mypy`, the test suite, the companion-schema drift check,
`scripts/check_workflows.py` and `scripts/check_repository_hygiene.py`. The wheel is installed into a fresh
virtual environment outside the checkout before it is exercised, so the evidence describes the artefact that
would be published, not the source tree. `SHA256SUMS` binds the evidence to the distribution files; the build
attestation binds the distribution bytes to the workflow identity and source revision. The scan of the example
agent is a static inventory of that example; it is not a statement about runtime coverage of anything else.

## Before enabling publication

1. **Confirm the distribution name.** `pyproject.toml` names the distribution `symbiote` and the command
   `symbiote`. Confirm that the name is owned by this project on PyPI (or choose and register another) before
   the first `publish=true` dispatch; the `publish` job's environment URL points at
   `https://pypi.org/p/symbiote`.
2. **Configure the trusted publisher** on PyPI for `aisecnomad/symbiote`, workflow `release.yml`, environment
   `pypi`. No long-lived API token is used anywhere.
3. **Protect the `pypi` environment**: required reviewers, deployments restricted to `main`.
4. **Protect `main`** so that `Verified CI` is a required status check (see
   [repository controls](repository-controls.md)). The workflow only runs from `main`.
5. **Dispatch a candidate** (`publish=false`). Inspect the wheel, sdist, evidence and attestations. Install the
   wheel in a clean environment and run `symbiote version --json` and `symbiote scan` on a project you know.
6. **Dispatch with `publish=true`** only after that review. It builds and tests a fresh candidate from the
   selected `main` revision; the environment approval gate is where the approver reviews the artefacts of
   *this exact run*. The publish job downloads the run's own distributions and authenticates through OIDC with
   `attestations: true`.
7. **Verify after publication**: download from PyPI, compare checksums with `SHA256SUMS`, verify the provenance
   (`gh attestation verify`), create the matching signed source tag and the release notes, and add the version
   heading to `CHANGELOG.md`. Do not claim a release until the index and the source revision agree.

## Permissions model

| Job | Permissions | Why |
|---|---|---|
| `build` | `contents: read` | runs project source and tests; must not be able to publish or attest |
| `attest` | `id-token: write`, `attestations: write` | signs what `build` produced; checks out nothing and runs no project code |
| `publish` | `id-token: write`, environment `pypi` | the only job that can publish, and only through the configured trusted publisher |

## Dependencies

The release tooling (`build`, `twine`) is the `release` extra in `pyproject.toml`; CI's `distribution` job uses
the same extra so every pull request builds and smoke-tests the wheel the same way. Dependency resolution is
not hash-locked on this branch: `pip` resolves the public ranges in `pyproject.toml` at build time. A
reproducible, hash-locked environment for releases is tracked as future work in
[work packages](work-packages.md) and should be adopted before 1.0.
