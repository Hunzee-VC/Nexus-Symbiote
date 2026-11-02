# Release procedure

`.github/workflows/release.yml` is dispatched manually from `main` with one input,
`publish`:

| `publish` | What the run does |
|---|---|
| `none` (default) | Builds, tests and attests a release candidate. Uploads nothing to a package index. |
| `testpypi` | The same candidate, then uploads it to [TestPyPI](https://test.pypi.org/p/nexus-symbiote) as a rehearsal. |
| `pypi` | The same candidate, then uploads it to [PyPI](https://pypi.org/p/nexus-symbiote). |

TestPyPI and PyPI use the same pipeline, the same gates and the same kind of attested
bytes, so a successful rehearsal exercises everything except the final index.

This repository change does not configure GitHub environments, package-index
ownership, trusted publishers or repository protection. A maintainer does that once,
as described below.

## One-time setup

1. **Make the repository's controls available.** Artifact attestations, and the
   environment protection the `pypi` and `testpypi` environments rely on, are
   available on every GitHub plan for public repositories. For private repositories
   they depend on the plan; for example, attestations in a private repository need
   GitHub Enterprise Cloud. GitHub Actions must also be able to run: check
   *Billing & plans* if jobs end without starting.
2. **Create two environments**, `testpypi` and `pypi`. Give each required reviewers,
   enable *Prevent self-review*, and restrict deployments to `main`.
3. **Create a pending trusted publisher on each index**, right before the first
   upload, because a pending publisher does not reserve the name:
   - PyPI: <https://pypi.org/manage/account/publishing/>
   - TestPyPI: <https://test.pypi.org/manage/account/publishing/>

   Use project name `nexus-symbiote`, owner `aisecnomad`, repository
   `Nexus-Symbiote`, workflow `release.yml`, and environment `pypi` or `testpypi`
   respectively. Always set the environment: without it, any job in the workflow
   holding an OIDC token could publish. No API token is needed or stored.
4. **Protect `main`** and require `Verified CI` and reviewed changes, following
   [repository controls](repository-controls.md). The workflow cannot create these
   controls itself.

## Each release

1. Choose the version. `pyproject.toml` and `src/nexus_symbiote/__init__.py` must
   agree; `scripts/check_repository_hygiene.py` fails CI otherwise. Move the
   changelog's *Unreleased* entries under the new version.
2. Dispatch with `publish=none`. Inspect the run's wheel, source distribution, SBOM,
   installed-distribution inventory, checksums and build attestation. Test the wheel
   in an isolated environment outside the checkout.
3. Dispatch with `publish=testpypi` and approve the `testpypi` environment. Install
   the rehearsal in a fresh environment, taking dependencies from PyPI:

   ```bash
   python -m venv /tmp/rehearsal && . /tmp/rehearsal/bin/activate
   pip install --index-url https://test.pypi.org/simple/ \
     --extra-index-url https://pypi.org/simple/ nexus-symbiote==<version>
   nexus-symbiote --version
   ```

   An index never accepts the same file name twice, so a second rehearsal of the
   same version needs a new version number, for example a release candidate such
   as `0.1.0rc2`.
4. Dispatch with `publish=pypi` and approve the `pypi` environment. Review the
   artifacts of this exact run at the approval gate.
5. Verify the published files against this run's checksums and provenance, for
   example with `gh attestation verify <file> --repo aisecnomad/Nexus-Symbiote`.
   Create a matching signed tag `v<version>` and release notes. Do not claim
   publication succeeded until the package index and the source revision agree.

A `testpypi` or `pypi` run fails closed if its read-only preflight cannot establish
the required branch controls and successful CI for the exact source commit.

## What the pipeline guarantees

**Build integrity.** The build job exports the checked-out commit with `git archive`
and builds there with `SOURCE_DATE_EPOCH` set to the commit time. Nothing that a
later step writes into the workspace, such as test output or release evidence, can
reach the source distribution. Two local builds of the same commit produced
identical files; reproducibility across runners is not attested. The job then
checks that there is exactly one wheel and one sdist, runs `twine check --strict`,
and uploads them **before** anything runs tests, writes evidence or resolves
dependencies without hashes. The attest and publish jobs use those uploaded bytes,
so a dependency that misbehaves during a later step cannot change what is attested
or published.

**Locked build tools.** The release build uses `--no-isolation` after installing
`requirements-ci.lock` with hash verification. The build frontend, backend and
their dependencies come from the reviewed environment instead of a fresh, unpinned
one.

**Acceptance against the exact wheel.** The `distribution` CI job and the release
build install the exact candidate wheel into the locked test environment. The
acceptance runner verifies its SHA-256 against pip installation metadata, checks
the package import location, and runs selected tests outside the checkout. These
cover a clean repository baseline, a complete ShadowScan source report, a forged
inventory omitting a project file, an MCP endpoint substitution, supplier-controlled
policy discovery, a revoked trust signer, and distinct SPDX revision identities. A
failed or skipped acceptance case blocks the candidate before attestation.

**Public dependency ranges.** A separate clean installation resolves the wheel's
runtime dependencies from PyPI, as users will, and exercises it. Its
installed-distribution inventory is part of the release evidence. Because that
resolution is not hash-locked, it runs only after the distributions are uploaded.

**Evidence.** `project.cdx.json` is a static inventory of the checked-out project,
not a guarantee of complete runtime or build dependency coverage.
`installed-distributions.json` records the smoke-test environment. `SHA256SUMS`
covers the release distributions and evidence files. GitHub's build attestation
binds the distribution bytes to the workflow identity and source revision. Every
candidate also runs the committed per-case security-regression gate and keeps its
complete `security-regressions.json` report, including failures. Passing those
finite fixture contracts is a release prerequisite, not an estimate of production
efficacy. The normal CI `Verified CI` check also requires statement and branch
coverage floors (90% and 75%) and every verification job to succeed.

**Privilege separation.** The build job reads repository content and Actions run
metadata only. A separate attest job holds OIDC and attestation-write permissions,
and only the environment-gated publish job can upload, through the trusted
publisher configured for its environment. Neither of those jobs checks out or runs
project source or any shell step. Both download artifacts with
`digest-mismatch: error`, so a corrupted transfer stops the run.

The composite GitHub Action uses a separate hashed runtime and build lock and an
isolated environment, then installs its reviewed source with dependency resolution
and build isolation disabled. This fixes its dependency input set without claiming
byte-identical builds.
