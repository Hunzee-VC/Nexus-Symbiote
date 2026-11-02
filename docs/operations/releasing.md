# Releasing

This runbook is for the maintainer. It covers the one-time setup and the
per-release steps that put a reviewed revision of Nexus SymBiote on
[TestPyPI](https://test.pypi.org/) as a rehearsal and then on
[PyPI](https://pypi.org/) as `nexus-symbiote`, so that
`pip install nexus-symbiote` installs it.

Publication is a manual maintainer action. Coding agents and contributors
prepare candidates; they never push a version tag, dispatch the workflow with
`publish` set, or approve a deployment. A green CI run is not a review.

## How an upload is gated

The release workflow
([`.github/workflows/release.yml`](../../.github/workflows/release.yml),
**Release candidate and approved publication**) is the only path to a package
index. No package-index token exists anywhere: PyPI and TestPyPI trust this
repository's workflow and environment through OpenID Connect
([trusted publishing](https://docs.pypi.org/trusted-publishers/)).

| Job | What it enforces | Permissions |
| --- | --- | --- |
| `build` | Runs on `main` only. The commit must equal the `expected_commit` input, so a candidate cannot silently move with `main`. Installs the hash-locked CI environment, runs the full check sequence (tests, ruff, mypy, workflow checks), builds the sdist and wheel, checks them with twine, installs the wheel outside the checkout and exercises it, records the installed distributions, a CycloneDX inventory of the checkout, the inventory benchmark evidence and `SHA256SUMS`. | `contents: read` |
| `attest` | GitHub build-provenance attestations for the distributions and for the inventory benchmark archive. No checkout. | `id-token`, `attestations` |
| `publication-gate` | Runs only when `publish` is `testpypi` or `pypi`. Requires exactly one wheel and one sdist of the same public release version (no `.dev`, `.post` or local part). For `pypi`, the tag `v<version>` must already point at the reviewed commit. | `contents: read` |
| `publish` | Waits for approval in the protected environment named by `publish`. Checks out nothing, downloads the attested distributions from this run, verifies their digests and uploads them with [`pypa/gh-action-pypi-publish`](https://github.com/pypa/gh-action-pypi-publish), which adds PEP 740 attestations. | `id-token: write` only |

With the default `publish: none`, the workflow builds and attests a review
candidate and uploads nothing.

## One-time setup

1. **Accounts.** PyPI and TestPyPI are separate accounts. Both require
   two-factor authentication; prefer a hardware security key.
2. **Pending trusted publishers.** On PyPI, open
   [Publishing](https://pypi.org/manage/account/publishing/) and add a GitHub
   pending publisher. Repeat on
   [TestPyPI](https://test.pypi.org/manage/account/publishing/) with the
   environment name `testpypi`.

   | Field | Value |
   | --- | --- |
   | PyPI project name | `nexus-symbiote` |
   | Owner | `aisecnomad` |
   | Repository name | `Nexus-symbiote` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` (TestPyPI: `testpypi`) |

   A pending publisher does not reserve the name; anyone can still register
   it. Publish the first release soon after registering. Keep the publisher
   afterwards: it becomes the project's publisher. The publisher names the
   repository, so renaming the repository requires re-registering it.
3. **GitHub environments.** Under **Settings → Environments** create `pypi`
   and `testpypi` with required reviewers (the maintainer; add a second
   reviewer and enable **Prevent self-review** as soon as one exists),
   deployment branches limited to `main`, and no secrets. Trusted publishing
   needs no token, and a stored token would bypass these gates.
4. **Protect release tags.** Add a tag ruleset for `v*` that blocks updates and
   deletion with no bypass actors. The publication gate reads the tag before
   the approval wait, and the ruleset keeps that answer true until the upload.
5. **Repository visibility.** Publishing an sdist makes the source public.
   Decide the repository's visibility first; CodeQL default setup, OpenSSF
   Scorecard result publishing and the README badges need a public repository.

## Per release

1. **Prepare the candidate.** The version is read from
   `src/nexus_symbiote/__init__.py` (`__version__`); set the same value in
   `CITATION.cff`. Date the release heading in `CHANGELOG.md`. `README.md` is
   the PyPI project description and is frozen with every upload, the TestPyPI
   rehearsal included: it must use absolute links, name no unpublished state as
   current, and describe the release accurately. Merge through the normal review
   process and note the full 40-character SHA of the resulting `main` commit.
2. **Review the exact commit** as [GOVERNANCE.md](../../GOVERNANCE.md)
   requires, and confirm the push CI run for that commit succeeded.
3. **Rehearse on TestPyPI.** Dispatch the workflow and approve the `testpypi`
   deployment:

   ```bash
   gh workflow run release.yml --repo aisecnomad/Nexus-symbiote --ref main \
     -f expected_commit=<reviewed-40-character-sha> -f publish=testpypi
   ```

   Check that the project page renders, then install in a throwaway
   environment. Use `--no-deps` so that TestPyPI, where anyone can register
   names, never supplies a dependency, and leave the checkout so that
   `python -m` imports the installed wheel rather than the source tree:

   ```bash
   python -m venv /tmp/nsb && . /tmp/nsb/bin/activate
   python -m pip install nexus-symbiote==0.1.0 --no-deps --index-url https://test.pypi.org/simple/ \
     && python -m pip install --require-hashes -r requirements-ci.lock
   cd "$(mktemp -d)" && nexus-symbiote --version && python -m nexus_symbiote --help
   mkdir empty && nexus-symbiote scan empty --report-only -f json -o agentbom.json
   ```

4. **Tag the reviewed commit.** Create an annotated tag on that exact commit.
   Signing the tag is optional; provenance comes from the workflow's GitHub
   attestations and the PyPI publish attestations:

   ```bash
   git tag --no-sign -a v0.1.0 -m "Nexus SymBiote 0.1.0" <reviewed-40-character-sha>
   git push origin refs/tags/v0.1.0
   ```

5. **Publish.** Dispatch again with `publish=pypi` and approve the `pypi`
   deployment. The gate rejects the run unless `v<version>` points at
   `expected_commit`.
6. **Verify and announce.** Download the published files and compare them with
   the run's `SHA256SUMS`, then verify the attestation:

   ```bash
   python -m pip download nexus-symbiote==0.1.0 --no-deps --no-binary :none: -d verify
   sha256sum verify/*
   gh attestation verify verify/nexus_symbiote-0.1.0-py3-none-any.whl --repo aisecnomad/Nexus-symbiote
   ```

   Create a GitHub release for the tag with the changelog entry, and enable the
   PyPI badge in `README.md`. Do not claim publication succeeded until the
   package index and the source revision agree.

## What the evidence files mean

`project.cdx.json` is a static inventory of the checked-out project collected
with the smoke-tested wheel; it is not a guarantee of complete runtime or build
dependency coverage. `installed-distributions.json` records the wheel smoke-test
environment. `inventory-benchmark.tar.gz` holds the public inventory corpus
results, their in-toto statement and the tested wheel's digest (see
[benchmarks/inventory/README.md](../../benchmarks/inventory/README.md)).
`SHA256SUMS` covers the distributions and evidence files. GitHub's build
attestation binds the distribution bytes to the workflow identity and source
revision.

Build and test jobs receive read access to repository content only. The
attestation job receives OIDC and attestation-write permissions and checks out
nothing. Only the environment-gated publish job can upload, through the
configured trusted-publisher identity, and it checks out nothing either.

Dependency locks make CI dependencies reviewable. Build isolation still
resolves the build backend declared in `pyproject.toml`; bit-for-bit
reproducible builds are not claimed. Test the supported minimum and current
dependency sets before widening version bounds.
