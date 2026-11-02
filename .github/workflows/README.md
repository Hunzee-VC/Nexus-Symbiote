# Workflows

Every GitHub Actions workflow in this directory, what starts it, what it gates,
and what it may write. GitHub runs only the `.yml` files here; this page is
documentation.

[`scripts/check_workflows.py`](../../scripts/check_workflows.py) runs in the
CI quality job and in `tests/test_action_security.py`. It rejects any `uses:`
that is not pinned to a full commit SHA and any `${{ }}` expression inside a
`run:` block (values pass through `env`), and it checks the workflow skeleton
(top-level keys, jobs with steps, known `needs`). Conventions the script does
not check but every workflow follows: the pin comment names the tag the SHA
was taken from, every checkout sets `persist-credentials: false`, every job
has `timeout-minutes`, the top-level permission is `contents: read`, and write
scopes are granted per job, only where that job needs them.

## Inventory

| Workflow | Starts on | What it does and gates | Writes |
| --- | --- | --- | --- |
| [CI](ci.yml) | push to `main`, every pull request, manual | `test`: the suite on Python 3.11, 3.12 and 3.13 from the hash-locked environment. `coverage`: the suite with line coverage on 3.12. `quality`: `ruff check`, `ruff format --check`, `mypy src/nexus_symbiote` and `scripts/check_workflows.py`. `distribution`: `python -m build`, `twine check`, then installs the wheel outside the source tree and exports native, CycloneDX and SPDX inventories of an empty directory. These four jobs are the merge gate. | nothing |
| [Release candidate and approved publication](release.yml) | manual only (`workflow_dispatch`, and only from `main`) | `build`: checks that `GITHUB_SHA` equals the `expected_commit` input, then runs the full check sequence, builds the sdist and wheel, runs `twine check` and the wheel smoke test, and records the release evidence (`installed-distributions.json`, `project.cdx.json`, `inventory-benchmark.tar.gz`, `SHA256SUMS`) as run artifacts. `attest`: GitHub build-provenance attestations for the distributions and for the inventory benchmark archive, with no checkout. `publication-gate` (only when `publish` is `testpypi` or `pypi`): requires exactly one wheel and one sdist of the same public version, matching the build's checksums, and for `pypi` the tag `v<version>` on the reviewed commit. `publish` (same condition): waits for approval in the environment named by `publish`, re-checks the checksums and uploads the attested files with `pypa/gh-action-pypi-publish` through trusted publishing with PEP 740 attestations. With the default `publish: none` nothing is uploaded. | `id-token`, `attestations` (`attest`); `id-token` (`publish`) |
| [CodeQL](codeql.yml) | push to `main`, pull requests to `main`, Monday 05:41 UTC; only once the repository is public | Python code scanning. Results appear under Security > Code scanning and as a check on the pull request. | `security-events` |
| [Scorecard](scorecard.yml) | push to `main`, branch protection changes, Monday 05:53 UTC, manual; only once the repository is public | OpenSSF Scorecard. Publishes the result to the Scorecard API and uploads the SARIF to code scanning. The score measures repository practices, not code quality or independent review. | `security-events`, `id-token` |

The repository is private today. CodeQL on a private repository needs GitHub
Advanced Security, and Scorecard result publishing needs a public repository,
so the `analyze` and `analysis` jobs carry
`if: ${{ !github.event.repository.private }}` and are skipped until the
repository is public. A skipped run is expected until then, not a passing
analysis.

The [release runbook](../../docs/operations/releasing.md) describes how a
maintainer uses the release workflow, including the TestPyPI rehearsal that
[GOVERNANCE.md](../../GOVERNANCE.md#releases) requires before a PyPI
publication.

## Changing a workflow

Run `python scripts/check_workflows.py` (or `make check-workflows`) and the
test suite before pushing. Dependabot ([`dependabot.yml`](../dependabot.yml))
proposes pin updates weekly; a new pin keeps the version comment, and the
`codeql-action` sub-actions move together. A new write scope is granted only
to the job that needs it and recorded in the table above.
