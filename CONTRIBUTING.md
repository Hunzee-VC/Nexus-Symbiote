# Contributing to Nexus SymBiote

Nexus SymBiote's compatibility baseline is the `nexus_symbiote` Python package and `nexus-symbiote` CLI on `main`. The product name is Nexus SymBiote. Experimental implementations on other branches are not interchangeable packages; port useful capabilities through reviewed, tested changes.

## First contribution

Read [SUPPORT.md](SUPPORT.md) for how the tool behaves and what to include when you ask for help; it is the place for usage questions. Well-bounded starter tasks are in the known-limitations list of [SECURITY.md](SECURITY.md#known-limitations-in-010): each names a file type, collector or check that is not covered yet. Open an issue with the feature form saying which one you will take before you start, so that two people do not do the same work.

Contributions are accepted under the project's [MIT licence](LICENSE): by opening a pull request you agree that your contribution is licensed under the same terms (inbound equals outbound), and that you have the right to submit it.

## Development

Use Python 3.11 through 3.14 on Linux and an isolated virtual environment. `make install-locked` installs the locked environment, and `make check` runs the offline subset of the required CI checks: quality, the coverage-gated test suite, the security regression contracts and the distribution build. The individual commands, from a checkout:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pip check
python -m pytest --strict-skips
ruff check src tests scripts
ruff format --check src tests scripts
mypy src/nexus_symbiote scripts
python scripts/check_workflows.py
python scripts/check_repository_hygiene.py
python scripts/check_locks.py
python scripts/check_security_regressions.py --out security-regressions.json
python -m pytest --strict-skips --cov=nexus_symbiote --cov=scripts --cov-branch --cov-report=json:coverage.json
python scripts/check_coverage.py coverage.json
python -m build --no-isolation
python -m twine check --strict dist/*
```

`make test-floor` runs the suite on Python 3.11 with every runtime dependency at its declared lower bound (it needs `python3.11`; set `PYTHON_FLOOR` to use another interpreter), as the CI `floor` job does. Both leave out the tests marked `locked_only`, which compare what a pinned library generates, such as the JSON schema pydantic derives from the models, with a committed file; every behaviour test still runs. A test that fails only at the floors means the declared floor is wrong: raise it and run `make lock`.

## Tests

`tests/conftest.py` gives every test a clean environment: the variables the tool, the Action runner and the gate scripts read (`NEXUS_SYMBIOTE_*`, `SYMBIOTE_*`, `GITHUB_*`, `GH_TOKEN`, colour and width settings) are removed, and `HOME` and the XDG directories point at a private temporary directory. A test that leaves an operating mode enforced fails. Use the `runner` fixture for a `CliRunner` and `tests/support.py`'s `load_script` (or the `load_script` fixture) to import a script from `scripts/`; do not import one test module from another.

Each test has a time limit and fails with its traceback when it hangs, instead of using up the CI job's budget: `test_timeout` in `pyproject.toml` (300 seconds, for loaded development machines), tightened to 120 seconds in CI (240 under coverage). Mark a known slow test with `@pytest.mark.timeout(seconds)`, and give every `subprocess.run` in a test its own `timeout` as well. To show that parsing a hostile input stays linear, compare two input sizes with `tests.support.scaling_ratio` instead of asserting a duration: a busy runner or coverage tracing slows both sizes alike.

The run lists every skip with its reason. With `--strict-skips`, which CI and `make test` pass, any skip other than a host file-system difference (a case-insensitive alias that a case-sensitive file system cannot have, or a name the file system refuses) fails the run. Do not guard a required dependency with `pytest.importorskip`; import it.

Parsers of hostile input need generated inputs as well as examples. `tests/test_parser_properties.py` checks the requirements collector against `packaging`, Dockerfile `FROM` handling, redaction of planted secrets, that no collected file can crash `scan`, and that hostile inputs parse in bounded time. The suite's Hypothesis profile is deterministic; a weekly job runs the same properties with the randomized `fuzz` profile (`python -m pytest --hypothesis-profile=fuzz tests/test_parser_properties.py`). Write new properties without a fixed `max_examples` so that profile can widen them.

## Dependency locks

Three hash locks are generated from `pyproject.toml`; never edit them by hand.

| Lock | Contents | Used by |
| --- | --- | --- |
| `requirements-ci.lock` | Every extra and the `dev` dependency group, for CPython 3.11 and later on every platform | CI, the release build, `make install-locked` |
| `requirements-action.lock` | The core dependencies, the `sigstore` extra and the build backend, resolved inside the CI lock: the same versions and the same hashes | The GitHub Action and the README's verified installs |
| `requirements-floor.lock` | Each runtime dependency and the build backend at its declared lower bound on Python 3.11, with the test tools at their CI versions | The `floor` CI job, `make test-floor` |

`make lock` regenerates all three with the uv version pinned in `scripts/check_locks.py` (it refuses any other). It keeps the existing CI pins unless a declaration needs a change, considers only packages uploaded before the cut-off recorded in the locks, and records that cut-off, the uv version and a digest of the dependency declarations in each lock's header. `make lock-upgrade` moves the cut-off to seven days ago and upgrades every CI pin to the newest release older than that, so a release has a week of public scrutiny before it can be locked. Both need access to PyPI; never run them with release credentials, or on a pull request you have not reviewed.

`make lock-check` (`python scripts/check_locks.py`, also part of the CI quality job) checks offline that each lock was generated from the current declarations with the pinned uv and one cut-off, that every pin is an exact, hashed version inside its declared range, that the Action lock repeats the CI lock's versions and hashes and holds no test tool, and that the floor lock tests exactly each declared lower bound. A declared floor that cannot be installed together with the others, such as `pydantic>=2.10` beside the `sigstore` extra, which needs 2.12, fails until the floor is raised to what is tested.

Dependabot proposes range changes in `pyproject.toml` only. Such a pull request fails `make lock-check` until a maintainer runs `make lock` on its branch. Before merging any change to the declared ranges or the locks, review new packages, hashes, markers and licences, and wait for the "Dependency health" workflow, which runs the full suite on the newest releases the ranges admit; it is not part of `Verified CI` because its result depends on PyPI rather than on the change. The same workflow audits every locked pin against OSV daily and runs the randomized property tests weekly.

Every CI and release install of a lock uses `--require-hashes --only-binary=:all:` followed by `pip check`: a missing wheel stops the job instead of building a source distribution with unpinned build tools.

`Dependency advisories` blocks on any OSV advisory for a pin of the CI or Action lock. If an advisory cannot be fixed in time and does not affect this project, add a waiver to `config/dependency-advisory-waivers.json` in a reviewed pull request: the advisory ID, the package and exact version, a reason of at least 20 characters, and an expiry at most 90 days ahead. The gate prints and records every waiver, fails on an expired or malformed one, and fails on a waiver that no longer matches an advisory of the version it names. If OSV is unreachable, the gate fails closed: re-run the job later; there is no bypass.

## Verified CI and coverage

`Verified CI` aggregates the test matrix, the dependency-floor tests, coverage, quality, distribution, security-regression, dependency-advisory and CodeQL jobs. Missing, failed, cancelled and skipped prerequisites fail that stable check. Branch protection must require it; see [repository controls](docs/repository-controls.md). `scripts/check_workflows.py` fails if any of those jobs stops running the command that makes it a gate, so a job cannot be emptied while keeping its name.

The coverage gate (`scripts/check_coverage.py`) uses exact counts rather than rounded display percentages. It holds the package to its statement and branch floors and each security-critical module (confined reads, hashing, signature verification and policy, the validators, the differ, the offline guard, runtime authorization, redaction and terminal neutralization) to its own, so that a well-tested average cannot hide an untested module. The gate scripts are measured as well, without counting toward the package figure, and the Action's runner `scripts/run_action.py` has a floor of its own; a report that leaves `scripts/` out fails. The job prints the measured figures beside the floors and writes them to the run summary; the floors themselves live only in that script. They prevent regression and are not a completeness claim. Raise them as missing paths gain tests.

## Architecture boundaries

Nexus-ShadowScan is the primary discovery engine. Preserve the `import-shadowscan` workflow when changing collection or graph code. Imported claims, local observations, approved snapshots, and mediated operations have different assurance. Keep A2A, IDE, and registry declarations explicit rather than inferring deployment or effective permissions from presence alone.

Run `PYTHONPATH=src python scripts/benchmark_security.py --out benchmark-results.json` after security changes. Review individual cases, corpus/source digests, unknowns, and denominators. Do not replace labels or remove negative fixtures to improve the result. The corpus is a finite regression suite, not representative field efficacy evidence.

CI and release candidates also run `scripts/check_security_regressions.py`. Every committed detection label and control contract must pass; missing cases, abstentions on detection cases, duplicate cases and evaluator errors fail. A passing malformed-input coverage control can deliberately have an unknown detection prediction. The full per-case report is retained even when this gate fails. New labels and changed expectations require review of the fixture and its rationale; passing these fixtures establishes no production accuracy or percentile ranking.

## Security changes

State the trust boundary and an abuse case before changing security decisions. Add a regression that fails on the vulnerable behavior, including unknown and invalid inputs. Keep evidence of origin separate from evidence of approval and observed runtime behavior. Invalid policies, incomplete collection, missing required evidence, and unsupported critical semantics must not become silent successful verdicts.

Exporter changes must validate against the pinned official schema and preserve references, unknown states, and loss reports. Canonical digest changes require versioned profiles and test vectors. Do not update a golden file merely to make a failing test pass.

## Pull requests

Explain the concrete problem, resulting behavior, validation, and material limitations. Keep changes focused and include applicable documentation. Do not claim production enforcement for execution paths that bypass the adapter. Add no network access, executable discovery, or credential collection without an explicit design and tests.

During the interim single-maintainer period (see [repository controls](docs/repository-controls.md)), keep every change on a pull request, up to date with `main` before it merges, and leave behavior- or security-changing pull requests open for a soak window of at least 24 hours before merging; re-read the full rendered diff after `Verified CI` completes and treat it as the reviewed artifact. Small documentation-only fixes may merge once CI is green. High-volume days of self-merged reviews are where defects slip through; the soak window is the control that compensates for the absent second reviewer. Fill in the pull request's review record: who reviewed the diff, when, and how. Publication repeats the soak mechanically: the release workflow refuses to publish to PyPI until the release commit has been on `main` for 24 hours (see [releasing](docs/releasing.md)).

A pull request that rewrites a whole file from an old branch can silently revert changes merged since. Resolve conflicts against current `main`, never by taking your side wholesale, and check that the diff removes nothing you did not mean to remove; `scripts/check_workflows.py` also refuses an action pin older than its recorded floor and a gate job that lost its command.

## AI-assisted contributions

Contributions written with an AI assistant are welcome on the same terms as any other, and much of this project's history was written that way. The person who opens the pull request is its author: they must understand every line, have run the checks, and answer review questions themselves.

- Disclose the assistance: a `Co-Authored-By:` trailer naming the assistant, or a sentence in the pull request.
- Review the full rendered diff yourself after `Verified CI` completes. Generated code tends to restate what it was asked rather than what the code does; check tests for assertions that cannot fail.
- A review by an assistant is a useful second opinion but not an independent review unless it runs outside the session that wrote the change, with its findings attached to the pull request. Record which it was in the review record.
- Never paste secrets, private BOMs or unpublished vulnerability details into an assistant.

## Repository hygiene

The quality job also checks tracked source for conflict markers; documentation links, including heading anchors and absolute links into this repository; package, distribution and citation version agreement; and the vendored schemas' recorded SHA-256 digests. The README is also the package-index description, and `twine check` does not render Markdown, so the check rejects relative links and images in it and confirms that each absolute one still resolves to a tracked file and heading. These checks are offline and do not authenticate an upstream publisher. Review changes to schema bytes and their provenance manifest together. Keep experimental-branch merges and manually ported changes distinct from ancestry on `main`; the [closed-PR audit](docs/audits/closed-pr-review-2026-11-02.md) records that distinction.

Read [SECURITY.md](SECURITY.md) before reporting security-sensitive defects. This project is licensed under MIT as specified in [LICENSE](LICENSE).
