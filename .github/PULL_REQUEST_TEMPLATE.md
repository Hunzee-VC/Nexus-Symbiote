## Problem

<!-- The concrete problem this change solves. Link related issues; write "Fixes #NNN" only when the issue is resolved completely. -->

## Resulting behavior

<!-- What the tool does after this change that it did not do before: changed output, exit codes, coverage, policy decisions. -->

## Validation

<!-- Paste the commands you ran and their results. Name the commit you tested and any check you did not run. -->

- [ ] `python -m pytest`
- [ ] `ruff check src tests scripts` and `ruff format --check src tests scripts`
- [ ] `mypy src/nexus_symbiote`
- [ ] `python scripts/check_workflows.py` (when `action.yml` or `.github/workflows/` changed)
- [ ] `python -m build` and `python -m twine check dist/*` (when packaging or dependencies changed)
- [ ] `PYTHONPATH=src python scripts/benchmark_security.py --out benchmark-results.json` after security changes, with individual cases, corpus and source digests, unknowns and denominators reviewed, and no label replaced or negative fixture removed

## Material limitations

<!-- What this change does not cover, what remains unverified, and what a user must still check themselves. -->

## Security changes

<!-- Delete this section if the change touches no security decision, trust boundary, parser of untrusted input, exporter or digest. -->

- Trust boundary crossed:
- Abuse case considered:
- [ ] A regression test fails on the vulnerable behavior, including unknown and invalid inputs
- [ ] Evidence of origin, evidence of approval and observed runtime behavior stay separate
- [ ] Invalid policies, incomplete collection, missing required evidence and unsupported critical semantics do not become silent successful verdicts
- [ ] Exporter changes validate against the pinned official schema and preserve references, unknown states and loss reports; canonical digest changes carry versioned profiles and test vectors
- [ ] `SECURITY.md` updated if a trust boundary or control changed

## Checklist

- [ ] Tests added or updated for the changed behavior; no golden file updated merely to make a failing test pass
- [ ] Documentation updated, and a `CHANGELOG.md` line added under `Unreleased` for user-visible changes
- [ ] No new network access, executable discovery or credential collection without an explicit design and tests
- [ ] No production-enforcement claim for execution paths that bypass the adapter
- [ ] No real credentials, private inventories or customer data in the diff, the fixtures or this description
- [ ] The change is focused on the stated problem
