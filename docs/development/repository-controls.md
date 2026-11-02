# Repository verification controls

## One required status check

`.github/workflows/ci.yml` ends with an aggregate job named **`Verified CI`**. It runs on `always()`, needs
every other job (`test` across the Python matrix, `quality`, `distribution`, `rego-parity`, `docs`) and fails
if any of them failed, was skipped or was cancelled. `scripts/check_workflows.py` fails CI if the aggregate
stops covering a job. Make this exact context a required status check on `main`; a workflow that merely runs
enforces nothing.

## Proposed branch protection

[`config/github-main-protection.json`](https://github.com/aisecnomad/symbiote/blob/main/config/github-main-protection.json)
is a **proposal**, not applied state. It requires an up-to-date branch, a successful `Verified CI`, one
approving review including approval of the last push, resolved conversations, and enforcement for
administrators; it disables force pushes and branch deletion. The one-approval rule needs a second authorised
reviewer. After reviewing the file, an administrator with repository Administration permission applies it with

```sh
gh api --method PUT repos/aisecnomad/symbiote/branches/main/protection \
  --input config/github-main-protection.json
```

If GitHub reports a plan limitation or insufficient permission, resolve that before claiming that `main` is
protected. Never place an administrative token in CI for this purpose.

## Workflow hygiene gates

Two offline scripts run in the `quality` job and in the release build:

- `scripts/check_workflows.py` rejects every `uses:` that is not pinned to a 40-hex commit (one reviewed,
  documented exception is listed in the script), rejects `${{ }}` expressions inside `run:` blocks (inputs
  travel through `env`), checks that `needs` only name real jobs, and requires the `Verified CI` aggregate.
- `scripts/check_repository_hygiene.py` rejects unresolved conflict markers, dangling inline local Markdown
  links (including `spec/`, the README and the root policies, which `mkdocs --strict` does not cover),
  disagreement between `pyproject.toml` and `symbiote.__version__`, and any vendored schema whose digest
  differs from `config/vendored-schema-provenance.json`.

## Publication preflight

Publication (`release.yml` with `publish=true`) relies on the `pypi` environment's required reviewers and on
`main` being protected as above. A read-only API preflight that fails publication closed unless the live
branch protection, the required check and the CI run for the exact SHA can be confirmed was part of the
previous `main` and is **not** carried on this branch; re-add it when publication is enabled
([work packages](work-packages.md)). Until then the approver at the environment gate performs that review by
hand: the run's source SHA equals the `main` head, `Verified CI` succeeded for it, and the artefacts under
review belong to this run.
