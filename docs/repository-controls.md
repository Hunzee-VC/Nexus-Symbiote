# Repository verification controls

The `Verified CI` job summarizes the full test matrix, quality checks,
coverage, distribution checks, security regressions, dependency-advisory acceptance
and CodeQL security policy. CodeQL is part of this same CI run rather than an
independent green badge. It fails if
any prerequisite fails, is skipped or is cancelled. Make this exact context a
required status check on `main`; running a workflow alone does not enforce it.

`config/github-main-protection.json` is a proposed GitHub branch-protection
configuration. It binds `Verified CI` to the GitHub Actions app (ID 15368) and
requires an up-to-date branch, that successful check, one
independent approval including approval of the last push, resolved discussions,
and enforcement for administrators. It disables branch deletion and force pushes.
The configuration file is not an applied repository setting. The approval
requirement needs another authorized reviewer.

`config/github-main-protection-interim.json` is the same configuration with
`required_pull_request_reviews` set to `null`. Use it only while the project
has no second authorized reviewer: applying the full configuration's
`required_approving_review_count: 1` with `enforce_admins: true` and no
bypass actor/restrictions on a single-maintainer repository blocks the
maintainer from merging their own pull requests, because GitHub does not
count self-approval toward a required review. The interim file still binds
`Verified CI` to the GitHub Actions app, enforces it for administrators, and
disables force pushes and branch deletion — `scripts/check_repository_controls.py`
only checks for those properties plus the enforced status check, not for
required reviews, so the interim configuration satisfies the same
publication preflight. Switch to the full configuration once a second
reviewer can approve changes, rather than leaving the weaker one in place
indefinitely.

After reviewing the exact configuration, an administrator with the appropriate
GitHub plan and repository Administration permission can apply it with:

```sh
# Solo-maintainer interim: no required review, same enforced status check
gh api --method PUT repos/Hunzee-VC/Nexus-Symbiote/branches/main/protection \
  --input config/github-main-protection-interim.json

# Full target configuration, once a second reviewer is available
gh api --method PUT repos/Hunzee-VC/Nexus-Symbiote/branches/main/protection \
  --input config/github-main-protection.json
```

Do not place an administrative token in CI. The publication preflight uses
only repository contents-read and Actions-read permissions:

```sh
python scripts/check_repository_controls.py --repo Hunzee-VC/Nexus-Symbiote --branch main --sha "$GITHUB_SHA"
```

The preflight requires `GH_TOKEN` or `GITHUB_TOKEN`. It checks GitHub's live
branch metadata, requires protection and administrator-wide status-check
enforcement, and verifies that `Verified CI` is required. It also requires the exact
source SHA to match the live branch head, the newest run of `.github/workflows/ci.yml`
for that SHA to succeed in this repository on the expected branch, and exactly one
successful `Verified CI`, `CodeQL policy` and `Dependency advisories` jobs in that
run's latest attempt. An unbound status with the same name cannot satisfy the
protection preflight. A pending or failed
newer run cannot be replaced by an older success. Missing or truncated job data,
an API failure, redirects and an unprotected branch fail closed. The SHA defaults
to `GITHUB_SHA`; local invocations must supply their reviewed commit explicitly.
This limited preflight
does not independently audit approval counts, bypass actors,
environment configuration or package-index ownership; an administrator must
review those separately. The preflight checks live state during the build; it
does not lock GitHub settings or cancel a candidate after later administrative
changes. Review the exact run and current controls at the environment approval.
Candidate builds remain available while controls are
being configured; publication requires a successful preflight.

If GitHub reports an unavailable plan feature or insufficient Administration
permission, resolve that account setting before claiming branch protection is
active. The GitHub connection used to prepare this change could read branch
metadata but was denied branch-protection administration. It did not apply the
configuration. Review the latest run annotations to resolve failures that happen
before any job steps start; a local passing suite does not establish that GitHub
Actions successfully ran.

## Security acceptance evidence

The `CodeQL policy` job analyzes the workflow checkout with the pinned CodeQL
Action and `security-and-quality` queries. The next step requires a nonempty
CodeQL rule catalog and rejects every security result with `security-severity`
7.0 or greater, including existing and suppressed results. Missing or invalid
severity on a security-tagged result fails closed. A successful analysis step
alone is not a zero-alert policy decision. Raw SARIF and the policy report are
retained together.

The policy script requires the actual Git `HEAD` to equal `GITHUB_SHA` and no
tracked source changes. On pull requests, default checkout and `GITHUB_SHA` both
identify the merge commit; substituting the PR head SHA fails. On `main` they
identify the push commit. Optional SARIF revision metadata must agree, and any
supplied invocation must explicitly report success. Native CodeQL can omit those
optional fields: source binding then comes from the trusted, pinned preceding
workflow step and the checked checkout, with a SARIF digest in the report. The
standalone SARIF evaluator does not authenticate an arbitrary file's origin.
Weekly/manual CodeQL runs apply the same policy; only the exact-source CI run
supplies publication acceptance.

`Dependency advisories` audits exact installed distribution versions after the
hashed CI lock is installed. It reuses the bounded HTTPS transport and follows
[OSV's per-query batch pagination](https://google.github.io/osv.dev/post-v1-querybatch/)
with package, page, response and total-time limits. Every query must complete;
transport errors, malformed results and missing pages deny acceptance and retain
a failure report. Any known advisory blocks the gate, without a hidden severity
exception or allowlist. No new audit-tool dependency is resolved outside the lock.
This queries public `https://api.osv.dev/v1/querybatch` without credentials and
needs direct outbound HTTPS. This source-built project is excluded from PyPI
lookups and identified by the reviewed source revision instead. An empty OSV
response means no advisory known to OSV for that queried version; it does not
establish absence of vulnerabilities, malicious packages or undisclosed defects.

## Operator prerequisites

The 2026-11-03 review observed `main` with no classic branch protection
(`GET /branches/main/protection` returns 404) and one repository ruleset named
`main` whose `conditions.ref_name.include` list is empty. A ruleset with no
included refs targets no branch, so its pull-request, code-scanning and
non-fast-forward rules are inert. Consistent with that, most first-parent
commits on `main` arrived as direct pushes rather than merged pull requests.
Secret scanning was also disabled.

An administrator must apply the reviewed protection configuration above (or
retarget the ruleset to `~DEFAULT_BRANCH` and add `Verified CI` as a required
check), enable secret scanning, and then observe a successful exact-source CI
run. `scripts/check_repository_controls.py` reads the live state and fails the
publication preflight until the enforced check is present. Do not remove the
acceptance gates to work around an unavailable platform feature. Configure and
independently verify the `pypi` environment reviewers and main-only deployment
restriction before requesting publication.
