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

After reviewing the exact configuration, an administrator with the appropriate
GitHub plan and repository Administration permission can apply it with:

```sh
gh api --method PUT repos/aisecnomad/Nexus-Symbiote/branches/main/protection \
  --input config/github-main-protection.json
```

Do not place an administrative token in CI. The publication preflight uses
only repository contents-read and Actions-read permissions:

```sh
python scripts/check_repository_controls.py --repo aisecnomad/Nexus-Symbiote --branch main --sha "$GITHUB_SHA"
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

The review observed `main` unprotected, no required-check enforcement, and hosted
CI/CodeQL jobs failing before any runner steps started. The API did not establish
the startup failure's cause. Rulesets reported that the current private-repository
plan does not enable the feature; protection administration was unavailable to
the integration. These changes do not activate account features or change those
remote settings. An administrator must resolve those account/runner prerequisites,
enable the required code-scanning entitlement and permissions, apply the reviewed
protection configuration above, and observe a successful exact-source CI run.
Do not remove the acceptance gates to work around an unavailable platform feature.
Configure and independently verify the `pypi` environment reviewers and main-only
deployment restriction before requesting publication.
