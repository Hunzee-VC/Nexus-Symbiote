# Repository verification controls

The `Verified CI` job summarizes the full test matrix, quality checks,
coverage, distribution checks and security-regression expectations. It fails if
any prerequisite fails, is skipped or is cancelled. Make this exact context a
required status check on `main`; running a workflow alone does not enforce it.

`config/github-main-protection.json` is a proposed GitHub branch-protection
configuration. It requires an up-to-date branch, successful `Verified CI`, one
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

Do not place an administrative token in CI. A contents-read workflow token is
sufficient for the publication preflight:

```sh
python scripts/check_repository_controls.py --repo aisecnomad/Nexus-Symbiote --branch main
```

The preflight requires `GH_TOKEN` or `GITHUB_TOKEN`. It checks GitHub's live
branch metadata, requires protection and administrator-wide status-check
enforcement, and verifies that `Verified CI` is required. Missing data, an API
failure, redirects and an unprotected branch fail closed. This limited preflight
does not independently audit approval counts, app binding, bypass actors,
environment configuration or package-index ownership; an administrator must
review those separately. Candidate builds remain available while controls are
being configured; publication requires a successful preflight.

If GitHub reports an unavailable plan feature or insufficient Administration
permission, resolve that account setting before claiming branch protection is
active. The GitHub connection used to prepare this change could read branch
metadata but was denied branch-protection administration. It did not apply the
configuration. Review the latest run annotations to resolve failures that happen
before any job steps start; a local passing suite does not establish that GitHub
Actions successfully ran.
