# Pull-request labels

What each label on a pull request means, who sets it, and which labels every pull request carries. A
label's one-line description in GitHub's label settings should agree with this page; when you add a
label, add its row here in the same change.

## Rules

- Every pull request carries at least one [type](#type) label and one [area](#area) label.
- An open pull request carries exactly one [review state](#review-state) label. It starts at
  `needs-independent-review`, and its reviewers move it.
- A pull request closed without merging carries a [disposition](#disposition) label and a comment
  that names its successor or gives the reason.
- Labels never replace the review comment. A state label points to a comment that holds the
  evidence: the head SHA reviewed, the checks run and the findings.

## Review state

"Independent" means the review ran outside the session or person that wrote the change, as
[AI-assisted contributions](../CONTRIBUTING.md#ai-assisted-contributions) defines it.

| Label | Meaning | Set by |
| --- | --- | --- |
| `needs-independent-review` | No independent review yet, or a new head that no reviewer has read | The author, when opening the pull request or pushing a new head after a review |
| `review: changes-needed` | An independent review found blocking issues; its comment lists them | The reviewer |
| `review: verified` | The pull request passed an independent, test-executing review at the head SHA named in the review comment. A later head needs a new review | The reviewer |
| `do-not-merge` | A hold: do not merge until the blocking review comment, or the merge coordination issue, clears it. It goes with `review: changes-needed` for a reproduced high-severity defect, or a conflict with a recorded decision | A reviewer, or whoever holds the merge lock |

## Severity

The `severity: high`, `severity: medium` and `severity: low` labels follow the scale of the
[finding catalog](finding-catalog.md), and they have two uses. Read the review comment to tell which
one applies.

- **On a fix:** the severity of the vulnerability or defect it fixes.
- **On a pull request under review:** the most severe open review finding. The reviewer sets it with
  `review: changes-needed`, and the next review updates or removes it when the findings are fixed.

## Type

| Label | Use it for |
| --- | --- |
| `bug` | A fix for behaviour that differs from what the documentation or tests promise |
| `enhancement` | New behaviour or a new output |
| `documentation` | Documentation and contributor guides |
| `refactor` | A restructure with no intended change in behaviour |
| `code quality` | Lint, static-analysis and CodeQL clean-ups |
| `dependencies` | Dependency ranges, pins and locks |
| `breaking-change` | A change in behaviour or output that users, reviewed baselines or downstream consumers depend on. Its CHANGELOG entry says what to re-baseline |
| `migration` | A schema, fingerprint or data migration that needs inventories to be collected again |

## Area

| Label | Covers |
| --- | --- |
| `core` | The core framework: models, evidence, hashing, policy and the CLI |
| `scanner` | Collectors under `src/nexus_symbiote/scanners/` |
| `generator` | Exports under `src/nexus_symbiote/generators/` |
| `validator` | Validators under `src/nexus_symbiote/validators/` |
| `integration` | Cross-tool integration, such as the ShadowScan import and export |
| `provenance` | Build provenance, attestations and evidence binding |
| `standards` | CycloneDX, SPDX, SARIF, VEX and other standards conformance |
| `spec` | Specification and policy definitions |
| `security` | A change to a trust boundary or a security control |
| `testing` | Tests, fixtures and test infrastructure |
| `performance` | Performance and resource budgets |
| `ci-cd`, `github_actions` | Workflows, the composite Action and release automation |
| `python` | Python code and packaging; Dependabot also applies it to pip updates |

## Disposition

| Label | Meaning |
| --- | --- |
| `superseded` | Closed in favour of a later pull request that carries the change. The closing comment names that pull request, or the merge commit through which the change reached `main` |
| `duplicate` | Closed because another pull request or issue already does the same |
| `wontfix` | Closed on purpose; the closing comment gives the reason |

## Campaigns

| Label | Meaning |
| --- | --- |
| `audit-2026-11` | Fixes from the November 2026 audits: the [security audit of 2026-11-14](audits/security-audit-2026-11-14.md) and the [repository audit of 2026-11-16](audits/repository-audit-2026-11-16.md) |
