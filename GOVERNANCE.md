# Governance

## Current model and accountability

Nexus SymBiote is maintained by [@aisecnomad](https://github.com/aisecnomad),
a single maintainer who is accountable for project decisions, merge authority,
releases, security advisories, and repository administration. Development is
AI-assisted: commits are co-authored with AI coding assistants. There is no
foundation, governing board, paid support, or independent review team, and
there are no response-time guarantees.

Because one person holds every role, there is no non-author review of
maintainer-authored changes. An AI-assisted, single-maintainer project has no
independent review unless a release's notes state, for that release, who
reviewed which commit and what they verified. A green CI run, a CodeQL or
Scorecard result, or a build attestation is not an independent review.

## Roles

| Role | Responsibilities | Current holders |
| --- | --- | --- |
| Maintainer | Review and merge changes, decide direction, manage releases and repository access, respond to security reports, moderate project spaces | [@aisecnomad](https://github.com/aisecnomad) |
| Contributor | Submit code, fixtures, tests, or documentation; report issues; take part in design and review discussions | Open to everyone |

There is no separate reviewer role today. A role is not a claim of independent
assurance: whoever produced a change cannot supply its independent review.

## Decision process

- **Small fixes and documentation:** open a focused pull request that explains
  the problem, the resulting behavior, the validation performed, and any
  material limitation, as [CONTRIBUTING.md](CONTRIBUTING.md) describes.
- **New scanners, exporters, validators, or live operations:** open an issue
  first. Describe the evidence source, the trust boundary, the failure
  behavior, the synthetic fixtures that will test it, and the maintenance cost
  before implementing it.
- **Architecture and trust boundaries:** discuss options in an issue. The
  maintainer makes the final decision after considering the discussion and
  records the rationale in the pull request and, when behavior changes, in
  [CHANGELOG.md](CHANGELOG.md) and the documentation.
- **Security changes:** use private reporting where public details would
  expose users ([SECURITY.md](SECURITY.md)). Document the resulting policy
  and compatibility changes once disclosure is appropriate.
- **Breaking changes:** document the reason, the affected behavior, and the
  migration steps in the changelog and under
  [docs/migrations](docs/migrations/). Call out existing snapshots,
  baselines, and digests that need recollection or recomputation.

State relevant conflicts of interest. A disputed decision can be revisited in
the original issue with new evidence, an alternative, or a narrower proposal.
Conduct concerns follow the [code of conduct](CODE_OF_CONDUCT.md), not a
technical discussion.

## What a change needs to merge

- A green CI run on the final revision: the test matrix on Python 3.11 to
  3.13, the coverage job, the quality job (`ruff check`, `ruff format
  --check`, `mypy`, and `scripts/check_workflows.py`), and the distribution
  job (`python -m build`, `twine check`, and the wheel smoke test). CodeQL
  analysis runs on every pull request to `main` as well.
- Maintainer review. Until a second maintainer exists, maintainer-authored
  changes merge without non-author review; this limitation is stated above
  and must not be described otherwise.
- For security-relevant changes, the trust-boundary statement, the abuse
  case, and the regression test that
  [CONTRIBUTING.md](CONTRIBUTING.md#security-changes) requires. The regression
  must fail on the vulnerable behavior, including unknown and invalid inputs.
  Invalid policies, incomplete collection, missing required evidence, and
  unsupported critical semantics must not become silent successful verdicts.
- For exporter changes, validation against the pinned official schemas with
  references, unknown states, and loss reports preserved; canonical digest
  changes need versioned profiles and test vectors.
- A [CHANGELOG.md](CHANGELOG.md) entry under `Unreleased` for user-visible
  changes, and documentation for new behavior.
- No new network access, executable discovery, or credential collection
  without an explicit design and tests. Static scans execute nothing and
  contact nothing; live operations stay explicit opt-ins.

Do not weaken a gate, bypass a check, or update a golden file merely to make a
failing test pass.

## Releases

Nexus SymBiote is alpha software at version 0.1.0 and is not yet published on
PyPI. Publication is a manual maintainer action; nothing publishes
automatically. A release requires:

1. A candidate built by the release workflow
   ([`.github/workflows/release.yml`](.github/workflows/release.yml)) from the
   `main` commit named in its `expected_commit` input: the full check
   sequence, the sdist and wheel, the twine check, the wheel smoke test, and
   the release evidence produced in that run, with GitHub build-provenance
   attestations for the distributions.
2. A TestPyPI rehearsal before any publication of that version to PyPI, with
   the rehearsed distribution installed and exercised outside the source tree
   as the [release runbook](docs/operations/releasing.md) describes.
3. A version that agrees everywhere: `__version__` in
   `src/nexus_symbiote/__init__.py` (the value `pyproject.toml` reads),
   [CITATION.cff](CITATION.cff), a dated [CHANGELOG.md](CHANGELOG.md)
   section, and an annotated tag `v<version>` on the exact published commit,
   which the workflow's publication gate checks before a PyPI upload. A tag
   is never moved; a mistaken publication is superseded by a new version.
4. Approval in the protected `pypi` environment by the maintainer. The
   workflow uploads only the attested distributions through PyPI trusted
   publishing; no package-index token exists.
5. A statement in the release notes of what review the candidate received.
   Unless the notes name an independent reviewer and the commit they
   reviewed, the release had none.

Publishing an sdist to PyPI, or to TestPyPI during the rehearsal, makes the
source public, so repository visibility is decided before the first upload.
The repository is private today; the CodeQL and Scorecard workflows run only
once it is public.

A published package or a version string is not proof of independent review or
of acceptance for any particular deployment.

## Adding a maintainer

Sustained, careful contributions and willingness to maintain changes inform an
invitation; commit volume does not. Before access is granted, the current
maintainer and the candidate agree on scope (for example scanners, exporters,
or releases), decision authority, expected availability, and the escalation
path for out-of-scope decisions. The current maintainer then records the role,
scope, and effective date in [MAINTAINERS.md](MAINTAINERS.md), grants the
least GitHub permission the role needs (write access, not administration,
unless administration is in scope), and records the handover in a pull
request. The project holds no shared credentials, signing keys, or
package-index tokens; PyPI publication uses trusted publishing from the
protected environment, so there is nothing to share beyond repository access.

A second maintainer makes non-author review possible. When one joins, this
document and the merge requirements change to require it. Until then the
project carries a single-person continuity risk.

## Stepping down

When a maintainer steps away, the project revokes their repository and
environment access, rotates any shared credential that may exist by then,
records the departure date and an emeritus entry in
[MAINTAINERS.md](MAINTAINERS.md), and reviews their recent security-sensitive
approvals so none is left without an accountable owner. A sole maintainer who
steps down either names a successor and transfers administration and the
trusted-publisher configuration to them, recording the handover, or archives
the repository so that no one mistakes an unmaintained project for a
maintained one.

## AI-assisted development

The project uses AI coding assistants for implementation and review. The
maintainer remains responsible for correctness, licensing, security, test
evidence, and explaining every change. Generated code receives the same checks
as any other code. AI output, including an AI review of AI-produced code, does
not satisfy an independent review requirement, and internal hardening notes
are never described as third-party audits.

## Community policies

Participation follows the [code of conduct](CODE_OF_CONDUCT.md). Use
[SUPPORT.md](SUPPORT.md) for questions and [SECURITY.md](SECURITY.md) for
private vulnerability reports. Changes to this document or any policy are
proposed in a pull request with the reason and practical impact and follow the
same merge requirements as code.
