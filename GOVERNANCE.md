# Governance

Nexus SymBiote is an alpha project with a single maintainer. This document separates decision ownership, review expectations and proposed repository controls from observed enforcement, and states what a single maintainer means for the people who rely on the tool.

## Maintainer and decisions

[Emmanuel Dahunsi (@aisecnomad)](https://github.com/aisecnomad) holds final authority on project direction, architecture, dependency changes, merges and releases during alpha. See [MAINTAINERS.md](MAINTAINERS.md) for ownership and responsibilities.

Contributors can propose changes through issues and pull requests. The maintainer evaluates scope, compatibility, security consequences and available evidence. Experimental branches do not replace the supported `nexus_symbiote` package on `main`; useful capabilities require explicit, reviewed ports.

## Review expectations

Use the review contract in [CONTRIBUTING.md](CONTRIBUTING.md): explain the concrete problem, resulting behavior, tests and material limitations. Changes should pass the configured `Verified CI` aggregate, quality checks, coverage floors, distribution checks and committed security contracts.

Security-sensitive changes require a stated trust boundary and abuse case, a regression that fails on the vulnerable behavior, and review of the affected security corpus. Record the checks that actually ran and any unavailable verification. Local evidence does not establish a successful hosted matrix or CodeQL run. Any maintainer-authorized alpha exception must state its scope and remaining checks; it must not be described as passing unavailable CI or satisfying inactive protection.

### Review policy while there is one maintainer

No second person reviews changes today. What stands in for that review, and what each part does and does not establish:

- **Required checks.** `Verified CI` must pass on a branch that is up to date with `main`; branch protection enforces it for everyone, administrators included. It establishes that the gates ran, not that the change is right.
- **Gate integrity.** `scripts/check_workflows.py` fails when a verification job stops running its gate command, when an action pin moves back past its floor, or when a workflow gains a privileged trigger, writable top-level permissions, or a job write scope outside the reviewed list (code-scanning upload, attestation signing, trusted publishing). A change to those files is still self-approved; read such diffs line by line.
- **Soak window.** Behavior- and security-changing pull requests stay open for at least 24 hours before merging. Merging is not mechanically held; publication is: the release workflow refuses to publish to PyPI until the release commit has been on `main` for 24 hours, unless the maintainer states an urgent reason that the run log records.
- **Review record.** Each pull request records who reviewed the full rendered diff after CI and how, including whether an AI review ran outside the session that wrote the change.
- **AI-assisted changes.** Most of the history was written with AI assistance, disclosed in commit trailers. They receive the same review as any other change: the maintainer reads the full diff and is accountable for what merges. An assistant's review is a second opinion, not an independent reviewer. See "AI-assisted contributions" in CONTRIBUTING.md.

Adopters who need independent human review of their security tooling should treat this as a limitation: no release so far has had one. The first change once a second maintainer exists is the full branch-protection profile below, which requires their approval.

## Repository controls and current status

The checked-in [protection proposal](config/github-main-protection.json) requires `Verified CI`, up-to-date branches, independent review including the last push, code-owner review, resolved conversations, administrator enforcement, and no force pushes or branch deletion. It permits merge commits; it does not require linear history. The proposed independent approval requires another authorized reviewer beyond the sole maintainer's own changes.

Pull requests are also capped, in CI, at 1,500 changed lines outside `tests/` and `benchmarks/`. That cap does not require a second person. Signed commits are requested in [CONTRIBUTING.md](CONTRIBUTING.md#pull-requests). Turning the signature requirement on, adding a second code owner, applying the full protection profile, deleting merged branches and turning on automatic deletion of head branches are administrator settings. This repository cannot do them. The commands are in [repository controls](docs/repository-controls.md#administrator-actions-still-outstanding).

Until a second authorized reviewer exists, applying that configuration as written would block the sole maintainer from merging their own pull requests, since GitHub does not count self-approval toward a required review. [`config/github-main-protection-interim.json`](config/github-main-protection-interim.json) drops only the review requirement — `Verified CI` remains enforced for everyone, including administrators, and force pushes and branch deletion remain disabled. Treat it as a temporary floor, not a replacement for the full proposal. `.github/CODEOWNERS` names the owner of the gate paths; it requests review but enforces none under the interim profile.

This file does not apply GitHub settings. The hosted CI and CodeQL failures recorded by the 2026-11-02 audit have since been fixed, and hosted runs pass. On 2026-11-06 the interim configuration was applied to `main`, the repository ruleset was retargeted to the default branch, and the `testpypi` and `pypi` environments were limited to deployments from `main`, with the sole maintainer as their required reviewer. [Issue #74](https://github.com/Hunzee-VC/Nexus-Symbiote/issues/74) records the remediation history; the remaining administrator actions are tracked in the [roadmap](ROADMAP.md). See [repository controls](docs/repository-controls.md#operator-prerequisites) for the observed state of each control and the administrator commands that apply them. The publication preflight now checks that the release-tag ruleset is active and stops tags from moving or being deleted, and checks the environment's reviewer, branch restriction and administrator bypass itself, so a missing prerequisite blocks the release instead of being recorded as outstanding. GitHub shows who may bypass a ruleset only to an administrator, so the workflow's read-only token cannot check that and says so in the run log; before approving a publication, the maintainer runs the [administrator check](docs/repository-controls.md#apply-the-outstanding-controls), which fails unless the bypass list is readable and empty.

Do not claim active merge enforcement from a workflow file, governance statement or local passing suite. Verify live settings and successful checks for the revision being considered.

## Releases

Publication requires an explicit maintainer request. The release procedure separates read-only build and verification from attestation and OIDC publication. Required repository, environment and package-index settings must be configured before publication; the preflight verifies the ones the workflow token can read and fails closed when they are missing or unreadable. The release-tag ruleset's bypass list is the exception: only an administrator can read it, so the administrator check verifies it instead.

Review the exact candidate artifacts, checksums, source revision and provenance. The production publication preflight requires successful canonical CI evidence for the exact source SHA, protected-branch settings, the release-tag ruleset, a protected environment, the 24-hour soak and the signed release tag on that commit. See [releasing](docs/releasing.md) and [repository controls](docs/repository-controls.md). A candidate build or successful upload does not establish a production release or package safety.

## Continuity

One person is today the only reviewer, release approver, security contact and conduct contact. If that account is unavailable or compromised, nobody else can merge a fix, approve a release, yank a version or answer a report. Until that changes:

- **Security reports** go through GitHub's private vulnerability reporting, which survives a change of maintainer, and [SECURITY.md](SECURITY.md#reporting-a-vulnerability) describes a public fallback that discloses nothing.
- **Published versions** stay installable and verifiable without the maintainer: the README's verified install checks the attestation and the tagged lock, not a person.
- **Forking** is the recovery path if the project stops: the MIT license, the hash locks and the release workflow let a successor rebuild and re-attest under their own identity, but not publish under this project's PyPI name.

The maintainer's open actions, which no repository change can do for them: add a second owner to the Hunzee-VC organization and to the `nexus-symbiote` project on PyPI and TestPyPI, record both in MAINTAINERS.md together with who can yank a release and publish a fix, give the security and conduct policies a contact other than the maintainer, and keep recovery codes for both accounts somewhere a successor can reach. Until then, organizations with supplier-continuity requirements should treat the single point of failure as unresolved.

## Future governance

Additional maintainers, architectural RFCs and broader decision processes may be introduced as participation grows. Changes to governance should be documented through the same review process, including who owns the decision and which external controls are actually active.
