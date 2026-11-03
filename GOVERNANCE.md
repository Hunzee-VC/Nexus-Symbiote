# Governance

Nexus SymBiote is an alpha project with a single maintainer. This document separates decision ownership, review expectations and proposed repository controls from observed enforcement.

## Maintainer and decisions

[Emmanuel Dahunsi (@aisecnomad)](https://github.com/aisecnomad) holds final authority on project direction, architecture, dependency changes, merges and releases during alpha. See [MAINTAINERS.md](MAINTAINERS.md) for ownership and responsibilities.

Contributors can propose changes through issues and pull requests. The maintainer evaluates scope, compatibility, security consequences and available evidence. Experimental branches do not replace the supported `nexus_symbiote` package on `main`; useful capabilities require explicit, reviewed ports.

## Review expectations

Use the review contract in [CONTRIBUTING.md](CONTRIBUTING.md): explain the concrete problem, resulting behavior, tests and material limitations. Changes should pass the configured `Verified CI` aggregate, quality checks, coverage floors, distribution checks and committed security contracts.

Security-sensitive changes require a stated trust boundary and abuse case, a regression that fails on the vulnerable behavior, and review of the affected security corpus. Record the checks that actually ran and any unavailable verification. Local evidence does not establish a successful hosted matrix or CodeQL run. Any maintainer-authorized alpha exception must state its scope and remaining checks; it must not be described as passing unavailable CI or satisfying inactive protection.

## Repository controls and current status

The checked-in [protection proposal](config/github-main-protection.json) requires `Verified CI`, up-to-date branches, independent review including the last push, resolved conversations, administrator enforcement, and no force pushes or branch deletion. It permits merge commits; it does not require linear history. The proposed independent approval requires another authorized reviewer beyond the sole maintainer's own changes.

Until a second authorized reviewer exists, applying that configuration as written would block the sole maintainer from merging their own pull requests, since GitHub does not count self-approval toward a required review. [`config/github-main-protection-interim.json`](config/github-main-protection-interim.json) drops only the review requirement — `Verified CI` remains enforced for everyone, including administrators, and force pushes and branch deletion remain disabled. Treat it as a temporary floor, not a replacement for the full proposal.

This file does not apply GitHub settings. At the 2026-11-02 audit, live `main` metadata reported `protected: false`, and inspected hosted jobs had no recorded runner or steps. Those observations and required remediation are tracked in [issue #74](https://github.com/Hunzee-VC/Nexus-Symbiote/issues/74). See [repository controls](docs/repository-controls.md) for the actual verification boundary and administrator setup.

Do not claim active merge enforcement from a workflow file, governance statement or local passing suite. Verify live settings and successful checks for the revision being considered.

## Releases

Publication requires an explicit maintainer request. The release procedure separates read-only build and verification from attestation and OIDC publication. Required repository, environment and package-index settings must be configured and verified before publication; their presence is not established by this document.

Review the exact candidate artifacts, checksums, source revision and provenance. The production publication preflight requires successful canonical CI evidence for the exact source SHA as well as protected-branch settings. See [releasing](docs/releasing.md) and [repository controls](docs/repository-controls.md). A candidate build or successful upload does not establish a production release or package safety.

## Future governance

Additional maintainers, architectural RFCs and broader decision processes may be introduced as participation grows. Changes to governance should be documented through the same review process, including who owns the decision and which external controls are actually active.
