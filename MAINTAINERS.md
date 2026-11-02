# Maintainers

## Current maintainers

| Name | GitHub | Role |
| --- | --- | --- |
| AISecNomad | [@aisecnomad](https://github.com/aisecnomad) | Maintainer |

There is one maintainer. Review, merge, release, and security decisions are
made by that account, with AI coding assistants used for implementation and
review. [GOVERNANCE.md](GOVERNANCE.md) states what that means for independent
review and how it changes when a second maintainer joins.

## Responsibilities

- Triage issues and private vulnerability reports ([SECURITY.md](SECURITY.md))
- Review pull requests against [CONTRIBUTING.md](CONTRIBUTING.md) and the
  [merge requirements](GOVERNANCE.md#what-a-change-needs-to-merge)
- Keep static collection free of execution and network access, and keep
  validation, policy decisions, and live operations fail-closed
- Build release candidates, rehearse on TestPyPI, tag, and publish
  ([release runbook](docs/operations/releasing.md))
- Keep the dependency lock, the Action pins, and the vendored schemas reviewed
  and current
- Enforce the [code of conduct](CODE_OF_CONDUCT.md)

## How to reach the maintainer

- Public: [issues](https://github.com/aisecnomad/Nexus-symbiote/issues) and
  pull requests, routed by [SUPPORT.md](SUPPORT.md)
- Private (vulnerabilities, credential exposure, conduct concerns): the
  repository's private vulnerability reporting (**Security > Report a
  vulnerability**), as [SECURITY.md](SECURITY.md) describes; if it is
  unavailable, the [@aisecnomad](https://github.com/aisecnomad) GitHub profile
- There is no project e-mail address, chat, or paid support channel

## Becoming a maintainer

See [GOVERNANCE.md](GOVERNANCE.md#adding-a-maintainer). Start with
documentation, reproducible issues, synthetic fixtures, tests, or reviews. To
offer help, open a [usage question](https://github.com/aisecnomad/Nexus-symbiote/issues/new?template=question.yml)
titled `Maintainer interest` with your background. Experience with AI agent
supply chains, MCP, CycloneDX or SPDX, SARIF, Sigstore, or Python packaging is
particularly useful.

## Emeritus

None.
