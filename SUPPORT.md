# Support

Nexus SymBiote is alpha software with a single volunteer maintainer. Support is
best effort: there is no guaranteed response time, no commercial support, and no
service-level agreement. A successful scan is an inventory result, not a safety
certificate, and a version string does not establish that a revision has been
reviewed for your environment.

## Choose the right route

| Need | Route |
| --- | --- |
| Installation, commands, export formats, or what a result means | [README](README.md), the [documentation](docs/), and the steps below |
| Usage question | [Usage question form](https://github.com/aisecnomad/Nexus-symbiote/issues/new?template=question.yml) |
| Reproducible bug, wrong inventory entry, or unexpected validation, risk, or export result | [Bug report form](https://github.com/aisecnomad/Nexus-symbiote/issues/new?template=bug_report.yml) |
| Scanner, exporter, policy, CLI, or Action proposal | [Feature request form](https://github.com/aisecnomad/Nexus-symbiote/issues/new?template=feature_request.yml) |
| Missing, unclear, or incorrect documentation | [Documentation form](https://github.com/aisecnomad/Nexus-symbiote/issues/new?template=documentation.yml) |
| Vulnerability, credential exposure, or unsafe tool behavior | [SECURITY.md](SECURITY.md): private reporting only, never a public issue |
| Participation or conduct concern | [Code of conduct](CODE_OF_CONDUCT.md#reporting-a-concern) |
| Contribute a fix, a fixture, or a review | [CONTRIBUTING.md](CONTRIBUTING.md) |

Search [existing issues](https://github.com/aisecnomad/Nexus-symbiote/issues)
before opening a new one, and add new evidence to an existing report instead of
opening a duplicate.

## Before you report

1. Record the output of `nexus-symbiote --version` and `python --version`, and
   your operating system. Version `0.1.0` is not yet published and the same
   version string covers many commits, so for a source checkout also record
   `git rev-parse HEAD`.
2. Reduce the problem to one command and the smallest synthetic project that
   reproduces it, for example a temporary directory holding a single
   `.mcp.json`, `CLAUDE.md`, or model file. `--scanner` narrows collection to
   the scanner in question.
3. Read the coverage, validation, and risk output before concluding that a
   result is wrong. Static collection reports failed or inaccessible inputs as
   collection gaps rather than hiding them, and a command can write an output
   file while returning a failing exit code. Both are expected behavior.
4. Say whether the command was a static one or an opt-in live operation
   (`verify-live`, `discover-mcp`, `advisories`). Static scans execute nothing
   and contact nothing; the live operations are documented in the
   [README](README.md) and bounded by [SECURITY.md](SECURITY.md).

## What a useful report contains

- The version, Python, and operating system details from step 1.
- The exact command, with private paths, account identifiers, and secrets
  removed, and the output format used (`json`, `cyclonedx`, `spdx`, `sarif`,
  or `vex`).
- The synthetic input needed to reproduce the problem, or a public repository
  pinned to a commit.
- Expected behavior, actual behavior, and the process exit code.
- The relevant part of the sanitized output or error, and the policy file
  (`.nexus-symbiote.yaml`) if one was in use.

## What never to post publicly

Do not attach real credentials or tokens, private inventories or BOM exports,
evidence directories, launch policies with real launcher paths and digests,
Nexus-ShadowScan reports from real environments, customer data, or exploit
details. Inventories can expose infrastructure, permissions, endpoints, and
instruction fingerprints, and export redaction cannot identify every secret or
sensitive business detail. Inspect every attachment before posting it. If a
reproduction would expose a vulnerability or confidential data, use the private
route in [SECURITY.md](SECURITY.md).

## What to expect

One maintainer triages issues as capacity permits, with AI-assisted
development; there is no team, on-call rotation, or paid support. Fixes land on
`main`; there is no backport commitment for older revisions. Security and
data-integrity concerns are assessed first, then reproducible regressions, then
new capabilities. A request for more evidence is not a promise of a fix or a
delivery date. Contributing a reproducer, fixture, test, or documentation
change linked to the issue is the fastest way to move it forward.
