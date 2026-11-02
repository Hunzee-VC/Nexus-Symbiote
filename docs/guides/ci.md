# Symbiote in CI

How to run Symbiote in GitHub Actions: generate the AgentBOM on every change, gate on policy findings, upload
SARIF to code scanning, keep the three documents as build artefacts, and (optionally) sign the snapshot
keylessly. Two shapes are shown: the composite Action shipped in this repository (`action.yml`) and the plain
CLI steps it runs, for runners that cannot use a composite action. Exit codes are listed in the
[CLI reference](../reference/cli.md#exit-codes).

## The composite Action

```yaml
name: AgentBOM

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write     # only needed with sarif-upload: true

jobs:
  agentbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aisecnomad/symbiote@main          # pin to a tag or commit in production
        with:
          scan-path: .
          output-dir: agentbom
          fail-on: high                         # critical | high | medium | low | info
          fail-on-indeterminate: "false"        # "true": unknowns fail the gate too
          exclude: SYM-COV-001                  # check-id globs to skip; "" gates on full coverage
          conformance-level: none               # none | minimal | standard | verified
          sarif-upload: "true"
```

The Action installs its runtime from `requirements-action.lock` (hash-locked, wheels only, with
`--require-hashes --only-binary=:all:`) and the reviewed source with `--no-deps --no-build-isolation` into an
isolated virtual environment, so a compromised or typosquatted dependency release cannot enter your job. It then runs
`scripts/run_action.py`, which drives the CLI as a subprocess: `symbiote scan` (all three documents) →
`symbiote validate` → `symbiote policy check --sarif --json` → optional `symbiote conformance`. Every input
arrives through an environment variable, never through shell source; every path is confined to
`GITHUB_WORKSPACE`. Because the checked-out tree is untrusted (a pull request controls it), `output-dir` must not
exist yet or must be empty and must not be a symlink: the Action refuses to write through planted links or to ship
planted files as evidence, and it uploads only the exact files it wrote. The default `exclude: SYM-COV-001` skips
the "not fully covered" check, which a static scan can never pass (runtime, network and instructions surfaces need
live collection); `SYM-COV-002` still guards absent-verified claims. The documents, `agentbom.sarif`, `findings.json` (and `conformance.json`) are uploaded as the
`agentbom` artifact even when the gate fails. Outputs: `agentbom-path`, `sarif-path`, `policy-exit-code`,
`conformance-exit-code`. The step's own exit code follows the CLI: 1 findings at or above `fail-on` (or a
failed conformance requirement), 3 an emitted document failed its schema, 5 conformance blocked by unknowns,
6 the scan could not read or write. `conformance-level` runs `symbiote conformance` after the policy gate so
both verdicts are recorded; `symbiote scan --profile LEVEL` is the single-command equivalent for plain steps.

## The same pipeline as plain steps

```yaml
name: AgentBOM

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write     # upload-sarif

jobs:
  agentbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - name: Install Symbiote
        run: uv tool install symbiote          # from a checkout of this repo: uv pip install -e .

      - name: Generate the AgentBOM (companion, CycloneDX 1.7, SPDX 3.0.1)
        run: symbiote scan . -o agentbom/

      - name: Validate the emitted documents against the official schemas
        run: symbiote validate agentbom/agentbom.json agentbom/agentbom.cdx.json agentbom/agentbom.spdx.json

      - name: Policy checks (SARIF for code scanning, JSON for the record)
        id: policy
        continue-on-error: true
        run: symbiote policy check agentbom/agentbom.json --sarif agentbom/agentbom.sarif --json > agentbom/findings.json

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agentbom/agentbom.sarif
          category: symbiote

      - name: Keep the documents
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agentbom
          path: agentbom/

      - name: Fail the job on findings at or above high
        if: steps.policy.outcome == 'failure'
        run: exit 1
```

Why the shape:

- **`scan` exits 0 even with findings** (collection succeeded; the findings are inside the document), so the gate
  is `policy check`, whose exit code 1 means "a `fail` finding at or above `--fail-on`". `continue-on-error`
  plus the final step lets the SARIF and artefact uploads run first and still fails the job.
- `validate` is cheap insurance that what you archive is schema-valid (`scan` already validated it and would
  have exited 3 otherwise).
- `upload-sarif` needs `security-events: write`. Indeterminate findings arrive as `note`-level `review` results,
  so an unknown never silently disappears from the Security tab.

## Tuning the gate

```bash
symbiote policy check agentbom/agentbom.json --fail-on critical                 # only critical fails the job
symbiote policy check agentbom/agentbom.json --fail-on-indeterminate            # unknowns fail too
symbiote policy check agentbom/agentbom.json --exclude 'SYM-COV-*'              # skip coverage checks for now
symbiote conformance agentbom/agentbom.json --level minimal                      # exit 1 fail / 5 unknown
symbiote diff approved/agentbom.json agentbom/agentbom.json \
    --fail-on-change tool-definition-changed --fail-on-change server-identity-changed
```

`diff` against an **approved** snapshot checked into the repository (or fetched from an artefact store) is the
change-control gate: a changed tool definition or server identity exits 1, a cosmetic re-collection exits 0.
Keep the approved document under review like code.

## Keyless signing

With an OIDC token available to the job, the snapshot can be signed through Sigstore and verified against an
identity constraint that names the workflow:

```yaml
permissions:
  contents: read
  id-token: write          # ambient OIDC credential for Sigstore
steps:
  - run: uv tool install 'symbiote[sign]'
  - run: symbiote scan . -o agentbom/ --store .symbiote/store
  - run: symbiote attest snapshot agentbom/agentbom.json --keyless -o agentbom/snapshot.sigstore.json
  - run: symbiote verify agentbom/snapshot.sigstore.json --policy .symbiote/verify-policy.yaml --companion agentbom/agentbom.json
```

```yaml
# .symbiote/verify-policy.yaml — only this workflow on main may vouch for the agent
identities:
  - identity: "re:^https://github\\.com/acme/widgets/\\.github/workflows/agentbom\\.yml@refs/heads/main$"
    issuer: "https://token.actions.githubusercontent.com"
```

A signature from any other identity verifies cryptographically but is reported as `identity-mismatch` (exit 4);
a policy without identities is refused rather than silently accepted. Details and the key-based alternative for
air-gapped runners: [attestation and enforcement](attestation-and-enforcement.md). Keyless signing was not
exercised while writing this page (it needs Fulcio, Rekor and an OIDC identity); the key-based flow was.

## Anti-rollback across runs

Persist the chain store between runs (`actions/cache` keyed on the agent, or a small bucket) and pass it to both
`scan --store` and `verify --store`. A snapshot whose serial does not exceed the recorded head is refused with
exit 7, so a replayed older BOM cannot pass review. Treat the store like a signed artefact: whoever can rewrite
it can rewind it.

## Exit codes in one place

| Code | Meaning | Typical step |
|---|---|---|
| 0 | success | — |
| 1 | findings at or above `--fail-on`; a requirement failed; a `--fail-on-change` event; a blocked tool | `policy check`, `conformance`, `diff`, `allowlist check` |
| 2 | usage error | any |
| 3 | schema validation failed | `validate`, `scan` |
| 4 | signature, binding or identity verification failed | `verify`, `merkle verify` |
| 5 | conformance blocked by unknowns (coverage) | `conformance` |
| 7 | serial regression or fork against the chain store | `verify --store`, `scan --store` |

## Pre-commit

This repository publishes two hooks in `.pre-commit-hooks.yaml`: `symbiote-scan` writes the companion document
to `.symbiote/out/` and `symbiote-policy` runs the `SYM-*` checks over it (exit 1 on findings at or above
`high`). Order matters: the policy hook reads what the scan hook wrote.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/aisecnomad/symbiote
    rev: main            # pin to a tag or commit
    hooks:
      - id: symbiote-scan
      - id: symbiote-policy
        args: [--fail-on, high]
```

Add `.symbiote/out/` to `.gitignore` (this repository ignores `.symbiote/` entirely); keep `.symbiote/store/`
if you want anti-rollback locally. Without the published hook, a `repo: local` entry with
`entry: bash -c 'symbiote scan . -o .symbiote/out --format companion >/dev/null && symbiote policy check
.symbiote/out/agentbom.json'` and `language: system` does the same.
