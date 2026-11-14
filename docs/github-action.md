# GitHub Action

The composite Action collects an AgentBOM in a workflow job and applies the collection, completeness, integrity, risk and drift gates. Every input and output is defined in [action.yml](../action.yml). On `pull_request` the workflow file comes from the change under review, so also [protect the gate](drift-gate.md#protect-the-gate).

## Add it to a workflow

Pin the Action to a reviewed 40-character commit:

```yaml
name: Agent inventory
on: [push, pull_request]
permissions:
  contents: read
jobs:
  inventory:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: Hunzee-VC/Nexus-Symbiote@<reviewed-40-character-commit-sha>
        with:
          scan-path: .
          output-file: agentbom.json
          validate: 'true'
          risk-check: 'true'
          risk-threshold: '50'
          fail-on-severity: 'high'
          sarif-upload: 'false'
```

The Action installs its own hash-locked runtime, including Sigstore verification, in a private virtual environment that it keeps off the job's `PATH`, without changing the job's default Python. It ignores policy in the scanned checkout and fails on collection errors. Text from the checkout reaches the job log only inside a `stop-commands` block, neutralized, so it cannot set outputs or create annotations. Keep a job timeout like the one above: hostile input can keep a scan running until the job times out.

## What each gate checks

- **Every gate states its result.** The `result` output is `passed` or `failed`, and `gates` is a JSON object with the state of each gate (`collection`, `completeness`, `integrity`, `risk`, `drift`): `passed`, `failed`, `skipped` (switched off by an input) or `not-run`. Every gate an input switches off is printed as a warning.
- **Integrity needs one matching digest or signature.** With `validate: 'true'`, integrity passes only when at least one artifact hash or signature verifies and no component's evidence is unknown, so a repository in which nothing verifies, such as an empty checkout or one with only an MCP configuration, fails. The digest of an instruction file counts, although the same run recorded it from the same checkout: adding a one-line `CLAUDE.md` to such a repository makes integrity pass without verifying anything about its MCP servers (a [known limitation](known-limitations.md#gates-and-drift)). A model counts only as a SafeTensors file whose every weight file is signed or digest-pinned in a [signer policy](model-integrity.md#operator-signature-policy) you own, so a repository that contains a model fails unless every model meets such a policy. `validate-integrity: 'false'` checks completeness without integrity, for a repository whose models cannot be signed yet; `validate: 'false'` skips both.
- **The risk gate.** `fail-on-severity` defaults to `high`: any finding at or above that severity fails the run, including a permission bypass or an unpinned launcher, even when the aggregate score stays under `risk-threshold`. Set `fail-on-severity: critical` to restore the previous Action behavior, which failed on severity only for critical findings, or `none` to disable the severity check (printed as a warning). The aggregate score is an unbounded sum of finding weights, not a percentage from 0 to 100; `risk-threshold` is a threshold for that sum and the Action accepts 0 to 100. `risk-threshold: '0'` removes only the score threshold; findings at or above `fail-on-severity`, unverified SafeTensors, incomplete coverage and missing evidence still fail it. With `validate: 'true'`, risk reconciles the inventory against `scan-path` with the same signer policy, so a reconciliation failure fails it too, without a score. `risk-check: 'false'` skips it.
- **Unverified discovery evidence.** A ShadowScan report in the repository is unsigned discovery evidence unless the signer policy verifies its producer, and the completeness and risk gates fail on it. `allow-unsigned-discovery: 'true'` accepts it explicitly, with a warning.
- **The drift gate.** `reviewed-baseline` adds it: the absolute path of a reviewed AgentBOM outside the workspace, written from a trusted source like the signer policy below, which the Action compares with `diff --fail-on-alert`. The `drift-passed` and `drift-alerts` outputs report the result. The Action collects with the step's `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, if any, so record the baseline with the same key, or with none. [Gate drift in CI](drift-gate.md) says where the baseline must come from.
- **Limits.** `limits` raises [collection limits](collection-limits.md#set-a-limit), for example `'entries=200000,model-total-bytes=512GiB'`. The job's own `NEXUS_SYMBIOTE_LIMITS` is ignored, and so are its `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT` and `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256`: signatures verify against the trust root embedded in the Action's hash-locked `sigstore` package, never a file an earlier step named.
- **SARIF.** Set `sarif-upload: 'true'` and add `security-events: write` to upload SARIF. The upload is skipped, with a warning, for an inventory that merges imported ShadowScan discovery. Give each Action step in one workflow run its own `artifact-name` and `sarif-category`.

## Supply the signer policy

Write the signer policy outside the workspace from a trusted source, such as a repository or organization variable, never from the checked-out code:

```yaml
      - name: Write the signer policy
        env:
          SIGNER_POLICY: ${{ vars.NEXUS_SYMBIOTE_SIGNER_POLICY }}
        run: printf '%s' "$SIGNER_POLICY" > "$RUNNER_TEMP/signers.json"
      - uses: Hunzee-VC/Nexus-Symbiote@<reviewed-40-character-commit-sha>
        with:
          scan-path: .
          signature-policy: ${{ runner.temp }}/signers.json
```

The Action refuses a policy inside the workspace, a path that passes through a symlink (including a symlinked `RUNNER_TEMP`), or a hard link, passes one snapshot of it to collection, validation and the risk gate, and reports its SHA-256, as `sha256:<hex>`, in the `signature-policy-digest` output. It verifies signatures offline against the Sigstore trust root shipped in its hash-locked `sigstore` package, never a cache on the runner. The [signer policy format](cli-reference.md#signer-policy) is in the CLI reference.
