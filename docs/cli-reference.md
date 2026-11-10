# CLI reference

Every `nexus-symbiote` command and option. `nexus-symbiote --help` and
`nexus-symbiote <command> --help` describe the version you installed and are
authoritative where this page differs; `tests/test_cli_reference.py` fails when a
command, option or environment variable is missing here.

```text
nexus-symbiote [--offline | --live] [--debug] [--version] [--help] COMMAND [ARGS]...
```

## Global options

| Option | Description |
|---|---|
| `--offline` | Refuse name resolution, network connections and process creation (the default). |
| `--live` | Allow the network and process steps of `discover-mcp`, `advisories` and `verify-live`. Every other command stays offline. |
| `--debug` | Print where a collector or internal error was raised on standard error: its class and the files, lines and functions of its traceback, without its message, which can quote project or inventory text. Without it, an unexpected error ends the command with `Error: internal error (<error class>)` and exit status 1, and a collector error is recorded by its diagnostic code only. |
| `--version` | Print the version and exit. |
| `--help` | Print help and exit. |

Every `-o`/`--output` file, and the policy file `init --path` creates, is written
atomically and never through a symbolic link:
its directory must already exist, and no directory on the path may be a symbolic
link (on macOS, write under `/private/tmp` rather than `/tmp`). `..` steps to the
real parent directory, as the operating system resolves it. A refused path ends the
command with an error and writes nothing; any other failure, such as a permission
error, is reported by the operating system's message, without the path.

Mode flags and `--debug` go before the command. Without a flag,
`NEXUS_SYMBIOTE_MODE=offline|live` selects the mode; without either, the mode is
offline. See [offline and live modes](offline-and-live-modes.md).

## Commands

| Command | Mode | Purpose |
|---|---|---|
| [`scan`](#scan) | offline | Inventory a project and write an AgentBOM (native JSON, CycloneDX, SPDX or SARIF) |
| [`import-shadowscan`](#import-shadowscan) | offline | Convert a Nexus ShadowScan report into an AgentBOM of imported claims |
| [`validate`](#validate) | offline | Check an AgentBOM's completeness and integrity, optionally against the project |
| [`risk`](#risk) | offline | Score findings and apply the risk gate |
| [`diff`](#diff) | offline | Compare two AgentBOMs and report security-relevant drift |
| [`summary`](#summary) | offline | Print component and risk counts |
| [`blast-radius`](#blast-radius) | offline | List agents and components associated with one component |
| [`baseline`](#baseline) | offline | Write an unsigned snapshot only if the scan gate passes |
| [`vex`](#vex) | offline | Export findings as a VEX document with status `in_triage` |
| [`verify-artifact`](#verify-artifact) | offline | Check a file's SHA-256, and optionally its Sigstore bundle |
| [`verify-discovery`](#verify-discovery) | offline | Check that a BOM was imported from exactly this ShadowScan report |
| [`init`](#init) | offline | Create a `.nexus-symbiote.yaml` policy file |
| [`runtime keygen`](#runtime-keygen) | offline | Create an Ed25519 key pair for runtime contracts |
| [`runtime sign`](#runtime-sign) | offline | Sign a runtime contract |
| [`runtime verify`](#runtime-verify) | offline | Verify a signed runtime contract's purpose, signers and validity window |
| [`discover-mcp`](#discover-mcp) | **live** | List the tools an HTTPS MCP server serves, without calling them |
| [`advisories`](#advisories) | **live** | Query OSV for advisories affecting exact PyPI and npm package versions |
| [`verify-live`](#verify-live) | **live** | Compare an AgentBOM with the tools that operator-pinned stdio servers serve |

## Output and CI logs

Results go to standard output: the reports of `validate`, `risk`, `diff`, `summary`
and `blast-radius`, the inventory that `scan` and `vex` print without `-o`, and every
`--json-output` document. Progress, notes, warnings and errors go to standard error.
`scan` writes its progress and its gate verdict there too, so that standard output can
carry the inventory: `nexus-symbiote summary bom.json > summary.txt` keeps the summary,
and `2>/dev/null` hides only diagnostics.

Text taken from an inventory or a checkout, such as names, paths, references and
descriptions, is printed literally and inert, in a terminal and in a CI log:

- control, format and line-break characters are replaced with U+FFFD, so such text
  cannot move the cursor, rewrite earlier output or start a new line;
- a `##` that would introduce a CI log command anywhere in a line (GitHub Actions'
  legacy `##[command]`, Azure Pipelines' `##vso[`, TeamCity's `##teamcity[`) is
  followed by U+FFFD;
- no such text starts an output line: every line opens with fixed text, so a name
  cannot become a `::command::` workflow command;
- nothing is read as markup or emoji codes, and lines are never wrapped.

The JSON that `scan` and `vex` print without `-o`, and the `--json-output` documents of
`validate`, `risk`, `diff`, `summary` and `blast-radius`, write a `[` that follows such a
`##` as `\u005b`; the document parses to exactly the same value. Files written
with `-o` are not changed.
Colors are used only on a terminal, and `NO_COLOR` turns them off.

## Exit codes

| Exit | Meaning |
|---|---|
| `0` | The command completed and every requested gate passed. |
| `1` | A gate or check failed (risk gate, integrity, digest or signature mismatch, `diff --fail-on-alert`, incomplete collection or observation), the input could not be read or parsed, `import-shadowscan` ran without `--report-only`, or an unexpected internal error occurred. |
| `2` | Usage error: an unknown command or option, a missing argument or file, a `PROJECT_PATH` of `scan` or `baseline` or a `--project` of `validate`, `risk` or `verify-artifact` that is a file, an invalid value (including a malformed `verify-artifact --sha256` and an incomplete `--bundle`, `--signer-identity` and `--issuer` set), a relative project path that a symbolic link leads outside the working directory, an invalid `NEXUS_SYMBIOTE_MODE`, a `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` shorter than 32 characters, or a live command run without live mode. |

What exit status 1 means for each gate:

| Command | Exits 1 when |
|---|---|
| `scan` | A collector failed or the scan gate failed, unless `--report-only` or a report-only project policy applies. |
| `validate` | Completeness, integrity (including integrity that is only unknown), the discovery producer check, the minimum assurance level or the dependency graph failed. |
| `risk` | The risk gate failed, or `--project` reconciliation failed. |
| `diff` | `--fail-on-alert` was given and the diff reports a security alert. |
| `baseline` | The scan gate failed, under the project policy or the built-in one. |
| `verify-artifact`, `verify-discovery`, `verify-live` | The digest, signature, projection or observation does not match. |

## Environment variables

| Variable | Effect |
|---|---|
| `NEXUS_SYMBIOTE_MODE` | `offline` or `live`; selects the mode when no mode flag is given. Any other value is a usage error. |
| `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` | An operator secret of at least 32 characters. `scan`, `validate --project` and `risk --project` then bind MCP and A2A configuration values with an HMAC under it; the key never enters the inventory. A shorter key is a usage error before any collector runs. See [verification source binding](verification-source-binding.md). |
| `NEXUS_SYMBIOTE_LIMITS` | Raised collection limits for this invocation, as `NAME=VALUE` pairs separated by commas; the CLI validates the names and values. It is read from the environment of the operator, never from a scanned checkout. The GitHub Action sets it only from its `limits` input. |
| `NO_COLOR` | Any value turns colors off. |
| `XDG_CACHE_HOME`, `HOME` | Where sigstore-python caches the trusted root that offline Sigstore verification uses; see [SECURITY.md](../SECURITY.md#known-limitations-in-010). |
| `TMPDIR` | Where `verify-live` stages the private copy of a pinned launcher. |
| `_NEXUS_SYMBIOTE_COMPLETE` | Ignored. Shell completion is not offered, because an inherited completion variable would make every command, gates included, exit 0 without running. |

## File formats

### Signer policy

`--signature-policy` (`scan`, `validate`, `risk`) and the Action's
`signature-policy` input take a strict JSON file, at most 4 MiB and 1,000 artifacts,
written by the operator, never by the checkout:

```json
{
  "version": 1,
  "artifacts": [
    {
      "artifact_path": "models/classifier.safetensors",
      "bundle_path": "models/classifier.safetensors.sigstore",
      "expected_identity": "https://github.com/acme/models/.github/workflows/release.yml@refs/tags/v1.0.0",
      "expected_issuer": "https://token.actions.githubusercontent.com"
    }
  ]
}
```

Both paths are relative to the project. Every record needs exactly these four fields;
unknown fields, duplicate keys or artifacts, symbolic links and missing files are
refused.

### Launch policy

`verify-live --launch-policy` takes a JSON object, outside the project, that maps each
MCP server's `bom_ref` to exactly a `command` and a `sha256`:

```json
{
  "mcp-server:146dd7ec16be91c2b267497bf940d8fa6b2d58909b7e2c15c0dd30d10c7a3a3c": {
    "command": "/opt/mcp/docs-server",
    "sha256": "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
  }
}
```

`command` is an absolute path to a standalone executable, and `sha256` is the SHA-256
of its bytes as `sha256:<64 lowercase hexadecimal characters>`. A server without an
entry is not started.

### JSON documents

| Command | Document |
|---|---|
| `validate --json-output` | `passed`; `assessment_basis` (`supplied-bom` or `project-reconciled`); `policy_source` and `policy_weakened`; `completeness` and `integrity`, each with a `status` (`pass`, `fail`, `unknown` for integrity, or `skipped` with `skipped_by`) and the validator's issues; `discovery_producer` (`null` unless the check applies); `minimum_assurance_level`, `assurance_errors` and `graph_issues`. |
| `risk --json-output` | `passed`; `overall_score` (`null` when `--project` reconciliation failed); `risk_level`; `coverage_status`; `gate_reasons`; `findings`; `severity_counts`; `category_scores`; `total_components` and `components_with_risks`; `assessment_basis` (`supplied-bom`, `project-reconciled` or `project-reconciliation-failed`); `score_threshold` (`null` with `--no-score-threshold`); `fail_on_severity`; `policy_source` and `policy_weakened`. A failed reconciliation has the same keys, with empty findings. |
| `diff --json-output` | `has_changes`, `total_changes`, `components_added`, `components_removed`, `components_modified`, `dependencies_added`, `dependencies_removed`, `security_alerts` and `metadata_changes`. |
| `summary --json-output` | `total_components`, `component_types`, `total_dependencies`, `total_risks`, `risk_breakdown` and the inventory's `completeness` claim. |
| `blast-radius --json-output` | `affected_agents` and `reachable_components`. |

## Pre-commit hooks

The repository ships two [pre-commit](https://pre-commit.com) hooks. Both run
`nexus-symbiote scan . --no-project-policy --check`: they collect the working tree and
apply the scan gate with the built-in policy, write nothing into the tree, and ignore
the checkout's `.nexus-symbiote.yaml`, so a change cannot relax the gate it is checked
under. `nexus-symbiote-risk` is kept as the same gate so that existing configurations
keep working; configure one of the two.

```yaml
repos:
  - repo: https://github.com/Hunzee-VC/Nexus-Symbiote
    rev: <reviewed-40-character-commit-sha>
    hooks:
      - id: nexus-symbiote-scan
```

pre-commit installs a hook of `language: python` into its own environment with
`pip install`, which resolves the dependency ranges in `pyproject.toml` from PyPI
without hashes, unlike the hash-locked install the README describes. Pin `rev` to a
reviewed commit, and treat the hooks as a convenience for your own tree, not a control:
a failing hook can be skipped, and the GitHub Action or a protected CI job is the
gate.

## Command details

### `advisories`

Live: query OSV for exact PyPI/npm package URLs in the inventory.

```text
nexus-symbiote advisories [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Write the advisory report to this file instead of standard output. |

### `baseline`

Stage a static snapshot for review; publish it only after the scan gate passes.

```text
nexus-symbiote baseline [OPTIONS] [PROJECT_PATH]
```

| Option | Description |
|---|---|
| `-o`, `--baseline-path` `PATH` | Where to write the unsigned baseline (default: .nexus-symbiote-baseline.json, in the working directory, not the project). |

The snapshot must also pass the built-in gate: a project policy cannot relax it.
When it does not, `baseline` prints each reason and the findings that tripped the gate.

### `blast-radius`

Show repository dependencies potentially affected by a component compromise.

```text
nexus-symbiote blast-radius [OPTIONS] AIBOM_PATH COMPONENT_REF
```

| Option | Description |
|---|---|
| `--json-output` | Output as JSON |

### `diff`

Compare two AIBOM snapshots for supply-chain drift.

```text
nexus-symbiote diff [OPTIONS] OLD_PATH NEW_PATH
```

| Option | Description |
|---|---|
| `--json-output` | Output as JSON |
| `--fail-on-alert` | Exit with status 1 if the diff reports a security alert. |

The report lists security alerts, notes, and added, removed and modified components,
and added and removed relationships with their conditions.

### `discover-mcp`

Live: observe tools/list without executing tools or starting local servers.

```text
nexus-symbiote discover-mcp [OPTIONS] ENDPOINT
```

| Option | Description |
|---|---|
| `--allowed-origin` `TEXT` | Exact HTTPS origin explicitly approved by the operator (required, repeatable) |
| `--token-env` `TEXT` | Environment variable holding a bearer token; the token is never written to evidence |
| `-o`, `--output` `PATH` | Write the observation to this file instead of standard output. |

### `import-shadowscan`

Import a Nexus-ShadowScan report and generate an AIBOM of imported claims.

```text
nexus-symbiote import-shadowscan [OPTIONS] REPORT_PATH
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Output AIBOM path (required) |
| `-f`, `--format` `json\|cyclonedx\|spdx\|sarif` | Output format (default: json). sarif is refused: it cannot carry imported coverage. |
| `--report-only` | Emit imported claims without a CI gate failure |

### `init`

Initialize a .nexus-symbiote.yaml policy configuration.

```text
nexus-symbiote init [OPTIONS]
```

| Option | Description |
|---|---|
| `--force` | Overwrite existing .nexus-symbiote.yaml |
| `--path` `PATH` | Directory to create .nexus-symbiote.yaml in |

### `risk`

Score supply-chain risks in an AIBOM.

```text
nexus-symbiote risk [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `--threshold` `FLOAT` | Fail when the aggregate score reaches this positive value (default: from policy, built-in 50). |
| `--no-score-threshold` | Do not gate on the aggregate score. Findings at or above `--fail-on-severity`, unverified SafeTensors, incomplete coverage and missing evidence still fail the gate. Cannot be combined with `--threshold`. |
| `--json-output` | Output as JSON |
| `--project` `DIRECTORY` | Reconcile the supplied BOM against this project's static evidence before scoring; a failed reconciliation reports an unknown risk level and a null score. The only source of a project policy: without it the built-in policy applies |
| `--signature-policy` `FILE` | Explicit operator signer policy for model recollection; requires --project |
| `--fail-on-severity` `critical\|high\|medium\|low\|info\|none` | Fail on any finding at or above this severity (default: from policy, built-in critical); none disables it. |
| `--no-project-policy` | Use built-in policy without reading configuration from the target. |

The report gives the score, the assessment basis, coverage, the severity counts and
the top 15 findings (`--json-output` lists all). Under `Gate: PASSED` or
`Gate: FAILED` it names each reason, such as `finding at or above critical` or
`collection coverage is unknown or incomplete`, the findings that tripped the
severity cutoff, and the score with the threshold it was compared with.

### `runtime keygen`

Create an Ed25519 key pair without overwriting existing files.

```text
nexus-symbiote runtime keygen [OPTIONS]
```

| Option | Description |
|---|---|
| `--private-key` `PATH` | New PEM private key file, created with mode 0600; must not exist. (required) |
| `--public-key` `PATH` | New PEM public key file, created with mode 0600; must not exist. (required) |

### `runtime sign`

Sign an explicit contract; signatures do not establish unmeasured facts.

```text
nexus-symbiote runtime sign [OPTIONS] CONTRACT_PATH
```

| Option | Description |
|---|---|
| `--kind` `snapshot\|approval\|trust\|model` | Contract purpose; a signature is valid only for this purpose. (required) |
| `--key` `PATH` | Ed25519 private key PEM; repeat for multiple signers. (required, repeatable) |
| `--out` `PATH` | Signed envelope file to create; must not exist. (required) |

### `runtime verify`

Verify purpose, signer, subject and time; invocation uses ReferenceGateway.

```text
nexus-symbiote runtime verify [OPTIONS] ENVELOPE_PATH
```

| Option | Description |
|---|---|
| `--kind` `snapshot\|approval\|trust\|model` | Expected contract purpose; a contract signed for another purpose is rejected. (required) |
| `--public-key` `PATH` | Trusted Ed25519 public key PEM; repeat to build the trusted key ring. (required, repeatable) |
| `--threshold` `INTEGER RANGE` | Minimum number of distinct trusted signatures (default: 1). |
| `--bom` `PATH` | The exact companion BOM; required for snapshot contracts. |

### `scan`

Scan a project and generate an AIBOM.

```text
nexus-symbiote scan [OPTIONS] [PROJECT_PATH]
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Output file path (default: standard output) |
| `-f`, `--format` `json\|cyclonedx\|spdx\|sarif` | Output format (default: json, or from .nexus-symbiote.yaml) |
| `--scanner` `TEXT` | Collector to run, once each: mcp, model, prompt, rag, registry, a2a, ide_agents, shadowscan (default: all, or from .nexus-symbiote.yaml). A collector left out makes coverage partial. (repeatable) |
| `--report-only` | Emit findings and collection failures without a CI failure |
| `--check` | Collect and apply the scan gate without writing an inventory. Cannot be combined with `-o`. |
| `--signature-policy` `PATH` | Explicit operator signer policy JSON |
| `--no-project-policy` | Use built-in policy without reading configuration from the target. |

`PROJECT_PATH` is resolved before collection, because the collectors refuse a root
reached through a symbolic link. When it resolves through a link, `scan` names the
directory it collects; a relative path without `..` that a link leads outside the
working directory is refused, so a checkout cannot redirect `scan ./my-agent` to
another directory on the machine. `validate --project` and `risk --project` follow the
same rule.

`scan` prints each collector with the number of components it found and, unless
complete, its status. It ends with `Scan gate passed` or `Scan gate failed`, followed
by why: each gate reason, the findings at or above the severity cutoff, the score
and threshold, the collectors that were not run, and the first ten collection
failures and excluded surfaces, each with its collector. The inventory records them
all under `metadata.completeness`; `--check` and `baseline` keep no inventory, so
their gate says to run `scan -o FILE` to see the rest. An export that fails its
schema or consistency checks ends the command with an error that names the format;
rerun with `--debug` for details.

### `summary`

Print a summary of an AIBOM.

```text
nexus-symbiote summary [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `--json-output` | Print the summary as JSON. |

### `validate`

Validate an AIBOM for completeness and integrity.

```text
nexus-symbiote validate [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `--project` `DIRECTORY` | Project root for cross-validation. The only source of a project policy: without it the built-in policy applies |
| `--signature-policy` `PATH` | Explicit operator signer policy JSON; requires --project |
| `--no-project-policy` | Use built-in policy without reading configuration from the target. |
| `--skip-integrity` | Check completeness only and report integrity as skipped, for a repository whose models cannot be signed yet. The skip is printed and recorded in `--json-output`. |
| `--json-output` | Print the validation report as JSON. |

Every report states its assessment basis. Without `--project` it is `supplied-bom`:
only the inventory's own claims were checked, its coverage claim and its internal
consistency, and nothing was compared with a project, so a hand-written inventory
can pass. With `--project` it is `project-reconciled`: the inventory was compared
with a fresh local collection of that project. Integrity is `PASS`, `FAIL` or
`UNKNOWN`; unknown fails the check, and when no issue explains it the report says
that no hash or signature could be verified. The report ends with
`Validation: PASSED` or `Validation: FAILED`.

### `verify-artifact`

Verify a local artifact's digest and optionally its Sigstore bundle.

```text
nexus-symbiote verify-artifact [OPTIONS] ARTIFACT_PATH
```

| Option | Description |
|---|---|
| `--project` `DIRECTORY` | Trusted project root; ARTIFACT_PATH is relative to it, not to the working directory (required) |
| `--sha256` `TEXT` | Expected sha256:<hex> from a trusted source (required) |
| `--bundle` `FILE` | Optional Sigstore bundle |
| `--signer-identity` `TEXT` | Expected Sigstore signing identity |
| `--issuer` `TEXT` | Expected Sigstore OIDC issuer |

A malformed `--sha256`, or a `--bundle`, `--signer-identity` and `--issuer` set that
is incomplete, is a usage error (exit 2).

### `verify-discovery`

Verify source bytes and optionally their native projection and producer.

```text
nexus-symbiote verify-discovery [OPTIONS] AIBOM_PATH REPORT_PATH
```

| Option | Description |
|---|---|
| `--projection` | Rebuild and compare the direct native import. |
| `--bundle` `FILE` | Verify the report producer's Sigstore bundle and the direct native projection. |
| `--signer-identity` `TEXT` | Expected report signer from operator policy. |
| `--issuer` `TEXT` | Expected OIDC issuer from operator policy. |

### `verify-live`

Live: observe independently pinned stdio launchers; optionally emit an unsigned candidate.

```text
nexus-symbiote verify-live [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `--project` `PATH` | Untrusted project root (default: current directory); the launch policy must be outside it. |
| `--launch-policy` `FILE` | Operator-owned JSON outside the project: exact server references to absolute commands and SHA-256 pins; see [launch policy](#launch-policy). (required) |
| `--json-output` | Output the verification report as JSON. |
| `--record` | Print an unsigned candidate BOM with the observed descriptors instead of a report. |

### `vex`

Export schema-validated findings in triage, without asserting exploitability.

```text
nexus-symbiote vex [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Write the VEX document to this file instead of standard output. |
