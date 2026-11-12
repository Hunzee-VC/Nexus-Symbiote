# CLI reference

Every `nexus-symbiote` command and option. `nexus-symbiote --help` and
`nexus-symbiote <command> --help` describe the version you installed and are
authoritative where this page differs; `tests/test_cli_reference.py` fails when a
command, option or environment variable is missing here.

```text
nexus-symbiote [--offline | --live] [--debug] [--limit NAME=VALUE]... [--version] [--help] COMMAND [ARGS]...
```

## Global options

| Option | Description |
|---|---|
| `--offline` | Refuse name resolution, network connections and process creation (the default). |
| `--live` | Allow the network and process steps of `discover-mcp`, `advisories` and `verify-live`. Every other command stays offline. |
| `--debug` | Print where a collector or internal error was raised on standard error: its class and the files, lines and functions of its traceback, without its message, which can quote project or inventory text. Without it, an unexpected error ends the command with `Error: internal error (<error class>)` and exit status 1, and a collector error is recorded by its diagnostic code only. |
| `--limit` `NAME=VALUE` | Set one [collection limit](collection-limits.md) for this command, such as `entries=200000` or `model-bytes=128GiB`. Repeatable; overrides `NEXUS_SYMBIOTE_LIMITS` for that name. |
| `--version` | Print the version and exit. |
| `--help` | Print help and exit. |

Every `-o`/`--output` file, and the policy file `init --path` creates, is written
atomically and never through a symbolic link:
its directory must already exist, and no directory on the path may be a symbolic
link (the standard macOS root links `/tmp`, `/var` and `/etc` to `/private` are
the only exception). `..` steps to the
real parent directory, as the operating system resolves it. A refused path ends the
command with an error and writes nothing; any other failure, such as a permission
error, is reported by the operating system's message, without the path.

Every AgentBOM a command reads is opened the same way: neither the file nor any
directory on its path may be a symbolic link (with the same macOS exception), and
FIFOs, devices, directories and `/dev/stdin` are refused. The
error names the reason. Native inventories are limited to 16 MiB for reading and
writing alike.

Mode flags and `--debug` go before the command. Without a flag,
`NEXUS_SYMBIOTE_MODE=offline|live` selects the mode; without either, the mode is
offline. See [offline and live modes](offline-and-live-modes.md).

`--limit` also goes before the command. `NEXUS_SYMBIOTE_LIMITS=NAME=VALUE,NAME=VALUE`
sets limits from the environment, and `--limit` wins for the names it sets. Limits
apply to every command that collects from a project; a project's own files never
change them. See [collection limits](collection-limits.md).

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
| [`verify-discovery`](#verify-discovery) | offline | Check that a ShadowScan report's bytes match the digest a BOM records; with `--projection` or `--bundle`, also compare the BOM's imported components with the report |
| [`init`](#init) | offline | Create a `.nexus-symbiote.yaml` policy file |
| [`runtime keygen`](#runtime-keygen) | offline | Create an Ed25519 key pair for runtime contracts |
| [`runtime sign`](#runtime-sign) | offline | Sign a runtime contract |
| [`runtime verify`](#runtime-verify) | offline | Verify a signed runtime contract's purpose, signers and validity window |
| [`runtime digest`](#runtime-digest) | offline | Print the digest a runtime contract, approval or revocation list binds |
| [`runtime key-id`](#runtime-key-id) | offline | Print the key ID of an Ed25519 public key |
| [`runtime register`](#runtime-register) | offline | Make a newly issued runtime snapshot current in a gateway state store |
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

Every command prints text taken from an inventory, a checkout or a live server, such as
names, paths, references and descriptions, literally and inert, in a terminal and in a
CI log:

- control, format and line-break characters are replaced with U+FFFD, so such text
  cannot move the cursor, rewrite earlier output or start a new line;
- a `##` that would introduce a CI log command anywhere in a line (GitHub Actions'
  legacy `##[command]`, Azure Pipelines' `##vso[`, TeamCity's `##teamcity[`) is
  followed by U+FFFD;
- no such text starts an output line: every line opens with fixed text, so a name
  cannot become a `::command::` workflow command;
- nothing is read as markup or emoji codes, and lines are never wrapped.

The JSON that `scan`, `vex`, `discover-mcp` and `advisories` print without `-o`, the
JSON that every `runtime` command prints, such as the identities of the snapshot that
`runtime register` made current, the candidate inventory that `verify-live --record`
prints, and the `--json-output`
documents of `validate`, `risk`, `diff`, `summary`, `blast-radius` and `verify-live`,
write a `[` that follows such a `##` as `\u005b`; the document parses to exactly the
same value. Files written with `-o` are not changed.

Colors are used only on a terminal, and `NO_COLOR` turns them off.

## Exit codes

| Exit | Meaning |
|---|---|
| `0` | The command completed and every requested gate passed. |
| `1` | A gate or check failed (risk gate, integrity, digest or signature mismatch, `diff --fail-on-alert`, incomplete collection or observation), the input could not be read or parsed, `import-shadowscan` ran without `--report-only`, or an unexpected internal error occurred. |
| `2` | Usage error: an unknown command or option, a missing argument or file, a `PROJECT_PATH` of `scan` or `baseline` or a `--project` of `validate`, `risk`, `verify-artifact` or `verify-live` that is a file, a `verify-live` launch policy kept where the [launch policy](#launch-policy) rules forbid, an invalid value (including a malformed `verify-artifact --sha256` and an incomplete `--bundle`, `--signer-identity` and `--issuer` set), a relative project path that a symbolic link leads outside the working directory, an invalid `NEXUS_SYMBIOTE_MODE` or collection limit, a `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` shorter than 32 characters, or a live command run without live mode (`advisories --dry-run` contacts nothing and runs in either mode). |

What exit status 1 means for each gate:

| Command | Exits 1 when |
|---|---|
| `scan` | A collector failed or the scan gate failed, unless `--report-only` or a report-only project policy applies. |
| `validate` | Completeness, integrity (including integrity that is only unknown), the discovery producer check, the minimum assurance level or the dependency graph failed. |
| `risk` | The risk gate failed, or `--project` reconciliation failed. |
| `diff` | `--fail-on-alert` was given and the diff reports a security alert. |
| `baseline` | The scan gate failed, under the project policy or the built-in one. |
| `verify-artifact`, `verify-discovery` | The digest, signature or projection does not match. |
| `verify-live` | A stdio server could not be observed completely (a run with no stdio server observes nothing), or a server's served tools, declarations or identity differ from the inventory; with `--record`, such drift fails unless `--accept-drift` is given. |
| `discover-mcp` | The observation is incomplete; with `--record`, nothing is written. |
| `advisories` | An advisory was found (unless `--no-fail-on-advisory`), or not every package in scope was looked up (`coverage` is `partial` or `none`); with `--dry-run`, only when the report lists an error. |

`--report-only` on `scan` and `import-shadowscan` reports collection failures and
findings without turning them into exit status 1, as a project policy with
`failure_mode: report-only` does for `scan`. It is for exploration, not approval:
`baseline` applies the built-in gate whatever the project policy says.

## Environment variables

| Variable | Effect |
|---|---|
| `NEXUS_SYMBIOTE_MODE` | `offline` or `live`; selects the mode when no mode flag is given. Any other value is a usage error. |
| `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` | An operator secret of at least 32 characters. `scan`, `validate --project` and `risk --project` then bind MCP, A2A, RAG and IDE settings values with an HMAC under it; the key never enters the inventory. A shorter key is a usage error before any collector runs. See [verification source binding](verification-source-binding.md). |
| `NEXUS_SYMBIOTE_LIMITS` | Raised collection limits for this invocation, as `NAME=VALUE` pairs separated by commas; the CLI validates the names and values. It is read from the environment of the operator, never from a scanned checkout. The GitHub Action sets it only from its `limits` input. |
| `NO_COLOR` | Any value turns colors off. |
| `XDG_CACHE_HOME`, `HOME` | Where sigstore-python caches the trusted root that offline Sigstore verification uses; see [known limitations](known-limitations.md#signatures). |
| `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT` | An explicit Sigstore `trusted_root.json` file, or a directory holding one, for offline Sigstore verification. `--trust-root` overrides it. Without a pinned digest the file and its directory must be owned by the user and not writable by group or others. |
| `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256` | The SHA-256 the explicit trust root's bytes must match. `--trust-root-sha256` overrides it; set without a trust root, it is a usage error. |
| `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `TF_BUILD`, `JENKINS_URL`, `BUILDKITE`, `DRONE`, `TRAVIS` | Any value other than empty, `0` or `false` marks the run as automated: `import-shadowscan`, `validate` and `risk` then fail on unverified ShadowScan discovery evidence unless `--allow-unsigned-discovery` is given. |
| `TMPDIR` | Where `verify-live` stages the private copy of a pinned launcher. |
| `_NEXUS_SYMBIOTE_COMPLETE` | Ignored. Shell completion is not offered, because an inherited completion variable would make every command, gates included, exit 0 without running. |

## File formats

### Signer policy

`--signature-policy` (`scan`, `validate`, `risk`, `baseline`) and the Action's
`signature-policy` input take a strict JSON file, at most 4 MiB and 1,000 artifacts,
written by the operator, never by the checkout. A policy inside the scanned project,
also under another name for the project directory, or one with other hard links is
refused:

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

Both paths are relative to the project. In version 1 every record needs exactly these
four fields. Version 2 names a `kind` on every entry: `sigstore-message-signature`
takes these four fields and an optional `expected_sha256`, and `digest-pin` takes only
`artifact_path` and `expected_sha256`; see [model integrity](model-integrity.md#operator-signature-policy).
Unknown fields, duplicate keys or artifacts, symbolic links and missing files are
refused.

### Launch policy

`verify-live --launch-policy` takes a JSON object, outside the project, that maps each
stdio MCP server's `bom_ref` to exactly a `command` and a `sha256`:

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

The file must lie outside the project and outside the repository (the nearest
directory with a `.git` entry) that holds the project or the inventory. On POSIX
systems it must also be a single-link regular file owned by you or root that only its
owner can write, in a directory owned by you or root that others cannot write unless
it is sticky. A policy that breaks these rules is a usage error (exit 2). The checks
catch a misplaced policy; they do not authenticate it.

### JSON documents

| Command | Document |
|---|---|
| `validate --json-output` | `passed`; `assessment_basis` (`supplied-bom`, `project-reconciled`, `project-reconciled-with-supplier-claims` or `project-reconciliation-failed`); `policy_source` and `policy_weakened`; `completeness` and `integrity`, each with a `status` (`pass`, `fail`, `unknown` for integrity, or `skipped` with `skipped_by`) and the validator's report (its own `assessment_basis`, issues, `issues_omitted`; for completeness `supplier_claims` and `supplier_claims_omitted`; for integrity `bytes_charged`); `discovery_producer` (`null` without discovery evidence or a producer check, otherwise a `status` of `verified`, `failed`, `not-applicable` or `not-verified`, with `problems`); `minimum_assurance_level`, `assurance_errors` and `graph_issues`. |
| `risk --json-output` | `passed`; `overall_score` (`null` when `--project` reconciliation failed); `risk_level`; `coverage_status` and `coverage_gaps`; `gate_reasons`; `gate` (the effective thresholds, cutoff, ignored categories and suppression count, each with a `*_source` of `cli`, `project policy` or `built-in`); `findings`; `severity_counts`; `category_scores`; `ignored_findings`; `suppressed_findings`, `suppressions_expired` and `suppressions_unused`; `total_components` and `components_with_risks`; `warning_threshold_exceeded`; `assessment_basis` (`supplied-bom`, `project-reconciled`, `project-reconciled-with-supplier-claims` or `project-reconciliation-failed`); `supplier_claims` and `supplier_claims_omitted`; `discovery_producer` (`verified`, `failed`, `not-verified` or `not-applicable`); `score_threshold` (`null` with `--no-score-threshold`); `fail_on_severity`; `policy_source` and `policy_weakened`. A failed reconciliation has the same keys, with empty findings. |
| `diff --json-output` | `has_changes`, `total_changes`, `components_added`, `components_removed`, `components_modified`, `dependencies_added`, `dependencies_removed` (each with its `severity` and `conditions`), `security_alerts`, `metadata_changes` and `notes`. |
| `summary --json-output` | `total_components`, `component_types`, `total_dependencies`, `total_risks`, `risk_breakdown` and the inventory's `completeness` claim. |
| `blast-radius --json-output` | `subject`, `affected_agents`, `dependent_components`, `reachable_components`, `declared_principals`, `scope`, `effective_authority`, `linked` and `limitations`. |
| `discover-mcp` | The observation: `endpoint`, `protocol_version` and `requested_protocol_version`, `collector_id`, `collection_id`, `observed_at`, `completed_at`, `client_info`, `user_agent`, `session_established`, `session_digest`, `server_info`, `server_capabilities`, `instructions` and `instructions_hash`, `declaration_hash` and `identity_hash` with their profiles, `tools` (each with its redacted `descriptor`, `definition_hash`, `fingerprint` and `lints`), `prompts`, `resource_templates`, `failures`, `complete`, `pages_observed`, `bytes_observed` and `coverage`, which names what was not observed. With `--record`, a native AgentBOM instead. |
| `advisories` | `components_checked`, `components_skipped` and `components_excluded`, with the `skipped` and `excluded` entries and their reasons; `queries` (the ecosystem, name and version of each package in scope); `advisories`; `errors`; `coverage` (`complete`, `partial` or `none`) and `complete`; `dry_run`; `checked_at`, `tool_version` and `inventory_sha256`; `scope` and `sent_to_osv`. |
| `verify-live --json-output` | `complete`, `servers_checked`, `servers_reachable`, `servers_skipped`, `has_drift`, `inputs` (the SHA-256 of the inventory and of the launch policy) and `results`: per MCP server, `server`, `server_ref`, `status` (`verified`, `failed` or `not-verifiable`), `reachable`, `reason`, `error`, `transport`, `protocol_version`, `launcher_sha256`, `rug_pull_detected`, `live_schema_hash`, `declaration_hash` and `declaration_status`, `identity_hash` and `identity_status`, and `tools` (each tool's `name`, `definition_hash` and `status`: `match`, `changed`, `new` or `unverifiable`). |
| `runtime keygen` | `key_id` and `encrypted`. |
| `runtime sign` | `out`, `predicate`, `digest`, `signers` and `signed`. |
| `runtime verify` | `contract_verified`, `kind`, `digest`, `accepted_signers` and `invocation_authorized`, which is always `false`: only the gateway authorizes a call. |
| `runtime digest` | `kind` and `digest`. |
| `runtime key-id` | `key_id`. |
| `runtime register` | `registered`, `tenant`, `deployment_id`, `agent_id`, `serial` and `digest`. |

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
| `--fail-on-advisory` / `--no-fail-on-advisory` | Exit with status 1 when an advisory is found (default: fail). |
| `--exclude` `NAME` | Never send this package name to OSV; a trailing `*` matches a prefix (repeatable). |
| `--exclude-private-origins` | Send only packages whose lockfile resolution records the public PyPI or npm registry. Requirements files and `pyproject.toml` record no index, so Python packages that no `uv.lock` or `poetry.lock` resolves are withheld; withhold private names with `--exclude` instead to keep public ones checked. |
| `--dry-run` | List the package identities that would be sent, without contacting OSV (works offline). |

The command sends each package's ecosystem, normalized name and exact version to
`https://api.osv.dev/v1/querybatch`, including packages resolved from a private
registry unless you exclude them. Requirements files and `pyproject.toml` name no
index, so the registry collector labels a Python package that no `uv.lock` or
`poetry.lock` resolves with the public PyPI origin; for such a package only
`--exclude` (previewed with `--dry-run`) keeps a private name local while public
ones are still checked. It exits 1 when an advisory is found, or when
not every package in scope was looked up (`coverage` is `partial` or `none`,
including an inventory with no exact PyPI or npm package). With `--dry-run` it looks
nothing up, so `coverage` is `none`, and it exits 1 only when a package in scope has
no exact identity or more than 500 packages would be sent. A report keeps at most
10,000 advisories per package and 20,000 in total; beyond that, lookups end with an
error and `coverage` is `partial`.

### `baseline`

Stage a static snapshot for review; publish it only after the scan gate passes.

```text
nexus-symbiote baseline [OPTIONS] [PROJECT_PATH]
```

| Option | Description |
|---|---|
| `-o`, `--baseline-path` `PATH` | Where to write the unsigned baseline (default: .nexus-symbiote-baseline.json, in the working directory, not the project). |
| `--no-project-policy` | Use built-in policy without reading configuration from the target, as scan does. |
| `--signature-policy` `FILE` | Explicit operator signer policy JSON, kept outside the project, as for scan. |

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

The report lists security alerts, notes (`[INFO]` metadata changes, and `[NOTE]` lines
about the comparison itself, also after `No changes detected.`), and added, removed and
modified components, and added and removed relationships, each with its severity and
conditions.

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
| `--record` | Write a native AgentBOM inventory of a complete observation, for `diff`, instead of the observation report; an incomplete observation writes nothing. |
| `--server-ref` `TEXT` | Component reference of the observed server in the inventory (default: derived from the endpoint). |
| `--client-name` `TEXT` | `clientInfo` name sent in `initialize` (default: `nexus-symbiote-discovery`); use your production host's so the server cannot single out the observer. |
| `--client-version` `TEXT` | `clientInfo` version sent in `initialize` (default: the tool version). |
| `--user-agent` `TEXT` | `User-Agent` header to send; none is sent by default. |
| `--raw-descriptors` `PATH` | Also write the unredacted server info, capabilities, instructions, tool descriptors, prompts and resource templates to this new file (mode 0600) for review; only the bearer token and session ID are masked. |

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
| `--bundle` `FILE` | Verify the report producer's Sigstore bundle over the exact report bytes; requires `--signer-identity` and `--issuer`, and records the evidence as verified in the BOM |
| `--signer-identity` `TEXT` | Expected report signer, with `--bundle` and `--issuer` |
| `--issuer` `TEXT` | Expected OIDC issuer, with `--bundle` and `--signer-identity` |
| `--fail-on-unsigned-discovery` | Exit with status 1 when the imported discovery evidence is unverified |
| `--allow-unsigned-discovery` | Accept unverified discovery evidence explicitly (still warns); required in CI |

### `init`

Initialize a .nexus-symbiote.yaml policy configuration.

```text
nexus-symbiote init [OPTIONS]
```

| Option | Description |
|---|---|
| `--force` | Overwrite the existing project policy file (`.nexus-symbiote.yaml`, or `.nexus-symbiote.yml` when that is the only one); refused when both exist |
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
| `--require-discovery-signature` | Require the operator signature policy to verify any ShadowScan report the inventory records or the project contains, whatever the project policy says; requires --project. JSON output reports the result as `discovery_producer` |
| `--fail-on-unsigned-discovery` | Exit with status 1 when the BOM's ShadowScan evidence is unverified |
| `--allow-unsigned-discovery` | Accept unverified discovery evidence explicitly (still warns); required in CI |

The report gives the score, the assessment basis, coverage, the severity counts and
the top 15 findings (`--json-output` lists all). Under `Gate: PASSED` or
`Gate: FAILED` it lists, one `  - ` line each, every reason, such as
`finding at or above critical` or `collection coverage is unknown or incomplete`, the
findings that tripped the severity cutoff, the score with the threshold it was compared
with, the first 20 of the inventory's collection failures (and how many more
`metadata.completeness.scan_failures` holds), its other coverage gaps, and how many
findings the project policy suppressed. When unsigned ShadowScan evidence was accepted,
the report says `Discovery producer: not verified (unsigned evidence accepted)`.
### `runtime keygen`

Create an Ed25519 key pair without overwriting existing files.

```text
nexus-symbiote runtime keygen [OPTIONS]
```

| Option | Description |
|---|---|
| `--private-key` `PATH` | New PEM private key file, created with mode 0600; must not exist. (required) |
| `--public-key` `PATH` | New PEM public key file, created with mode 0600; must not exist. (required) |
| `--passphrase-file` `PATH` | Encrypt the private key with the passphrase on the first line of this file, which only its owner may read. |

Use one key pair per purpose: snapshot, approval and trust rings must not share keys.
A passphrase is at most 1,023 bytes, and a passphrase file that its group or others
can read is refused. If either file cannot be written, neither key is kept.

### `runtime sign`

Sign an explicit contract; signatures do not establish unmeasured facts.

```text
nexus-symbiote runtime sign [OPTIONS] CONTRACT_PATH
```

| Option | Description |
|---|---|
| `--kind` `snapshot\|approval\|trust\|model` | Contract purpose; a signature is valid only for this purpose. (required) |
| `--key` `PATH` | Ed25519 private key PEM with mode 0600; repeat for multiple signers. (required, repeatable) |
| `--out` `PATH` | Signed envelope file to create; must not exist. (required) |
| `--passphrase-file` `PATH` | Passphrase for encrypted private keys, on the first line of this file, which only its owner may read. |

A contract that could never verify, because its validity window is longer than its
purpose allows or has already ended, is refused. The output includes the contract
`digest` that approvals and revocation lists use.

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

Revocation, signer scopes, approver identities and an approval's bindings are
checked only by the gateway. A failure names its reason code, listed in the
[runtime contract reference](runtime-contract-reference.md#reason-codes).

### `runtime digest`

Print the canonical digest that contracts, approvals and revocations bind.

```text
nexus-symbiote runtime digest [OPTIONS] INPUT_PATH
```

| Option | Description |
|---|---|
| `--kind` `snapshot\|approval\|trust\|model\|context\|request\|tool\|bom` | What the file holds: an unsigned contract, an execution context, a tool call, a served tool descriptor or a companion BOM. (required) |

It verifies nothing and works for contracts that are not yet valid or expired.

### `runtime key-id`

Print the key ID that envelopes, key rings and revocation lists use.

```text
nexus-symbiote runtime key-id [OPTIONS] PUBLIC_KEY
```

### `runtime register`

Make a newly issued snapshot current; gateways sharing the store deny older serials.

```text
nexus-symbiote runtime register [OPTIONS] SNAPSHOT_PATH
```

| Option | Description |
|---|---|
| `--trust` `PATH` | Signed, currently valid trust status for the snapshot's tenant. (required) |
| `--state` `PATH` | Initialized state database that the gateways share. (required) |
| `--snapshot-key` `PATH` | Trusted snapshot-signing public key PEM; repeat to build the ring. (required, repeatable) |
| `--trust-key` `PATH` | Trusted trust-status public key PEM; repeat to build the ring. (required, repeatable) |
| `--approval-key` `PATH` | Approval public key PEM the gateways trust; repeat for each. Only checked, so the gateways' signer scope map can be passed unchanged. (repeatable) |
| `--snapshot-threshold` `INTEGER RANGE` | Minimum number of distinct snapshot signers (default: 1). |
| `--trust-threshold` `INTEGER RANGE` | Minimum number of distinct trust-status signers (default: 1). |
| `--signer-scopes` `PATH` | JSON object mapping key IDs to the signer scopes the gateways use. |
| `--allow-shared-keys` | Accept a key in more than one ring, as gateways built with `allow_shared_keys=True` do. |

The snapshot and trust status are checked as the gateway checks them, except the
workload context and the companion BOM, so pass the rings, quorums, signer scopes
and shared-key setting the gateways use. Pass the approval keys too when the scope
map covers them. A scope entry for a key in no ring, or a key in two rings without
`--allow-shared-keys`, fails with `configuration-invalid` and names the key ID. The
output names the tenant, deployment, agent, serial and contract `digest` that
became current.

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
by why, one `  - ` line each: every gate reason, the findings at or above the
severity cutoff, the score and threshold, the collectors that were not run, the first
20 collection failures and the first ten excluded surfaces, each with the collector
(or `agent.yaml`, or the `graph` check) that recorded it. The inventory records them
all under `metadata.completeness` (`scan_failures`, `surfaces_excluded`), and the gate
says how many more it holds; `--check` and `baseline` keep no inventory, so their gate
says to run `scan -o FILE` to see the rest. An export that fails its
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
| `--require-discovery-signature` | Require the operator signature policy to verify any ShadowScan report the inventory records or the project contains, whatever the project policy says; requires --project |
| `--fail-on-unsigned-discovery` | Exit with status 1 when the BOM's ShadowScan evidence is unverified |
| `--allow-unsigned-discovery` | Accept unverified discovery evidence explicitly (still warns); required in CI |

Every report states its assessment basis. Without `--project` it is `supplied-bom`:
only the inventory's own claims were checked, its coverage claim and its internal
consistency, and nothing was compared with a project, so a hand-written inventory
can pass. With `--project` the inventory was compared with a fresh local collection
of that project, and the basis is `project-reconciled`,
`project-reconciled-with-supplier-claims` (the inventory adds claims the collection
cannot confirm; each is listed as a `SUPPLIER-CLAIM` line) or
`project-reconciliation-failed`; `risk --project` uses the same values. The
completeness check also prints the completeness validator's own `Basis:`
(`supplied-claims` without `--project`). Integrity is `PASS`, `FAIL` or `UNKNOWN`;
unknown fails the check, and when no issue explains it the report says that no hash
or signature could be verified. When the inventory carries ShadowScan discovery
evidence that no producer check covered, the report says
`Discovery producer: not verified (unsigned evidence accepted)`. The report ends with
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
| `--trust-root` `FILE` | Explicit Sigstore trusted_root.json file (or directory holding one); overrides `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT` and the user cache |
| `--trust-root-sha256` `TEXT` | Pinned SHA-256 (sha256:\<hex\>) the explicit trust root must match |

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
| `--trust-root` `FILE` | Explicit Sigstore trusted_root.json file (or directory holding one); overrides `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT` and the user cache |
| `--trust-root-sha256` `TEXT` | Pinned SHA-256 (sha256:\<hex\>) the explicit trust root must match |

### `verify-live`

Live: observe independently pinned stdio launchers; optionally emit an unsigned candidate.

```text
nexus-symbiote verify-live [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `--project` `DIRECTORY` | Untrusted project root (required); the launch policy must be outside it and outside the repository that holds the project or the inventory. |
| `--launch-policy` `FILE` | Operator-owned JSON outside the project: exact server references to absolute commands and SHA-256 pins; see [launch policy](#launch-policy). (required) |
| `--json-output` | Output the verification report as JSON. |
| `--record` | Print an unsigned candidate BOM with the observed descriptors instead of a report; exits 1 when served tools, declarations or the server identity drifted, unless `--accept-drift`. |
| `--accept-drift` | With `--record`, exit 0 although changed or new tools, declarations or server identity were recorded. |

Servers whose transport is `sse`, `streamable-http` or `http` are reported as not
verifiable by `verify-live` (reason `remote-transport`) and do not make the run
incomplete; observe them with `discover-mcp --record` and compare the inventories
with `diff`. Any transport label other than these and `stdio`, such as the
`websocket` that the `mcp` collector records for a `ws://` or `wss://` endpoint, fails
with reason `unsupported-transport`. The [launch policy](#launch-policy) section gives the
policy's format and where it may be kept.

### `vex`

Export schema-validated findings in triage, without asserting exploitability.

```text
nexus-symbiote vex [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Write the VEX document to this file instead of standard output. |
