# CLI reference

Every `nexus-symbiote` command and option. `nexus-symbiote --help` and
`nexus-symbiote <command> --help` describe the version you installed and are
authoritative where this page differs; `tests/test_cli_reference.py` fails when a
command or option is missing here.

```text
nexus-symbiote [--offline | --live] [--version] [--help] COMMAND [ARGS]...
```

## Global options

| Option | Description |
|---|---|
| `--offline` | Refuse name resolution, network connections and process creation (the default). |
| `--live` | Allow the network and process steps of `discover-mcp`, `advisories` and `verify-live`. Every other command stays offline. |
| `--version` | Print the version and exit. |
| `--help` | Print help and exit. |

Every `-o`/`--output` file, and the policy file `init --path` creates, is written
atomically and never through a symbolic link:
its directory must already exist, and no directory on the path may be a symbolic
link (on macOS, write under `/private/tmp` rather than `/tmp`). `..` steps to the
real parent directory, as the operating system resolves it. A refused path ends the
command with an error and writes nothing; any other failure, such as a permission
error, is reported by the operating system's message, without the path.

Mode flags go before the command. Without a flag, `NEXUS_SYMBIOTE_MODE=offline|live`
selects the mode; without either, the mode is offline. See
[offline and live modes](offline-and-live-modes.md).

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

## Exit codes

| Exit | Meaning |
|---|---|
| `0` | The command completed and every requested gate passed. |
| `1` | A gate or check failed (risk gate, integrity, digest or signature mismatch, `diff --fail-on-alert`, incomplete collection or observation), the input could not be read or parsed, or `import-shadowscan` ran without `--report-only`. |
| `2` | Usage error: an unknown command or option, a missing argument or file, an invalid value, an invalid `NEXUS_SYMBIOTE_MODE`, or a live command run without live mode. |

`--report-only` on `scan` and `import-shadowscan` reports collection failures and
findings without turning them into exit status 1. It is for exploration, not
approval.

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
| `--exclude-private-origins` | Send only packages whose lockfile resolution records the public PyPI or npm registry. pip requirements record no index, so pip packages are withheld; withhold private names with `--exclude` instead to keep public ones checked. |
| `--dry-run` | List the package identities that would be sent, without contacting OSV (works offline). |

The command sends each package's ecosystem, normalized name and exact version to
`https://api.osv.dev/v1/querybatch`, including packages resolved from a private
registry unless you exclude them. The registry collector labels every pip package
with the public PyPI origin because requirements files name no index, so only
`--exclude` (previewed with `--dry-run`) keeps a private pip package name local
while public ones are still checked. It exits 1 when an advisory is found, or when
not every package in scope was looked up (`coverage` is `partial` or `none`,
including an inventory with no exact PyPI or npm package). A report keeps at most
10,000 advisories per package and 20,000 in total; beyond that, lookups end with an
error and `coverage` is `partial`.

### `baseline`

Stage a static snapshot for review; publish it only after the scan gate passes.

```text
nexus-symbiote baseline [OPTIONS] [PROJECT_PATH]
```

| Option | Description |
|---|---|
| `-o`, `--baseline-path` `PATH` | Where to write the unsigned baseline (default: .nexus-symbiote-baseline.json). |

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
| `--raw-descriptors` `PATH` | Also write the unredacted served instructions, tool descriptors, prompts and resource templates to this new file (mode 0600) for review; only the bearer token and session ID are masked. |

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
| `--threshold` `FLOAT` | Fail threshold score |
| `--json-output` | Output as JSON |
| `--project` `PATH` | Reconcile the supplied BOM against this project's static evidence before scoring; a failed reconciliation reports an unknown risk level and a null score. The only source of a project policy: without it the built-in policy applies |
| `--signature-policy` `PATH` | Explicit operator signer policy for model recollection; requires --project |
| `--fail-on-severity` `critical\|high\|medium\|low\|info\|none` | Fail on any finding at or above this severity (default: from policy, built-in critical); none disables it. |
| `--no-project-policy` | Use built-in policy without reading configuration from the target. |

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
| `-o`, `--output` `PATH` | Output file path |
| `-f`, `--format` `json\|cyclonedx\|spdx\|sarif` | Output format (default: json, or from .nexus-symbiote.yaml) |
| `--scanner` `TEXT` | Specific scanners to run (default: all, or from .nexus-symbiote.yaml) (repeatable) |
| `--report-only` | Emit findings and collection failures without a CI failure |
| `--signature-policy` `PATH` | Explicit operator signer policy JSON |
| `--no-project-policy` | Use built-in policy without reading configuration from the target. |

### `summary`

Print a summary of an AIBOM.

```text
nexus-symbiote summary [OPTIONS] AIBOM_PATH
```

### `validate`

Validate an AIBOM for completeness and integrity.

```text
nexus-symbiote validate [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `--project` `PATH` | Project root for cross-validation. The only source of a project policy: without it the built-in policy applies |
| `--signature-policy` `PATH` | Explicit operator signer policy JSON; requires --project |
| `--no-project-policy` | Use built-in policy without reading configuration from the target. |

### `verify-artifact`

Verify a local artifact's digest and optionally its Sigstore bundle.

```text
nexus-symbiote verify-artifact [OPTIONS] ARTIFACT_PATH
```

| Option | Description |
|---|---|
| `--project` `DIRECTORY` | Trusted project root (required) |
| `--sha256` `TEXT` | Expected sha256:<hex> from a trusted source (required) |
| `--bundle` `FILE` | Optional Sigstore bundle |
| `--signer-identity` `TEXT` | Expected Sigstore signing identity |
| `--issuer` `TEXT` | Expected Sigstore OIDC issuer |

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
| `--project` `DIRECTORY` | Untrusted project root (required); the launch policy must be outside it and outside the repository that holds the project or the inventory. |
| `--launch-policy` `FILE` | Operator-owned JSON outside the project: exact server references to absolute commands and SHA-256 pins. (required) |
| `--json-output` | Output the verification report as JSON. |
| `--record` | Print an unsigned candidate BOM with the observed descriptors instead of a report; exits 1 when served tools or declarations drifted, unless `--accept-drift`. |
| `--accept-drift` | With `--record`, exit 0 although changed or new tools or declarations were recorded. |

Servers reached over HTTP are reported as not verifiable by `verify-live` (reason
`remote-transport`) and do not make the run incomplete; observe them with
`discover-mcp --record` and compare the inventories with `diff`. The launch policy is a
JSON object that maps each stdio server's `bom_ref` in the inventory to exactly
`{"command": "/absolute/path", "sha256": "sha256:<64 hex>"}`.

### `vex`

Export schema-validated findings in triage, without asserting exploitability.

```text
nexus-symbiote vex [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Write the VEX document to this file instead of standard output. |
