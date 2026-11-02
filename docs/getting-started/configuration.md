# Configuration

Nexus SymBiote reads one optional policy file, `.nexus-symbiote.yaml`, and, for signature
verification, an operator-supplied signature policy JSON passed explicitly on the command
line. Both are defined in `src/nexus_symbiote/policy.py` and
`src/nexus_symbiote/signature_policy.py`. Treat the policy file as security-relevant
configuration: it can narrow collection and relax gates, and it is read from the scanned
checkout by default.

## Creating a policy file

`nexus-symbiote init` writes the built-in template to `.nexus-symbiote.yaml` in the current
directory. It refuses to overwrite an existing file unless `--force` is given, and `--path`
selects another directory:

```console
$ nexus-symbiote init
Created /path/to/agent-project/.nexus-symbiote.yaml
  Edit this file to customize scan, risk, and validation policies.
$ nexus-symbiote init
Warning: /path/to/agent-project/.nexus-symbiote.yaml already exists. Use --force to overwrite.
```

The second call exits 1. The template contains every supported key with its default:

```yaml
# Nexus SymBiote policy; malformed or unsupported settings fail closed.
version: "1.0"
scan:
  scanners: ["mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"]
  exclude_paths: ["node_modules", ".git", "__pycache__", ".venv"]
  failure_mode: "error"
risk:
  fail_threshold: 50.0
  warn_threshold: 25.0
  fail_on_severity: "critical"
  ignore_categories: []
validate:
  require_completeness: true
  require_integrity: true
  minimum_assurance_level: "declared"
output:
  default_format: "json"
```

## How the file is found and parsed

The search starts at a command-specific directory and walks up through parent directories
to the filesystem root. The first `.nexus-symbiote.yaml` or `.nexus-symbiote.yml` found is
used, so a policy in a parent directory applies to nested projects. With no file anywhere on
that path, the built-in defaults apply.

| Command | Search starts at |
| --- | --- |
| `scan` | The project directory being scanned. |
| `validate` | The `--project` directory when given, otherwise the inventory file's directory. |
| `risk` | The inventory file's directory. |
| `import-shadowscan` | The report file's directory. |
| `baseline` | The project directory (through `scan`). |

Parsing fails closed. The command stops with `Error: invalid policy <path>: ...` and exit
code 1 when the file is a symbolic link, is not a regular file, exceeds 1 MiB, is not a YAML
mapping with unique string keys, contains an unknown key, or holds a value of the wrong type
or outside its range. Values are checked strictly: `fail_threshold: 50` must be a number, and
a quoted `"true"` is not a boolean. The YAML loader is a `SafeLoader` subclass; tags that
construct objects are not supported.

## Keys

Every key the code reads, with its default and effect. Unknown keys anywhere are rejected.

### `version`

| Key | Default | Effect |
| --- | --- | --- |
| `version` | `"1.0"` | Must be the string `"1.0"`. |

### `scan`

| Key | Default | Effect |
| --- | --- | --- |
| `scanners` | all eight names | The collectors `scan` runs when `--scanner` is not given. Names must be unique and drawn from `mcp`, `model`, `prompt`, `rag`, `registry`, `shadowscan`, `a2a`, `ide_agents`; at least one is required. Collectors that are not run are recorded as `unknown` in `scanner_status`, which keeps coverage partial. |
| `exclude_paths` | `["node_modules", ".git", "__pycache__", ".venv"]` | Relative paths beneath the scan root that collectors skip. Entries must be nonempty, relative and free of `..`. The collector additionally always skips directories named `.git`, `node_modules`, `__pycache__`, `.venv` and `venv`. Skipped paths are recorded in `surfaces_excluded` only when a collector encounters them. |
| `failure_mode` | `"error"` | `"report-only"` makes `scan` and `import-shadowscan` exit 0 even when collection failures or the risk gate would otherwise exit 1, exactly as the `--report-only` flag does. The inventory records the same failures either way. |

### `risk`

| Key | Default | Effect |
| --- | --- | --- |
| `fail_threshold` | `50.0` | Aggregate score at or above which the gate fails. Must be greater than 0. `risk --threshold` overrides it. |
| `warn_threshold` | `25.0` | Aggregate score at or above which `scan` prints `Risk warning: score ...` and the risk report sets `warning_threshold_exceeded`. Must be at least 0 and no greater than `fail_threshold`. |
| `fail_on_severity` | `"critical"` | The gate fails when any finding is at or above this severity: `critical`, `high`, `medium`, `low`, `info`, or `none` to disable this reason. `risk --fail-on-severity` overrides it. |
| `ignore_categories` | `[]` | Exact finding category names (for example `transport_security`) that the scorer drops. Ignored findings are counted in `ignored_findings` and contribute nothing to the score. |

The thresholds, severity cutoff and ignored categories are used by `scan`, `risk`,
`import-shadowscan` and `baseline`. See [risk scoring](../concepts/risk-scoring.md) for how
the gate combines them with coverage.

### `validate`

| Key | Default | Effect |
| --- | --- | --- |
| `require_completeness` | `true` | Run the completeness validator. `false` prints `SKIPPED by explicit policy` and does not contribute a failure. |
| `require_integrity` | `true` | Run the integrity validator. `false` prints `SKIPPED by explicit policy`. |
| `minimum_assurance_level` | `"declared"` | `"observed"` additionally fails validation unless the inventory has a completeness claim, every component has `assurance_level` of at least `observed`, and every component carries claim provenance. `"verified"` makes `validate` stop with an error: offline validation cannot establish verified assurance. |

Graph integrity (dangling or wrongly typed references) is always checked by `validate` and
cannot be disabled by policy.

### `output`

| Key | Default | Effect |
| --- | --- | --- |
| `default_format` | `"json"` | The `scan` output format when `-f` is not given: `json`, `cyclonedx`, `spdx` or `sarif`. |

## `--no-project-policy`

`scan`, `validate` and `risk` accept `--no-project-policy`, which uses the built-in defaults
and never opens a policy file. Use it whenever the checkout is untrusted: a policy file in a
hostile repository can select `failure_mode: report-only`, restrict `scanners`, exclude paths,
ignore finding categories or disable both validators, and an invalid file otherwise stops the
command. The [GitHub Action](../reference/github-action.md) passes `--no-project-policy` to
every command it runs and takes its settings from the workflow inputs instead. Standalone CLI
calls read the project policy by default.

```bash
nexus-symbiote scan /path/to/untrusted-checkout --no-project-policy --report-only -o agentbom.json
nexus-symbiote validate agentbom.json --project /path/to/untrusted-checkout --no-project-policy
nexus-symbiote risk agentbom.json --no-project-policy --threshold 50
```

## Signature policy JSON

Signature verification of model artifacts never trusts a BOM field or an adjacent signature
file. It requires a policy that the operator selects explicitly with
`scan --signature-policy FILE` or `validate --signature-policy FILE --project DIR`, and the
`sigstore` extra. The file may live outside the project, but every artifact and bundle it
names must be a regular file beneath the project root:

```json
{
  "version": 1,
  "artifacts": [
    {
      "artifact_path": "models/tiny/model.safetensors",
      "bundle_path": "models/tiny/model.safetensors.sigstore",
      "expected_identity": "release@example.test",
      "expected_issuer": "https://issuer.example.test"
    }
  ]
}
```

Loading fails closed when the document has keys other than `version` and `artifacts`,
`version` is not the integer `1`, `artifacts` is empty or longer than 1,000 entries, an entry
does not have exactly those four string fields, a path is absolute, contains `..`, a
backslash, a drive letter or `://`, an artifact path repeats, the issuer is not an HTTPS URL
without credentials, query or fragment, or a referenced file is missing, a symbolic link, or
over the size limits (5 GiB for an artifact, 4 MiB for a bundle). The policy file itself is
limited to 4 MiB of strict JSON.

A loaded policy authorizes one verification per artifact. The model scanner records
`signing_status: sigstore-signed` and the signer identity only when the bundle verifies for
that exact identity and issuer and the signed digest equals the artifact's SHA-256; otherwise
it records `verification-failed`. Without a policy entry, an artifact is recorded as
`signature-present-unverified` when a signature-named file sits beside it, or
`signature-not-found`. The integrity validator treats a model without a policy entry as
unknown, which does not pass. A verified signature establishes who signed which bytes; it does
not establish that the model is safe.

## Environment variables

| Variable | Read by | Effect |
| --- | --- | --- |
| `NEXUS_SYMBIOTE_MODE` | every command | `offline` or `live`; any other value, including an empty one, is a usage error (exit 1). `--offline` and `--live` before the command take precedence. Unset means offline. See [offline and live modes](../operations/offline-and-live-modes.md). |
| The name given to `discover-mcp --token-env` | `discover-mcp` in live mode | A bearer token for the explicit HTTPS observation. It is sent in the `Authorization` header and redacted from the evidence; the command stops when the named variable is empty. |

The policy file has no mode key, and no key of it can enable network access or process
execution: the file is read from the checkout being inventoried, which may be untrusted.

The GitHub Action passes its inputs to `scripts/run_action.py` through `SYMBIOTE_*`
environment variables that `action.yml` sets; those are an implementation detail of the
Action, described in the [GitHub Action reference](../reference/github-action.md).

Human-readable progress and reports are printed through Rich, which honors the `COLUMNS`
variable when deciding where to wrap lines in non-interactive output such as CI logs.
