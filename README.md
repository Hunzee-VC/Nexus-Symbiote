# Nexus SymBiote

Nexus SymBiote is an alpha toolkit for creating and reviewing an Agent Bill of Materials. It inventories agent-related configuration and artifacts, records integrity and provenance evidence, exports standard BOM formats, and supports policy checks and snapshot comparisons.

**A successful scan is an inventory result.** It does not establish that a model is benign, that a tool backend obeys its description, or that every agent action was mediated. Read the [security model](docs/security-model.md) and [security policy](SECURITY.md) before using the results in an approval process.

## Install from reviewed source

The product is named Nexus SymBiote. Its distribution and command are `nexus-symbiote`; its Python import package is `nexus_symbiote`. Until a published release's ownership, source revision, and provenance have been verified, install from a reviewed checkout:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install .
nexus-symbiote --version
```

For optional signature integration, install `.[sigstore]` from the same checkout. See [CONTRIBUTING.md](CONTRIBUTING.md) for development dependencies and locked CI checks. Parallel experimental branches do not replace the `main` compatibility baseline.

## Discovery and verification workflow

[Nexus-ShadowScan](https://github.com/aisecnomad/Nexus-ShadowScan) is the primary multi-surface discovery engine. Run it separately with the permissions appropriate to the discovery surfaces. Nexus SymBiote consumes its native JSON or CycloneDX report, maps findings into an agent-native model, checks integrity and policy, and emits reviewable BOMs.

```bash
# Preferred input from a separate discovery run
nexus-symbiote import-shadowscan shadowscan-report.json -o agentbom.json --report-only

# Or place the report at .shadowscan/report.json and collect local evidence too
nexus-symbiote scan /path/to/agent-project -f json -o agentbom.json

# Export imported claims directly
nexus-symbiote import-shadowscan shadowscan-report.json -f cyclonedx -o agentbom.cdx.json --report-only
```

Imported discovery records retain the exact source-report SHA-256, source-reported status and unmapped finding indexes. Unknown kinds remain unmapped, and imported coverage stays partial. See [ShadowScan integration](docs/shadowscan-integration.md). Imported discovery records remain attributed claims. Importing them does not verify their publisher, observe the deployment again, establish effective authorization, or upgrade a supplied trust label. Local collectors complement discovery with file-level evidence. A command can write evidence while returning a failing policy status; inspect both the exit code and the inventory. `--report-only` is an explicit exploratory option, not successful approval.

## Collect and inspect

```bash
nexus-symbiote scan /path/to/agent-project -f json -o agentbom.json
nexus-symbiote validate agentbom.json --project /path/to/agent-project
nexus-symbiote risk agentbom.json --threshold 50
nexus-symbiote diff previous.json agentbom.json --json-output
nexus-symbiote summary agentbom.json
```

Collection is static by default: repository instructions, MCP configuration, local model references and files, retrieval configuration, and package manifests provide evidence of declared composition. A configuration entry does not prove that a server is running or that its live tool definitions match the declaration. Failed or inaccessible inputs must remain visible in coverage.

Additional review commands:

```bash
nexus-symbiote baseline /path/to/agent-project -o reviewed-baseline.json
nexus-symbiote vex agentbom.json -o findings.vex.json
nexus-symbiote advisories agentbom.json -o advisories.json
```

`baseline` publishes an unsigned snapshot only after collection and risk gates pass; review and authenticate it separately. VEX exports schema-validated inventory findings as `in_triage`, without asserting exploitability. `advisories` explicitly contacts OSV over constrained HTTPS for exact declared PyPI/npm package URLs; unresolved identities and lookup failures return a nonzero status. Unsupported ecosystems are counted as skipped. Manifest references do not prove which artifacts were installed.

SafeTensors fingerprints record header bytes and tensor names, dtypes, shapes and offsets. They describe metadata; changing weight bytes without changing the header leaves those metadata fingerprints unchanged. Whole-file digests remain required for weight-byte integrity. Collection and verification use bounded reads within the supplied root.

`verify-live` requires an independently provisioned launch policy outside the project. It starts only private copies of explicitly pinned standalone POSIX launchers, without project arguments, environment or working directory. For example:

```bash
nexus-symbiote verify-live agentbom.json --project /path/to/project --launch-policy /operator/launch-policy.json --json-output
```

The policy maps exact server BOM references to `{"command":"/operator/approved-launcher","sha256":"sha256:<64 lowercase hex characters>"}` records. Acquire pins through a trusted operator channel. `--record` emits a separate unsigned candidate on stdout after complete collection; missing tools prevent candidate emission. It never overwrites the supplied inventory. Run launchers under an externally isolated identity with restricted filesystem and egress; the OS, interpreter and linked dependencies remain trusted. A descriptor match does not establish backend safety or authorization.

For explicitly authorized HTTPS observations, use `discover-mcp ENDPOINT --allowed-origin HTTPS_ORIGIN`. Both commands enumerate served descriptors without calling tools. Review and authenticate their observations separately before using them as approval evidence.

MCP server and tool references are scoped to the relative configuration path and declared name. The same server name in two hosts remains two inventory entries, with separate client links. Existing snapshots using name-only references require review and recollection before comparison or approval.

| Surface | Evidence and limitation |
| --- | --- |
| ShadowScan reports | Primary discovery input; imported claims retain coverage and assurance limitations. |
| MCP and tools | Client configuration and declared tool definitions; a descriptor hash does not establish backend behavior. |
| Models | Artifact identity, serialization and loader-risk signals, model configuration, and signature evidence where available; file extensions and signatures do not prove benignness. |
| Instructions and skills | Prompt, instruction, and skill artifacts with integrity and source information. |
| Retrieval and memory | Declared data/index configuration and lineage references; reconstruction needs actual source versions and execution evidence. |
| Registries and packages | Declared references and version constraints; publisher identity and approval require separate evidence. |
| A2A | Static Agent Cards, client configuration, and code references; a card is not proof of endpoint identity or delegated authority. |
| IDE agents and extensions | Coding-agent configuration and extension declarations; a configured agent is not evidence of execution, and a verification label is not a validated signature. |

Use `--scanner` to request a subset explicitly. Available names are `shadowscan`, `mcp`, `model`, `prompt`, `rag`, `registry`, `a2a`, and `ide_agents`. Unknown names fail rather than silently shrinking collection scope.

## Export formats

```bash
nexus-symbiote scan . -f cyclonedx -o agentbom.cdx.json
nexus-symbiote scan . -f spdx -o agentbom.spdx.json
nexus-symbiote scan . -f sarif -o results.sarif
```

Native JSON retains the product's agent-specific model. CycloneDX 1.7 and SPDX 3.0.1 exports use supported native structures and documented extension points. Schema validity is necessary but does not establish equivalent semantics or completeness. Consumers must inspect coverage, unknown values, and conversion limitations before using an export for authorization. SARIF carries reviewable findings rather than an admission decision.

## GitHub Action

Use a reviewed immutable Nexus SymBiote commit SHA in a consuming repository. For a local checked-out copy, this workflow runs only the local Action and shows explicit SARIF permissions:

```yaml
name: Agent inventory
on: [push, pull_request]
permissions:
  contents: read
jobs:
  inventory:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          persist-credentials: false
      - uses: ./
        with:
          scan-path: .
          output-file: agentbom.json
          validate: 'true'
          risk-check: 'true'
          risk-threshold: '50'
          sarif-upload: 'true'
```

`uses: ./` is for this repository or a trusted, separately checked-out Nexus SymBiote source tree. In another repository use `aisecnomad/nexus-symbiote@<reviewed 40-character commit SHA>`; do not point `uses: ./` at an unrelated target project. Treat Action source as executable code. Do not run an untrusted pull request's Action checkout with deployment credentials or use `pull_request_target` to execute its content.

The Action installs its own reviewed source, collects once, and derives the requested format and SARIF from that same native inventory. Inputs are passed as data, validation failures fail the Action, and malformed risk reports cannot become a zero score. Scan and output paths must stay inside the workspace, and output paths must not contain artifact glob syntax. Collection failures fail the Action even when later validation is disabled. Isolated Python execution prevents the scanned repository from supplying a replacement module through its current directory or `PYTHONPATH`. SARIF uploading is off by default; enable it only when repository code scanning and the event's permissions support uploading. Fork pull requests may have restricted tokens; use the evidence artifact when upload is unavailable.

A threshold of `0` explicitly disables the risk gate. Disabling `validate` or `risk-check` is a caller policy choice, not evidence that verification passed. Outputs distinguish an actual risk score from a skipped evaluation. Inventories may expose infrastructure details; restrict access to uploaded artifacts.

## Policy and trust

```bash
nexus-symbiote init
```

Review `.nexus-symbiote.yaml` as security-relevant configuration. A risk score summarizes findings under a policy; it is not a probability of compromise or a safety certificate. Signatures need explicit subject and signer constraints. Registry membership, trust labels, or model-visible hints must not increase permissions.

Runtime approval integrations govern only calls that pass through their adapter. Use deployment identity, token scopes, sandboxing, and network policy to enforce the surrounding boundary. See the [security model](docs/security-model.md) and [runtime assurance guide](docs/runtime-assurance.md) for the contract, invocation binding, revocation state, and limitations.

## Reproduce the security regression corpus

```bash
PYTHONPATH=src python scripts/benchmark_security.py --out benchmark-results.json
```

The [committed synthetic corpus](benchmarks/README.md) contains inspectable labels and hashes. The runner records its corpus and source digests, tool version, confusion counts, unknowns, denominators, runtime, and Python allocation measurements. Credential-redaction and coverage contracts are separate from detection metrics. These finite hand-authored fixtures support regression evidence, not a representative efficacy estimate or a claim to rank in a particular percentile.

## Development and releases

[CONTRIBUTING.md](CONTRIBUTING.md) describes tests, type checking, exporter validation, and wheel smoke checks. [The release procedure](docs/releasing.md) explains manual candidates, checksums, provenance, PyPI trusted-publisher configuration, and environment approval. Publication is disabled unless a maintainer explicitly requests it and configures the external controls.

[CHANGELOG.md](CHANGELOG.md) records changes. Use [SECURITY.md](SECURITY.md) for sensitive reports. The repository is licensed under [MIT](LICENSE).
