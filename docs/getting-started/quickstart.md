# Quick start

This walk-through inventories a small agent project, reads the result, applies the
validation and risk gates, compares two snapshots, imports a Nexus ShadowScan
report and exports standard formats. Every command runs offline: nothing in this
guide contacts a network or starts a process. Install first, as
[installation](install.md) describes.

The example project is synthetic: two MCP servers in `.mcp.json` (one pinned to an
exact version, one floating on `@latest`), a `CLAUDE.md` system prompt, a small
SafeTensors file under `models/`, a `requirements.txt` and a `package.json`.
Output below is real, abridged where marked.

## 1. Collect an inventory

```bash
nexus-symbiote scan support-agent --report-only -o agentbom.json
```

```
Scanning /work/support-agent
  Running mcp scanner...
    Found 3 components
  Running model scanner...
    Found 1 components
  Running prompt scanner...
    Found 1 components
  ...
  Running ide_agents scanner...
    Found 1 components
Saved agentbom.json
Risk warning: score 26.0
Report only
```

`--report-only` writes the inventory and exits 0 whatever it finds, which suits a
first look. Without it, `scan` is a gate:

```
$ nexus-symbiote scan support-agent -o agentbom.json
...
Error: scan gate failed: collection coverage is unknown or incomplete (risk score 26.0)
```

That run exits 2: the evidence is complete as collected, but the default policy
requires complete coverage, and this project has surfaces no collector could
cover (no ShadowScan report, no retrieval configuration, no A2A card). A collector
failure would exit 3 instead. See [exit codes](../reference/exit-codes.md).

The inventory records how it was produced:

```json
"completeness": {
  "scope": "repository",
  "collectors_requested": ["mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"],
  "surfaces_excluded": ["a2a (no A2A configurations found)", "rag (no RAG configuration found)", "shadowscan-report (no report found)", "..."],
  "scan_failures": [],
  "unobserved_surfaces": ["runtime", "effective-identity", "effective-authorization", "live-tools", "network"],
  "collection_mode": "offline",
  "offline_enforced": true
}
```

## 2. Read it

```
$ nexus-symbiote summary agentbom.json
AIBOM Summary
  Components: 10
  Dependencies: 6
  Risks: 5
  Component types:
    agent: 1
    ide-agent: 1
    mcp-client: 1
    mcp-server: 2
    model: 1
    prompt-template: 1
    registry-entry: 3
  Risk breakdown:
    high: 2
    medium: 3
```

The `agent` is the repository itself, linked to everything collected from it. The
secret in the floating server's `env` block is redacted before anything is
written.

## 3. Validate against the checkout

```
$ nexus-symbiote validate agentbom.json --project support-agent
Completeness check
  Status: FAIL
  Components: 10
  ERROR  Excluded surfaces leave coverage incomplete.
  ERROR  Scanner coverage is partial.
  ...
Integrity check
  Status: FAIL
  Hashes verified: 4, failed: 0
  WARNING  MCP package version is not pinned
  UNKNOWN  No trusted artifact-bound signer policy was supplied
```

Validation re-hashes the recorded artifacts in the checkout (all four matched) and
checks coverage and signer evidence. It exits 2 here. Missing evidence is reported
as unknown, never as a pass.

## 4. Score and gate

```
$ nexus-symbiote risk agentbom.json --threshold 50
Risk Score: 26.0 (high)
  Components: 10 total, 4 with risks
  ...
│ high │ ticket-service           │ version_pinning │ MCP server 'ticket-service' uses an unpinned ...
│ high │ models/classifier.safet… │ signing_status  │ Model 'classifier.safetensors' has no verified ...
...
Gate (threshold=50.0): FAILED: collection coverage is unknown or incomplete
```

The score summarizes findings under the policy; it is not a probability of
compromise. The gate failed on coverage, not on the threshold. `--json-output`
prints the same report as JSON, including `gate_reasons`. See
[risk scoring](../concepts/risk-scoring.md).

## 5. Compare snapshots

After pinning a new filesystem server version and adding a `shell` server:

```
$ nexus-symbiote diff previous.json agentbom.json --fail-on-change
3 changes detected

Security Alerts:
  [MEDIUM] New component 'shell' (mcp-server) added to supply chain.

+1 added
  + shell (mcp-server)

~1 modified
  ~ filesystem: Version changed: 0.6.2 → 0.6.3
```

With `--fail-on-change` the command exits 2 when the snapshots differ, which makes
it a drift gate for CI. Without it, `diff` reports and exits 0.

## 6. Import ShadowScan discovery

[Nexus ShadowScan](https://github.com/aisecnomad/Nexus-ShadowScan) discovers
agents across an organization; SymBiote records its findings as attributed claims.

```
$ nexus-symbiote import-shadowscan shadowscan.json -o imported.json --report-only
Imported 2 components and saved imported.json; discovery coverage remains partial.

$ nexus-symbiote verify-discovery imported.json shadowscan.json
Report bytes match the recorded digest. Source identity, signature, and truth were not verified.
```

Imported records keep declared assurance and the exact SHA-256 of the report. See
[ShadowScan integration](../operations/shadowscan-integration.md) for verifying a
signed report.

## 7. Export

```bash
nexus-symbiote scan support-agent --report-only -f cyclonedx -o agentbom.cdx.json
nexus-symbiote scan support-agent --report-only -f spdx -o agentbom.spdx.json
nexus-symbiote scan support-agent --report-only -f sarif -o results.sarif
nexus-symbiote vex agentbom.json -o findings.vex.json
```

CycloneDX and SPDX exports embed a digest-bound copy of the native inventory and
record what they cannot represent. See [output formats](../reference/output-formats.md).

## 8. Optional: offline advisories and live checks

Known-vulnerability lookups work offline against a saved OSV export:

```
$ nexus-symbiote advisories agentbom.json --input osv/
{
  "collection_mode": "offline",
  "source": "osv-export",
  "advisories": [{"advisory_id": "GHSA-demo-0001", "package_url": "pkg:pypi/langchain@0.3.7", ...}],
  "errors": ["registry:npm/@modelcontextprotocol/sdk: OSV lookup incomplete or identity unverified"],
  "complete": false,
  ...
}
```

It exits 3 here: the npm dependency is declared as `^1.0.0`, so it has no exact
identity to check, and an unchecked dependency is never reported as clean. The
same command with `--live` and without `--input` queries the OSV API. See
[offline and live modes](../operations/offline-and-live-modes.md).

## Next steps

- [Configuration](configuration.md): the `.nexus-symbiote.yaml` policy.
- [GitHub Action](../reference/github-action.md): the same steps in CI.
- [Security model](../concepts/security-model.md): what each evidence state means.
