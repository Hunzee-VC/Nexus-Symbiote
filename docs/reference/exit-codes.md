# Exit codes

Every `nexus-symbiote` command uses the same four exit codes, so a CI job can tell
a usage mistake from a policy result and a policy result from missing evidence.
They follow the contract Nexus ShadowScan uses.

| Exit | Meaning | What to do |
| --- | --- | --- |
| 0 | Complete for the requested scope and within policy | Nothing; keep the evidence |
| 1 | Usage, configuration, input or output failure; no usable result | Fix the command line, the policy file or the input, then rerun |
| 2 | Complete evidence, but a gate or a verification failed | Review the findings or the mismatch; the evidence is trustworthy as collected |
| 3 | Incomplete collection or observation, or a live step refused because offline mode is in effect | Do not rely on the result; read the reported failures, or rerun with `--live` or `--input` |

A command can write evidence and still exit 2 or 3. Inspect both the exit code and
the inventory or report.

## By command

| Command | 1 | 2 | 3 |
| --- | --- | --- | --- |
| `scan` | Unknown option, scanner or format; unreadable project; invalid policy; SARIF requested for imported discovery; output refused | Collection completed and the risk gate failed | A collector failed (`metadata.completeness.scan_failures` is not empty) |
| `import-shadowscan` | Malformed or unsupported report; output exists | The import gate failed (imported claims cannot establish complete coverage) | The source report is incomplete or its status is unknown |
| `baseline` | As `scan` | The gate failed; no baseline is written | Collection was incomplete; no baseline is written |
| `validate` | Unreadable inventory; invalid signature policy; a policy that requires `verified` assurance, which offline validation cannot establish | Completeness, integrity, assurance or graph validation failed | |
| `risk` | Unreadable inventory; invalid threshold | Aggregate threshold or severity gate reached, coverage incomplete, or SafeTensors structure unverified | |
| `diff` | Unreadable inventory | `--fail-on-change` and the snapshots differ | |
| `verify-artifact` | Path outside the project; malformed digest; unreadable bundle; Sigstore extra missing | Digest or signature mismatch | |
| `verify-discovery` | Unreadable files; no recorded digest | Digest, projection or signature mismatch | |
| `discover-mcp` | Missing endpoint or origin; live options with `--input`; empty token variable | | Observation or export incomplete; refused offline |
| `advisories` | Unreadable inventory | | A lookup failed, an identity is unresolved, an export entry cannot be evaluated; refused offline |
| `verify-live` | Missing or misplaced launch policy; invalid recording | Descriptors drifted from the inventory | A server could not be observed or is not in the recording; candidate not emitted; refused offline |
| `runtime verify` | Unreadable key, envelope or companion inventory | The contract fails purpose, signer, threshold, subject or validity checks | |
| `runtime keygen`, `runtime sign`, `init`, `summary`, `blast-radius`, `vex` | Invalid input or a refused output path | | |

`--report-only` on `scan` and `import-shadowscan` writes the evidence and exits 0
where 2 or 3 would apply. It is an explicit exploratory choice, not approval; the
inventory still records every failure.

A conflicting or invalid mode setting (`--offline` with `--live`, or an invalid
`NEXUS_SYMBIOTE_MODE`) is a usage error and exits 1 before any input is read. If
offline mode ever stopped a static command because it reached a network or
process operation, the command exits 3 with a message asking for a defect report.
See [offline and live modes](../operations/offline-and-live-modes.md).

## In CI

```bash
nexus-symbiote scan . -o agentbom.json
status=$?
case "$status" in
  0) echo "inventory complete and within policy" ;;
  2) echo "policy gate failed; review agentbom.json" ;;
  3) echo "collection incomplete; do not rely on agentbom.json" ;;
  *) echo "usage or input failure" ;;
esac
exit "$status"
```

The GitHub Action fails its step for any nonzero result and sets the
`risk-passed` output to `false` only when the risk command exited 2. Any other
nonzero exit from the risk step is treated as a failure to run, never as a score.
