# CLI and Python API

Typer app `symbiote`. Every command accepts `--json` (machine output on stdout; human output via rich on
stderr when a TTY), `--quiet`, `--store PATH` (default `./.symbiote/store`), `--deterministic [--nonce HEX]`,
`--config symbiote.yaml`. Secrets never appear in output.

## Exit codes (stable)
| Code | Meaning |
|---|---|
| 0 | success / no findings at or above `--fail-on` |
| 1 | policy or conformance findings at or above `--fail-on` (default `high`) |
| 2 | usage error |
| 3 | schema validation failure (input or output) |
| 4 | verification failure (signature, digest binding, identity constraint, expired trust status) |
| 5 | coverage insufficient for the requested conformance level (blocking unknowns) |
| 6 | collector / I-O error (unreadable source, network needed but unavailable) |
| 7 | anti-rollback / chain conflict (serial regression; chain gap under `--strict`) |
| 8 | loss report contains dropped security-relevant fields under `--strict` |

## Commands
| Command | Purpose |
|---|---|
| `symbiote init [--from-cwd] [--framework F]` | write `symbiote.yaml` (agent name/version/owner, sources, identity policy) by scanning the cwd |
| `symbiote scan [PATH] [--live] [--registry] [--profile minimal|standard|verified] [--valid-for DAYS] [--shadowscan-report FILE] [-o DIR]` | zero-config collection → `declared` (and `observed` with `--live`) snapshot; writes `agentbom.json` (last, with `links` to the exports by digest and the loss report), `agentbom.cdx.json`, `agentbom.spdx.json`, loss reports, `agentbom.validation.json`; `--profile` evaluates conformance (exit 5 when not attained) |
| `symbiote collect [--source NAME…] [--live]` | run selected collectors into the store |
| `symbiote observe mcp --server ID|--all [--watch]`, `symbiote observe otel FILE…` | produce `observed` snapshots and deltas |
| `symbiote generate [--kind K] [--format cyclonedx|spdx|companion|all] [--cdx-version 1.7|1.6] [--embed-records] [--include-text] [--redact CLASS…] [--jsf-sign]` | export from the store |
| `symbiote validate FILE… [--cross]` | validate against official + Symbiote schemas (companion, CycloneDX, SPDX, loss reports, validation evidence); `--cross` triangulates model digests |
| `symbiote import FILE --format cdx|spdx|k8s-aibom|cdxgen|syft|harness-aibom [--as declared|observed|deployed]` | import with loss report and assurance tagging |
| `symbiote convert IN -o OUT --to cyclonedx|spdx|companion [--loss-report]` | format conversion with loss report |
| `symbiote diff A B [--fail-on-change EVENT…] [--sarif]` | `Delta` between snapshots/documents of any kind; the diff is the finding |
| `symbiote digest tooldef FILE|-`, `digest file PATH`, `digest dir PATH`, `digest prompt FILE --engine E --role R`, `digest server …` | compute digests exactly as the BOM does |
| `symbiote model manifest DIR [--tensors]`, `model risk DIR`, `model sign DIR`, `model verify DIR --bundle B --identity I --issuer U` | model identity, serialization risk, signing (model-signing) |
| `symbiote registry resolve REF [--live] [--pin]` | name-resolution record; `--pin` writes the immutable ref back |
| `symbiote policy check FILE [--fail-on SEV] [--select GLOB…] [--exclude GLOB…] [--baseline FILE] [--sarif OUT] [--rego DIR] [--fail-on-indeterminate]`, `policy list`, `policy explain ID`, `policy export-rego DIR` | built-in checks, organisation Rego, SARIF, Rego export (`checks.md §5`), documentation |
| `symbiote conformance [FILE] --level minimal|standard|verified [--evidence agentbom.validation.json]` | per-requirement pass/fail/unknown; validation evidence is read from the companion's sibling `agentbom.validation.json` by default |
| `symbiote score [FILE]` | completeness score with reasons and assurance distribution |
| `symbiote attest snapshot|toolset|coverage|evaluation|resolution|delta|trust-status|approval … --out X.sigstore.json [--key KEY] [--staging] [--identity-token T]` | build and sign statements |
| `symbiote verify FILE… --policy policy.yaml [--live] [--state-file F] [--insecure-unconstrained] [--trust-status-stale-ok]` | verification flow (`attestation.md §3`) |
| `symbiote trust allow|quarantine|revoke SUBJECT --reason R --expires D`, `trust list`, `trust publish --sign` | maintain and sign trust-status lists |
| `symbiote allowlist export --format gab|opa-data|envoy-ext-authz-json|mcp-gateway-generic` | enforcement exports |
| `symbiote redact --class C… IN -o OUT`, `symbiote merkle verify FILE --root R|--bundle B`, `symbiote merkle prove FILE --id ID` | redaction and Merkle proofs |
| `symbiote index build`, `symbiote query who-holds-credential --server ID`, `query ran-under --snapshot D --between T1 T2`, `query trusts-publisher --publisher P`, `query blast-radius --tool ID`, `query drift --agent ID --since T` | incident index over the store |
| `symbiote shadowscan import REPORT [-o DIR] [--name N] [--scope estate|root] [--scan-root P] [--format …] [--deterministic]` | Nexus ShadowScan JSON report or CycloneDX output → **observed** snapshot (`shadowscan-mapping.md §2`); writes `agentbom.observed.json` (+ `.cdx.json`, `.spdx.json`, loss reports) |
| `symbiote shadowscan inventory COMPANION -o DIR|FILE [--format cards|agents|csv] [--scan-root P] [--resource PAT…] [--include-external] [--classification C]` | the AgentBOM as the ShadowScan inventory (Capability Cards v2, `agents.yaml`, CSV) so *shadow* means *not in the AgentBOM* (§4) |
| `symbiote shadowscan reconcile COMPANION REPORT [--scan-root P] [--fail-on SEV] [-o FILE] [--sarif FILE]` | declared vs observed tool servers, autonomy verdicts, `SYM-SS-*` findings; exit 1 at `--fail-on` (§5) |
| `symbiote shadowscan levels` | the L0-L5 scale and its ISO/IEC 22989 projection |
| `symbiote scan … --shadowscan-report FILE [--shadowscan-scope root|estate]` | fold a ShadowScan report into the scan through the `shadowscan-report` collector (§6) |
| `symbiote schema export companion|predicates|taxonomy|conformance`, `symbiote version` | introspection |

## Python API (`symbiote.api`)
```python
from symbiote import api
bom = api.scan(".", live=False)                              # AgentBOM (declared snapshot)
cdx, loss = api.export_cyclonedx(bom, profile="standard")    # dict + LossReport
spdx, loss2 = api.export_spdx(bom)
companion = api.export_companion(bom)
findings = api.policy_check(bom, fail_on="high")             # list[Finding]
d = api.digest_tooldef(raw_tool_json)                        # Digest or Undigestable
delta = api.diff(approved, observed)                         # Delta
result = api.verify("snapshot.sigstore.json", policy=api.VerifyPolicy.from_yaml("policy.yaml"))
gab = api.export_allowlist(approved, trust_status=ts, fmt="gab")
```
Everything public is re-exported from `symbiote.api`; other modules are private.

## GitHub Action and pre-commit
`action.yml` (composite): `symbiote scan . --profile standard`, `symbiote policy check --sarif`, uploads the
SARIF and the three documents as artifacts; optional keyless `symbiote attest snapshot`. `.pre-commit-hooks.yaml`:
`symbiote-scan` (fast static scan + policy check on changed agent configs).
