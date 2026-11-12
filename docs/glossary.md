# Glossary

The documentation uses each term below with one meaning. Where the code, the CLI or
another format uses a different word for the same thing, the entry says so.

## The document

### AgentBOM

The agent bill of materials that Nexus SymBiote writes: an agent's components, the
relationships between them, findings and coverage. The native form is JSON, format
1.1.0 ([schemas](../schemas/README.md)); CycloneDX, SPDX, SARIF and VEX output are
exports of it.

### AIBOM

The same document under the name the code and the CLI use: the `AIBOM` class,
`AIBOM_PATH` arguments, "Scan a project and generate an AIBOM", the schema file
`nexus-symbiote-aibom-1.0.schema.json` and the Action's `aibom-path` output. Other
tools use AIBOM or AI BOM for a bill of materials of models and datasets; here it
is not a separate artifact.

### Inventory, snapshot

An inventory is an AgentBOM, or the components it lists. A snapshot is an inventory
saved at one time so that a later one can be compared with it.

### Component

One record in an inventory: an agent, MCP server or client, tool, model, prompt,
guardrail, memory store, RAG or data source, registry entry, skill, A2A client or
server, IDE agent or extension (`ComponentType` in `core/enums.py`). The type
`verified-extension` names the kind of record, an agent extension; it does not mean
that anything about the extension was verified.

## Collection and coverage

### Collector, scanner

One module that reads one class of declarations from a checkout. The documentation
says collector; the code and the CLI say scanner (`--scanner`, `scanners/`,
`scanner_status`, "Running mcp scanner..."). There are eight: `mcp`, `model`,
`prompt`, `rag`, `registry`, `a2a`, `ide_agents` and `shadowscan`.

### Coverage gap

An input a collector recognizes but cannot collect, such as an MCP client file it
only detects, or a path the policy excludes. Gaps are listed in
`surfaces_excluded`, the collector's status becomes `partial`, and the default
gates fail. What no collector recognizes is not a gap: it is not recorded at all
([known limitations](known-limitations.md)).

### Scan failure

A read, parse or limit problem that stopped the collection of a file or of a whole
collector, such as a file over a [collection limit](collection-limits.md). Failures
are listed in `scan_failures`, the collector's status becomes `failed`, and the
default gates fail. Also called a collection failure.

### Coverage words

Each layer reports coverage in its own words:

| Where | Values |
| --- | --- |
| One collector (`scanner_status`) | `complete`; `partial` (a gap); `failed` (a failure); `unknown` (did not run) |
| `validate` (`completeness.coverage_status`) | `complete`, `partial` or `unknown`; the check's `status` is `pass` or `fail` |
| `risk` (`coverage_status`) | `reported` (complete coverage of a nonempty inventory), `partial` or `unknown` |
| CycloneDX, SPDX and SARIF exports | `incomplete`, or `unknown` (`noAssertion` in SPDX); never complete |
| `advisories` | `complete`, `partial` or `none` |

## Evidence

### Declared, observed, verified

The assurance level of a component or claim says how it was established.
**Declared**: a file, manifest, supplier or report says so. **Observed**: a named
collector measured it from bytes in a stated scope, such as a weight file's digest.
**Verified**: a check under operator policy succeeded, such as a signer-policy
signature or digest pin on a model's weights. Collection never makes a component's
identity verified, and an inventory's own `verified` labels are not trusted. The
[security model](security-model.md)'s four states add two that are not assurance
levels: approved configuration, a signed runtime approval, and mediated execution,
a gateway decision.

### Trust tier

Who stands behind a component: `internal-verified`, `internal-unverified`,
`third-party-signed`, `third-party-unsigned`, `untrusted-public` or `unknown`. A
collector records the tier its evidence supports, such as `third-party-signed` for
a model whose weights are Sigstore-signed under the signer policy. In a supplied
inventory a tier is a claim, and `diff` rates a raised tier as a medium alert.

### Binding key

`NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, an operator secret of at least 32 characters.
With it, a scan records an HMAC over the MCP, A2A, RAG and IDE settings values the
inventory does not export, so `diff` and `validate --project` detect changes to
them. Without it, only unkeyed structure digests are recorded, and records with
unbound values carry a low `completeness` finding. The key never enters an
inventory; use one key for a baseline and every scan compared with it
([source binding](verification-source-binding.md)).

### Supplied inventory, reconciliation

An inventory a command reads rather than collects. With `--project`, `validate` and
`risk` collect the checkout again and reconcile the two; the result's
`assessment_basis` is `project-reconciled`, `project-reconciled-with-supplier-claims`
or `project-reconciliation-failed`. Without it, the basis is `supplied-bom` (the
completeness check calls it `supplied-claims`): only the inventory's own claims were
checked.

## Gates and policy

### Finding, alert, issue

A finding, or risk, is a categorized observation about one component, listed in the
[finding catalog](finding-catalog.md). An alert is a change between two snapshots
that `diff` rates medium or higher ([drift gate](drift-gate.md#what-the-alerts-mean)).
An issue is a problem that `validate` reports in its completeness or integrity check.

### Severity

How serious one finding is: `critical`, `high`, `medium`, `low` or `info`. `diff`
rates each change with the same words.

### Risk level

The label `risk` prints beside the aggregate score, as in `Risk Score: 37.0 (high)`.
It reuses severity words with another meaning: `critical` for a critical finding or
a score at or above the fail threshold, `high` for a score at or above the warning
threshold (25 by default), `moderate` for any other score above 0, `clean` for 0,
and `unknown` when there are no findings and coverage is not reported, or when
`--project` reconciliation failed. A `high` risk level can therefore come with a
passing gate, as on the demo agent, whose score of 37 is below the default fail
threshold of 50.

### Gate

A check whose failure makes a command exit 1: the scan gate of `scan` and
`baseline`, the completeness and integrity checks of `validate`, the risk gate of
`risk`, and the drift gate of `diff --fail-on-alert`. The GitHub Action reports each
as `collection`, `completeness`, `integrity`, `risk` and `drift`. By default the
scan, `validate` and `risk` gates fail on unknown or incomplete coverage, and the
drift gate fails when coverage regresses.

### Baseline, candidate

A baseline is a reviewed snapshot that later snapshots, the candidates, are compared
with by `diff`. The `baseline` command writes one only when the scan gate passes,
under the built-in policy too. A baseline is unsigned: the gate is only as strong
as the place it is read from
([trust anchor](drift-gate.md#the-trust-anchor-is-the-baseline)).

### Policy kinds

| Policy | Written by | What it does |
| --- | --- | --- |
| Built-in policy | The release | The default gates, used with `--no-project-policy` |
| Project policy | The project, as `.nexus-symbiote.yaml` | Selects collectors and exclusions, and changes gates and output; every relaxation is listed in `policy_weakened` ([policy reference](policy-reference.md)) |
| Signer policy | The operator, outside the project | Names the Sigstore signers or digest pins that verify model artifacts and ShadowScan reports ([signer policy](cli-reference.md#signer-policy)) |
| Launch policy | The operator, outside the project and its repository | Pins the stdio launchers `verify-live` may start ([launch policy](cli-reference.md#launch-policy)) |

Collection limits and the binding key are operator settings, not policies: nothing
in a checkout can change them. Runtime contracts and gateway configuration are
described in the [runtime contract reference](runtime-contract-reference.md).
