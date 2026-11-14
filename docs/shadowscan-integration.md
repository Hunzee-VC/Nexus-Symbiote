# ShadowScan discovery and Nexus SymBiote verification

Nexus-ShadowScan is a separate project,
[Hunzee-VC/Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan). Install
it from that repository at a commit you have reviewed. The PyPI project named
`shadowscan` is an unrelated tool from another publisher.

Run Nexus-ShadowScan separately with the least privileges needed for the chosen
connectors and save its JSON report. Keep the report under appropriate access and
retention controls. For example, following the ShadowScan version's own CLI help:

```sh
shadowscan code /path/to/repository --format json -o shadowscan.json
nexus-symbiote import-shadowscan shadowscan.json -o agentbom.json --report-only
nexus-symbiote import-shadowscan shadowscan.json --format cyclonedx -o agentbom.cdx.json --report-only
nexus-symbiote verify-discovery agentbom.json shadowscan.json --projection
nexus-symbiote verify-artifact model.safetensors --project /path/to/repository --sha256 "$TRUSTED_SHA256"
```

A standalone import always records partial coverage, so `validate` of
`agentbom.json` always fails. To gate on discovery together with the repository's
own evidence, put the report at one of the supported paths in the repository (see
below) and validate a merged scan:

```sh
shadowscan code /path/to/repository --format json -o /path/to/repository/shadowscan.json
nexus-symbiote scan /path/to/repository --no-project-policy -o merged.json
nexus-symbiote validate merged.json --project /path/to/repository --no-project-policy
```

The output path must not exist. An incomplete source produces a partial BOM and
nonzero exit; a malformed or unsupported report is rejected. With `--report-only`
the exit status is 0 either way, except that unverified discovery evidence fails in CI
unless `--bundle` verifies the producer or `--allow-unsigned-discovery` accepts it; read `metadata.completeness.source_report_status`
(`complete`, `incomplete` or `unknown`) in the written BOM to tell them apart. A locally generated
report digest binds the imported bytes, not the identity of their producer or the
truth of their contents. Verification of signatures, sources and artifacts is a
separate operation; this importer does not perform it. Do not infer production
activity, effective access or authorization from a finding or inventory mismatch.
`verify-discovery` compares exact report bytes with the native BOM's recorded
digest; without `--projection` it does not compare the BOM's components. It does
not authenticate either the BOM or the report.
`verify-artifact` hashes a selected local artifact within the project root against
an operator-supplied expected digest. To verify a Sigstore bundle as well, pass
`--bundle`, `--signer-identity`, and `--issuer`. The expected digest and signer
policy must come from a trusted source. This verifies the selected artifact, not
its association with a discovery finding, deployment, or safety.

The importer maps native `agent`, `mcp-server` and `local-model` findings,
including MCP tool observations distinguished by resource type. It
also accepts ShadowScan's CycloneDX 1.6/1.7 components and services, marking the
projection partial. Unmapped entries are counted with source indexes. For
CycloneDX, the index is into components followed by services. The source report
and its scope, timestamps, detailed evidence, identities and full graph remain
the authoritative discovery record. Only supported, mapped-endpoint CycloneDX
dependencies are projected as declared claims; the rest of those fields remain
in the report. This reduces leakage but does not create a complete evidence graph.

All imported components have declared assurance and unknown trust. The importer
does not run ShadowScan, execute tools, fetch endpoints, infer agent autonomy, or
promote a signature filename into verified evidence.

`validate --project` judges imported components as imported claims, not local
subjects. Once reconciliation has bound them to the report beneath the project
root, an imported model or MCP tool that has no local artifact or digest is listed
as an informational integrity issue instead of making integrity unknown; findings
about the claim itself, such as an unsafe loading format, still fail. Without
`--project`, or when the inventory's discovery evidence differs from the report,
nothing is bound and those components keep integrity unknown. Imported components
never count as the local subject that `validate --project` and `risk --project`
require. ShadowScan risk and shadow
flags remain source-reported heuristics; an inventory mismatch is not proof of
unauthorized activity. Output contains report and source-ID digests and indexes,
not raw source descriptions, locations or snippets. Both artifacts may still be
sensitive and must be handled accordingly.

The projection profile `nexus-symbiote/shadowscan-projection/v4` identifies the
SymBiote mapping, not a ShadowScan report schema or authenticated producer
version. Each projected component records the exact report digest
(`shadowscan:report-sha256`) and a content digest of its own source finding
(`shadowscan:finding-sha256`, see below). CycloneDX `dependsOn` edges are copied
only when both endpoints map to components. They remain declared, source-reported
relationships, with the dependency-array index recorded on the edge; the BOM
metadata binds them to the report digest. Unmapped endpoint
edges are counted as limitations; raw source identifiers are not included. This
does not verify deployment, association or authorization. The native ShadowScan
format has no general dependency graph, and this importer does not infer one from
fields that merely mention a model. Consumers of standards exports must retain
the SymBiote extension to preserve the edge assurance and provenance.

ShadowScan's endpoint connector can report an MCP tool using kind `mcp-server`
and resource type `mcp-tool`. Since projection version 2, the importer projects that
exact combination as a declared, unverified tool rather than as a server. It does not infer a server
association, tool definition hash, endpoint identity or authorization. Conflicting
tool and kind claims remain unmapped. Native JSON uses `resource_type` and
CycloneDX uses the `shadowscan:resource-type` property. This mapping follows the
[ShadowScan endpoint producer at 1a821e5](https://github.com/Hunzee-VC/Nexus-ShadowScan/blob/1a821e5763e9340ea96564b0606d1ab581fde90e/shadowscan/connectors/endpoint/runtime.py)
and its [CycloneDX reporter](https://github.com/Hunzee-VC/Nexus-ShadowScan/blob/1a821e5763e9340ea96564b0606d1ab581fde90e/shadowscan/reporters/cyclonedx.py).
Version 1 projections used the server type for these findings, and version 2
recorded the exact report digest on CycloneDX edges and had no finding digest.
Version 3 resolved a CycloneDX entry whose type or group contradicts its
`shadowscan:kind`, such as kind `agent` on a `machine-learning-model`, by
precedence; version 4 leaves it unmapped.
Retain the original importer to reproduce or verify an older projection, then
regenerate inventories with the current profile and review them before comparison or
approval. Producer schema and version changes require compatibility testing; the
report remains untrusted.

At present the bridge does not resolve agents across tenants or reports, verify
live MCP identities, or map every ShadowScan finding type, model association or
dependency. A complete ShadowScan run is only complete for its configured scope;
Nexus SymBiote records the imported BOM coverage as partial. SARIF is not available
for imported discovery because its finding projection does not retain complete
coverage and provenance: `scan -f sarif` and `import-shadowscan -f sarif` refuse
such an inventory, the GitHub Action skips its SARIF upload with a warning, and the
`vex` command omits imported findings and records how many it omitted in the
property `nexus-symbiote:omittedImportedFindings`.

## Import and policy gates

The native importer compares reported totals and supplied per-kind,
per-surface and per-risk-level counts and the shadow count with the final findings
array. A contradictory summary is an invalid report, including in report-only mode.
Reports must be UTF-8 JSON, optionally with a byte-order mark; UTF-16 and UTF-32
reports are rejected, because `verify-discovery` could not read them.

A finding is still imported when it carries a risk level, a shadow flag or a
surface the projection does not recognize, such as `Critical` instead of
`critical`, a `risk` object with a score but no level string, or the string
`"true"` instead of `true`, but the value is not represented: the projection
limitations count such entries and the collector
records the coverage gap "ShadowScan report contains values the projection does
not recognize", so the default gate does not pass on a finding whose rating was
dropped.

| Limit | Value |
| --- | --- |
| Report size | 16 MiB |
| Native findings, or CycloneDX components and services | 10,000 |
| CycloneDX dependency edges | 10,000 |
| Finding identifiers, CycloneDX `bom-ref` and dependency references | 4,096 characters |

A report within these limits can still yield an inventory larger than the 16 MiB
that `validate`, `risk`, `diff` and the other commands read. A merged `scan` reaches
it at roughly 8,000 to 9,000 findings that each carry a risk level, fewer when they
are also flagged as shadow; a standalone import of 10,000 such findings stays below
it. Individual connector counts can
precede filtering or deduplication and can legitimately differ from the final
array.

Standalone import records partial coverage even when the source reports a completed
scan. It writes the evidence and exits with status 1. Pass `--report-only` to
accept that result for inspection. The command ignores project policy in the
report directory and its ancestors. Incomplete source reports retain their
status in either mode. Each import requires a new output path.

Native JSON, CycloneDX and SPDX preserve report provenance, source status and
unmapped indexes. Portable formats embed a digest-bound native inventory extension;
its round trip preserves the imported limitations without authenticating the
producer. CycloneDX also declares an incomplete composition. SARIF imports remain
unavailable because a finding-only projection does not preserve this evidence.

The importer API returns `ImportedReport`, including `components`, coverage and
provenance, rather than a bare component list. It rejects bare finding arrays that
cannot carry source coverage. Unknown finding kinds remain unmapped. Imported
assets are not automatically linked to the repository agent or asserted present
on the local filesystem.

### Scope of a repository baseline

`scan` and `baseline` assess the supported static files in one repository.
All eight collectors must finish for the default gate to pass. A successful
search can find zero matching files. Git metadata, dependency directories and
virtual environments are outside the built-in scope. The inventory lists those
patterns under `exclusions`. Unreadable files, unsupported declarations and
additional policy exclusions encountered inside the scope keep coverage partial.
A baseline also requires a local subject. The inferred repository agent
and imported findings alone provide no evidence of a local agent or artifact.

The collector reads a report at one of three paths beneath the project root:
`.shadowscan/report.json`, `shadowscan-report.json` or `shadowscan.json`. Exactly
one may exist. When more than one does, the scan records the failure
"ShadowScan reports found at more than one supported path (...); keep exactly one"
and imports none, so a file committed under another name cannot silently replace
the report a pipeline generated. The inventory lists the path it read under
`surfaces_scanned`. If none exists, the inventory records that observation. A fully mapped native report
whose source collection completed can accompany a successful repository baseline.
The digest and `source_projection_limitations` record the external evidence
separately. Imported assets retain declared assurance and unknown trust, and
the CycloneDX composition remains incomplete. Incomplete sources, unmapped
entries and lossy CycloneDX inputs keep the default repository gate closed.

Project validation also compares imported dependency endpoints, relationship types,
assurance, provenance and multiplicity against the local report projection. Missing,
modified or additional edges involving imported components fail reconciliation.

### Compare discovery across reruns

The exact report digest changes on every ShadowScan run, because the report
records when the run started and finished. It stays the value that
`verify-discovery`, Sigstore and `validate --project` authenticate. For drift,
the inventory also records `source_report_content_digest` under the profile
`nexus-symbiote/shadowscan-content/v1`: the SHA-256 of the RFC 8785 canonical
JSON of the strictly parsed report without its run-event fields. These are, for
native JSON, the top-level and per-connector `started_at` and `finished_at` and
each finding's `last_seen`; for CycloneDX, `serialNumber` and
`metadata.timestamp`. Each is dropped only when it is null or shaped as an RFC
3339 timestamp written with ASCII digits, or for the serial number a URN UUID. The list is closed. Every
other field or value, including a field a later ShadowScan release adds, counts
as content. `shadowscan:finding-sha256`
applies the same rule to one finding, or to one CycloneDX component or service.

When both inventories carry content digests under the same profile, `diff`
ignores a changed exact digest and records an informational metadata note,
"ShadowScan report regenerated; normalized content unchanged", which is not a
security alert. A changed finding raises a medium alert on its own component,
including when only fields that the BOM does not project changed, and the
changed report content raises the high alert "ShadowScan report content changed".
Findings are matched by their source identifier, not their position: a finding
inserted before others alerts only as an added component, and reordering the
CycloneDX `dependencies` array changes no relationship. An inventory
written by an earlier version may have no content digests or an older projection
profile. The first comparison after an upgrade then falls back to the exact report
digest, which raises a high alert when the report bytes differ, and raises a medium
alert for every imported component, even when the report bytes are unchanged,
because the new inventory adds the content digests, the v4 projection profile and
the per-component finding digests. Later comparisons use the content digests. The content
digests are not authentication; `validate --project` compares them with the
local report as it does the exact digest. Text output prints the note under
Notes; `--json-output` lists it in `metadata_changes`.

ShadowScan's own finding content can include absolute paths of the directory it
scanned, which the content digests keep. Run ShadowScan from the same checkout path
for reports you intend to compare, or expect each finding to show as changed.

Reruns whose reports contain redacted credential findings compare cleanly only
when ShadowScan keys credential identities with a stable key, which the report
records as `collection_scope.credential_identity_scope` `keyed`; reports without
such findings compare cleanly in either scope. In the `run` scope, ShadowScan derives each redacted credential
finding's id from a random per-run key, so those findings get new ids on every
run and `diff` reports them as removed and added components. That fails safe,
as alerts, but configure a stable credential identity key in ShadowScan, by
setting `SHADOWSCAN_IDENTITY_KEY` for every run, before you compare reruns.

### Require a signed report in CI

`validate --project` and `risk --project` can require that the ShadowScan
evidence in a merged `scan` BOM comes from a report signed by the expected
producer. List the report in the operator signature policy passed with
`--signature-policy`, using the path the collector reads:

```json
{"version": 1, "artifacts": [{"artifact_path": ".shadowscan/report.json",
  "bundle_path": ".shadowscan/report.json.sigstore",
  "expected_identity": "https://github.com/acme/infra/.github/workflows/discovery.yml@refs/heads/main",
  "expected_issuer": "https://token.actions.githubusercontent.com"}]}
```

```sh
nexus-symbiote validate agentbom.json --project . --signature-policy /etc/ci/signers.json
nexus-symbiote risk agentbom.json --project . --signature-policy /etc/ci/signers.json
```

A signature policy entry that names one of the conventional report paths turns
the check on. An entry matches the report by path or by file, so another name
for the same file, such as a different case on a case-insensitive filesystem,
counts too. So does `--require-discovery-signature` on `validate` or `risk`, or
`validate.require_discovery_signature: true` in the project policy, which then
fails when no entry names the report. The project-policy setting is ignored, like
the rest of the file, under `--no-project-policy`, so CI that ignores the project
policy passes the command-line flag. Keep the signature policy outside the
checkout, as the project policy can be changed by the code it gates. When the
check runs on an inventory without ShadowScan evidence, it fails if a report lies
beneath the project root or a policy entry names one, so stripping the evidence
cannot pass it; with no evidence and no report it prints `not applicable`. When
no check runs, `validate` prints that discovery evidence was accepted unverified
and `risk --json-output` reports `discovery_producer` as `not-verified`. When the
BOM carries ShadowScan evidence, the check reads
the report beneath the project root with the collector's confined reader and
requires its digest to equal the BOM's recorded `source_report_digest`. It then
verifies the bundle offline over those exact bytes against the policy's identity
and issuer, and requires the BOM's discovery evidence to match the report's
projection. A missing entry or bundle, another signer or issuer, a bundle over
other bytes, or a report changed since the scan fails the command; `risk` then
reports `project-reconciliation-failed` with the reason. Values recorded in the
BOM are never trusted for this check. A passing check authenticates the
report's producer, not the truth of its findings, and imported components keep
declared assurance. Install the Sigstore extra for this mode.

The check binds the report to its producer and to the exact report bytes, and
the BOM records the verification outcome (`metadata.completeness.discovery_verification`):
`verified` with the signer identity and issuer, or `unverified`, together with
the report digest, the report's own run time, and the repository/commit the
report carries — currently both `unknown`, because the report format carries
neither. It does not bind the report to this repository or commit. Anyone who
can write to the checkout can substitute an older report, or another
repository's report, signed by the same identity, for example one from before a
shadow agent appeared, and regenerate the BOM from it. Give each repository's
discovery workflow its own signer identity, and bind the commit separately
where you need that. Unsigned evidence warns loudly on `import-shadowscan`,
`validate` and `risk`, and fails in CI (or with `--fail-on-unsigned-discovery`)
unless the operator explicitly passes `--allow-unsigned-discovery`.

The GitHub Action runs in CI, so a checkout with a ShadowScan report fails its
completeness and risk gates by default: the `gates` output records both as
`failed`, `risk-score` stays empty and the job log and step summary give the
reason. With `validate: 'true'` the Action passes its `signature-policy` snapshot
to both `validate --project` and `risk --project`, so a policy entry that names the report and
verifies its producer passes the check. To accept unsigned evidence instead, set
the `allow-unsigned-discovery` input to `'true'`, which passes
`--allow-unsigned-discovery` to `validate` and `risk` and prints a warning.

To accept only one report, write a
version 2 entry (`"kind": "sigstore-message-signature"`) with `expected_sha256`
set to the report's SHA-256: the check then also fails for other report bytes,
however they are signed. The report needs such a signature entry: a
`digest-pin` entry for it, or an entry for a report location the collector does
not read (it considers `.shadowscan/report.json`, `shadowscan-report.json` and
`shadowscan.json`, and rejects multiple distinct reports), is reported as an
unused policy entry by `scan` and `validate --project`
([model integrity](model-integrity.md#operator-signature-policy)).

### Verify the native import and its producer

For a BOM written by `import-shadowscan`, reproduce the direct import and compare
the component records, dependencies, coverage, unmapped indexes and metadata.

```sh
nexus-symbiote verify-discovery agentbom.json shadowscan.json --projection
```

For an independently signed report, pass the signing policy from trusted operator
configuration. The bundle must be a Sigstore artifact bundle over the exact
ShadowScan report bytes. Install the Sigstore extra for this mode.

```sh
nexus-symbiote verify-discovery agentbom.json shadowscan.json \
  --bundle shadowscan.json.sigstore --signer-identity "$EXPECTED_IDENTITY" \
  --issuer "$EXPECTED_ISSUER"
```

The same verification can run at import time: `import-shadowscan --bundle
shadowscan.json.sigstore --signer-identity "$EXPECTED_IDENTITY" --issuer
"$EXPECTED_ISSUER"` records the evidence as `verified` with the signer identity
and issuer in the BOM. Without `--bundle` the import records `unverified`;
`validate` and `risk` then warn loudly, and fail in CI (or with
`--fail-on-unsigned-discovery`) unless `--allow-unsigned-discovery` is given.

The signed mode also verifies the direct native projection. Use the same importer
version. The comparison ignores JSON object key ordering and the BOM's locally
generated timestamp and serial number. Source findings keep their declared
assurance. Merged, enriched and portable BOMs require their own provenance, so
`verify-discovery --bundle` rejects a `scan` BOM; use the CI check above for one.

The offline signature regression uses a public release bundle from
[sigstore-python at 19b8aec](https://github.com/sigstore/sigstore-python/blob/19b8aec7063e62c718efd327f5a45582472c3b3c/test/assets/bundle_v3_github.whl.sigstore).
Its Apache-2.0 license accompanies the fixture. Production report verification
requires your own producer identity, issuer and report bundle.

## Approve in SymBiote, reconcile in ShadowScan

ShadowScan's `--inventory` does not read the native AgentBOM; it refuses it. To
make an agent you approved in SymBiote review an approved agent in ShadowScan's
reconciliation, export the reviewed inventory and give the file to ShadowScan:

```sh
nexus-symbiote export-inventory reviewed.json --format shadowscan-simple \
  --resource-prefix github:acme/support-triager -o approved.json
```

The file approves only the project that ShadowScan's code connectors report for
the repository at that resource, registered under the agent's reference, which the
`id` in `agent.yaml` determines. Keep it where the change under review cannot
write, sign it with `attest`, and check the signature with `verify-attestation`
before ShadowScan reads it, because ShadowScan checks none. See
[Approve agents for ShadowScan reconciliation](shadowscan-inventory-export.md) for
the binding rules, the prefix to use and what the file does not establish.
