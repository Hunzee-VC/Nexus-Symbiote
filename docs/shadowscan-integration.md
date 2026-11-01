# ShadowScan discovery and Nexus SymBiote verification

Run Nexus-ShadowScan separately with the least privileges needed for the chosen
connectors and save its JSON report. Keep the report under appropriate access and
retention controls. For example, following the ShadowScan version's own CLI help:

```sh
shadowscan code /path/to/repository --format json -o shadowscan.json
nexus-symbiote import-shadowscan shadowscan.json -o agentbom.json
nexus-symbiote import-shadowscan shadowscan.json --format cyclonedx -o agentbom.cdx.json
nexus-symbiote verify-discovery agentbom.json shadowscan.json
nexus-symbiote validate agentbom.json --project /path/to/repository
```

The output path must not exist. An incomplete source produces a partial BOM and
nonzero exit; a malformed or unsupported report is rejected. A locally generated
report digest binds the imported bytes, not the identity of their producer or the
truth of their contents. Verification of signatures, sources and artifacts is a
separate operation; this importer does not perform it. Do not infer production
activity, effective access or authorization from a finding or inventory mismatch.
`verify-discovery` compares exact report bytes with the native BOM's recorded
digest. It does not authenticate either the BOM or the report.

The importer maps native `agent`, `mcp-server` and `local-model` findings. It
also accepts ShadowScan's CycloneDX 1.6/1.7 components and services, marking the
projection partial. Unmapped entries are counted with source indexes. For
CycloneDX, the index is into components followed by services. The source report
and its scope, timestamps, detailed evidence, identities and graph remain the
authoritative discovery record; those fields are not duplicated into the BOM.
This reduces leakage but does not turn the BOM into a complete evidence graph.

All imported components have declared assurance and unknown trust. The importer
does not run ShadowScan, execute tools, fetch endpoints, infer agent autonomy, or
promote a signature filename into verified evidence. ShadowScan risk and shadow
flags remain source-reported heuristics; an inventory mismatch is not proof of
unauthorized activity. Output contains report and source-ID digests and indexes,
not raw source descriptions, locations or snippets. Both artifacts may still be
sensitive and must be handled accordingly.

At present the bridge does not resolve agents across tenants or reports, verify
live MCP identities, or map every ShadowScan finding type, model association or
dependency. A complete ShadowScan run is only complete for its configured scope;
Nexus SymBiote records the imported BOM coverage as partial. SPDX and SARIF are not
available for imported discovery until their coverage and provenance mappings
are validated.
