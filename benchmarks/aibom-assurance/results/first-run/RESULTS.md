# AAB v1.0 results

Fixture `acme-support-agent`: 76 labelled items, 11 planted risks, 3 decoys. Evidence labels: M measured, D documentation (capped at 60 percent), U unverified (0).

| Rank | Tool | Full-stack | Grade | In-scope | D1 /30 | D2 /15 | D3 /12 | D4 /12 | D5 /10 | D6 /12 | D7 /5 | D8 /4 | Evidence M/D/U |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Nexus SymBiote 0.2.0 (this repository) | **77.8** | B | 77.8 | 20.14 | 9.73 | 6.55 | 11.43 | 10 | 12 | 4 | 4 | 34/1/0 |
| 2 | agent-bom 0.115.3 | **61.8** | C | 61.8 | 17.38 | 5.16 | 8.36 | 9.14 | 5 | 12 | 1.2 | 3.6 | 31/4/0 |
| 3 | cdxgen 13.8.0 (OWASP), `aibom` command | **54.0** | D | 54.0 | 11.17 | 8.14 | 3.82 | 9.71 | 7 | 10 | 1 | 3.2 | 30/5/0 |
| 4 | Cisco AI BOM 1.10.1 (deterministic tiers only) | **52.0** | D | 52.0 | 17.72 | 3.92 | 2 | 10.14 | 4 | 10 | 1 | 3.2 | 30/5/0 |
| 5 | Trusera ai-bom 3.6.0 | **36.5** | F | 36.5 | 7.66 | 3.4 | 1 | 4.86 | 4 | 11 | 1 | 3.6 | 30/5/0 |
| 6 | AIsbom 1.7.0 (model-file scanner) | **36.2** | F | 38.1 | 2.76 | 6.2 | 1.91 | 8.14 | 5 | 9 | 0 | 3.2 | 29/6/0 |
| 7 | OWASP AIBOM Generator (git main, Hugging Face models) | **24.3** | F | 30.0 | 0.43 | 8 | 0 | 5.86 | 0 | 8 | 0 | 2 | 28/6/1 |
| 8 | k8s-aibom (Google Cloud, Kubernetes controller) | **20.2** | F | 56.1 | 0 | 7.2 | 0 | 3.6 | 0 | 5.8 | 3 | 0.6 | 2/14/19 |
| 9 | WasmAgent agentbom-core 0.4.0 (spec and library) | **5.0** | F | 20.0 | 0 | 0 | 0 | 0 | 2 | 3 | 0 | 0 | 7/8/20 |
| 10 | Snyk `snyk aibom` (CLI 1.1308.4) | **4.4** | F | 33.8 | 0 | 0 | 0 | 1.8 | 0 | 2 | 0 | 0.6 | 2/9/24 |

## Discovery recall by family

| Tool | agent | mcp | model | data | tools | Decoys reported |
| --- | --- | --- | --- | --- | --- | --- |
| Nexus SymBiote 0.2.0 (this repository) | 10/12 | 20/21 | 4/14 | 2/8 | 13/21 | - |
| agent-bom 0.115.3 | 6/12 | 18/21 | 7/14 | 0/8 | 19/21 | - |
| cdxgen 13.8.0 (OWASP), `aibom` command | 8/12 | 1/21 | 8/14 | 1/8 | 15/21 | - |
| Cisco AI BOM 1.10.1 (deterministic tiers only) | 7/12 | 14/21 | 9/14 | 2/8 | 16/21 | - |
| Trusera ai-bom 3.6.0 | 2/12 | 6/21 | 5/14 | 0/8 | 14/21 | - |
| AIsbom 1.7.0 (model-file scanner) | 0/12 | 0/21 | 4/14 | 0/8 | 11/21 | - |
| OWASP AIBOM Generator (git main, Hugging Face models) | 0/12 | 0/21 | 1/14 | 0/8 | 0/21 | - |
| k8s-aibom (Google Cloud, Kubernetes controller) | n/a | n/a | n/a | n/a | n/a | - |
| WasmAgent agentbom-core 0.4.0 (spec and library) | n/a | n/a | n/a | n/a | n/a | - |
| Snyk `snyk aibom` (CLI 1.1308.4) | n/a | n/a | n/a | n/a | n/a | - |

## Planted risks surfaced

| Tool | Found | Missed |
| --- | --- | --- |
| Nexus SymBiote 0.2.0 (this repository) | K1, K4, K5, K8, K10 | K2, K3, K6, K7, K9, K11 |
| agent-bom 0.115.3 | K1, K2, K3, K4, K8, K10, K11 | K5, K6, K7, K9 |
| cdxgen 13.8.0 (OWASP), `aibom` command | K7, K11 | K1, K2, K3, K4, K5, K6, K8, K9, K10 |
| Cisco AI BOM 1.10.1 (deterministic tiers only) |  | K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11 |
| Trusera ai-bom 3.6.0 |  | K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11 |
| AIsbom 1.7.0 (model-file scanner) | K5 | K1, K2, K3, K4, K6, K7, K8, K9, K10, K11 |
| OWASP AIBOM Generator (git main, Hugging Face models) |  | K1, K2, K3, K4, K5, K6, K7, K8, K9, K10, K11 |
| k8s-aibom (Google Cloud, Kubernetes controller) | not run | not run |
| WasmAgent agentbom-core 0.4.0 (spec and library) | not run | not run |
| Snyk `snyk aibom` (CLI 1.1308.4) | not run | not run |

## Scanner safety probes

| Tool | Canary (code executed) | Outside sentinel | Credential sentinel | Default-mode egress | Offline-mode egress | Determinism |
| --- | --- | --- | --- | --- | --- | --- |
| Nexus SymBiote 0.2.0 (this repository) | none | confined | absent | none observed | none observed | identical-raw |
| agent-bom 0.115.3 | none | confined | absent | 104.16.0.34:0, 104.16.0.34:443, 104.16.1.34:0, 104.16.1.34:443, 104.16.10.34:0, 104.16.10.34:443, 104.16.11.34:0, 104.16.11.34:443, 104.16.2.34:0, 104.16.2.34:443, 104.16.3.34:0, 104.16.3.34:443, 104.16.4.34:0, 104.16.4.34:443, 104.16.5.34:0, 104.16.5.34:443, 104.16.6.34:0, 104.16.6.34:443, 104.16.7.34:0, 104.16.7.34:443, 104.16.8.34:0, 104.16.8.34:443, 104.16.9.34:0, 104.16.9.34:443, 151.101.0.223:0, 151.101.0.223:443, 151.101.128.223:0, 151.101.128.223:443, 151.101.192.223:0, 151.101.192.223:443, 151.101.64.223:0, 151.101.64.223:443, 8.8.4.4:53, 8.8.8.8:53, api.github.com:443, api.osv.dev:443, www.cisa.gov:443 | none observed | identical-normalized |
| cdxgen 13.8.0 (OWASP), `aibom` command | setup-py-executed | confined | absent | none observed | none observed | identical-normalized |
| Cisco AI BOM 1.10.1 (deterministic tiers only) | none | confined | absent | api.osv.dev:443, huggingface.co:443, raw.githubusercontent.com:443 | no offline mode run | identifier-only |
| Trusera ai-bom 3.6.0 | none | confined | absent | none observed | no offline mode run | identical-normalized |
| AIsbom 1.7.0 (model-file scanner) | none | confined | absent | 151.101.0.223:443, 151.101.128.223:443, 151.101.192.223:443, 151.101.64.223:443, 8.8.8.8:53, api.aisbom.io:443 | none observed | identical-normalized |
| OWASP AIBOM Generator (git main, Hugging Face models) | none | confined | absent | huggingface.co:443 | no offline mode run | differs |
| k8s-aibom (Google Cloud, Kubernetes controller) | not run | not run | not run | not run | not run | not run |
| WasmAgent agentbom-core 0.4.0 (spec and library) | not run | not run | not run | not run | not run | not run |
| Snyk `snyk aibom` (CLI 1.1308.4) | not run | not run | not run | not run | not run | not run |

## Per-tool criteria

### Nexus SymBiote 0.2.0 (this repository): 77.8 (B)

Run as `nexus-symbiote scan <fixture> -f cyclonedx|json|spdx|sarif -o ...` with defaults (offline), plus `trace-diff` against the fixture's OTLP export and `minimum-elements` on the CycloneDX export. The scan gate fails on the fixture (exit 1) by design because the pickle model is a critical finding; the inventory is still written. Conflict of interest: the benchmark lives in this tool's repository; see BENCHMARK.md section 8.


| Criterion | Points | Max | Label | Evidence |
| --- | ---: | ---: | --- | --- |
| D1.agent | 6.67 | 8 | M | 10/12 items |
| D1.mcp | 9.52 | 10 | M | 20/21 items |
| D1.model | 1.71 | 6 | M | 4/14 items |
| D1.data | 1 | 4 | M | 2/8 items |
| D1.tools | 1.24 | 2 | M | 13/21 items |
| D1.decoy_penalty | 0 | 0 | M | none reported |
| D2.locator | 4 | 4 | M | 49/49 matched components carry a locator |
| D2.hash | 3 | 3 | M | 4/4 local artifacts hashed; 4 match the file's SHA-256 |
| D2.version | 0.73 | 3 | M | 12/49 carry a version or revision |
| D2.license | 0 | 2 | M | 0/49 carry a license |
| D2.supplier | 0 | 1 | M | 0/49 carry a supplier, author, publisher or group |
| D2.confidence | 2 | 2 | M | confidence or tier labels on 100% of matched components |
| D3.recall | 4.55 | 10 | M | 5/11 planted risks surfaced |
| D3.quality | 2 | 2 | M | findings carry a code, severity, the offending component and remediation guidance; SARIF rules map to the crosswalk |
| D4.cyclonedx | 3 | 3 | M | 1 document(s) valid against spec 1.7 |
| D4.spdx | 2 | 2 | M | SPDX 3.0.1 JSON-LD: 157 elements, 5 AI-profile, 3 dataset-profile |
| D4.sarif | 2 | 2 | M | valid |
| D4.ml_structures | 3 | 3 | M | typed ML components, modelCard/data, services/formulation/evidence |
| D4.g7 | 1.43 | 2 | M | 5/7 clusters: metadata, system, models, datasets, security |
| D5.determinism | 4 | 4 | M | two default runs identical-raw |
| D5.serial | 1 | 1 | M | serial number identical across runs |
| D5.signing | 3 | 3 | M | `attest` signed the native inventory with an Ed25519 key into a DSSE envelope and `verify-attestation` verified it (attestation_verified true, subject and attested SHA-256 equal) |
| D5.diff | 2 | 2 | M | `diff` compared two collections of the fixture and reported 13 changes, all medium alerts for values left unbound without the source-binding key; exit 1 by design |
| D6.no_exec | 3 | 3 | M | no canary fired in any run |
| D6.confinement | 2 | 2 | M | outside-sentinel absent from every output |
| D6.redaction | 2 | 2 | M | credential sentinel absent from every output |
| D6.offline | 2 | 2 | M | no network attempt in offline |
| D6.pinning | 2 | 2 | M | hash-locked CI environment, Dependabot, OpenSSF Scorecard and release workflows; PyPI release carries PEP 740 provenance attestations |
| D6.security_policy | 1 | 1 | M | SECURITY.md present |
| D7.ingest | 3 | 3 | M | undeclared items surfaced: gpt-4.1-mini, export_customers |
| D7.capability | 1 | 2 | D | `verify-live` compares the inventory with the tools operator-pinned stdio servers serve, and a signed runtime authorization gateway exists; no proxy or cluster inventory; not exercised |
| D8.gate | 1 | 1 | M | scan gate exited 1 on the critical pickle finding; `risk` and `--fail-on-alert` gates documented |
| D8.ci | 1 | 1 | M | SARIF produced for code-scanning upload |
| D8.speed | 1 | 1 | M | default run 2.46s |
| D8.docs | 1 | 1 | M | `nexus-symbiote scan <dir> -f cyclonedx -o file` ran as the CLI reference documents |

Missed items: A5, A8, M10, MD1, MD2, MD3, MD4, MD5, MD10, MD11, MD12, MD13, E1, D1, D2, D3, D4, D5, R1, L12, G1, I1, I2, I3, I4, I5, I6. Default run: 2.46s. CycloneDX validation: {"default-1/bom.cdx.json": ["valid", ""]}

### agent-bom 0.115.3: 61.8 (C)

Run as `agent-bom scan <fixture> -f cyclonedx|json|sarif|spdx` with defaults (vulnerability lookups on) and once with `--offline`. The offline run warns that it needs a pre-populated local vulnerability database and exits 1 while still writing the BOM.


| Criterion | Points | Max | Label | Evidence |
| --- | ---: | ---: | --- | --- |
| D1.agent | 4 | 8 | M | 6/12 items |
| D1.mcp | 8.57 | 10 | M | 18/21 items |
| D1.model | 3 | 6 | M | 7/14 items |
| D1.data | 0 | 4 | M | 0/8 items |
| D1.tools | 1.81 | 2 | M | 19/21 items |
| D1.decoy_penalty | 0 | 0 | M | none reported |
| D2.locator | 0.53 | 4 | M | 4/30 matched components carry a locator |
| D2.hash | 0 | 3 | M | 0/4 local artifacts hashed; 0 match the file's SHA-256 |
| D2.version | 2.3 | 3 | M | 23/30 carry a version or revision |
| D2.license | 0.33 | 2 | M | 5/30 carry a license |
| D2.supplier | 0 | 1 | M | 0/30 carry a supplier, author, publisher or group |
| D2.confidence | 2 | 2 | M | confidence or tier labels on 87% of matched components |
| D3.recall | 6.36 | 10 | M | 7/11 planted risks surfaced |
| D3.quality | 2 | 2 | M | findings carry severity, rule ids and fix guidance in SARIF and the console report |
| D4.cyclonedx | 1 | 3 | M | emitted but invalid: [{'license': {'id': 'SEE LICENSE IN LICENSE'}}] is not valid under any of the given schemas

Failed validating 'oneOf' in schema['properties']['components']['items']['properties']['licenses']:
    {'t |
| D4.spdx | 2 | 2 | M | SPDX 3.0.1 JSON-LD: 1491 elements, 0 AI-profile, 0 dataset-profile |
| D4.sarif | 2 | 2 | M | valid |
| D4.ml_structures | 3 | 3 | M | typed ML components, modelCard/data, services/formulation/evidence |
| D4.g7 | 1.14 | 2 | M | 4/7 clusters: metadata, models, datasets, infrastructure |
| D5.determinism | 4 | 4 | M | two default runs identical-normalized |
| D5.serial | 0 | 1 | M | serial number or digest changes per run |
| D5.signing | 0 | 3 | D | no BOM signing or attestation feature documented |
| D5.diff | 1 | 2 | M | `scan --baseline <report.json> -f json` ran without error but the JSON output and console carried no visible delta section in this run; the HTML report documents deltas |
| D6.no_exec | 3 | 3 | M | no canary fired in any run |
| D6.confinement | 2 | 2 | M | outside-sentinel absent from every output |
| D6.redaction | 2 | 2 | M | credential sentinel absent from every output |
| D6.offline | 2 | 2 | M | no network attempt in offline |
| D6.pinning | 2 | 2 | M | uv.lock, Dependabot and an OpenSSF Scorecard workflow in the repository; PyPI release carries PEP 740 provenance attestations |
| D6.security_policy | 1 | 1 | M | SECURITY.md present |
| D7.ingest | 0 | 3 | D | no ingestion of exported traces against the BOM |
| D7.capability | 1.2 | 2 | D | runtime MCP proxy and gateway that alert on or block injected tool results (`--injection-mode enforce`), and `--introspect` connects to live MCP servers; documented, not exercised |
| D8.gate | 0.6 | 1 | D | --fail-on-severity, --fail-on-kev, --fail-if-ai-risk and --policy |
| D8.ci | 1 | 1 | M | SARIF produced for code-scanning upload |
| D8.speed | 1 | 1 | M | default run 37.41s |
| D8.docs | 1 | 1 | M | `agent-bom scan . -f cyclonedx -o sbom.cdx.json` ran as documented |

Missed items: A1, A2, A3, A4, A6, A8, M7, M10, M11, MD4, MD5, MD10, MD11, MD12, MD13, E1, D1, D2, D3, D4, D5, R1, R2, R3, I3, I4. Default run: 37.41s. CycloneDX validation: {"default-1/bom.cdx.json": ["invalid", "[{'license': {'id': 'SEE LICENSE IN LICENSE'}}] is not valid under any of the given schemas\n\nFailed validating 'oneOf' in schema['properties']['components']['items']['properties']['licenses']:\n    {'title': 'License Choice',\n     'description': 'EITHER (li

### cdxgen 13.8.0 (OWASP), `aibom` command: 54.0 (D)

Run as `aibom <fixture> -o bom.cdx.json` (the AI-BOM entry point) and as plain `cdxgen <fixture> -o bom.cdx.json` (auto-detected project types, which adds the MCP and JavaScript overlays); discovery credit is the union of both documented zero-configuration invocations. Also `--format spdx` and a `--no-install-deps` safe run. The plain `cdxgen` run executed the fixture's `setup.py` while resolving Python metadata with install-deps on, which cdxgen itself warns about on the console; the `aibom` run did not.


| Criterion | Points | Max | Label | Evidence |
| --- | ---: | ---: | --- | --- |
| D1.agent | 5.33 | 8 | M | 8/12 items |
| D1.mcp | 0.48 | 10 | M | 1/21 items |
| D1.model | 3.43 | 6 | M | 8/14 items |
| D1.data | 0.5 | 4 | M | 1/8 items |
| D1.tools | 1.43 | 2 | M | 15/21 items |
| D1.decoy_penalty | 0 | 0 | M | none reported |
| D2.locator | 4 | 4 | M | 33/33 matched components carry a locator |
| D2.hash | 0 | 3 | M | 0/3 local artifacts hashed; 0 match the file's SHA-256 |
| D2.version | 1.36 | 3 | M | 15/33 carry a version or revision |
| D2.license | 0.36 | 2 | M | 6/33 carry a license |
| D2.supplier | 0.42 | 1 | M | 14/33 carry a supplier, author, publisher or group |
| D2.confidence | 2 | 2 | M | confidence or tier labels on 76% of matched components |
| D3.recall | 1.82 | 10 | M | 2/11 planted risks surfaced |
| D3.quality | 2 | 2 | M | bom-audit rules carry stable ids (MCP-009, CISA-MIN-001 style), severity and mitigation text; findings land in annotations and the console report |
| D4.cyclonedx | 3 | 3 | M | 2 document(s) valid against spec 1.7 |
| D4.spdx | 2 | 2 | M | SPDX 3.0.1 JSON-LD: 56 elements, 0 AI-profile, 0 dataset-profile |
| D4.sarif | 0 | 2 | M | no SARIF output |
| D4.ml_structures | 3 | 3 | M | typed ML components, modelCard/data, services/formulation/evidence |
| D4.g7 | 1.71 | 2 | M | 6/7 clusters: metadata, system, models, datasets, infrastructure, security |
| D5.determinism | 4 | 4 | M | two default runs identical-normalized |
| D5.serial | 0 | 1 | M | serial number or digest changes per run |
| D5.signing | 3 | 3 | M | `aibom --generate-key-and-sign` produced a key pair and a BOM with a JSON Signature Format `signature` block (algorithm, publicKey, value); cdx-sign and cdx-verify also exist |
| D5.diff | 0 | 2 | D | no built-in BOM-to-BOM diff; consumers such as Dependency-Track provide it |
| D6.no_exec | 1 | 3 | M | canary fired in default mode (), not in safe mode |
| D6.confinement | 2 | 2 | M | outside-sentinel absent from every output |
| D6.redaction | 2 | 2 | M | credential sentinel absent from every output |
| D6.offline | 2 | 2 | M | no network attempt in safe |
| D6.pinning | 2 | 2 | M | pnpm-lock.yaml and uv.lock in the repository; npm release carries provenance attestations (registry probe) |
| D6.security_policy | 1 | 1 | M | SECURITY.md present |
| D7.ingest | 0 | 3 | D | no ingestion of agent runtime telemetry against a BOM |
| D7.capability | 1 | 2 | D | tracebom profiles running applications and services into CycloneDX 1.7; not agent-specific, not exercised |
| D8.gate | 0.6 | 1 | D | --introspect-fail-below and cdx-audit exit codes gate CI; --fail-on-error |
| D8.ci | 0.6 | 1 | D | official GitHub Action and Dependency-Track upload; no SARIF output observed |
| D8.speed | 1 | 1 | M | default run 7.29s |
| D8.docs | 1 | 1 | M | `aibom .` ran exactly as the AI-BOM guide documents |

Missed items: A1, A3, A6, A8, M1, M2, M3, M4, M6, M7, M8, M9, M10, M11, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, MD5, MD7, MD11, MD12, MD13, E1, D2, D3, D4, D5, R1, R2, R3, G1, I1, I2, I3, I4, I5. Default run: 7.29s. CycloneDX validation: {"autodetect/bom.cdx.json": ["valid", ""], "default-1/bom.cdx.json": ["valid", ""]}

### Cisco AI BOM 1.10.1 (deterministic tiers only): 52.0 (D)

`cisco-aibom analyze` refuses to run without an LLM provider, so the benchmark drove the same `ScanPipeline` class that `cisco-aibom watch` uses (tiers 1 and 2, no agentic stage) and rendered the package's own JSON, CycloneDX, SARIF and SPDX reporters. The vendor's full pipeline sends every candidate to an LLM for confirmation and enrichment; results here are a floor for discovery and may include candidates the LLM stage would have removed.


| Criterion | Points | Max | Label | Evidence |
| --- | ---: | ---: | --- | --- |
| D1.agent | 4.67 | 8 | M | 7/12 items |
| D1.mcp | 6.67 | 10 | M | 14/21 items |
| D1.model | 3.86 | 6 | M | 9/14 items |
| D1.data | 1 | 4 | M | 2/8 items |
| D1.tools | 1.52 | 2 | M | 16/21 items |
| D1.decoy_penalty | 0 | 0 | M | none reported |
| D2.locator | 3.92 | 4 | M | 47/48 matched components carry a locator |
| D2.hash | 0 | 3 | M | 0/5 local artifacts hashed; 0 match the file's SHA-256 |
| D2.version | 0 | 3 | M | 0/48 carry a version or revision |
| D2.license | 0 | 2 | M | 0/48 carry a license |
| D2.supplier | 0 | 1 | M | 0/48 carry a supplier, author, publisher or group |
| D2.confidence | 0 | 2 | M | confidence or tier labels on 0% of matched components |
| D3.recall | 0 | 10 | M | 0/11 planted risks surfaced |
| D3.quality | 2 | 2 | M | risk flags carry severity, weight, description and file location; SARIF rules carry ids |
| D4.cyclonedx | 3 | 3 | M | 1 document(s) valid against spec 1.6 |
| D4.spdx | 2 | 2 | M | SPDX 3.0.1 JSON-LD: 59 elements, 12 AI-profile, 3 dataset-profile |
| D4.sarif | 2 | 2 | M | valid |
| D4.ml_structures | 2 | 3 | M | typed ML components, modelCard/data, services/formulation/evidence |
| D4.g7 | 1.14 | 2 | M | 4/7 clusters: metadata, models, datasets, security |
| D5.determinism | 2 | 4 | M | content identical, but reference identifiers (bom-ref, ids) change between runs |
| D5.serial | 0 | 1 | M | serial number or digest changes per run |
| D5.signing | 0 | 3 | D | no BOM signing or attestation feature documented |
| D5.diff | 2 | 2 | M | `cisco-aibom diff run` compared the two deterministic reports: 58 unchanged components, 0 added, 0 removed, 0 changed |
| D6.no_exec | 3 | 3 | M | no canary fired in any run |
| D6.confinement | 2 | 2 | M | outside-sentinel absent from every output |
| D6.redaction | 2 | 2 | M | credential sentinel absent from every output |
| D6.offline | 0 | 2 | M | no offline flag; the deterministic run queried OSV (403 through the sandbox proxy) and `analyze` needs an LLM endpoint |
| D6.pinning | 2 | 2 | M | aibom/uv.lock in the repository; PyPI release carries PEP 740 provenance attestations |
| D6.security_policy | 1 | 1 | M | SECURITY.md present |
| D7.ingest | 0 | 3 | D | no runtime telemetry ingestion against a BOM |
| D7.capability | 1 | 2 | D | cloud scanning of Bedrock, Vertex AI and Azure AI resources inventories deployed AI assets; `watch` re-scans on change; neither exercised |
| D8.gate | 0.6 | 1 | D | --fail-on severity and --policy YAML gates on `analyze` |
| D8.ci | 1 | 1 | M | SARIF produced for code-scanning upload |
| D8.speed | 1 | 1 | M | default run 96.14s |
| D8.docs | 0.6 | 1 | D | documented quickstart needs an LLM key, so it could not be reproduced here; command syntax matched the CLI help |

Missed items: A1, A4, A7, S3, P1, M7, M9, M10, T6, T7, T8, T9, MD5, MD7, MD10, MD11, MD13, D1, D2, D5, R1, R2, R3, L5, G1, I1, I4, I6. Default run: 96.14s. CycloneDX validation: {"default-1/report.cdx.json": ["valid", ""]}

### Trusera ai-bom 3.6.0: 36.5 (F)

Run as `ai-bom scan <fixture> -f cyclonedx|json|sarif` with defaults, plus one `--deep` run (AST-based Python analysis) that is excluded from discovery credit. Telemetry is opt-in. Last release March 2026.


| Criterion | Points | Max | Label | Evidence |
| --- | ---: | ---: | --- | --- |
| D1.agent | 1.33 | 8 | M | 2/12 items |
| D1.mcp | 2.86 | 10 | M | 6/21 items |
| D1.model | 2.14 | 6 | M | 5/14 items |
| D1.data | 0 | 4 | M | 0/8 items |
| D1.tools | 1.33 | 2 | M | 14/21 items |
| D1.decoy_penalty | 0 | 0 | M | none reported |
| D2.locator | 2.96 | 4 | M | 20/27 matched components carry a locator |
| D2.hash | 0 | 3 | M | 0/3 local artifacts hashed; 0 match the file's SHA-256 |
| D2.version | 0.44 | 3 | M | 4/27 carry a version or revision |
| D2.license | 0 | 2 | M | 0/27 carry a license |
| D2.supplier | 0 | 1 | M | 0/27 carry a supplier, author, publisher or group |
| D2.confidence | 0 | 2 | M | confidence or tier labels on 0% of matched components |
| D3.recall | 0 | 10 | M | 0/11 planted risks surfaced |
| D3.quality | 1 | 2 | M | components carry a risk score and risk factors; SARIF results exist but findings are per-component flags rather than discrete rules with remediation |
| D4.cyclonedx | 1 | 3 | M | emitted but invalid: 'service' is not one of ['application', 'framework', 'library', 'container', 'platform', 'operating-system', 'device', 'device-driver', 'firmware', 'file', 'machine-learning-model', 'data', 'cryptogra |
| D4.spdx | 0 | 2 | M | no SPDX output |
| D4.sarif | 2 | 2 | M | valid |
| D4.ml_structures | 1 | 3 | M | typed ML components, modelCard/data, services/formulation/evidence |
| D4.g7 | 0.86 | 2 | M | 3/7 clusters: metadata, models, infrastructure |
| D5.determinism | 4 | 4 | M | two default runs identical-normalized |
| D5.serial | 0 | 1 | M | serial number or digest changes per run |
| D5.signing | 0 | 3 | D | no BOM signing or attestation feature documented |
| D5.diff | 0 | 2 | D | no BOM diff; `--save-dashboard` stores history for the Trusera dashboard |
| D6.no_exec | 3 | 3 | M | no canary fired in any run |
| D6.confinement | 2 | 2 | M | outside-sentinel absent from every output |
| D6.redaction | 2 | 2 | M | credential sentinel absent from every output |
| D6.offline | 2 | 2 | M | no offline flag, but the default run made no network attempt |
| D6.pinning | 1 | 2 | M | no lockfile in the repository (Dependabot only); PyPI release carries PEP 740 provenance attestations |
| D6.security_policy | 1 | 1 | M | SECURITY.md present |
| D7.ingest | 0 | 3 | D | no runtime telemetry ingestion against a BOM |
| D7.capability | 1 | 2 | D | separate Trusera runtime SDKs evaluate Cedar policies on agent HTTP calls; not part of the scanner, not exercised |
| D8.gate | 0.6 | 1 | D | --fail-on severity and --policy YAML |
| D8.ci | 1 | 1 | M | SARIF produced for code-scanning upload |
| D8.speed | 1 | 1 | M | default run 1.72s |
| D8.docs | 1 | 1 | M | `ai-bom scan . -f cyclonedx -o ai-bom.cdx.json` ran as documented |

Missed items: A1, A2, A3, A4, A6, A7, S1, S2, S3, P1, M2, M7, M8, M9, M10, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, MD1, MD3, MD4, MD5, MD7, MD10, MD11, MD13, E1, D1, D2, D3, D4, D5, R1, R2, R3, L5, L11, L12, L14, G1, I1, I5. Default run: 1.72s. CycloneDX validation: {"default-1/bom.cdx.json": ["invalid", "'service' is not one of ['application', 'framework', 'library', 'container', 'platform', 'operating-system', 'device', 'device-driver', 'firmware', 'file', 'machine-learning-model', 'data', 'cryptographic-asset']\n\nFailed validating 'enum' in schema['properti

### AIsbom 1.7.0 (model-file scanner): 36.2 (F)

A static scanner for model files (pickle, Keras, GGUF, ONNX, safetensors) that also lists Python requirements. Run as `aisbom scan <fixture> --format json|spdx --output ...` and once with `--offline`. Agents, MCP servers, skills and datasets are outside its claimed scope, so its in-scope score covers only the model and tools families.


| Criterion | Points | Max | Label | Evidence |
| --- | ---: | ---: | --- | --- |
| D1.agent | 0 | 8 | M | 0/12 items |
| D1.mcp | 0 | 10 | M | 0/21 items |
| D1.model | 1.71 | 6 | M | 4/14 items |
| D1.data | 0 | 4 | M | 0/8 items |
| D1.tools | 1.05 | 2 | M | 11/21 items |
| D1.decoy_penalty | 0 | 0 | M | none reported |
| D2.locator | 0 | 4 | M | 0/15 matched components carry a locator |
| D2.hash | 3 | 3 | M | 4/4 local artifacts hashed; 4 match the file's SHA-256 |
| D2.version | 2 | 3 | M | 10/15 carry a version or revision |
| D2.license | 1.2 | 2 | M | 9/15 carry a license |
| D2.supplier | 0 | 1 | M | 0/15 carry a supplier, author, publisher or group |
| D2.confidence | 0 | 2 | M | confidence or tier labels on 0% of matched components |
| D3.recall | 0.91 | 10 | M | 1/11 planted risks surfaced |
| D3.quality | 1 | 2 | M | per-file risk and legal columns with a severity label; no remediation text or stable rule ids in the BOM |
| D4.cyclonedx | 3 | 3 | M | 1 document(s) valid against spec 1.7 |
| D4.spdx | 2 | 2 | M | SPDX 3.0.1 JSON-LD: 24 elements, 4 AI-profile, 0 dataset-profile |
| D4.sarif | 0 | 2 | M | no SARIF output |
| D4.ml_structures | 2 | 3 | M | typed ML components, modelCard/data, services/formulation/evidence |
| D4.g7 | 1.14 | 2 | M | 4/7 clusters: metadata, models, datasets, security |
| D5.determinism | 4 | 4 | M | two default runs identical-normalized |
| D5.serial | 0 | 1 | M | serial number or digest changes per run |
| D5.signing | 0 | 3 | D | no BOM signing or attestation feature documented |
| D5.diff | 1 | 2 | D | `--vex-baseline` compares against a previous SBOM to emit VEX; a partial diff, not exercised |
| D6.no_exec | 3 | 3 | M | no canary fired in any run |
| D6.confinement | 2 | 2 | M | outside-sentinel absent from every output |
| D6.redaction | 2 | 2 | M | credential sentinel absent from every output |
| D6.offline | 1 | 2 | M | offline mode is quiet, but the default mode phones home to api.aisbom.io |
| D6.pinning | 1 | 2 | M | poetry.lock in the repository; PyPI release has no provenance attestation (HTTP 404 on the integrity endpoint) |
| D6.security_policy | 0 | 1 | M | no SECURITY.md found at the repository root |
| D7.ingest | 0 | 3 | D | not in scope |
| D7.capability | 0 | 2 | D | not in scope |
| D8.gate | 0.6 | 1 | D | --fail-on-risk returns exit code 2 |
| D8.ci | 0.6 | 1 | D | GitHub Action on the Marketplace posts a PR comment; no SARIF output |
| D8.speed | 1 | 1 | M | default run 1.68s |
| D8.docs | 1 | 1 | M | `aisbom scan <dir>` ran as documented |

Missed items: A1, A2, A3, A4, A5, A6, A7, A8, S1, S2, S3, P1, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, MD1, MD2, MD3, MD4, MD5, MD10, MD11, MD12, MD13, E1, D1, D2, D3, D4, D5, R1, R2, R3, L12, L13, L14, G1, I1, I2, I3, I4, I5, I6. Default run: 1.68s. CycloneDX validation: {"default-1/bom.cdx.json": ["valid", ""]}

### OWASP AIBOM Generator (git main, Hugging Face models): 24.3 (F)

Generates one AIBOM per Hugging Face model id; it does not scan repositories. The benchmark ran it on the fixture's pinned DistilBERT model (`python -m src.cli <model> -o aibom.json`), so discovery credit can only reach that one model item. It needs the Hugging Face API by design.


| Criterion | Points | Max | Label | Evidence |
| --- | ---: | ---: | --- | --- |
| D1.agent | 0 | 8 | M | 0/12 items |
| D1.mcp | 0 | 10 | M | 0/21 items |
| D1.model | 0.43 | 6 | M | 1/14 items |
| D1.data | 0 | 4 | M | 0/8 items |
| D1.tools | 0 | 2 | M | 0/21 items |
| D1.decoy_penalty | 0 | 0 | M | none reported |
| D2.locator | 4 | 4 | M | 1/1 matched components carry a locator |
| D2.hash | 0 | 3 | M | 0/0 local artifacts hashed; 0 match the file's SHA-256 |
| D2.version | 3 | 3 | M | 1/1 carry a version or revision |
| D2.license | 0 | 2 | M | 0/1 carry a license |
| D2.supplier | 1 | 1 | M | 1/1 carry a supplier, author, publisher or group |
| D2.confidence | 0 | 2 | M | confidence or tier labels on 0% of matched components |
| D3.recall | 0 | 10 | M | 0/11 planted risks surfaced |
| D3.quality | 0 | 2 | M | produces a completeness score with recommendations, not security findings |
| D4.cyclonedx | 3 | 3 | M | 2 document(s) valid against spec 1.6 |
| D4.spdx | 0 | 2 | M | no SPDX output |
| D4.sarif | 0 | 2 | M | no SARIF output |
| D4.ml_structures | 2 | 3 | M | typed ML components, modelCard/data, services/formulation/evidence |
| D4.g7 | 0.86 | 2 | M | 3/7 clusters: metadata, system, models |
| D5.determinism | 0 | 4 | M | outputs differ after normalization: {"aibom.json": ["metadata"], "aibom_1_7.json": ["metadata"]} |
| D5.serial | 0 | 1 | M | serial number or digest changes per run |
| D5.signing | 0 | 3 | D | no BOM signing or attestation feature documented |
| D5.diff | 0 | 2 | D | no diff feature |
| D6.no_exec | 3 | 3 | M | no canary fired in any run |
| D6.confinement | 2 | 2 | M | outside-sentinel absent from every output |
| D6.redaction | 2 | 2 | M | credential sentinel absent from every output |
| D6.offline | 0 | 2 | U | no rubric entry |
| D6.pinning | 1 | 2 | M | uv.lock in the repository; distributed from git, no package release to attest |
| D6.security_policy | 0 | 1 | M | no SECURITY.md found at the repository root |
| D7.ingest | 0 | 3 | D | not in scope |
| D7.capability | 0 | 2 | D | not in scope |
| D8.gate | 0 | 1 | D | no pass or fail gate; completeness score only |
| D8.ci | 0 | 1 | D | web UI and HTTP API; no SARIF or CI action |
| D8.speed | 1 | 1 | M | default run 22.73s |
| D8.docs | 1 | 1 | M | ran as the README documents |

Missed items: A1, A2, A3, A4, A5, A6, A7, A8, S1, S2, S3, P1, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, MD1, MD2, MD3, MD5, MD6, MD7, MD8, MD9, MD10, MD11, MD12, MD13, E1, D1, D2, D3, D4, D5, R1, R2, R3, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, G1, I1, I2, I3, I4, I5, I6. Default run: 22.73s. CycloneDX validation: {"default-1/aibom.json": ["valid", ""], "default-1/aibom_1_7.json": ["valid", ""]}

### k8s-aibom (Google Cloud, Kubernetes controller): 20.2 (F)

Not run: A Kubernetes controller that inventories running AI workloads. This sandbox has no container runtime or cluster, so nothing could be measured. Criteria are from the project README (D) or unverifiable (U). It is a runtime tool; a static fixture is not its input.


| Criterion | Points | Max | Label | Evidence |
| --- | ---: | ---: | --- | --- |
| D1.agent | 0 | 8 | U | static fixture is not its input |
| D1.mcp | 0 | 10 | U | static fixture is not its input |
| D1.model | 0 | 6 | U | would inventory served models from running pods; not measurable here |
| D1.data | 0 | 4 | U | static fixture is not its input |
| D1.tools | 0 | 2 | U | would inventory runtime containers; not measurable here |
| D1.decoy_penalty | 0 | 0 | U | none reported |
| D2.locator | 2.4 | 4 | D | README: an evidence locator for every attribute |
| D2.hash | 1.8 | 3 | D | image digests once pulled; model identity verified against Sigstore or OpenSSF Model Signing since v1.5.0 |
| D2.version | 1.8 | 3 | D | runtime and model versions where declared or inferred |
| D2.license | 0 | 2 | U | not documented |
| D2.supplier | 0 | 1 | U | not documented |
| D2.confidence | 1.2 | 2 | D | declared, verified, inferred and unresolved tiers per attribute |
| D3.recall | 0 | 10 | U | not measurable here |
| D3.quality | 0 | 2 | U | not measurable here |
| D4.cyclonedx | 1.8 | 3 | D | CycloneDX 1.6 ML-BOM documents |
| D4.spdx | 0 | 2 | D | no SPDX output documented |
| D4.sarif | 0 | 2 | D | no SARIF output documented |
| D4.ml_structures | 1.8 | 3 | D | ML-BOM with machine-learning-model components; modelCard use not confirmed |
| D4.g7 | 0 | 2 | U | not measurable here |
| D5.determinism | 0 | 4 | U | runtime state changes; not measurable here |
| D5.serial | 0 | 1 | U | not measurable here |
| D5.signing | 0 | 3 | U | verifies model signatures; signing of the emitted BOM not documented |
| D5.diff | 0 | 2 | D | write-once storage sink; no BOM diff documented |
| D6.no_exec | 1.8 | 3 | D | observes through the Kubernetes API only; no privileged container, DaemonSet or node agent |
| D6.confinement | 0 | 2 | U | not applicable to a cluster controller; not measured |
| D6.redaction | 0 | 2 | U | not measured |
| D6.offline | 1 | 2 | D | in-cluster operation with air-gapped trust-root files supported |
| D6.pinning | 2 | 2 | M | go.sum and an OpenSSF Scorecard workflow in the repository; Helm chart on ghcr.io |
| D6.security_policy | 1 | 1 | M | SECURITY.md present |
| D7.ingest | 1.8 | 3 | D | builds the BOM from runtime state and separates declared from inferred and unresolved attributes; does not compare against a pre-declared BOM |
| D7.capability | 1.2 | 2 | D | unprivileged controller inventories inference services, agent stacks, RAG pipelines and training jobs at runtime |
| D8.gate | 0 | 1 | U | not documented |
| D8.ci | 0.6 | 1 | D | Helm chart and Artifact Hub listing; GKE blueprint integration |
| D8.speed | 0 | 1 | U | not measurable here |
| D8.docs | 0 | 1 | U | not reproducible here |

### WasmAgent agentbom-core 0.4.0 (spec and library): 5.0 (F)

Not run: A TypeScript library that validates, compliance-checks and diffs documents in its own AgentBOM format. It does not discover components, so there is no scan to run against the fixture. The library's validate, compliance and diff functions were exercised on a hand-written document (see RESULTS.md); everything else is from its README.


| Criterion | Points | Max | Label | Evidence |
| --- | ---: | ---: | --- | --- |
| D1.agent | 0 | 8 | U | no discovery |
| D1.mcp | 0 | 10 | U | no discovery |
| D1.model | 0 | 6 | U | no discovery |
| D1.data | 0 | 4 | U | no discovery |
| D1.tools | 0 | 2 | U | no discovery |
| D1.decoy_penalty | 0 | 0 | U | none reported |
| D2.locator | 0 | 4 | U | no discovery |
| D2.hash | 0 | 3 | U | no discovery |
| D2.version | 0 | 3 | U | no discovery |
| D2.license | 0 | 2 | U | no discovery |
| D2.supplier | 0 | 1 | U | no discovery |
| D2.confidence | 0 | 2 | U | no discovery |
| D3.recall | 0 | 10 | U | no scanner; compliance rules apply to a document the user supplies |
| D3.quality | 0 | 2 | M | checkCompliance threw TypeError with the README's options object and with two guessed profile shapes on 0.4.0; no findings could be produced |
| D4.cyclonedx | 0 | 3 | D | own JSON format; alignment with the CycloneDX Agent BOM proposal is stated, no CycloneDX output |
| D4.spdx | 0 | 2 | D | none |
| D4.sarif | 0 | 2 | D | none |
| D4.ml_structures | 0 | 3 | D | own format |
| D4.g7 | 0 | 2 | U | not applicable |
| D5.determinism | 0 | 4 | U | no generation step |
| D5.serial | 0 | 1 | U | no generation step |
| D5.signing | 1 | 3 | D | compliance rule `require_signed` checks a signature field; no signing implementation |
| D5.diff | 1 | 2 | M | diffAgentBOM ran and returned tools, permissions and risks sections; the README's buildDriftAlert does not exist in 0.4.0 and createDriftAlert plus formatDriftAlert threw on a guessed input |
| D6.no_exec | 0 | 3 | U | no scanner |
| D6.confinement | 0 | 2 | U | no scanner |
| D6.redaction | 0 | 2 | U | no scanner |
| D6.offline | 2 | 2 | M | pure functions; no network use |
| D6.pinning | 1 | 2 | M | npm release carries provenance attestations; no lockfile found at the repository root |
| D6.security_policy | 0 | 1 | M | no SECURITY.md found |
| D7.ingest | 0 | 3 | D | none |
| D7.capability | 0 | 2 | D | none |
| D8.gate | 0 | 1 | M | checkCompliance, the documented gate, could not be run (TypeError) |
| D8.ci | 0 | 1 | D | library only |
| D8.speed | 0 | 1 | U | no scan |
| D8.docs | 0 | 1 | M | README examples do not run on 0.4.0: validateAgentBOM works, but the documented tools shape fails validation, checkCompliance throws and buildDriftAlert is not exported |

### Snyk `snyk aibom` (CLI 1.1308.4): 4.4 (F)

Not run: The Snyk CLI wrapper could not download its binary through the sandbox proxy, and the `aibom` command requires a Snyk account and sends the project to Snyk's hosted analysis. Every criterion below is from Snyk's documentation (D) or unverifiable (U).


| Criterion | Points | Max | Label | Evidence |
| --- | ---: | ---: | --- | --- |
| D1.agent | 0 | 8 | U | documentation lists agents and tools; recall not measurable here |
| D1.mcp | 0 | 10 | U | documentation lists MCP servers; recall not measurable here |
| D1.model | 0 | 6 | U | documentation lists models; recall not measurable here |
| D1.data | 0 | 4 | U | documentation lists datasets; recall not measurable here |
| D1.tools | 0 | 2 | U | documentation lists AI libraries; recall not measurable here |
| D1.decoy_penalty | 0 | 0 | U | none reported |
| D2.locator | 0 | 4 | U | not observable |
| D2.hash | 0 | 3 | U | not observable |
| D2.version | 0 | 3 | U | not observable |
| D2.license | 0 | 2 | U | not observable |
| D2.supplier | 0 | 1 | U | not observable |
| D2.confidence | 0 | 2 | U | not observable |
| D3.recall | 0 | 10 | U | not observable |
| D3.quality | 0 | 2 | U | not observable |
| D4.cyclonedx | 1.8 | 3 | D | documented output is CycloneDX 1.6 JSON |
| D4.spdx | 0 | 2 | D | no SPDX output documented |
| D4.sarif | 0 | 2 | D | no SARIF output documented; HTML report via --html |
| D4.ml_structures | 0 | 3 | U | not observable |
| D4.g7 | 0 | 2 | U | not observable |
| D5.determinism | 0 | 4 | U | not observable |
| D5.serial | 0 | 1 | U | not observable |
| D5.signing | 0 | 3 | D | no BOM signing documented |
| D5.diff | 0 | 2 | D | no BOM diff documented |
| D6.no_exec | 0 | 3 | U | not observable |
| D6.confinement | 0 | 2 | U | not observable |
| D6.redaction | 0 | 2 | U | not observable |
| D6.offline | 0 | 2 | D | requires an internet connection and a Snyk account; the project is analysed by Snyk's service |
| D6.pinning | 1 | 2 | M | package-lock.json in snyk/cli; npm release signed but without provenance attestations (registry probe) |
| D6.security_policy | 1 | 1 | M | SECURITY.md present in snyk/cli |
| D7.ingest | 0 | 3 | D | not documented |
| D7.capability | 0 | 2 | D | not documented |
| D8.gate | 0 | 1 | U | no fail-on option documented for `snyk aibom` |
| D8.ci | 0.6 | 1 | D | Snyk CLI runs in every major CI; JSON output pipes into the open-source aibom viewer |
| D8.speed | 0 | 1 | U | not observable |
| D8.docs | 0 | 1 | U | not reproducible here |

