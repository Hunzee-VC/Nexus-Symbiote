# AIBOM-Bench results

Benchmark 1.1.0, corpus 1.1.0 `7d99ff052f0f0bec`: 92 components, 8 decoys, 20 planted risks, 10 planted changes, 8 hostile-input cases. Scored scans ran with no network.

† The score is a floor: the tool could not run as designed here. See the notes below.

## Scores

| Tool | Version | Total | Grade | Discovery | Precision | Record fidelity | Standards | BOM integrity | Risk analysis | Change detection | Scanner safety |
| --- | --- | ---: | :---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ShadowScan + SymBiote | ShadowScan 0.1.4, SymBiote 0.2.0 | **69.4** | C | 15.6/30 | 1.5/4 | 11.5/14 | 8.6/10 | 6.7/10 | 7.8/12 | 6.2/8 | 11.5/12 |
| Nexus SymBiote | 0.2.0 (this checkout) | **67.9** | C | 13.2/30 | 1.5/4 | 11.3/14 | 8.7/10 | 10.0/10 | 7.0/12 | 6.2/8 | 9.9/12 |
| agent-bom | 0.115.4 | **65.4** | C | 15.7/30 | 2.0/4 | 10.0/14 | 8.7/10 | 9.7/10 | 6.9/12 | 4.0/8 | 8.5/12 |
| OWASP cdxgen | 13.8.0 | **51.1** | D | 13.5/30 | 3.0/4 | 8.9/14 | 10.0/10 | 6.4/10 | 1.8/12 | 1.9/8 | 5.6/12 |
| Cisco AI BOM † | 1.10.1 | **48.6** | D | 16.1/30 | 3.0/4 | 8.2/14 | 6.6/10 | 3.8/10 | 1.0/12 | 2.2/8 | 7.8/12 |
| AIROM | 0.4.7 | **45.0** | D | 11.6/30 | 2.0/4 | 8.9/14 | 8.6/10 | 3.8/10 | 2.2/12 | 1.9/8 | 6.0/12 |
| Nexus ShadowScan | 0.1.4 (commit 2b80f19) | **44.4** | D | 10.0/30 | 2.5/4 | 5.8/14 | 5.5/10 | 3.6/10 | 5.1/12 | 3.0/8 | 8.8/12 |
| Trusera ai-bom | 3.6.0 | **32.2** | E | 10.7/30 | 1.0/4 | 5.2/14 | 5.2/10 | 0.0/10 | 0.4/12 | 1.9/8 | 7.8/12 |
| Anchore Syft | 1.57.2 | **27.7** | E | 4.3/30 | 0.5/4 | 8.1/14 | 5.7/10 | 3.7/10 | 0.0/12 | 0.0/8 | 5.3/12 |
| AIsbom | 1.7.0 | **26.1** | E | 4.2/30 | 0.5/4 | 6.2/14 | 6.4/10 | 2.4/10 | 2.2/12 | 1.6/8 | 2.6/12 |
| Snyk Agent Scan † | 0.6.11 | **18.1** | F | 1.7/30 | 0.5/4 | 5.4/14 | 0.0/10 | 5.0/10 | 0.0/12 | 2.4/8 | 3.1/12 |
| OWASP AIBOM Generator | commit 45851cb | not graded | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |

## Points by criterion

| Criterion | Max | ShadowScan + SymBiote | Nexus SymBiote | agent-bom | OWASP cdxgen | Cisco AI BOM | AIROM | Nexus ShadowScan | Trusera ai-bom | Anchore Syft | AIsbom | Snyk Agent Scan |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1.1 Models | 7 | 1.9 | 1.9 | 3.9 | 4.7 | 4.7 | 4.7 | 2.3 | 2.3 | 1.2 | 1.9 | 0.0 |
| 1.2 Data | 6 | 1.1 | 0.6 | 1.1 | 0.6 | 2.2 | 3.3 | 1.1 | 0.6 | 0.0 | 0.0 | 0.0 |
| 1.3 Tools and frameworks | 5 | 4.4 | 4.2 | 4.7 | 3.1 | 4.4 | 2.5 | 1.1 | 2.5 | 2.8 | 2.2 | 0.0 |
| 1.4 Agent components | 9 | 7.0 | 6.6 | 4.9 | 4.9 | 4.4 | 0.7 | 4.4 | 2.7 | 0.0 | 0.0 | 1.7 |
| 1.5 Infrastructure and deployment | 3 | 1.1 | 0.0 | 1.1 | 0.4 | 0.4 | 0.4 | 1.1 | 2.6 | 0.4 | 0.0 | 0.0 |
| 2.1 Decoy resistance | 4 | 1.5 | 1.5 | 2.0 | 3.0 | 3.0 | 2.0 | 2.5 | 1.0 | 0.5 | 0.5 | 0.5 |
| 3.1 Version and supplier | 4 | 3.8 | 3.7 | 4.0 | 3.9 | 3.8 | 3.4 | 3.0 | 2.0 | 4.0 | 4.0 | 1.0 |
| 3.2 Content digests | 3 | 3.0 | 3.0 | 1.9 | 0.0 | 0.0 | 1.5 | 0.0 | 0.0 | 0.0 | 1.9 | 0.0 |
| 3.3 Evidence location | 3 | 2.8 | 3.0 | 2.5 | 3.0 | 3.0 | 2.9 | 0.9 | 2.2 | 3.0 | 0.0 | 2.6 |
| 3.4 Domain facts and licence | 2 | 1.6 | 1.3 | 1.0 | 1.5 | 1.1 | 0.8 | 1.9 | 1.0 | 1.1 | 0.3 | 1.8 |
| 3.5 Relationships | 2 | 0.3 | 0.3 | 0.6 | 0.6 | 0.3 | 0.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| 4.1 CycloneDX output validates | 3 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 | 1.5 | 3.0 | 3.0 | 0.0 |
| 4.2 SPDX output validates | 2 | 2.0 | 2.0 | 2.0 | 2.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 2.0 | 0.0 |
| 4.3 AI vocabulary in CycloneDX | 2 | 1.0 | 1.0 | 1.5 | 2.0 | 1.6 | 2.0 | 1.0 | 1.0 | 1.0 | 1.4 | 0.0 |
| 4.4 Package URLs | 1 | 0.6 | 0.7 | 0.7 | 1.0 | 0.0 | 0.6 | 0.0 | 0.7 | 0.7 | 0.0 | 0.0 |
| 4.5 SARIF output validates | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 |
| 4.6 Minimum-element or framework reporting (assessed) | 1 | 1.0 | 1.0 | 0.5 | 1.0 | 0.0 | 1.0 | 0.5 | 0.0 | 0.0 | 0.0 | 0.0 |
| 5.1 Deterministic output | 4 | 0.7 | 4.0 | 3.7 | 2.4 | 2.8 | 2.8 | 1.6 | 0.0 | 2.9 | 2.4 | 4.0 |
| 5.2 Signing, attestation and verification (assessed) | 3 | 3.0 | 3.0 | 3.0 | 3.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.8 | 0.0 | 0.0 |
| 5.3 Reports what it could not read | 1 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| 5.4 States collection scope and coverage (assessed) | 1 | 1.0 | 1.0 | 1.0 | 0.0 | 0.5 | 0.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| 5.5 Evidence typing per record (assessed) | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 0.5 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| 6.1 Planted-risk recall | 8 | 4.6 | 3.8 | 4.2 | 0.8 | 0.0 | 0.4 | 3.8 | 0.4 | 0.0 | 0.4 | 0.0 |
| 6.2 Clean controls not flagged | 2 | 1.7 | 1.7 | 1.7 | 1.0 | 0.0 | 0.3 | 1.3 | 0.0 | 0.0 | 0.3 | 0.0 |
| 6.3 Advisory mapping and VEX (assessed) | 2 | 1.5 | 1.5 | 1.0 | 0.0 | 1.0 | 1.5 | 0.0 | 0.0 | 0.0 | 1.5 | 0.0 |
| 7.1 Changes visible in the BOM | 3 | 2.1 | 2.1 | 2.1 | 0.6 | 0.9 | 0.6 | 1.5 | 0.6 | 0.0 | 0.3 | 0.9 |
| 7.2 Native drift report | 3 | 2.1 | 2.1 | 0.6 | 0.0 | 0.3 | 0.3 | 0.3 | 0.0 | 0.0 | 0.3 | 0.0 |
| 7.3 CI and policy gate (assessed) | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 |
| 7.4 Runtime reconciliation (assessed) | 1 | 1.0 | 1.0 | 0.2 | 0.2 | 0.0 | 0.0 | 0.2 | 0.2 | 0.0 | 0.0 | 0.5 |
| 8.1 Executes nothing from the project | 4 | 4.0 | 3.4 | 4.0 | 0.0 | 3.4 | 2.3 | 2.9 | 2.9 | 1.1 | 1.1 | 1.1 |
| 8.2 Stays inside the project | 2 | 2.0 | 2.0 | 0.0 | 1.3 | 1.3 | 0.7 | 0.7 | 0.7 | 0.7 | 0.0 | 0.0 |
| 8.3 Does not disclose secrets | 2 | 2.0 | 1.0 | 1.5 | 1.0 | 1.0 | 0.0 | 2.0 | 1.5 | 0.0 | 0.0 | 0.0 |
| 8.4 Neutralizes hostile names | 1 | 0.5 | 0.5 | 1.0 | 1.0 | 0.0 | 0.5 | 0.5 | 0.0 | 0.5 | 0.0 | 0.5 |
| 8.5 Survives hostile input | 2 | 2.0 | 2.0 | 1.5 | 1.8 | 1.5 | 2.0 | 1.8 | 1.8 | 2.0 | 1.0 | 0.5 |
| 8.6 Works offline, attempts no egress | 1 | 1.0 | 1.0 | 0.5 | 0.5 | 0.5 | 0.5 | 1.0 | 1.0 | 1.0 | 0.5 | 1.0 |

## Measurements

| Tool | Component recall | Risks caught | Changes visible | Decoys reported / faced | Canaries tripped / faced | Secrets disclosed / faced | Hostile cases passed / faced | Default-command egress attempts | Scan time |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ShadowScan + SymBiote | 60% | 11/19 | 7/10 | 1/4 | 0/7 | 0/4 | 8/8 | 0 | 17.4 s |
| Nexus SymBiote | 52% | 9/19 | 7/10 | 1/4 | 0/6 | 0/2 | 8/8 | 0 | 10.9 s |
| agent-bom | 56% | 10/19 | 7/10 | 1/5 | 0/7 | 0/3 | 6/8 | 2 | 13.0 s |
| OWASP cdxgen | 49% | 2/19 | 2/10 | 1/7 | 1/5 | 0/2 | 7/8 | 2 | 13.4 s |
| Cisco AI BOM † | 55% | 0/19 | 3/10 | 1/7 | 0/6 | 0/2 | 6/8 | 2 | 106.5 s |
| AIROM | 34% | 1/19 | 2/10 | 0/4 | 0/4 | 0/0 | 8/8 | 2 | 0.1 s |
| Nexus ShadowScan | 36% | 9/19 | 5/10 | 0/5 | 0/5 | 0/4 | 7/7 | 0 | 9.2 s |
| Trusera ai-bom | 37% | 1/19 | 2/10 | 2/4 | 0/5 | 1/4 | 7/8 | 0 | 4.4 s |
| Anchore Syft | 15% | 0/19 | 0/10 | 0/1 | 0/2 | 0/0 | 8/8 | 0 | 2.1 s |
| AIsbom | 14% | 1/19 | 1/10 | 0/1 | 0/2 | 0/0 | 4/4 | 2 | 2.3 s |
| Snyk Agent Scan † | 8% | 0/19 | 3/10 | 0/1 | 0/2 | 0/0 | 2/2 | 0 | 3.3 s |

## Sensitivity to the weights

Each cell is the tool's total out of 100, and its rank, under a different weighting. A ranking that changes with the weights is a judgement, not a measurement.

| Tool | declared weights | equal weight per group | measured criteria only | inventory only (groups 1 to 3) | without scanner safety | without BOM integrity | Rank range |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| ShadowScan + SymBiote | 69.4 (#1) | 70.4 (#2) | 66.6 (#1) | 59.7 (#1) | 65.8 (#1) | 69.7 (#1) | 1 to 2 |
| Nexus SymBiote | 67.9 (#2) | 71.0 (#1) | 64.8 (#2) | 54.3 (#4) | 65.8 (#2) | 64.3 (#2) | 1 to 4 |
| agent-bom | 65.4 (#3) | 66.9 (#3) | 64.1 (#3) | 57.7 (#2) | 64.7 (#3) | 61.9 (#3) | 2 to 3 |
| OWASP cdxgen | 51.1 (#4) | 54.1 (#4) | 49.8 (#5) | 53.0 (#5) | 51.7 (#4) | 49.7 (#5) | 4 to 5 |
| Cisco AI BOM † | 48.6 (#5) | 48.9 (#5) | 50.7 (#4) | 56.7 (#3) | 46.4 (#5) | 49.8 (#4) | 3 to 5 |
| AIROM | 44.9 (#6) | 46.0 (#7) | 44.9 (#7) | 46.7 (#6) | 44.3 (#6) | 45.7 (#6) | 6 to 7 |
| Nexus ShadowScan | 44.4 (#7) | 47.8 (#6) | 46.2 (#6) | 38.1 (#7) | 40.4 (#7) | 45.3 (#7) | 6 to 7 |
| Trusera ai-bom | 32.2 (#8) | 30.2 (#8) | 34.4 (#8) | 35.3 (#8) | 27.7 (#8) | 35.7 (#8) | 8 |
| Anchore Syft | 27.6 (#9) | 27.9 (#9) | 29.9 (#9) | 27.0 (#9) | 25.4 (#10) | 26.6 (#9) | 9 to 10 |
| AIsbom | 26.1 (#10) | 27.4 (#10) | 26.3 (#10) | 22.6 (#10) | 26.7 (#9) | 26.4 (#10) | 9 to 10 |
| Snyk Agent Scan † | 18.1 (#11) | 20.3 (#11) | 18.5 (#11) | 15.8 (#11) | 17.0 (#11) | 14.6 (#11) | 11 |

## Scores that are floors, not measurements

- **Cisco AI BOM**: The tool requires an LLM. No key was supplied, so it ran with an unreachable local provider and marks every component unreviewed (agentic_status: degraded). Its score is a floor for its deterministic analysis only.
- **Snyk Agent Scan**: `scan`, which runs the risk analysis, needs a Snyk token and Snyk's API. Only `inspect` ran: it lists what one configuration file declares. Without --dangerously-run-mcp-servers it starts no server, so no tool definitions are read.

## Observed outside the scored run

- **ShadowScan + SymBiote**: This entry is the two tools' combined output. Counting SymBiote's merged inventory alone, the pair identifies the same 48 components as SymBiote alone: ShadowScan found 13 components SymBiote does not, and none reaches the inventory in identifiable form. The import maps mcp-server and agent findings to components named by a hash, does not reconcile them with the servers SymBiote already found, and records the other finding kinds as unmapped.
- **Nexus SymBiote**: In an earlier rerun, one of 46 scans hit the tool's 0.25-second wall-clock limit on TypeScript parsing, dropped a TypeScript MCP server and its tool, and so differed from the next scan of identical input. It did not recur in twelve follow-up scans or in the scored run, where 5.1 is full. Two runs cannot rule it out; treat the determinism score as an upper bound.

## Not graded

- **OWASP AIBOM Generator**: Takes a Hugging Face model ID, not a project, so it cannot be pointed at the corpus. Given one model ID from the corpus with huggingface.co unreachable, it wrote a schema-valid placeholder BOM and exited 0. Any discovery or safety number for it here would be an echo of its input, so no total is reported.

## Schemas used

- `bom-1.6.schema.json` sha256 `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d`
- `bom-1.7.schema.json` sha256 `73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce`
- `cryptography-defs.schema.json` sha256 `013919cfb1c6209f919cd7253a4e3f740cb44023697bb4657a5f0584d6f47137`
- `jsf-0.82.schema.json` sha256 `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae`
- `sarif-2.1.0.schema.json` sha256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`
- `spdx-2.3.schema.json` sha256 `4126dc29f15e92feec92e9622f4939131ad58b125d6f578aa93e980a6e6f3212`
- `spdx-3.0.1.schema.json` sha256 `bf586836b9abc14e54fa2a4f215290e5f39cd0d9e5c45646bc5a9b89b7dc6e1f`
- `spdx.schema.json` sha256 `4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359`
