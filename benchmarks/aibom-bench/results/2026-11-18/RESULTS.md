# AIBOM-Bench results

Benchmark 1.0.0, corpus `6221015927c28696`: 91 components, 8 decoys, 20 planted risks, 10 planted changes, 8 hostile-input cases. All runs offline.

## Scores

| Tool | Version | Total | Grade | Discovery | Precision | Record fidelity | Standards | BOM integrity | Risk analysis | Change detection | Scanner safety |
| --- | --- | ---: | :---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Nexus SymBiote | 0.2.0 (this checkout) | **71.1** | B | 13.3/30 | 3.5/4 | 11.7/14 | 8.7/10 | 10.0/10 | 6.8/12 | 5.1/8 | 12.0/12 |
| agent-bom | 0.115.4 | **60.5** | C | 15.2/30 | 3.5/4 | 8.1/14 | 8.5/10 | 4.5/10 | 6.4/12 | 3.4/8 | 11.0/12 |
| OWASP cdxgen | 13.8.0 | **56.0** | C | 13.7/30 | 3.5/4 | 8.9/14 | 10.0/10 | 3.5/10 | 2.8/12 | 1.9/8 | 11.8/12 |
| AIROM | 0.4.7 | **53.0** | D | 11.6/30 | 4.0/4 | 8.9/14 | 8.6/10 | 3.4/10 | 3.4/12 | 1.6/8 | 11.5/12 |
| Cisco AI BOM | 1.10.1 | **49.5** | D | 16.5/30 | 3.5/4 | 8.0/14 | 6.5/10 | 2.0/10 | 1.0/12 | 1.6/8 | 10.5/12 |
| AIsbom | 1.7.0 | **37.5** | E | 3.4/30 | 3.5/4 | 5.4/14 | 6.4/10 | 2.4/10 | 3.4/12 | 1.0/8 | 12.0/12 |
| Trusera ai-bom | 3.6.0 | **36.9** | E | 9.4/30 | 3.0/4 | 4.3/14 | 5.2/10 | 0.0/10 | 2.4/12 | 1.9/8 | 10.8/12 |
| Anchore Syft | 1.57.2 | **36.8** | E | 4.3/30 | 4.0/4 | 8.1/14 | 5.7/10 | 3.1/10 | 0.0/12 | 0.0/8 | 11.5/12 |
| Snyk Agent Scan | 0.6.11 | **28.9** | E | 1.8/30 | 4.0/4 | 4.2/14 | 0.0/10 | 5.0/10 | 0.0/12 | 2.4/8 | 11.5/12 |
| OWASP AIBOM Generator | commit 45851cb | **17.3** | F | 0.4/30 | 0.0/4 | 0.2/14 | 5.2/10 | 0.0/10 | 0.0/12 | 0.0/8 | 11.5/12 |

## Points by criterion

| Criterion | Max | Nexus SymBiote | agent-bom | OWASP cdxgen | AIROM | Cisco AI BOM | AIsbom | Trusera ai-bom | Anchore Syft | Snyk Agent Scan | OWASP AIBOM Generator |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1.1 Models | 7 | 2.3 | 2.7 | 4.7 | 4.7 | 4.7 | 1.2 | 2.3 | 1.2 | 0.0 | 0.4 |
| 1.2 Data | 6 | 0.6 | 1.1 | 0.6 | 3.3 | 2.7 | 0.0 | 0.6 | 0.0 | 0.0 | 0.0 |
| 1.3 Tools and frameworks | 5 | 4.2 | 4.7 | 3.1 | 2.5 | 4.4 | 2.2 | 2.5 | 2.8 | 0.0 | 0.0 |
| 1.4 Agent components | 9 | 6.2 | 5.5 | 5.0 | 1.0 | 3.9 | 0.0 | 1.8 | 0.0 | 1.8 | 0.0 |
| 1.5 Infrastructure and deployment | 3 | 0.0 | 1.1 | 0.4 | 0.2 | 0.8 | 0.0 | 2.2 | 0.4 | 0.0 | 0.0 |
| 2.1 Decoy resistance | 4 | 3.5 | 3.5 | 3.5 | 4.0 | 3.5 | 3.5 | 3.0 | 4.0 | 4.0 | 0.0 |
| 3.1 Version and supplier | 4 | 3.7 | 3.8 | 3.9 | 3.4 | 3.8 | 4.0 | 1.8 | 4.0 | 1.0 | 0.2 |
| 3.2 Content digests | 3 | 3.0 | 0.0 | 0.0 | 1.5 | 0.0 | 1.1 | 0.0 | 0.0 | 0.0 | 0.0 |
| 3.3 Evidence location | 3 | 2.9 | 2.6 | 3.0 | 2.9 | 3.0 | 0.0 | 1.6 | 3.0 | 1.5 | 0.0 |
| 3.4 Domain facts and licence | 2 | 1.4 | 1.1 | 1.5 | 0.8 | 0.8 | 0.3 | 1.0 | 1.1 | 1.8 | 0.0 |
| 3.5 Relationships | 2 | 0.6 | 0.6 | 0.6 | 0.3 | 0.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| 4.1 CycloneDX output validates | 3 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 | 1.5 | 3.0 | 0.0 | 3.0 |
| 4.2 SPDX output validates | 2 | 2.0 | 2.0 | 2.0 | 1.0 | 1.0 | 2.0 | 1.0 | 1.0 | 0.0 | 0.0 |
| 4.3 AI vocabulary in CycloneDX | 2 | 1.0 | 1.3 | 2.0 | 2.0 | 1.4 | 1.4 | 1.0 | 1.0 | 0.0 | 1.4 |
| 4.4 Package URLs | 1 | 0.7 | 0.7 | 1.0 | 0.6 | 0.0 | 0.0 | 0.7 | 0.7 | 0.0 | 0.3 |
| 4.5 SARIF output validates | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 0.0 | 0.0 | 0.0 |
| 4.6 Minimum-element or framework reporting (assessed) | 1 | 1.0 | 0.5 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.5 |
| 5.1 Deterministic output | 4 | 4.0 | 0.0 | 0.0 | 2.4 | 0.0 | 2.4 | 0.0 | 2.4 | 4.0 | 0.0 |
| 5.2 Signing, attestation and verification (assessed) | 3 | 3.0 | 1.5 | 1.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.8 | 0.0 | 0.0 |
| 5.3 Reports what it could not read | 1 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 |
| 5.4 States collection scope and coverage (assessed) | 1 | 1.0 | 1.0 | 0.0 | 0.0 | 0.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| 5.5 Evidence typing per record (assessed) | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 0.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| 6.1 Planted-risk recall | 8 | 3.8 | 3.4 | 0.8 | 0.4 | 0.0 | 0.4 | 0.4 | 0.0 | 0.0 | 0.0 |
| 6.2 Clean controls not flagged | 2 | 2.0 | 2.0 | 2.0 | 2.0 | 0.0 | 2.0 | 2.0 | 0.0 | 0.0 | 0.0 |
| 6.3 Advisory mapping and VEX (assessed) | 2 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| 7.1 Changes visible in the BOM | 3 | 2.4 | 1.5 | 0.6 | 0.3 | 0.3 | 0.0 | 0.6 | 0.0 | 0.9 | 0.0 |
| 7.2 Native drift report | 3 | 1.2 | 0.6 | 0.0 | 0.3 | 0.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| 7.3 CI and policy gate (assessed) | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 0.0 |
| 7.4 Runtime reconciliation (assessed) | 1 | 0.5 | 0.2 | 0.2 | 0.0 | 0.0 | 0.0 | 0.2 | 0.0 | 0.5 | 0.0 |
| 8.1 Executes nothing from the project | 4 | 4.0 | 4.0 | 4.0 | 4.0 | 4.0 | 4.0 | 4.0 | 4.0 | 4.0 | 4.0 |
| 8.2 Stays inside the project | 2 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 |
| 8.3 Does not disclose secrets | 2 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 | 1.5 | 2.0 | 2.0 | 2.0 |
| 8.4 Neutralizes hostile names | 1 | 1.0 | 1.0 | 1.0 | 0.5 | 0.5 | 1.0 | 0.5 | 0.5 | 0.5 | 1.0 |
| 8.5 Survives hostile input | 2 | 2.0 | 1.5 | 1.8 | 2.0 | 1.5 | 2.0 | 1.8 | 2.0 | 2.0 | 2.0 |
| 8.6 Works offline, attempts no egress | 1 | 1.0 | 0.5 | 1.0 | 1.0 | 0.5 | 1.0 | 1.0 | 1.0 | 1.0 | 0.5 |

## Measurements

| Tool | Component recall | Records emitted | Risks caught | Changes visible | Hostile cases passed | Canaries tripped | Secrets disclosed | Egress attempts | Scan time |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| Nexus SymBiote | 52% | 625 | 9/19 | 8/10 | 8/8 | none | 0 | 0 | 11.2 s |
| agent-bom | 56% | 2516 | 8/19 | 5/10 | 6/8 | none | 0 | 2 | 11.5 s |
| OWASP cdxgen | 50% | 325 | 2/19 | 2/10 | 7/8 | none | 0 | 0 | 25.4 s |
| AIROM | 35% | 427 | 1/19 | 1/10 | 8/8 | none | 0 | 0 | 0.1 s |
| Cisco AI BOM | 56% | 476 | 0/19 | 1/10 | 6/8 | none | 0 | 2 | 120.9 s |
| AIsbom | 12% | 48 | 1/19 | 0/10 | 8/8 | none | 0 | 0 | 1.6 s |
| Trusera ai-bom | 32% | 273 | 1/19 | 2/10 | 7/8 | none | 1 | 0 | 3.9 s |
| Anchore Syft | 15% | 583 | 0/19 | 0/10 | 8/8 | none | 0 | 0 | 1.2 s |
| Snyk Agent Scan | 8% | 22 | 0/19 | 3/10 | 8/8 | none | 0 | 0 | 2.6 s |
| OWASP AIBOM Generator | 1% | 1 | 0/19 | 0/10 | 8/8 | none | 0 | 2 | 35.4 s |

## Scores that are floors, not measurements

- **Cisco AI BOM**: The tool requires an LLM. No key was supplied, so it ran with an unreachable local provider and marks every component unreviewed (agentic_status: degraded). Its score is a floor for its deterministic analysis only.
- **Snyk Agent Scan**: `scan`, which runs the risk analysis, needs a Snyk token and Snyk's API. Only `inspect` ran: it lists what one configuration file declares. Without --dangerously-run-mcp-servers it starts no server, so no tool definitions are read.
- **OWASP AIBOM Generator**: Takes a Hugging Face model ID, not a directory, and has no offline input. huggingface.co was unreachable, so it wrote a placeholder BOM. Its score is a floor, not a measurement of its model-card extraction.

## Schemas used

- `bom-1.6.schema.json` sha256 `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d`
- `bom-1.7.schema.json` sha256 `73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce`
- `cryptography-defs.schema.json` sha256 `013919cfb1c6209f919cd7253a4e3f740cb44023697bb4657a5f0584d6f47137`
- `jsf-0.82.schema.json` sha256 `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae`
- `sarif-2.1.0.schema.json` sha256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`
- `spdx-2.3.schema.json` sha256 `4126dc29f15e92feec92e9622f4939131ad58b125d6f578aa93e980a6e6f3212`
- `spdx-3.0.1.schema.json` sha256 `bf586836b9abc14e54fa2a4f215290e5f39cd0d9e5c45646bc5a9b89b7dc6e1f`
- `spdx.schema.json` sha256 `4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359`
