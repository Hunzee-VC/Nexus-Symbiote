# ShadowScan primary discovery integration

[Nexus-ShadowScan](https://github.com/aisecnomad/Nexus-ShadowScan) supplies primary
multi-surface discovery. Nexus SymBiote imports those reports as declared evidence
for supply-chain verification, risk review and AgentBOM generation.

- Importer: `src/nexus_symbiote/scanners/shadowscan.py` (`ShadowScanImporter`).
- Command: `nexus-symbiote import-shadowscan`.
- [Workflow, coverage, provenance and API limitations](docs/shadowscan-integration.md).

An imported report does not authenticate its producer or authorize a deployment.
Coverage remains partial, and source-report bytes must be retained separately.
