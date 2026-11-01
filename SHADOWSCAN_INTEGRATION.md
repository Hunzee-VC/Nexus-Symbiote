# ShadowScan Primary Discovery Integration

This branch implements the dual-system architecture:

- **Nexus-ShadowScan** — primary multi-surface discovery
- **SymBiote** — verification, integrity, risk scoring, and AIBOM generation

## Key additions

- `src/symbiote/scanners/shadowscan.py` — `ShadowScanImporter`
- CLI command: `symbiote import-shadowscan`
- Updated README with recommended workflow

See the commit history on this branch for the full set of changes.
