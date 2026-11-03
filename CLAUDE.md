# Nexus SymBiote

Agent Bill of Materials (AgentBOM) generator and validator for AI agent supply chain security.

## Project structure

```
src/nexus_symbiote/
  core/        — Domain models (Pydantic v2), enums, AIBOM container, RFC 8785 JCS hashing
  scanners/    — Component discovery (MCP, model weights, prompts, RAG, registry, A2A, IDE agents, ShadowScan reports)
  generators/  — BOM output (native JSON, CycloneDX 1.7, SPDX 3.0)
  validators/  — Completeness, integrity, and risk scoring
  diff/        — AIBOM version comparison
  utils/       — Sigstore verification, file hash utilities
  cli.py       — Click CLI entrypoint
```

## Build and test

```bash
make install-locked   # hash-locked CI environment plus an editable install
make quality          # ruff, format check, mypy strict, workflow and hygiene checks
make test             # full pytest suite; `make coverage` enforces the CI floors
```

## Key conventions

- Python 3.11+, Pydantic v2, Click for CLI
- All hashing uses `core/hashing.py` — RFC 8785 JCS for tool definitions, SHA-256 for files
- Component types are in `core/enums.py:ComponentType`
- Every scanner extends `scanners/base.py:Scanner` and returns `ScanResult`
- Risk assessments use `RiskSeverity` enum: critical > high > medium > low > info
- Trust tiers: internal-verified > internal-unverified > third-party-signed > third-party-unsigned > untrusted-public > unknown
- Tests live in `tests/` and use pytest
- Ruff for linting (line-length 100), mypy strict mode
- No comments unless the why is non-obvious
