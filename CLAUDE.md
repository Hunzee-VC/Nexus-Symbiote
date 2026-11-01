# Nexus SymBiote

Agent Bill of Materials (AgentBOM) generator and validator for AI agent supply chain security.

## Project structure

```
src/nexus_symbiote/
  core/        — Domain models (Pydantic v2), enums, AIBOM container, RFC 8785 JCS hashing
  scanners/    — Component discovery (MCP, model weights, prompts, RAG, registry, A2A, IDE agents)
  generators/  — BOM output (native JSON, CycloneDX 1.7, SPDX 3.0)
  validators/  — Completeness, integrity, and risk scoring
  diff/        — AIBOM version comparison
  live/        — Live MCP server verification (runtime rug-pull detection)
  advisories.py — OSV.dev advisory lookups
  utils/       — Sigstore verification, file hash utilities
  cli.py       — Click CLI entrypoint
```

## Build and test

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/
mypy src/
```

## Key conventions

- Python 3.11+, Pydantic v2, Click for CLI
- All hashing uses `core/hashing.py` — RFC 8785 JCS for tool definitions, SHA-256 for files,
  `safetensors_fingerprint()` for per-tensor model digests
- Component types are in `core/enums.py:ComponentType` (16 types)
- Every scanner extends `scanners/base.py:Scanner` and returns `ScanResult`
- Risk assessments use `RiskSeverity` enum: critical > high > medium > low > info
- Trust tiers: internal-verified > internal-unverified > third-party-signed > third-party-unsigned > untrusted-public > unknown
- `version_pinned` is tri-state: True (pinned), False (floating package), None (no package to pin)
- Tests live in `tests/` and use pytest; `tests/test_baseline_cli.py::test_every_readme_command_exists`
  guards against dropping documented CLI commands
- Ruff for linting (line-length 100), mypy strict mode
- No comments unless the why is non-obvious
