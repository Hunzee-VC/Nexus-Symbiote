# Nexus SymBiote

Agent Bill of Materials (AgentBOM) generator and validator for AI agent supply chain security.

## Project structure

```
src/nexus_symbiote/
  cli.py          — Click CLI entrypoint (scan, import-shadowscan, validate, risk, diff, summary, init, verify-signature)
  policy.py       — .nexus-symbiote.yaml model, discovery (scan only), and explicit loading
  core/           — Domain models (Pydantic v2), enums, AIBOM container, vocab.py (scanner and state strings),
                    redact.py, textsafety.py, evidence.py, hashing.py (RFC 8785 JCS)
  scanners/       — Eight scanners: a2a, ide_agents, mcp, model, prompt, rag, registry, shadowscan
  generators/     — BOM output: native (AIBOM.to_json), CycloneDX 1.7, SPDX 3.0, SARIF 2.1.0
  validators/     — coverage.py (the single coverage rule), completeness.py, integrity.py, risk.py
  diff/           — differ.py: AIBOM version comparison
  utils/          — fsio.py (bounded no-follow reads, safe writes), confined.py (project-confined hashing),
                    crypto.py (file hashes and Sigstore verification)
tests/            — pytest suite
```

## Build and test

```bash
pip install -e ".[dev,all]"
pytest
ruff check src/ tests/
mypy src/
```

## Key conventions

- Python 3.11+, Pydantic v2, Click for CLI
- All hashing uses `core/hashing.py` — RFC 8785 JCS for tool definitions, SHA-256 for files
- Component types are in `core/enums.py:ComponentType`
- Every scanner extends `scanners/base.py:Scanner` and returns `ScanResult`
- Scanner names and state strings come from `core/vocab.py`. Producers and consumers import them; do not retype the literals.
- Absence is recorded with `result.record_absent(...)`. Use `record_excluded` only for real exclusions, and `record_failure` for errors.
- Scanners report only `signature-not-found` or `signature-present-unverified`. `signature-verified` is reserved for a result from `utils/crypto.py`.
- Reads go through `utils/fsio.read_regular_text`; writes go through `utils/fsio.write_text_safely`.
- Risk assessments use `RiskSeverity` enum: critical > high > medium > low > info
- Trust tiers: internal-verified > internal-unverified > third-party-signed > third-party-unsigned > untrusted-public > unknown
- Exit codes: 0 pass; 1 gate, validation, or diff-threshold failure; 2 usage or input error; 3 unexpected internal error
- Tests live in `tests/` and use pytest
- Ruff for linting (line-length 100), mypy strict mode
- No comments unless the why is non-obvious
