# Nexus SymBiote

Agent Bill of Materials (AgentBOM) generator and validator for AI agent supply chain security.

## Project structure

```
src/nexus_symbiote/
  cli.py              — Click entry point: root group (mode flags, exit-code contract) and core commands
  cli_common.py       — Shared command helpers: active mode, live-step refusal, BOM loading
  live_cli.py         — discover-mcp (live HTTPS, or --input export)
  supply_chain_cli.py — verify-live, baseline, vex, advisories
  runtime_cli.py      — runtime keygen/sign/verify
  modes.py            — Offline/live resolution and the offline guard (no network, no processes)
  exits.py            — Exit codes 0/1/2/3 and GateFailed/Incomplete exceptions
  core/               — Domain models (Pydantic v2), enums, AIBOM container, RFC 8785 JCS hashing, evidence
  scanners/           — Collectors: mcp (+ python_tools, ts_tools), model, prompt, rag, registry, a2a,
                        ide_agents, shadowscan importer; live_mcp is the opt-in HTTPS discovery client
  generators/         — Native JSON, CycloneDX 1.7, SPDX 3.0.1, SARIF, VEX; validation against vendored schemas
  validators/         — Completeness, integrity, risk scoring
  diff/               — Snapshot comparison
  live/               — Pinned stdio launcher and descriptor verification (live or recorded)
  utils/              — Confined reads, output writing, Sigstore verification, secrets, tensors
  advisories.py       — OSV advisories: live API client and offline export matching
  osv_export.py       — Bounded OSV export reader and OSV range evaluation
  graph.py, lineage.py, policy.py, signature_policy.py, runtime.py, scanner_catalog.py
scripts/              — Action runner, workflow checker, docs/schema/CLI-reference generators, benchmarks
schemas/              — Generated JSON Schemas (never hand-edit; see scripts/generate_schemas.py)
```

## Build and test

```bash
python -m pip install --require-hashes -r requirements-ci.lock
python -m pip install --no-deps --no-build-isolation -e .
make check          # tests, ruff, ruff format, mypy, workflow and docs checks, build, twine
```

After changing a model, run `python scripts/generate_schemas.py --write`. After changing CLI
help, run `python scripts/generate_cli_reference.py --write`. The test suite fails when either
is stale, and when a Markdown link or anchor is broken.

## Key conventions

- Python 3.11+, Pydantic v2, Click for CLI
- Commands run offline by default; only discover-mcp, advisories and verify-live do live work,
  and only with `--live`. Tests that exercise a live path pass `--live` before the command.
- Exit codes: 0 complete, 1 usage/input failure, 2 gate or verification failed, 3 incomplete or
  refused offline. Raise `exits.GateFailed` / `exits.Incomplete`, never `sys.exit(1)`.
- All hashing uses `core/hashing.py` — RFC 8785 JCS for tool definitions, SHA-256 for files
- Component types are in `core/enums.py:ComponentType`
- Every scanner extends `scanners/base.py:Scanner` and returns `ScanResult`
- Risk assessments use `RiskSeverity` enum: critical > high > medium > low > info
- Trust tiers: internal-verified > internal-unverified > third-party-signed > third-party-unsigned > untrusted-public > unknown
- Tests live in `tests/` and use pytest
- Ruff for linting (line-length 100), mypy strict mode
- No comments unless the why is non-obvious
