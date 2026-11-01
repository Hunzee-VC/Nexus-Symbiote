# Contributing to Nexus SymBiote

## Setup

```bash
git clone https://github.com/aisecnomad/nexus-symbiote.git
cd nexus-symbiote
pip install -e ".[dev,all]"
```

## Development workflow

```bash
pytest                          # run tests
ruff check src/ tests/          # lint
ruff format src/ tests/         # format
mypy src/nexus_symbiote/               # type check
```

## Project structure

- `src/nexus_symbiote/core/` — Domain models, enums, AIBOM container, JCS hashing
- `src/nexus_symbiote/scanners/` — Component discovery (MCP, model, prompt, RAG, registry)
- `src/nexus_symbiote/generators/` — Output formats (native JSON, CycloneDX 1.7, SPDX 3.0)
- `src/nexus_symbiote/validators/` — Completeness, integrity, risk scoring
- `src/nexus_symbiote/diff/` — AIBOM version comparison
- `src/nexus_symbiote/utils/` — Sigstore verification, file hashing
- `tests/` — pytest test suite

## Adding a scanner

1. Create `src/nexus_symbiote/scanners/your_scanner.py` extending `Scanner`
2. Implement `scan(project_root) -> ScanResult`
3. Register it in `cli.py:_get_scanners()` and `scanners/__init__.py`
4. Add tests in `tests/`

## Code standards

- Python 3.11+, Pydantic v2, strict mypy
- Ruff for linting and formatting (line-length 100)
- No comments unless the why is non-obvious
- All hashing through `core/hashing.py`
