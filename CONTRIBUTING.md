# Contributing to Nexus SymBiote

Nexus SymBiote's compatibility baseline is the `nexus_symbiote` Python package and `nexus-symbiote` CLI on `main`. The product name is Nexus SymBiote. Experimental implementations on other branches are not interchangeable packages; port useful capabilities through reviewed, tested changes.

## Development

Use Python 3.11 through 3.13 and an isolated virtual environment. From a checkout:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-ci.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pytest
ruff check src tests scripts
ruff format --check src tests scripts
mypy src/nexus_symbiote
python scripts/check_workflows.py
python -m build
python -m twine check dist/*
```

The lock records the full CI dependency set. The wheel smoke test separately checks a minimal runtime installation. Regenerate the lock after changing declared dependencies; inspect new packages, hashes, supported Python markers, and license implications. Never resolve or publish dependencies from an untrusted pull request with release credentials.

## Architecture boundaries

Nexus-ShadowScan is the primary discovery engine. Preserve the `import-shadowscan` workflow when changing collection or graph code. Imported claims, local observations, approved snapshots, and mediated operations have different assurance. Keep A2A, IDE, and registry declarations explicit rather than inferring deployment or effective permissions from presence alone.

Run `PYTHONPATH=src python scripts/benchmark_security.py --out benchmark-results.json` after security changes. Review individual cases, corpus/source digests, unknowns, and denominators. Do not replace labels or remove negative fixtures to improve the result. The corpus is a finite regression suite, not representative field efficacy evidence.

## Security changes

State the trust boundary and an abuse case before changing security decisions. Add a regression that fails on the vulnerable behavior, including unknown and invalid inputs. Keep evidence of origin separate from evidence of approval and observed runtime behavior. Invalid policies, incomplete collection, missing required evidence, and unsupported critical semantics must not become silent successful verdicts.

Exporter changes must validate against the pinned official schema and preserve references, unknown states, and loss reports. Canonical digest changes require versioned profiles and test vectors. Do not update a golden file merely to make a failing test pass.

## Pull requests

Explain the concrete problem, resulting behavior, validation, and material limitations. Keep changes focused and include applicable documentation. Do not claim production enforcement for execution paths that bypass the adapter. Add no network access, executable discovery, or credential collection without an explicit design and tests.

Read [SECURITY.md](SECURITY.md) before reporting security-sensitive defects. This project is licensed under MIT as specified in [LICENSE](LICENSE).
