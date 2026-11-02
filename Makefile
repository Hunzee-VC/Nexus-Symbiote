.DEFAULT_GOAL := help
SHELL := /bin/bash

# Every recipe is a command from CONTRIBUTING.md. `make install-dev` once, then
# `make check` runs the documented sequence in the documented order.

# --- Development -----------------------------------------------------------

# Fail fast on an interpreter the project does not support, before the
# hash-locked install runs (pyproject.toml declares 3.11 to 3.13).
.PHONY: ensure-python
ensure-python:
	@python -c 'import sys; sys.exit(None if (3, 11) <= sys.version_info[:2] < (3, 14) else "Nexus SymBiote development needs CPython 3.11 to 3.13; this python is " + sys.version.split()[0] + ". Create a virtual environment with a supported interpreter, for example: python3.12 -m venv .venv")'

.PHONY: install-dev
install-dev: ensure-python ## Install the hash-locked CI dependency set and this package in editable mode
	python -m pip install --require-hashes -r requirements-ci.lock
	python -m pip install --no-deps --no-build-isolation -e .

# --- Quality ---------------------------------------------------------------

.PHONY: test
test: ## Run the test suite
	python -m pytest

.PHONY: coverage
coverage: ## Run the test suite with line coverage, as the CI coverage job does
	python -m pytest --cov=nexus_symbiote --cov-report=term-missing

.PHONY: lint
lint: ## Run the ruff linter
	ruff check src tests scripts

.PHONY: format
format: ## Rewrite Python files with the ruff formatter
	ruff format src tests scripts

.PHONY: format-check
format-check: ## Check formatting without changing files
	ruff format --check src tests scripts

.PHONY: typecheck
typecheck: ## Run mypy in strict mode on the package
	mypy src/nexus_symbiote

.PHONY: check-workflows
check-workflows: ## Reject unpinned Actions and expressions inside shell source
	python scripts/check_workflows.py

.PHONY: check-docs
check-docs: ## Check Markdown links and that generated schemas and the CLI reference are current
	python scripts/check_docs.py
	python scripts/generate_schemas.py --check
	python scripts/generate_cli_reference.py --check

.PHONY: generate
generate: ## Regenerate the JSON Schemas and the CLI reference after a model or help change
	python scripts/generate_schemas.py --write
	python scripts/generate_cli_reference.py --write

# --- Build -----------------------------------------------------------------

.PHONY: build
build: ## Build the sdist and wheel, then check them with twine
	python -m build
	python -m twine check dist/*

.PHONY: check
.NOTPARALLEL: check
check: test lint format-check typecheck check-workflows check-docs build ## Run the documented check sequence (after make install-dev)
	@echo "All checks passed."

# --- Benchmark -------------------------------------------------------------

.PHONY: benchmark
benchmark: ## Run the synthetic security regression corpus (benchmarks/README.md); review cases, digests, unknowns and denominators
	PYTHONPATH=src python scripts/benchmark_security.py --out benchmark-results.json

# --- Cleanup ---------------------------------------------------------------

.PHONY: clean
clean: ## Remove build artifacts, caches and the benchmark result
	rm -rf dist build *.egg-info src/*.egg-info .mypy_cache .pytest_cache .ruff_cache .hypothesis .coverage coverage.xml htmlcov
	rm -f benchmark-results.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# --- Help ------------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@awk 'BEGIN { FS = ":.*## "; if (system("test -t 1") == 0) { b = "\033[1m"; c = "\033[36m"; r = "\033[0m" } } /^# --- / { t = $$0; gsub(/^# --- | -+$$/, "", t); printf "\n%s%s%s\n", b, t, r; next } /^[a-zA-Z_-]+:.*## / { printf "  %s%-16s%s %s\n", c, $$1, r, $$2 }' $(MAKEFILE_LIST)
