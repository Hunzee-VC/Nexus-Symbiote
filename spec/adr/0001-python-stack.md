# ADR-0001: Python 3.11+ stack with Pydantic v2 and Typer

**Status:** accepted · **Date:** 2026-11-01

## Context
Symbiote must read the artefacts agents are actually built from (MCP client configs, SKILL.md, framework
configs, Hugging Face model directories, OpenTelemetry traces), speak to the libraries that already define
the trust primitives (OpenSSF model-signing, sigstore-python, in-toto-attestation, rfc8785, the MCP SDK,
spdx-python-model, cyclonedx-python-lib), and be adopted by AI security teams whose tooling is Python-first.

## Decision
- Python ≥ 3.11, packaged with `hatchling`, developed with `uv`.
- Pydantic v2 models are the single semantic model; every exporter/importer is a pure function over it.
- Typer + rich for the CLI; every command supports `--json`.
- Optional heavy dependencies live behind extras: `[sign]` (sigstore, in-toto), `[models]` (model-signing),
  `[mcp]` (MCP SDK). The core install must work offline and without them.
- Tests never touch the network; live collectors are exercised against in-process fixture servers.

## Consequences
A Go single-binary gateway verifier is a possible later component; the verification algorithms are
specified precisely enough (`spec/digests.md`, `spec/attestation.md`) to be re-implemented.
