# Contributing to Symbiote

Thank you for helping build the AgentBOM toolkit. This guide covers the mechanics; the design rules live in
[`spec/`](spec/README.md).

## Ground rules
- **The spec wins.** Code implements `spec/`. If you need the behaviour to differ, change the spec in the same
  pull request and add or amend an ADR under `spec/adr/`.
- **Nothing invented at the top level of CycloneDX or SPDX.** New facts go through sanctioned extension points,
  get an `agentbom:` taxonomy entry (`spec/taxonomy.md`) and a divergence-register entry (`spec/divergences.md`).
- **Fail closed.** Digests of non-canonicalizable input are `undigestable`, never best-effort. Unknown is never
  rendered as absence. `verified` is never produced without a satisfied signer identity constraint.
- **No secrets, ever.** Collectors record env-var and header *names*, never values; fixtures use obviously fake
  shapes that the secret scanner must still redact; tests assert that nothing secret-shaped leaves the process.
- **Tests run offline.** Live network behaviour is exercised against in-process fixture servers.

## Development setup
```bash
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[dev]"
ruff format src tests scripts && ruff check src tests scripts
pytest -q
python scripts/check_workflows.py && python scripts/check_repository_hygiene.py   # what the CI quality job runs
```
Python 3.11+ is required. Optional extras: `[sign]` (Sigstore keyless), `[models]` (OpenSSF model-signing),
`[mcp]` (live MCP collectors), `[release]` (`build`, `twine`; used by the `distribution` CI job and the release
workflow). CI requires `Verified CI` to pass: every job, including the workflow linter, repository hygiene, the
wheel build and the strict docs build (`docs/development/repository-controls.md`).

## Making a change
1. Pick or open a work package in `docs/development/work-packages.md`; set yourself as owner.
2. Branch from `claude/symbiote-foundation` (the integration branch until 0.1.0) as `wp-NN-<slug>` or
   `feat/<slug>`.
3. If you add or change an emitted field, update **all** of: the model, `spec/taxonomy.md`,
   `spec/divergences.md`, the generated companion schema (`symbiote schema export companion -o
   src/symbiote/schemas/agentbom/agentbom-0.1.schema.json`), golden files, and `CHANGELOG.md`. CI checks the
   first four mechanically.
4. Add tests: unit tests for logic, property tests for canonicalization/Merkle invariants, golden files for
   emitted documents (validated against the official schemas).
5. Open a pull request against the integration branch. Describe the threat the change addresses or the gap it
   closes, and link the spec section.

## Commit messages
Imperative mood, a body that explains *why*, and no model identifiers or tool advertising in the message
body beyond the attribution trailer your environment adds.

## Reporting security issues
See [`SECURITY.md`](https://github.com/aisecnomad/Nexus-symbiote/blob/claude/symbiote-foundation/SECURITY.md). Do not open public issues for vulnerabilities.

## Code of conduct
This project follows the [Contributor Covenant](https://github.com/aisecnomad/Nexus-symbiote/blob/claude/symbiote-foundation/CODE_OF_CONDUCT.md).
