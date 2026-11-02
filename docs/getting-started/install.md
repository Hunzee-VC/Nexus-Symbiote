# Installation

Nexus SymBiote is alpha software. Version 0.1.0 is not yet on PyPI; a release through
TestPyPI and then PyPI is being prepared. Until it is published, install from a reviewed
checkout. The [PyPI section](#from-pypi-once-010-is-published) below applies once the
maintainer announces the release.

## Requirements

| Requirement | Detail |
| --- | --- |
| Python | CPython 3.11, 3.12 or 3.13. `pyproject.toml` declares `requires-python = ">=3.11"`; CI exercises exactly these three versions. |
| Operating system | CI runs on Linux (`ubuntu-latest`). The collectors and the output writer need POSIX descriptor-relative, no-follow file operations (`os.open` with `dir_fd` and `O_NOFOLLOW`) and fail closed where they are unavailable; the output writer refuses to run when `os.name` is not `posix`. macOS is not exercised by CI and is untested. Windows is not supported. |
| Network | None. Installation from a checkout needs access to the package index for dependencies. Every command then runs offline by default and refuses network access and process execution; only `discover-mcp` and `advisories` (network) and `verify-live` (process execution) do live work, and only with `--live`. See [offline and live modes](../operations/offline-and-live-modes.md). |

The runtime dependencies are declared in `pyproject.toml`: `click`, `pydantic`, `rich`,
`rfc8785`, `pyyaml`, `jsonschema`, `referencing`, `cryptography`, `packaging`, `tree-sitter`
and `tree-sitter-typescript`. `packaging` evaluates PEP 440 version ranges when `advisories`
matches a saved OSV export offline. The tree-sitter packages provide the parser used by the
[static TypeScript MCP inventory](../reference/typescript-inventory.md) and are installed with
the product.

## From a reviewed checkout

Review the exact revision you install. Use a full 40-character commit SHA and a fresh virtual
environment:

```bash
SYMBIOTE_REVISION="REPLACE_WITH_REVIEWED_40_CHARACTER_SHA"
git clone https://github.com/aisecnomad/Nexus-symbiote.git
cd Nexus-symbiote
git checkout --detach "$SYMBIOTE_REVISION"
test "$(git rev-parse HEAD)" = "$SYMBIOTE_REVISION"
python -m venv .venv
. .venv/bin/activate
python -m pip install .
nexus-symbiote --version
```

`python -m pip install .` resolves dependencies from the live package index within the
version ranges declared in `pyproject.toml`. For a deployment, prefer the
[hash-locked install](#hash-locked-developer-install) below, which installs only the reviewed
dependency set recorded in `requirements-ci.lock`.

### Optional extras

| Extra | Installs | What it enables |
| --- | --- | --- |
| `sigstore` | `sigstore` | Sigstore bundle verification: `verify-artifact --bundle`, `verify-discovery --bundle`, and the `--signature-policy` option of `scan` and `validate`. Without it, bundle verification reports `sigstore package not installed; install nexus-symbiote[sigstore]` and the artifact is not treated as verified. |
| `cyclonedx` | `cyclonedx-python-lib[json-validation]` | Independent CycloneDX validation used by the test suite (`tests/test_export_assurance.py`, `tests/test_export_conformance.py`). The exporters themselves validate against the pinned official schemas vendored in `src/nexus_symbiote/generators/schemas/vendor/` and do not import this library. |
| `all` | both of the above | Both features. |

```bash
python -m pip install ".[sigstore]"
python -m pip install ".[all]"
```

## Hash-locked developer install

[CONTRIBUTING.md](../../CONTRIBUTING.md) describes the development environment that CI
uses. It installs the full locked dependency set with hash checking and then the project
itself without resolving anything further:

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

The lock records the complete CI dependency set, including test, lint and build tools.
Regenerate it after changing declared dependencies and review the new packages, hashes and
licenses before merging.

## Verify what you installed

```bash
nexus-symbiote --version
python -m nexus_symbiote --version
python -m pip check
```

Both version commands print `nexus-symbiote, version 0.1.0` for the current revision. The
console script and `python -m nexus_symbiote` run the same Click entry point
(`nexus_symbiote.cli:main`). Run `python -m nexus_symbiote` from outside the checkout when you
want to be sure the installed package, rather than the source tree, is imported.

CI's wheel smoke test exercises an installed copy against an empty directory. It is a useful
check that the installation can collect, assemble and export:

```bash
mkdir empty
nexus-symbiote scan empty --report-only -f json -o agentbom.json
```

The command exits 0 and writes an inventory whose only component is the repository agent
definition, with `deployment_status` set to `unknown` and no findings.

## From PyPI (once 0.1.0 is published)

This section applies only after the maintainer has published version 0.1.0 through the
[release procedure](../operations/releasing.md). Before that, a distribution named
`nexus-symbiote` on a package index would not be this project: a pending trusted publisher
does not reserve the name. Confirm the release announcement and verify provenance before
installing.

```bash
pipx install nexus-symbiote                      # isolated command installation
python -m pip install nexus-symbiote             # inside a virtual environment
python -m pip install "nexus-symbiote[sigstore]"  # with Sigstore verification
```

### Verify provenance

Each release run attests the built wheel and sdist with GitHub build provenance and publishes
them through trusted publishing. Download the files without installing them, compare their
digests with the `SHA256SUMS` file from the release run, and verify the attestation with the
GitHub CLI:

```bash
python -m pip download nexus-symbiote==0.1.0 --no-deps -d verify
sha256sum verify/*
gh attestation verify verify/nexus_symbiote-0.1.0-py3-none-any.whl --repo aisecnomad/Nexus-symbiote
```

With `--repo` alone, `gh` accepts an attestation produced by any workflow of the repository.
To require the release workflow, the `main` branch and the reviewed commit, add the stricter
flags that the [inventory benchmark verification](../../benchmarks/inventory/README.md) uses:

```bash
gh attestation verify verify/nexus_symbiote-0.1.0-py3-none-any.whl \
  --repo aisecnomad/Nexus-symbiote \
  --signer-workflow aisecnomad/Nexus-symbiote/.github/workflows/release.yml \
  --source-ref refs/heads/main --source-digest "${RELEASE_COMMIT:?set the reviewed commit}" \
  --deny-self-hosted-runners
```

`RELEASE_COMMIT` is the full SHA that the `v0.1.0` tag names; the publication gate requires
that tag to point at the reviewed commit before an upload is approved. Repeat the check for
the sdist (`nexus_symbiote-0.1.0.tar.gz`) if you install from source.

### TestPyPI rehearsal

The release procedure rehearses on TestPyPI first. Anyone can register names there, so
install the rehearsal wheel with `--no-deps` and take dependencies from the locked set in a
reviewed checkout, as the [release procedure](../operations/releasing.md) shows. Do not use
TestPyPI for a deployment.

## Uninstall

```bash
python -m pip uninstall nexus-symbiote   # inside the virtual environment
pipx uninstall nexus-symbiote            # for a pipx installation
```

Deleting the virtual environment removes everything the installation added. The tool writes
only the files you ask for: the `-o` output of a command, `.nexus-symbiote.yaml` from `init`,
the `baseline` output (default `.nexus-symbiote-baseline.json`), and the runtime key files
from `runtime keygen`. The GitHub Action collects into a temporary directory that is removed
when the step ends.
