# Support

Nexus SymBiote is alpha security tooling maintained by a single developer. This document routes common questions to the right place.

## Where to go

| I need to... | Go to |
| --- | --- |
| Report a security vulnerability | [SECURITY.md](SECURITY.md) — use private reporting |
| Report a bug | [GitHub Issues](https://github.com/aisecnomad/nexus-symbiote/issues) |
| Request a feature | [GitHub Issues](https://github.com/aisecnomad/nexus-symbiote/issues) |
| Set up a development environment | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Understand the security model | [`docs/security-model.md`](docs/security-model.md) |
| Learn about runtime assurance | [`docs/runtime-assurance.md`](docs/runtime-assurance.md) |
| Integrate with Nexus-ShadowScan | [`docs/shadowscan-integration.md`](docs/shadowscan-integration.md) |
| Review the release process | [`docs/releasing.md`](docs/releasing.md) |

## Troubleshooting

### Installation fails

- Nexus SymBiote requires **Python 3.11 or later**. Check with `python --version`.
- On systems where `python` points to Python 2, use `python3` or `python3.11` explicitly.
- If `tree-sitter` or `tree-sitter-typescript` fail to build, ensure you have a C compiler installed (`gcc` or `clang`) and up-to-date `pip` (`pip install --upgrade pip`).

### Missing optional features

Some capabilities require optional extras:

```bash
pip install "nexus-symbiote[sigstore]"   # Sigstore signature verification
pip install "nexus-symbiote[cyclonedx]"  # CycloneDX library validation
pip install "nexus-symbiote[all]"        # Everything
```

### Scanner reports zero components

- Verify the scan path points to the agent project root, not a subdirectory.
- Check that the project contains recognized configuration files (MCP configs, model files, prompt templates, etc.).
- Use `--scanner` to request specific scanners and confirm they apply to your project.
- Review scan failures in the output — a scanner may have failed silently.

### Import-shadowscan exits with an error

- Ensure the input file is a valid Nexus-ShadowScan native JSON or CycloneDX report.
- Use `--report-only` for exploratory imports where the source report is incomplete.
- Standalone imports ignore project policy files alongside the report.

### CycloneDX or SPDX export fails validation

- Ensure the `cyclonedx` extra is installed for CycloneDX library validation.
- Schema validation uses pinned official schemas shipped with the package.

## Response expectations

This is an alpha project with a single maintainer. There are no guaranteed response times or SLAs. Security reports are prioritized. Feature requests and bug reports are addressed as capacity allows.
