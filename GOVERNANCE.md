# Governance

Nexus SymBiote is in alpha and follows a single-maintainer governance model. This document describes how decisions are made, how changes are merged, and what to expect as the project matures.

## Maintainer

The project is maintained by [Emmanuel Dahunsi (@aisecnomad)](https://github.com/aisecnomad), who holds final authority on merges, releases, and project direction during the alpha phase.

See [MAINTAINERS.md](MAINTAINERS.md) for the current maintainer table.

## Decision making

During alpha, the maintainer makes final decisions on:

- Feature scope and roadmap priorities
- Architecture and security model changes
- Release timing and distribution
- Dependency additions and upgrades
- Breaking changes to CLI, output formats, or policy semantics

Community input through issues and pull requests is valued and influences decisions, but the maintainer reserves the right to decline changes that conflict with the project's security model or architectural direction.

## Merge policy

Every change to `main` must:

1. Pass the full CI pipeline (`Verified CI` aggregation job).
2. Pass ruff linting and formatting checks.
3. Pass mypy strict type checking.
4. Include tests for new behavior and regressions for bug fixes.
5. Be reviewed by the maintainer before merge.

Security-sensitive changes additionally require:

- A stated trust boundary and abuse case.
- A regression test that fails on the vulnerable behavior.
- Review of the security regression corpus after changes.

## Branch protection

The `main` branch enforces:

- Required status checks (Verified CI).
- No direct pushes — all changes go through pull requests.
- Linear history (rebase or squash merges only).
- No force pushes.

See [repository controls](docs/repository-controls.md) for the full configuration.

## Releases

Releases are manually triggered, environment-gated, and require OIDC trusted publishing. The maintainer must explicitly request publication. See [releasing](docs/releasing.md) for the full procedure including checksums, provenance, and PyPI configuration.

## Future governance

As the project matures beyond alpha and gains contributors, governance may evolve to include:

- Additional maintainers with defined areas of responsibility.
- A documented consensus process for architectural decisions.
- A formal RFC process for breaking changes.

Until then, this document reflects the current single-maintainer reality.
