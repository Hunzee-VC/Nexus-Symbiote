# Release procedure

The release workflow is manually dispatched from `main`. Its default creates a candidate and does not publish. This repository change does not itself configure GitHub environments, PyPI ownership, trusted publishers, or repository protection.

Before enabling publication:

1. Choose and verify the package name and release version. Confirm package-index ownership and that the distribution metadata, source tag, and changelog agree. The product name is Nexus SymBiote; the current distribution and command are `nexus-symbiote`.
2. Configure the PyPI trusted publisher for this repository, `.github/workflows/release.yml`, and the `pypi` environment. Use no long-lived API token.
3. Configure `pypi` required reviewers and restrict deployment to `main`. Require successful `Verified CI` and reviewed changes on the default branch. Follow [repository controls](repository-controls.md); a publication request fails closed if its read-only preflight cannot establish the required branch controls and successful CI for the exact source commit. Candidate runs remain available before those controls are configured. The workflow cannot create these controls itself.
4. Generate a release candidate with `publish=false`. Inspect its wheel, source distribution, SBOM, installed-distribution inventory, checksums, and build attestation. Test the wheel in an isolated environment outside the checkout.
5. Dispatch with `publish=true` only after that review. This builds and tests a new candidate from the selected main revision and requires the configured environment approval before publication; review the artifacts of this exact run at the approval gate. The publisher downloads the run's built distributions and authenticates through OIDC.
6. Verify the published wheel and sdist checksums and provenance against this exact run. Create a matching signed source tag and release notes. Do not claim publication succeeded until the package index and source revision agree.

The `distribution` job and the manual candidate build install the exact candidate wheel into the locked test environment. The acceptance runner verifies its SHA-256 against pip installation metadata, checks the package import location, and runs selected tests outside the checkout. These cover a clean repository baseline, a complete ShadowScan source report, a forged inventory omitting a project file, an MCP endpoint substitution, supplier-controlled policy discovery, a revoked trust signer, and distinct SPDX revision identities. A failed or skipped acceptance case blocks the candidate before attestation. A separate clean installation exercises the wheel with its normal runtime dependencies.

The source scan in `project.cdx.json` inventories the checked-out project. `installed-distributions.json` records the locked environment used to generate the release evidence. `SHA256SUMS` covers the release distributions and evidence files. GitHub's build attestation binds the distribution bytes to the workflow identity and source revision.

Every candidate runs the committed per-case security-regression gate and retains its complete `security-regressions.json` report, including failures. Passing the finite fixture contracts is a release prerequisite, not an estimate of production efficacy. The normal CI `Verified CI` check also requires measured statement and branch coverage floors (90% and 75%) and all verification jobs to succeed.

Build/test jobs receive only read access to repository content. A separate attestation job receives OIDC and attestation-write permissions. Only the environment-gated publishing job can publish through its configured trusted-publisher identity. Neither job checks out or runs project source.

The build installs its frontend and backend from `requirements-ci.lock` with hash verification and builds with `--no-isolation`. It installs the wheel into a fresh environment with hash-checked binaries from `requirements-action.lock`, then collects the SBOM and benchmark evidence. The build uploads the distributions and evidence and passes their immutable GitHub artifact IDs to subsequent jobs.

A separate compatibility job downloads the candidate wheel by ID onto a fresh runner and tests installation and scanning against the published dependency ranges. Its token has no repository or OIDC permissions. It must pass before attestation. The attestation and publication jobs download the build's artifacts by ID, so files modified by a compatibility dependency cannot replace the candidate.

The consuming composite Action uses the same hashed runtime/build lock in an isolated environment and installs its reviewed source with dependency resolution and build isolation disabled.
