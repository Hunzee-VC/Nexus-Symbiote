# Release procedure

The release workflow is manually dispatched from `main`. Its default creates a candidate and does not publish. This repository change does not itself configure GitHub environments, PyPI ownership, trusted publishers, or repository protection.

Before enabling publication:

1. Choose and verify the package name and release version. Confirm package-index ownership and that the distribution metadata, source tag, and changelog agree. The product name is Nexus SymBiote; the current distribution and command are `nexus-symbiote`.
2. Configure the PyPI trusted publisher for this repository, `.github/workflows/release.yml`, and the `pypi` environment. Use no long-lived API token.
3. Configure `pypi` required reviewers and restrict deployment to `main`. On the default branch, require review and successful checks for `Tests Python 3.11`, `Tests Python 3.12`, `Tests Python 3.13`, `Coverage Python 3.12`, `quality`, and `distribution` on the proposed revision. The workflow cannot create these controls itself.
4. Generate a release candidate with `publish=false`. Inspect its wheel, source distribution, SBOM, installed-distribution inventory, checksums, and build attestation. Test the wheel in an isolated environment outside the checkout.
5. Dispatch with `publish=true` only after that review. This builds and tests a new candidate from the selected main revision and requires the configured environment approval before publication; review the artifacts of this exact run at the approval gate. The publisher downloads the run's built distributions and authenticates through OIDC.
6. Verify the published wheel and sdist checksums and provenance against this exact run. Create a matching signed source tag and release notes. Do not claim publication succeeded until the package index and source revision agree.

The `distribution` job and the manual candidate build install the exact candidate wheel into the locked test environment. The acceptance runner verifies its SHA-256 against pip installation metadata, checks the package import location, and runs selected tests outside the checkout. These cover a clean repository baseline, a complete ShadowScan source report, a forged inventory omitting a project file, an MCP endpoint substitution, supplier-controlled policy discovery, a revoked trust signer, and distinct SPDX revision identities. A failed or skipped acceptance case blocks the candidate before attestation. A separate clean installation exercises the wheel with its normal runtime dependencies.

The source scan in `project.cdx.json` is a static inventory of the checked-out project; it is not a guarantee of complete runtime or build dependency coverage. `installed-distributions.json` independently records the wheel smoke-test environment. `SHA256SUMS` covers the release distributions and evidence files; GitHub's build attestation binds the distribution bytes to the workflow identity and source revision.

Build/test jobs receive only read access to repository content. A separate attestation job receives OIDC and attestation-write permissions. Only the environment-gated publishing job can publish through its configured trusted-publisher identity. Neither job checks out or runs project source.

Dependency locks make CI dependencies reviewable. Build isolation still resolves the build backend defined in `pyproject.toml`; bit-for-bit reproducible builds are not claimed. Test the supported minimum and current dependency sets before widening version bounds.
