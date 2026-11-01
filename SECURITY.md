# Security policy

Nexus SymBiote is alpha security tooling. Inventory, signature verification, and policy decisions have different meanings. A successful scan or low risk score does not establish that an agent, model, dataset, or tool is benign.

## Reporting a vulnerability

Report security-sensitive defects through the repository's **Security > Report a vulnerability** feature when available. If private reporting is unavailable, contact the repository owner through their GitHub profile and request a private reporting channel. Do not put credentials, private BOMs, exploit details, or customer data in a public issue.

Include the affected commit or distribution version, platform and Python version, reproduction steps with synthetic inputs, expected and observed behavior, and the trust boundary crossed. Keep real credentials and sensitive agent context out of reproduction artifacts.

The project does not promise response or remediation deadlines. Maintainers should acknowledge a report, agree on a disclosure plan with the reporter, and publish an advisory with affected and fixed versions when appropriate.

## Supported versions

Only the latest reviewed alpha revision is developed. There is no long-term support commitment or established production support window. Confirm release provenance and the matching source revision before installing a published distribution.

## Imported discovery evidence

Treat ShadowScan reports, CycloneDX imports, A2A cards, IDE settings, and extension manifests as untrusted inputs. A discovery record does not grant authority or authenticate the discovered endpoint. Verify the expected subject, signer, tenant, time, and policy before upgrading a claim. Never grant deployment or publication credentials to the import job merely to parse a report.

## Security boundaries

Static collection must not execute project modules, model loaders, repository hooks, or MCP launch commands. Treat repositories, model files, tool metadata, registry records, and imported BOMs as hostile input. Run scans with read-only access and without deployment or publication credentials.

A signature proves that authorized key material signed particular bytes under the verifier's policy. It does not prove that the content is accurate or safe. A matching tool descriptor cannot prove that the backend behaves as declared. Enforcement integrations govern only calls actually mediated by those integrations.

Agent inventories can expose infrastructure, permissions, endpoints, and instruction fingerprints. Restrict access to exported evidence and review its contents before sharing it. Keep raw credentials out of BOMs, logs, and issue reports.
