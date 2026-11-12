# Security policy

Nexus SymBiote is an Agent Bill of Materials toolkit. It is not related to Symbiote, the Linux malware of the same name reported in 2022.

Nexus SymBiote is alpha security tooling. Inventory, signature verification, and policy decisions have different meanings. A successful scan or low risk score does not establish that an agent, model, dataset, or tool is benign.

## Reporting a vulnerability

Report security-sensitive defects through the repository's **Security > Report a vulnerability** feature: [open a private report](https://github.com/Hunzee-VC/Nexus-Symbiote/security/advisories/new). Private vulnerability reporting is enabled for this repository; the report reaches the repository's administrators and stays private until an advisory is published. Do not put credentials, private BOMs, exploit details, or customer data in a public issue.

Include the affected commit or distribution version, platform and Python version, reproduction steps with synthetic inputs, expected and observed behavior, and the trust boundary crossed. Keep real credentials and sensitive agent context out of reproduction artifacts.

**What to expect.** The project has one maintainer and offers best effort, not a service level: an acknowledgement within 7 days, and coordinated disclosure 90 days after the report by default, or earlier once a fixed version is published. The reporter and the maintainer can agree on another date. Fixes ship as a new version, and the advisory names the affected and fixed versions.

**If nobody answers.** There is no second security contact yet ([continuity](GOVERNANCE.md#continuity)). If a private report has no acknowledgement after 7 days, open a public issue titled "Security report awaiting acknowledgement" that gives the report's date and nothing about its content. If the form itself is unavailable, open such an issue asking for a private channel instead; never put details in it.

**Scope.** A way to make a documented guarantee fail is in scope: a gate that passes when it should fail, collection that reads, executes or reaches the network where the documentation says it does not, a secret that reaches an inventory, log or export, or terminal or CI output an input can steer. The [known limitations](docs/known-limitations.md) are tracked publicly; a new consequence of one, such as a bypass the entry does not describe, is still worth a private report.

## Supported versions

Only the latest reviewed alpha revision is developed. There is no long-term support commitment or established production support window. Confirm release provenance and the matching source revision before installing a published distribution.

## Imported discovery evidence

Treat ShadowScan reports, CycloneDX imports, A2A cards, IDE settings, and extension manifests as untrusted inputs. A discovery record does not grant authority or authenticate the discovered endpoint. Verify the expected subject, signer, tenant, time, and policy before upgrading a claim. Never grant deployment or publication credentials to the import job merely to parse a report.

To require that a merged inventory's ShadowScan evidence comes from a signed report, name the report in an operator signature policy kept outside the checkout and pass it to `validate --project` or `risk --project` ([require a signed report in CI](docs/shadowscan-integration.md#require-a-signed-report-in-ci)). Setting `validate.require_discovery_signature: true` in the project policy also turns the check on. The content digest that `diff` compares detects drift; it does not authenticate a report.

## Security boundaries

Static collection must not execute project modules, model loaders, repository hooks, or MCP launch commands. Treat repositories, model files, tool metadata, registry records, and imported BOMs as hostile input. Run scans with read-only access and without deployment or publication credentials.

Every bound on what a scan reads fails closed. The [collection limits](docs/collection-limits.md) are operator settings, changed only with `--limit` or `NEXUS_SYMBIOTE_LIMITS`; nothing in the scanned checkout can change them. TypeScript MCP server files are parsed inside the scanning process by tree-sitter, which is native code. Size, node and time bounds limit that parse but do not isolate it, so a memory-safety defect in the parser would run with the scan's privileges.

Confined file operations and pinned stdio launchers require POSIX descriptor-relative and no-follow primitives. Unsupported platforms fail closed rather than weakening those checks. Hard links are regular files: a hard-linked file inside the scanned root is read and hashed like any other, so an inventory can describe an inode that also has a name outside the root. Run static collection with the content author's privileges rather than as root, on hosts with `fs.protected_hardlinks=1`, and extract untrusted archives with a tool that refuses link targets outside the destination (GNU tar, or Python `tarfile` with `filter='data'`). The configured hosted matrix targets Ubuntu with Python 3.11 through 3.14; it does not qualify macOS or Windows support.

`verify-live` is an explicit execution operation. Its operator-owned [launch policy](docs/cli-reference.md#launch-policy) must lie outside the scanned project and the repository that holds it, be writable only by its owner, and bind exact server references to independently obtained executable SHA-256 pins. It stages the approved bytes privately, passes no project arguments, clears inherited environment variables and sets only a default `PATH`, uses a private working directory and terminates the process group after bounded protocol collection. It invokes no tools. Launcher pins do not authenticate the OS, interpreter, linked libraries or other host dependencies. Execute launchers in an externally isolated worker with resource limits and restricted filesystem, identity and network access. `--record` emits a separate unsigned candidate, not an approval or admission decision; incomplete observations and missing tools fail closed, and changed or new tools, server declarations or server identity make it exit 1 unless `--accept-drift` is given. `verify-live` does not verify servers reached over HTTP; observe them with `discover-mcp --record` and compare the inventories with `diff`.

A signature proves that authorized key material signed particular bytes under the verifier's policy. It does not prove that the content is accurate or safe. A matching tool descriptor cannot prove that the backend behaves as declared. Enforcement integrations govern only calls actually mediated by those integrations.

Agent inventories can expose infrastructure, permissions, endpoints, and instruction fingerprints. Restrict access to exported evidence and review its contents before sharing it. Keep raw credentials out of BOMs, logs, and issue reports.

## Known limitations

<a id="known-limitations-in-010"></a>

Gates and `diff` compare what the collectors record. These limits matter most; the [known limitations](docs/known-limitations.md) list every limit by surface, with what to do about each.

- **What no collector reads passes every gate.** An MCP server started from application code, a Codex setting other than its approval, sandbox and MCP server settings, or an instruction file under a name the `prompt` collector does not read is not a coverage gap. `validate`, `risk` and `diff --fail-on-alert` pass when it changes.
- **Changed values need `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`.** Without it, `diff` does not alert on a changed MCP argument, environment or header value, or on a URL path changed on the same host: any MCP endpoint path, and an A2A or RAG path of the same depth.
- **MCP launchers are classified only in named shapes.** Other commands are recorded as local programs, and what a local program or project script runs is not read.
- **Some claims are not verified.** OpenSSF Model Signing signatures are not verified, and ShadowScan producer verification is opt-in and does not bind a report to a commit or time. Without `--project`, `validate` and `risk` check only the inventory's own claims.
- **A pull request can weaken its own gate** through `.nexus-symbiote.yaml` or the workflow file. Pass `--no-project-policy`, and require the workflow through an organization ruleset or a `pull_request_target` job.
- **Inventories written by 0.1.0 need a new baseline.** On an unchanged project, `diff --fail-on-alert` against one fails.
- **Limits bound size, not time.** Set a job timeout: within the collection limits, an SPDX export of a crafted project can run for hours.
