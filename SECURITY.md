# Security

## Status and boundaries

Nexus SymBiote is alpha software. Treat a repository, BOM, model file, registry response and tool description as untrusted input. A static scan observes supported local files; it does not prove the absence of other components or the effective permissions or behavior of a running agent.

A digest identifies bytes only relative to a trusted expected digest. A signature must be verified against an authorized identity, issuer, subject and policy; it is not proof that content is safe or that the inventory is complete. Unknown, stale, excluded and failed collection are not evidence of absence.

Generated inventories may contain sensitive paths, endpoint details, prompts, tool descriptions or configuration. Review and protect outputs and CI artifacts, apply appropriate access controls and retention, and avoid scanning sensitive production environments until the collection and redaction controls have been assessed.

Do not execute discovered MCP servers, model code, hooks or other artifacts simply to inventory them. Scan untrusted projects in a disposable, least-privilege environment without production credentials or unnecessary network access.

The `verify-live` command is a deliberate, scoped exception: it launches the MCP servers already configured in the project's own config files, speaks only the read-only `tools/list` protocol method, never executes a tool, injects no arguments beyond those the user's config already specifies, and always terminates the process. It is intended for pre-deployment review of your own project, not for arbitrary untrusted repositories. A server's response to `tools/list` is a claim about its tools, not proof of its runtime behavior.

## Trust boundaries

- Project files and imported BOMs cross into the parser and must not escape the intended filesystem scope or exhaust resources.
- Model, registry and signature metadata are assertions until their source and subject are verified under an explicit trust policy.
- The `advisories` command is the only networked surface; it posts package name and version to OSV.dev. `scan` and `verify-live` make no network requests of their own (launched MCP servers may).
- The generated BOM and findings are inputs to a decision; they do not provide runtime isolation, authorization or enforcement.
- CI and artifact publishing have separate trust boundaries. Never expose release credentials to workflows processing untrusted repository content.

## Reporting a vulnerability

Please avoid publishing exploit details or secrets in a public issue. Contact the repository maintainers privately, or use GitHub's private vulnerability reporting if enabled for this repository. Include affected versions, a minimal reproduction without real credentials, impact, and any suggested mitigation. The maintainers will determine the supported disclosure channel and coordinate remediation.

## Deployment guidance

Before relying on a particular revision, independently test its security controls, supported formats and failure modes. Pin the revision, run with least privilege, validate outputs against the target standard, and keep production gating separate from a score or completeness claim.
