# Security policy

## Reporting a vulnerability
Please report security issues privately through GitHub's private vulnerability reporting on
`aisecnomad/symbiote` (Security → Report a vulnerability). Do not open a public issue. You will receive an
acknowledgement within 72 hours and a remediation plan or status within 14 days.

## Scope
In scope: the `symbiote` package and CLI, the companion schema and predicate definitions, the digest and Merkle
algorithms, the attestation and verification flows, and the GitHub Action. Out of scope: vulnerabilities in the
agents, MCP servers or models that Symbiote describes (report those to their maintainers), and the content of
third-party documents Symbiote imports.

## Supported versions
Security fixes are applied to the latest minor release. Pre-1.0, only the latest `0.x` release is supported.

## What an AgentBOM never contains
Symbiote records credential and header **names**, never values; identity **references** (SPIFFE IDs, client ids,
ARNs), never tokens; tool definitions by **digest** unless text inclusion is explicitly requested. A validator
rejects secret-shaped strings in identity fields, and emitted documents are scanned for credential shapes before
they are written. If you find a path that leaks a secret, treat it as a vulnerability and report it.

## Threat model
See [`THREAT-MODEL.md`](https://github.com/aisecnomad/Nexus-symbiote/blob/claude/symbiote-foundation/THREAT-MODEL.md) for the per-feature threat model: what each control detects or
prevents, how an attacker would evade it, and the residual risk.

## Verifying releases
Release artefacts are published to PyPI through trusted publishing and signed with Sigstore; a CycloneDX SBOM
and an AgentBOM of the example agent accompany each release. Verify with `sigstore verify` or `symbiote verify`.
