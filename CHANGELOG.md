# Changelog

All notable changes to Symbiote are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/). The AgentBOM profile (property taxonomy, companion
schema, predicate types) is versioned independently of the tool; see `spec/versioning.md`.

## [Unreleased]

### Added
- Initial public foundation: semantic model, canonical digests, CycloneDX 1.7 and SPDX 3.0.1
  exporters, collectors, policy checks, conformance levels, attestations, and the `symbiote` CLI.
- WP10 observed layer: `mcp-live` collector (raw newline-delimited JSON-RPC stdio client — digests
  over the wire-exact objects, allowlist-gated execution, pagination, log-noise tolerance, honest
  coverage for remote transports), `otel-traces` collector (GenAI semconv spans → invoked tools
  with counts/windows, hosted-model alias routing, sub-agent spawns, data/memory sources, hashed
  system instructions, trace-summary evidence), `mcp-registry` collector (injectable transport,
  name-resolution records with publisher verification, typosquat distance, unreachable ⇒ unknown),
  the `k8s-aibom` importer (CR unwrapping via status.bomDocument, §5 confidence mapping, no
  signature laundering), and the drift-mode fixture MCP server
  (description|schema|annotations|order|pagination|unicode).
