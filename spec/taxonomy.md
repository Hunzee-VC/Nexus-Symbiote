# `agentbom:` property taxonomy — version 0.1

Namespace rules: ADR-0002. Grammar: `agentbom:<segment>(:<segment>)*`, segments lower-kebab ASCII; `<i>` is a
zero-based index segment for ordered records; names ending `:json` carry RFC 8785 canonical JSON; booleans
are `true|false`; tri-state facts are `true|false|unknown`; digests `sha256:<hex>`; times RFC 3339 `Z`;
lists are **repeated properties** unless indexed. Every name below is add-only within 0.x; see `versioning.md`.
Each name has a divergence entry when it encodes something CycloneDX cannot express natively (`divergences.md`).

## Document (`metadata.properties`)
| Name | Type / values | Card. |
|---|---|---|
| `agentbom:spec-version` | `0.1` | 1 |
| `agentbom:snapshot:kind` | `declared|approved|deployed|observed` | 1 |
| `agentbom:snapshot:serial` | int ≥ 1 | 1 |
| `agentbom:snapshot:prev` | digest or `none` | 1 |
| `agentbom:snapshot:digest` | digest (= Merkle root) | 1 |
| `agentbom:snapshot:not-before`, `agentbom:snapshot:not-after` | time | 0..1 |
| `agentbom:snapshot:observation-start`, `agentbom:snapshot:observation-end` | time | 0..1 (observed) |
| `agentbom:merkle:root`, `agentbom:merkle:leaf-count`, `agentbom:merkle:algorithm` | digest, int, `rfc6962-sha256-salted` | 1 |
| `agentbom:companion:ref`, `agentbom:companion:digest`, `agentbom:companion:schema` | uri/urn, digest, uri | 0..1 |
| `agentbom:coverage:<surface>` | `queried|partial|permission-denied|unreachable|not-attempted|truncated` for `code, registry, identity, model-gateway, tools, data, runtime, network, instructions, policy` | 1 each |
| `agentbom:coverage:window-start`, `agentbom:coverage:window-end` | time | 0..1 |
| `agentbom:coverage:source` | `<source>@<locator>=<ok|permission-denied|unreachable|timeout|truncated>` | 0..n |
| `agentbom:coverage:exclusion` | pattern | 0..n |
| `agentbom:flag:<name>` | `true|false|unknown` for `lethal-trifecta, rule-of-two-violation, unpinned-tool, floating-model-alias, destructive-open-world-ungated, unsigned-model, unsafe-serialization, unauthenticated-tool-server, static-long-lived-credential, undeclared-component-observed` | 1 each |
| `agentbom:flag:<name>:input` | bom-ref | 0..n |
| `agentbom:redaction:applied` | redaction class | 0..n |
| `agentbom:trust:revoked-publisher` | publisher identity | 0..n |
| `agentbom:loss:items` | int (number of loss-report items), `agentbom:loss:security-relevant` int | 0..1 |

## Any element
| Name | Values |
|---|---|
| `agentbom:kind` | `agent|sub-agent|external-agent|mcp-server|mcp-package|a2a-agent|openapi-service|builtin|tool|skill|instruction|prompt-template|model|dataset|rag-index|memory-store|retrieval-connector|knowledge-plugin|live-feed|policy-bundle|identity|registry-entry|software` |
| `agentbom:assurance` | `declared|observed|verified` |
| `agentbom:state` | `present|absent-verified|unknown` |
| `agentbom:evidence:source` | `mcp-config|tools-list|instruction-file|skill-md|framework-config|model-manifest|provider-api|registry|otel-span|k8s-aibom|sbom|agent-card|identity-config|human` |
| `agentbom:evidence:locator` | exact source path / JSON Pointer / `file:line` |
| `agentbom:evidence:collector` | `<name>@<version>` |
| `agentbom:evidence:collected-at` | time |
| `agentbom:evidence:ref` | evidence digest (repeated) |
| `agentbom:edge:<type>` | target bom-ref (repeated) for `uses-model, invokes-tool, provides-tool, delegates-to, spawns, loads-instruction, reads-context-from, reads-memory-from, writes-memory-to, acts-as, holds-credential, resolved-from, derived-from, embeds, evaluated-by, sends-data-to` |
| `agentbom:redaction:applied`, `agentbom:merkle:leaf` | class; leaf hash |
| `agentbom:trust:status`, `agentbom:trust:reason`, `agentbom:trust:decided-by`, `agentbom:trust:decided-at`, `agentbom:trust:expires`, `agentbom:trust:serial` | `allowlisted|quarantined|revoked`; text; party; time; time; int |
| `agentbom:import:dialect`, `agentbom:import:source-digest` | `cdxgen|k8s-aibom|harness-aibom|brox|syft|generic`; digest |

## Agent (`agentbom:agent:*`, `agentbom:deployment:*`)
`agentbom:agent:role` (`root|sub-agent|external-agent`), `:version`, `:digest`, `:framework`, `:framework-version`, `:purpose`, `:owner`, `:operator`, `:automation-level` (ISO/IEC 22989 names), `:autonomy:<i>:capability`, `:autonomy:<i>:mode` (`autonomous|approval-required|forbidden`), `:autonomy-assessment:scale`, `:autonomy-assessment:floor`, `:autonomy-assessment:ceiling`, `:autonomy-assessment:floor-level`, `:autonomy-assessment:ceiling-level` (ISO/IEC 22989 names), `:autonomy-assessment:oversight` (`bypassed|gated|unknown`), `:autonomy-assessment:initiation` (`schedule|event|human|unknown`), `:autonomy-assessment:declared`, `:autonomy-assessment:declared-source`, `:autonomy-assessment:assessor`, `:autonomy-assessment:assurance`, `:autonomy-assessment:basis` (repeated `<bound>:<rule>=<value>`), `:autonomy-assessment:evidence` (repeated digest), `:entrypoint`, `:parent`, `:policy-bundle-digest`,
`agentbom:a2a:card-digest`, `:card-url`, `:protocol-version` (repeated), `:skill` (repeated `<id>`), `:security-scheme` (repeated), `:signature-status` (`none|present|verified`),
`agentbom:deployment:environment`, `:tenant`, `:instance-id`, `:deployed-at`, `:ended-at`, `:workload-identity`, `:workload-ref`, `:snapshot-digest` (repeated).

## Tool server (`agentbom:mcp:*`) — on `services[]`
`agentbom:mcp:kind` (`mcp|a2a|openapi|builtin`), `:client`, `:transport`, `:endpoint-origin`, `:command`, `:args-digest`, `:launcher`, `:package-purl`, `:pinned` (tri-state), `:env-var-name` (repeated), `:header-name` (repeated), `:auth-mode`, `:auth-issuer`, `:scope-requested` (repeated), `:trust-zone`, `:crosses-trust-boundary`, `:protocol-version`, `:server-name`, `:server-version`, `:instructions-digest`, `:toolset-digest`, `:toolset-digest-status` (`ok|undigestable`), `:tool-count`, `:tools-list-ttl-ms`, `:tools-list-cache-scope`, `:server-digest`, `:client-trust:<key>`.

## Tool (`agentbom:tool:*`) — on `components[]` (`type: data`)
`agentbom:tool:server-ref`, `:definition-digest`, `:definition-digest-status` (`ok|undigestable`), `:definition-digest-reason`, `:full-digest`, `:description-digest`, `:input-schema-digest`, `:source` (`declared-config|registry|served-live|trace|approved-file`), `:annotation:read-only`, `:annotation:destructive`, `:annotation:idempotent`, `:annotation:open-world` (each `true|false|absent`), `:side-effect-class`, `:capability` (repeated), `:required-scope` (repeated), `:approval-gate`, `:text-flag` (repeated), `:state` (`declared|served|invoked`), `:invocation-count`, `:first-seen`, `:last-seen`.

## Instruction / prompt / skill
`agentbom:instruction:kind`, `:path`, `:size`, `:media-type`, `:line-endings`, `:precedence`, `:editor` (repeated), `:loads-remote` (repeated), `:secret-like-redacted` (bool), `:normalized-digest`, `:frontmatter-digest`;
`agentbom:prompt:engine`, `:role`, `:digest`, `:variables-schema-digest`, `:risk-class`;
`agentbom:skill:name`, `:manifest-root`, `:skill-md-digest`, `:allowed-tool` (repeated), `:compatibility`, `:file-count`, `:script-count`, `:has-scripts`, `:name-matches-directory`.

## Model (`agentbom:model:*`)
`agentbom:model:kind` (`weights|hosted|adapter|tokenizer|chat-template|embedding`), `:provider`, `:requested-ref`, `:resolved-ref`, `:resolved-ref-state`, `:alias-pinning` (`pinned|floating|unknown`), `:endpoint-origin`, `:manifest-format` (`oms-v1`), `:manifest-root`, `:manifest-ref`, `:manifest-items`, `:tensor-manifest-root`, `:serialization:format` (repeated), `:serialization:risk` (`none|low|code-exec-on-load|template-execution`), `:trust-remote-code`, `:chat-template-executable`, `:chat-template-digest`, `:tokenizer-digest`, `:generation-config-digest`, `:scanner`, `:scanner-report-digest`, `:derivation:<i>:kind`, `:derivation:<i>:parent`, `:derivation:<i>:parameters-digest`, `:derivation:<i>:parameters:json`, `:signature:status` (`unsigned|claimed|verified`), `:signature:outcome`, `:signature:reason`, `:signature:identity`, `:signature:issuer`, `:signature:log-entry`, `:signature:subject-name-mismatch`, `:signature:bundle-digest`, `:fingerprint:method`, `:fingerprint:digest`, `:fingerprint:sampled-at`, `:fingerprint:expires`, `:external` (1.6 downgrade only).

## Data (`agentbom:data:*`)
`agentbom:data:kind`, `:classification`, `:data-class` (repeated), `:trust-tier`, `:instruction-bearing` (tri-state), `:sanitization:<i>:name`, `:sanitization:<i>:digest`, `:snapshot:commitment`, `:snapshot:method`, `:snapshot:at`, `:live`, `:refresh-policy`, `:embedding-model` (bom-ref), `:chunking:json`, `:source:<i>:uri`, `:source:<i>:digest`, `:source:<i>:fetched-at`, `:source:<i>:license`, `:source:<i>:consent-status`, `:acl-mode`, `:writer` (repeated), `:tenant-isolation`, `:retention`, `:quarantine-status`, `:quarantine-since`, `:invalidation-dependent` (repeated), `:poison-scan-digest`.

## Identity, credential, authorization (on the subject element)
`agentbom:identity:<i>:kind`, `:ref`, `:issuer`, `:tenant`;
`agentbom:credential:<i>:identity`, `:kind` (`static-long-lived|ephemeral-task-scoped|obo-token|service-account|unauthenticated|unknown`), `:lifetime`, `:storage-kind`, `:storage-locator`, `:scope-granted:<j>`;
`agentbom:authz:<i>:id`, `:layer` (`declared|effective|observed`), `:capability`, `:scope-digest`, `:scope:resource:<j>`, `:scope:egress:<j>`, `:scope:data-class:<j>`, `:scope:spend-ceiling`, `:granter`, `:delegation-chain:json`, `:condition:<j>`, `:approval-gate`, `:not-before`, `:not-after`, `:policy-digest`, `:enforcement-point`, `:enforcement-attested`, `:credential-binding`, `:assurance`.

## Registry and resolution (on the resolved element)
`agentbom:registry:kind` (`mcp-registry|huggingface|npm|pypi|oci|nuget|mcpb|a2a-catalog|enterprise|other`), `:url`, `:entry-id`, `:entry-version`, `:role` (`distribution|discovery|approval`), `:status`, `:published-at`, `:updated-at`, `:is-latest`, `:publisher`, `:publisher-verification`, `:record-digest`, `:fetched-at`, `:package-digest`;
`agentbom:resolution:requested`, `:requested-kind`, `:resolved`, `:resolved-digest`, `:resolved-state`, `:resolved-at`, `:resolver`, `:alias-policy`, `:signer-status`, `:signer-outcome`, `:signer-identity`, `:signer-issuer`, `:log-type`, `:log-index`, `:log-inclusion-verified`, `:typosquat-nearest`, `:typosquat-distance`, `:warning` (repeated).

## Evidence, evaluation, VEX, policy, delta
`agentbom:eval:harness`, `:harness-version`, `:harness-digest`, `:dataset-digest`, `:config-digest`, `:threat` (repeated `<framework>/<id>`), `:result:<i>:json`, `:assessor`, `:third-party`, `:performed-at`, `:expires`, `:status` (`valid|stale`);
`agentbom:vex:justification`, `:scope:config-digest`, `:scope:subject`, `:expires`;
`agentbom:policy:kind`, `:engine`, `:enforcement-point`, `:bundle-digest`;
`agentbom:delta:type`, `:subject`, `:before`, `:after`, `:from-snapshot`, `:to-snapshot`, `:observed-at`, `:attestation-digest`.

## Generator provenance (`symbiote:*`, `metadata.properties` only)
`symbiote:version`, `symbiote:scan:root`, `symbiote:scan:started-at`, `symbiote:collector:<name>:version`, `symbiote:collector:<name>:status` (`ok|partial|failed|skipped`), `symbiote:level:claimed`, `symbiote:level:validated`, `symbiote:score`.

## Compatibility aliases accepted on import
k8s-aibom: `aibom.confidence`, `aibom.evidence.locator`, `aibom.evidence.source`, `aibom.workload.*`, `aibom.controller.*`, `aibom.redaction.applied`, `signature.status|outcome|reason|identity|rekorEntry|subjectNameMismatch`, and the `k8s-aibom:*` colon forms. cdxgen: `cdx:mcp:*`, `cdx:agent:*`, `cdx:agentic:*`, `cdx:ai:*`, `cdx:mcpb:*`, `cdx:gguf:*`. agent-harness-aibom: `harness-aibom:*`. Unknown properties are preserved verbatim.
