# The AgentBOM in CycloneDX 1.7

`symbiote scan` writes `agentbom.cdx.json`: a CycloneDX 1.7 document that **validates against the official
`bom-1.7` JSON Schema** and uses only sanctioned constructs. Agent semantics travel in four rungs, each used
only when the one above does not fit: a native field with matching meaning; a native structure narrowed by a
property; an `agentbom:` property from the closed [taxonomy](../spec/taxonomy.md); and the companion document,
linked by digest. Everything at rungs three and four has an entry in the [divergence register](../spec/divergences.md).
The excerpts below are from the example scan (`symbiote scan examples/triage-agent -o out/ --deterministic`);
the normative mapping is [`spec/cyclonedx-mapping.md`](../spec/cyclonedx-mapping.md).

## How it is produced

The exporter emits JSON directly from the semantic model ([ADR-0003](../spec/adr/0003-cyclonedx-direct-emission.md)):
`cyclonedx-python-lib`'s object model has no `declarations`, `citations`, `compositions`, `formulation` or
`modelCard` classes and drops `modelCard` on import, and those constructs are load-bearing here. Output is
deterministic under `--deterministic` (sorted arrays and properties, `metadata.timestamp` pinned to the snapshot
time, `serialNumber` content-addressed), and every document is validated before it is written:

```text
$ symbiote validate out/agentbom.cdx.json --json
[{"file": "out/agentbom.cdx.json", "format": "cyclonedx-1.7", "ok": true, "errors": []}]
```

Validation runs the vendored official Draft-7 schema with its `jsf-0.82` and `spdx` sub-schemas resolved locally
(so it works offline) and, when installed, `cyclonedx-python-lib`'s `JsonStrictValidator(V1_7)` as an
independent second opinion. A schema error names the path and the offending value, which is also how the
exporter is kept honest about `component.type`:

```text
FAIL bad.cdx.json (cyclonedx-1.7)
   components/0/type: 'agent' is not one of ['application', 'framework', 'library', 'container', 'platform',
'operating-system', 'device', 'device-driver', 'firmware', 'file', 'machine-learning-model', 'data', 'cryptographic-asset']
```

## The document header

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:f58c098a-c7db-55ae-bd9f-0a1d6d408725",
  "version": 1,
  "metadata": {
    "timestamp": "2000-01-01T00:00:00Z",
    "lifecycles": [
      {"phase": "design"},
      {"name": "agentbom:snapshot:declared", "description": "AgentBOM declared snapshot (spec/agentbom-profile.md)"}
    ],
    "tools": {"components": [
      {"type": "application", "bom-ref": "producer:symbiote", "name": "symbiote", "version": "0.1.0"},
      {"type": "application", "bom-ref": "producer:collector:mcp-config", "name": "mcp-config", "version": "0.1.0",
       "properties": [{"name": "agentbom:kind", "value": "collector"}, {"name": "symbiote:collector:mode", "value": "declared"}]}
    ]},
    "component": {
      "type": "application",
      "bom-ref": "agent:triage-agent",
      "name": "triage-agent",
      "version": "2.3.1",
      "description": "Label and acknowledge incoming GitHub issues for acme/widgets",
      "supplier": {"name": "Acme Platform Security", "url": ["https://acme.example"]},
      "externalReferences": [
        {"type": "other", "url": "agentbom.json", "comment": "agentbom-companion",
         "hashes": [{"alg": "SHA-256", "content": "e2888aed689586c452328ea87daa921851a71e9bbb33e41da8056ea16038e3c0"}]}
      ],
      "properties": [
        {"name": "agentbom:agent:framework", "value": "claude-agent-sdk"},
        {"name": "agentbom:agent:framework-version", "value": "0.9.4"},
        {"name": "agentbom:agent:owner", "value": "party:acme-platform-security"},
        {"name": "agentbom:agent:role", "value": "root"},
        {"name": "agentbom:assurance", "value": "declared"},
        {"name": "agentbom:evidence:locator", "value": "agent.yaml"},
        {"name": "agentbom:evidence:source", "value": "config"},
        {"name": "agentbom:kind", "value": "agent"},
        {"name": "agentbom:merkle:leaf", "value": "sha256:842324561a975eb88c9740cea5db5aa1871fbea09f5d8e8338efb5bd64b88c08"}
      ],
      "tags": ["agent"]
    }
  }
}
```

- `serialNumber` is a UUIDv5 of the snapshot digest, so the BOM's identity is content-addressed and BOM-Links
  (`urn:cdx:<uuid>/<version>#<bom-ref>`) work natively; `version` is the snapshot serial.
- The snapshot kind is encoded twice: the nearest predefined lifecycle phase (`design` for declared, `post-build`
  for approved, `operations` for deployed, `discovery` for observed) and a **named** lifecycle
  `agentbom:snapshot:<kind>`, which is authoritative ([D-007](../spec/divergences.md)).
- `metadata.tools.components[]` lists Symbiote and every collector that ran; `metadata.component` is the root
  agent, an `application` tagged `agentbom:kind=agent` with its owner as `supplier`.
- The companion document is linked by an `externalReferences` entry of type `other` with the SHA-256 of its
  bytes, and again in `metadata.properties` (`agentbom:companion:ref`, `:digest`, `:schema`).

`metadata.properties` carries the document-level facts (79 properties in the example): `agentbom:spec-version`,
`agentbom:snapshot:kind | serial | prev | digest`, `agentbom:merkle:root | leaf-count | algorithm
(rfc6962-sha256-salted)`, one `agentbom:coverage:<surface>` per surface plus `agentbom:coverage:source` records
(`claude-code:project@.mcp.json=ok`, `user-scope@-=not-attempted`), the computed flags with their cited inputs
(`agentbom:flag:unpinned-tool = true`, repeated `agentbom:flag:unpinned-tool:input = server:…`), and the
generator-provenance names under `symbiote:` (`symbiote:version`, `symbiote:collector:<name>:status | version`,
`symbiote:level:claimed`). Multi-valued facts are **repeated properties with the same name**, never comma-joined,
and `agentbom:` is reserved for facts any generator could emit while `symbiote:` is reserved for facts about this
generator ([ADR-0002](../spec/adr/0002-agentbom-namespace.md)).

## Entities

**Tool servers are `services[]`.** A remote MCP server uses the native endpoint, authentication and trust fields;
everything agent-specific is an `agentbom:mcp:*` property:

```json
{
  "bom-ref": "server:claude-code-github",
  "name": "github",
  "group": "claude-code",
  "endpoints": ["https://api.githubcopilot.com/mcp/"],
  "authenticated": true,
  "x-trust-boundary": true,
  "trustZone": "external",
  "externalReferences": [{"type": "configuration", "url": "file://.mcp.json", "comment": "agentbom:source-locator"}],
  "properties": [
    {"name": "agentbom:assurance", "value": "declared"},
    {"name": "agentbom:credential:0:identity", "value": "ident:claude-code-github-header-authorization"},
    {"name": "agentbom:credential:0:kind", "value": "unknown"},
    {"name": "agentbom:credential:0:storage-kind", "value": "env"},
    {"name": "agentbom:credential:0:storage-locator", "value": "header:Authorization"},
    {"name": "agentbom:edge:holds-credential", "value": "cred:claude-code-github-header-authorization"},
    {"name": "agentbom:evidence:collector", "value": "mcp-config@0.1.0"},
    {"name": "agentbom:evidence:locator", "value": ".mcp.json#/mcpServers/github"},
    {"name": "agentbom:identity:0:kind", "value": "api-key-ref"},
    {"name": "agentbom:identity:0:ref", "value": "header:Authorization"},
    {"name": "agentbom:kind", "value": "mcp-server"},
    {"name": "agentbom:mcp:auth-mode", "value": "api-key"},
    {"name": "agentbom:mcp:crosses-trust-boundary", "value": "true"},
    {"name": "agentbom:mcp:endpoint-origin", "value": "https://api.githubcopilot.com/mcp/"},
    {"name": "agentbom:mcp:header-name", "value": "Authorization"},
    {"name": "agentbom:mcp:server-digest", "value": "sha256:7b2f02ac270ad6752c2066371be28ad830fb97cba5179e9cd952adadbb38dbc2"},
    {"name": "agentbom:mcp:tool-count", "value": "0"},
    {"name": "agentbom:mcp:transport", "value": "streamable-http"},
    {"name": "agentbom:mcp:trust-zone", "value": "external"},
    {"name": "agentbom:merkle:leaf", "value": "sha256:adeb0ebbb4b322b4437570b8481ceaf366eacefc821ff475670c6e80edadf0b2"}
  ]
}
```

Identities, credential bindings and grants have no native CycloneDX object, so they appear as indexed
properties on the subject (`agentbom:identity:<i>:*`, `agentbom:credential:<i>:*`, `agentbom:authz:<i>:*`) with the
full records in the companion ([D-003](../spec/divergences.md)); the header *name* is recorded, never its value.
A stdio server (`npx -y @modelcontextprotocol/server-filesystem@latest`) is a service without endpoints
(`authenticated: false`, `trustZone: local-process`) whose launch facts are properties — `agentbom:mcp:launcher=npx`,
`agentbom:mcp:package-purl=pkg:npm/%40modelcontextprotocol/server-filesystem`, `agentbom:mcp:pinned=false`,
`agentbom:mcp:args-digest`, `agentbom:mcp:env-var-name=FS_ROOT` — and whose package is a separate `application`
component linked through `dependencies[]`:

```json
{"type": "application", "bom-ref": "server:claude-code-filesystem/package", "name": "server-filesystem",
 "purl": "pkg:npm/%40modelcontextprotocol/server-filesystem",
 "properties": [{"name": "agentbom:kind", "value": "mcp-package"}, {"name": "agentbom:mcp:pinned", "value": "false"}]}
```

**Tool definitions are `data` components** of type `definition` with `hashes[]` = the `tooldef/v1` digest and
`group` = the server id ([D-006](../spec/divergences.md)); the model-visible text and schema are embedded as a
base64 attachment only with `--include-text`. The example's declared scan observed no tool definitions, so this
section of the document is empty until a live or approved snapshot is exported; the server → tool relation is
`dependencies[].provides` ([D-004](../spec/divergences.md)). Instructions and prompt templates are `file`
components with exact-byte hashes, skills are `library` components with nested files, models are
`machine-learning-model` components (weights: `hashes` = manifest root, `pedigree.ancestors[]` for lineage; hosted:
`isExternal: true` plus a `service` for the endpoint), data sources and policies are `data` components, all
tagged `agentbom:kind`. Model facts go on `component.properties`, **never** on `modelCard.properties`: the initial
1.7 XML and Protobuf schemas lacked that element (fixed in 1.7.1, [CycloneDX/specification#726](https://github.com/CycloneDX/specification/issues/726)),
and consumers pinned to earlier 1.7.x or to 1.6 would drop it ([D-005](../spec/divergences.md)).

**Edges.** `dependencies[]` carries the composition (`agent dependsOn servers, models, instructions, …`;
`server provides tools`); the edge *kind* is not expressible natively, so it is repeated as an
`agentbom:edge:<type>` property on the source element (`agentbom:edge:holds-credential` above) with the qualifiers
only in the companion ([D-002](../spec/divergences.md)):

```json
"dependencies": [
  {"ref": "agent:triage-agent", "dependsOn": ["server:claude-code-filesystem", "server:claude-code-github",
                                              "server:claude-code-triage-tools", "server:codex-github", "…"]},
  {"ref": "server:claude-code-filesystem", "dependsOn": ["server:claude-code-filesystem/package"]}
]
```

## Coverage, claims, attribution and assembly

**`compositions[]`** carries coverage: one entry per surface with `aggregate` `complete` (queried), `incomplete`
(partial) or `unknown` (not attempted), listing the `assemblies` on that surface, plus one document-level entry
([D-010](../spec/divergences.md)):

```json
"compositions": [
  {"bom-ref": "composition:code", "aggregate": "unknown"},
  {"bom-ref": "composition:tools", "aggregate": "incomplete",
   "assemblies": ["server:claude-code-filesystem", "server:claude-code-github", "…"]},
  {"bom-ref": "composition:document", "aggregate": "incomplete"}
]
```

**`declarations.claims[]`** restates every computed flag as a claim with its inputs as reasoning, so a consumer can
recompute it ([D-011](../spec/divergences.md)):

```json
{"bom-ref": "claim:flag:unpinned-tool:server:claude-code-filesystem", "target": "server:claude-code-filesystem",
 "predicate": "agentbom:flag:unpinned-tool=true", "reasoning": "inputs: server:claude-code-filesystem"}
```

**`citations[]`** (new in 1.7) attribute each element to the collector that produced it and the exact locator:

```json
{"pointers": ["/services/1"], "timestamp": "2000-01-01T00:00:00Z",
 "attributedTo": "producer:collector:mcp-config", "note": ".mcp.json#/mcpServers/github"}
```

**`formulation[]`** records how the BOM was assembled: one workflow for the collection run, one task per collector
with its status and reason (`agentbom:coverage:status=skipped`, `agentbom:coverage:reason=not-detected`), and —
for observed snapshots — one step per delta event ([D-009](../spec/divergences.md)). AI weaknesses, when a
document carries VEX statements, are `vulnerabilities[]` keyed to MITRE ATLAS or OWASP ASI ids with
`ratings[].method = other` and the agentic justification mapped onto the VEX vocabulary
(`approval-required → protected_at_runtime`, `egress-denied → protected_at_perimeter`, …; [D-008](../spec/divergences.md)).

## What did not fit: the loss report

Every export returns a loss report (`agentbom.cdx.loss.json`) listing each model field that has no native home,
where it was preserved and how much it matters:

```json
{
  "direction": "model→cdx",
  "sourceFormat": "agentbom-model",
  "targetFormat": "cyclonedx-1.7",
  "modelDigest": "sha256:1672f9d2fa7b0364833f857df21f0930e73ce68f2e051c1c51af466a3146651f",
  "items": [
    {"path": "/credentialBindings/cred:claude-code-github-header-authorization",
     "entity": "cred:claude-code-github-header-authorization",
     "reason": "no-native-construct", "preservedIn": "property", "severity": "security-relevant"},
    {"path": "/edges/holdsCredential:server:claude-code-github->cred:claude-code-github-header-authorization/qualifiers",
     "entity": "server:claude-code-github", "field": "qualifiers",
     "reason": "no-native-construct", "preservedIn": "companion", "severity": "info"},
    {"path": "/merkle/leaves", "reason": "no-native-construct", "preservedIn": "companion", "severity": "info"}
  ]
}
```

Items under the authorization or assurance planes are `security-relevant`; a `preservedIn: dropped` item of that
severity is what `--strict` (specified; exit 8) will refuse. Nothing is dropped in the example: credential
bindings survive as properties, edge qualifiers and Merkle leaves live in the companion.

## Interoperability

- **Consumers.** Any CycloneDX 1.7 consumer can read the document; those that do not know `agentbom:` see a valid
  BOM of applications, services and data components. Dependency-Track accepts 1.7 since v5.1.0 / v4.14.4; a
  `--cdx-version 1.6` downgrade (dropping `citations`, reported in the loss report) is specified for older sinks.
- **Producers.** The `agentbom:` taxonomy is deliberately tool-neutral so cdxgen, k8s-aibom or an enterprise
  registry could emit the same names; registration in the CycloneDX property taxonomy is planned after the first
  release. On import, Symbiote accepts k8s-aibom (`aibom.*`, `k8s-aibom:*`, `signature.*`), cdxgen (`cdx:mcp:*`,
  `cdx:agent:*`, `cdx:ai:*`) and agent-harness-aibom (`harness-aibom:*`) names and preserves unknown properties
  verbatim ([`spec/companion.md §6`](../spec/companion.md)); the k8s-aibom importer is implemented, the generic
  CycloneDX importer is pending.
- **Signing.** DSSE/Sigstore attestations are referenced through `externalReferences[]` of type `attestation` or
  `digital-signature` with hashes; CycloneDX JSF signing is specified as optional.
