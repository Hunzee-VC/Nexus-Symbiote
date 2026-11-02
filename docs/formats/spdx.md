# The AgentBOM in SPDX 3.0.1

`symbiote scan` writes `agentbom.spdx.json`: SPDX 3.0.1 JSON-LD produced through the official `spdx-python-model`
bindings and **validated against the official 3.0.1 JSON schema**. Native classes and relationship types are used
wherever their meaning fits; agent-specific qualifiers are **typed extension classes** in Symbiote's namespace;
and every `agentbom:*` property is mirrored into `extension_CdxPropertiesExtension`, the bridge SPDX 3.0.1 ships
for CycloneDX properties, so the two formats carry one vocabulary losslessly. The excerpts below come from the
example scan; the normative mapping is [`spec/spdx-mapping.md`](../spec/spdx-mapping.md).

## Shape of the document

```text
$ symbiote validate out/agentbom.spdx.json
ok  out/agentbom.spdx.json (spdx-3.0.1)
```

The file is a JSON-LD document with `"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"` and a flat
`@graph`. The example's graph has 37 elements: 1 `SpdxDocument`, 1 `CreationInfo`, 1 `software_Sbom`,
1 `ai_AIPackage` (the agent), 7 `software_Package` (tool servers), 5 `SoftwareAgent` (the agent's principal, the
three credential identities and the producer), 5 `Tool` (Symbiote and the four collectors), 1 `Organization`
(the owner), 14 `LifecycleScopedRelationship` and 1 `Relationship`.

- **Identifiers.** The document namespace is
  `https://aisecnomad.github.io/symbiote/spdx/doc/<agent-slug>/<snapshot-digest12>/`, and every element's
  `spdxId` is that namespace plus its companion id (`…/agent:triage-agent`, `…/server:claude-code-github`), so
  `bom-ref ↔ spdxId` is a pure function and a consumer holding the CycloneDX and the SPDX documents can match
  elements without a lookup table.
- **Profiles.** `profileConformance: ["core", "software", "ai", "dataset", "extension"]` (plus `security` when
  VEX statements are present). SPDX conformance is per profile and non-composable, so the document says which
  profiles it claims instead of leaving it to the reader.
- **Creation.** One `CreationInfo` blank node (`created` = snapshot time; `createdBy` = a `SoftwareAgent` for
  Symbiote and the owner `Organization`; `createdUsing` = `Tool` elements for Symbiote and each collector;
  `comment` = tool version, profile version and snapshot digest).

## The snapshot: `software_Sbom` with typed extensions

```json
{
  "type": "software_Sbom",
  "spdxId": "https://aisecnomad.github.io/symbiote/spdx/doc/triage-agent/1672f9d2fa7b/sbom",
  "software_sbomType": ["design"],
  "rootElement": ["https://aisecnomad.github.io/symbiote/spdx/doc/triage-agent/1672f9d2fa7b/agent:triage-agent"],
  "element": ["…every element and relationship…"],
  "extension": [
    {"type": "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/Snapshot",
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/kind": ["declared"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/serial": [1],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/digest": ["sha256:1672f9d2fa7b0364833f857df21f0930e73ce68f2e051c1c51af466a3146651f"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/merkleRoot": ["sha256:1672f9d2fa7b0364833f857df21f0930e73ce68f2e051c1c51af466a3146651f"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/merkleLeafCount": [59],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/companionDigest": ["sha256:e2888aed689586c452328ea87daa921851a71e9bbb33e41da8056ea16038e3c0"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/companionRef": ["agentbom.json"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/specVersion": ["0.1"]},
    {"type": "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/Coverage",
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/surfaces": "…",
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/collectors": ["mcp-config@0.1.0:ok", "mcp-live@0.1.0:skipped", "mcp-registry@0.1.0:skipped", "otel-traces@0.1.0:skipped"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/textIncluded": [false],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/completeness": ["incomplete"]},
    {"type": "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/DerivedFlags", "…": "…"},
    {"type": "extension_CdxPropertiesExtension", "extension_cdxProperty": ["…"]}
  ]
}
```

`sbomType` maps the snapshot kind onto the native vocabulary (`declared → design`, `approved → build`,
`deployed → deployed`, `observed → runtime`). Everything the snapshot header needs beyond that — kind, serial,
`prev`, Merkle root and leaf count, validity, observation window, companion linkage — is a `Snapshot` extension;
coverage and the computed flags are `Coverage` and `DerivedFlags` extensions. Extension classes are IRIs under
`https://aisecnomad.github.io/symbiote/spdx/0.1/terms/`, and the 3.0.1 schema accepts any IRI `type` on an
`extension_Extension` with `unevaluatedProperties: true`, which is what makes a typed, schema-valid extension
possible without changing the standard ([D-016](../spec/divergences.md)).

## The agent: `ai_AIPackage` plus a `SoftwareAgent` principal

```json
{
  "type": "ai_AIPackage",
  "spdxId": "https://aisecnomad.github.io/symbiote/spdx/doc/triage-agent/1672f9d2fa7b/agent:triage-agent",
  "name": "triage-agent",
  "software_primaryPurpose": "application",
  "software_packageVersion": "2.3.1",
  "software_downloadLocation": "NOASSERTION",
  "suppliedBy": "https://aisecnomad.github.io/symbiote/spdx/doc/triage-agent/1672f9d2fa7b/party:acme-platform-security",
  "ai_autonomyType": "noAssertion",
  "ai_informationAboutApplication": "Label and acknowledge incoming GitHub issues for acme/widgets",
  "extension": [
    {"type": "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/AgentProfile",
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/role": ["root"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/framework": ["claude-agent-sdk"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/frameworkVersion": ["0.9.4"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/principalRef": ["agent:triage-agent/principal"]},
    {"type": "extension_CdxPropertiesExtension",
     "extension_cdxProperty": [
       {"type": "extension_CdxPropertyEntry", "extension_cdxPropName": "agentbom:agent:framework", "extension_cdxPropValue": "claude-agent-sdk"},
       {"type": "extension_CdxPropertyEntry", "extension_cdxPropName": "agentbom:agent:role", "extension_cdxPropValue": "root"},
       {"type": "extension_CdxPropertyEntry", "extension_cdxPropName": "agentbom:assurance", "extension_cdxPropValue": "declared"},
       {"type": "extension_CdxPropertyEntry", "extension_cdxPropName": "agentbom:kind", "extension_cdxPropValue": "agent"},
       "…"
     ]}
  ]
}
```

An AI agent is simultaneously an artefact and a principal, and SPDX 3.0.1 has no dual typing, so Symbiote emits
both halves and ties them together: the artefact is an `ai_AIPackage` with `primaryPurpose: application`
([D-017](../spec/divergences.md)), which gives access to the AI profile's `autonomyType` (`yes` when any
capability in the autonomy profile is autonomous, `no` when none, `noAssertion` when unknown — as here) and
`informationAboutApplication`; the principal is a `SoftwareAgent` (`…/agent:triage-agent/principal`) joined by an
`invokedBy` relationship, exactly as 3.0.1 defines `invokedBy` and `delegatedTo`. `downloadLocation` is
`NOASSERTION` when the agent has no download location, which is the honest value the Package inheritance forces.

## Tool servers, identities and edges

A tool server is a `software_Package` with `primaryPurpose: application`. A remote server carries its endpoint as
`downloadLocation`; a stdio server carries `packageUrl` and a `verifiedUsing` hash that is the `server/v1`
identity digest ([D-018](../spec/divergences.md) covers tool definitions as `specification` packages):

```json
{
  "type": "software_Package",
  "spdxId": "https://aisecnomad.github.io/symbiote/spdx/doc/triage-agent/1672f9d2fa7b/server:claude-code-filesystem",
  "name": "filesystem",
  "software_primaryPurpose": "application",
  "software_packageUrl": "pkg:npm/%40modelcontextprotocol/server-filesystem",
  "software_downloadLocation": "pkg:npm/%40modelcontextprotocol/server-filesystem",
  "verifiedUsing": [{"type": "Hash", "algorithm": "sha256", "hashValue": "f04220a451aae540636f80bc6ab054e0cc667e7a8da9833f23011d335c207cfc"}],
  "extension": [
    {"type": "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/ToolServer",
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/kind": ["mcp"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/client": ["claude-code"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/transport": ["stdio"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/packagePurl": ["pkg:npm/%40modelcontextprotocol/server-filesystem"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/floating": [true],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/launcher": ["npx"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/authMode": ["none"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/trustZone": ["local-process"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/crossesTrustBoundary": [false],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/envVarNames": ["FS_ROOT"]},
    {"type": "extension_CdxPropertiesExtension", "extension_cdxProperty": ["…the same agentbom:* properties as the CycloneDX service…"]}
  ]
}
```

Identities are `SoftwareAgent` elements with an `Identity` extension (`kind: api-key-ref`, `ref:
header:Authorization`) and an `externalIdentifier`; a credential reference is thus an element, never a value.

**Edges are typed relationships that carry qualifiers.** SPDX relationships are elements, so they can carry
extensions — the one structural trick SPDX enables and CycloneDX cannot match. Composition edges are
`LifecycleScopedRelationship` with `scope: runtime` and an `EdgeQualifiers` extension that records the AgentBOM
edge type and its qualifiers:

```json
{
  "type": "LifecycleScopedRelationship",
  "spdxId": "https://aisecnomad.github.io/symbiote/spdx/doc/triage-agent/1672f9d2fa7b/rel:holds-credential:cred:claude-code-github-header-authorization",
  "scope": "runtime",
  "relationshipType": "dependsOn",
  "from": "https://aisecnomad.github.io/symbiote/spdx/doc/triage-agent/1672f9d2fa7b/server:claude-code-github",
  "to": ["https://aisecnomad.github.io/symbiote/spdx/doc/triage-agent/1672f9d2fa7b/ident:claude-code-github-header-authorization"],
  "extension": [
    {"type": "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/EdgeQualifiers",
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/edgeType": ["holdsCredential"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/credentialKind": ["unknown"]}
  ]
}
```

Where 3.0.1 has a native relationship with the right meaning it is used (`invokedBy`, `delegatedTo`, `usesTool`,
`contains`, `configures`, `descendantOf`, `trainedOn`, `testedOn`); where it does not, `dependsOn` carries the
`edgeType` qualifier. The `agent → server` edges of the example are `dependsOn` with
`{edgeType: dependsOn, relation: mcp-server, client: claude-code, configScope: project, assurance: declared}`.

## Unknown is not absence

SPDX has the native idiom for the distinction Symbiote insists on. A surface that was queried and found empty is
a relationship whose `to` is `NoneElement` with `completeness: complete`; a surface that could not be examined is
a relationship to `NoAssertionElement` with `completeness: noAssertion` ([D-019](../spec/divergences.md)). The
example scan did not attempt the code, data, instructions and model-gateway surfaces, and says so:

```json
{
  "type": "LifecycleScopedRelationship",
  "spdxId": "https://aisecnomad.github.io/symbiote/spdx/doc/triage-agent/1672f9d2fa7b/rel:surface:code",
  "scope": "runtime",
  "relationshipType": "dependsOn",
  "completeness": "noAssertion",
  "from": "https://aisecnomad.github.io/symbiote/spdx/doc/triage-agent/1672f9d2fa7b/agent:triage-agent",
  "to": ["NoAssertionElement"],
  "extension": [
    {"type": "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/EdgeQualifiers",
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/surface": ["code"],
     "https://aisecnomad.github.io/symbiote/spdx/0.1/terms/coverageStatus": ["not-attempted"]}
  ]
}
```

A consumer that reads only native SPDX sees `dependsOn → NoAssertionElement, completeness: noAssertion` for the
agent's code dependencies; one that reads the extension learns which surface and why.

## Round trip and loss

`import(export(M))` must reproduce the model digest, which is why everything structured lives in typed
extensions and everything scalar is mirrored as `CdxPropertiesExtension` entries ([D-020](../spec/divergences.md)).
The SPDX loss report for the example is empty:

```json
{"direction": "model→spdx", "sourceFormat": "agentbom-model", "targetFormat": "spdx-3.0.1",
 "modelDigest": "sha256:1672f9d2fa7b0364833f857df21f0930e73ce68f2e051c1c51af466a3146651f", "items": []}
```

Validation runs the vendored official `spdx-json-schema-3.0.1.json`; the exporter is also exercised by
round-tripping its output through the `spdx-python-model` `v3_0_1` bindings (`SHACLObjectSet` /
`JSONLDSerializer`) in the test suite. `symbiote validate` recognises an SPDX document by its `@context`.

## Models, data, evidence and VEX

Beyond what the example exercises, the mapping covers the rest of the model: weights are `ai_AIPackage` with
`primaryPurpose: model`, `packageUrl`, `verifiedUsing Hash` = manifest root, the native `ai_typeOfModel`,
`ai_hyperparameter`, `ai_informationAboutTraining`, `ai_limitation`, `ai_safetyRiskAssessment` where known, and a
`ModelIdentity` extension (manifest format and root, per-tensor root, serialization formats and risk,
`trust_remote_code`, chat-template executability, signature status and outcome); lineage is `descendantOf` with a
`Derivation` extension **on the relationship** (kind and parameters digest); hosted models are `ai_AIPackage` with
a `HostedModel` extension (provider, requested and resolved refs, alias pinning, fingerprint). Data sources are
`dataset_DatasetPackage` with the native `datasetType`, `confidentialityLevel`, `datasetUpdateMechanism` and a
`MutableStore` extension (trust tier, instruction-bearing flag, snapshot commitment, writers, ACL mode, tenant
isolation, quarantine); `modifiedBy` points at memory writers. Evidence, approvals and evaluations are
`software_File` elements with `primaryPurpose: evidence` and `verifiedUsing`, reached through `hasEvidence`;
AI weaknesses are `security_Vulnerability` elements with an `externalIdentifier` of type `securityOther`
(`AML.T0110`, `ASI04`) and the VEX assessment relationships (`doesNotAffect`, `affects`, …) with a `VexScope`
extension binding the statement to a configuration digest. Grants are `CapabilityGrant` extensions on their
subject; trust status is a `TrustStatus` extension.

## Looking at 3.1

Symbiote promises no mapping to classes that do not exist. SPDX 3.1-rc1 (24 January 2026) deprecates
`ai_autonomyType` for the Core property `isoAutomationLevel` (the ISO/IEC 22989 ladder, which the AgentBOM
`automation_level` already uses by name), adds relationship types such as `finetunedOn`, `pretrainedOn`,
`evaluatedOn`, `validatedOn`, `verifiedBy`, `implementedBy`, `runsOn`, `hasInstance` and `hasResolution`, and —
on the post-rc1 development branch — an `AI/InteractionTemplate` artefact class for prompt-like templates. It
does **not** contain `AIAgent`, `Prompt` or `RAG` classes; those remain open proposals. The planned 3.1 exporter
mapping is listed in [`spec/spdx-mapping.md §5`](../spec/spdx-mapping.md) and the history of that question in
the [gap analysis](../gap-analysis.md).
