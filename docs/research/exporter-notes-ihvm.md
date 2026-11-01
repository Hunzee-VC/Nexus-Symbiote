# Exporter-stack research input from session ihVM (WP6/7/8 handoff)

> Written pre-M0 while WP6/7/8 were proposed to me; the lead reassigned WP6/7 (port of
> feat/symbote-core) and took WP8. These notes carry primary-source-verified standards facts
> and mapping designs. Where they disagree with spec/, **spec wins** — but the Verified-facts
> appendices below were checked directly against schemas/model repos on 2026-11-01 and should
> be folded into spec/divergences.md and docs/research/verified-claims.json.

# WP6 — The `symbiote:` taxonomy and the CycloneDX 1.7 mapping

Status: DRAFT v0.2 (pre-M0; kinds will be renamed to match frozen WP1 model on integration)
Owner: session `…ihVM`. Branch target: `wp06-cdx-exporter`.

## 1. Design rules

1. **One shared namespace.** Every agentic fact that has no native CycloneDX home is carried as a
   `properties[]` entry with a `symbiote:` name. No per-vendor keys (the `brox.*` anti-pattern from the
   source notes). The same names round-trip into SPDX via `/Extension/CdxPropertiesExtension`, which the
   SPDX model explicitly documents as "intended to be compatible with the CycloneDX property
   `properties`" (verified: spdx-3-model `model/Extension/Classes/CdxPropertiesExtension.md`, main @ fa3b579).
2. **Content digests are identity; names are locators.** Every component carries
   `symbiote:digest`; purl/name/alias are auxiliary. Resolution of name→bytes is recorded, never assumed.
3. **Never use `modelCard.properties`.** It exists in the 1.7 JSON schema but not in the 1.7 XSD
   (`modelCardType` has no `properties` element — verified by schema inspection, bom-1.7.schema.json vs
   bom-1.7.xsd), so JSON↔XML conversion silently drops it. All symbiote properties live at
   **component level**, which both serializations support. → DR-0001.
4. **Multi-valued = repeated property names.** CDX permits duplicate property names;
   `CdxPropertiesExtension` documents duplicate-name support. Never comma-join values.
5. **Determinism.** Under `--deterministic`: sorted keys, fixed property emission order (taxonomy order),
   `serialNumber = urn:uuid:<uuidv5(ns=symbiote, name=snapshot-digest)>`, `metadata.timestamp` set from the
   snapshot's `observed-at` (never wall clock). Golden files are byte-identical.

## 2. Property taxonomy v1 (normative list)

Namespace version marker (BOM metadata property): `symbiote:taxonomy` = `"1"`.

### 2.1 Identity & resolution (any component)
| Property | Value | Notes |
|---|---|---|
| `symbiote:kind` | one of WP1 kinds: `agent`, `agent-deployment`, `mcp-server`, `tool-definition`, `skill`, `instruction`, `prompt-template`, `model`, `serving-config`, `dataset`, `rag-index`, `memory-store`, `registry-entry`, `policy-bundle`, `evaluation`, `observation` | authoritative type; CDX `component.type` is only the nearest native bucket (DR-0002) |
| `symbiote:digest` | `sha256:<hex>` over the WP2 canonical form | primary key |
| `symbiote:resolution:requested-ref` | string | what the config asked for (`latest`, alias, tag) |
| `symbiote:resolution:resolved-ref` | string | immutable ref actually obtained (version+digest, revision SHA) |
| `symbiote:resolution:registry` | URL/id | where it resolved from |
| `symbiote:resolution:provenance` | `self-claimed` \| `verified-publisher` \| `build-attested` | registry assurance (source notes §registry) |
| `symbiote:resolution:log-inclusion` | transparency-log entry ref | optional |

### 2.2 Assurance & observation
| Property | Value |
|---|---|
| `symbiote:assurance` | `declared` \| `observed` \| `verified` (per claim, not per agent) |
| `symbiote:observed-at` | RFC3339 (from snapshot, not wall clock) |
| `symbiote:collector` | collector id/version |

### 2.3 Authority & context (the "composition ≠ authority" fix)
| Property | Value |
|---|---|
| `symbiote:capability` | repeated; `<class>[:<scope>]`, class ∈ `read-only`, `state-modifying`, `destructive`, `network-egress`, `filesystem-read`, `filesystem-write`, `code-execution`, `credential-access`, `financial`, `communication` |
| `symbiote:egress` | repeated; allowed destination pattern |
| `symbiote:credential` | `<type>:<lifetime>` e.g. `oauth:ephemeral`, `token:static-long-lived` — **names/kinds only, never values** |
| `symbiote:approval-gate` | `none` \| `conditional` \| `required` |
| `symbiote:trust-zone` | `1-internal-verified` … `4-untrusted-public` |
| `symbiote:instruction-bearing` | `true`/`false` — does this context source carry instructions into the model |
| `symbiote:flag:rule-of-two` | computed: untrusted input + private data + egress channel all reachable |

### 2.4 Tool definitions (rug-pull surface)
| Property | Value |
|---|---|
| `symbiote:definition-digest` | JCS(SHA-256) over `{name, description, inputSchema, annotations}` (WP2 `tooldef`) |
| `symbiote:description-digest` / `symbiote:schema-digest` | sub-digests so a diff names the mutated surface |
| `symbiote:annotation:<hint>` | mirrored MCP annotations (`read-only`, `destructive`, `idempotent`, `open-world`) |
| `symbiote:transport` | `stdio` \| `http` \| `sse` |

### 2.5 Models & serving
| Property | Value |
|---|---|
| `symbiote:serialization-format` | `safetensors` \| `gguf` \| `onnx` \| `pickle` \| `pytorch-bin` \| `api` \| `unknown` |
| `symbiote:serialization-risk` | `code-exec-on-load` \| `data-only` \| `n/a-api` |
| `symbiote:trust-remote-code` | `true`/`false` |
| `symbiote:provider-alias` / `symbiote:resolved-snapshot` | alias vs provider snapshot id; absence of snapshot ⇒ `symbiote:pinned=false` |
| `symbiote:chat-template-digest` | executable Jinja is a separately compromisable artifact |
| `symbiote:signing-bundle` | OpenSSF model-signing / Sigstore bundle ref |

### 2.6 Snapshot binding & anti-rollback (BOM metadata)
`symbiote:snapshot-digest`, `symbiote:snapshot-serial` (monotone int), `symbiote:prior-snapshot`,
`symbiote:validity-until`, `symbiote:policy-digest` (digest of the policy bundle the runtime enforces),
`symbiote:companion-digest` (→ WP8).

### 2.7 Coverage (the "unknown ≠ absent" fix)
Repeated at BOM metadata: `symbiote:coverage:surface` (∈ `code`,`registry`,`identity`,`model-gateway`,
`tools`,`data`,`runtime`,`network`), `symbiote:coverage:excluded`, `symbiote:coverage:failed`.
A failed registry query MUST appear in `coverage:failed`; it never licenses "no shadow agents".

## 3. Kind → CycloneDX mapping

| WP1 kind | CDX home | Native fields used | Register |
|---|---|---|---|
| agent | `metadata.component`, type `application` | name, version, hashes | DR-0002 |
| mcp-server (stdio) | component `application` (assembly parent of its tools) | hashes, externalReferences(distribution), purl when derivable (`pkg:npm/...@ver` for `npx`, `pkg:pypi/...` for `uvx`) | DR-0010 |
| mcp-server (http/sse) | component + paired `services[]` entry (endpoints, `authenticated`, `trustZone`, `data[]` flows); linked via `symbiote:service-ref` | | DR-0004 (SPDX side) |
| tool-definition | nested component, type `data`, child of its server | hashes = definition digest | DR-0003 edges |
| instruction / prompt-template / skill | component type `file` | hashes over exact bytes | |
| model | component type `machine-learning-model` (+`modelCard` for human-facing card; **never** modelCard.properties) | pedigree for lineage where it fits | DR-0001, DR-0009 |
| serving-config | component type `data` attached to model via dependency `provides` | | |
| dataset / rag-index / memory-store | component type `data` (+ CDX `data` classification where applicable) | | DR-0011 |
| registry-entry | `externalReferences` type `distribution` on the resolved component + §2.1 resolution properties | | |
| policy-bundle | component type `data`, digest in hashes; referenced from metadata `symbiote:policy-digest` | | |
| evaluation | `declarations` (CDXA): claim per evaluation, evidence with harness/version/dataset digests; `targets` = component bom-ref | DR-0007 |
| observation | component properties (`symbiote:assurance=observed`, `observed-at`, `collector`) | DR-0005 |
| typed edges (invokes, delegates-to, retrieves-from, writes-memory-to, acts-as) | **companion document only**; CDX `dependencies[]` carries only dependsOn/provides projection | | DR-0003 |

## 4. Exporter/importer contract

- `symbiote export --format cdx-1.7 [--spec 1.6] --deterministic --loss-report loss.json`
- Export MUST emit a loss report (WP8 schema): every (kind, field) with disposition
  `native` | `property` | `companion-only` | `dropped`, each non-`native` row keyed to a DR id.
- Import MUST: verify `symbiote:taxonomy` version; verify digests where bytes are reachable; mark every
  ingested claim `assurance=declared` unless an attached attestation upgrades it; refuse to feed
  **enforcement** (WP12/13) from a BOM whose coverage block is absent (fail-closed, DR-0012 analogue).
- 1.6 downlevel: identical except no `citations`; emit the same properties (they are version-agnostic).

## Verified-facts appendix (primary sources, checked 2026-11-01)

- CDX 1.7 vs 1.6 top-level delta = `citations` only; new $defs = citation, patents, IKEv2 crypto, TLP
  `distributionConstraints`; component additions `isExternal`, `versionRange`; **component.type enum
  unchanged** (no agent/tool kinds); `declarations` present in 1.6 AND 1.7. (Diffed
  bom-1.6/1.7.schema.json from CycloneDX/specification@master.)
- 1.7 XSD `modelCardType` lacks `properties` (bom-1.7.xsd) while 1.7 JSON schema has it → DR-0001.
- CDX hash-alg enum includes SHA-256, SHA3, BLAKE2b/3 — no Merkle/manifest construct → multi-shard model
  identity needs WP2 Merkle manifest carried via properties (DR-0010).

---

# WP7 — SPDX 3.0.1 mapping and the symbiote extension vocabulary

Status: DRAFT v0.2 (pre-M0). Owner: `…ihVM`. Branch target: `wp07-spdx-exporter`.

## 1. Version strategy (verified against spdx/spdx-3-model git tags, 2026-11-01)

- **Target: SPDX 3.0.1** (released; tooling baseline). Serialization: JSON-LD with the 3.0.1 context.
- **3.1-rc1** (tag exists): AI profile classes are UNCHANGED vs 3.0.1 (`AIPackage`, `EnergyConsumption`,
  `EnergyConsumptionDescription` — **no AIAgent/Prompt/RAG classes in the RC**). It DOES deprecate
  `autonomyType` in favor of `/Core/isoAutomationLevel` and grows RelationshipType 59 → 76 entries
  (+`evaluatedOn`, `finetunedOn`, `pretrainedOn`, `runsOn`, `verifiedBy`, `hasResolution`, …).
- **post-rc1 main** adds `/AI/InteractionTemplate` (prompt/template artifact, SubclassOf Core/Artifact)
  and references a future `/AI/AIAgent` (class file not yet present). Forward-compat table below.
- Consequence: we build on 3.0.1 + extensions now, with a mechanical upgrade path for 3.1.

## 2. Kind → SPDX 3.0.1 mapping

| WP1 kind | SPDX element | Purpose/relationships used | Register |
|---|---|---|---|
| agent (artifact) | `software_Package`, `primaryPurpose=application` | root via `describes`; duality with Core/Agent noted — the *running* collector identity is a separate `SoftwareAgent` in `CreationInfo` | DR-0013 |
| agent-deployment | `software_Package` + extension (environment, tenant) | `dependsOn` scoped via `LifecycleScopedRelationship(scope=runtime)` | |
| mcp-server | `software_Package` (`primaryPurpose=application`); **no Service class in 3.0.1** → endpoint/auth into extension | server `contains` tool-definitions; agent `dependsOn`(runtime) server | DR-0004 |
| tool-definition | `software_File`, `primaryPurpose=configuration`, `verifiedUsing: Hash(sha256 of canonical def)` | server `contains` tool; agent `usesTool` tool (native 3.0.1 type!) | DR-0003 shrinks SPDX-side |
| instruction / skill | `software_File`, `primaryPurpose=configuration` | `configures` agent (native) | |
| prompt-template | 3.0.1: `software_File` (purpose=configuration); **3.1+: `/AI/InteractionTemplate` via `configures`(runtime)** | forward-compat switch | DR-0014 |
| model | `ai_AIPackage`; fill native fields honestly (`typeOfModel`, `hyperparameter`, `safetyRiskAssessment` if assessed); `autonomyType` only for 3.0.1 compat (deprecated in 3.1) | `trainedOn`/`testedOn` to datasets where known | DR-0006 |
| serving-config | `software_File` purpose=configuration + `configures`(runtime) model | | |
| dataset | `dataset_DatasetPackage` (native `datasetUpdateMechanism` marks mutability) | | DR-0011 |
| rag-index / memory-store | `dataset_DatasetPackage` + extension (embedding-model binding, chunking, write-policy); modeled as **derived artifact**: index `generates`←/`descendantOf` corpus + embedding model | | DR-0011 |
| registry-entry | `ExternalIdentifier`/`ExternalRef` on the artifact + extension resolution record; 3.1 adds `hasResolution` — adopt when available | | |
| policy-bundle | `software_File` purpose=configuration; digest via `verifiedUsing` | | |
| evaluation | no native eval-provenance element → extension records keyed to artifact + `evaluatedOn` when on 3.1 | | DR-0007 |
| typed edges | native where match exists: `usesTool`, `invokedBy`, `delegatedTo`, `configures`, `trainedOn`, `dependsOn`, `contains` — **all 3.0.1-native (verified)**; `retrieves-from`/`writes-memory-to`/`acts-as` → `other` + extension qualifier + companion | | DR-0003 |

## 3. The symbiote extension vocabulary

Primary mechanism: **`/Extension/CdxPropertiesExtension`** attached to each element, carrying the SAME
`symbiote:` properties as the CDX export (duplicate names allowed; verified in the model doc). This gives
loss-free property parity across formats with zero invented classes.

Edge qualifiers (permission, granter, validity window — SPDX relationships carry no qualifiers) ride on a
`CdxPropertiesExtension` attached to the `Relationship` element itself (Relationships are Elements in SPDX
3.x, so they can carry extensions — this is the one structural trick SPDX enables that CDX cannot match;
mirrored into the companion for CDX consumers). → DR-0005 inverse.

## 4. Conformance guard (import)

SPDX profile conformance is per-profile and non-composable; "SPDX 3 support" does not imply AI + Dataset +
Extension semantics together. The importer verifies the document's declared profiles and **refuses to feed
enforcement** from documents missing required profiles; missing information imports as `unknown`, never as
a verified absence. → DR-0012.

## 5. Determinism

JSON-LD emitted with sorted keys, stable @id generation (`urn:symbiote:<kind>:<digest>`), `CreationInfo.created`
taken from the snapshot timestamp. Golden files byte-identical under `--deterministic`.

## Verified-facts appendix (2026-11-01, primary sources)

- Tags present: `3.0`, `3.0-rc1`, `3.0-rc2`, `3.0.1`, `3.1-rc1` (spdx/spdx-3-model).
- 3.0.1 RelationshipType = 59 entries incl. `invokedBy`, `delegatedTo`, `usesTool`, `configures`,
  `trainedOn`, `testedOn`, `hasDataFile`; 3.1-rc1 = 76 (+17 incl. `evaluatedOn`, `finetunedOn`,
  `pretrainedOn`, `hasResolution`, `runsOn`, `verifiedBy`). Counted from
  `model/Core/Vocabularies/RelationshipType.md` at each tag (method: `^- <entry>` lines).
- `autonomyType.md` @ main: "**DEPRECATED in SPDX 3.1.** Use /Core/isoAutomationLevel instead."
  `IsoAutomationLevel` vocabulary present (ISO/SAE automation levels); `isoAutomationLevel` property in
  Core/Properties at 3.1-rc1.
- `SoftwarePurpose` includes `model`, `data`, `configuration`, `evidence`, `manifest`, `bom` (3.0.1) —
  the companion document exports as `software_File` `primaryPurpose=bom`.
- AI profile @ 3.0.1 and @ 3.1-rc1: classes AIPackage/EnergyConsumption(+Description) only;
  `InteractionTemplate` exists on main only (post-rc1); `AIAgent` referenced in docs, class absent.

---

# WP8 — Companion document, loss model, cross-format linkage, divergence register

Status: DRAFT v0.2 (pre-M0). Owner: `…ihVM`. Branch target: `wp08-companion-loss-model`.

## 1. Why a companion document

CycloneDX and SPDX are projections; neither can carry the full agentic graph (typed edges with
qualifiers, authorization records, evidence, coverage). Rather than fork a third standard (the source
notes' explicit warning), SymBiote keeps ONE lossless, canonical, signable companion JSON and treats both
BOMs as derived views that reference it by digest. "Exporters must disclose any information lost during
conversion" is implemented mechanically: every export emits a loss report derived from the mapping tables.

## 2. Companion schema `symbiote-companion/1` (JSON, JCS-canonical, WP2 digest)

```jsonc
{
  "schema": "symbiote-companion/1",
  "snapshot": {
    "serial": 7,                      // monotone; anti-rollback
    "digest": "sha256:…",             // of this doc, JCS, excluding this field
    "prior": "sha256:…",              // hash chain
    "observedAt": "2026-11-01T12:00:00Z",
    "validityUntil": "2026-11-08T12:00:00Z",   // freshness; expiry forces re-attestation
    "policyDigest": "sha256:…"        // the policy bundle the runtime actually enforces
  },
  "nodes": [ { "id": "sha256:…", "kind": "tool-definition", "names": ["get_issue"],
               "locators": ["pkg:npm/@x/y@1.2.3"], "assurance": "observed",
               "properties": { "symbiote:…": ["…"] } } ],
  "edges": [ { "from": "sha256:…", "to": "sha256:…",
               "kind": "invokes|delegates-to|retrieves-from|writes-memory-to|acts-as|configures|contains|depends-on|approved-under|observed-using",
               "scope": "runtime|build|design",
               "qualifiers": { "permission": "…", "granter": "…", "validUntil": "…", "conditions": ["…"] } } ],
  "authorizations": [ { "subject": "sha256:…", "principal": "…", "delegatedBy": "…",
                        "actions": ["…"], "resources": ["…"], "conditions": ["…"],
                        "approval": "none|conditional|required", "expiry": "…", "policyRef": "…" } ],
  "evidence": [ { "claim": "…", "subject": "sha256:…", "method": "…", "collector": "…",
                  "at": "…", "attestation": "ref-or-digest", "assurance": "declared|observed|verified" } ],
  "coverage": { "surfaces": ["code","registry","identity","model-gateway","tools","data","runtime","network"],
                "excluded": ["…"], "failed": ["registry:…timeout"], "window": {"from":"…","to":"…"} }
}
```

Node ids ARE content digests (identity = content). Edges reference digests, so a mutated tool definition
cannot silently inherit its predecessor's edges.

## 3. Cross-format linkage (the triangle)

- CDX export: BOM metadata property `symbiote:companion-digest`; `serialNumber = uuidv5(snapshot.digest)`;
  `externalReferences` entry (type `other`, comment `symbiote-companion`) pointing at the companion.
- SPDX export: companion itself exported as `software_File` with `primaryPurpose=bom`,
  `verifiedUsing: Hash`; SpdxDocument `describes` it; every element carries the same
  `symbiote:companion-digest` property via `CdxPropertiesExtension`.
- Verification rule: CDX.serialNumber ↔ SPDX document id ↔ companion.snapshot.digest must agree;
  a consumer holding any two artifacts can detect a mismatched third. Signing (WP11) wraps the companion
  in DSSE; the BOMs then inherit integrity transitively through the digest.

## 4. Loss model (machine-readable)

`loss-report/1`: one row per (kind, field): `{ "kind": "...", "field": "...",
"disposition": "native|property|extension|companion-only|dropped", "register": "DR-00xx" }`.
Dispositions come from the WP6/WP7 mapping tables at build time — the report is generated from the same
table the exporter executes, so docs cannot drift from code. CI golden-tests the reports.
Round-trip contract: export→import across formats preserves all `native|property|extension` fields
bit-exact and recovers `companion-only` fields through the companion; `dropped` is forbidden for
security-critical fields (digest, capability, resolution, coverage) — the build fails if the table ever
maps one to `dropped`.

## 5. Divergence register (seed; each entry carries evidence)

| ID | Area | CDX 1.7 | SPDX 3.0.1 | Disposition | Evidence (verified 2026-11-01) |
|---|---|---|---|---|---|
| DR-0001 | modelCard.properties | JSON schema has it; XSD `modelCardType` lacks it → XML conversion drops data | n/a | never use; component properties instead | bom-1.7.schema.json vs bom-1.7.xsd inspection |
| DR-0002 | agent/tool component types | component.type enum unchanged 1.6→1.7; no agent/tool/prompt kinds | no AIAgent/Prompt/RAG classes in 3.0.1 or 3.1-rc1 | `symbiote:kind` property (CDX) / purpose+extension (SPDX) | schema diff; spdx-3-model tags |
| DR-0003 | typed edges | `dependencies[]` = dependsOn/provides only, no qualifiers | 59 native types incl. usesTool/invokedBy/delegatedTo/configures, but no qualifiers on edges | SPDX: native type + extension qualifiers; CDX: projection + companion | schema + RelationshipType.md |
| DR-0004 | remote service modeling | native `services[]` with endpoints, authenticated, trustZone | no Service class in 3.0.1 | SPDX: Package + extension | spdx-3-model 3.0.1 tree |
| DR-0005 | lifecycle scope on edges | none | `LifecycleScopedRelationship(scope=runtime)` native | CDX: companion | Core/Classes |
| DR-0006 | autonomy | none | `autonomyType` yes/no (3.0.1), deprecated in 3.1 for `isoAutomationLevel` | both: action-specific authority lives in companion `authorizations[]`; emit native field only as compat hint | autonomyType.md @ main |
| DR-0007 | eval provenance | CDXA `declarations` (claims/evidence) exists but conformance targets are free-form | no native eval element in 3.0.1 (3.1-rc1 adds `evaluatedOn` relationship only) | structured eval records in companion; CDX projects into declarations | schema; tag diff |
| DR-0008 | signing | native JSF enveloped signature (rarely used in ecosystems) | no in-document signature | DSSE over companion (WP11); BOMs inherit via digest | spec review |
| DR-0009 | serialization-format risk | no native field (modelCard/modelParameters lack it) | no native field in AI profile | `symbiote:serialization-format` + `-risk` property/extension | schema inspection |
| DR-0010 | model identity for sharded/converted weights | hashes[] is whole-artifact; purl qualifiers ambiguous for HF revision/quantization | `verifiedUsing: Hash` whole-artifact | WP2 manifest Merkle root carried as property; resolution record mandatory | hash-alg enum; purl spec |
| DR-0011 | mutable data (RAG/memory) | `data` component, static | `DatasetPackage` + native `datasetUpdateMechanism`; still snapshot-shaped | snapshot digests + validity + write-policy in companion | Dataset profile |
| DR-0012 | conformance composability | monolithic schema | profiles optional beyond Core; "SPDX-compatible" ≠ AI+Dataset+Extension together | importer verifies profile set; enforcement fail-closed | SPDX conformance docs |
| DR-0013 | agent-as-actor vs agent-as-artifact | n/a | Core/Agent = BOM author; agent artifact = Package | collector = SoftwareAgent in CreationInfo; product agent = Package; never conflated | Core/Classes |
| DR-0014 | prompt/template class | component type `file` | 3.0.1: File; main adds `/AI/InteractionTemplate` (post-rc1) | forward-compat switch keyed on target version | spdx-3-model main @ fa3b579 |

## 6. Open items blocked on fleet inputs

- WP1 final kind names + WP2 digest API names → s/placeholder/frozen/.
- WP4 authorization object shape → companion `authorizations[]` field names must match 1:1.
- Verified-facts register (…VoM3 + my workflow): citation URLs for DR evidence column where the claim
  originated in the source notes (CDX #973/#1015, cdxgen #4593, maintainer confirmation for DR-0001).
