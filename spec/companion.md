# Companion AgentBOM document, linkage and loss reports

## 1. Purpose
The companion is the JSON serialisation of the semantic model (`agentbom-profile.md`). It is the structured
source of truth for consumers that need more than CycloneDX/SPDX can natively express — the **Policy Input
Document** for OPA and the built-in checker, the input to the Gateway Allowlist Bundle, and the record store
of the incident index. CycloneDX and SPDX documents are projections of it.

## 2. Format
- Media type `application/vnd.agentbom+json`; `$schema` =
  `https://aisecnomad.github.io/symbiote/schemas/agentbom/0.1/agentbom.schema.json` (also vendored in the wheel
  at `symbiote/schemas/agentbom/agentbom-0.1.schema.json`, so validation is offline).
- The JSON Schema (Draft 2020-12, `additionalProperties: false` everywhere) is **generated** from the Pydantic
  model (`AgentBOM.model_json_schema()` + post-processing) and checked into the repository; CI fails if the
  generated schema differs from the committed one, so code and schema cannot drift.
- Field names are camelCase in JSON (alias generator), snake_case in Python.
- Ordering: every list is sorted by `id` (entities), `(type, from, to)` (edges), or the natural key documented
  on the entity; under `--deterministic` the serialised bytes are stable.

## 3. Linkage
- CycloneDX → companion: `metadata.component.externalReferences[]{type:"other", url, hashes:[sha256], comment:"agentbom-companion"}` + `agentbom:companion:ref|digest|schema`.
- SPDX → companion: `Snapshot` extension `companionDigest`, `companionRef`.
- Companion → formats: `links.cyclonedx = {serialNumber, version, bomLink, digest}`, `links.spdx = {documentIri, digest}`.
- All three carry the **model digest** (`merkle.root`); `symbiote validate --cross` recomputes it from each and
  reports divergence, which detects post-export tampering of one representation.

## 4. Loss report
Every exporter and importer returns `(document, LossReport)`:
```
LossReport = {direction: model→cdx | cdx→model | model→spdx | spdx→model | cdx→spdx | spdx→cdx,
              source_format, target_format, model_digest,
              items: [{path (JSON Pointer into the model), entity, field,
                       reason: no-native-construct | enum-narrowed | precision-lost | cardinality-collapsed |
                               unsupported-in-target-version | string-flattened | redacted | library-limitation | foreign-unmapped,
                       preserved_in: companion | property | extension | embedded-record | dropped,
                       severity: none | info | security-relevant}],
              lossless: bool, retained_ratio: number}
```
Rules: items under the authorization or assurance planes (grants, digests, assurance, trust status, coverage,
resolution, signature facts) are `security-relevant`; under `--strict` any `security-relevant` item with
`preserved_in = dropped` fails the export (exit code 8). `symbiote convert --loss-report` prints the table and
writes `<out>.loss.json`. Round trip is tested on the model digest, not on bytes.

## 5. Embedded records (self-contained CycloneDX)
With `--embed-records` (default for Standard+), every structured record without a native CycloneDX home is
also carried inside the CycloneDX document as `declarations.evidence[].data[].contents.attachment`
(`contentType: application/vnd.agentbom.record+json`, base64 of the JCS bytes, `propertyName` = record kind),
so a lone CycloneDX file round-trips losslessly without the companion.

## 6. Importers
- CycloneDX 1.5–1.7 JSON: raw JSON validated against the vendored schema for its `specVersion`; dialect
  adapters for k8s-aibom (`aibom.*`, `k8s-aibom:*`, `signature.*`), cdxgen (`cdx:mcp:*`, `cdx:agent:*`,
  `cdx:ai:*`), agent-harness-aibom (`harness-aibom:*`); unknown properties preserved verbatim in
  `foreign_properties` with `agentbom:import:dialect` and `agentbom:import:source-digest` recorded.
  k8s-aibom `AIBOM` custom resources are accepted directly (`status.bomDocument` inline or referenced).
- SPDX 3.0.1 JSON-LD: via `JSONLDDeserializer`; Symbiote extensions decoded by IRI; `CdxPropertiesExtension`
  entries → properties → model.
- Imported documents are tagged `assurance=declared` unless they carry verifiable evidence
  (`agentbom-profile.md §5` for the k8s-aibom confidence mapping).
