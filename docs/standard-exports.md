# Standard exports

One native AgentBOM projects to CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0 and a CycloneDX VEX document. This page says what each standard field carries, what only the native extension carries, and how to read the extension's properties. [What results do and do not establish](security-model.md#what-results-do-and-do-not-establish) applies to every format.

- [Projection versions](#projection-versions)
- [CycloneDX 1.7](#cyclonedx-17)
- [SPDX 3.0.1](#spdx-301)
- [Extension properties](#extension-properties)
- [SARIF for GitHub code scanning](#sarif-for-github-code-scanning)
- [VEX](#vex)
- [Minimum elements](#minimum-elements)
- [Loading exports into other tools](#loading-exports-into-other-tools)
- [Validation](#validation)

## Projection versions

CycloneDX and SPDX exports embed the native document and declare which projection produced their standard fields in the `nexus-symbiote:projection` property: `cyclonedx-1.7/2` or `spdx-3.0.1/2`. Exports written by 0.1.0 carry no marker and use projection 1. Recovery (`CycloneDXGenerator.recover`, `SPDXGenerator.recover`) checks every standard field against the declared projection of the embedded document and rejects an unknown marker, a document that claims a projection it does not match, and any edit to a standard field. The one omission it accepts is a missing CycloneDX `compositions` array, which readers such as cyclonedx-python-lib drop, when the projection's only composition says `unknown`; a composition that is present must match exactly. [Fingerprint migration](fingerprint-migration.md#standard-projection-versions) lists what changed between the projections.

## CycloneDX 1.7

| Native | CycloneDX | Notes |
| --- | --- | --- |
| Repository agent of a scan | `metadata.component` | The `agent:repository:` agent that `scan` assembles is the BOM's subject and is not repeated in `components`. Other inventories have no subject. |
| Component kind | `type` | Agents, MCP servers and clients, A2A endpoints and IDE agents are `application`; models are `machine-learning-model`; prompts, memory, RAG and data sources are `data`; tools, skills, guardrails and verified extensions are `library`. Registry entries are `container` for `docker-hub`, `docker` and `oci`, and `library` otherwise. |
| `version` | `version` | Exact versions only: a validated package URL version, an exact PyPI pin (`==`, `===` or a bare version), an exact npm version or an image version tag. Ranges, markers, URLs and tags such as `latest` go to `nexus-symbiote:requestedVersion` instead. Other component kinds export their declared version unchanged; any version longer than 1024 characters, the schema's limit, goes to the property too. |
| `package_url` | `purl` | Only a declared package URL that agrees with the component (see the loss report for omitted ones). |
| `hashes` and single-purpose digests | `hashes` | Declared digests, then an instruction file's `content_hash`, a RAG source's `index_snapshot_hash`, a dataset's `content_hash` and an npm lockfile integrity value when the algorithm is not already present. MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512 and BLAKE3 digests are supported; an empty, malformed or conflicting digest fails the export. |
| `source_path` | `evidence.occurrences[].location` | The file that declared the component. |
| `supplier`, `description` | `supplier.name`, `description` | As declared. |
| Unconditional `depends-on` | `dependencies[].dependsOn` | Source depends on target. |
| Unconditional `provides-tool` | `dependencies[].dependsOn` | The tool depends on the MCP server that provides it. |
| Conditional edges and every other relationship | `nexus-symbiote:dependency:relationship` property | Conditions, invocation, lineage and authority are not dependencies. A static scan's agent edges are all conditional, so a scan's graph holds at most tool-to-server rows. |
| Completeness claim | `compositions[].aggregate` | `incomplete` or `unknown`, never `complete`; with a subject, the composition names it in `assemblies` and `dependencies`. |
| Repository scan | `metadata.lifecycles` | `pre-build`: configuration read from a repository describes what is planned to run. |
| `metadata.authors` | `metadata.authors` | Exported when set; `scan` sets none. |

Risk findings, capabilities, authorizations, trust tiers, assurance levels and deployment profiles have no standard field and stay in the extension. Remote MCP servers and A2A endpoints are components, not CycloneDX `services`, and models have no `modelCard`.

## SPDX 3.0.1

| Native | SPDX | Notes |
| --- | --- | --- |
| Inventory | `software_Sbom` | The document's root element. Its root is the repository agent of a scan, otherwise every agent. `software_sbomType` is `source` for a repository scan. |
| Agents and models | `ai_AIPackage` | `software_primaryPurpose` is `application` or `model`; `ai_typeOfModel` carries a model's declared type and `ai_informationAboutApplication` an agent's description. |
| Memory, RAG and data sources | `dataset_DatasetPackage` | `dataset_datasetType` is `noAssertion`, the only property the class requires. |
| Prompts | `software_File` | `verifiedUsing` carries the content digest. |
| Everything else | `software_Package` | |
| Licenses | `hasDeclaredLicense` and `hasConcludedLicense` | Every AI and dataset package points both at `expandedlicensing_NoAssertionLicense`, the individual SPDX 3.0.1 defines for no assertion. |
| Relationships | `Relationship` | Unconditional `invokes`, `depends-on`, `trained-on` and derivation edges are typed (`usesTool`, `dependsOn`, `trainedOn`, `descendantOf`); every other edge is `other` with a `comment` naming the native relationship and its condition. |
| Coverage | relationship `completeness` and the document `comment` | `incomplete` or `noAssertion`. |

`profileConformance` lists `core`, `software` and `extension`, plus `expandedLicensing` when the license individual is used. The AI and Dataset profiles are not claimed: their classes are used, but the profiles also require a supplier, release time, version and download location (and, for datasets, an originator and build time) that an inventory does not collect. Unknown optional fields are omitted rather than filled with placeholder text, and `software_downloadLocation` is not written.

Element identifiers are scoped to one inventory revision. By default the document identifier is `urn:uuid:<uuid>` derived from the revision; `SPDXGenerator(namespace)` mints identifiers under `<namespace>/document/<revision digest>` instead. The namespace must be an absolute IRI without a query or fragment, and must not be under `spdx.org`.

## Extension properties

CycloneDX properties and SPDX `extension_CdxPropertyEntry` records use these names. A string value is written as is; booleans are `true` or `false`; numbers and structured values are compact JSON. Names and encodings are stable within a projection version. The `agentbom:` and `nexus-symbiote:` namespaces belong to this project and are not registered in the CycloneDX property taxonomy.

| Name | Where | Value |
| --- | --- | --- |
| `nexus-symbiote:document` | Document | The native AgentBOM as UTF-8 JSON with sorted keys and no whitespace (not RFC 8785). |
| `nexus-symbiote:documentDigest` | Document | `sha256:` and the SHA-256 of the UTF-8 bytes of the `nexus-symbiote:document` value, exactly as embedded. |
| `nexus-symbiote:lossReport` | Document | JSON naming selected native fields the standard fields omit or normalize (profile `nexus-symbiote-export/v2`). |
| `nexus-symbiote:projection` | Document | The projection version. |
| `nexus-symbiote:dependency:relationship` | CycloneDX document | One JSON object per native edge: `from`, `to`, `type`, and `"conditional": true` for a conditional edge. |
| `nexus-symbiote:discovery:reportSha256`, `:sourceFormat`, `:sourceStatus`, `:unmappedCount` | CycloneDX document | Imported ShadowScan report digest, format, status and number of unmapped entries. |
| `nexus-symbiote:omittedImportedFindings` | SARIF run, VEX document | How many imported ShadowScan findings were left out. |
| `nexus-symbiote:component` | Component | The native component as JSON. |
| `nexus-symbiote:relationship` | SPDX relationship | The native edge as JSON. |
| `agentbom:kind` | Component | The native component type. |
| `agentbom:claimsVerifiedByExporter` | Component | Always `false`: export does not verify claims. |
| `nexus-symbiote:packageIdentifierProjection` | Registry entry | `declared`, `unknown` or `unavailable-invalid`. |
| `nexus-symbiote:componentType`, `:trustTier`, `:assuranceLevel` | CycloneDX component | Native enumeration values. |
| `nexus-symbiote:requestedVersion` | CycloneDX component | A declared version that is not exact. |
| `nexus-symbiote:autonomyLevel`, `:framework`, `:modelRef`, `:toolRef` | CycloneDX agent | `autonomyLevel` is `unknown` when not declared; references repeat per target. |
| `nexus-symbiote:modelType`, `:provider`, `:serializationFormat`, `:serializationSafety`, `:signingStatus`, `:trustRemoteCode` | CycloneDX model | `trustRemoteCode` is a declared setting. |
| `nexus-symbiote:definitionHash`, `:definitionHashVersion`, `:annotation.<name>` | CycloneDX tool | One annotation property per MCP annotation. |
| `nexus-symbiote:transport`, `:toolCount`, `:versionPinned`, `:schemaHash` | CycloneDX MCP server | `toolCount` is written only when nonzero, because zero also means not observed. |
| `nexus-symbiote:promptType`, `:contentHash` | CycloneDX prompt | |
| `nexus-symbiote:guardrailType` | CycloneDX guardrail | |
| `nexus-symbiote:storeType`, `:tenantIsolated`, `:encryptionAtRest` | CycloneDX memory store | Absent means unknown. |
| `nexus-symbiote:corpusType`, `:embeddingModel` | CycloneDX RAG source | |
| `nexus-symbiote:registryType`, `:publisherVerified` | CycloneDX registry entry | |
| `nexus-symbiote:skillType` | CycloneDX skill | |

Projection 1 (0.1.0) wrote booleans as `True` and `False`, structured annotation values in Python notation, and `toolCount` `0` for unobserved counts.

## SARIF for GitHub code scanning

Every result has one location: a URI relative to `%SRCROOT%`, with no `originalUriBaseIds` and therefore no host path. `%SRCROOT%` is the working directory for `scan` (the scanned directory itself when it lies outside the working directory) and the workspace for the GitHub Action, so a project scanned below the repository root is located under its path. A finding takes its component's file; a tool without one takes its MCP server's file; anything else, such as a vector store detected from an import or a path outside the source root, is anchored to `.nexus-symbiote.yaml` in the scanned directory, and the result's `location_source` property says which applied. No result has a line region: the inventory records files, not lines.

Rules are keyed by category and severity (`nexus_symbiote/<category>/<severity>`), so a rule's `security-severity` (critical 9.5, high 8.0, medium 5.0, low 2.0, info 0.0) and `defaultConfiguration.level` never depend on the other findings in a run. Rule descriptions and help come from the catalog below, never from the inventory. Each result carries `partialFingerprints.primaryLocationLineHash` and `nexus_symbiote/v1`, both derived from the category, the component reference and the finding text: they stay the same across runs, checkouts and severity changes, and differ for two findings in one file. Because the severity is part of the rule id, a finding whose severity changes is reported under another rule: GitHub code scanning then opens a new alert and closes the old one, and a dismissal of the old alert does not carry over. The first upload after upgrading from 0.1.0, whose rule ids had no severity, re-creates every alert this way ([migration](fingerprint-migration.md#sarif-rule-identifiers)).

Messages and recommendations are one line of plain text: control, bidirectional and invisible characters become U+FFFD, the text is cut at 1,000 characters, every `://` and `www.` is defanged (`https[:]//`, `www[.]`) whatever precedes it, and brackets and backslashes are escaped as SARIF requires. Text from a repository therefore cannot form an embedded link, and a web address in it is not turned into a link. SARIF message text is plain text; a viewer that rendered it as Markdown or HTML would need its own escaping.

`invocations[0].executionSuccessful` is `false` when the inventory records a collection failure or a failed collector. `toolExecutionNotifications` lists failures as errors, coverage gaps and collectors that did not run as warnings, and the coverage summary; at most 100 notifications are written. A run with more than 25,000 results, which GitHub does not keep in full, gets a warning. The run's `coverage` property is `incomplete` or `unknown`. Findings on components imported from a ShadowScan report are not this tool's findings: they are omitted, and the run property `nexus-symbiote:omittedImportedFindings` counts them.

| Category | Rule title | CWE | OWASP |
| --- | --- | --- | --- |
| `version_pinning` | Unpinned version | CWE-829 | LLM03, ASI04 |
| `mutable_image_tag` | Mutable image tag | CWE-829 | LLM03, ASI04 |
| `transport_security` | Transport security | CWE-319 for high and critical findings | ASI07 |
| `authentication` | Missing authentication requirement | CWE-306 | ASI03, ASI07 |
| `serialization_format` | Unsafe model serialization | CWE-502 for critical, CWE-1336 for high findings | LLM03, ASI04, ASI05 |
| `serialization_format_unknown` | Unknown model serialization safety | CWE-502 | LLM03, ASI04 |
| `signing_status` | Unsigned model artifact | CWE-345 | LLM03, ASI04 |
| `code_execution` | Remote code execution enabled | CWE-494, CWE-829 | LLM03, ASI04, ASI05 |
| `invisible_characters` | Invisible characters in instructions | CWE-451, CWE-1427 | LLM01, ASI01 |
| `bidi_override` | Bidirectional override in instructions | CWE-451, CWE-1427 | LLM01, ASI01 |
| `tag_characters` | Unicode tag characters in instructions | CWE-451, CWE-1427 | LLM01, ASI01 |
| `prompt_size` | Large instruction file | none | LLM01, ASI01 |
| `instruction_layering` | Layered instruction files | none | LLM01, ASI01 |
| `permission_scope` | Unscoped agent permissions | CWE-250 | LLM06, ASI02, ASI03 |
| `capability_scope` | Destructive tool capability | none | LLM06, ASI02 |
| `data_integrity` | Retrieval source integrity | CWE-319 for high and critical findings | LLM04, LLM08, ASI06 |
| `rag_discovery` | Undeclared retrieval source | none | LLM08, ASI06 |
| `attestation` | Unattested extension | CWE-345 | LLM03, ASI04 |
| `completeness`, `detection_method`, `shadowscan-heuristic`, `shadowscan-inventory-unmatched` | Inventory notes | none | none |

`LLM` identifiers refer to the OWASP Top 10 for LLM Applications 2025 and `ASI` identifiers to the OWASP Top 10 for Agentic Applications. Tags use GitHub's `external/cwe/cwe-NNN` form and every rule is tagged `security`. A category outside the catalog gets a generic rule with only the `security` tag. The mapping states which weakness a finding indicates; a finding is a declaration in the repository, not a confirmed vulnerability.

The exporter checks its output with a structural SARIF validator (required properties, levels, rule cross-references, relative locations and fingerprints). The OASIS SARIF JSON schema is not vendored, so output is not validated against it.

## VEX

`vex` writes a CycloneDX 1.7 document whose `vulnerabilities` are the inventory's risk findings:

- Its serial number is derived from the inventory's, so it never shares the inventory's identity, and its version is the inventory's version. `metadata` names the producing tool and the inventory's timestamp, and an external reference of type `bom` points at the inventory with a BOM-Link (`urn:cdx:<serial>/<version>`). An inventory without a serial number gets the content-derived serial its CycloneDX export would have, so the link names that export. Like the CycloneDX and SPDX exports, `vex` rejects an inventory whose timestamp has no time zone, whose component references repeat, or whose dependencies name an unknown component.
- Components carry the type, version, package URL and digests the CycloneDX inventory export gives them.
- Each finding's identifier is `NEXUS-` and the SARIF `nexus_symbiote/v1` fingerprint: it stays the same when an artifact digest or the severity changes, and changes with the finding text.
- Descriptions and details are neutralized like SARIF messages.
- Findings on components imported from a ShadowScan report are omitted; the metadata property `nexus-symbiote:omittedImportedFindings` counts them.

What it cannot express: every statement is `in_triage`; the command takes no triage decisions, so it never states `not_affected`, `exploitable`, `resolved` or a justification. `NEXUS-` identifiers name inventory findings, not entries in any vulnerability database, so tools that apply VEX statements to known vulnerabilities have nothing to apply them to. VEX output states no coverage.

## Minimum elements

How an export covers the minimum SBOM elements that NTIA published in 2021 and that later guidance builds on. "Unknown" means the inventory does not collect the element; the export omits it rather than guess.

| Element | CycloneDX | SPDX | Status |
| --- | --- | --- | --- |
| Supplier name | `components[].supplier.name` | `suppliedBy` | Only when declared, such as an `agent.yaml` owner; usually unknown. |
| Component name | `name` | `name` | Collected. |
| Version | `version` | `software_packageVersion` | Exact versions only; ranges are in `nexus-symbiote:requestedVersion`. |
| Other unique identifiers | `purl`, `bom-ref`, `hashes` | `externalIdentifier`, `software_packageUrl`, `verifiedUsing` | Package URLs for exact PyPI and npm declarations; digests for files, models, prompts and lockfile entries. |
| Dependency relationship | `dependencies`, `compositions` | `Relationship` | Unconditional relationships only; conditional ones are in the extension or SPDX `other`. |
| Author of SBOM data | `metadata.authors`, `metadata.tools` | `CreationInfo.createdBy`, `createdUsing` | The tool is recorded; `scan` records no author. |
| Timestamp | `metadata.timestamp` | `CreationInfo.created` | Collected. |

CISA's updated minimum elements add a component hash, a license, the generating tool and the generation context; check the current CISA publication for the exact list. Hashes and the tool are covered as above; licenses are not collected (SPDX states no assertion, CycloneDX omits them); the generation context is `metadata.lifecycles` (`pre-build`) and `software_sbomType` (`source`) for a repository scan. Fields of AI-specific baselines that the inventory does not collect, such as training data, model performance and energy use, are absent. An export is evidence for such a review, not a determination that a baseline or regulation is met.

## Loading exports into other tools

Neither integration below is tested by this project; check the version you run.

- **Dependency-Track** ingests CycloneDX BOMs through its BOM upload API and user interface. Use the CycloneDX export rather than VEX: VEX statements apply only to vulnerabilities Dependency-Track already tracks, and `NEXUS-` findings are not among them. Check that your release accepts specification version 1.7, and whether it keeps component properties: the `nexus-symbiote:document` property holds the whole native inventory and can be megabytes long. Keep the original export, because only it recovers.
- **GUAC** ingests SPDX and CycloneDX documents. Check its support for SPDX 3.0.1 JSON-LD before relying on the SPDX export; the CycloneDX export carries the same package identities.

## Validation

Every CycloneDX, SPDX and VEX export is validated before it is returned, and recovery validates its input first. Validation uses the schemas vendored under `src/nexus_symbiote/generators/schemas/vendor/`, each checked against its recorded SHA-256 digest before use; the CycloneDX cryptography definitions that the 1.7 schema references are vendored too. Format assertions (`date-time`, `date`, `iri-reference`, `uri`, `idn-email`) use checkers defined in the package, so the result is the same whichever optional packages are installed. Validation time grows linearly with the document: array uniqueness is checked with a set, and SPDX's reference unions skip the class alternatives for identifier strings, which is equivalent for every document. SPDX remains the slowest: an SPDX export takes about 50 to 120 milliseconds per component, so 100,000 components, which one MCP configuration of under 2 MiB can declare, take hours. CycloneDX and VEX exports take about a millisecond per component. No export limit stops a large export; bound the job's time instead, for example with `timeout-minutes` in GitHub Actions. Because recovery validates first, recovering a large SPDX export takes about as long as writing it.
