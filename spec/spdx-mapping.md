# SPDX 3.0.1 mapping (and 3.1 forward notes)

Symbiote emits SPDX 3.0.1 JSON-LD through `spdx-python-model` (`spdx_python_model.bindings.v3_0_1`:
`SHACLObjectSet`, `JSONLDSerializer`) and validates every document against the vendored official 3.0.1 JSON
schema (`schemas/vendor/spdx/spdx-json-schema-3.0.1.json`). Native classes and relationship types are used
wherever their meaning fits; agent-specific qualifiers go into **typed extension classes** in Symbiote's
namespace (verified to validate with zero errors: `extension_Extension` accepts any IRI `type` and
`unevaluatedProperties: true`), and every `agentbom:*` property is mirrored into
`extension_CdxPropertiesExtension` for lossless CycloneDX ⇄ SPDX round trips.

## 1. Identifiers and namespaces
- Document namespace: `https://aisecnomad.github.io/symbiote/spdx/doc/<agent-slug>/<snapshot-digest12>/`
  (override: `--spdx-namespace`). Element `spdxId` = namespace + `<bom-ref>` (so `bom-ref ↔ spdxId` is a pure
  function). `CreationInfo` is a blank node as the bindings emit.
- Extension vocabulary: `https://aisecnomad.github.io/symbiote/spdx/0.1/terms/<ClassName>` and
  `.../terms/<propertyName>`; published as JSON-LD context + SHACL shapes in `schemas/spdx/`.
- `profileConformance = [core, software, ai, dataset, extension]` plus `security` when VEX statements exist.

## 2. Class and relationship mapping
| Entity | SPDX 3.0.1 class | Key properties | Relationships |
|---|---|---|---|
| Document / snapshot | `software_Sbom` (`software_sbomType`: declared→`design`, approved→`build`, deployed→`deployed`, observed→`runtime`), `verifiedUsing Hash(sha256 = snapshot digest)`; ext `Snapshot{kind, serial, prev, merkleRoot, notBefore, notAfter, observationStart, observationEnd}`; ext `Coverage{...}` | `rootElement` = agent | `describes` |
| Creation | `CreationInfo{created, createdBy: [Organization owner?, SoftwareAgent "symbiote"], createdUsing: [Tool symbiote@v, Tool <collector>@v]}` | | `usesTool` (build) Sbom → Tool |
| Agent (artifact) | `ai_AIPackage` (`software_primaryPurpose: application`, `software_packageVersion`, `suppliedBy` owner, `software_downloadLocation` repo or `NOASSERTION`); `ai_autonomyType` from the autonomy profile (`yes` if any capability is autonomous, `no` if none, `noAssertion` if unknown); `ai_informationAboutApplication` = purpose; ext `AgentProfile{role, framework, automationLevel, autonomyProfile[], autonomyAssessmentScale, autonomyFloor, autonomyCeiling, autonomyFloorLevel, autonomyCeilingLevel, autonomyOversight, autonomyInitiation, autonomyDeclared, autonomyAssessor, autonomyBasis[], policyBundleDigest, entrypoint}` | | `describes`; sub-agents: `contains`/`dependsOn`; `delegatedTo` for delegation (see Identity) |
| Agent (principal) | `SoftwareAgent` (+ ext `AgentIdentity{principalOf, identityRefs[]}`) | | `invokedBy` (ToolDefinition → SoftwareAgent); `delegatedTo` (granter Agent → the `invokedBy` relationship) exactly as 3.0.1 defines |
| Deployment | `software_Package` (`primaryPurpose: other`) + ext `Deployment{environment, tenant, workloadIdentity, workloadRef, startedAt, endedAt}` | `externalIdentifier(urlScheme)` for cluster/namespace locators | `LifecycleScopedRelationship(dependsOn, scope=runtime)` Deployment → AIPackage; `hasEvidence` → snapshot attestation File |
| ToolServer | `software_Package` (`primaryPurpose: application`; `software_packageUrl` for stdio packages; `software_downloadLocation` = endpoint or purl location); `externalIdentifier(urlScheme)` endpoint; `externalRef(other, locator = registry record URL, comment "mcp-registry-entry")`; `verifiedUsing Hash` (server digest); ext `ToolServer{kind, client, transport, endpointOrigin, launcher, floating, authMode, trustZone, crossesTrustBoundary, instructionsDigest, protocolVersion, toolsetDigest, toolsetDigestStatus}` | | `LifecycleScopedRelationship(usesTool, runtime)` Agent → ToolServer; `contains` ToolServer → ToolDefinition; `availableFrom` → registry Organization |
| ToolDefinition | `software_Package` (`primaryPurpose: specification`), `verifiedUsing Hash(sha256 = tooldef digest, comment "agentbom:tool:definition-digest")`; ext `ToolDefinition{digestAlgorithm, digestStatus, fullDigest, readOnlyHint, destructiveHint, idempotentHint, openWorldHint, annotationsPresent, sideEffectClass, capabilities[], requiredScopes[], approvalGate, textFlags[], source, state}` | | `LifecycleScopedRelationship(usesTool, runtime)` Agent → ToolDefinition; `invokedBy` ToolDefinition → SoftwareAgent principal (observed: `startTime/endTime`) |
| Instruction / PromptTemplate | `software_File` (`primaryPurpose: configuration`, `contentType`), `verifiedUsing Hash`; ext `Instruction{kind, precedence, lineEndings, editors[], loadsRemote[], secretLikeRedacted}` / `PromptTemplate{engine, role, variablesSchemaDigest, riskClass}` | | `LifecycleScopedRelationship(configures, runtime)` File → Agent |
| Skill | `software_Package` (`primaryPurpose: module`) `contains` `software_File`s; ext `Skill{manifestRoot, allowedTools[], hasScripts, nameMatchesDirectory}` | | `configures` (runtime) |
| Model (weights) | `ai_AIPackage` (`primaryPurpose: model`, `software_packageUrl` purl), `verifiedUsing Hash(sha256 = manifest root)`; native `ai_typeOfModel`, `ai_domain`, `ai_hyperparameter`, `ai_informationAboutTraining`, `ai_limitation`, `ai_safetyRiskAssessment` where known; ext `ModelIdentity{manifestFormat, manifestRoot, manifestRef, tensorManifestRoot, serializationFormats[], serializationRisk, trustRemoteCode, chatTemplateExecutable, signatureStatus, signatureOutcome, signatureIdentity, signatureIssuer, logEntry}` | tokenizer / chat template as `software_File` | `descendantOf`/`ancestorOf` + ext `Derivation{kind, parametersDigest, parameters}` **on the Relationship**; `trainedOn`/`testedOn` → DatasetPackage; `hasDataFile` → Files |
| Model (hosted) | `ai_AIPackage` (`software_downloadLocation` = endpoint origin, `software_packageVersion` = resolved ref or requested alias); ext `HostedModel{provider, requestedRef, resolvedRef, resolvedRefState, aliasPinning, providerEvidence[], fingerprintMethod, fingerprintDigest, fingerprintExpires}` | | `LifecycleScopedRelationship(dependsOn, runtime)` Agent → Model with ext `EdgeQualifiers{edgeType: usesModel, role}` |
| DataSource | `dataset_DatasetPackage` (`dataset_datasetType`, `dataset_confidentialityLevel`, `dataset_datasetUpdateMechanism` = refresh policy, `dataset_intendedUse`, `dataset_hasSensitivePersonalInformation`, `dataset_datasetAvailability`); ext `MutableStore{kind, trustTier, instructionBearing, snapshotCommitment, snapshotMethod, live, embeddingModelRef, chunkingDigest, aclMode, writers[], tenantIsolation, retention, quarantineStatus}` | | `dependsOn(runtime)` Agent → DataSource with ext `EdgeQualifiers{edgeType: readsContextFrom|readsMemoryFrom|writesMemoryTo}`; `modifiedBy` DataSource → writer SoftwareAgent; index `descendantOf` corpus; index `dependsOn` embedding model |
| Identity | `SoftwareAgent` (workload / service account), `Person` (OBO user), `Organization`; ext `Identity{kind, ref, issuer, tenant}`; ext `CredentialBinding{kind, lifetime, storageKind, storageLocator, scopesGranted[]}` on the subject | | `invokedBy` chains |
| Grant | ext `CapabilityGrant{layer, capability, scopeResources[], scopeEgress[], scopeDataClasses[], spendCeiling, granter, delegationChain, conditions[], approvalGate, notBefore, notAfter, policyDigest, enforcementPointKind, enforcementPointLocator, enforcementAttested, credentialBindingRef, assurance}` attached to the subject element | one extension object per grant | — |
| Approval | `software_File` (`primaryPurpose: evidence`, the signed approval) + ext `Approval{approver, approvedSnapshotDigest, coversToolDigests[], coversModelIds[], coversGrantIds[], policyDigest, issuedAt, expires}` | | `hasEvidence` Sbom → Approval; `amendedBy` on supersession |
| RegistryResolution | ext `RegistryResolution{requestedKind, requestedRef, resolvedRef, resolvedDigest, resolvedState, resolvedAt, registryUrl, entryId, entryVersion, status, publishedAt, isLatest, publisher, publisherVerification, signerStatus, signerOutcome, signerIdentity, signerIssuer, logIndex, logInclusionVerified, aliasPolicy}` on the resolved element | | `availableFrom` element → registry `Organization` |
| Evidence | `software_File` (`primaryPurpose: evidence`, `verifiedUsing Hash`), `externalRef` (`secureSoftwareAttestation`, `runtimeAnalysisReport`, `securityThreatModel`, `riskAssessment`, `dynamicAnalysisReport`, `securityPenTestReport`) | | `hasEvidence` subject → Evidence |
| Evaluation | `software_File` (`primaryPurpose: evidence`) + ext `Evaluation{subjectConfigDigest, threatModel[], harnessName, harnessVersion, harnessDigest, datasetDigest, attackConditions, results[], assessor, thirdParty, performedAt, expires, invalidatedBy[]}` | | `testedOn` Model → eval DatasetPackage; `hasEvidence` AIPackage → Evaluation |
| VexStatement | `security_Vulnerability` + `externalIdentifier(securityOther, identifier = "AML.T0110" / "ASI04")`; `security_VexNotAffectedVulnAssessmentRelationship` (`justificationType`: guardrail-enforced→`inlineMitigationsAlreadyExist`, tool-disabled / approval-required→`vulnerableCodeNotInExecutePath`, not-reachable / egress-denied→`vulnerableCodeCannotBeControlledByAdversary`, component-not-present→`componentNotPresent`; `impactStatement`) or `security_VexAffected…` / `security_VexUnderInvestigation…` / `security_VexFixed…`; ext `VexScope{configDigest, justification, expires}` on the relationship | | `doesNotAffect` / `affects` / `underInvestigationFor` / `fixedIn` |
| Coverage | ext `Coverage` on the `software_Sbom`; `RelationshipCompleteness` (`complete|incomplete|noAssertion`) on every relationship; `to = [NoAssertionElement]` for **unknown** | native idiom | |
| TrustStatus | ext `TrustStatus{status, reason, decidedBy, decidedAt, expires, serial}` on the subject; revoked publisher as `Organization`/`SoftwareAgent` with ext | | `hasEvidence` → trust-status attestation File |
| Software layer | `software_Package`/`software_File` from the merged SBOM, `dependsOn` | foreign properties via `CdxPropertiesExtension` | |
| Property bridge | `extension_CdxPropertiesExtension{cdxProperty: [CdxPropertyEntry{cdxPropName, cdxPropValue}]}` on every element carrying `agentbom:*` properties | lossless | |

## 3. Unknown vs absence
An empty collection uses `to: NoAssertionElement` with `completeness: noAssertion` for its runtime
relationship. The coverage extension distinguishes a completed source query from a failed or skipped one.
Absence from the declared files or sampled traces does not establish absence from the running deployment.

## 4. Round trip and loss
`import(export(M))` must reproduce the model digest. Everything structured lives in extensions; everything
scalar is mirrored as properties; the loss report lists anything that fell back to `CdxPropertiesExtension`
only (`--no-extensions` mode) as `string-flattened`.

## 5. SPDX 3.1 forward notes (verified against `spdx-3-model` `3.1-rc1` and `develop`, 2026-11-01)
- Present: Core `isoAutomationLevel` (7 ISO/IEC 22989 levels; `ai_autonomyType` deprecated), Core `intendedUse`,
  `AI/InteractionTemplate` (an `Artifact` subclass for prompt-like templates), new profiles `Service`,
  `Operations`, `SupplyChain`, `Hardware`, and new `RelationshipType`s (`finetunedOn`, `pretrainedOn`,
  `evaluatedOn`, `validatedOn`, `verifiedBy`, `performedBy`, `runsOn`, `hasInstance`, `conformsTo`,
  `implementedBy`, `resolved`/`hasResolution`, `createdBy`, `locatedAt`); 77 relationship types in 3.1-rc1.
- **Absent:** `AIAgent`, `Prompt`, `RAG` classes. Symbiote promises no mapping to them.
- The 3.1 exporter (when 3.1 is final) maps: `automation_level → isoAutomationLevel`; `derivedFrom(fineTuneOf) →
  finetunedOn/pretrainedOn`; `Evaluation → evaluatedOn/validatedOn/verifiedBy`; `approvedUnder → conformsTo`;
  `RegistryResolution → resolved/hasResolution`; `ToolServer → Service profile`; `Deployment → hasInstance/runsOn`;
  `PromptTemplate → InteractionTemplate`.
