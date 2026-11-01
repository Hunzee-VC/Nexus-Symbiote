# Divergence register

Every place where Symbiote's CycloneDX or SPDX output extends, narrows or re-purposes native semantics. Format
follows k8s-aibom's register: status `active | rescinded | upstreamed`, the spec section, what we do, what the
spec says, why, upstream tracking. CI checks that every rung-3/4 encoding in the exporters has an entry here.

| ID | Status | Spec section | What we do | What the spec says | Why | Upstream tracking |
|---|---|---|---|---|---|---|
| D-001 | active | CDX `component.type` | agents, tools, instructions, prompts, skills, data stores, policies are `application` / `data` / `file` / `library` components tagged `agentbom:kind` | no agent-native component types | the only way to stay schema-valid | CycloneDX 2.0 actor model (spec #909), `component.type` for runtime (spec #1145), Agent BOM proposal (spec #895) |
| D-002 | active | CDX `dependencies` | edge kinds carried as repeated `agentbom:edge:<type>` properties on the source element; qualifiers in the companion | `dependsOn`/`provides` only | relationships are the attack surface (`invokes`, `delegatesTo`, `writesMemoryTo`) | CycloneDX 2.0 relationships / declared-behaviour (spec #990) |
| D-003 | active | CDX | identities, credential bindings and grants as indexed `agentbom:identity|credential|authz:<i>:*` properties + companion records | no authority model | composition ≠ authority | spec #1015 (`toolManifestDigest`, `policyBundleDigest`), 2.0 declared behaviour |
| D-004 | active | CDX `dependencies.provides` | server → tool as `provides` | `provides` is for implemented specifications | a tool contract is a specification the server implements | — |
| D-005 | active | CDX `modelCard.properties` | never written; model facts on `component.properties` | JSON schema has it; initial 1.7 XSD lacked it (present from 1.7.2) | XML round-trip safety across 1.7.x and 1.6 parity | CycloneDX 2.0 `modelProperties` (spec #990) |
| D-006 | active | CDX `data.type = definition` | a tool definition is a `data` component of type `definition` with `hashes` = tooldef digest | `definition` = "data that defines something" | closest native semantics; the definition is model-visible data, not code | spec #1015 |
| D-007 | active | CDX `metadata.lifecycles` | snapshot kind as a predefined phase **plus** a named lifecycle `agentbom:snapshot:<kind>` | phases are build-centric | declared/approved/deployed/observed are not build phases | 2.0 OBOM / behaviour evidence |
| D-008 | active | CDX `vulnerabilities[]` | AI weaknesses keyed to MITRE ATLAS / OWASP ASI ids with `ratings.method = other` and justification mapping | CVE-shaped | no CVE exists for injection susceptibility | 2.0 `definitions.weaknesses` (spec #990) |
| D-009 | active | CDX `formulation` | runtime assembly events and the collection run as workflows with `taskTypes: ["other"]` | formulation describes build recipes | the 1.7 hook for runtime assembly the source analysis calls for | 2.0 behaviour evidence |
| D-010 | active | CDX `compositions` + properties | per-surface coverage with explicit `unknown`, failure classes and truncation | aggregate completeness only | unknown must be distinguishable from verified absence | 2.0 completeness scope |
| D-011 | active | CDX properties | per-element assurance/evidence locators as properties in addition to native `citations` | citations attribute, properties are grep-able | k8s-aibom precedent (`aibom.confidence`, `aibom.evidence.locator`) | property-taxonomy #175 (`ai:runtime:*`), k8s-aibom `ai:model:signature:*` proposal |
| D-012 | active | CDX properties | Merkle root, leaf hashes, redaction classes | no redaction or commitment semantics | verifiable redacted views | none yet — to propose with k8s-aibom |
| D-013 | active | CDX `type: library` | a skill directory is a `library` with nested `file` components | libraries are code | a skill is an installable package of instructions and scripts | 2.0 actor model |
| D-014 | active | CDX `externalReferences.type = other` | the companion document link | no BOM-profile reference type | avoids consumers parsing the companion as CycloneDX | — |
| D-015 | active | CDX `isExternal` + `services[]` | a hosted model is an external `machine-learning-model` component **and** a service for its endpoint | one object per thing | provider endpoint identity and model identity are separately compromisable | 2.0 |
| D-016 | active | SPDX extension | typed Symbiote extension classes (`.../spdx/0.1/terms/*`) on elements and on relationships | `Extension` is an open hook | agent qualifiers have no native class | SPDX 3.1 AI profile work (no `AIAgent`/`Prompt`/`RAG` in 3.1-rc1) |
| D-017 | active | SPDX `ai_AIPackage` | an agent application is an `AIPackage` with `primaryPurpose = application` | AIPackage is model-centric | gives access to autonomy/application fields | SPDX 3.1 `isoAutomationLevel`, `intendedUse` |
| D-018 | active | SPDX `software_Package(primaryPurpose = specification)` | a tool definition is a specification package verified by its digest | no tool-definition class | the model-visible contract is a specification | SPDX 3.1 Service profile |
| D-019 | active | SPDX `NoneElement` / `NoAssertionElement` | verified absence vs unknown per relationship | native idiom | the source analysis' "unknown ≠ absence" requirement | — |
| D-020 | active | SPDX `extension_CdxPropertiesExtension` | every `agentbom:*` property mirrored | the bridge exists for CycloneDX properties | lossless round trip | — |
