# Versioning

| Artefact | Version scheme | Where it appears | Compatibility rule |
|---|---|---|---|
| Tool (`symbiote` package) | SemVer `MAJOR.MINOR.PATCH` | `symbiote version`, `symbiote:version` | Standard SemVer |
| AgentBOM profile / companion schema | `MAJOR.MINOR` (currently `0.1`) | `agentbom:spec-version`, companion `specVersion`, schema `$id` path | Within a MINOR: add-only (new optional fields/names/enum values). A MINOR bump may add required fields with defaults. A MAJOR bump may remove or rename. |
| Property taxonomy | tied to the profile version | `spec/taxonomy.md` | Names are add-only; renames = new name + `rescinded` register entry for the old one; importers accept rescinded names for two MINOR versions |
| Digest types | `/v1`, `/v2` in the type URI | `digests.md` | A digest payload field set never changes under the same URI; any change is a new URI; both are computed during a transition |
| Predicate types | `/v1`, `/v2` in the predicate URI | `attestation.md` | Same rule as digest types; verifiers accept a configurable set |
| SPDX extension vocabulary | `/0.1/terms/` path segment | `spdx-mapping.md` | Same as the profile |
| Checks | ID stable forever (`SYM-TOOL-001`); severity and logic may change with a CHANGELOG entry | `checks.md` | Rego export regenerated in the same change |
| Conformance requirements | ID stable; new requirements are appended; a removed requirement keeps its ID as `retired` | `conformance.md` | |
| Divergence register | `D-NNN` stable; status `active | rescinded | upstreamed` | `divergences.md` | Updated in the same PR as any emitted-field change |

Every PR that changes an emitted field MUST touch: the model, the taxonomy (if a property), the divergence
register (if rung 3/4), the generated companion schema, the golden files, and `CHANGELOG.md`. CI enforces the
first four mechanically.
