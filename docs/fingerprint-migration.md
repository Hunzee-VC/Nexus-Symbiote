# Tool fingerprint migration

Prior versions used a serializer that was not RFC 8785 compliant. The corrected
serializer may produce different SHA-256 digests for the same tool definition,
particularly for floating point numbers and non-BMP property names. Current scanner
findings record `definition_hash_version: rfc8785-jcs-v2`. The v2 profile also
binds supported descriptor annotations; v1 and absent profiles require
recollection before verification.
An absent or unsupported version is not treated as verified. A bare
`sha256:` digest does not identify which serializer produced it.

Before using the corrected version for drift or policy decisions, re-collect
and re-approve both baseline and observed tool definitions under the same
version. Do not migrate a trusted baseline by copying its old digest or treat
old and new digests as directly comparable. Keep the original evidence for
audit. Malformed or non-finite numeric values now fail canonicalization rather
than being converted to null.

The source fingerprint covers the original declared name, description, input
schema and annotations, and also `title`, `outputSchema` and `_meta` when the
descriptor declares them. A definition without those members keeps the
fingerprint it had before they were bound, so `rfc8785-jcs-v2` is unchanged;
a tool whose descriptor declares one of them gets a new fingerprint once, and
its baseline needs one re-approval. Exported schemas omit literal defaults,
examples, constants and enumeration values, which can contain credentials. When
the displayed definition differs, `redacted_definition_hash` binds that view.
The inventory displays only the name, description, input schema and
annotations, so a tool that declares `title`, `outputSchema` or `_meta` always
has a `redacted_definition_hash`, and `validate` reports its fingerprint as
`unknown` (`descriptor_source_unavailable`) until source evidence corroborates
it. The source fingerprint is an unkeyed digest of the original, so anyone
holding the BOM who knows the rest of a descriptor can confirm a guess of an
omitted low-entropy literal or of scrubbed text; keep credentials out of tool
descriptors and treat exported BOMs as sensitive. For a static MCP
configuration, run `validate` with `--project` and
`--no-project-policy` to corroborate the source fingerprint against the
checkout. An inventory written by `discover-mcp --record` has no local source,
so such tools stay `unknown` there; `diff` against an earlier observation is the
check for them. A displayed schema with omitted literals is unsuitable for
deciding which arguments a live tool accepts.

Model components are now referenced by their path relative to the scanned
root: `model:<relative path>`, with the same relative path as `name` and
`source_path`. A model in a direct subdirectory of the root keeps its previous
reference; a model at the root or deeper in the tree gets a new one, so `diff`
against an older baseline reports it as removed and added. New model records
also bind ONNX external data, SavedModel variables, shard indexes,
configuration, tokenizer files, chat templates and declared custom code, and
`tokenizer_hash` and `chat_template_hash` are now digests over every such file
([model integrity](model-integrity.md)). Recollect and review the baseline once
after upgrading instead of comparing old and new model records.

For classified package launchers, new inventories retain `launcher_package`
alongside the declared version and, for an exact npm or PyPI version resolved
from the default registry, `package_url`. Inventories written by 0.1.0
identified only `npx`, `bunx`, `uvx`, `pipx` and `docker run` with a few
options, recorded a version-tagged image as pinned (only a digest pins an image
now) and carry the static configuration digest profile
`nexus-symbiote/mcp-static-config/v2`, which `validate --project` reports as
unknown. Recollect the baseline and review the identity, the new findings and
the `packages`, `package_sources` and `launch_context` properties before
approving the new snapshot. Python server references no longer contain the
declaration line, and the stdio note moved from `transport_security` to
`local_process`, so `diff` against a 0.1.0 baseline reports those records as
removed and added or changed once. An observed package name and version do not
establish the identity of installed executable bytes.

CycloneDX `dependsOn` contains only unconditional native `depends-on` edges
and, since projection 2, the dependency of a tool on the MCP server whose
unconditional `provides-tool` edge offers it. Invocation, lineage and
conditional relationships remain in the native extension, and the
`nexus-symbiote:dependency:relationship` property of a conditional edge carries
`"conditional": true`. CycloneDX and SPDX recovery check the standard projection
against the embedded document.

## SARIF rule identifiers

0.1.0 keyed SARIF rules by category (`nexus_symbiote/<category>`) and raised a
rule's `security-severity` to the highest severity among that category's
findings in the run. Rules are now keyed by category and severity
(`nexus_symbiote/<category>/<severity>`), so a rule's severity no longer
depends on the other findings. GitHub code scanning matches a result to an
existing alert only under the same rule, so the first upload after upgrading
closes every alert from 0.1.0 and opens new ones: dismissals and comments on
the old alerts do not carry over, so review the new alerts and dismiss them
again where that still applies. Later, a finding whose severity changes moves
to the rule of its new severity, and code scanning again opens a new alert and
closes the old one. The `nexus_symbiote/v1` fingerprint keeps its 0.1.0 value
and, like `primaryLocationLineHash`, stays the same when the severity changes;
consumers that match findings across runs should use it rather than the rule id.

## Standard projection versions

Every CycloneDX and SPDX export declares the projection that produced its
standard fields in the `nexus-symbiote:projection` property, and recovery checks
the document against that projection only. Projection 1 is what 0.1.0 wrote:
those exports have no marker and still recover. Projection 2
(`cyclonedx-1.7/2`, `spdx-3.0.1/2`) changes the standard fields as follows.

- CycloneDX: the repository agent of a scan is `metadata.component` instead of a
  component; registry entries are `library` or `container` instead of `platform`,
  their `version` carries exact versions only, and their other declarations move
  to the `nexus-symbiote:requestedVersion` property; instruction-file, RAG index,
  dataset and lockfile digests are `hashes`; `source_path` is
  `evidence.occurrences`; the composition names the subject; a repository scan
  has the `pre-build` lifecycle. Extension properties spell booleans `true` and
  `false` instead of `True` and `False`, write structured values as JSON, and
  omit a `toolCount` of 0.
- SPDX: license relationships point at `expandedlicensing_NoAssertionLicense`
  instead of `https://spdx.org/rdf/3.0.1/terms/Licensing/NoAssertion`, which SPDX
  3.0.1 does not define; placeholder AI and dataset text, `noAssertion` presence
  fields and `software_downloadLocation` are omitted; a `software_Sbom` element is
  the document's root; `profileConformance` adds `expandedLicensing`; and the
  default identifiers are `urn:uuid` IRIs instead of IRIs under
  `https://spdx.org/spdxdocs/nexus_symbiote`.
- Both: the loss report (profile `nexus-symbiote-export/v2`) also lists risk
  findings and declared versions that are not exact. A package URL is a standard
  identifier only when it is a PyPI, npm or OCI identity that agrees with the
  component: a PyPI or npm package URL only on a registry entry whose
  `registry_type` names that ecosystem and the registry it was resolved from, and
  an MCP server's package URL when it names the server's launcher package and
  version.

A document with an unknown marker, or one whose standard fields match a
projection other than the one it declares, is rejected. Recovery returns the
embedded inventory unchanged; re-export it to give standard-only consumers the
projection 2 fields. Only projection 1 recovery accepts the undefined license
IRI. Recovery compares standard fields with the embedded document text, so
fields that the native model gains in a later release do not make earlier
exports unrecoverable. See [standard exports](standard-exports.md) for every
field.

For historical CycloneDX exports that flattened all relationships into
`dependsOn` and wrote no `conditional` flag, the Python API accepts
`CycloneDXGenerator.recover(document, allow_legacy_relationships=True)`.
Legacy mode applies only to exports without a projection marker, and accepts
that exact historical edge projection only as a whole. It rejects a mixture of
the historical and current edge projections, and it still checks every other
public field, including the coverage composition, against projection 1.
Re-export the recovered inventory to give standard consumers the corrected
graph and flags.

Exports written by builds before 0.1.0 can fail recovery, because their
standard fields match neither projection.
Legacy mode, which only CycloneDX recovery has, does not help with:

- a CycloneDX export whose `dependsOn` already lists only unconditional
  `depends-on` edges but whose conditional edges have no flag;
- a CycloneDX export of a scan whose coverage is now `incomplete`, such as one
  narrowed with `--scanner`, written before every export had a `compositions`
  entry;
- any SPDX export written before the document `comment` and relationship
  `completeness` existed, with or without an unconditional relationship exported
  as `other`.

Regenerate such exports from the native AIBOM or by rescanning. Keep the
original export when a downstream consumer discards fields such as the
CycloneDX incomplete-composition claim, because recovery requires that
evidence to remain present. cyclonedx-python-lib 11.12.0, for example, drops
`compositions` whenever it reserializes a BOM. A reserialized `incomplete`
export then no longer recovers, while a reserialized `unknown` export still
does.

Current CycloneDX 1.7 and SPDX 3.0.1 exports are checked against pinned official
schemas and exercised by independent consumer-library round trips. These checks
do not certify semantic equivalence or admission authority.

Static MCP configuration source binding is a separate versioned contract. See
[source reconciliation and snapshot migration](verification-source-binding.md).
