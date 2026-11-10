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
it. For a static MCP configuration, run `validate` with `--project` and
`--no-project-policy` to corroborate the source fingerprint against the
checkout. An inventory written by `discover-mcp --record` has no local source,
so such tools stay `unknown` there; `diff` against an earlier observation is the
check for them. A displayed schema with omitted literals is unsuitable for
deciding which arguments a live tool accepts.

For supported package launchers, new inventories retain `launcher_package`
alongside the declared version. An older inventory can lack this field even
when the current checkout identifies the package. Recollect the baseline and
review the identity before approving the new snapshot. An observed package
name and version do not establish the identity of installed executable bytes.

CycloneDX `dependsOn` now contains only unconditional native `depends-on`
edges. Capability, invocation and conditional relationships remain in the
native extension, and the `nexus-symbiote:dependency:relationship` property of
a conditional edge carries `"conditional": true`. CycloneDX and SPDX recovery
check the standard projection against the embedded document.

For historical CycloneDX exports that flattened all relationships into
`dependsOn` and wrote no `conditional` flag, the Python API accepts
`CycloneDXGenerator.recover(document, allow_legacy_relationships=True)`.
Legacy mode accepts that exact historical edge projection only as a whole. It
rejects a mixture of the historical and current edge projections, and it still
checks every other public field, including the coverage composition, against
the current projection. Re-export the recovered inventory to give standard
consumers the corrected graph and flags.

Other exports written by pre-release builds can fail recovery, because their
standard fields no longer match what the embedded document projects to.
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
