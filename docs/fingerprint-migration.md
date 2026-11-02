# Tool fingerprint migration

Prior versions used a serializer that was not RFC 8785 compliant. The corrected
serializer may produce different SHA-256 digests for the same tool definition,
particularly for floating point numbers and non-BMP property names. Current scanner findings record `definition_hash_version: rfc8785-jcs-v2`.
An absent or unsupported version is not treated as verified. A bare
`sha256:` digest does not identify which serializer produced it.

Before using the corrected version for drift or policy decisions, re-collect
and re-approve both baseline and observed tool definitions under the same
version. Do not migrate a trusted baseline by copying its old digest or treat
old and new digests as directly comparable. Keep the original evidence for
audit. Malformed or non-finite numeric values now fail canonicalization rather
than being converted to null.

The source fingerprint covers the original declared name, description, input
schema and annotations. Exported schemas omit literal defaults, examples,
constants and enumeration values, which can contain credentials. When the
displayed definition differs, `redacted_definition_hash` binds that view. For a
static MCP configuration, run `validate` with `--project` and
`--no-project-policy` to corroborate the source fingerprint against the
checkout. A displayed schema with omitted literals is unsuitable for deciding
which arguments a live tool accepts.

For supported package launchers, new inventories retain `launcher_package`
alongside the declared version. An older inventory can lack this field even
when the current checkout identifies the package. Recollect the baseline and
review the identity before approving the new snapshot. An observed package
name and version do not establish the identity of installed executable bytes.

CycloneDX `dependsOn` now contains unconditional native `depends-on` edges.
Capability, invocation and conditional relationships remain in the native
extension. CycloneDX and SPDX recovery check the standard projection against
the embedded document. For historical CycloneDX exports that flattened all
relationships into `dependsOn`, the Python API accepts
`CycloneDXGenerator.recover(document, allow_legacy_relationships=True)`.
This accepts the exact historical edge projection and still checks the other
public fields. Re-export the recovered inventory to give standard consumers
the corrected graph. Keep the original export when a downstream consumer
discards fields such as the CycloneDX incomplete-composition claim. Recovery
requires that evidence to remain present.
