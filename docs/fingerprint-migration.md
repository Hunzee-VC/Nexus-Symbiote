# Tool fingerprint migration

Prior versions used a serializer that was not RFC 8785 compliant. The corrected
serializer may produce different SHA-256 digests for the same tool definition,
particularly for floating point numbers and non-BMP property names. New scanner findings record `definition_hash_version: rfc8785-jcs-v1`.
An absent or unsupported version is not treated as verified. A bare
`sha256:` digest does not identify which serializer produced it.

Before using the corrected version for drift or policy decisions, re-collect
and re-approve both baseline and observed tool definitions under the same
version. Do not migrate a trusted baseline by copying its old digest or treat
old and new digests as directly comparable. Keep the original evidence for
audit. Malformed or non-finite numeric values now fail canonicalization rather
than being converted to null.

CycloneDX dependency edges encode only generic dependencies. Original SymBiote
relationship types are carried as JSON strings in `symbote:dependency:relationship`
metadata properties; consumers that discard those properties lose the typed
edge semantics. The SPDX exporter has not been independently validated and is
not claimed conformant by these changes.
