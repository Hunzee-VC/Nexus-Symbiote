# Security fields: unknown rather than invented defaults

When evidence is missing, newly constructed native BOMs no longer infer tenant isolation, encryption at rest, remote-code settings, publisher verification, execution isolation, human approval, or whether approval is required. These fields now default to `null` in a full model dump and are absent when serialization excludes nulls. Both represent **unknown**, not `false` or an empty permission. Existing explicit `true`, `false`, and enum values retain their meaning.

`trust_remote_code` read from a local model configuration is only a declared setting. The actual runtime loader argument can differ, so even an explicit `false` does not prove remote code was disabled when the model ran. Missing, null, and non-boolean configuration values are unknown. Assess the effective runtime setting separately.

Consumers must handle unknown values explicitly. In particular, avoid boolean coercion (`if not value`) when false and unknown have different consequences. Older BOMs may contain security values created by earlier defaults; those values do not independently prove that the protections were observed. Recollect the evidence rather than upgrading their assurance based on the old default.

The current CycloneDX exporter may omit explicit `false` properties; native JSON should be retained until lossless export handling is available.
