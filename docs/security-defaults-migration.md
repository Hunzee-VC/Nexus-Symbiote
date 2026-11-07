# Security fields: unknown rather than invented defaults

When evidence is missing, newly constructed native BOMs no longer infer tenant isolation, encryption at rest, remote-code settings, publisher verification, execution isolation, human approval, or whether approval is required. These fields now default to `null` in a full model dump and are absent when serialization excludes nulls. Both represent **unknown**, not `false` or an empty permission. Existing explicit `true`, `false`, and enum values retain their meaning.

`trust_remote_code` read from a local model configuration is only a declared setting. The actual runtime loader argument can differ, so even an explicit `false` does not prove remote code was disabled when the model ran. Missing, null, and non-boolean configuration values are unknown. Assess the effective runtime setting separately.

Consumers must handle unknown values explicitly. In particular, avoid boolean coercion (`if not value`) when false and unknown have different consequences. Older BOMs may contain security values created by earlier defaults; those values do not independently prove that the protections were observed. Recollect the evidence rather than upgrading their assurance based on the old default.

Agent autonomy also defaults to unknown. Loading an agent with an omitted or null
`autonomy_level` no longer creates an `L2-agent` assertion. An explicitly supplied
autonomy enum is retained as a declaration. Historical snapshots that already
contain `L2-agent` cannot reveal whether it was a producer assertion or an old
constructor default; recollect or review them before relying on that value.

CycloneDX and SPDX preserve explicit false and unknown native values through the
digest-bound native extension and report projection limitations. Standard-only
consumers must account for those limitations. Conditional edges are never
exported as typed SPDX relationships or in the CycloneDX dependency graph, and
every export states its coverage as `incomplete` or `unknown` in standard
fields. A lossless extension round trip
does not authenticate the values or their producer.

Snapshot comparison now covers component semantics, missing integrity evidence,
capabilities, authorization records and dependency conditions or assurance.
Set-like native collections ignore ordering; opaque JSON arrays, command
arguments and tool schemas retain order. Fresh claim observation timestamps do
not alone constitute component drift. The diff remains a comparison of supplied
snapshots; authenticate their provenance and evaluate coverage separately.
