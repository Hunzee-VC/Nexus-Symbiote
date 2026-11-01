# Security fields: unknown rather than invented defaults

When evidence is missing, newly constructed native BOMs no longer infer tenant isolation, encryption at rest, remote-code settings, publisher verification, execution isolation, human approval, or whether approval is required. These fields now default to `null` in a full model dump and are absent when serialization excludes nulls. Both represent **unknown**, not `false` or an empty permission. Existing explicit `true`, `false`, and enum values retain their meaning.

`trust_remote_code` read from a local model configuration is only a declared setting. The actual runtime loader argument can differ, so even an explicit `false` does not prove remote code was disabled when the model ran. Missing, null, and non-boolean configuration values are unknown. Assess the effective runtime setting separately.

Consumers must handle unknown values explicitly. In particular, avoid boolean coercion (`if not value`) when false and unknown have different consequences. Older BOMs may contain security values created by earlier defaults; those values do not independently prove that the protections were observed. Recollect the evidence rather than upgrading their assurance based on the old default.

The current CycloneDX exporter may omit explicit `false` properties; native JSON should be retained until lossless export handling is available.

## Behaviour changes

Review these before upgrading a pipeline that depends on the previous behaviour.

- **Policy discovery.** `scan` still discovers `.nexus-symbiote.yaml`. `risk` and `validate` no longer discover a policy; they read one only with `--policy PATH`. `--policy none` disables discovery.
- **Coverage.** A location that was checked and found empty is recorded as scanned, not excluded. Only real exclusions make a claim partial. Every built-in scanner is required, so running a subset makes the claim partial.
- **Gate.** The risk gate requires complete coverage, no critical finding, and a score below the threshold.
- **Policy fields.** Every field is enforced, and unknown keys are rejected. Thresholds are bounded to 0 through 100, and `warn_threshold` may not exceed `fail_threshold`. An invalid policy fails the command; nothing falls back to defaults.
- **Exit codes.** 0 pass; 1 gate, validation, or diff-threshold failure; 2 usage or input error; 3 unexpected internal error. A script that treats any non-zero exit as a gate failure should check for exit 1 specifically.
- **Output files.** Written with mode `0600`. A symbolic link at the output path is refused.
- **Redaction.** Credential-shaped values in component fields are redacted before output. Tool definition text, schemas, annotations, and hashes are not changed.
- **Diff.** `diff` fails at `high` by default. Use `--fail-on none` to report without failing.
- **Signing vocabulary.** Signing status uses `signature-not-found`, `signature-present-unverified`, and `signature-verified`. The legacy values `unsigned`, `sigstore-signed`, and `pgp-signed` are read as the current states, and none of them means verified.
- **GitHub Action.** Validation failures fail the job by default (`fail-on-validation-error`). The scanner allowlist accepts all eight scanners. `policy-file` selects a policy; when empty, the action runs with `--policy none`. SARIF upload and artifact upload can be turned off.
