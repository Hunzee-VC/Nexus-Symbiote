# Reviewed Gitleaks fixtures

The repository's `.gitleaks.toml` extends Gitleaks's built-in rules. It requires
version 8.30.1 or later for the rule-targeted allowlists. These exceptions were
checked with the official 8.30.1 Linux binary against its published checksum.
The `minVersion` field produces a warning rather than refusing older binaries;
operators must verify the scanner version themselves.
Gitleaks is an optional local or external scan; no repository workflow currently
invokes it, and these checks are not part of `Verified CI`.

Thirteen exceptions cover fourteen findings in the tracked tree. Each requires
all three of: one named detection rule, one exact repository-relative path, and
the entire exact matched value. `condition = "AND"` combines the path and value;
`targetRules` restricts the rule. Anchored hexadecimal escapes encode literal
bytes without creating new token-shaped strings in the configuration. No file,
directory, prefix, low-entropy value or line-number range is exempted.

| File | Rule | Reviewed origin and reason |
| --- | --- | --- |
| [Inventory attestation](inventory-attestation.md) | `generic-api-key` | The public SHA-256 identifier of the walkthrough signing public key, repeated in two command outputs; it is not private key material. |
| [A2A binding test](../tests/test_a2a_binding.py) | `generic-api-key` | Public fixed HMAC key for the committed deterministic test vector. |
| [A2A collection test](../tests/test_a2a_collection.py) | `generic-api-key` | Public key identifier intentionally retained by the ordinary-key-ID test. |
| [A2A collection test](../tests/test_a2a_collection.py) | `github-pat` | Patterned fake PAT for signature-header redaction. |
| [Collector security test](../tests/test_collector_security.py) | `generic-api-key` | Synthetic positional command argument for collector redaction. |
| [Confined bounds test](../tests/test_confined_bounds.py) | `generic-api-key` | Explicit canary proving an oversized input is never quoted in the failure. |
| [MCP environment sources test](../tests/test_mcp_environment_sources.py) | `github-pat` | Patterned fake PAT in an environment-variable name for name redaction. |
| [MCP source binding test](../tests/test_mcp_source_binding.py) | `generic-api-key` | Public fixed HMAC key for the committed deterministic test vector. |
| [RAG identifier redaction test](../tests/test_rag_identifier_redaction.py) | `generic-api-key` | Explicit synthetic bare-token constant for RAG identifier redaction. |
| [Scanner test](../tests/test_scanners.py) | `generic-api-key` | Synthetic API-key placeholder for environment-value redaction. |
| [Secret-name redaction test](../tests/test_secret_name_redaction.py) | `github-pat` | Patterned fake PAT in an authorization-header fixture. |
| [Secret-name redaction test](../tests/test_secret_name_redaction.py) | `jwt` | Synthetic JWT whose signature decodes to the literal word `signature`. |
| [Secret-name redaction test](../tests/test_secret_name_redaction.py) | `private-key` | Exact source span containing truncated, invalid private-key examples. The upstream rule spans several source lines because the first example alone is too short for its minimum body length. |

`tests/test_gitleaks_config.py` pins each reviewed value by SHA-256, verifies that
its bytes remain in the named fixture and refuses wildcard or broader matching.
Changing a fixture requires a new review; do not expand an expression until a
finding disappears. In particular, a path-and-line fingerprint in
`.gitleaksignore` could hide a changed value at the same location and is not a
substitute for this path, rule and full-value match.

The initial tracked-tree scan returned fourteen findings. With only this config
changed it returned none. Disposable copies then verified that all fourteen
changed fixture values were detected in their original contexts; forty fresh
canaries (API keys, PATs, JWTs and private keys) were detected across all ten
reviewed paths; and all thirteen reviewed values were detected outside their
approved paths. These are finite configuration regression checks, not evidence
that the repository or any future revision is free of secrets. No credential
was tested against a service, and the scan did not cover Git history.

For an equivalent current-tree scan, run a checksum-verified Gitleaks from the
repository root with `gitleaks dir --redact=100 .`. Review any finding's origin
before proposing an exception. Never baseline unreviewed output, suppress an
entire fixture file, or include raw detected values in logs or review reports.
