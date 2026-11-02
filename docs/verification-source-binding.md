# Reconcile a BOM with its MCP configuration

`validate --project` checks a supplied inventory against freshly collected local
evidence. Static MCP server records now include `static_config_hash` and
`static_config_hash_profile` properties. The profile is
`nexus-symbiote/mcp-static-config/v1`: a domain-separated RFC 8785 digest of the
original server configuration object, calculated before arguments, environment
values and endpoint details are redacted from the exported fields.

This binding detects a different package with the same version, changes to an
opaque launcher, ordered arguments, environment values, endpoint paths and
declared tool definitions. Credential rotation therefore also requires a new
inventory. JSON object-key ordering and whitespace do not change the binding.
The digest establishes source consistency; it does not authenticate a publisher,
identify the installed executable or establish that a tool backend is benign.
It is not encryption or password protection: someone who knows the surrounding
configuration can test guesses for a low-entropy secret against the digest.
Restrict access to these BOMs and their exports as sensitive integrity evidence.

Configured tool entries retain their configuration source path and static
collection mode. Validation compares their descriptor digest, fingerprint
version and server reference with a fresh collection. Recomputing the digest of
an edited supplied descriptor establishes only self-consistency and cannot make
it match a different local declaration. An asserted live-observation claim does
not substitute for the static configuration evidence.

## Upgrade existing snapshots

Older static MCP snapshots lack the source binding and configured tool locators.
They cannot establish this stronger reconciliation contract. Missing or unknown
binding profiles fail validation and require recollection; copying a newly
calculated digest into an old approved snapshot is not a migration.

```sh
nexus-symbiote scan /path/to/project --no-project-policy --report-only -o candidate.json
nexus-symbiote validate candidate.json --no-project-policy --project /path/to/project
nexus-symbiote diff reviewed.json candidate.json --json-output --fail-on-alert
```

`--report-only` allows collection of a candidate despite policy findings. It does
not approve that candidate. Review the diff and coverage, resolve failed or
unknown checks, and independently authenticate any replacement approval.

Static configuration and served descriptors are separate observation scopes.
Live candidates whose served descriptors differ from the declaration need their
own authenticated review; passing one scope does not establish the other.

The regression cases in `tests/test_mcp_source_binding.py` cover changed source,
edited supplied descriptors, missing legacy evidence, redaction and canonical
object-key ordering. These cases test the stated contract, not detection efficacy
across an independently sampled population of agent deployments.
