# Reconcile a BOM with its MCP and A2A configuration

`validate --project` checks a supplied inventory against freshly collected local
evidence. Static MCP server records carry two kinds of source binding.

`static_config_hash` (profile `nexus-symbiote/mcp-static-config/v2`) is an RFC 8785
digest of the server's structure: configuration field names, the displayed
launcher, transport, endpoint origin, argument count, environment variable names
and declared tool names. It covers only information the inventory already exports
in clear, so it reveals nothing about secret values. It detects added or removed
arguments, environment variables, fields and tools, and changed endpoint origins.

Values are bound only when the operator sets `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` to
a secret of at least 32 characters during collection and validation. Records then
also carry `static_value_binding`, an HMAC-SHA256 under that key over the original
server object (profile `nexus-symbiote/mcp-static-values/v1`), and a key
identifier. This detects a different package with the same version, changed
arguments, environment values, endpoint paths and opaque launchers. The key never
enters the BOM; without it, the binding cannot be used to test guesses for a
secret. Keep the key in the CI secret store, use the same key for a baseline and
its candidates, and rotate it by recollecting both. A keyed BOM validated without
the key, or with a different key, fails reconciliation.

Profile v1 records (an unkeyed digest over raw configuration, including secret
values) let anyone holding the BOM confirm guesses for low-entropy secrets. They
fail reconciliation as unknown and require recollection; treat existing v1 exports
as sensitive and replace them. Neither binding authenticates a publisher,
identifies the installed executable or establishes that a tool backend is benign.
JSON object-key ordering and whitespace do not change either binding.

Configured tool entries retain their configuration source path and static
collection mode. Validation compares their descriptor digest, fingerprint
version and server reference with a fresh collection. Recomputing the digest of
an edited supplied descriptor establishes only self-consistency and cannot make
it match a different local declaration. An asserted live-observation claim does
not substitute for the static configuration evidence.

## A2A agent cards and client entries

A2A records export only URL origins: the path, query and user information of a
card's `url` and of a client's `agentCardUrl` never enter the BOM, and neither do
the parameters of declared security schemes, such as `tokenUrl`.

Every A2A server record carries `static_card_hash` (profile
`nexus-symbiote/a2a-card-structure/v1`) and every client record carries
`static_config_hash` (profile `nexus-symbiote/a2a-client-structure/v1`). These
RFC 8785 digests cover field names, the URL shape (the number of path separators
and whether a query, fragment or user information is present), declared security
scheme names with their mapped types, and the scopes named by each security
requirement. They cover no path or query value, so they cannot confirm a guessed
path, and a path change on the same origin leaves them unchanged.

With `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` set, records also carry
`static_value_binding`, an HMAC-SHA256 under that key over the whole card (profile
`nexus-symbiote/a2a-card-values/v1`) or client entry (profile
`nexus-symbiote/a2a-client-values/v1`), and the key identifier that MCP records use
for the same key. A changed path, query, token URL or any other card value then
changes a compared property, and `diff --fail-on-alert` reports a medium
`properties changed` alert. Each record states `source_values_bound`, so a keyed
baseline validated without its key, or with a different key, fails reconciliation.

Without the key, a same-origin path change is not detected. Records whose URL goes
beyond its origin carry a low `completeness` risk that says so; for clients, the
root paths `/.well-known/agent.json` and `/.well-known/agent-card.json` do not count.

Two security declarations are recorded in clear. The scopes named by the card's
`security` requirements are in `capabilities.oauth_scopes`, where a change raises a
high `capabilities changed` alert. Declared scheme types, mapped onto `apiKey`,
`http`, `oauth2`, `openIdConnect`, `mutualTLS` or `other`, are in
`properties.security_scheme_types`. `authentication_required` is true only when
every `security` alternative names declared schemes and none is empty (an empty
alternative permits anonymous access), and a legacy `authentication` object lists
at least one scheme. These are declarations: they do not show that an endpoint
enforces authentication. `tests/test_a2a_binding.py` holds the test vectors for
the four profiles.

## Upgrade existing snapshots

Older static MCP snapshots lack the source binding and configured tool locators,
and older A2A snapshots lack the structure digests. They cannot establish this
stronger reconciliation contract. Missing or unknown binding profiles fail
validation and require recollection; copying a newly calculated digest into an
old approved snapshot is not a migration.

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
