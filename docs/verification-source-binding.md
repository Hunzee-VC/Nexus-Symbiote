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

A2A records export URLs only as origins (scheme, host and port): the path, query
and user information of a card's `url`, of its `additionalInterfaces` URLs, of
security scheme URLs such as `tokenUrl` and `openIdConnectUrl`, and of a client's
`agentCardUrl` never enter the BOM. A URL whose host may be split differently by
other parsers, such as `https://host\path` (WHATWG parsers read a path after the
backslash), is exported as `[redacted]` and counts as unbound.

Several security declarations are recorded in clear:

- `capabilities.oauth_scopes` holds the scopes that the card's `security`
  requirements name for `oauth2` and `openIdConnect` schemes. Scopes are public
  identifiers (RFC 6749 section 3.3), so scope URIs such as
  `https://www.googleapis.com/auth/drive.readonly` or `api://<app>/access_as_user`
  are kept in full. A scope with user information, a query, a fragment or a
  credential assignment is reduced by the standard redaction, and one in a known
  token format (a JWT or a `ghp_`, `AKIA`, `sk-`, `xox`, `glpat-` or `AIza`
  prefix) is exported as `***`. A scope change raises a high
  `capabilities changed` alert.
- `properties.security_scheme_types` lists the declared scheme types, mapped onto
  `apiKey`, `http`, `oauth2`, `openIdConnect`, `mutualTLS` or `other`.
- `properties.security_scheme_origins` and
  `properties.additional_interface_origins` list the origins of the URL fields in
  `securitySchemes` (any field whose name ends in `url` or `uri`, outside scope
  maps) and of `additionalInterfaces`. Moving a token endpoint or an alternative
  interface to another host raises a medium `properties changed` alert without a
  key.

Requirement arrays for other scheme types hold role names, which may be anything,
so they are not exported. `authentication_required` is true only when every
`security` alternative is non-empty and names only declared schemes that state a
type (an empty alternative permits anonymous access), and a legacy
`authentication` object lists at least one non-empty scheme name. A `null`
`securitySchemes`, `security`, `authentication` or `authentication.schemes` counts
as absent. These are declarations: they do not show that an endpoint enforces
authentication.

Every A2A server record carries `static_card_hash` (profile
`nexus-symbiote/a2a-card-structure/v1`) and every client record carries
`static_config_hash` (profile `nexus-symbiote/a2a-client-structure/v1`). These
RFC 8785 digests cover field names, security scheme names with their mapped types,
the exported scopes of each requirement (or, for other scheme types, the number of
role names), the number of non-empty legacy scheme names, and the shape of each URL:
the number
of path separators, whether a query, fragment or user information is present, and
the path itself only when it is a public root path (`/` or, for clients,
`/.well-known/agent.json` or `/.well-known/agent-card.json`). They hold no other
path, query or role value, so a path change on the same origin leaves them
unchanged. They are unkeyed, so anyone holding the BOM can test guesses against
them: they reveal field and scheme names, path depth and whether user information
or a query is present, but not the values.

With `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` set, records also carry
`static_value_binding`, an HMAC-SHA256 under that key over the whole card (profile
`nexus-symbiote/a2a-card-values/v1`) or client entry (profile
`nexus-symbiote/a2a-client-values/v1`), and the key identifier that MCP records use
for the same key. A changed path, query, token URL, role name or any other value
then changes a compared property, and `diff --fail-on-alert` reports a medium
`properties changed` alert. Each record states `source_values_bound`, so a keyed
baseline validated without its key, or with a different key, fails reconciliation.
The binding needs RFC 8785 JSON values: under the key, a client entry with a value
such as an unquoted YAML date is a scan failure that names the key.

Without the key, those changes are not detected. A card carries a low
`completeness` risk naming the key and listing what is unbound when its endpoint,
a security scheme URL or an additional interface URL goes beyond its origin, a
scope was redacted, or a requirement lists role names. A client carries it when its
`agentCardUrl` goes beyond its origin and is not one of the root paths above.
`tests/test_a2a_binding.py` holds the test vectors for the four profiles.

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
