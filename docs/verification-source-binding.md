# Reconcile a BOM with its MCP and A2A configuration

`validate --project` checks a supplied inventory against freshly collected local
evidence. Static MCP server records carry two kinds of source binding.

`static_config_hash` (profile `nexus-symbiote/mcp-static-config/v3`) is an RFC 8785
digest of the server's exported structure: configuration field names, the displayed
command basename, the classified launcher with its wrappers and effective command,
the identity, version and pin of every package it launches, package source origins,
the names of the project resolver settings that apply to it, launch context flags and
counts, transport, endpoint origin, argument count, environment variable and header
names, client settings (auto-approval, disabled, tool filters) and declared tool names.
It covers only information the record exports in clear, so it reveals nothing about
secret values. It detects added or removed arguments, environment variables, headers,
fields, resolver settings and tools, and changed launchers, package identities and
versions (including dependencies added with `--with`), package source origins, launch
context and endpoint origins.

Package sources are the registry and index options of a launcher (`--registry`,
`--@scope:registry`, `--index-url`, `--find-links` and similar), environment
variables that redirect resolution (`npm_config_registry`, `UV_INDEX_URL`,
`PIP_INDEX_URL`, `UV_PYTHON_INSTALL_MIRROR`, `JSR_URL`, `DOCKER_HOST`, `GOPROXY` and
similar), container engine options (`docker -H`, `--context`, `--config`; `podman
--url`, `--root`), `pipx --pip-args` index and trust options (matched by unique
prefix, as pip's parser does; an unknown option is a gap) and project-root resolver
settings that apply to the launched package: `.npmrc` for npm, pnpm, bun and Deno
`npm:` specifiers, `bunfig.toml` for bun, `.yarnrc.yml` for `yarn dlx`, and `uv.toml`
and `pyproject.toml` `[tool.uv]` (indexes, mirrors, insecure hosts and `sources`
entries for a launched package) for `uv run`. `.npmrc` is read as npm reads it: keys
and values are trimmed, JSON-decoded when quoted and cut at an unescaped `;` or `#`
otherwise, lines end at a carriage return or line feed, keys after the first
`[section]` line are ignored, and a key containing `${...}` is `[unresolved]`. Its
registry, cache, offline, proxy, `strict-ssl=false`, CA, user and global
configuration, prefix and store settings are sources; auth settings (`//host/:...`,
`_auth`, `username` and similar) are ignored. They are exported as `package_sources`
entries such as `.npmrc:@acme:registry=https://npm.acme.example`: the origin only,
`[local]` for a path or other value and `[unresolved]` for a value with `${...}`
expansion. A server that runs in another working directory (a `cwd` other than the
root, `env -C`, `pwsh -WorkingDirectory`, `wsl --cd`, `uv --directory` or `--project`,
`deno --config`) may read other resolver files, so it carries
`working-directory=[unresolved]`. A redirected package keeps its version but loses
`launcher_package` and `package_url`, and carries a medium `package_source` risk. The names of the other `.npmrc` settings are exported as
`resolver_settings` and digested; their values enter only the keyed binding.

Values are bound only when the operator sets `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` to
a secret of at least 32 characters during collection and validation. Generate it
randomly, for example with `openssl rand -hex 32`: the exported key identifier lets
anyone holding the BOM test guesses of a weak key. Records then also carry
`static_value_binding`, an HMAC-SHA256 under that key over the original server object
and the raw values of every project resolver setting that applies to it, auth
settings excepted (profile
`nexus-symbiote/mcp-static-values/v2`), and a key identifier. This detects a different
package with the same version, changed arguments, environment and header values,
endpoint and index paths and the directory of a command. The key never enters the
BOM; without it, the binding cannot be used to test guesses for a secret. Keep the key
in the CI secret store, use the same key for a baseline and its candidates, and rotate
it by recollecting both. A keyed BOM validated without the key, or with a different
key, fails reconciliation. A key shorter than 32 characters is one scan failure per
configuration file that names the variable, and no server of that file is recorded.
Every record states `source_values_bound`; without the key, a record with arguments,
environment or header values, an endpoint path or a command directory also carries a
low `completeness` risk that names the key.

Profile v1 records (an unkeyed digest over raw configuration, including secret
values) let anyone holding the BOM confirm guesses for low-entropy secrets. They
fail reconciliation as unknown and require recollection; treat existing v1 exports
as sensitive and replace them. Profile v2 records (0.1.0) were digested before
launchers, package sources and launch context were classified; `validate --project`
reports them as unknown and asks for recollection, like v1. Neither binding
authenticates a publisher, identifies the installed executable or establishes that a
tool backend is benign. JSON object-key ordering and whitespace do not change either
binding.

Configured tool entries retain their configuration source path and static
collection mode. Validation compares their descriptor digest, fingerprint
version and server reference with a fresh collection. Recomputing the digest of
an edited supplied descriptor establishes only self-consistency and cannot make
it match a different local declaration. An asserted live-observation claim does
not substitute for the static configuration evidence.

## A2A agent cards and client entries

A2A records export URLs only as origins (scheme, host and port): the path, query,
fragment and user information of a card's `url`, of its A2A 1.0
`supportedInterfaces` and A2A 0.3 `additionalInterfaces` URLs, of security scheme
URLs such as `tokenUrl` and `openIdConnectUrl`, and of a client's `agentCardUrl`
never enter the BOM. A URL without a scheme keeps its host and port in the form
`//host:port`: the network-path reference `//auth.example.com/token` is exported as
`//auth.example.com`, and the A2A 1.0 gRPC address `grpc.example.com:443` as
`//grpc.example.com:443`. A URL whose origin cannot be exported is exported as
`[redacted]` and counts as unbound: one without a host or with an invalid port, a
bare `host:port` or `host/path` whose host is not a dotted name, `localhost` or a
bracketed IP, or one whose host, as Python's parser reads it, contains a character
other than letters, digits, `.`, `-`, `_` or `:`, such as `https://host\path`
(WHATWG parsers read a path after the backslash). A backslash before an `@` is not
caught: `https://evil.example\@good.example/` is exported as `https://good.example`
while WHATWG parsers connect to `evil.example`, and the change raises only the
medium structure-digest alert for user information.

The scanner reads A2A 0.3 cards and A2A 1.0 cards. For 1.0 it follows the
`lf.a2a.v1` messages in `specification/a2a.proto` of the A2A repository and, as
proto3 JSON parsers do, reads `supportedInterfaces`, `securitySchemes`,
`securityRequirements`, the skills' `securityRequirements` and the security scheme
members under their JSON or proto names, such as `supportedInterfaces` or
`supported_interfaces`. A card that gives both names for one of these is a scan
failure; other 1.0 fields are not read. `supportedInterfaces` lists the
interfaces with the preferred one first. When the card has no top-level `url`, the
first entry becomes the record's `endpoint_url`. The card's `url` and its first
supported interface must both use HTTPS, or the card carries a high
`transport_security` risk. A scheme-less URL, including a gRPC `host:port`
address, fails that check because it does not show TLS.

Several security declarations are recorded in clear:

- `capabilities.oauth_scopes` holds the scopes that the requirements of the card
  and of its skills name for `oauth2` and `openIdConnect` schemes. Requirements
  come from the 0.3 `security` lists of the card and of each skill, and from the 1.0
  `securityRequirements` lists of the card and of each skill, whose entries take the
  form `{"schemes": {"<scheme>": {"list": ["<scope>"]}}}`. Scopes are public
  identifiers (RFC 6749 section 3.3), so scope URIs such as
  `https://www.googleapis.com/auth/drive.readonly` or `api://<app>/access_as_user`
  are kept in full. A scope in `scheme://` URL form with user information, a query or a
  fragment is reduced to its origin, a recognised credential assignment such as
  `token=...` or `api_key=...` is reduced by the standard redaction, and one in a
  known token format (a JWT or a `ghp_`, `AKIA`, `sk-`, `xox`, `glpat-` or `AIza`
  prefix) is exported as `***`; a scheme-less scope that contains `?`, `#` or
  `@`, such as `a?b=1`, is exported in full. A change to the set of scopes raises a high
  `capabilities changed` alert. A scope moved between the card and a skill, or
  between skills, changes only the structure digest below and raises a medium
  `properties changed` alert.
- `properties.security_scheme_types` lists the declared scheme types, mapped onto
  `apiKey`, `http`, `oauth2`, `openIdConnect`, `mutualTLS` or `other`. A 0.3
  `type` is matched without regard to case, so `OAuth2` counts as `oauth2`. A 1.0
  scheme names its type by its single member: `apiKeySecurityScheme`,
  `httpAuthSecurityScheme`, `oauth2SecurityScheme`, `openIdConnectSecurityScheme`
  or `mtlsSecurityScheme`. A scheme with two members, or whose `type` contradicts
  its member, is a scan failure.
- `properties.security_scheme_origins`, `properties.additional_interface_origins`
  and `properties.supported_interface_origins` list the origins of the URL fields in
  `securitySchemes` (any field whose name ends in `url` or `uri`, outside scope
  maps), of `additionalInterfaces`, and of `supportedInterfaces` in their declared
  order. Without a key, moving a token endpoint or interface to a host the card did not
  already use for such a URL, or putting first a supported interface with a
  different origin or path depth, raises a medium `properties changed` alert;
  reordering supported interfaces that share an origin and path depth is detected
  only with the key. Moving the endpoint, including the first supported interface
  of a card without `url`, raises a high `endpoint_url changed` alert.

Requirement values of schemes that are not declared as `oauth2` or
`openIdConnect` (`apiKey`, `http`, `mutualTLS`, `other`, or a scheme the card does
not declare) may be role names or anything else, even a pasted credential, so they
are not exported. The structure digest below covers them instead, so a change such
as `read:only` to `admin` raises a medium `properties changed` alert without a key,
in a skill's requirements as in the card's.

`authentication_required` is true only when the card declares at least one of
`security`, `securityRequirements` or a legacy `authentication` object, and each
one it declares passes: every alternative in `security` and `securityRequirements`
is non-empty and names only declared schemes that state a type, and a legacy
`authentication` object lists at least one non-empty scheme name. An empty alternative (`{}` or `{"schemes": {}}`) permits
anonymous access, and an empty list declares no requirement. The specifications do
not say how a skill's requirements combine with the card's, so skill requirements
can make `authentication_required` false but never true. A skill alternative that
is empty or names an undeclared or untyped scheme makes it false, with a medium
`authentication` finding that a skill has no non-empty requirement. Requirements
declared only on skills leave a card without requirements of its own at false. An
empty skill list adds no requirement, because proto3 JSON does not distinguish it
from an absent field. A `null` `securitySchemes`, `security`,
`securityRequirements`, `authentication` or `authentication.schemes` counts as
absent, and so does a skill's `null` `security` or `securityRequirements`. These are
declarations: they do not show that an endpoint enforces authentication.

Every A2A server record, and every client record read from an A2A configuration
file, carries `static_card_hash` (profile `nexus-symbiote/a2a-card-structure/v2`)
or `static_config_hash` (profile `nexus-symbiote/a2a-client-structure/v1`); the
`a2a-client:code-detected` record created from an SDK import carries neither digest
nor `source_values_bound`. These RFC 8785 digests cover the top-level field names
of the card or client entry, security scheme names with their mapped types, each
requirement alternative of the card and of each skill (keyed by the skill's exported
name) with its exported scopes and the values of other scheme types, the number of
non-empty legacy scheme names, and the shape of each URL: the number of path
separators, whether a query, fragment or user information is present, and the path
itself only when it is a public root path (`/` or, for clients,
`/.well-known/agent.json` or `/.well-known/agent-card.json`). They hold no other
path, query or tenant value, so a same-origin path change that keeps the number of
path separators, and does not move to or from a root path, leaves them unchanged. They are unkeyed, so anyone holding the BOM can test guesses against
them. They reveal field and scheme names, path depth and whether user information or
a query is present, and they let a BOM holder confirm a guess of the requirement
values of schemes other than `oauth2` and `openIdConnect`.

With `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` set, records also carry
`static_value_binding`, an HMAC-SHA256 under that key over the whole card (profile
`nexus-symbiote/a2a-card-values/v1`) or client entry (profile
`nexus-symbiote/a2a-client-values/v1`), and the key identifier that MCP records use
for the same key. A changed path, query, token URL, interface tenant or any other
value then changes a compared property, and `diff --fail-on-alert` reports a medium
`properties changed` alert. Each record states `source_values_bound`, so a keyed
baseline validated without its key, or with a different key, fails reconciliation.
The binding needs RFC 8785 JSON values: under the key, a client entry with a value
such as an unquoted YAML date is a scan failure that names the key.

Without the key, a changed path, query, tenant or other unexported value is
detected only when it changes an exported origin, a URL's shape, a top-level field
name or the record's completeness risk; a same-depth path change on the same host,
or a changed tenant value, passes `diff --fail-on-alert`. A card carries a low `completeness`
risk naming the key and listing what is unbound when its endpoint, a supported or
additional interface URL, or a security scheme URL goes beyond its exported origin
or has none, when a supported interface sets a `tenant`, or when a scope of the card
or of a skill was redacted. A client carries it when its `agentCardUrl` goes beyond
its exported origin and is not one of the root paths above. Other values are bound
only by the key, and the risk does not list them: descriptions; the id of a skill
that has a name, and skill descriptions, tags, examples and input or output modes;
security scheme fields other than their types and URLs, such as an API key's `name`
and location, an HTTP scheme's `scheme` and `bearerFormat`, an authorization code
flow's `pkceRequired` and the scope descriptions of a flow; interface transports;
`protocolBinding`; and `protocolVersion`. `tests/test_a2a_binding.py` holds the test
vectors for the four profiles, with a second card vector in the A2A 1.0 form. Both
card vectors include a skill with its own requirements.

## Upgrade existing snapshots

Older static MCP snapshots lack the source binding and configured tool locators,
and older A2A snapshots lack the structure digests or carry the superseded
`nexus-symbiote/a2a-card-structure/v1` profile. They cannot establish this
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
edited supplied descriptors, missing legacy evidence, redaction, canonical
object-key ordering and project resolver settings, and hold the known-answer vectors
for the v3 structure digest and the v2 keyed binding. These cases test the stated contract, not detection efficacy
across an independently sampled population of agent deployments.
