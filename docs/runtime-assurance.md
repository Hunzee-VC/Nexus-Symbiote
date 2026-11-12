# Runtime assurance integration

The `nexus_symbiote` package is the compatibility baseline. Runtime contracts add an
explicit approval boundary to its inventory model. The experimental parallel
foundation package is not a dependency of this implementation.

The [runtime contract reference](runtime-contract-reference.md) specifies every
contract field, the envelope, the digests, the order of checks, the reason codes,
the state store, the key lifecycle and what an integrator must build. This page
describes the security boundary and how to operate the gateway.

## Security boundary

`ReferenceGateway` mediates calls made through its `invoke` method. The operator
must provide authenticated workload and endpoint adapters, a trusted scope
resolver, an executor, purpose-specific public keys and protected state storage.
It does not intercept other network requests, sandbox a process, or establish
that an unchanged tool backend is benign. Restrict bypass paths through the
surrounding runtime, credentials, sandbox and network policy.

Every denial raises `AuthorizationError` with a stable `reason` code. Exceptions
raised by the operator's adapters propagate unchanged, so treat every exception
from `invoke` as a denial.

The gateway copies the request before scope resolution and rejects a resolver
that modifies its copy during resolution. A resolver retaining that copy cannot
change the request subsequently submitted to the executor. The resolver remains
trusted to derive the correct scope, and the executor remains trusted to send
the authorized call over the same authenticated session used for observation.

Four signed contracts have distinct predicate types and schemas:

| Contract | Purpose | Maximum validity |
| --- | --- | --- |
| Approved snapshot | Bind an exact companion BOM, deployment, workload, tenant, policy and tool grants | 24 hours |
| Trust status | Publish tenant-scoped tool, endpoint, signer and snapshot revocations | 1 hour |
| Action approval | Bind one or more approvers to one snapshot, execution context, exact request and single-use nonce | 5 minutes |
| Hosted model attestation | Bind a trusted provider statement to endpoint, requested alias and resolved revision | 24 hours |

Approval nonces are single-use within a tenant and state store; draw each one from a cryptographically secure generator with at least 128 bits of entropy (for example `secrets.token_hex(16)`), never from a counter.

Signatures authenticate the claims of authorized issuers. They do not prove
human presence, model safety, complete discovery, or the truth of a provider's
statement. The operator owns the purpose rings, the signer scopes and the
approver-key-to-person map.

The snapshots, trust statuses and companion BOM passed to `invoke` must come from
an operator-controlled channel, not from the agent being mediated. Whoever
presents the evidence chooses among the contracts that are still valid, so retire
superseded snapshots explicitly (see [State and supersession](#state-and-supersession))
and never pre-sign trust statuses for later windows.

## Signing and verification

Create one Ed25519 key pair per purpose, outside scanned repositories. A key in
more than one purpose ring is refused unless the gateway is constructed with
`allow_shared_keys=True`. Each passphrase file holds its passphrase, at most 1,023
bytes, on the first line and must be readable only by its owner (mode 0600, for
example written under `umask 077`):

```sh
nexus-symbiote runtime keygen --private-key snapshot.pem --public-key snapshot.pub --passphrase-file snapshot.pass
nexus-symbiote runtime keygen --private-key approval.pem --public-key approval.pub --passphrase-file approval.pass
nexus-symbiote runtime keygen --private-key trust.pem --public-key trust.pub --passphrase-file trust.pass
nexus-symbiote runtime digest agentbom.json --kind bom
nexus-symbiote runtime digest send-tool.json --kind tool
nexus-symbiote runtime sign approved-snapshot.json --kind snapshot --key snapshot.pem --passphrase-file snapshot.pass --out snapshot.dsse.json
nexus-symbiote runtime verify snapshot.dsse.json --kind snapshot --public-key snapshot.pub --bom agentbom.json
```

`runtime digest` prints the digests a snapshot binds: `--kind bom` for
`bom_digest` and `--kind tool` for a served descriptor's `definition_digest`. It
also prints the contract, context and request digests that approvals and
revocation lists use, and `runtime key-id` prints a key ID. The
[contract reference](runtime-contract-reference.md#contracts) shows the fields of
`approved-snapshot.json` and the other contracts.

The sign command accepts an explicit contract rather than granting authority
to a scan result automatically. It refuses a contract that could never verify,
because its validity window is longer than its purpose allows or has already
ended, refuses a private key file that its group or others can read, and prints
the contract digest. `--passphrase-file` encrypts a new private key or unlocks an
encrypted one; a passphrase file that its group or others can read is refused, and
`runtime keygen` keeps neither key if either cannot be written. Keys held in a
KMS, an HSM or an agent sign through `sign_contract` with any object that has
`sign(data)` and `public_key()`.

Outputs use DSSE pre-authentication encoding and in-toto statements. Complete
companion content is digest-bound; selective disclosure is not supported by this
profile. Existing files are not overwritten. Verification requires the expected
purpose, an authorized key set, distinct signers, subject consistency, schema
validity and the current validity window. Envelopes may use the standard or the
URL-safe base64 alphabet in canonical form, and a signature without a matching
`keyid` is tried against each trusted key.
Predicates must be in canonical contract form, the form `runtime sign` emits
(`model_dump(mode="json")`): an envelope from another DSSE signer whose predicate
encodes the same contract differently is rejected, so one contract has exactly
one digest. `revoked_snapshots` entries and `ActionApproval.snapshot_digest` use
that digest, which `runtime sign`, `runtime verify` and `runtime digest` print as
`digest`.
`sign_contract` re-validates a contract before signing it and refuses one that does
not validate or is not already in canonical form, such as a copy made with
`model_copy(update=...)` that holds a non-UTC timestamp. The signer's digest of the
contract it holds is therefore the digest the envelope binds.
`revoked_snapshots` and `revoked_tools` entries must be `sha256:` followed by 64
lowercase hexadecimal digits, `revoked_signers` entries must be a 64-digit
lowercase key ID, and `revoked_endpoints` entries, like a grant's
`endpoint_identity`, must be a pinned launcher identity or a canonical URL as the
[reference](runtime-contract-reference.md#endpoint-identities) defines it.
Revocation entries are compared verbatim, so any other form is rejected when the
trust status is signed or verified instead of being ignored.
The CLI reports contract verification separately from invocation authorization,
and every failure ends with its reason code.

`ReferenceGateway` accepts independent `snapshot_threshold`, `approval_threshold`
and `trust_threshold` keyword arguments. Each defaults to `1`; set a larger value
when the operator policy requires multiple distinct authorized signers for that
purpose. Values must be integers from 1 through 32 and cannot exceed the number
of distinct, correctly identified public keys in that purpose's key ring.
Booleans and duplicate aliases do not establish a quorum. An empty key ring is
allowed only with the default threshold and disables verification for that
purpose; it never approves an unsigned contract. The pinned stdio adapter carries
the gateway's whole configuration into the same-process invocation.

An approval quorum counts people, not keys. `approval_actors` maps each approval
key to the person who holds it; an approval needs signers from at least
`approval_threshold` different people, and its `actor` must be one of them. Two
keys of one person are one approval, so `approval_threshold=2` with each
person's keys mapped to their own name is a two-person rule.

`signer_scopes` limits individual keys to tenants, deployments, agents, tools
and a validity period with a `SignerScope`. Signers outside their scope do not
count towards a quorum. Without scopes, any key in a ring can sign for any
tenant, so a gateway that serves several tenants must scope its keys or run one
configuration per tenant.

Runtime CLI contract and key inputs must be bounded regular files. Symlinks and
FIFOs are rejected rather than followed or waited on.

## Gateway adapters

Construct `ReferenceGateway` with these callbacks:

- `authenticate()` returns the current `ExecutionContext` from the runtime's
  authenticated session. Do not construct it from caller-controlled request fields.
- `describe(server_id, tool_name)` returns the actual served definition and
  authenticated endpoint identity. Bind discovery and execution to the same
  authenticated session/version where the upstream protocol supports it.
- `resolve_scope(call)` derives the effective action and resource from the exact
  operation arguments. Reject ambiguous operations; do not trust the request's
  action/resource labels. For example, derive a mailbox resource from the mailbox
  argument that the executor actually uses.
- `execute(call)` performs only that admitted operation against the checked
  endpoint. It must not add unapproved destinations or use broader credentials.
- `on_decision(decision)`, optional, receives a record of every admitted or
  denied call: reason code, context, serials, digests and signer key IDs, never
  argument values. Send it to an audit log.

The gateway checks exact grants, endpoint identity, descriptor digest, offline
input-schema validity, request-bound approval and revocation before execution.
The descriptor digest covers `name`, `description`, `inputSchema`,
`annotations`, `title`, `outputSchema` and `_meta`; a descriptor with any other
field, such as `icons`, fails closed until the digest profile is upgraded.
Arguments are copied before checking; schema references cannot trigger network
retrieval. Identities and validity are checked again immediately before execution.
The executor receives the arguments as the caller sent them; the approval binds
their RFC 8785 form, in which `1` and `1.0` are equal and key order does not
count. The caller therefore chooses the key order and number spelling that the
executor sees, which the approver of the canonical form never saw. When a backend
depends on either, for example a command named by its first key or a strictly
typed integer, construct the gateway with `canonical_arguments=True`: the executor
then receives exactly the form the approval binds, with keys in RFC 8785 order and
integral numbers below 10^21 as integers. Alternatively, reject non-canonical
arguments in `resolve_scope`. Integers must lie between -(2^53 - 1) and
2^53 - 1; pass larger values, such as 64-bit IDs, as strings.

Schema validity does not bound validation cost. Approved tool schemas and hostile
arguments are checked in disposable isolated Python workers with a 256 MiB
address-space limit. macOS refuses that limit, so workers there run without it;
on every other platform a worker that cannot set it fails closed. Interpreter
start-up and imports have their own budget of
ten seconds of wall time and ten CPU seconds; the evaluation then gets a
two-second wall deadline and at least one CPU second, so a slow or throttled
host does not spend the evaluation budget on start-up. Call
`check_validation_worker()` at start-up or from a readiness probe to find a host
where the worker cannot run. Validation requires POSIX resource limits and fails
closed if a worker cannot start, crashes, times out or returns an invalid result.
At most four validations run concurrently in one gateway process; additional
requests fail closed with `validation-capacity`, and a timeout with
`validation-timeout`, both of which can be retried. JSON input is bounded to 32
levels and 20,000 nodes per value, 256 KiB per served descriptor/schema and 1 MiB
per argument object. Deployments must also rate-limit requests and bound the
trusted authentication, description, scope and execution adapters. Workers load
the reviewed package installed in the gateway's Python environment using isolated
mode; a source tree available only through `PYTHONPATH` is insufficient and fails
closed.

Schemas are evaluated in the dialect their `$schema` declares: draft-04, draft-06,
draft-07, 2019-09 or 2020-12. A schema without `$schema` is evaluated as 2020-12.
Any other dialect is refused. A constraint that evaluation would skip makes the
schema invalid rather than approved but unenforced: a keyword that the declared
dialect's specification does not define, such as draft-07 `dependencies` in a
schema without `$schema`, `const` in a draft-04 schema or `maxContains` in a
draft-07 schema; a keyword that only drafts before draft-04 define (`divisibleBy`,
`disallow`, `extends`, `requires`, `maxDecimal`, `minimumCanEqual`,
`maximumCanEqual`), and an `optional` whose value is not `true`, in any dialect; a
2019-09 `unevaluatedItems` that applies where a `contains` does, because
jsonschema would treat the items `contains` matched as evaluated; an assertion
next to `$ref` in draft-04 to draft-07, which ignore the siblings of `$ref`; a
subschema with its own `$schema` or base URI (`$id`, or
`id` in draft-04); and a reference that is not a JSON Pointer within the schema,
such as `https://tools.example.test/run#/x` or an anchor. `format` is an
annotation and is never asserted. `pattern` and `patternProperties` have ECMA-262
meaning, read with the `u` flag that JSON Schema recommends: `$` does not match
before a final newline, `\d` and `\w` are ASCII, `\s` and `.` use ECMA-262's
whitespace and line terminators, and `[\s\S]` matches any character. Pattern
syntax that ECMA-262 rejects or reads differently and that has no translation
makes the schema invalid: inline flags, possessive quantifiers such as `a*+`,
`{,n}`, quantified assertions, `\d`, `\w` or `\s` as a range bound, such as
`[%-\w]`, and a backreference to a group that may not take part, such as
`^(['"])?rm\1\s`, which ECMA-262 reads as empty and Python as a failed match. A
backreference to a group that always takes part first, as in `^(['"]).*\1$`,
keeps its meaning. A pattern that is valid only without the `u` flag, such as
`^\-?\d+$`, is accepted and read with code-point semantics, so `.` and negated
classes match one character outside the Basic Multilingual Plane where Annex B
would count two UTF-16 code units; it is refused if it names such characters.
Every worker first checks that patterns have this meaning in each dialect; if a
jsonschema upgrade changed that, the worker does not start and calls fail with
`validation-unavailable`.

Revocation and required operation approvals are checked before schema evaluation.
The worker cannot retrieve schema references from the network. Validation failure
does not consume an approval nonce.

### Pinned stdio integration

`nexus_symbiote.live.session.invoke_pinned_stdio` is an opt-in POSIX adapter that
starts a private copy of an independently pinned standalone launcher, enumerates
its tools, authorizes the requested operation, and sends `tools/call` through the
same still-running process and streams. The approved `ToolGrant.endpoint_identity`
must be `stdio+launcher:sha256:<64 lowercase hex characters>` for that launcher.
The pin and launcher path come from operator-controlled configuration, not the
scanned project. The adapter refuses arguments, project environment and working
directory, reconnects, repeated calls, invalid JSON-RPC and list pagination beyond
its limits. Log and progress notifications that arrive before a reply are skipped
within the same frame and byte limits. The session accepts MCP protocol revisions
2024-11-05, 2025-03-26, 2025-06-18 and 2025-11-25. The handshake and tool listing
share one 20-second deadline starting after launcher staging and process startup;
`tools/call` gets its own `call_deadline_seconds` (default 20, at most 3,600),
counted from when the call is sent. This does not bound staging, authentication,
scope resolution, state storage or other synchronous gateway work. Operators
must impose an external end-to-end deadline on the invocation and its adapters.

Use `invoke_pinned_stdio(gateway, call, command=..., sha256=..., snapshot=...,
trust=..., bom=..., approval=..., call_deadline_seconds=...)`. It replaces only
the gateway's `describe` and `execute` callbacks, through `bind_adapters`, and
uses the same process for both steps; the gateway's keys, quorums, signer scopes,
state and `on_decision` callback still apply. It raises `AuthorizationError` only
before `tools/call` is sent. After that, a JSON-RPC error reply raises
`ToolCallError`, which carries the error `code`, and any other failure raises
`ExecutionOutcomeUnknown`. Neither means that the gateway refused the call: it was
admitted and its approval spent, and an unknown outcome means the tool may have
run, so record it as unknown rather than as not executed. Authenticate the
workload and derive scope using trusted gateway callbacks. Keep all other network
and process paths from bypassing this gateway.

Same-process binding does not establish that a server's implementation or
remote backend is immutable, safe or honest; a server can change behavior between
listing and invocation, including during a tool call. The pin covers launcher
bytes only, not interpreters, shared libraries or dependencies. A launcher is
executed before the authorization check, so only operator-approved launchers may
be used. Run it in an externally provisioned sandbox with restricted identity,
filesystem and egress. The adapter does not create that sandbox or mediate other
calls. `PinnedStdioSession` is a transport primitive and must not be invoked
directly as an authorization decision.

## State and supersession

Create the SQLite `StateStore` once with `StateStore.initialize(path)` and open it
with `StateStore(path)`. Opening a missing or uninitialized file is refused, and a
store removed while a gateway runs makes every call fail, so lost state is never
mistaken for first use. The store records snapshot and trust-status high-water
marks and consumes approval nonces. One-use approvals and rollback protection
hold per state file: every gateway that serves the same tenants must share one
store.

A snapshot that passes its signature, validity, context, revocation and
signer-scope checks becomes the current snapshot for its tenant, deployment and
agent as soon as it is seen, even if that call is denied later; a lower serial is
then denied with `snapshot-superseded`. To retire a superseded snapshot before
the agent presents its replacement, register the replacement when you issue it,
on the host of each store:

```sh
nexus-symbiote runtime register snapshot.dsse.json --trust trust.dsse.json --state state.sqlite --snapshot-key snapshot.pub --trust-key trust.pub
```

Registration checks the snapshot and the current trust status as `invoke` does,
except the workload context and the companion BOM, so pass the rings, quorums and
`--signer-scopes` that the gateways use. In Python, call
`gateway.register_snapshot(new_snapshot, trust=current_status)`, or build a
registration-only gateway without adapters with `ReferenceGateway.registrar(...)`.
To retire a snapshot on stores you cannot reach, list its digest in
`revoked_snapshots` of the next trust status. A superseded snapshot or an older
trust status is refused from a read of the store, without taking its write lock.

Fresh authenticated revocation knowledge is retained even when the current
operation is denied. Failed signature or binding checks cannot advance snapshot
state. After the final identity check, the gateway takes the database write lock,
confirms the current trust head and snapshot head, and checks validity against
its clock before committing the nonce. The commit admits the call. A newer trust
status or snapshot committed before admission denies the stale call and preserves
its nonce. A later revocation applies to subsequent admissions. Cancellation of
work already admitted requires executor support. Execution failure after
admission consumes the approval. Use a fast, local clock for the validity check.

Each tenant's accepted trust status records its revoked signer IDs in the same
transaction as the serial and digest. The gateway checks the signers on the next
status against both the prior revocations and the proposed list. To reinstate a
key, a still-authorized trust issuer must sign a higher serial that removes the
key from the list. Remove a compromised key from the configured trust ring on
every gateway. Keep a separately protected recovery issuer available.

Before upgrading an existing gateway fleet, stop writers to the shared database,
back it up, and retain each tenant's last accepted trust predicate. Older databases
contain only the serial and digest. The upgraded gateway can recover the revoked
signer IDs by replaying the exact, still-valid signed status. For an expired
status, load the archived predicate with
`StateStore(path).restore_trust_status(TrustStatus.model_validate(predicate))`.
This matches the tenant, serial and canonical digest already on disk and restores
only its signer list. A currently valid signed status is required to authorize a
call. If the archive is missing, restore it from a trusted backup before advancing
that tenant. Preserve the original database and its consumed nonces throughout
the migration. Existing databases need no initialization; opening one adds the
new columns and a store ID.

Protect the database against modification, deletion and rollback, and place it
outside scanned repositories. Database backup/restore must preserve monotonic
state. The adapter must refresh signed trust status; a cached list cannot prove
that no newer revocation exists. The enforced validity window bounds staleness.

## Hosted identity and mutable data

`HostedModelIdentity` records alias-only, provider-reported and provider-attested
identity separately. Deserializing an attestation claim cannot establish verified
identity. `verify_attestation` authenticates the signed provider contract and
checks its complete subject, observation time and expiry. Changing a copied
identity invalidates the cached verification. Behavioral canaries are drift
signals and never establish immutable model identity.

`LineageIndex` records tenant-local source, chunk, index, cache and memory versions.
It is a library helper; no command uses it. Retrieval requires current ACL evidence
across the ancestry and records returned version identifiers, content digests,
principal, time and read watermark. Source withdrawal cascades to derived records;
source ACL revocation blocks subsequent retrieval of derived records. `update_acl`
refuses a revision already used for that version, so an earlier, wider ACL cannot
be restored under its old revision to replay retrievals approved against it.
Connect these helpers to the actual datastore's transaction/snapshot and ACL
enforcement APIs. They do not by themselves delete remote content or authorize
access to a live vector database.

## Verification evidence

`tests/test_runtime_authorization.py` drives every denial path of
`ReferenceGateway.invoke`, including snapshot, endpoint, tool and approver
revocation, the capability allow-list, each approval binding, expired and
over-long validity windows, replayed approvals and rollback, and asserts each
one's reason code. `tests/test_runtime_supersession.py`,
`tests/test_runtime_policy.py` and `tests/test_runtime_state.py` cover snapshot
supersession and registration, approval quorums, signer scopes, decision
records and the state store, and `tests/test_runtime_schema_semantics.py` covers
schema dialects and ECMA-262 pattern meaning. `tests/test_runtime_vectors.py`
checks known-answer vectors for signed contracts and every digest an approval
binds, and `tests/test_runtime_reference.py` runs the reference's worked example.
`tests/test_lineage.py` covers source withdrawal, cross-tenant rejection, ACL
revocation and hosted identity verification boundaries. These fixtures establish
local contract behavior, not a production penetration test or a comparative
security benchmark.
