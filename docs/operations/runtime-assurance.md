# Runtime assurance integration

The `nexus_symbiote` package is the compatibility baseline. Runtime contracts add an
explicit approval boundary to its inventory model. The experimental parallel
foundation package is not a dependency of this implementation.

## Security boundary

`ReferenceGateway` mediates calls made through its `invoke` method. The operator
must provide authenticated workload and endpoint adapters, a trusted scope
resolver, an executor, purpose-specific public keys and protected state storage.
It does not intercept other network requests, sandbox a process, or establish
that an unchanged tool backend is benign. Restrict bypass paths through the
surrounding runtime, credentials, sandbox and network policy.

Four signed contracts have distinct predicate types and schemas:

| Contract | Purpose | Maximum validity |
| --- | --- | --- |
| Approved snapshot | Bind an exact companion BOM, deployment, workload, tenant, policy and tool grants | 24 hours |
| Trust status | Publish tenant-scoped tool, endpoint, signer and snapshot revocations | 1 hour |
| Action approval | Bind an authorized approver key to one snapshot, execution context, exact request and single-use nonce | 5 minutes |
| Hosted model attestation | Bind a trusted provider statement to endpoint, requested alias and resolved revision | 24 hours |

Signatures authenticate the claims of authorized issuers. They do not prove
human presence, model safety, complete discovery, or the truth of a provider's
statement. The operator owns the signer-to-role and approver-key-to-actor maps.

## Signing and verification

Create operator-owned Ed25519 keys outside scanned repositories:

```sh
nexus-symbiote runtime keygen --private-key approval.pem --public-key approval.pub
nexus-symbiote runtime sign approved-snapshot.json --kind snapshot --key approval.pem --out snapshot.dsse.json
nexus-symbiote runtime verify snapshot.dsse.json --kind snapshot --public-key approval.pub --bom agentbom.json
```

The sign command accepts an explicit contract rather than granting authority
to a scan result automatically. Outputs use DSSE pre-authentication encoding and
in-toto statements. Complete companion content is digest-bound; selective
disclosure is not supported by this profile. Existing files are not overwritten.
Verification requires the expected purpose, an authorized key set, distinct
signers, subject consistency, schema validity and current validity window.
The CLI reports contract verification separately from invocation authorization.

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
- `execute(call)` performs only that normalized operation against the checked
  endpoint. It must not add unapproved destinations or use broader credentials.

The gateway checks exact grants, endpoint identity, descriptor digest, offline
input-schema validity, request-bound approval and revocation before execution.
Unsupported descriptor fields fail closed until the digest profile is upgraded.
Arguments are copied before checking; schema references cannot trigger network
retrieval. Identities and validity are checked again immediately before execution.

The SQLite `StateStore` atomically records snapshot and trust-status high-water
marks and consumes approval nonces. Fresh authenticated revocation knowledge is
retained even when the current operation is denied. Failed signature or binding
checks cannot advance snapshot state. Expiry during authorization fails closed;
an approval consumed before a late failure requires a new approval.

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
Retrieval requires current ACL evidence across the ancestry and records returned
version identifiers, content digests, principal, time and read watermark. Source
withdrawal cascades to derived records; source ACL revocation blocks subsequent
retrieval of derived records. Connect these helpers to the actual datastore's
transaction/snapshot and ACL enforcement APIs. They do not by themselves delete
remote content or authorize access to a live vector database.

## Verification evidence

`tests/test_runtime_authorization.py` exercises signature thresholds, tampering,
wrong identities, changed arguments, schema references, revocation replay,
approval replay, scope mismatches, expiry during adapter execution and durable
rollback/fork rejection. `tests/test_lineage.py` covers source withdrawal,
cross-tenant rejection, ACL revocation and hosted identity verification boundaries.
These fixtures establish local contract behavior, not a production penetration
test or a comparative security benchmark.
