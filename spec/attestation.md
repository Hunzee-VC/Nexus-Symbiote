# Attestation, signing, verification, anti-rollback and trust status

## 1. Statement shape
All statements are in-toto Statement v1 (`_type: https://in-toto.io/Statement/v1`), `payloadType:
application/vnd.in-toto+json`, wrapped in a DSSE envelope. Subjects are matched by **digest only**; subject
`name`s are informative. Predicate payloads are validated against vendored JSON Schemas
(`symbiote/schemas/predicates/*.json`).

| predicateType | subject[] | predicate (exact keys) |
|---|---|---|
| `https://aisecnomad.github.io/symbiote/attestation/agentbom-snapshot/v1` | `{name: "snapshot:<agent-id>", digest: {sha256: <merkle root>}}` plus `{name: "companion", digest}`, `{name: "cyclonedx", digest}`, `{name: "spdx", digest}` when exported | `{agent: {id, name, version}, kind, serial, prev, validity: {notBefore, notAfter}, producedAt, producer: {name, version, digest}, leafCount, leaves: [{kind, id, leafHash}], coverageDigest, policyBundleDigest, toolsetDigests: {<server-id>: <toolset digest>}, modelIdentities: [{id, manifestRoot | resolvedRef | "unknown"}], grantsDigest, redactions: [{class, count}]}` |
| `.../attestation/tool-definition-set/v1` | one subject per tool `{name: "tool:<server>/<name>", digest}` plus `{name: "toolset:<server>", digest}` | `{server: {id, digest, kind, transport, endpointOrigin?, package?: {purl, digest}, serverInfo?, protocolVersion?, instructionsDigest?}, observedAt, method: "mcp.tools/list" | "declared-config" | "registry" | "approved-file", capture: {digest, mediaType}, tools: [{name, digest, fullDigest?, annotations?, textFlags: []}], truncated: bool}` |
| `.../attestation/coverage/v1` | `{name: "snapshot:<id>", digest}` | the `Coverage` object plus `{collectors: [{name, version, digest}], window, textIncluded}` |
| `.../attestation/evaluation/v1` | every digest in `subjectConfig` | the `Evaluation` object; `results[].denominator` mandatory |
| `.../attestation/registry-resolution/v1` | `{name: "resolution:<requested ref>", digest: <resolution record digest>}` plus the resolved artefact digest when known | the `RegistryResolution` record |
| `.../attestation/observed-delta/v1` | `{name: "delta", digest}` plus `from`/`to` snapshot digests | `{fromSnapshot, toSnapshot, producedAt, producer, events: [DeltaEvent]}` |
| `.../attestation/trust-status/v1` | `{name: "trust-status:<org>", digest: sha256(JCS(entries))}` | `{serial, supersedes?, issuedAt, expires, decidedBy, entries: [TrustStatus]}` |
| `.../attestation/approval/v1` | `{name: "snapshot:<id>", digest: <approved root>}` | the `Approval` object |
| reused: `https://model_signing/signature/v1.0` | model manifest root | produced/verified by OpenSSF model-signing |
| reused: `https://cyclonedx.org/bom/v1.7`, `https://spdx.dev/Document/v3` | whole-document digests | for consumers that expect vetted BOM predicates |
| consumed: `https://slsa.dev/provenance/v1`, `https://in-toto.io/attestation/vulns/v0.2`, `https://in-toto.io/attestation/scai/v0.3` | software components | referenced as Evidence, not produced |

## 2. Signing flows
- **Keyless (default in CI)** — sigstore-python: `SigningContext.from_trust_config(ClientTrustConfig.production()|staging())`,
  identity token from ambient credentials or an OIDC issuer, `Signer.sign_dsse(statement) → Bundle`; written as
  `<name>.sigstore.json` (bundle v0.3 with the DSSE envelope, certificate and Rekor entry).
- **Key-based (air-gapped / enterprise PKI)** — Symbiote's own DSSE v1 implementation (PAE
  `DSSEv1 <len(type)> <type> <len(payload)> <payload>`), multi-signature envelopes, `keyid = sha256(SPKI DER)`,
  ECDSA P-256 (ES256) and Ed25519 via `cryptography`; verification by keyring. Needed because sigstore-python's
  `Envelope` accepts exactly one signature and has no key-based path.
- **Optional CycloneDX JSF** (`--jsf-sign`, ES256) for CycloneDX-native consumers; DSSE remains authoritative.

## 3. Verification (`symbiote verify`) — k8s-aibom Design 002 as code
1. Parse the bundle/envelope; for Sigstore bundles verify with `Verifier.production()|staging()|Verifier(trusted_root)` and
   `verify_dsse(bundle, policy)` where `policy = AllOf([Identity(identity=<anchored regex>, issuer=<issuer>), ...])` is
   built from `policy.yaml identities[]`. `UnsafeNoOp` is refused unless `--insecure-unconstrained`, and then the outcome
   is `signature-valid-unconstrained` and assurance stays `observed`.
2. Check `predicateType` against the expected set; validate the predicate schema; check `subject` digests against the
   artefact being verified (snapshot root, toolset digest, model manifest root).
3. Bindings: recompute the Merkle root from the companion/CycloneDX; recompute `toolset/v1` from live `tools/list`
   (`--live`) or from the captured evidence; compare the declared model manifest root with the signed subject.
   Digest contradictions block (`digest-mismatch`); a subject-name mismatch is recorded, never load-bearing.
4. **Anti-rollback**: the state file (`~/.symbiote/trust-state.json` or `--state-file`) keeps
   `last_seen[(agent, kind)] = {serial, digest}`; `serial ≤ last_seen` ⇒ `SYM-SNAP-001`, exit 7; `prev ≠ last_seen.digest` ⇒
   `chain-gap` recorded.
5. **Trust status**: load the latest unexpired `trust-status/v1` under the same identity policy; an expired list fails
   closed (exit 4) unless `--trust-status-stale-ok`; `revoked`/`quarantined` subjects in the snapshot ⇒ SYM-TRUST-001.
6. Emit `VerificationResult{outcome, identity, issuer, logIndex, integratedTime, bindings[], warnings[]}`; `verified`
   only when every step passed.

Outcome vocabulary (shared with model signature facts): `verified`, `signature-valid-unconstrained`,
`identity-mismatch`, `digest-mismatch`, `subject-name-mismatch`, `failed: <reason>`, `error: <class>`.

## 4. Where evidence lives
`Evidence.id = "ev:" + sha256(bytes)[:12]`; CycloneDX cites it in `declarations.evidence[].data[].contents.url`
and `externalReferences[type=attestation|evidence].hashes`; SPDX via `software_File.verifiedUsing` and
`hasEvidence`; the companion holds the full records; `--evidence-dir` writes raw files as `evidence/<sha256>.<ext>`.

## 5. Gateway Allowlist Bundle (GAB)
`symbiote allowlist export --format gab` produces `{gabVersion: "1", agent, snapshot: {kind: approved, digest, serial, prev, notBefore, notAfter}, policy: {maxStaleness, failClosedOnExpiredTrustStatus, requireAnnotationsForDestructive}, servers: {<server-id>: {identity: {digest, transport, endpointOrigin, package, instructionsDigest, signer}, toolset, tools: {<name>: {digest, gate, capabilities}}, deniedTools: []}}, models: {<id>: {provider, alias, resolvedRef, aliasPinned}}, instructions: {<id>: digest}, trustStatus: {serial, expires, revoked: [], quarantined: [], revokedPublishers: []}, attestations: [paths]}`.
The descriptor comparator checks served tool definitions, including digest drift, revocation and quarantine.
Use the signed [gateway admission protocol](gateway-admission.md) for execution decisions, exact-resource grants,
time bounds, persistent rollback protection, per-call approvals and signed audit receipts. An authenticated
gateway must derive the request principal, resource and observed peer from its own transport and adapter.
The GAB and OPA projection preserve grants. The generic projection rejects grants it cannot represent.
