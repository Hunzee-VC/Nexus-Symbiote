# Trust model

What Symbiote trusts, what it refuses to assume, and what an attacker would have to do to get past it. This is
the summary; the per-feature table (detects / evades / residual risk, with OWASP ASI and MITRE ATLAS ids) is
[`THREAT-MODEL.md`](../THREAT-MODEL.md), and the disclosure process is in [`SECURITY.md`](../SECURITY.md).

## The asset

The asset is not the agent's code. It is the **authority an agent exercises** — which tools it can call, with
which credentials, on which data, sending output where — and the **inputs that steer that authority**: tool
descriptions, instructions, retrieved documents, memory. The incidents that motivate the design (Clinejection,
Deadbugz, postmark-mcp, the Rules File Backdoor, the Amazon Q extension) all changed one of those inputs after
someone had approved the configuration. An AgentBOM therefore has to make *change since approval* visible and
make *authority* queryable, not merely list components.

## Adversaries

| Adversary | Can | Cannot (assumed) |
|---|---|---|
| **Upstream publisher or registry account** (compromised or malicious) | change what a package, MCP server, skill or model serves after approval; re-register a deleted namespace; typosquat | forge a signature from an identity the operator constrained; alter a transparency log |
| **Content author** (anyone who can write an issue, a document, a web page, a memory entry) | place instructions where the model will read them; trigger tool calls | change the declared configuration or the gateway's allowlist |
| **Insider or CI pipeline with write access** | change instructions, rules files, hooks, configuration; approve bypass flags | sign as the operator's constrained identity without that identity |
| **Network position** | serve a different `tools/list` to the collector than to the agent; replay an old BOM or allowlist; block distribution of a revocation list | break TLS to a pinned origin; forge the Merkle root |
| **Document holder** (a partner or customer who receives the BOM) | read everything in the document; forward it | learn redacted leaves from a redacted view; alter the document without invalidating the root |

## Trust boundaries Symbiote draws

1. **Names locate, digests identify.** Package names, aliases, display names and URLs are never load-bearing.
   Allowlists, diffs and approvals operate on content digests: `tooldef/v1` over the model-visible tool
   definition, `server/v1` over server identity, exact bytes for instructions, per-file manifests for weights.
   A name match never upgrades assurance; a known name with a new digest is the rug-pull signal.
2. **Fail closed on canonicalization.** Input that RFC 8785 cannot represent (non-finite numbers, integers beyond
   2^53, duplicate keys) is `undigestable` and treated as unpinned, never approximated. Remote `$ref`s in a schema
   are a finding; no normalization is applied to anything collected, so a zero-width character is a change.
3. **Unknown is not absence.** A surface that was not examined is `not-attempted`; a failed query is
   `unreachable` or `permission-denied`; a claim of absence requires that the surface was queried
   (`SYM-COV-002`). Policy checks with unknown inputs are `indeterminate` and the Verified level cannot be reached
   with blocking unknowns.
4. **Three assurance levels, per claim.** `declared` (the owner or configuration says so), `observed` (a
   collector corroborated it against the running system within a window), `verified` (authenticated evidence
   evaluated against an explicit trust policy with a constrained signer). The document never carries one
   trust score for the whole agent.
5. **No laundering of signatures.** `verified` requires a satisfied signer identity constraint. A valid signature
   from an unconstrained signer is recorded as `signature-valid-unconstrained` and stays `observed`; an imported
   k8s-aibom `verified` without a recorded constraint is downgraded the same way. A verification policy with no
   identities is refused.
6. **Snapshot kinds never merge silently.** Declared, approved, deployed and observed are separate documents over
   one graph; the diff between them is the detection primitive, and an undeclared component observed at runtime
   is a critical finding, not a log line.
7. **Monotone serials and hash chains.** Every snapshot has a serial and a `prev` digest; a verifier with the
   chain store refuses a serial regression or a fork (`SYM-SNAP-001`, exit 7) and records chain gaps. Validity
   windows and trust-status lists expire and fail closed.
8. **Secrets never enter the document.** Collectors record environment-variable and header *names*, identity
   *references*, and tool definitions by digest unless text inclusion is requested; a validator rejects
   secret-shaped strings in identity fields, and inline secrets found in configuration become a `static-long-lived`
   credential binding plus a redaction record.
9. **Transparency without an attack map.** The Merkle commitment uses per-leaf salts derived from a withheld
   nonce, so a redacted document still verifies against the signed root while the hidden leaves cannot be
   dictionary-guessed. Redaction is recorded at document level and on the entity, never silent.

## What Symbiote does not claim

- **A schema digest does not see a backend swap.** A tool that keeps its name, description and schema and starts
  exfiltrating data is invisible to `tooldef/v1`. Server identity (package digest, endpoint origin, instructions
  digest, signer) narrows the gap; effects must be enforced at the gateway, sandbox or network boundary.
- **Observed is not verified.** OpenTelemetry spans, live `tools/list` captures and registry responses are
  `observed` evidence. Forged telemetry can add noise; it cannot upgrade assurance.
- **Enforcement is the gateway's job.** Symbiote exports what a gateway should enforce (the Gateway Allowlist
  Bundle) and ships a reference check, but it is not in the request path. Re-verification per session, per
  `tools/list`, on `list_changed` and per call is what defeats time-gated poisoning; a one-time check at approval
  is not.
- **State files are the operator's.** The chain store and trust-status lists must live in signed or immutable
  storage; a verifier whose state can be rewound can be rolled back.
- **Deterministic mode is for reproducibility, not confidentiality.** `--deterministic` pins the Merkle nonce to
  a known value, which makes redaction of that document guessable. Use a random nonce for anything you intend
  to redact.
- **Human readers can still over-trust.** The score is completeness, never safety; conformance is about the
  document; findings cite their inputs so they can be recomputed and disputed.

## Mapping to the checks

The policy checks are the operational form of this model: `SYM-TOOL-001/002/004` (pinning and served ≠ approved),
`SYM-MCP-002/005` (floating launchers, typosquats), `SYM-AUTHZ-001` (lethal trifecta), `SYM-INSTR-003/004`
(changed or hidden-Unicode instructions), `SYM-MEM-001/002` (memory writers), `SYM-SNAP-001…003` (anti-rollback),
`SYM-COV-001/002` (coverage), `SYM-ATT-001` (unconstrained signer), `SYM-TRUST-001/002` (revocation), `SYM-CI-001…003`
(the Clinejection pattern). Each is mapped to OWASP ASI and MITRE ATLAS ids in [`spec/checks.md`](../spec/checks.md)
and explained by `symbiote policy explain ID`.
