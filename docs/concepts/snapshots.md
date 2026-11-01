# Snapshots and the diff

A snapshot is one document of one kind for one agent:

| Kind | Produced by | Meaning |
|---|---|---|
| `declared` | `symbiote scan` over configuration | What the owner says the agent is made of and may do |
| `approved` | a reviewer's signed `approval/v1` over a declared snapshot digest | What was authorised, bound to digests — never to display names |
| `deployed` | deployment identity + environment + workload identity | What is actually running where, under which principal |
| `observed` | live `tools/list`, OpenTelemetry GenAI traces, k8s-aibom inventories | What the runtime actually served, called, routed and spawned |

Every snapshot has a monotone `serial` per `(agent, kind)`, a `prev` digest forming a hash chain, and a
validity window. Its `digest` is the Merkle root over every entity, edge, coverage object and derived flag, so
the digest commits to the whole document and is what gets signed.

**The diff is the finding.** `symbiote diff approved.json observed.json` yields a `Delta` whose events —
`tool-definition-changed`, `tool-registered`, `model-routed`, `sub-agent-spawned`, `memory-writer-added`,
`grant-added`, … — are the detection primitive. Deltas can be signed independently (`observed-delta/v1`), so a
runtime can publish "tool X's description changed at T" without re-publishing the snapshot.

Verifiers keep a small state file of the last seen `(serial, digest)` per agent and kind; a serial regression is
a critical finding (`SYM-SNAP-001`) and a chain gap is recorded. Trust-status lists expire, so a stale revocation
list fails closed.
