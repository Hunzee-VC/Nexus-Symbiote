# ADR-0004: Content addressing uses RFC 8785 over typed digest envelopes, fail-closed

**Status:** accepted · **Date:** 2026-11-01

## Context
Tool definitions, prompts, policy bundles and manifests must be identified by content so that any change
after approval is a digest mismatch. Naive hashing of pretty-printed JSON is brittle (key order,
whitespace, number forms), and hashing different artefact kinds with the same algorithm invites cross-type
collisions (a prompt whose bytes equal a tool definition's canonical form).

## Decision
- Structural digests are `sha256(JCS(E))` where `E = {"_type": <digest-type URI>, ...payload}` and JCS is
  RFC 8785 as implemented by `rfc8785`. The `_type` tag gives domain separation.
- Raw byte artefacts (instruction files, policy files, model shards) use plain `SHA-256(bytes)` so that
  `sha256sum` and OpenSSF model-signing agree with Symbiote.
- No normalization (Unicode, whitespace, case) is applied to anything collected from the wire or disk.
  A separate *triage* digest over normalized text exists only to classify drift as cosmetic/semantic and is
  never used for allowlisting.
- Input that violates JCS domain rules (NaN/±Inf, integers outside ±2^53, duplicate keys, non-UTF-8) is
  **not** given a best-effort digest: the entity is marked `digest.status = undigestable` with a reason and
  policy treats it as unpinned (`SYM-TOOL-004`).
- `$ref`s in JSON Schemas are never expanded; remote `$ref`s are flagged (`SYM-TOOL-005`).

## Consequences
Gateways and Symbiote compute identical digests from the raw JSON-RPC result, independent of SDK
re-serialization. A tool whose schema cannot be canonicalized cannot be pinned, by design.
