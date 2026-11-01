# Digests and the Merkle commitment

## Name is locator, digest is identity
Names, purls, aliases and URLs locate things. Equality, diffs and allowlists operate on content digests.

Structural digests are `sha256(JCS(E))` where JCS is RFC 8785 canonical JSON and `E` is a **typed envelope**
`{"_type": "https://aisecnomad.github.io/symbiote/digest/<kind>/v1", …payload}`. The type tag separates domains
(a prompt can never collide with a tool definition). Raw files — instructions, policies, model shards — use plain
SHA-256 so `sha256sum` and OpenSSF model-signing agree with Symbiote.

| Kind | Covers |
|---|---|
| `tooldef/v1` | name, title, description, inputSchema, outputSchema, annotations — as served, from the raw JSON-RPC result |
| `tooldef-full/v1` | the above plus `_meta`, `icons`, `execution` |
| `toolset/v1` | the sorted (name, digest) set of a server's tools — the allowlist unit |
| `server/v1` | kind, transport, normalised endpoint, package purl+digest, server info, instructions digest |
| `prompt/v1`, `jsondoc/v1`, `agent/v1` | templates, JSON documents (agent cards, registry records), the agent definition |
| `dirmanifest/v1` | skills, policy bundles, model directories — root byte-compatible with model-signing |
| `tensormanifest/v1` | per-tensor digests inside a safetensors file, so a poisoned adapter layer is localised |

## Fail closed
No normalization is applied to collected data: any byte change is a change. Input that JCS cannot represent —
NaN, integers of magnitude ≥ 2^53, duplicate keys — is **undigestable**, never approximated, and policy treats
the tool as unpinned. `$ref`s are never expanded; a remote `$ref` is a finding.

## The Merkle commitment
Each entity, edge, coverage object and flag is a leaf `SHA-256(0x00 ‖ JCS({_type, salt, kind, id, body}))`, with a
per-leaf salt derived (HKDF) from a per-snapshot nonce. Leaves are sorted and combined RFC 6962-style; the root is
the snapshot digest and the attestation subject.

Because leaves are salted, a **redacted** document — one where sensitive entities are replaced by their leaf
hash and their salt is withheld — still verifies against the signed root, and an attacker holding the redacted
view cannot dictionary-guess the hidden leaves. `symbiote merkle prove` emits an inclusion proof so a partner can
verify a single tool definition against the signed root without seeing anything else.
