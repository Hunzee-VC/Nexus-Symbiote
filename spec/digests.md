# Digests, canonicalization, Merkle commitment, model identity and name resolution

Implementation: `symbiote.digest`. Everything here is reproducible by a third party with the information in
this document alone; gateways and auditors MUST be able to recompute every digest from raw inputs.

## 1. Canonical JSON (RFC 8785)
Structural digests are computed over **JCS** (RFC 8785) bytes produced by `rfc8785.dumps`. Properties the
implementation relies on: object keys sorted by UTF-16 code units; `1.0` serialises as `1`; `1e21` as `1e+21`;
NaN/±Infinity raise; integers with |n| ≥ 2^53 raise. No `null` members are stripped (absent and `null` are
different facts). No Unicode normalization, whitespace normalization or case folding is ever applied to
collected data (ADR-0004).

## 2. Typed digest envelopes
`digest(kind, payload) = "sha256:" + hex(SHA-256(JCS({"_type": TYPE[kind], **payload})))`.
The `_type` URI gives domain separation between artefact kinds. Type URIs are
`https://aisecnomad.github.io/symbiote/digest/<kind>/v1`.

Failure semantics: if JCS raises (non-finite number, |integer| ≥ 2^53, invalid UTF-8) or the source JSON text
contained duplicate keys (detected with an `object_pairs_hook`), the result is
`{algorithm: "<kind>/v1", status: "undigestable", reason: "<class>: <detail>"}` — never a best-effort value.

## 3. Digest kinds

### 3.1 `tooldef/v1` — MCP tool definition (model-visible surface)
Payload fields, taken from the **raw JSON-RPC `tools/list` result object** (not from SDK types):
`name` (string), `title` (string, only if present), `description` (string, only if present),
`inputSchema` (JSON as served), `outputSchema` (only if present), `annotations` (object as served, only if present).
Absent keys are omitted (absent ≠ null ≠ `{}`). `$ref`s are not resolved. `_meta`, `icons`, `execution` are
excluded because the model does not read them.

### 3.2 `tooldef-full/v1`
`tooldef/v1` payload plus `_meta`, `icons`, `execution` when present. Detects non-model-visible changes.

### 3.3 `toolset/v1` — the allowlist unit
`{"server": <server digest>, "protocolVersion": <string|null>, "tools": [{"name", "digest"}...]}` with
`tools` sorted by `name` (UTF-16 code-unit order) after fetching **all** pages (`nextCursor` until absent).
Identical sets ⇒ identical digests regardless of list order or pagination. If any tool is `undigestable`,
the toolset is `undigestable` too.

### 3.4 `server/v1` — tool-server identity
`{"kind", "transport", "endpoint": <normalised URL: lowercase scheme and host, explicit port, path kept, no query/fragment> | null, "package": {"purl", "digest"} | null, "serverInfo": {"name", "version"} | null, "instructionsDigest": <sha256 of instructions bytes> | null}`.
The MCP `instructions` string is model-visible, so it is part of server identity.

### 3.5 `prompt/v1`
`{"engine", "role", "template": <exact string>, "variablesSchema": <JSON|null>}`.

### 3.6 `dirmanifest/v1` — skills, policy bundles, rules directories, local model snapshots
`{"method": "files", "hashType": "sha256", "allowSymlinks": false, "ignore": [...patterns...], "resources": [{"name": <POSIX relative path>, "algorithm": "sha256", "digest": <hex>}...]}` sorted by `name` (byte order of the UTF-8 path). Symlinks are rejected unless `allowSymlinks` is true (then hashed as their target path string). `.git/**` is always ignored.
**Root digest** = `SHA-256(concat(digest bytes in sorted order))` — exactly the subject digest OpenSSF
model-signing computes for a directory, so Symbiote directory roots are byte-compatible with
model-signing v1 subjects.

### 3.7 `jsondoc/v1`
`{"mediaType", "body": <parsed JSON>}` — A2A agent cards (minus `signatures`), MCP registry `server.json`
records, OpenAPI documents, policy JSON.

### 3.8 `resolution/v1`, `grant/v1`, `approval/v1`, `leaf/v1`
Canonical entity bodies (companion JSON form of the entity with `id`, emission timestamps and derived
digests removed), used for Merkle leaves and attestation subjects.

### 3.9 `agent/v1`
`{"name", "version", "framework": <name@version|null>, "instructions": [<digest>...] (in precedence order), "tools": [<tool digest>...] sorted, "models": [<model identity digest>...] sorted, "policyBundle": <digest|null>}`.

### 3.10 `tensormanifest/v1` — per-tensor digests inside a weights file
For safetensors files: parse the 8-byte little-endian header length and the JSON header
(`{<tensor>: {dtype, shape, data_offsets}}`), compute `sha256` over each tensor's byte range, and emit
`{"file": <posix name>, "format": "safetensors", "tensors": [{"name", "dtype", "shape", "digest"}] sorted by name}` with an RFC 6962 root over the
tensor digests. This localises a poisoned adapter layer or a single swapped tensor behind an unchanged file
name and corroborates adapter/merge lineage without external tooling (`symbiote model manifest --tensors`).
GGUF uses the v3 tensor-info table (parser must be validated against the reference implementation before
it is promoted from experimental).

### 3.11 Raw bytes
Instruction files, prompt files, policy files, model files, tokenizer files, chat templates:
`sha256(bytes)` of the file exactly as stored (BOM and CRLF preserved). Recorded alongside: `size`,
`line_endings`. An optional **triage** digest `sha256(NFC(UTF-8 decode) → LF → strip trailing whitespace)` is
used only to classify a drift as cosmetic vs semantic; it is never an identity.

## 4. Name-resolution record (`RegistryResolution`)
Recorded for every externally sourced component (models, MCP packages/servers, skills, agent cards):
```
{ "_type": ".../digest/resolution/v1",
  "requested": {"kind": "mcp-registry|npm|pypi|oci|nuget|huggingface|a2a-card|url|hosted-alias", "ref": "<as configured>"},
  "resolved_at": "<time>", "resolver": {"name", "version", "digest?"},
  "resolved": {"immutable_ref": "<purl with version+checksum | commit | digest | snapshot id>", "digest": "<sha256>|null", "state": "present|unknown"},
  "registry": {"url", "entry_id", "version", "status": "active|deprecated|deleted|unknown", "published_at", "updated_at", "is_latest", "schema"},
  "publisher": {"namespace", "identity", "verification": "github-oidc|github-oauth|dns|http|none|unknown"},
  "signer": {"status": "unsigned|claimed|verified", "outcome", "identity", "issuer", "bundle_digest"},
  "transparency_log": {"type": "rekor", "log_id", "log_index", "integrated_time", "inclusion_proof_verified"},
  "alias_policy": "pinned|floating", "typosquat_distance": {"nearest", "levenshtein"}, "warnings": [] }
```
The official MCP registry has no signature/attestation fields; `signer` comes from package-ecosystem
attestations (npm provenance, PyPI attestations, Sigstore bundles for OCI) when present, else `unsigned`.
`alias_policy=pinned` iff the resolved ref is immutable (commit SHA, dated snapshot id, OCI digest, version
plus checksum). Hosted models whose provider discloses no snapshot id get `state=unknown` and MAY carry a
behavioural fingerprint claim with an expiry (assurance never above `observed`).

## 5. Merkle commitment and verifiable redaction
- Every snapshot has a 32-byte random **nonce**; each leaf's **salt** = `HKDF-SHA256(ikm=nonce, salt="agentbom-leaf", info=kind ‖ "/" ‖ id, L=16)`. Under `--deterministic --nonce <hex>` (and in the test suite) the nonce is supplied, so re-exports are byte-identical (I7) while salts stay unguessable to anyone without the nonce.
- Leaf `L_i = SHA-256(0x00 ‖ JCS({"_type": ".../digest/leaf/v1", "salt": <hex>, "kind": <entity kind>, "id": <id>, "body": <canonical entity>}))`, leaves sorted by `(kind, id)`; internal node `SHA-256(0x01 ‖ left ‖ right)`; an odd node is promoted (RFC 6962 shape). Edges, grants, coverage and derived flags are leaves too.
- `snapshot.digest = root`. The companion carries `merkle.leaves[] = {kind, id, salt, leaf_hash}` for disclosed leaves and `{kind, leaf_hash}` for redacted ones — never the body **or the salt** of a redacted leaf, so a redacted leaf cannot be dictionary-guessed from the root (SD-JWT-style selective disclosure). The nonce is never emitted in a redacted view.
- **Redaction**: `symbiote redact --class <c>` replaces an entity body with `{"redacted": true, "class": c, "leaf_hash": "<hex>"}`, appends a `Redaction{class, count, applied_by, applied_at}` record and the `agentbom:redaction:applied` property. `symbiote merkle verify` recomputes the root from (disclosed bodies+salts) ∪ (redacted leaf hashes) and compares with the signed root; `symbiote merkle prove --id <id>` emits an inclusion proof (sibling hashes) so a partner can verify one entity against the signed root without seeing the rest.
- Redaction classes: `credential-shaped-token`, `endpoint-internal-host`, `tool-text`, `prompt-text`, `instruction-body`, `identity-ref`, `grant-detail`, `data-source-detail`, `custom:<name>`.

## 6. Model identity
- `ModelManifest = {format: "oms-v1", serialization: {method: "files"|"shards", hash_type: "sha256", allow_symlinks: false, shard_size?}, items: [{name: <posix path>, digest: {sha256}, size?}] sorted by name, root: Digest}` with `root` as in §3.6.
  Items are byte-compatible with model-signing `FileManifestItem`/`ShardedFileManifestItem`, so an existing
  `model.sig` bundle's in-toto subjects can be compared item-for-item.
- Serialization risk class per file, aggregated per model: `safetensors|onnx|gguf|npz → none`;
  `tf-savedmodel|keras-h5 → low`; `pickle|torch-zip (.bin/.pt/.pth)|joblib|dill|npy(allow_pickle) → code-exec-on-load`;
  `config.json.auto_map` or `trust_remote_code=true` ⇒ `code-exec-on-load`; `tokenizer_config.json.chat_template`
  present ⇒ `chat_template_executable=true` (Jinja) ⇒ at least `template-execution`.
  Detection uses extension **and** magic bytes (`\x80\x04` pickle opcode, `GGUF`, safetensors 8-byte header +
  JSON, ONNX protobuf).
- Hosted identity tuple: `(provider, endpoint_origin, requested_ref, resolved_ref)`; `alias_pinning` from a
  provider rule table (`providers.yaml`: e.g. `claude-sonnet-4-5` floating vs `claude-sonnet-4-5-20250929`
  pinned; `gpt-4o` vs `gpt-4o-2024-08-06`; Bedrock ids pinned by version suffix).

## 7. Adversarial robustness (what each rule defends against)
| Pitfall | Attack | Rule |
|---|---|---|
| Unicode normalization, homoglyphs, zero-width/bidi/tag characters | visually identical description carrying hidden instructions | no normalization in digests; `text_flags.hidden-unicode` on Cf/Co/Cn, bidi (U+202A–202E, U+2066–2069) and tag (U+E0000–E007F) code points ⇒ `SYM-TOOL-006` |
| JSON number forms (`1` vs `1.0`, `-0`, big ints, NaN) | false drift, or BOM/gateway desync | JCS normalises doubles; big ints / non-finite ⇒ undigestable (fail closed) |
| key order / duplicate keys | evading string comparison; parser disagreement | JCS fixes order; duplicates ⇒ undigestable |
| `$ref`/`$defs`/remote refs in schemas | semantics change behind a URL with no digest change | never expand; remote `$ref` ⇒ `SYM-TOOL-005` |
| whitespace / trailing newline / CRLF | reviewer approves "same text", tooling trims | exact bytes; triage digest separately |
| absent vs explicit default annotations | removing `readOnlyHint: true` makes a tool destructive by default | absence is encoded as absence (digest changes); policy applies MCP defaults; `SYM-TOOL-007` |
| pagination/order of `tools/list` | splitting pages to evade set comparison | `toolset/v1` sorts by name; all pages fetched; truncation recorded |
| same tool name on two servers | rug-pull via shadowing | ids include the server; `SYM-TOOL-008` |
| SDK re-serialization | gateway sees raw JSON, BOM sees SDK output | digest the raw JSON-RPC object; SDK types for typing only |
