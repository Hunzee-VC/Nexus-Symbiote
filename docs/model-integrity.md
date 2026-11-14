# Model integrity

This page describes what the `model` collector records for model files, which other
files it binds to them by digest, and how an operator signature policy verifies
model weights. Collection is static: no model file is loaded, no template is
rendered and no repository code is imported.

## Model files and references

The collector inventories every file whose name has one of these suffixes:
`.safetensors`, `.onnx`, `.gguf`, `.ggml`, `.h5`, `.hdf5`, `.keras`, `.tflite`,
`.mlmodel`, `.pte`, and the pickle family `.pkl`, `.pickle`, `.pck`, `.dill`,
`.pt`, `.pth`, `.bin`, `.joblib`, `.ckpt` and `.pdparams`. A pickle-family name
inside an archive or compression suffix, such as `checkpoint.pth.tar` or
`model.pkl.gz`, counts as pickle family too. TensorFlow graphs named
`saved_model.pb` or `saved_model.pbtxt` are collected; other `.pb` files are not.

Each model file is one component. Its `bom_ref` is `model:` followed by the
file's path relative to the scanned root, and its `name` and `source_path` are
that relative path, so the same tree scanned at two locations produces identical
records, and two files with the same name in directories with the same name stay
distinct.

The serialization rating is:

| Rating | When |
| --- | --- |
| `unsafe-code-execution` | A pickle-family name, rated on the name alone, even when the file cannot be read; or content recognized as a binary or text-protocol pickle, or a ZIP archive whose first member is a pickle (as `torch.save` writes it), under any other model suffix |
| `safe` | A SafeTensors file whose header is UTF-8 JSON with string metadata, known dtypes and tensor spans that index the whole data region, with no configured chat template matching the access-pattern heuristic. The rating is not a guarantee that the template is safe; `validate` compares templates only through its completeness check |
| `unsafe-template-injection` | A GGUF file whose embedded chat template matches the access-pattern heuristic, or a SafeTensors file that would be `safe` in a directory whose Hugging Face chat template matches it. A match does not establish that the renderer executes the pattern or that its sandbox is bypassed |
| `unknown` | Everything else, including ONNX, GGUF, Keras, HDF5, SavedModel, TFLite, Core ML and ExecuTorch files, and a SafeTensors header over the 1 MiB inspection limit |

## Files bound to the weights

Some formats keep weights outside the file the collector rates. The collector
binds those files to the model by SHA-256 and lists them, with paths relative to
the root, in the component's `properties.weight_files`:

| Layout | Bound files |
| --- | --- |
| ONNX with external data | Every file that a tensor stored as `EXTERNAL` names in its `location`, in graph initializers, node attributes, subgraphs, functions and training graphs |
| TensorFlow SavedModel | Every file under `variables/`, `assets/` and `assets.extra/`, and `fingerprint.pb` and `keras_metadata.pb`, beside `saved_model.pb` |
| Sharded checkpoints | The shard index (for example `model.safetensors.index.json` or `pytorch_model.bin.index.json`) on every shard it lists |

An external-data location that leaves the model's directory or names a missing
file, a shard index that lists a missing file, a file in another directory or a
file that is not a collected model file, and an ONNX file that may name external
data the reader cannot attribute are collection failures. The reader counts a
`location` key in every encoding a protobuf runtime accepts, including the
over-long tags whose low 32 bits protobuf's C++ parser keeps; in a file it can
parse, each such key must be an external-data entry it read or a name, and a
file it cannot parse, or one beyond its limits, fails whenever the bytes
`location` occur in it at all. A tensor's `data_location` is read as protobuf
reads the enum: as a 32-bit value, where a later value that the enum does not
define never replaces an earlier `EXTERNAL`. A singular tensor field written more
than once, such as a node attribute's tensor, which protobuf merges into one
tensor, is a file the reader cannot parse.

When `variables/`, `assets/` or `assets.extra/` beside a SavedModel graph is a
symlink to a directory in the project, the files below it are bound under the
names a loader opens through the link, and they are hashed without following it,
so each is a collection failure. When one of those directories, `fingerprint.pb`
or `keras_metadata.pb` is absent, another spelling of its name that differs only
by case or Unicode normalization is a failure, because case-insensitive file
systems open it.

A file that many models bind costs one binding per model, so the bindings are
bounded. A directory with more than 16 shard indexes binds none of them and
fails. One scan records at most twice the `entries`
[collection limit](collection-limits.md) in bindings (200,000 by default),
counting each distinct entry of a shard index once when the index is read and
each file once for every model it is bound to; beyond that, the scan fails and
binds nothing more to the remaining models.

`validate --project` observes the files again and fails with
`weight_files_mismatch` when they differ from the BOM's record, so replacing one
shard or one external-data file fails integrity and changes the inventory. For
this model check, one validation walks each model directory once, reads a file
that many models share once rather than once per model, verifies each policy
entry once, and reads and binds at most what one scan may (the
`model-total-bytes` limit, and twice the `entries` limit in bindings). A model
beyond either budget gets the `unknown` issue `validation_budget_exhausted`. In
addition, `validate` charges the model's own file, each Sigstore verification of
it and the file-hash check's digests (each algorithm computed once per run) to
the validation's artifact budget, six times the `model-total-bytes` limit
(1.5 TiB by default), and
a second model component that names the same weights file, or the same artifact
the signer policy names, fails as `duplicate_artifact`.

## Configuration, tokenizer, chat templates and custom code

For every directory that holds a model, the collector reads and digests these
files when present, and records the digests on each model in the directory:

| Field | Source files |
| --- | --- |
| `properties.config_files` | `config.json`, `model_config.json`, `adapter_config.json`, `tokenizer_config.json`, `generation_config.json`, `quantize_config.json`, `preprocessor_config.json`, `processor_config.json`, `chat_template.json`; each must be a JSON object |
| `tokenizer_hash`, `properties.tokenizer_files` | `tokenizer.json`, `tokenizer.model`, `spiece.model`, `sentencepiece.bpe.model`, `vocab.json`, `vocab.txt`, `merges.txt`, `special_tokens_map.json`, `added_tokens.json` |
| `chat_template_hash`, `properties.chat_templates` | `chat_template` in any of the configuration files, as a string or a list of named templates; `chat_template.jinja`, `chat_template.jinja2` and `additional_chat_templates/*.jinja`; the `tokenizer.chat_template` entries embedded in a GGUF file, with each key read up to its first NUL byte, as llama.cpp reads it |

`tokenizer_hash` and `chat_template_hash` are manifest digests: the SHA-256 of
the RFC 8785 JSON `{"files": [{"path": ..., "sha256": ...}]}` built from the
recorded list, sorted by path (for a chat template, the path is the source,
such as `tokenizer_config.json#chat_template`).

An `additional_chat_templates` symlink to a directory in the project is read
through the link, under the names a loader opens. When one of these files or that
directory is absent, another spelling of its name that differs only by case or
Unicode normalization is a failure, because case-insensitive file systems open it.

Every model records these digests for its directory, so one scan records at
most twice the `entries` limit of them across its models (200,000 by default),
counting each configuration file,
tokenizer file, chat template, custom-code reference and Python file once per
model. Beyond that, the scan fails and the remaining models record none of
these lists, `tokenizer_hash` or `chat_template_hash`.

`trust_remote_code` is `true` when any configuration file says so, so an empty
`config.json` cannot hide it in a later file. A configuration that declares
`auto_map` or `custom_pipelines` declares custom code, which the loader imports
only with `trust_remote_code`: the model gets a high `custom_code` finding, and
`properties.custom_code` records which files declare it, the well-formed module
references, whether any reference names another repository, and the digests of
the directory's `.py` files. Without such a declaration, Python files are not
recorded, so adding an unrelated script does not change the inventory. The
`base_model_name_or_path` of an `adapter_config.json` is recorded as
`properties.base_model` when it is a Hugging Face model identifier.

In `diff`, a change to `tokenizer_hash` or `chat_template_hash` is a high alert,
and a change to a bound weight file, a configuration file or custom code is a
high alert naming the property that records its digest.

Every chat template that `properties.chat_templates` lists is checked for potential
Python-internals access patterns: a dunder attribute, named or subscripted, a
dunder name as a string such as an `attribute=` argument, or the `attr` filter.
The heuristic decodes string escapes such as `\x5f`, removes a backslash before a
line break, and folds adjacent constant strings joined with `~` or `+`, or written
next to each other, inside Jinja expressions. It does not evaluate templates.
Matches may be harmless in the actual context; a correctly configured sandbox can
deny the access. Other ways to construct names may not match. A Hugging Face template
that matches gives every
model in its directory a critical `serialization_format` finding that names up to
three matching templates and counts the rest, and a model that would otherwise be
rated `safe` is rated `unsafe-template-injection`. A model rated `unknown` or
`unsafe-code-execution` keeps its rating and the findings that come with it, such as
`invalid_safetensors` for a SafeTensors file that does not validate, so a suppression
of the template finding does not accept them. `validate` checks each model file's own
structure again, not its directory's templates: its completeness check, on by
default, and `risk --project` compare the rating and the finding with a new
collection. A template file larger than the `file-bytes` limit is digested but not
checked, and is a coverage gap in `surfaces_excluded`.

A GGUF file whose metadata exceeds the reader's bounds (65,536 keys, 16 MiB
strings, 2,097,152 array items, 128 MiB of metadata, or the 16,000,000
structure units one scan may spend on ONNX and GGUF files) keeps the rating
`unknown`, records `properties.gguf_metadata` and is a coverage gap in
`surfaces_excluded`, because its chat templates were not inspected.

## Operator signature policy

A model passes integrity only when every one of its weight files (the model file
and the files bound to it) verifies under a signature policy you own. Pass the
same policy to `scan`, `validate --project`, `risk --project` and `baseline`
with `--signature-policy`, or to the GitHub Action with `signature-policy`.

Keep the policy outside the checkout: the commands refuse a policy file inside
the scanned project, also under another name for the project directory such as a
case variant or a bind mount (compared by device and inode), or one with other
hard links, and they resolve the project path first, so a symlinked `--project`
path works for every command. Every entry must name a file beneath the project,
spelled as its directory spells it: another case is refused on every file system,
also where file names fold case.
An entry that names neither a collected model weight file nor the ShadowScan
report makes the `model` collector fail, and `validate --project` reports it as
the integrity error `unused_policy_entry` even when the completeness check does
not run, so an entry can never look enforced while nothing checks it. An entry
beneath the directory of a model that got `validation_budget_exhausted` is not
reported as unused: that model's weight files were not all bound, and its
`unknown` issue already keeps integrity from passing.

The ShadowScan report is checked by the discovery producer check of
`validate --project` and `risk --project`, not by `scan`, and only through a
`sigstore-message-signature` entry for the report the collector reads, the first
of `.shadowscan/report.json`, `shadowscan-report.json` and `shadowscan.json`
that exists. Its `expected_sha256`, if set, must equal the report's digest. A
`digest-pin` entry for the report, or an entry for another report location, is
an unused entry.

Version 1 policies stay valid; every entry is a Sigstore message signature:

```json
{"version": 1, "artifacts": [{"artifact_path": "models/classifier.safetensors",
  "bundle_path": "models/classifier.safetensors.sigstore.json",
  "expected_identity": "https://github.com/acme/models/.github/workflows/release.yml@refs/heads/main",
  "expected_issuer": "https://token.actions.githubusercontent.com"}]}
```

Version 2 names a `kind` on every entry and rejects unknown kinds and fields:

```json
{"version": 2, "artifacts": [
  {"kind": "sigstore-message-signature", "artifact_path": "models/classifier.safetensors",
   "bundle_path": "models/classifier.safetensors.sigstore.json",
   "expected_identity": "https://github.com/acme/models/.github/workflows/release.yml@refs/heads/main",
   "expected_issuer": "https://token.actions.githubusercontent.com",
   "expected_sha256": "sha256:<hex>"},
  {"kind": "digest-pin", "artifact_path": "models/onnx/model.onnx_data",
   "expected_sha256": "sha256:<hex>"}]}
```

- `sigstore-message-signature` verifies a Sigstore bundle offline over the
  file's SHA-256, under the exact identity and OIDC issuer. Produce the bundle
  with sigstore-python, for example `python -m sigstore sign --bundle
  model.safetensors.sigstore.json model.safetensors` in a workflow with an OIDC
  identity. A signature proves only that the identity signed those bytes at some
  time: anyone who can write to the checkout can put an older or another
  artifact signed by the same identity, with its bundle, in its place. The
  optional `expected_sha256` pins the exact bytes and closes that gap.
- `digest-pin` recomputes the file's SHA-256 through the collector's confined
  reader and compares it with `expected_sha256`. You are the trust root, as you
  are for the policy itself; no Sigstore install is needed. Compute the value
  with `sha256sum`.

OpenSSF Model Signing signatures (`model.sig`) are not verified yet: they are
Sigstore bundles whose DSSE envelope signs an in-toto statement listing every
file's digest, not the file itself. Such a bundle named in a policy fails with
the reason `Bundle carries a DSSE envelope (an OpenSSF Model Signing signature
or an attestation); only Sigstore message-signature bundles are verified`. Pin
the files, or sign each weight file with a message signature, instead.

### Signing status and evidence

| `signing_status` | Meaning |
| --- | --- |
| `sigstore-signed` | Every weight file verified, the model file by its Sigstore signature |
| `digest-pinned` | Every weight file verified, the model file by its digest pin |
| `partially-verified` | Some weight files verified and no entry names the others |
| `verification-failed` | An entry did not verify: other bytes, another signer or issuer, a pin mismatch, or a bundle the verifier refused |
| `verification-unavailable` | A Sigstore entry could not be checked because the `sigstore` extra is not installed; the scan also fails with the install hint |
| `signature-present-unverified` | No entry, but a signature-looking file lies beside the model |
| `signature-not-found` | No entry and no signature-looking file |

The trust tier is `third-party-signed` for `sigstore-signed` and
`internal-verified` for `digest-pinned`. Whenever an entry was checked, the
component's `claims.signing_status` records how: `method`
(`sigstore-message-signature` or `digest-pin`), `assurance` (`verified` or,
after a failure, `observed` with the reasons in `unknown_reason`), the model
file as `locator`, and `evidence_refs` such as `policy:sha256:<policy file
digest>`, `digest-pin:<path>@sha256:<digest>`,
`sigstore-message-signature:<path>@sha256:<digest>`,
`bundle:<bundle path>@sha256:<bundle digest>`, `identity:<signer>` and
`issuer:<issuer>`. `validate` does not trust these records: it verifies every
weight file again from the policy. The `policy:` reference identifies the
policy file of the run, not the model, so project reconciliation and `diff`
ignore it: an equivalent policy with other bytes, or one with more entries, does
not make a verified model look mismatched or changed.

## What this does not establish

A pin or a signature shows that the bytes are the ones the operator or signer
approved, not that the model is benign. Formats rated `unknown` have no
structural validator: Keras Lambda layers, SavedModel operations and custom
TensorRT or TFLite operators are not inspected. Pickles under names other than
those listed above, and NumPy `.npy` and `.npz` arrays, are not inventoried. SafeTensors
tensor bytes are hashed but not inspected, so a payload that also parses as
another format is not flagged. The chat template check is a heuristic, not template
analysis: a name assembled through variables, formatting, filters, nested expressions
or other operations can pass it, as can a template that instructs the model. The
heuristic does not establish whether a renderer is vulnerable or a sandbox escape
exists. Review templates and use an appropriately sandboxed renderer.
