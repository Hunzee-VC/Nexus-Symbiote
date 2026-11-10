# Collection limits

Every collector bounds what it reads from a project, so that very large or hostile
input cannot exhaust memory or hold a scan indefinitely. Each bound fails closed.
When a collector reaches one, it records a scan failure and its status becomes
`failed`, so `scan`, `baseline`, `validate`, `risk` and the GitHub Action fail. The
failure names the limit, its value, the root-relative path where it was reached
and how to raise it, and quotes nothing from the file:

```text
vendor/legacy: entries limit of 100000 exceeded; raise it with --limit entries=N
models/llama/model.gguf: model-bytes limit of 64 GiB exceeded; raise it with --limit model-bytes=N
```

The failures are recorded under `metadata.completeness.scan_failures` in the
native inventory, and `validate` prints them. A walk, or the mcp collector's
source search, can fail once for every entry, so each collector lists such
failures only up to a [fixed bound](#fixed-bounds) and then adds one line for each
reason, naming the first path it did not list:

```text
vendor/links/l01000: symlink excluded (and 93999 more not listed)
```

Raising a limit moves the point where collection stops. It never turns a reported
stop into a silent one and never relaxes a gate, and lowering one can only add
failures.

- [Set a limit](#set-a-limit)
- [Limits](#limits)
- [Why these defaults](#why-these-defaults)
- [Fixed bounds](#fixed-bounds)

## Set a limit

Only the operator sets limits, in one of two ways:

- `--limit NAME=VALUE` before the command. Repeat it for several limits.
- The environment variable `NEXUS_SYMBIOTE_LIMITS`, as comma-separated
  `NAME=VALUE` pairs.

```bash
nexus-symbiote --limit entries=200000 --limit model-bytes=128GiB scan . -o agentbom.json
```

```bash
NEXUS_SYMBIOTE_LIMITS="entries=200000,source-files=200" nexus-symbiote scan . -o agentbom.json
```

`--limit` wins over the environment variable for the names it sets; the others
keep their environment value. Values are whole numbers. Byte limits also accept a
`KiB`, `MiB` or `GiB` suffix, which are powers of 1024. An unknown name, a
malformed or out-of-range value, or a name set twice in one place is a usage error
(exit status 2), whatever the command.

Limits apply to every command that collects from a project: `scan`, `baseline`,
`validate --project` and `risk --project`, which collect the project again, and
`verify-artifact`, which hashes under `model-bytes`. `import-shadowscan` reads one
report under a [fixed bound](#fixed-bounds). Nothing in the scanned checkout can
change a limit, including the project policy file `.nexus-symbiote.yaml`. Use the
same limits for `scan` and for a later `validate --project` or `risk --project` of
its inventory, because those commands collect the project again.

In the GitHub Action, the `limits` input is passed to the scan as
`NEXUS_SYMBIOTE_LIMITS`, in the same comma-separated form:

```yaml
with:
  limits: 'entries=200000,model-total-bytes=512GiB'
```

The pre-commit hooks add their arguments after the command, so set
`NEXUS_SYMBIOTE_LIMITS` in the environment that runs them instead.

## Limits

| Limit | Default | Maximum | What it bounds | When it is reached |
|---|---|---|---|---|
| `file-bytes` | 4 MiB | 1 GiB | One file a collector reads into memory: configuration, manifests, lockfiles and instruction files. The mcp collector holds this much of each source file it searches. | The file is not read. A larger source file is still searched, as a stream; see [below](#source-files-the-mcp-collector-searches) for when it fails. |
| `total-bytes` | 32 MiB | 64 GiB | All bytes one collector reads, apart from model files and the mcp collector's source search, which have their own budgets below. Each collector has its own budget. | That file is not read; later files are read only while they fit in what remains. |
| `entries` | 100000 | 10000000 | Files and directories one collector lists while it walks the project. Directories named `.git`, `node_modules`, `__pycache__`, `.venv` or `venv`, and paths excluded by policy, count as one entry each and are not listed. | The directory being listed, and everything after it, is not walked. |
| `depth` | 32 | 256 | Directory nesting below the walk's starting directory. | That directory and everything beneath it are not walked. |
| `model-bytes` | 64 GiB | 1024 GiB | One model weight or tokenizer file that the model collector inspects and hashes; also the artifact `verify-artifact` hashes and the weights `validate --project` hashes again for tensor metadata. | The file is recorded without a hash. |
| `model-total-bytes` | 256 GiB | 16384 GiB | All bytes the model collector reads, weights and model configuration included. | That file is recorded without a hash; later files are hashed only while they fit in what remains. |
| `source-files` | 50 | 100000 | Files containing an MCP SDK reference that the mcp collector parses, counted separately for Python sources, TypeScript server sources, and root-level `.ts` and `.js` client references. Files without a reference are not counted. | The remaining files of that kind are not parsed; the failure names the first one and how many there are. |
| `source-scan-bytes` | 256 MiB | 64 GiB | Python and TypeScript sources, and root-level JavaScript, that the mcp collector reads to find files containing an MCP SDK reference. | The file being read when it runs out is a failure, and the remaining files are not searched; a second failure names the first of them and how many there are. |
| `syntax-bytes` | 256 KiB | 64 MiB | One file containing an MCP SDK reference that the mcp collector parses. | That file is not parsed. |
| `ts-nodes` | 20000 | 10000000 | Syntax nodes in one TypeScript MCP server file. | That file is not collected. |

### Source files the mcp collector searches

Which source files the mcp collector searches is unchanged: Python files outside
directories named `tests`, `test`, `dist` and `build`; TypeScript files outside
`tests`, `test`, `__tests__`, `dist` and `build`, other than `.d.ts`, `.spec.ts`
and `.test.ts` files; and `.ts` and `.js` files at the project root. Each is read
as a stream, in the text the language's own tools read, and only candidates are
parsed:

- A Python file is a candidate when it contains `mcp` or `MCPClient` as Python
  reads it: decoded as its encoding declaration says, with identifiers in the NFKC
  form Python compares them in, so fullwidth or other compatibility letters count.
- A TypeScript server file is a candidate when it contains both
  `@modelcontextprotocol/` and `McpServer`, and a root-level client reference when
  it contains `@modelcontextprotocol/sdk`. A TypeScript or JavaScript file that
  starts with a UTF-16 byte order mark is searched and parsed as UTF-16, as tsc
  and web browsers read it (bun reads only the little-endian form); any other is
  read as UTF-8, as tsc, Node.js and bun read it. That includes UTF-16 without a
  byte order mark, which a web server or page can declare but static reading
  cannot see.

These are failures rather than silent skips:

- A Python file whose encoding declaration names a codec that does not read ASCII
  as ASCII, such as `utf-7`, `unicode_escape`, UTF-16, ISO-2022 or an unknown
  codec, or a name longer than 64 characters, which no codec has. Such a file can
  spell a reference in a form that static reading cannot follow, and Python
  decodes it differently when it is run as a script and when it is imported.
  Single-byte code pages such as `latin-1` and `cp1252`, and the stateless
  multibyte codecs such as `shift_jis` and `gbk`, are followed.
- A Python file that `python -x` reads in another way. That option skips the
  first line through its line feed, so the line after it can declare a codec even
  when the first line is code. A declaration there that is not followed, or a
  different codec under which the rest of the file is valid and names the SDK,
  is the failure `unsupported source encoding declaration`.
- A Python file that is not valid in its encoding (`invalid UTF-8` when it
  declares none).
- A root-level `.ts` or `.js` file without a UTF-16 byte order mark that is not
  valid UTF-8, as in earlier releases (`invalid UTF-8`), and a candidate that is
  not valid in its encoding (`invalid UTF-8` or `invalid UTF-16`). tsc would read
  such a file with replacement characters, but another runtime could decode it
  differently. A TypeScript file below the root that is not a candidate is not
  checked for valid UTF-8, as before.
- A candidate larger than `syntax-bytes`, which is not parsed.
- A source file larger than `file-bytes` that is a candidate, or that is a Python
  file that is not plain ASCII, because its NFKC form cannot be searched without
  holding it.
- A plain ASCII Python file larger than `file-bytes` whose codec is unknown,
  because a line that can declare it starts as a comment and does not end in
  time: the first line, or the second after a blank or comment first line, within
  the first `file-bytes` of the file, or the line after the first line feed, which
  `python -x` reads, within `file-bytes` of that line feed. For example, a first
  line of `# ` and 5 MiB of text fails with the default limits.

Other plain ASCII sources of any size, such as generated protocol buffer modules
or bundles, are searched as a stream and pass.

An import of the Python MCP server SDK spelled only with compatibility characters
is recorded as a gap, because its servers and tools are not collected. Only files
whose parse produced a component, a gap or a failure are listed under
`surfaces_scanned`, so adding an unrelated source file does not change the
inventory.

## Why these defaults

Most defaults are the values earlier releases used. Four changed because
ordinary projects exceeded them:

- `entries` was 20,000. Mid-size monorepos, and working trees with tool caches
  such as `.tox`, `.nox` or a vendored `site-packages`, have more files and
  directories than that.
- `model-bytes` was 5 GiB, and tokenizer files were held to `file-bytes`.
  Single-file quantized checkpoints, such as GGUF files of 7 to 40 GB, are
  common, as are `tokenizer.json` files above 4 MiB. Tokenizers are now hashed as
  streamed model files.
- `model-total-bytes` was 5 GiB plus 32 MiB. A sharded checkpoint of four
  5 GB shards exceeded it; a 70-billion-parameter model in 16-bit weights is about
  141 GB.
- The mcp collector used to count every Python file outside `tests`, `test`,
  `dist` and `build`, every TypeScript file, and every root-level `.ts` and `.js`
  file toward fixed limits of 50, 50, 10 and 10, before looking at their content,
  so most medium-sized projects failed. It now counts only candidates, under
  `source-files`.

Hashing a 256 GiB model directory takes several minutes; keep a job timeout, as
the [README](../README.md) recommends.

## Fixed bounds

These bounds protect a format or the inventory rather than size a project, so
they are not operator settings. Reaching one is also a scan failure or a refusal
that names the file, except the listing bound in the first row, which only
shortens a list of failures that are recorded anyway.

| Bound | Value |
|---|---|
| Failures one collector lists from its walks, and from the mcp collector's source search, before one line for each reason sums up the rest | 1,000 lines or 65,536 characters |
| Codec name in a Python encoding declaration | 64 characters |
| MCP tool registrations in one TypeScript file | 1,000 |
| TypeScript native parse time per file | 250 ms, in proportion to `syntax-bytes` above its default |
| TypeScript analysis time per file | 2 s, in proportion to `ts-nodes` above its default |
| Native inventories and ShadowScan reports read by any command | 16 MiB |
| `agent.yaml` and `.nexus-symbiote.yaml` | 1 MiB each |
| Operator signature policy | 4 MiB |
| Model artifact named in an operator signature policy | 5 GiB |
| Sigstore bundle named in an operator signature policy | 4 MiB |
| Root `requirements*.txt` files, together | 4 MiB |

Some collectors apply further per-file bounds to the formats they parse, such as
JSON nesting, YAML token counts and A2A card entries; each is reported as a
failure or gap on the file that reached it. A signature policy entry over either
signature bound is refused with "Policy artifact or bundle is unavailable beneath
the project root", which does not yet name the bound; a model artifact above
5 GiB can be hashed under `model-bytes` but cannot be signer-verified.
