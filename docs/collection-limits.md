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
native inventory, and `validate` prints them.

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
| `file-bytes` | 4 MiB | 1 GiB | One file a collector reads into memory: configuration, manifests, lockfiles, instruction files and source searched for MCP SDK references. | The file is not read. |
| `total-bytes` | 32 MiB | 64 GiB | All bytes one collector reads, apart from model files and the mcp collector's source search, which have their own budgets below. Each collector has its own budget. | The file that would pass it is not read, nor are later ones. |
| `entries` | 100000 | 10000000 | Files and directories one collector lists while it walks the project. Directories named `.git`, `node_modules`, `__pycache__`, `.venv` or `venv`, and paths excluded by policy, count as one entry each and are not listed. | The directory being listed, and everything after it, is not walked. |
| `depth` | 32 | 256 | Directory nesting below the walk's starting directory. | That directory and everything beneath it are not walked. |
| `model-bytes` | 64 GiB | 1024 GiB | One model weight or tokenizer file that the model collector inspects and hashes; also the artifact `verify-artifact` hashes and the weights `validate --project` hashes again for tensor metadata. | The file is recorded without a hash. |
| `model-total-bytes` | 256 GiB | 16384 GiB | All bytes the model collector reads, weights and model configuration included. | The file that would pass it is recorded without a hash, as are later ones. |
| `source-files` | 50 | 100000 | Files containing an MCP SDK reference that the mcp collector parses, counted separately for Python sources, TypeScript server sources, and root-level `.ts` and `.js` client references. Files without a reference are not counted. | The remaining files of that kind are not parsed; the failure names the first one and how many there are. |
| `source-scan-bytes` | 256 MiB | 64 GiB | Python and TypeScript sources, and root-level JavaScript, that the mcp collector reads to find files containing an MCP SDK reference. | The remaining files are not searched; the failure names the first one and how many there are. |
| `syntax-bytes` | 256 KiB | 64 MiB | One file containing an MCP SDK reference that the mcp collector parses. | That file is not parsed. |
| `ts-nodes` | 20000 | 10000000 | Syntax nodes in one TypeScript MCP server file. | That file is not collected. |

Which source files the mcp collector searches is unchanged: Python files outside
directories named `tests`, `test`, `dist` and `build`; TypeScript files outside
`tests`, `test`, `__tests__`, `dist` and `build`, other than `.d.ts`, `.spec.ts`
and `.test.ts` files; and `.ts` and `.js` files at the project root. A Python file
is a candidate when it contains `mcp` or `MCPClient`, also after the NFKC folding
Python applies to identifiers; a TypeScript server file when it contains both
`@modelcontextprotocol/` and `McpServer`; a root-level client reference when it
contains `@modelcontextprotocol/sdk`. A non-UTF-8 Python file without an ASCII
marker is a failure, because Python could decode it to a reference under a coding
declaration, and so is a source file larger than `file-bytes`, which is not read.
Only candidates are parsed and only files whose parse produced a component, a gap
or a failure are listed under `surfaces_scanned`, so adding an unrelated source
file does not change the inventory.

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

These bounds protect a format rather than size a project, so they are not
operator settings. Reaching one is also a scan failure or a refusal that names
the file.

| Bound | Value |
|---|---|
| MCP tool registrations in one TypeScript file | 1,000 |
| TypeScript native parse time per file | 250 ms, in proportion to `syntax-bytes` above its default |
| TypeScript analysis time per file | 2 s, in proportion to `ts-nodes` above its default |
| Native inventories and ShadowScan reports read by any command | 16 MiB |
| `agent.yaml` and `.nexus-symbiote.yaml` | 1 MiB each |
| Operator signature policy | 4 MiB |
| Root `requirements*.txt` files, together | 4 MiB |

Some collectors apply further per-file bounds to the formats they parse, such as
JSON nesting, YAML token counts and A2A card entries; each is reported as a
failure or gap on the file that reached it.
