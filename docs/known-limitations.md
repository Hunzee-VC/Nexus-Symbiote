# Known limitations

This page lists what Nexus SymBiote does not collect, compare or verify, by surface,
and what to do about each limit. For how findings are classified, such as why a
`.bin` file is critical or which characters count as hidden, see
[known false-positive and false-negative classes](security-model.md#known-false-positive-and-false-negative-classes).
The list that shipped with 0.1.0 is in
[its security policy](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/v0.1.0/SECURITY.md#known-limitations-in-010).

For the collectors, each limit has one of three effects on a gate:

- **Not recorded.** No collector reads it. Coverage stays complete, so `validate`,
  `risk` and `diff --fail-on-alert` pass when it changes. Review such changes by
  other means.
- **Gap.** A collector recognizes the input but cannot collect it. Coverage is
  partial, and `scan`, `validate` and `risk` fail by default.
- **Failure.** Collection stopped. The collector's status is `failed`, and the same
  gates fail.

A way around a limit that its entry does not describe is worth a
[private report](../SECURITY.md#reporting-a-vulnerability).

- [Every collector](#every-collector)
- [MCP servers and tools](#mcp-servers-and-tools)
- [Models](#models)
- [Instructions and IDE settings](#instructions-and-ide-settings)
- [Registry and containers](#registry-and-containers)
- [A2A and RAG](#a2a-and-rag)
- [ShadowScan](#shadowscan)
- [Signatures](#signatures)
- [Attestations](#attestations)
- [Exports](#exports)
- [Gates and drift](#gates-and-drift)
- [Trace evidence](#trace-evidence)
- [Graph view](#graph-view)
- [G7 minimum elements](#g7-minimum-elements)
- [Live mode](#live-mode)
- [Runtime gateway](#runtime-gateway)
- [GitHub Action](#github-action)
- [Resource use](#resource-use)

## Every collector

- **Collection limits fail closed.** Reaching a [collection limit](collection-limits.md)
  is a failure that names the limit and the path. Only the operator can raise one,
  with `--limit NAME=VALUE` before the command, `NEXUS_SYMBIOTE_LIMITS`, or the
  Action's `limits` input; nothing in the checkout can. Use the same limits for
  `scan` and for a later `validate --project` or `risk --project`, which collect
  the project again.
- **Source search is bounded.** The mcp, a2a and rag collectors each read at most
  `source-scan-bytes` (64 MiB by default) of source text. Past that, one failure
  names the first file not read in full, and nothing after it is searched. Raise
  the limit for such a project.
- **Exclusions are gaps.** A path you exclude with `scan.exclude_paths` is recorded
  as a coverage gap, so excluding a file that fails collection turns the failure
  into a gap; the default gates still fail.
- **Default exclusions match by name.** Any path component named `.git`,
  `node_modules`, `__pycache__`, `.venv` or `venv` is skipped, and so is one whose
  name differs from these only by case, Unicode normalization, ignored format
  characters or trailing dots and spaces, such as `Venv` or `NODE_MODULES`, which
  case-insensitive file systems treat as the same name. These defaults are
  listed under `exclusions` in the inventory but are not a gap, except inside a
  directory whose every file the `prompt` collector reads, such as a skill, command,
  rule or subagent directory. There such an entry, such as `.claude/skills/venv`,
  `.claude/skills/Venv` or `.claude/agents/node_modules`, is a coverage gap that
  names it, so the default gates fail. A skill checked out with its own `.git`,
  including a Git submodule, whose `.git` is a file, or one whose script left a
  `__pycache__` beside it, fails them until that entry is removed.
- **Case variants.** When a fixed path such as `CLAUDE.md`, `.mcp.json`,
  `.claude/settings.json` or a model directory's configuration, tokenizer or chat
  template file or `additional_chat_templates` directory is absent, a file or
  directory whose name differs only by case or Unicode normalization is a failure,
  because case-insensitive file systems open
  it. When both exist, only the exact name is read, except for instruction files:
  another spelling of a fixed instruction path, such as `claude.md` beside
  `CLAUDE.md`, and of `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` or `.cursorrules` below
  the root, such as `pkg/claude.md`, is a failure even beside the exact name, as are
  those of nested `.claude/settings.json` files, because a case-insensitive checkout
  holds one file for both names. `CODEX.md` and `codex.md` are both read. A spelling
  that a subagent, rule, prompt, skill or command directory walk inventories, such
  as `.claude/agents/gemini.md`, is read there instead. Rename any other such file,
  including a documentation page such as `docs/agents.md`, which case-insensitive
  file systems open as `docs/AGENTS.md`. More than 16 such names in one directory,
  or a search beyond the `entries` limit, is a failure.
- **Symlinks.** A relative symlink to a regular file or directory in the project,
  not excluded, within the `depth` limit and reached without another symlink, is
  read through its target. A read through any other symlink, such as an absolute
  one or `.claude -> .`, is a failure. A walk of the project skips directory
  symlinks and walks their targets under the targets' own names.
- **Every walk fails on a link out of the project.** An absolute or escaping
  symlink anywhere in the tree, such as `assets/logo.png -> /usr/share/logo.png`,
  is a failure for each collector that walks the project (`mcp`, `model`,
  `prompt`, `rag`, `a2a` and `ide_agents`), whatever its name. Such a link may name
  a directory, and each of them reads names at any depth below directories of any
  name; telling a file from a directory would mean following the link out of the
  project, and the answer would hold only on the machine that scans, not on one
  that later opens the checkout. Replace the link with the file, or with a relative
  link inside the project.
- **Hard links are ordinary files.** A hard-linked file inside the root is read like
  any other, so an inventory can describe a file that also has a name outside the
  root. See [security boundaries](../SECURITY.md#security-boundaries).

## MCP servers and tools

- **Launcher classification covers named shapes.** The collector classifies `npx`,
  `npm`, `pnpm`, `yarn`, `bun`, `bunx`, `uv`, `uvx`, `pipx`, `docker`, `podman`,
  `nerdctl`, `deno` and `go`, also behind `env`, a shell with `-c`, `cmd /c`,
  `powershell` or `pwsh`, `wsl`, `exec`, `nohup`, and `op`, `doppler`,
  `infisical`, `dotenvx`, `aws-vault` or `with-secrets` with `--`. Any other
  command is recorded as a local program by its basename, without a gap, unless it
  is one of the runners or launches below that are gaps.
- **What a local program or project script runs is not read.** `./start.sh`,
  `make serve`, `npm run mcp`, `uv run server.py` or a program that installs
  packages can start an unpinned package the inventory does not show. Review what
  such commands run.
- **Unclassified runners are gaps.** `dnx`, `jbang`, `pip-run`, `nix run`,
  `dotnet tool`, `gem exec`, `pixi exec`, `corepack`, `mise`, `pkgx`, `finch`,
  Apple `container` and `apptainer` are a high `launcher_identity` finding and a
  gap, and so are package installs (`pip install`, also as `pip3.12` and after any
  run of options, `python -m pip install`, `gem install` or `gem i`, `cargo install`,
  `conda` or `mamba install`), `uv run` of a URL or
  of standard input, and a package from git without a full commit, from a URL or
  from a local path.
- **Inline code and nested launches are gaps.** Inline interpreter code such as
  `node -e` or `python -c`, and arguments that start a runner, shell or wrapper,
  such as `sudo npx ...`, are a high `launcher_identity` finding and a gap. The
  argument check is a heuristic: it reads each argument as written and as a shell
  or `cmd` may rewrite it (quoting removed, `@` prefixes dropped, expansions empty
  or at their default, brace lists expanded, patterns matched against runner
  names), but it can miss a launch in a form it does not know, and a prose
  argument that only reads like a launch is a gap too.
- **Text a shell reads again must read as written.** An `sh -c`, `bash -c`,
  `zsh -c` or `fish -c` script, a command line, `env -S`, `wsl` without `-e`,
  `eval` and `pwsh -Command` are classified only when no word holds a character the
  reader rewrites: braces, patterns, `~`, `#`, `!`, `^`, `$`, backquotes,
  non-ASCII text or, except for a POSIX shell, quoting. `cmd /c` needs a plain
  program word and no `%`, `!`, `"`, `^` or unusual whitespace; cmd keeps
  backslashes and single quotes, so `'npx'` is a gap and `n\px` is a program `px`
  in directory `n`. Anything else is an
  inline shell script: a gap. So `sh -c "npx -y pkg@1.2.3 $HOME/data"` is a gap;
  pass such values as separate arguments or through `env`.
- **Shell startup code is a gap.** bash sources a `--rcfile` or `--init-file`
  (also spelled `-rcfile`) when it is interactive or its standard input is a socket,
  as MCP clients provide; it imports exported functions (`BASH_FUNC_<name>%%` and its
  variants) from the environment; a non-interactive bash sources `BASH_ENV` and an
  interactive POSIX shell (`-i` or `-o interactive`) `ENV`; a shell tracing its
  commands (`-x`, `-o xtrace`, zsh's `--xtrace` or `xtrace` in `SHELLOPTS`) expands
  `PS4` before each one. Each runs code before the script that can replace the runner
  it names. A startup-file option or an exported function makes the launcher unknown,
  and so does a `PS4` with an expansion while tracing is on; `BASH_ENV`, and `ENV` for
  an interactive shell, do when the file may lie in the project: a path that is not
  absolute, has a `..` segment, or lies under `/proc` or `/dev/fd`. An absolute
  `BASH_ENV`, `ENV` for a shell that is not interactive, and `SHELLOPTS`, `BASHOPTS`
  or `PS4` otherwise stay a medium code-loading finding; an absolute path that happens
  to lead into the checkout through another link is not recognized.
- **A runner named by a path is classified by its name.** `./tools/npx`,
  `${workspaceFolder}/tools/npx` or a `PATH` entry in the project can run checkout
  code that the record attributes to the registry package. On Windows, an
  `npx.cmd` or `npx.exe` committed at the launch directory is found before the
  installed one. Review runner commands that are not bare names or absolute
  system paths.
- **Some ordinary forms are gaps.** `uvx -w` and `uv run -w` (aliases of `--with`)
  and a bare `pwsh server.ps1` are not read and fail the gates; spell `--with` and
  `-File`.
- **Environment that moves a runner's configuration is a gap.** A server's `env`
  that may point `HOME`, `XDG_CONFIG_HOME`, `PREFIX`, `DESTDIR`, `GOENV`,
  `ZDOTDIR` or a relative `PATH` entry into the project, or that replaces the
  package (`UV_OVERRIDE`, `UV_CONSTRAINT`, `PIP_CONSTRAINT`), makes the identity
  unknown. Other locations and the runner's own namespace (`UV_*`, `PIP_*`,
  `YARN_*`, `BUN_*`, `DOCKER_*` and similar) are a medium `package_source`
  finding, and the package URL is withheld. Configuration names that look like
  tokens or hold one after a prefix (`AWS_AKIA...`) are exported as `[redacted]`,
  and a launcher package whose name or specifier looks like a token is withheld
  (`[withheld]`, no package URL) with a medium `completeness` finding.
- **Changed values need the binding key.** Launch arguments, environment and header
  values are exported only as redacted positions and names, and endpoint and
  package index URLs as origins. With `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, `diff`
  alerts on any change to a server's command, arguments, environment or header
  values. Without it, `diff` alerts on a changed command basename, launcher,
  package or version, and on added or removed arguments, variables or headers; see
  [source binding](verification-source-binding.md).
- **Without the key, changed values pass.** A served directory widened from
  `./notes` to `/`, a changed flag, environment or header value, an endpoint or
  index path changed on the same host, a project resolver setting value, and the
  directory of a command raise no alert.
- **Unbound values add to the score.** Each server with such values carries a low
  `completeness` risk that names the key. It is not a gap, but it adds 1 to the
  risk score, so about ten such servers add 10 points toward the default fail
  threshold of 50.
- **Resolver settings outside the root are not read.** Settings are read from the
  root `.npmrc`, `bunfig.toml`, `.yarnrc.yml`, `.yarnrc`, `.env.yarn`, `uv.toml`
  and the `[tool.uv]` table of `pyproject.toml`. User and global configuration,
  parent directories, `pnpm-workspace.yaml` settings and corepack's
  `packageManager` field are not. For runners that read project resolver files, a
  server that runs in another working directory, or that a configuration file below
  the root declares, has its package identity withheld
  (`working-directory=[unresolved]`) and a medium `package_source` risk.
- **Injected environments are not visible.** Variables from an `envFile`, or from
  `dotenvx`, `doppler`, `infisical` or `op run --env-file`, are not read. A launched
  package then carries `environment-file=[unresolved]` instead of its identity.
- **A local `node_modules` can stand in for a pinned package.** `npx` and
  `npm exec` run a matching package already installed in the project's
  `node_modules`, which the collector does not read. A committed
  `node_modules/<name>` that claims the pinned version runs under the pinned
  identity.
- **Servers started from code are gaps, not records.** Application code that starts
  or reaches a server leaves no component for it, only a gap that fails the default
  gates: in Python, `StdioServerParameters`, `sse_client`, `streamablehttp_client` and
  `websocket_client` of the MCP SDK, `MCPServerStdio`, `MCPServerSse` and
  `MCPServerStreamableHttp` of the OpenAI Agents SDK, `MCPServerStdio`,
  `MCPServerSSE`, `MCPServerHTTP` and `MCPServerStreamableHTTP` of PydanticAI, and
  LangChain's `MultiServerMCPClient`, used outside an annotation; a class among
  them also as an attribute of any value, such as a module a parameter or another
  name holds, and a function as an attribute of any name the file imports; in
  TypeScript and
  JavaScript, the SDK's `StdioClientTransport`, `SSEClientTransport`,
  `StreamableHTTPClientTransport` and `WebSocketClientTransport`. A Python file that
  imports one of these by name from its package and does not use it outside an
  annotation is a gap too, because another module can import it from that file,
  as from a package `__init__.py` that re-exports it. A Python file that imports
  one by name from any other module, its own project's included, or uses its name
  after a star import of another module, is a gap whether or not it uses it, so a
  local class of the same name is a gap too. These names are searched for, so such
  a file is read even when it does not name `mcp`. The command, its
  package and pin are not inventoried even when they are literal; declare such a
  server in a client file to have it inventoried. A launcher reached only through
  `getattr`, `globals()` or code in a string, a launcher function such as
  `sse_client` reached as an attribute of a value the file did not import, a star
  import of its package that a file passes on without using a launcher, and the
  clients of other frameworks,
  leave no gap; the collector records some of those only as a code-detected client.
  User-level client settings in your home directory are not read either.
- **Some client files are only detected.** Zed `context_servers`, opencode `mcp`,
  `.continue/mcpServers/` and `.junie/mcp/mcp.json` are gaps; their servers are not
  parsed.
- **Every file with an MCP client name is parsed.** One that does not parse, or
  whose server map is not a map of server objects, is a failure even when it is not
  an MCP configuration. Rename such a file; excluding it records a gap instead.
- **Python server forms.** Servers are collected from `FastMCP` imported by name
  from `mcp.server`, `mcp.server.fastmcp`, `mcp.server.fastmcp.server`, `fastmcp`,
  `fastmcp.server` or `fastmcp.server.server`, and from `MCPServer` imported from
  `mcp.server.mcpserver`. Forms the collector recognizes but cannot follow are
  gaps: the low-level `Server`, a constructor given `tools=` or `**` arguments, a
  server passed to a helper, an aliased or subclassed factory,
  `FastMCP.from_openapi`, decorators on a server imported from another module, a
  qualified, module-alias or star import, an import spelled only with
  compatibility characters, a server class imported by name and not used
  outside an annotation, which another module can import from that file, a
  `FastMCP` or `MCPServer` imported by name from any other module, another
  submodule of `mcp` or `fastmcp` and its own project's included, or used by its
  name after a star import of one, whether or not it is used, and a `FastMCP` or
  `MCPServer` attribute of any value. `MCPServer` imported from `agents.mcp` or
  `pydantic_ai.mcp`, a client base class there, is not a gap. So a
  server built from a class a project module re-exports is a gap on the file that
  builds it, even when the re-exporting module's own server is inventoried. Any
  call whose first argument, or `name` keyword, is a literal that names `mcp`,
  `mcp.server` or `fastmcp`, or a submodule of the last two, is a gap whatever the
  callee, so a loader passed as an argument, bound by a `match` capture, read from
  a container or returned by a function is covered, and so is one that names a
  client module: `mcp.client`, `agents.mcp`, `pydantic_ai.mcp`,
  `langchain_mcp_adapters` or a submodule. The literal may be in any argument
  position, a keyword or an element of a list, tuple, set or dict argument, also
  behind `*` or `**`, so `functools.partial`, `map` and a thread target's `args` or
  `kwargs` are covered too. A call to another
  function with such a literal is a gap as well, except `logging.getLogger` and a
  server class imported from its own module, such as `FastMCP("mcp")`. A literal is a string or an
  f-string without placeholders. A dynamic import (`importlib.import_module`,
  `__import__` or `pkgutil.resolve_name`, or a name bound to one of them by an
  assignment, an unpacking, a `for`, comprehension or `with ... as` target, an
  import alias or a parameter default) counts on any literal argument, and a
  relative name counts once resolved against a literal package or `__import__`
  globals. A module name computed at run time, a relative name given to a loader
  no such binding shows, and a loader reached through `getattr`, `globals()` or
  code in a string are not followed and leave no gap.
- **Python files without a reference are not examined.** A file that names neither
  `mcp`, a supported agent framework nor an MCP launcher or server class is not parsed.
- **Unusual source encodings fail.** A Python file whose encoding declaration names
  an unknown codec, or one that does not read ASCII as ASCII, such as `utf-7` or
  UTF-16, is a failure. TypeScript and JavaScript files are read as UTF-8 unless
  they start with a UTF-16 byte order mark, as tsc reads them, so a server written
  in UTF-16 without one is not found and leaves no gap.
  See [source files the mcp collector searches](collection-limits.md#source-files-the-mcp-collector-searches).
- **TypeScript and JavaScript server forms.** Servers in `.ts`, `.mts`, `.cts`,
  `.tsx`, `.js`, `.mjs`, `.cjs` and `.jsx` files are collected when `McpServer` is
  imported from a known SDK module by name or through a namespace import; see
  [TypeScript inventory](typescript-inventory.md). In a parsed file, these uses of
  the SDK are gaps: `require`, a dynamic import, also of a module name the analysis
  cannot read, a re-export, another module path or specifier form (`npm:`, a URL, a
  version, a path into `node_modules`), a default import, the low-level `Server`
  and a use of the class other than constructing it. A JavaScript file the
  TypeScript grammar cannot parse is a gap, not a failure. These leave no gap: the
  SDK reached through an alias resolved outside the file,
  such as a `#` subpath import, tsconfig `paths` or an import map; a file that spells
  the SDK only with escape sequences or percent-encoding; a module loader reached
  through an alias or `Reflect.apply`; uses of a collected server other than a
  literal `tool` or `registerTool` call, such as `server.server`, a wrapped
  `registerTool` or the server passed to code in a file that does not name the SDK,
  which can register tools the inventory does not show; and servers built with
  other frameworks.
- **Some directories are skipped.** Server source under directories named `build`,
  `dist`, `test`, `tests`, `docs`, `benchmarks` or `examples`, and `__tests__` for
  TypeScript and JavaScript, is skipped without a gap, and so are TypeScript
  declaration files and scripts named like `server.test.mjs` or `server.spec.ts`.
- **Framework tools are collected by decorator only.** Module-level functions
  decorated with `@tool` (LangChain, CrewAI, smolagents), `@function_tool` (OpenAI
  Agents SDK) or PydanticAI's `@agent.tool` are collected by name; the descriptor is
  not. A decorated function that is not at module level, a rebound decorator, a
  qualified import and a star import are gaps. So is a PydanticAI agent given `tools=`,
  `toolsets=`, `builtin_tools=`, `mcp_servers=` or `*` or `**` arguments, or used
  other than through an attribute or a `with` statement, such as passed to a
  function or held in a list. Each agent's tools are named per agent, so two agents
  of a file can each have a tool of the same name. Class-based tools, such as
  `BaseTool` subclasses and `StructuredTool.from_function`, are neither collected
  nor reported.
- **Tool definitions are fingerprinted only when declared or observed.** A static
  scan fingerprints the tools in a server's `tools` array, a Nexus SymBiote
  convention that MCP clients do not write. Tools in server source are recorded by
  name with a digest of the declaring file; handlers imported from other modules
  are not covered. Observe the effective tools with `discover-mcp` or
  `verify-live`.
- **Tool digests are unkeyed.** A tool's `definition_hash` covers the declared
  descriptor, including text the exported descriptor omits, so anyone holding the
  inventory can confirm a guess of a low-entropy value withheld there.
- **Loopback endpoints raise no finding.** An MCP server declared with a `url` on
  `localhost` or a loopback address over plain `http`, and no `command`, is recorded
  without a transport or local-program finding: the endpoint is treated as secure
  because it does not leave the host, and nothing records which process serves it.
  Review such servers by other means.

## Models

- **OpenSSF Model Signing is not verified.** A DSSE bundle named in a signature
  policy fails verification. Pin each weight file's SHA-256, or sign each file with
  a Sigstore message signature, in the
  [operator signature policy](model-integrity.md#operator-signature-policy).
- **A signer can substitute its own artifacts.** A Sigstore entry without
  `expected_sha256` accepts any artifact its identity signed, such as an older
  release. Set `expected_sha256` when that matters.
- **Files above 5 GiB cannot be verified.** A signature policy that names a larger
  file, by digest pin or signature, is refused with "Policy artifact or bundle is
  unavailable beneath the project root". Such files are still hashed, up to the
  `model-bytes` limit.
- **Some formats are not inspected.** ONNX, GGUF, GGML, Keras, HDF5, SavedModel,
  TFLite, Core ML and ExecuTorch files are rated `unknown`: Keras Lambda layers,
  SavedModel operations and custom operators are not inspected. Each is a high
  finding, which the default gate does not fail on by severity alone.
- **Some files are not inventoried.** A file outside the
  [listed names](model-integrity.md#model-files-and-references) is inventoried by
  its content only when it is named `.npy`, `.npz` or `.dat` or has any name below a
  directory named `model`, `models`, `weights`, `checkpoint` or `checkpoints`, and it
  is not a model directory's configuration, tokenizer or chat template file or a
  Python or Jinja source. There, a recognized pickle, a NumPy array with an object
  dtype (which `np.load(allow_pickle=True)` unpickles) and a ZIP archive with a
  pickle-family member or such an array as a member are rated
  `unsafe-code-execution`, and a NumPy header or ZIP archive left unread at the
  bounds below is rated `unknown`. A pickle renamed anywhere else, an unrecognized
  pickle, a numeric NumPy array, a ZIP archive with neither kind of member, and `.pb`
  files other than `saved_model.pb` produce no component. A candidate ZIP archive is
  read to its end and digested, as a model archive is, and a candidate larger than
  the `model-bytes` limit is a collection failure.
- **Content recognition is bounded.** A binary pickle is recognized by its PROTO
  opcode and 16 well-formed opcodes in the first 64 KiB, and a text-protocol pickle
  by a consistent stream of at most 4,096 opcodes. A NumPy array's version 1, 2 or 3
  header is parsed when it is at most 64 KiB long, as every version 1 header is, and
  only its `descr` value is read for types, so a field named `O` is not one. A ZIP
  archive is recognized by a pickle-family member in its first local header or in a
  central directory of at most 1 MiB, read from the end of the archive, including
  ZIP64, and by an object-dtype array as any member, read from the member's local
  header and the start of its stored or DEFLATE-compressed data. A longer array
  header, a longer or malformed directory, a member compressed by another method,
  such as BZIP2 or LZMA, and a member whose data runs past the next member's local
  header are rated `unknown`, a high finding; a pickle hidden otherwise under
  `.onnx`, `.gguf` or another suffix is rated `unknown` too, and
  `validate --project` still refuses it as unverified.
- **Templates and tensors are checked shallowly.** GGUF and Hugging Face chat
  templates are checked for potential Python-internals access patterns, not evaluated;
  computed names can evade the heuristic, and a match does not establish a sandbox
  escape or execution. A template file larger
  than the `file-bytes` limit is digested but not checked, and is a coverage gap.
  SafeTensors tensor bytes are hashed but not inspected. See
  [what this does not establish](model-integrity.md#what-this-does-not-establish).

## Instructions and IDE settings

- **Instruction files under other names are not recorded.** The `prompt` collector
  reads the fixed files the [collector reference lists](collectors.md#what-each-collector-reads),
  `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` and `.cursorrules` in any subdirectory, and
  every file in the rule, prompt and subagent directories. Another spelling of a
  nested name, such as `claude.md` in a subdirectory, is a
  [failure](#every-collector), not a file that is read, unless one of those
  directories, or a skill or command directory, holds it. `CLAUDE.local.md`,
  `AGENTS.override.md`, `.clinerules` or `.windsurfrules` below the root, and other
  hosts' conventions, are neither inventoried nor checked for hidden characters.
  List such files in an [`agent.yaml`](agent-manifest.md).
- **Imports are followed from memory files.** `@path` imports are followed to five
  hops from the root `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md` and
  `GEMINI.md`, from every `CLAUDE.md` and `GEMINI.md` below the root, and from another
  spelling of either that a subagent, rule, prompt, skill or command directory holds,
  resolved from that file's directory. The imports of other instruction files, such
  as `AGENTS.md` or a rule file, are followed only when a memory file imports them.
  Imports are read from the text outside fenced code and code spans as CommonMark
  reads it, across lines and inside block quotes and list items. Where CommonMark
  readers disagree, as after a link reference definition or inside raw HTML, the
  text is searched as written, so more is looked up; a host that reads Markdown
  otherwise, such as with GitHub's table or autolink extensions, can still import a
  file from text read here as code.
  An import that leaves the project root, names an excluded path or lies deeper than
  the `depth` limit is a gap, so write a path alias such as `@/components` as code. A
  project with more than the [`import-lookups`](collection-limits.md#limits) limit of
  memory files and import targets fails until the limit is raised. Past 262,144
  characters of listed paths, an `imports` list is replaced by `imports_count` and
  `imports_digest`, and an `imported_by` list by `imported_by_count`; every file is
  still inventoried.
- **Fixtures count.** A nested `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` or `.cursorrules`
  in test fixtures or vendored code is inventoried, and its findings count, like any
  other.
- **Skill front matter is not interpreted.** Every file in the skill and command
  directories is bound by digest, but settings such as `allowed-tools` are not
  read. A skill declaration (`.md`, `.mdc`, `.markdown`, `.txt`, `.yaml`, `.yml`,
  `.json`, `.toml`) above the `file-bytes` limit is a failure; a larger script or
  other resource is streamed and digested.
- **Binary skill resources are checked only for runs and clusters of hidden
  characters.** A skill or command resource that is not UTF-8 is checked as an
  agent's reader decodes it: as UTF-16 or UTF-32 after that byte-order mark,
  otherwise as UTF-8 with U+FFFD for each invalid sequence. When such a file also
  holds a NUL byte and no byte-order mark, it is treated as binary, such as an image,
  and only runs of four or more hidden characters are reported, together with every
  plane-14 character (U+E0000 to U+E0FFF: tag characters, the variation selector
  supplement and the unassigned ones) once 16 of them lie within 4,096 characters,
  whatever separates them. Random bytes form a plane-14 character about once per MiB,
  so a count over the whole file would report large binaries. Not reported in such a
  file: hidden characters outside plane 14 that are not in a run of four, such as
  zero-width or bidirectional characters each separated by another byte, plane-14
  characters spread so that no 4,096 characters hold 16 of them, and a UTF-16 or
  UTF-32 file without a byte-order mark.
- **Hidden-character detection is character-based.** Lookalike letters are not
  detected, and neither are control characters such as ESC, spaces other than
  U+0020, such as U+00A0 and U+3000, or private-use characters. HTML and Markdown
  comments are reported by count, not text, and only in Markdown files and
  instruction files without a suffix, such as `.cursorrules`.
- **Settings alerts do not say what changed.** Rules, hook commands and other
  settings are bound by a digest of each settings file, not recorded. A changed
  value, such as an added hook command or a removed deny rule, raises a high
  `properties.settings_hashes changed` alert that names the agent, not the setting.
- **Effective permissions are not resolved.** User and managed settings, workspace
  trust and session flags are not read, and deny and ask rules are counted, not
  applied to the allow list. A Claude Code allow rule whose command word is a shell,
  an interpreter or a launcher and that contains a wildcard, such as `Bash(sh:*)`,
  `Bash(python3 -c:*)` or `Bash(sudo:*)`, is conservatively reported as an unscoped
  shell grant. This heuristic also flags a fixed script with wildcard arguments,
  such as `Bash(python3 scripts/report.py:*)`; it does not establish that every
  matching rule permits arbitrary commands. A rule that names another program, such as
  `Bash(npm run build:*)`, is read as scoped even where that program runs project code.
- **Settings digests can confirm guesses.** Without
  `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, the digests of the Claude Code settings,
  plugin manifests and plugin hooks, the Gemini CLI, Windsurf and Cline settings,
  `.cursor/settings.json`, `.cursor/hooks.json` and `.codex/config.json` cover the
  file as read, including the environment values of the MCP servers that
  `.gemini/settings.json` declares, which the `mcp` records bind only with the key,
  so anyone holding the inventory can confirm a guess of a whole file. With the key,
  and for the other settings files without it, a value the redaction leaves in
  place, such as a password pasted into a hook command, can still be confirmed. Keep
  credentials out of settings files; see
  [IDE agent settings](verification-source-binding.md#ide-agent-settings).
- **Some settings changes alert only with the key.** `.codex/config.toml`,
  `.cursor/cli.json` and the Antigravity, xAI and Copilot settings files are
  digested after the redaction, so that their digests cannot confirm a guess either.
  Without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, a change only to a value the
  redaction removes, such as an MCP server's environment value, a token, the value
  of an `Authorization`, `Cookie` or credential-named key such as `password` or
  `X-Api-Key`, or a URL path, query or userinfo on the same host in a `notify`
  command, raises no alert;
  such a record carries a low `completeness` finding. The redaction ends a URL or
  an assigned value at a shell operator (`;`, `|`, `&`, `$`, `` ` ``, parentheses,
  braces, `<`, `>` or a line break), and starts a new URL at each later scheme
  such as `https://`, so a command or operator glued to one without whitespace, and
  a host glued to one after an operator or a scheme, as in
  `--webhooks=https://a.example/n,https://b.example`, do alert. Other text glued
  to a URL without an operator or another scheme stays part of its redacted path;
  without the key a URL whose authority
  parsers read differently, such as one with a backslash, is a failure.
- **Codex settings are interpreted in part.** `.codex/config.toml` is digested
  whole after the redaction, so a new `notify` command or another changed setting
  raises an alert, unless only a value the redaction removes changed and the scans
  ran without the key (see the previous entry). Only `approval_policy`,
  `sandbox_mode` and the `mcp_servers` table are interpreted. A value that the
  digest or the keyed binding covers and that RFC 8785 JSON cannot represent, such
  as a TOML date or time, `nan`, `inf` or an integer of magnitude 2^53 or more, is a
  failure.
- **Other IDE agents' settings are digested, not interpreted.** For Cursor, Windsurf
  and Cline, a permission mode is read only from an `agent.permissionMode` key in
  their settings files, a convention their vendors do not document; for Codex, from
  that key in `.codex/config.json` or from `approval_policy`. No mode is read for
  Copilot, Gemini CLI, Antigravity or xAI. Files such as `.cursor/cli.json`,
  `.antigravity/settings.json`, `.xai/config.json` and
  `.github/copilot-extensions.json` are digested after the redaction, as
  `.codex/config.toml` is, so a changed setting raises the same high alert, but their
  permissions are not read: widening the Cursor CLI allow list from `Shell(ls)` to
  `Shell(*)` adds no finding.
- **Other settings files are not recorded.** A file the `ide_agents` collector does
  not recognize, such as `.vscode/settings.json`, or a host's user or managed
  settings outside the project, is neither digested nor a gap, so a change to it
  passes every gate.

## Registry and containers

- **Only catalog packages are inventoried.** The `registry` collector records the
  packages and images in its [AI package catalog](registry-collector.md#ai-package-catalog).
  Any other dependency, including a look-alike of a listed name, produces no
  component and no finding. It is not a full SBOM and does not detect typosquats.
- **Several manifests are not read.** Requirements files in subdirectories,
  `setup.py`, `setup.cfg`, dynamic dependencies, conda `environment.yml`,
  Kubernetes manifests, Helm charts, `.devcontainer` configuration and
  `docker buildx bake` files are not read and leave no gap.
  [Not read](registry-collector.md#not-read) lists them all.
- **Registry redirects are read from the project root only.** The
  [registry and index settings](registry-collector.md#registry-and-index-settings)
  of the root `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `bunfig.toml`, requirements
  files, `pip.conf`, `pip.ini`, `uv.toml` and `pyproject.toml` are recorded. User
  and global configuration, environment variables such as `PIP_INDEX_URL` or
  `npm_config_registry`, and command-line options can redirect a package with no
  finding. A PyPI setting is recorded on every PyPI package, even one that no
  install reading that file fetches, and an npm or PyPI package that a lockfile
  pins with integrity values loses its package URL all the same.
- **Lockfiles are claims.** Versions, integrity values and origins in a lockfile are
  recorded as declared; nothing is fetched or verified. Python lockfiles give the
  version and index origin, not artifact digests, and Yarn Berry `checksum` values
  are not recorded. Lockfiles of more than one npm package manager, or both
  `uv.lock` and `poetry.lock`, are a gap and bind no lockfile evidence.
- **Some lockfiles are not read.** `Pipfile.lock`, `pdm.lock`, `bun.lock` and
  `bun.lockb` give each package they may resolve a low `lockfile_unread` finding,
  not a gap.
- **A pin in any root file resolves a range.** A PyPI range that an exact pin of the
  same package in another root file satisfies is taken as resolved, even when that
  file, such as `requirements-docs.txt`, is never installed.
- **Some requirement text is not followed.** Options after a requirement, other than
  `-e` and `--hash`, are not checked. A `${NAME}` variable inside an option's value
  or a `name @ URL` reference is neither resolved nor reported, except in an index
  option's value, which is recorded as an `[unresolved]` redirect. pip expands
  variables before it splits a line, so a value with spaces could add options,
  including an include.
- **Images outside `FROM` are not recorded.** `COPY --from=<image>` and
  `RUN --mount=...,from=<image>` images are not inventoried, and a `# syntax=`
  directive that selects another Dockerfile frontend is not reported.

## A2A and RAG

- **Same-host URL changes need the binding key.** A2A and RAG records export URLs as
  origins. Without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, a path or query change on the
  same host that keeps the path depth raises no alert, and neither does a changed
  A2A interface `tenant` or a changed scope that was redacted. Such records carry a
  low `completeness` risk that names the key. See
  [A2A agent cards](verification-source-binding.md#a2a-agent-cards-and-client-entries)
  and [RAG sources](verification-source-binding.md#rag-sources).
- **Some A2A values are bound only by the key.** Values the record neither exports
  nor digests, such as descriptions, a skill's tags, examples and modes, security
  scheme fields other than their types and URLs, and `protocolVersion`, raise no
  alert without the key and add no `completeness` risk.
- **RAG values that are not exported enter the digest only as their type.** Without
  the key, a content filter written as `"strict"` and changed to `"off"` raises no
  alert. A boolean control is compared.
- **RAG transport is read from the locator's scheme.** A `source_uris` entry with a
  clear-text scheme such as `http`, with or without `//`, is a high finding. One with
  another scheme that is neither encrypted nor local, a `host:port`, a connection
  string or a `user@host` form is low, whatever TLS setting a connection string
  states. An entry without `:`, `@` or `=`, such as a bare host name, is read as a
  path and raises none.
- **Moved credential endpoints raise at most a medium alert.** A token endpoint or
  interface moved to another host raises a medium alert naming the property, such as
  `properties.security_scheme_origins changed`, and
  none when the card already uses the new host for such a URL or the URL is
  exported as `[redacted]`.
- **A backslash before `@` misleads the export.** `https://evil.example\@good.example/`
  is exported as `https://good.example`, although WHATWG parsers connect to
  `evil.example`. The change raises only a medium alert.
- **Authentication requirements are declarations.** Requirements on skills can make
  `authentication_required` false but never true. A card that declares
  requirements in another form, or names a scheme of no recognized type, is
  recorded as declaring none. None of this shows that an endpoint enforces
  authentication.
- **Card signatures are not verified.** They are recorded by count, algorithm and
  key id.
- **Only the endpoint gets the HTTPS check.** The card's `url` and its first
  `supportedInterfaces` entry are checked. A gRPC `host:port` address fails that
  check, because it does not show TLS.
- **Structure digests are unkeyed.** Anyone holding the inventory can confirm guesses
  of field and scheme names, path depth, whether a query or user information is
  present, and the requirement values of schemes other than OAuth 2.0 and OpenID
  Connect, including a credential pasted there by mistake.
- **Cards built in code are gaps.** A card built in Python is a gap. Cards are read
  only from `.well-known` directories and from `agent.json`, `agent-card.json` and
  `a2a/agent.json` in the root.
- **Python import heuristics are shallow.** The a2a and rag collectors read only
  Python files that name the SDK or a vector-store library. The rag collector skips
  one it cannot read or parse or that exceeds 262,144 characters. The a2a
  collector records one it cannot read as a failure, and skips one it cannot parse
  or that exceeds 262,144 characters unless it names `AgentCard`, which is a gap.
  The A2A search skips `tests`, `test`, `dist`, `build`, `docs`, `benchmarks` and
  `examples`.

## ShadowScan

- **Producer verification is recorded, and unsigned evidence fails in CI.** Importing a report
  records the verification outcome in the BOM (`metadata.completeness.discovery_verification`):
  `verified` with the signer identity and issuer when `import-shadowscan --bundle` authenticated
  the exact report bytes, otherwise `unverified`, with the report digest, the report's own run
  time, and the repository/commit the report carries — currently both `unknown`, because the
  ShadowScan report format carries neither, so the digest and run time are the binding, not a
  repository claim. A passing producer check of `validate` or `risk` with
  `--project --signature-policy` counts for that run only and writes no BOM. Unsigned evidence warns
  loudly on `import-shadowscan`, `validate` and `risk`, and fails the run in CI (or with
  `--fail-on-unsigned-discovery`) unless the operator explicitly passes `--allow-unsigned-discovery`.
  A project-policy setting can still be removed by the change it gates, and is ignored under
  `--no-project-policy`. `scan` does not verify the report.
- **A signature does not bind a commit or time.** A passing check authenticates the
  report's producer only. Anyone who can write to the checkout can substitute an
  older report, or another repository's report signed by the same identity. Give
  each repository's discovery workflow its own signer identity, or pin the report
  with `expected_sha256` in a version 2 `sigstore-message-signature` entry; see
  [require a signed report in CI](shadowscan-integration.md#require-a-signed-report-in-ci).
- **`verify-discovery --bundle` checks direct imports only.** It accepts only a BOM
  written by `import-shadowscan`. For a merged `scan` BOM, use the signature policy
  with `--project`.
- **Reruns need keyed credential identities.** When a report records
  `collection_scope.credential_identity_scope` as `run`, its redacted credential
  findings get new ids on every run, and `diff` reports them as removed and added.
  Set `SHADOWSCAN_IDENTITY_KEY` for every ShadowScan run; see
  [compare discovery across reruns](shadowscan-integration.md#compare-discovery-across-reruns).
- **`export-inventory` approves only the repository's root project.** Components,
  nested projects, agents that ShadowScan reports per source file, remote MCP servers
  and A2A cards stay findings that ShadowScan reconciles on their own; see
  [what the file approves](shadowscan-inventory-export.md#what-the-file-approves).
- **The resource prefix is not checked.** The inventory does not record ShadowScan's
  labels, so a prefix that names another repository approves that repository's
  project, and one that names nothing approves nothing.
- **ShadowScan approves a location, not content.** A later change under the bound
  resource stays approved there; compare content with `diff` against the reviewed
  baseline.
- **The exported file is unsigned, and its format is pinned.** `export-inventory`
  signs nothing and ShadowScan checks no signature on an inventory file: sign the
  exact bytes with `attest`, check them with `verify-attestation` before ShadowScan
  reads the file, and keep the file outside the checkout ShadowScan scans. The format
  was checked against ShadowScan 999bef1 (0.1.4) only.

## Signatures

- **The CLI checks the cache before trusting it.** Offline verification uses the trusted root
  that sigstore-python caches in `$XDG_CACHE_HOME/sigstore-python` when
  `XDG_CACHE_HOME` is set, and otherwise in `~/.cache/sigstore-python` on Linux or
  `~/Library/Caches/sigstore-python` on macOS. Before trusting it, the CLI checks that every
  directory from the TUF targets directory up to the sigstore-python cache directory is owned
  by the current user and is not group/world-writable or a symlink, and that `trusted_root.json`
  itself is owned by the current user, is not a symlink, and is not
  group/world-writable where anyone else can reach it (a file sigstore-python wrote under a
  group-writable umask is accepted only inside a private directory); a missing cache is created
  mode 0700 and seeded mode 0600 with the root embedded in sigstore-python, and any check
  failure fails verification closed with the offending path named. Pass
  an explicit trust root instead with `--trust-root` on `verify-artifact`/`verify-discovery`, or
  `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT` for any verification path, verified against a pinned
  SHA-256 when `--trust-root-sha256` or `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256` is supplied.
  A successful verification prints the trust-root path it used. On shared or persistent machines,
  such as self-hosted runners, set `XDG_CACHE_HOME` to an empty directory you own;
  on macOS, setting `HOME` alone is not enough when `XDG_CACHE_HOME` is set.
  The cached or explicit trust root is opened once without following symlinks, checked on
  that descriptor, and verification uses exactly the bytes read, so no directory on its
  path, including those above the cache such as a linked `~/.cache`, may be a symlink
  (macOS's `/var`, `/tmp` and `/etc` links excepted). The unpinned cache is still
  trusted because it is private: a process running as your user can write a root there
  before verification starts, which only an explicit, pinned trust root rules out.
- **The Action's trust root ages.** The Action gives its scans an empty private
  cache, so it uses the root embedded in its hash-locked `sigstore` package. A
  bundle that relies on a key Sigstore introduced later fails until you update the
  Action pin.

## Attestations

- **An attestation does not prove freshness.** An older file that the same keys
  attested for the same purpose still verifies. Bound it with `--max-age-days`,
  record `--source-revision`, and keep attested baselines where the change under
  review cannot choose among them; see
  [inventory attestation](inventory-attestation.md#limits).
- **No revocation, transparency log or keyless signing.** Retire a key by removing it
  from every trusted set. The commands sign with Ed25519 PEM keys only.
- **The purpose is signed, not bound to a key.** Any trusted key can sign either
  purpose; trust separate keys for `generated` and `reviewed`.
- **The trusted-key placement check is a heuristic.** It refuses a key inside a git
  working tree that holds the subject, the envelope or the current directory, also
  under another name for that tree directory, and a key file with other hard links.
  It does not authenticate a key, check its owner or permissions, recognize a
  checkout without a `.git` entry, or follow a key copied or mounted out of the
  checkout, such as one reached through `docker run -v "$PWD/keys:/keys"`.
- **Verification and use are separate reads.** Run `verify-attestation` and `diff`
  where the change under review cannot write between the two.
- **The verifying build must read the inventory's format.** An attestation of a
  native inventory in a format version that build cannot read fails with
  `subject-not-inventory`, even for its exact bytes. An inventory nested more than
  256 levels deep is attested by its bytes only, so `--match content` is unavailable
  for it.
- **The GitHub Action neither signs nor verifies attestations.** Run the commands in
  a workflow step.

## Exports

- **Coverage is coarse in standard fields.** CycloneDX `compositions` and SPDX
  relationship `completeness` say only `incomplete`, or `unknown` (`noAssertion` in
  SPDX), never `complete`: `incomplete` when a collector failed, was not run or left a
  gap, a surface or a path beyond the default exclusions was excluded, or discovery was
  imported, and `unknown` otherwise. Which collectors ran, failed or were excluded is
  only in the embedded native inventory. An SPDX export without native-edge
  relationships states its coverage only in the document `comment`.
- **Rewriting tools drop the coverage warning.** cyclonedx-python-lib 11.12.0 drops
  `compositions` when it reserializes a BOM. A document that loses an `incomplete`
  composition no longer recovers.
- **Conditions are extension-only.** The CycloneDX
  `nexus-symbiote:dependency:relationship` property marks a conditional edge only
  with `"conditional": true`; the condition text and assurance level are only in the
  embedded native inventory.
- **Some earlier exports do not recover.** CycloneDX and SPDX exports written by
  builds before 0.1.0 can fail recovery. Regenerate them from the native inventory; see
  [standard projection versions](fingerprint-migration.md#standard-projection-versions).
- **A recorded timestamp does not change the serial.** The serial number is the
  version 5 UUID of the inventory content digest, which excludes `metadata.timestamp`,
  the completeness claim's `timestamp` and `source_report_path`, and every claim's
  `observed_at`, so two documents that differ only in those fields share a serial.
  This is deliberate: the serial names the inventory, not the moment or the checkout
  it was observed from. Compare timestamps directly when they matter.
- **Malformed input stops some exports.** A JSON-escaped lone surrogate, such as
  `\ud800`, in a field that a record carries, such as an A2A skill name or version or
  a `package.json` dependency version, has no content digest and so no serial number:
  `scan` and `import-shadowscan` exit 1 with `Error: Inventory not written. Its serial
  number is derived from its content digest, ...` in every format, and write nothing.
  In an A2A card's name or
  requirement lists, in a RAG source, or anywhere in a card collected with
  `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, it is a scan failure instead. Both fail
  closed.
- **SARIF locations depend on the working directory.** Native JSON and CycloneDX are
  byte-identical for the same inputs, and SPDX too with `SOURCE_DATE_EPOCH` set (without
  it, SPDX records the export time as `CreationInfo.created`), but SARIF
  locations are relative to the working directory when the scanned directory lies
  below it, so two SARIF files match only when the scanned directory lies at the same
  path below the working directory in both scans, or below it in neither; see
  [reproducible inventories](reproducible-inventories.md#byte-identical-files-with-source_date_epoch).
- **Framework references are this project's statement.** No framework owner published
  or reviewed the crosswalk, and NIST AI RMF, EU AI Act, ISO/IEC 42001 and CWE
  identifiers were checked against secondary sources only. A reference never says
  that an attack happened, that a control fails or that an obligation applies; see
  [framework crosswalk](framework-crosswalk.md#limits).
- **Some SARIF tags do not hold for every finding of their rule.** CWE-319 and ASI07
  on `transport_security`, CWE-502 on `serialization_format` and CWE-306 on
  `authentication` were kept from the earlier rules so that existing filters still
  match; the crosswalk's limits name the findings each one does not hold for. Medium
  `nonregistry_source` findings have no framework reference.
- **`crosswalk` applies only the built-in policy and does not name its inventory.**
  Keep the report with the inventory it was made from. Its Markdown escapes markup,
  not a renderer's text filters, such as GitHub mentions and emoji codes.

## Gates and drift

- **A gate cannot see what is not recorded.** `validate`, `risk` and
  `diff --fail-on-alert` compare what the inventory records. The surfaces above
  that are not recorded pass every gate when they change.
- **Without `--project`, only claims are checked.** `validate` and `risk` then check
  the inventory's own coverage claim and consistency. Pass `--project` to compare it
  with a fresh collection of the checkout.
- **A re-hash of the checkout counts as verified.** With `--project`, which the
  GitHub Action passes, integrity passes once one recorded digest matches the
  checkout and no check fails or is unknown. The digest of an instruction file that
  the same run read from that checkout matches, so a repository with only an MCP
  configuration moves from unknown to passing integrity when it adds a `CLAUDE.md`,
  although nothing about its MCP servers was verified. Without a signer policy,
  passing integrity shows only that the inventory matches the checkout. The
  [roadmap](../ROADMAP.md#plan) tracks the change (N12).
- **A project policy can weaken its own gate.** `scan`, and `validate` and `risk`
  with `--project`, apply the checkout's `.nexus-symbiote.yaml`, including
  suppressions, ignored categories and raised thresholds. Each relaxation is listed
  in `policy_weakened`, in the inventory's metadata and in `risk --json-output`, and
  printed as a warning. When a CI variable such as `CI` or `GITHUB_ACTIONS` is set, a
  policy that weakens a gate fails the command unless `--no-project-policy` ignores it
  or `--accept-project-policy` accepts it explicitly; interactive runs only warn. There
  is no operator-owned policy file. See
  [what `policy_weakened` reports](policy-reference.md#what-policy_weakened-reports).
- **A suppressed chat template finding is bound to the model file.** A suppression
  names the [fingerprint](policy-reference.md#suppressions) of the finding, which
  binds the model's own content digest, the `sha256` of its file, not the chat
  template files beside it. A template finding names the matching templates in its
  detail, so a template file whose text changes while the same templates still match
  keeps the suppression. `diff --fail-on-alert` against a reviewed baseline reports the changed
  `chat_template_hash` as a security alert.
- **A baseline is written unsigned.** `baseline` and `scan` do not sign, and `diff`
  checks no signature, so `diff` alone cannot tell a reviewed baseline from one the
  change under review wrote. Read it from the protected branch. To check also that
  trusted keys signed exactly that file, attest it with `attest --purpose reviewed`
  and check it with `verify-attestation` before `diff`; an older attested baseline
  still verifies, so this does not replace reading the baseline from where the change
  under review cannot choose it; see
  [the trust anchor is the baseline](drift-gate.md#the-trust-anchor-is-the-baseline)
  and [inventory attestation](inventory-attestation.md).
- **Inventories from 0.1.0 need a new baseline.** They record absolute paths, a
  path-derived agent reference, native format 1.0.0 and older MCP bindings. On an
  unchanged project, `diff --fail-on-alert` against a 0.1.0 baseline fails with high
  and critical alerts, and `validate --project` asks for recollection. Take a new
  baseline with this release at the commit the old one was reviewed at; see
  [take both snapshots the same way](drift-gate.md#take-both-snapshots-the-same-way).
- **Both snapshots need the same binding key.** With a different key, every MCP,
  A2A, RAG and IDE settings binding changes and alerts, and the digests of the IDE
  settings files digested as read differ between a keyed and an unkeyed scan.
- **A content digest names content, not a producer.** Two inventories of the same
  content, a forged copy of a genuine one included, have the same content digest.
  List order is content: this build writes components and dependencies sorted, so a
  native document recovered from its CycloneDX or SPDX export is the native file, but
  a document another build wrote with its lists in another order has another content
  digest than its sorted rewrite; see
  [reproducible inventories](reproducible-inventories.md#limits).
- **Some readable inventories have no digests.** A document without a `components`
  list has no content digest, and one larger or deeper than
  a runtime snapshot binds has no canonical digest; `digest` prints `unavailable`
  for the missing one and exits 1.
- **An inventory nested deeper than 128 levels is not read.** Every command that
  reads a native inventory, `diff`, `validate`, `risk`, `graph`, `summary`,
  `digest`, `export-inventory` and the rest, refuses one whose arrays and objects
  nest more than 128 levels, the root counted, with "inventory nests deeper than 128
  levels" and exit 1. The bound is fixed, not the interpreter's recursion limit, so
  the same file is read or refused by every caller. A collected inventory stays
  within it, since its deepest values, MCP tool definitions, nest at most 64 levels;
  one edited by hand or written by another producer needs its `properties`
  flattened.
- **A malformed `SOURCE_DATE_EPOCH` stops collection.** `scan`, `baseline` and
  `import-shadowscan` exit 2 when it is set to anything but 1 to 12 ASCII digits
  naming an instant up to 9999-12-31T23:59:59Z, an empty value included. Unset it to
  record no collection time.

## Trace evidence

- **Telemetry is self-reported.** `trace-diff` reads what the agent's own
  instrumentation exported, which can omit, sample or forge spans. Exit 0 means only
  that nothing undeclared appeared in the traces read, and a missing span proves
  nothing; see [trace evidence](trace-evidence.md#trust-model-reported-not-observed).
- **Names, not identities.** Tools, models, agents and MCP endpoints are matched by
  name and by reported host and port, compared as text after trimming: nothing is
  resolved by DNS, Unicode is not normalized, and providers have no aliases. When a
  span reports no port, or a server's endpoint states none and its scheme has no
  default port, an endpoint is compared by host alone.
- **What a span leaves out narrows what it reports.** A span that leaves out a tool or
  agent name, a server address or a port reports less, without failing the gate; a
  span that reports a server address is compared only with the tools served there,
  even when it leaves out its transport. A tool, model, agent or endpoint identifier,
  an operation name, an MCP method, or the transport of a tool call or of an MCP client
  span that reports a server address, that is present but cannot be read fails the
  gate. A trace cannot attribute pipe or unix-socket MCP activity to a configured
  server, and skills, data sources, memory stores and prompts are listed for
  information only.
- **Remote tools are undeclared until recorded.** A static scan records only the
  tools that a client configuration declares for a remote MCP server, not the tools
  the server serves, so calls to its other tools are undeclared until an inventory
  records them, for example one that `discover-mcp --record` writes. Each run
  compares one inventory.
- **Not everything is read.** Span events, links, log records, span names, scope
  attributes and the attributes after the first 128 of a span or resource are not
  read, so content recorded on span events is not counted. A span or resource with
  more than 128 attributes fails the gate.
- **Fixed bounds and memory.** At most 16 files, 64 MiB per file, 1,000,000 spans
  and 100,000 distinct identifiers; `--limit` does not change them. A one-object file
  is parsed whole and can need about 2 GB for 64 MiB; prefer JSON Lines for large
  exports.

## Graph view

- **Risk classes restate recorded evidence.** They come from declared or name-inferred
  capabilities, side effects and egress domains, an MCP endpoint, an MCP environment
  name withheld as `[redacted-N]`, a model's serialization safety or
  `trust_remote_code`, two Claude Code starting modes and Codex
  `approval_policy = "never"`. A class does not establish what a
  component does at run time, and its absence establishes nothing: a component whose
  record holds nothing the rules read is unclassified, which is unknown, not safe; see
  [risk classes](graph-view.md#risk-classes).
- **Some permission settings are not read.** Claude Code's unscoped allow rules,
  which the collector records only in the text of a finding, Codex `sandbox_mode`
  and the `agent.permissionMode` of other hosts leave an IDE agent unclassified, so
  `permissions.allow: ["Bash", "Edit"]` does not make it a sink.
- **Exposure paths show potential reach.** A path is the shortest chain of recorded
  associations from an agent or IDE agent to a risky component. It does not show that
  the agent can invoke the component, that a credential reaches it or that an exploit
  is possible. At most 200 agents and IDE agents are searched and 200 paths kept, and
  the view reports how many were left out.
- **Large inventories make large pages.** `--max-nodes` bounds components, not edges,
  and the HTML page renders every detail when it is written, so a large or dense
  inventory gives a page that a browser opens slowly. Use `--focus` or
  `--format json` for such inventories.

## G7 minimum elements

- **Coverage, not compliance.** The G7 elements are non-binding. `minimum-elements`
  measures what the CycloneDX export carries in standard fields and verifies no
  value: a present element is a value recorded in an inventory that is written
  unsigned and can be edited; see [limits](minimum-elements.md#limits).
- **Secondary verification.** Element names and their order were checked against four
  independent enumerations, not the primary document, and each rule paraphrases the
  element's definition.
- **One export, one projection.** Only the CycloneDX 1.7 export of projection
  `cyclonedx-1.7/2` is evaluated, not the SPDX export.
- **This build cannot reach every element.** Four assessable elements have no
  CycloneDX 1.7 field, others have a field this projection does not write, and eleven
  need producer input; see
  [what a future projection could carry](minimum-elements.md#what-a-future-projection-could-carry).
- **Relationships are exported in part.** Only unconditional `depends-on` and
  `provides-tool` relationships reach the export's `dependencies`, so for a scanned
  repository SBOM dependency relationship is present only when `scan` collected tools
  from MCP server source, and is then marked partial.
- **Memory grows with the inventory.** The export is generated and schema-validated
  in memory, about 11 KiB per component: an inventory near the 16 MiB bound can need
  about 2.6 GiB.

## Live mode

- **Live commands observe declarations, not behavior.** `discover-mcp` and
  `verify-live` do not observe tool implementations, `resources/list` entries or
  resource contents, prompt messages, authorization metadata, or changes after the
  session; see [what a live observation does not cover](offline-and-live-modes.md#what-a-live-observation-does-not-cover).
- **A server can answer an observer differently.** Set `--client-name`,
  `--client-version` and `--user-agent` to match your production host.
  `verify-live` starts launchers with no arguments, a private working directory and
  an environment that holds only a default `PATH`.
- **Some servers cannot be observed.** A server that offers none of the supported
  protocol revisions, or only one without `initialize`, is reported as refused. A
  stream the server closes before its reply ends the observation as incomplete.
  `verify-live` observes stdio servers only: observe remote servers with
  `discover-mcp --record` and compare with `diff`. A WebSocket server is reported as
  `unsupported-transport`.
- **Launcher pins cover the launcher only.** They do not authenticate the operating
  system, interpreter or libraries. Run launchers in an isolated worker, as
  [security boundaries](../SECURITY.md#security-boundaries) describe.
- **The offline guard is a tripwire, not a sandbox.** Native code can bypass it, a
  process `verify-live` starts is not covered, and live mode removes it for the
  three live commands. Add an operating-system network boundary where you need one;
  see [limits](offline-and-live-modes.md#limits).
- **`advisories` sends package identities to OSV.** It sends each package's
  ecosystem, name and exact version, including private packages unless excluded.
  A Python package that no `uv.lock` or `poetry.lock` resolves is labelled with the
  public PyPI origin, which is assumed, not recorded. One that a project setting
  [redirects](registry-collector.md#registry-and-index-settings) has no origin and
  no package URL, and is not sent. Keep a private name local with `--exclude`, and
  preview with `--dry-run`; see [`advisories`](cli-reference.md#advisories).

## Runtime gateway

- **Lineage persistence needs trusted, current state.** The lineage helper's
  snapshot retains ACL revision histories, but does not authenticate them or stop
  rollback. Versions imported without their histories cannot have their ACLs
  updated until an operator supplies complete history; see
  [lineage persistence](runtime-assurance.md#hosted-identity-and-mutable-data).
- **Only mediated calls are governed.** `ReferenceGateway` authorizes only calls
  routed through `invoke`. The operator builds the authentication, description,
  scope and execution adapters and must close every other path to the tools; see
  [security boundary](runtime-assurance.md#security-boundary).
- **Superseded snapshots stay usable until retired.** Snapshots, trust statuses and
  the companion BOM must come from an operator-controlled channel. A superseded
  snapshot stays valid on a state store until a newer one is registered or
  presented there, or a trust status revokes it. Retire it with `runtime register`;
  see [state and supersession](runtime-assurance.md#state-and-supersession).
- **State is per store.** One-use approvals and rollback protection hold per SQLite
  state file, so every gateway that serves the same tenants must share one store.
- **`runtime verify` does not check revocation.** Revocation and approval bindings
  are checked only by the gateway.
- **Schemas are read in their declared dialect.** A schema without `$schema` is read
  as JSON Schema 2020-12. A constraint that evaluation would skip, or a pattern that
  ECMA-262 and Python read differently, such as a backreference to an optional
  group, makes the schema invalid and the call is denied with `schema-invalid`. A
  pattern valid only without the `u` flag is read with code-point semantics.
- **Canonical arguments are enabled by default.** By default (`canonical_arguments=True`),
  `resolve_scope` and `execute` receive the exact RFC 8785 canonical JSON value the
  approval binds (keys in RFC 8785 order and integral floats in `[-(2^53 - 1), 2^53 - 1]`
  converted to integers). Setting `canonical_arguments=False` forwards the caller's
  key order and float/int distinction while still rejecting integral floats outside
  `[-(2^53 - 1), 2^53 - 1]`.
- **macOS workers have no memory limit.** Schema validation workers run with a
  256 MiB address-space limit, which macOS refuses, so workers there run without it.

## GitHub Action

- **A pull request can change its own gate.** On `pull_request`, GitHub runs the
  workflow file of the pull request's merge commit, so a pull request can change the
  Action's inputs, switch a gate off or delete the step unless workflow edits are
  gated. The Action warns about each switched-off gate and reports every gate in its
  `gates` and `result` outputs, but cannot tell which workflow file a reviewer
  approved. Protect the gate with a workflow that an organization ruleset requires
  and `CODEOWNERS` review on `.github/`, as the [drift gate guide](drift-gate.md#protect-the-gate)
  shows, and avoid checking out untrusted pull request heads in `pull_request_target`
  workflows. Selecting a subset of `scanners` requires `validate: 'false'` and
  `risk-check: 'false'`, because both gates require all built-in collectors.
- **Earlier steps in the job are trusted.** A step that runs untrusted code before
  the Action can change the runner's Python or rewrite files under `RUNNER_TEMP`
  before the Action reads them. Write the signer policy and the reviewed baseline
  from a trusted source, and run untrusted build or test steps in a separate job.
- **Uploads replace each other.** A SARIF upload replaces an earlier one for the same
  commit and `sarif-category`, and two Action steps in one workflow run need
  different `artifact-name` values.

## Resource use

- **Limits bound size, not time.** The collection limits bound how much a command
  reads. Within them, hashing a 256 GiB model directory takes several minutes. Set a
  job timeout, such as `timeout-minutes` in GitHub Actions.
- **SPDX export is slow.** It is validated against the official schema and takes
  about 50 to 120 milliseconds per component. MCP client files of under 2 MiB in all
  can declare 100,000 tools (one file holds at most 5,000), which keeps
  `scan -f spdx` running for hours. The scan does not pass, but it can hold a CI job
  until the job times out.
- **Native inventories are limited to 16 MiB.** A larger inventory, such as one with
  100,000 MCP tools, is not written: `scan` exits 1 with `Error: Inventory not
  written. The inventory exceeds the 16 MiB limit that native readers accept.`
- **Validation work is bounded.** `validate --project` reads each artifact once per
  run and charges every read, including model inspection and signature bundles, to
  six times the `model-total-bytes` limit (1.5 TiB by default). What does not fit is
  reported as not checked.
- **The TypeScript parser is native code.** It runs inside the scanning process with
  size, node and time bounds, but without isolation; see
  [security boundaries](../SECURITY.md#security-boundaries).
