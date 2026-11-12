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
- [Exports](#exports)
- [Gates and drift](#gates-and-drift)
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
  `node_modules`, `__pycache__`, `.venv` or `venv` is skipped. These defaults are
  listed under `exclusions` in the inventory but are not a gap, except inside a
  directory whose every file the `prompt` collector reads, such as a skill, command,
  rule or subagent directory. There such an entry, such as `.claude/skills/venv` or
  `.claude/agents/node_modules`, is a coverage gap that names it, so the default
  gates fail. A skill checked out with its own `.git`, including a Git submodule,
  whose `.git` is a file, or one whose script left a `__pycache__` beside it, fails
  them until that entry is removed.
- **Case variants.** When a fixed path such as `CLAUDE.md`, `.mcp.json` or
  `.claude/settings.json` is absent, a file whose name differs only by case or
  Unicode normalization is a failure, because case-insensitive file systems open
  it. When both exist, only the exact name is read. More than 16 such names in one
  directory, or a search beyond the `entries` limit, is a failure.
- **Symlinks.** A relative symlink to a regular file or directory in the project,
  not excluded, within the `depth` limit and reached without another symlink, is
  read through its target. A read through any other symlink, such as an absolute
  one or `.claude -> .`, is a failure. A walk of the project skips directory
  symlinks and walks their targets under the targets' own names.
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
  gap, and so are package installs (`pip install`, `python -m pip install`,
  `gem install`, `cargo install`, `conda` or `mamba install`), `uv run` of a URL or
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
  program word and no `%`, `!`, `"`, `^` or unusual whitespace. Anything else is an
  inline shell script: a gap. So `sh -c "npx -y pkg@1.2.3 $HOME/data"` is a gap;
  pass such values as separate arguments or through `env`.
- **Shell startup code is a gap.** An interactive shell (`-i`) given `--rcfile` or
  `--init-file`, a `BASH_FUNC_<name>%%` exported function in the server's
  environment, and a `BASH_ENV` that is not an absolute path run code before the
  script that can replace the runner it names, so the launcher is unknown. An
  absolute `BASH_ENV` and `ENV` stay a medium code-loading finding.
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
  tokens are exported as `[redacted]`.
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
  LangChain's `MultiServerMCPClient`, used outside an annotation; in TypeScript and
  JavaScript, the SDK's `StdioClientTransport`, `SSEClientTransport`,
  `StreamableHTTPClientTransport` and `WebSocketClientTransport`. The command, its
  package and pin are not inventoried even when they are literal; declare such a
  server in a client file to have it inventoried. A launcher reached only through
  `getattr`, `globals()` or code in a string, and the clients of other frameworks,
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
  qualified, module-alias or star import, and an import spelled only with
  compatibility characters. A dynamic import (`importlib.import_module`,
  `__import__` or `pkgutil.resolve_name`) whose literal arguments name `mcp`,
  `mcp.server` or `fastmcp`, or a submodule of the last two, is a gap, and so is one
  that names a client module: `mcp.client`, `agents.mcp`, `pydantic_ai.mcp`,
  `langchain_mcp_adapters` or a submodule. A literal is a string or an f-string
  without placeholders, and a relative name counts once resolved against a literal
  package or `__import__` globals. A module name computed at run time, and other
  import machinery such as `importlib.util.find_spec` or `runpy`, are not followed
  and leave no gap.
- **Python files without a reference are not examined.** A file that names neither
  `mcp` nor a supported agent framework is not parsed.
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
  qualified import and a star import are gaps. Class-based tools, such as
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
- **Some files are not inventoried.** Pickles under names other than the
  [listed suffixes](model-integrity.md#model-files-and-references), NumPy `.npy` and
  `.npz` arrays, and `.pb` files other than `saved_model.pb` produce no component.
- **Templates and tensors are checked shallowly.** GGUF and Hugging Face chat
  templates are checked only for known sandbox-escape shapes. A template file larger
  than the `file-bytes` limit is digested but not checked, and is a coverage gap.
  SafeTensors tensor bytes are hashed but not inspected. See
  [what this does not establish](model-integrity.md#what-this-does-not-establish).

## Instructions and IDE settings

- **Instruction files under other names are not recorded.** The `prompt` collector
  reads the fixed files the [README lists](../README.md#what-each-collector-reads),
  `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` and `.cursorrules` in any subdirectory, and
  every file in the rule, prompt and subagent directories. Nested names must match
  exactly, so `CLAUDE.local.md`, `AGENTS.override.md`, `.clinerules` or
  `.windsurfrules` below the root, `claude.md` in a subdirectory, and other hosts'
  conventions are neither inventoried nor checked for hidden characters. List such
  files in an [`agent.yaml`](agent-manifest.md).
- **Imports are followed from memory files.** `@path` imports are followed to five
  hops from the root `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md` and
  `GEMINI.md`, and from every `CLAUDE.md` and `GEMINI.md` below the root, resolved
  from that file's directory. An import that leaves the project root, names an
  excluded path or lies deeper than the `depth` limit is a gap, so write a path
  alias such as `@/components` as code.
- **Fixtures count.** A nested `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` or `.cursorrules`
  in test fixtures or vendored code is inventoried, and its findings count, like any
  other.
- **Skill front matter is not interpreted.** Every file in the skill and command
  directories is bound by digest, but settings such as `allowed-tools` are not
  read. A skill declaration (`.md`, `.mdc`, `.markdown`, `.txt`, `.yaml`, `.yml`,
  `.json`, `.toml`) above the `file-bytes` limit is a failure; a larger script or
  other resource is streamed and digested.
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
  applied to the allow list.
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
  redaction removes, such as an MCP server's environment value, a token, or a URL
  path on the same host in a `notify` command, raises no alert.
- **Codex settings are interpreted in part.** `.codex/config.toml` is digested
  whole, so a changed setting such as a `notify` command raises an alert, but only
  `approval_policy`, `sandbox_mode` and the `mcp_servers` table are interpreted. A
  value that the digest or the keyed binding covers and that RFC 8785 JSON cannot
  represent, such as a TOML date or time, `nan`, `inf` or an integer of magnitude
  2^53 or more, is a failure.
- **Other IDE agents' settings are digested, not interpreted.** For Cursor, Windsurf
  and Cline, a permission mode is read only from an `agent.permissionMode` key in
  their settings files, a convention their vendors do not document; for Codex, from
  that key in `.codex/config.json` or from `approval_policy`. No mode is read for
  Copilot, Gemini CLI, Antigravity or xAI. Files such as `.cursor/cli.json`,
  `.antigravity/settings.json`, `.xai/config.json` and
  `.github/copilot-extensions.json` are digested, so a change raises the same high
  alert as other settings changes, but their permissions are not read: widening the
  Cursor CLI allow list from `Shell(ls)` to `Shell(*)` adds no finding.
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
  `setup.py`, `setup.cfg`, dynamic dependencies, conda `environment.yml`, index
  choices such as `--index-url` and `.npmrc`, Kubernetes manifests, Helm charts,
  `.devcontainer` configuration and `docker buildx bake` files are not read and
  leave no gap. [Not read](registry-collector.md#not-read) lists them all.
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
  or a `name @ URL` reference is neither resolved nor reported. pip expands
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
- **Moved credential endpoints raise at most a medium alert.** A token endpoint or
  interface moved to another host raises a medium `properties changed` alert, and
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
  Python files that name the SDK or a vector-store library, and skip one they cannot
  read or parse or that exceeds 262,144 characters; for A2A, such a file that names
  `AgentCard` is a gap. The A2A search skips `tests`, `test`, `dist`, `build`,
  `docs`, `benchmarks` and `examples`.

## ShadowScan

- **Producer verification is opt-in.** `validate` and `risk` accept unsigned
  ShadowScan evidence, and say so, unless an operator signature policy names the
  report, `--require-discovery-signature` is passed, or an honored project policy
  sets `validate.require_discovery_signature`. `scan` does not verify the report.
- **The result is not recorded.** The check's result is not written into the
  inventory, so `validate` or `risk` without `--project` cannot enforce it. A
  project-policy setting can be removed by the change it gates, and is ignored under
  `--no-project-policy`.
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

## Signatures

- **The CLI trusts a writable cache.** Offline verification uses the trusted root
  that sigstore-python caches in `$XDG_CACHE_HOME/sigstore-python` when
  `XDG_CACHE_HOME` is set, and otherwise in `~/.cache/sigstore-python` on Linux or
  `~/Library/Caches/sigstore-python` on macOS. sigstore-python reads that file
  without verifying it, so anyone who can write there chooses which certificate
  authorities and transparency logs are accepted. On shared or persistent machines,
  such as self-hosted runners, set `XDG_CACHE_HOME` to an empty directory you own;
  on macOS, setting `HOME` alone is not enough when `XDG_CACHE_HOME` is set.
- **The Action's trust root ages.** The Action gives its scans an empty private
  cache, so it uses the root embedded in its hash-locked `sigstore` package. A
  bundle that relies on a key Sigstore introduced later fails until you update the
  Action pin.

## Exports

- **Coverage is coarse in standard fields.** CycloneDX `compositions` and SPDX
  relationship `completeness` say only `incomplete`, or `unknown` (`noAssertion` in
  SPDX), never `complete`: `unknown` with only the default exclusions, `incomplete`
  with any other exclusion entry. Which collectors ran, failed or were excluded is
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
  builds before 0.1.0 can fail recovery, and so can a 0.1.0 export of an inventory
  built through the Python API with a package URL this release does not project:
  a type other than PyPI, npm and OCI, such as `pkg:docker` or `pkg:generic`, or a
  PyPI or npm URL with a qualifier other than a `repository_url` that names the
  component's own registry. Regenerate them from the native inventory; see
  [standard projection versions](fingerprint-migration.md#standard-projection-versions).
- **Malformed input stops some exports.** A JSON-escaped lone surrogate, such as
  `\ud800`, in a field that a record carries, such as an A2A skill name or version or
  a `package.json` dependency version, makes CycloneDX, SPDX and SARIF export exit 1
  with `Error: The inventory cannot be exported as <format>: ...`. The native JSON
  written for it is refused by the other commands. In an A2A card's name or
  requirement lists, in a RAG source, or anywhere in a card collected with
  `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, it is a scan failure instead. Both fail
  closed.

## Gates and drift

- **A gate cannot see what is not recorded.** `validate`, `risk` and
  `diff --fail-on-alert` compare what the inventory records. The surfaces above
  that are not recorded pass every gate when they change.
- **Without `--project`, only claims are checked.** `validate` and `risk` then check
  the inventory's own coverage claim and consistency. Pass `--project` to compare it
  with a fresh collection of the checkout.
- **A project policy can weaken its own gate.** `scan`, and `validate` and `risk`
  with `--project`, apply the checkout's `.nexus-symbiote.yaml`, including
  suppressions, ignored categories and raised thresholds. Each relaxation is listed
  in `policy_weakened`, in the inventory's metadata and in `risk --json-output`, and
  printed as a warning. Pass `--no-project-policy` in CI; there is no
  operator-owned policy file. See
  [what `policy_weakened` reports](policy-reference.md#what-policy_weakened-reports).
- **A baseline is unsigned.** `diff` cannot tell a reviewed baseline from one the
  change under review wrote. Read it from the protected branch; see
  [the trust anchor is the baseline](drift-gate.md#the-trust-anchor-is-the-baseline).
- **Inventories from 0.1.0 need a new baseline.** They record absolute paths, a
  path-derived agent reference, native format 1.0.0 and older MCP bindings. On an
  unchanged project, `diff --fail-on-alert` against a 0.1.0 baseline fails with high
  and critical alerts, and `validate --project` asks for recollection. Take a new
  baseline with this release at the commit the old one was reviewed at; see
  [take both snapshots the same way](drift-gate.md#take-both-snapshots-the-same-way).
- **Both snapshots need the same binding key.** With a different key, every MCP,
  A2A, RAG and IDE settings binding changes and alerts, and IDE settings digests
  differ between a keyed and an unkeyed scan.

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
  Requirements files and `pyproject.toml` name no index, so a Python package that
  no `uv.lock` or `poetry.lock` resolves is labelled with the public PyPI origin.
  Keep a private name local with `--exclude`, and preview with `--dry-run`; see
  [`advisories`](cli-reference.md#advisories).

## Runtime gateway

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
- **The executor sees the caller's argument form.** By default the executor receives
  the arguments in the key order and number spelling the caller sent, while the
  approval binds their RFC 8785 form. Construct the gateway with
  `canonical_arguments=True` for backends that depend on either.
- **macOS workers have no memory limit.** Schema validation workers run with a
  256 MiB address-space limit, which macOS refuses, so workers there run without it.

## GitHub Action

- **A pull request can change its own gate.** On `pull_request`, GitHub runs the
  workflow file of the pull request's merge commit, so a pull request can change the
  Action's inputs, switch a gate off or delete the step, and its run passes. The
  Action warns about each switched-off gate and reports every gate in its `gates`
  and `result` outputs, but cannot tell which workflow file a reviewer approved.
  Protect the gate with a workflow that an organization ruleset requires, or with a
  `pull_request_target` job, as the [README](../README.md#protect-the-gate) shows.
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
