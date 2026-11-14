# Static TypeScript MCP inventory

The MCP scanner collects literal `tool` and `registerTool` names from servers
written in TypeScript or JavaScript with the official MCP TypeScript SDK. A server
is collected when `McpServer` is imported from `@modelcontextprotocol/server` or
`@modelcontextprotocol/sdk/server/mcp.js`, by name (an alias or a string name such
as `import { "McpServer" as Server }` included) or through a namespace import
(`import * as sdk` and then `new sdk.McpServer(...)`), and is constructed as a
`const` at module or block level. Lexically bound server factories are supported.
Type-only imports, shadowed constructor parameters and shadowed server variables
do not establish SDK server bindings.

Each tool record has declared assurance, a digest of its registration call
(`registration_source_sha256`) and a digest of the whole declaring file
(`source_sha256`), so editing a handler defined elsewhere in that file changes the
inventory. Handlers imported from other modules are not covered. The scanner
does not execute source code, evaluate schemas or callbacks, establish that a
factory ran, or construct a tool-definition fingerprint. Effective descriptors
and runtime registration remain unknown; compare observed descriptors separately
before approving a live call.

## Files and grammars

`.ts`, `.mts` and `.cts` files are parsed with the TypeScript grammar of
tree-sitter. `.tsx`, `.js`, `.mjs`, `.cjs` and `.jsx` files are parsed with its TSX
grammar, the variant tsc uses for them, which reads JSX. Identifiers and module
names are read as JavaScript reads them, so `\u0073erver` is `server`. That grammar
is TypeScript's, so for a JavaScript file two cases are gaps rather than failures:
a file it cannot parse, and a file in which it reads a comparison such as
`a < b > (c)` as a call with type arguments. A TypeScript file that does not parse
is a failure, `invalid TypeScript syntax`.

A file is parsed when its text contains `@modelcontextprotocol/` together with
`McpServer` or `ClientTransport`, or names a server or client module of the SDK: it
contains `@modelcontextprotocol/sdk/server`, `@modelcontextprotocol/sdk/client`,
`@modelcontextprotocol/sdk/dist` or `@modelcontextprotocol/sdk@`, or
`@modelcontextprotocol/server` or `@modelcontextprotocol/client` followed by a quote,
`/`, `@`, `?` or `#`. A file that mentions these only in comments, or in strings other than
the first argument of a call, is parsed; if it parses, it produces nothing.

A module specifier names the SDK wherever `@modelcontextprotocol/` appears in it,
because a runtime or bundler can resolve it there: after `npm:` or `jsr:`, in a URL
such as `https://esm.sh/@modelcontextprotocol/sdk/server/mcp.js`, in a path into
`node_modules`, with a version after the package name, with a query or fragment
such as `?bundle`, percent-encoded, with backslashes or in another letter case. The
path segments after the package name, up to any query or fragment, tell a server
module from a client module. `McpServer` is collected only from the
two module names above; imported from any other spelling, it is a gap, and the
other gaps below apply to every spelling.

## Gaps

The uses of the SDK below are coverage gaps that name the file and line, so the
`mcp` collector is `partial` and the default gates fail. For the project in
`tests/fixtures/mcp-source-gaps`,

```bash
nexus-symbiote scan tests/fixtures/mcp-source-gaps --check
```

fails the scan gate and lists one gap for each file other than `src/server.ts`,
whose server and tool `read_note` are inventoried. The server in `src/plugins.mjs`
is inventoried too, with no tools: what the plugin it loads registers is behind
its gap.

```text
  - excluded: src/agent.ts:5 (MCP server launched from application code; launcher not inventoried) (from mcp)
  - excluded: src/deno.ts:1 (unsupported MCP SDK import) (from mcp)
  - excluded: src/index.ts:1 (MCP SDK class re-exported; servers it builds, starts or reaches elsewhere not inventoried) (from mcp)
  - excluded: src/legacy.ts:1 (low-level MCP server tool list uncollected) (from mcp)
  - excluded: src/plugins.mjs:4 (require or dynamic import of a module name the analysis cannot read; what it loads not inventoried) (from mcp)
  - excluded: src/server.cjs:1 (MCP server SDK loaded by require or dynamic import; servers and tools not inventoried) (from mcp)
```

- A module load of a server module: `require(...)`, `import(...)`,
  `module.require(...)`, a call of a loader that `createRequire` made, `require.call`
  and `require.apply`, and TypeScript's `import x = require(...)`. The same for a
  client module of the SDK is
  `MCP client SDK loaded by require or dynamic import; servers it starts or reaches not inventoried`.
- A module load of a name the analysis cannot read, such as `require(name)`, a
  concatenation or a template literal with a substitution:
  `require or dynamic import of a module name the analysis cannot read; what it loads not inventoried`.
- Any other call whose first argument names a server or client module, such as a
  loader of the file's own:
  `MCP SDK module named as a call argument; what the call loads not inventoried`.
- A re-export of `McpServer`, of the low-level `Server`, of a client transport, of
  the `default` of a server or client module, or of a whole server or client module
  (`export * from`).
- `McpServer` imported from any other module path of the SDK, such as one without
  the `.js` extension, with a version, after `npm:`, in a URL or in a path into
  `node_modules`, and a default import of a server or client module, also written
  `import { default as sdk }`: `unsupported MCP SDK import`.
- A use of the server class other than constructing it: an alias
  (`const Factory = McpServer`), a subclass, a parenthesized constructor, a value
  passed, exported or compared with `instanceof`, or a JSX element. Names inside type
  syntax, such as `typeof McpServer` or an annotation, are not uses.
- A namespace import of a server or client module used other than through a
  static member, such as `sdk[name]`, `const { McpServer } = sdk` or
  `sdk.default`, which CommonJS interop can make the whole module:
  `unsupported use of an MCP SDK namespace`.
- The low-level `Server` class of a server module, whose tool list is built at run
  time.
- A client transport that starts a server (`StdioClientTransport`) or reaches one
  (`SSEClientTransport`, `StreamableHTTPClientTransport`,
  `WebSocketClientTransport`), used other than in type syntax. The server it starts
  or reaches is not inventoried; a launch configuration in a client file is.
- A direct `eval` in a file with SDK imports, because the code it runs can use them,
  also parenthesized or wrapped in TypeScript syntax, as in `(eval)(code)` or
  `eval!(code)`.
- Dynamic method names, receiver aliases, unsupported constructor bindings and
  registration ordering.

These leave no gap:

- The SDK reached through an alias resolved outside the file, such as a
  `package.json` subpath import (`import { McpServer } from "#mcp"`), a tsconfig
  `paths` entry, an import map or a bundler alias, or through a copy of the SDK at a
  path without `@modelcontextprotocol/` in it. The file is not parsed, or the module
  it names is not recognized.
- A file whose text spells the SDK only with escape sequences or percent-encoding,
  such as `@modelcontextprotocol\u002fsdk`.
- A module loader called in any way other than directly or through `call` or
  `apply`, such as through an alias of `require`, `Reflect.apply`, `new Function` or
  an indirect `eval`.
- What code does with a collected server other than register tools by a literal
  `tool` or `registerTool` call: its low-level `server.server`, as in
  `server.server.setRequestHandler(...)`; `tool` or `registerTool` reached through
  `bind`, `call` or `apply`, or replaced by a wrapper; and the server passed to a
  function, returned or exported, after which code in a file that does not name the
  SDK can register tools on it. The server is inventoried with the tools registered
  in the supported form only. Within a parsed file, a registration on a receiver the
  analysis cannot resolve is still a gap.
- Servers built with other frameworks.

The analysis reads a `var` declaration as scoped to its block, like `let`.

## Limits

Collection shares the MCP scanner's pinned filesystem root, path exclusions and
I/O budgets. It traverses no symbolic links. The text read to find candidate files
counts toward the MCP collector's [`source-scan-bytes`
budget](collection-limits.md#limits), 64 MiB by default. Each parsed file is also
bounded by `syntax-bytes` (256 KiB) and `ts-nodes` (20,000 syntax nodes), by 1,000
registration calls, and by a 250 ms native parse timeout and a 2 s analysis
deadline, which grow in proportion when an operator raises `syntax-bytes` or
`ts-nodes`. Declaration files (`.d.ts`, `.d.mts`, `.d.cts`), test files
(`.test.` or `.spec.` before any of these suffixes), generated build directories and
directories named `docs`, `benchmarks` or `examples` are outside this collector's
supported scope. Limits, invalid TypeScript, absent or incompatible parser
dependencies and unreadable input produce collection failures that name the cause.

The parser dependencies are installed with the product. CI pins their versions
and package hashes alongside the existing environment. A damaged, incomplete or
incompatible installation, such as a tree-sitter release without the native parse
timeout, reports a parser-dependency failure when relevant MCP TypeScript or
JavaScript source is encountered.

The tree-sitter runtime and its TypeScript grammars are native code, and they parse
candidate files inside the scanning process. The size, node and time bounds limit
how long that takes; they do not isolate the parser. A memory-safety defect in it
would run with the scan's privileges, so scan untrusted repositories without
deployment or publication credentials, as the [security policy](../SECURITY.md#security-boundaries)
advises. The binding is held to the 0.25 release line, because later releases
remove the native timeout this collector relies on.
