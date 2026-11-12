# Static TypeScript MCP inventory

The MCP scanner collects literal `tool` and `registerTool` names from TypeScript
servers constructed through a named `McpServer` import from
`@modelcontextprotocol/server` or `@modelcontextprotocol/sdk/server/mcp.js`.
Import aliases and lexically bound server factories are supported. Type-only
imports, shadowed constructor parameters and shadowed server variables do not
establish SDK server bindings.

Each tool record has declared assurance, a digest of its registration call
(`registration_source_sha256`) and a digest of the whole declaring file
(`source_sha256`), so editing a handler defined elsewhere in that file changes the
inventory. Handlers imported from other modules are not covered. The scanner
does not execute source code, evaluate schemas or callbacks, establish that a
factory ran, or construct a tool-definition fingerprint. Effective descriptors
and runtime registration remain unknown; compare observed descriptors separately
before approving a live call.

Collection shares the MCP scanner's pinned filesystem root, path exclusions and
I/O budgets. It traverses no symbolic links. Only `.ts` files that contain both
`@modelcontextprotocol/` and `McpServer` are parsed, however many there are; the
text read to find them counts toward the MCP collector's [`source-scan-bytes`
budget](collection-limits.md#limits), 64 MiB by default. Each file is also bounded
by `syntax-bytes` (256 KiB) and `ts-nodes` (20,000 syntax nodes), by 1,000
registration calls, and by a 250 ms native parse timeout and a 2 s analysis
deadline, which grow in proportion when an operator raises `syntax-bytes` or
`ts-nodes`. Declaration files, test files, generated build directories and
directories named `docs`, `benchmarks` or `examples` are outside this collector's
supported scope. Limits, invalid source, absent or incompatible parser
dependencies and unreadable input produce collection failures that name the cause.
Dynamic names, receiver aliases, unsupported binding forms and registration
ordering leave explicit coverage gaps.

The parser dependencies are installed with the product. CI pins their versions
and package hashes alongside the existing environment. A damaged, incomplete or
incompatible installation, such as a tree-sitter release without the native parse
timeout, reports a parser-dependency failure when relevant MCP TypeScript source
is encountered.

The tree-sitter runtime and its TypeScript grammar are native code, and they parse
candidate files inside the scanning process. The size, node and time bounds limit
how long that takes; they do not isolate the parser. A memory-safety defect in it
would run with the scan's privileges, so scan untrusted repositories without
deployment or publication credentials, as the [security policy](../SECURITY.md#security-boundaries)
advises. The binding is held to the 0.25 release line, because later releases
remove the native timeout this collector relies on.
