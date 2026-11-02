# Static TypeScript MCP inventory

The MCP scanner collects literal `tool` and `registerTool` names from TypeScript
servers constructed through a named `McpServer` import from
`@modelcontextprotocol/server` or `@modelcontextprotocol/sdk/server/mcp.js`.
Import aliases and lexically bound server factories are supported. Type-only
imports, shadowed constructor parameters and shadowed server variables do not
establish SDK server bindings.

Each record has declared assurance and a source-registration digest. The scanner
does not execute source code, evaluate schemas or callbacks, establish that a
factory ran, or construct a tool-definition fingerprint. Effective descriptors
and runtime registration remain unknown; compare observed descriptors separately
before approving a live call.

Collection shares the MCP scanner's pinned filesystem root, path exclusions and
I/O budgets. It traverses no symbolic links. TypeScript collection has limits of
50 source files, 262,144 bytes per file, 20,000 syntax nodes and 1,000 registration
calls per file, plus a 250 ms native parse timeout. Declaration files, test files
and generated build directories are outside this collector's supported scope.
Limits, invalid source, absent parser dependencies and unreadable input produce
collection failures. Dynamic names, receiver aliases, unsupported binding forms
and registration ordering leave explicit coverage gaps.

The parser dependencies are installed with the product. CI pins their versions
and package hashes alongside the existing environment. A damaged or incomplete
installation reports a parser-dependency failure when relevant MCP TypeScript
source is encountered.
