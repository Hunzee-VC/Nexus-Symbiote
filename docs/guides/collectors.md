# Collectors

Collectors are the self-writing layer: they turn the artefacts an agent is actually built from (client
configurations, instruction files, model directories, traces, live `tools/list` responses) into AgentBOM
entities, edges, evidence and **coverage**. This guide says what is collected from which files on this branch,
how the coverage semantics work, and how the observed-layer collectors are driven today. The normative contract
and the full collector table are in [`spec/collectors.md`](../spec/collectors.md).

## The contract

A collector implements `symbiote.collect.base.Collector`: `name`, `version`, `surfaces` (which of the ten
coverage surfaces it is responsible for), `mode` (`declared` or `observed`), `detect(ctx) -> bool` and
`collect(ctx) -> CollectionResult` (entities, parties, edges, evidence, per-surface coverage fragments,
redactions, warnings). Four rules are enforced by the runner rather than left to each collector:

- **Every fact carries assurance and a locator.** `.mcp.json#/mcpServers/github`, `.codex/config.toml#/mcp_servers/github`
  and `live:server:fixture:tools/list` are locators you will see in the output; a reviewer can go to the exact
  place a fact came from.
- **Secret values are never read into entities.** Environment-variable and header *names* are kept; an inline
  literal secret becomes a `static-long-lived` credential binding stored in a file plus a redaction record; a
  credential in a URL's userinfo or query string is dropped with a warning.
- **Unknown is not absence.** A collector that is skipped, times out or crashes still contributes a coverage
  fragment (`not-attempted`, `partial` with the error class, `unreachable`, `permission-denied`), never an empty
  "nothing found". Each collector runs under a wall-clock budget (20 s by default) so a hostile input cannot
  stall a scan.
- **Nothing from the scanned repository is executed.** Configurations are parsed, not imported; the live
  collector launches a server process only when its id is on an explicit allowlist.

Third-party collectors register under the `symbiote.collectors` entry-point group and are loaded alongside the
built-ins; a built-in whose module is not installed is skipped with a warning, which is how packages land
independently.

## What `symbiote scan` runs on this branch

| Collector | Mode | Surface | Status here |
|---|---|---|---|
| `mcp-config` | declared | tools | **runs**: MCP servers from client configuration files (below) |
| `mcp-live` | observed | tools | module present; runs through the Python API with `options={"live": True, "live_servers": […], "live_allow": […]}`; `scan --live` is specified, not wired |
| `otel-traces` | observed | runtime | module present; Python API with `options={"otel_files": […]}` |
| `mcp-registry` | observed | registry | module present; Python API with `options={"registry": True, "registry_targets": […]}` (network, or an injected `http_get`) |
| `k8s-aibom` importer | observed | model-gateway, runtime | `symbiote.imp.k8s_aibom.import_k8s_aibom(document_or_cr)`; no CLI command yet |
| `instructions`, `skills`, `frameworks`, `models-hosted`, `models-local`, `a2a-cards`, `identity-config`, `sbom-merge` | declared | instructions, code, model-gateway, identity, policy | **specified** ([`spec/collectors.md`](../spec/collectors.md)); the modules are being built in work package WP9 and are listed in `BUILTIN_COLLECTORS` so they run as soon as they land |

This is why the example scan reports `coverage: tools=partial (other surfaces: not-attempted)` and
`collectors: mcp-config:ok, mcp-live:skipped, mcp-registry:skipped, otel-traces:skipped`: the three observed
collectors are present but their `detect()` requires options the CLI does not set yet, and the static collectors
are not installed on this branch. Nothing is reported as examined that was not.

## `mcp-config`: MCP servers from client configuration

The collector reads every supported client's configuration at project scope (and at user scope with
`--user-scope`), one `ToolServer` per configured server. Client formats are a data table, so adding a client is a
table entry plus a fixture:

| Client | Project-scope file | User-scope file (`--user-scope`) | Server map | Notes |
|---|---|---|---|---|
| Claude Code | `.mcp.json` | `~/.claude.json` (including `projects[<this path>].mcpServers`) | `mcpServers` | `.claude/settings.json` / `settings.local.json` supply `permissions.allow` (`mcp__server__tool`), `permissions.defaultMode`, `enableAllProjectMcpServers` |
| Claude Desktop | — | `<app config>/Claude/claude_desktop_config.json` | `mcpServers` | |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` | `mcpServers` | |
| VS Code | `.vscode/mcp.json` (JSONC) | `<app config>/Code/User/mcp.json`, `Code - Insiders/User/mcp.json` | `servers` | `.vscode/settings.json` supplies `chat.tools.autoApprove`, `chat.tools.global.autoApprove`, `chat.agent.enabled` |
| Windsurf | — | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` | URL key `serverUrl`; `disabledTools` |
| Codex | `.codex/config.toml` | `~/.codex/config.toml` | `[mcp_servers.<name>]` | `bearer_token_env_var`, `enabled_tools`/`disabled_tools`, timeouts; global `approval_policy`, `sandbox_mode`, `sandbox_workspace_write.network_access` |
| Gemini CLI | `.gemini/settings.json` | `~/.gemini/settings.json` | `mcpServers` | URL key `httpUrl`; `trust`, `includeTools`, `excludeTools`, `timeout`; global `autoAccept` |

`<app config>` is `~/Library/Application Support` on macOS, `%APPDATA%` on Windows and `$XDG_CONFIG_HOME` or
`~/.config` on Linux. Without `--user-scope` the user-scope locations are recorded as a `not-attempted` source,
so a CI scan never silently reads the runner's home directory and never pretends it did.

**Transport** follows one rule: a `command` means `stdio`; otherwise an explicit `type` (`http`, `sse`, `stdio`,
`ws`, …); otherwise `httpUrl` means `streamable-http`; otherwise a URL ending in `/sse` means `sse` and anything
else `streamable-http`. Remote endpoints are classified into a trust zone (`external`, `internal`, `loopback`, …)
and `crosses_trust_boundary`; stdio servers are `local-process`.

**Package identity and pinning** come from the launch command without executing it
(`symbiote.collect.launchers`): `npx`/`pnpx`/`bunx`/`npm exec`/`pnpm dlx`/`yarn dlx` → `pkg:npm`, `uvx`/`uv tool run`/`pipx run`
→ `pkg:pypi`, `docker`/`podman`/`nerdctl run` → `pkg:oci`, `dnx`/`dotnet dnx` → `pkg:nuget`, `deno run npm:|jsr:`, `go run`.
A reference is **pinned** only when it is immutable: an exact npm/PyPI/NuGet version (`@1.2.3`, `==1.2.3`), a full
40-hex git commit, or an OCI `@sha256:` digest. Dist-tags (`@latest`, `@next`), ranges, missing versions, git branches,
URLs and every OCI *tag* float, and the reason is recorded (`float:dist-tag:latest`, `float:no-version`,
`float:mutable-tag:1.2.3`, `float:range`, `float:url`, `float:git-ref`). Container launches are also scanned for
`--privileged`, host namespaces, `docker.sock` or host-root mounts, added capabilities and root users
(`SYM-MCP-007`).

What one server looks like in the companion (the `filesystem` server of the example, launched with
`npx -y @modelcontextprotocol/server-filesystem@latest`):

```json
{
  "id": "server:claude-code-filesystem",
  "name": "filesystem",
  "kind": "mcp",
  "client": "claude-code",
  "command": "npx",
  "argsDigest": "sha256:ac0d9a1e0671335158b9bf27ba17968306734566849d8eac5e68a4efa2ba1ece",
  "transport": {"value": "stdio", "state": "present", "assurance": "declared", "method": "config",
                "locator": ".mcp.json#/mcpServers/filesystem", "collector": "collector:mcp-config@0.1.0", "…": "…"},
  "package": {"value": {"purl": "pkg:npm/%40modelcontextprotocol/server-filesystem", "floating": true, "launcher": "npx"},
              "state": "present", "assurance": "declared", "…": "…"},
  "envVarNames": ["FS_ROOT"],
  "headerNames": [],
  "authentication": {"value": {"mode": "none", "scopesRequested": []}, "…": "…"},
  "trustZone": "local-process",
  "crossesTrustBoundary": {"value": false, "…": "…"},
  "clientTrustFlags": {"launcher": "npx"},
  "digest": "sha256:f04220a451aae540636f80bc6ab054e0cc667e7a8da9833f23011d335c207cfc",
  "tags": ["scope:project", "float:dist-tag:latest"]
}
```

Every contestable field is a `Claim` with `assurance`, `method`, `locator` and `collector`; `digest` is the
`server/v1` identity over kind, transport, normalised endpoint and package. The argument *shape* is kept as
`argsDigest` (over the redacted argv), the values are not.

**Credentials.** For every environment variable or header whose name looks credential-bearing, or whose value is
a placeholder (`${GITHUB_PAT}`) or an inline literal, the collector emits an `Identity` of kind `api-key-ref`
(`ref: "header:Authorization"`, `"env:GITHUB_PAT"`), a `CredentialBinding` (kind `unknown` for placeholders,
`static-long-lived` with tag `inline-secret-in-config` for literals, storage `env`, `keychain` for VS Code
`${input:…}`, or `file`) and a `holdsCredential` edge; literals also add a `credential-shaped-token` redaction
record. Authentication mode is `api-key` when an auth header or Codex `bearer_token_env_var` is configured,
`oauth2` when an OAuth block is present, `none` for stdio, and `unknown` (`not-collected`) for a remote server
whose configuration says nothing — MCP authorization is often negotiated at connect time, and a configuration
file cannot tell.

**Client trust settings** are copied into `clientTrustFlags` so policy can read them: Claude Code's per-server
`permissions.allow` rules and `defaultMode` (`bypassPermissions` fires `SYM-HITL-001`), VS Code
`chat.tools.autoApprove`, Gemini `trust` / `includeTools` / `excludeTools`, Codex `approval_policy` and
`sandbox_mode`. Tool names a client enumerates (`includeTools`, `enabled_tools`) become declared `ToolDefinition`
records whose digest is `undigestable` with reason `declared-without-definition`: a name is configured, the
definition the model will read is not, and only live observation can pin it.

## Coverage semantics

Every document carries a `Coverage` object with **all ten surfaces** — `code, registry, identity, model-gateway,
tools, data, runtime, network, instructions, policy` — each with a status and the source records it was derived
from:

| Status | Meaning |
|---|---|
| `queried` | every source for the surface was read successfully |
| `partial` | some sources succeeded and some failed, or a collector timed out |
| `permission-denied` / `unreachable` | every source failed with that error class |
| `truncated` | a listing was cut short (for example more than 64 `tools/list` pages); `truncatedAt` says where |
| `not-attempted` | no collector examined the surface (or it was skipped) |

A collector records a `SourceRun` per source it touched (`source`, `locator`, `ok`, `errorClass`, `items`); if it
does not set a status explicitly, the runner derives one from those records. When two collectors report on one
surface, the less complete status wins (`queried` + `queried` stays `queried`; any failure degrades it; a
`not-attempted` fragment never masks a fragment that ran). The example scan's tools surface:

```json
"tools": {
  "status": "partial",
  "itemsSeen": 7,
  "sources": [
    {"source": "claude-code:project", "locator": ".mcp.json", "ok": true, "items": 3},
    {"source": "cursor:project", "locator": ".cursor/mcp.json", "ok": true, "items": 1},
    {"source": "codex:project", "locator": ".codex/config.toml", "ok": true, "items": 2},
    {"source": "gemini-cli:project", "locator": ".gemini/settings.json", "ok": true, "items": 1},
    {"source": "user-scope", "ok": false, "errorClass": "not-attempted", "items": 0},
    {"source": "locations-checked", "locator": "5", "ok": true, "items": 0}
  ]
}
```

It is `partial` because user scope was not attempted, which is the honest answer in CI. Coverage drives
`SYM-COV-001` (surfaces not covered), `SYM-COV-002` (absence claimed on a surface that was not queried), the
Verified conformance level (`AB-VER-07`: all surfaces queried), and the `indeterminate` state of every check whose
inputs live on an unexamined surface. In CycloneDX the surfaces become `compositions[]` entries (`aggregate:
unknown | incomplete | complete`) and `agentbom:coverage:<surface>` properties; in SPDX, relationships to
`NoAssertionElement` with `completeness: noAssertion` and a `Coverage` extension on the `software_Sbom` (see the
[format pages](../formats/cyclonedx.md)).

## The observed layer through the Python API

The observed collectors exist and are tested; until `scan --live`, `--registry` and an OTel option are wired,
they run through `symbiote.collect.run_collectors` with options on the `CollectContext`. The two snippets below
were executed against the repository fixtures.

### OpenTelemetry GenAI traces

```python
from datetime import UTC, datetime
from pathlib import Path

from symbiote.collect import CollectContext, run_collectors
from symbiote.collect.otel import OtelTracesCollector

root = Path("examples/triage-agent").resolve()
ctx = CollectContext(root=root, agent_id="agent:triage-agent", now=datetime(2026, 11, 1, tzinfo=UTC),
                     options={"otel_files": [str(root / "traces" / "otel-genai.json")]})
[result] = run_collectors(ctx, [OtelTracesCollector()])
```

```text
status: ok warnings: []
coverage: {'runtime': 'queried'}
  ToolServer       server:observed
  ToolDefinition   tool:observed/add_issue_comment state=invoked source=trace digest=undigestable
  ToolDefinition   tool:observed/get_issue state=invoked source=trace digest=undigestable
  ToolDefinition   tool:observed/search_code state=invoked source=trace digest=undigestable
  Agent            agent:triage-agent
  edge invokesTool  agent:triage-agent -> tool:observed/add_issue_comment assurance=observed count=1
  edge invokesTool  agent:triage-agent -> tool:observed/get_issue assurance=observed count=1
  edge invokesTool  agent:triage-agent -> tool:observed/search_code assurance=observed count=1
  edge spawns       agent:triage-agent -> agent:triage-agent assurance=observed count=None
  evidence trace-summary sha256:e5c49d8443455af7b4adbfc4d912820639f3ccd0f13ab95210fbc031b05bfe61
```

The collector reads OTLP/JSON (`resourceSpans`) or JSONL span files offline. `execute_tool` spans become invoked
tool definitions with counts and first/last-seen (the digest is `undigestable` unless the instrumentation
captured `gen_ai.tool.definitions`, because a trace carries a name, not the definition the model read);
`chat`/`embeddings` spans become hosted models, and a `gen_ai.response.model` that differs from the request
(`claude-sonnet-4-5` → `claude-sonnet-4-5-20250929` in the fixture) is recorded in the trace summary so a diff
against the declared snapshot yields `model-routed`; `invoke_agent`/`create_agent` spans become `spawns` edges;
`gen_ai.data_source.id` and `gen_ai.memory.store.id` become observed data sources; `gen_ai.system_instructions`
is hashed, never stored. Resource attributes `agentbom.snapshot.digest` and `agentbom.deployment.id` tie the
trace to the snapshot that was active. Note `search_code`: it was invoked but is declared nowhere, which is the
`undeclared-component-observed` finding once this result is diffed against the declared snapshot.

### Live `tools/list` from an MCP server

The live collector speaks newline-delimited JSON-RPC to a stdio server itself, so digests are computed over
the **raw wire objects** rather than an SDK's re-serialisation; the gateway sees raw JSON and so must the BOM.
It launches a process only for servers on `live_allow`, passes environment values through without recording
them, fetches every `tools/list` page, and gives each server a deadline (15 s by default). Remote transports
(`streamable-http`, `sse`) are not attempted in this version and are recorded as an `unsupported-source` coverage
gap rather than a silent absence. Against the repository's fixture server (`tests/fixtures/mcp_fixture_server.py`,
which has drift modes):

```python
from symbiote.collect import CollectContext, run_collectors
from symbiote.collect.mcp_live import McpLiveCollector

spec = {"id": "server:fixture", "name": "fixture", "transport": "stdio",
        "command": sys.executable, "args": [str(fixture), "--drift", drift]}
ctx = CollectContext(root=repo, agent_id="agent:demo", deterministic=True,
                     options={"live": True, "live_servers": [spec], "live_allow": ["server:fixture"],
                              "live_deadline_seconds": 20})
[result] = run_collectors(ctx, [McpLiveCollector()])
```

```text
--- drift=none: status=ok warnings=[]
  server server:fixture toolset=sha256:d5db7d7dadacc7227a550d01c3074f5d4b5da39a5a0c5883a30f090719283995 protocol=2025-06-18
  tool tool:fixture/get_issue source=served-live digest=sha256:7f52fb600ba75495368c1cbfe739b49f0d8ebcad86682563d764ab718900b103 flags=[]
  tool tool:fixture/add_label source=served-live digest=sha256:6b65f84a9f7286a3f6538b64e8aef16912558ceabdd7519c77d0b63d5ff1b178 flags=[]
--- drift=description: status=ok warnings=[]
  server server:fixture toolset=sha256:07c8f20393369b42fc4894cd10c4b86d211362898fdc9995bbbc3c21cc4c8cb6 protocol=2025-06-18
  tool tool:fixture/get_issue source=served-live digest=sha256:9b8d8c0c24fe818845cc47d8cd2e108fbd6f252acecae03c4e483f82012da8fd flags=['cross-tool-directive']
  tool tool:fixture/add_label source=served-live digest=sha256:6b65f84a9f7286a3f6538b64e8aef16912558ceabdd7519c77d0b63d5ff1b178 flags=[]
--- diff none -> description
  critical tool-definition-changed    tool:fixture/get_issue before=sha256:7f52fb60… after=sha256:9b8d8c0c…
--- diff none -> order (reordered list): 0 event(s)
--- diff none -> pagination (one tool per page): 0 event(s)
--- unicode drift text flags: [[], ['hidden-unicode']]
```

Four facts are visible here. A changed description changes the tool's digest and the server's `toolset/v1`
digest (`tool-definition-changed`, critical). Reordering the list or splitting it across pages changes neither,
because `toolset/v1` sorts by name after fetching all pages. The drifted description also trips the
`cross-tool-directive` text lint (`SYM-TOOL-009`), and zero-width or tag characters smuggled into a description
trip `hidden-unicode` (`SYM-TOOL-006`). Writing the two results as companions and diffing them with the CLI gives
the same verdict:

```text
$ symbiote diff observed-none.agentbom.json observed-description.agentbom.json --fail-on-change tool-definition-changed
2 event(s): sha256:f47fff501f7f… (observed) -> sha256:4c8d5d63f966… (observed)
high     server-identity-changed      server:fixture  server facts outside server/v1 changed (command shape, env/header names, authent…
critical tool-definition-changed      tool:fixture/get_issue  model-visible description changed (schema unchanged)
$ echo $?
1
```

(The `server-identity-changed` event is honest too: the two runs launched the fixture with different `--drift`
arguments, so the argument shape changed.) The observed baseline exports directly as an allowlist:
`symbiote allowlist export observed-none.agentbom.json --format mcp-gateway-generic` lists `get_issue` and
`add_label` with their digests and gates.

### Registry resolution and k8s-aibom import

`McpRegistryCollector` takes `options={"registry": True, "registry_targets": [{"server_id", "name",
"package_purl" | "remote_url"}], "http_get": callable}` and produces a `RegistryResolution` per target from
`GET /v0/servers?search=<name>` on `registry.modelcontextprotocol.io` (or `registry_base`): entry id and version,
status, publisher verification inferred from the namespace (`io.github.*` ⇒ GitHub OIDC; reverse-DNS ⇒ DNS/HTTP),
typosquat distance to well-known names, and `signer: unsigned` because the registry has no attestation fields.
An unreachable registry yields coverage `registry: unreachable` **and** a resolution with `state: unknown`, never
"not registered". `http_get` is injectable, which is how the tests run offline.

`import_k8s_aibom(document, agent_id=…, now=…)` accepts a k8s-aibom CycloneDX 1.6 ML-BOM or an `AIBOM` custom
resource (`status.bomDocument.inline.data`, base64; a URL reference is rejected with guidance rather than
fetched) and maps per-attribute confidence to assurance: `declared → declared`, `inferred → observed`
(`method: heuristic`, confidence 0.5), `unresolved → state: unknown`, and `verified → verified` **only** when the
document carries a signer identity and a non-empty constraint record — otherwise `observed` plus the recorded
fact `imported-verified-without-constraint`. Unmapped `aibom.*` / `k8s-aibom:*` properties are kept verbatim as
foreign properties and `aibom.redaction.applied` becomes a redaction record.

## Writing a collector

Subclass `symbiote.collect.base.BaseCollector`, set `name`, `version`, `surfaces` and `mode`, implement
`detect()` and `collect()`, and call `result.add_source(surface, source, locator=…, ok=…, items=…)` for every
source you touch; the runner derives the surface status from those records and fills `not-attempted` for the
rest. Put facts in `Claim`s with a locator, never read secret values, never execute scanned content, and
register the class under the `symbiote.collectors` entry-point group. The spec row for each planned collector
([`spec/collectors.md`](../spec/collectors.md)) lists the exact inputs and parsing rules it must follow, and every
supported format needs a fixture.
