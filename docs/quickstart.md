# Quickstart

Every command below was run against the example agent in `examples/triage-agent`; the outputs are real, with
long lines trimmed. The [CLI reference](reference/cli.md) has every flag and exit code.

## Install

```bash
uv tool install symbiote        # or: pipx install symbiote
# from a checkout:
uv venv .venv && source .venv/bin/activate && uv pip install -e ".[dev]"
symbiote version                # symbiote 0.1.0 (AgentBOM profile 0.1)
```

Optional extras: `symbiote[sign]` (Sigstore keyless signing), `symbiote[models]` (OpenSSF model-signing
manifests), `symbiote[mcp]` (MCP SDK transports for live collectors).

## Scan a repository

```bash
symbiote scan examples/triage-agent -o out/ --deterministic
```

```text
agent:triage-agent  snapshot sha256:1672f9d2fa7b0364…  (declared, serial 1)
entities: agents=1, tool_servers=7, identities=3, credential_bindings=3, parties=1
coverage: tools=partial  (other surfaces: not-attempted)
collectors: mcp-config:ok, mcp-live:skipped, mcp-registry:skipped, otel-traces:skipped
written: out/agentbom.json
written: out/agentbom.cdx.json
written: out/agentbom.spdx.json
policy: 11 failing finding(s), 2 indeterminate — run `symbiote policy check out/agentbom.json` for details
  high     SYM-MCP-002  server:claude-code-filesystem  Server 'filesystem' launches pkg:npm/%40modelcontextprotocol/server-filesystem without pin…
  high     SYM-TOOL-001  server:claude-code-github  Server 'github': no tool definition is pinned (tools were never observed or approved).
  …
CycloneDX 1.7 validates against the official schema
SPDX 3.0.1 validates against the official schema
```

`out/agentbom.json` is the **companion document** (the structured source of truth), `out/agentbom.cdx.json` is
CycloneDX 1.7 and `out/agentbom.spdx.json` is SPDX 3.0.1 JSON-LD; both are validated against the official
schemas before they are written, and `*.loss.json` reports list every field that had no native home in the
target format. Coverage is honest: on this branch the zero-config scan reads MCP client configurations (Claude
Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex, Gemini CLI); surfaces no collector examined are reported
`not-attempted`, never as clean. Drop `--deterministic` for a random Merkle nonce when you intend to redact the
document later.

## Check, measure, validate

```bash
symbiote policy check out/agentbom.json --sarif out/agentbom.sarif   # exit 1 on `fail` findings at or above --fail-on (default high)
symbiote conformance out/agentbom.json --level minimal                 # pass / fail / unknown per requirement; exit 1 fail, 5 unknown
symbiote score out/agentbom.json                                       # completeness 63/100 — never a trust score
symbiote validate out/agentbom.json out/agentbom.cdx.json out/agentbom.spdx.json
symbiote merkle verify out/agentbom.json
```

```text
$ symbiote validate out/agentbom.json out/agentbom.cdx.json out/agentbom.spdx.json
ok  out/agentbom.json (agentbom-companion)
ok  out/agentbom.cdx.json (cyclonedx-1.7)
ok  out/agentbom.spdx.json (spdx-3.0.1)
$ symbiote merkle verify out/agentbom.json
verified sha256:1672f9d2fa7b0364833f857df21f0930e73ce68f2e051c1c51af466a3146651f
```

Policy checks whose inputs are unknown report `indeterminate` and never pass silently; see
[policy and conformance](guides/policy-and-conformance.md).

## Digest a tool definition exactly as a gateway would

Save the raw `tools/list` entry of an MCP tool as `tool.json` and run:

```text
$ symbiote digest tooldef tool.json --json
{
  "algorithm": "tooldef/v1",
  "value": "sha256:2436ff3a7eff3889c2e071ff658d6db0ca957620ba565f0fae3c80b0052c2c5b",
  "status": "ok",
  "textFlags": []
}
```

The digest covers the model-visible surface — `name`, `title`, `description`, `inputSchema`, `outputSchema`,
`annotations` — over RFC 8785 canonical JSON. A definition that cannot be canonicalized (NaN, integers beyond
2^53, duplicate keys) is reported as `undigestable` and exits 1: Symbiote never guesses.

```text
$ symbiote digest tooldef bad-tool.json
tooldef/v1: UNDIGESTABLE (integer-out-of-range: $.inputSchema.maxItems: |9007199254740993| >= 2^53)
```

## The diff is the finding

Scan twice into the same chain store (each scan gets the next serial and a `prev` link), then diff:

```text
$ symbiote scan examples/triage-agent -o v1/ --deterministic --store store/
$ symbiote scan ./triage-v2 -o v2/ --deterministic --store store/ --name triage-agent   # filesystem server pinned, jira server added
$ symbiote diff v1/agentbom.json v2/agentbom.json --fail-on-change server-identity-changed
2 event(s): sha256:1672f9d2fa7b… (declared) -> sha256:e647954ae86a… (declared)
high     server-added                 server:claude-code-jira  crosses a trust boundary
critical server-identity-changed      server:claude-code-filesystem  server/v1 identity changed (kind, transport, endpoint, package, …)
$ echo $?
1
```

## Sign and verify the snapshot

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem
openssl pkey -in key.pem -pubout -out key.pub

symbiote attest snapshot out/agentbom.json --key key.pem -o snapshot.dsse.json
symbiote verify snapshot.dsse.json --public-key key.pub --companion out/agentbom.json
```

```text
signed https://aisecnomad.github.io/symbiote/attestation/agentbom-snapshot/v1 -> snapshot.dsse.json
verified-constrained https://aisecnomad.github.io/symbiote/attestation/agentbom-snapshot/v1
```

The statement is in-toto v1 with predicate type
`https://aisecnomad.github.io/symbiote/attestation/agentbom-snapshot/v1`; its subject is the Merkle root, so any
change to any entity invalidates it (`digest mismatch`, exit 4), while a redacted copy of the document still
verifies. Add `--store store/` to `verify` and a replayed older snapshot is refused with `SERIAL REGRESSION`
(exit 7). Keyless Sigstore signing with identity constraints is covered in
[attestation and enforcement](guides/attestation-and-enforcement.md).

## Export the allowlist a gateway enforces

```text
$ symbiote allowlist export approved.agentbom.json --format gab -o gab.json
$ symbiote allowlist check gab.json server:github served-tools.json
allow get_issue                      digest-matches-allowlist
allow add_issue_comment              digest-matches-allowlist
$ symbiote allowlist check gab.json server:github served-tools-rugpull.json
block get_issue                      rug-pull-signal: known name, new digest
drop  send_email                     unknown-tool-name
drop  add_issue_comment              approved-tool-missing
```

A known tool name served with a new digest is the rug-pull signal; the gateway blocks it until the toolset is
re-approved.

## Build a document in Python

The same model is available as a library (this is how `approved.agentbom.json` above was produced):

```python
from datetime import UTC, datetime

from symbiote.digest import tooldef_digest
from symbiote.export.companion import companion_bytes
from symbiote.model import Claim, Edge, Producer, enums as E
from symbiote.model.entities import Agent, Authentication, ToolDefinition, ToolServer
from symbiote.snapshot import finalize, new_document, verify_document

raw_tool = {"name": "get_issue", "description": "Get an issue",
            "inputSchema": {"type": "object", "properties": {"number": {"type": "integer"}}, "required": ["number"]}}
agent = Agent(id="agent:triager", name="triager", version="1.0.0", role=E.AgentRole.ROOT)
server = ToolServer(
    id="server:github", kind=E.ToolServerKind.MCP,
    transport=Claim.declared(E.Transport.STDIO, locator=".mcp.json#/mcpServers/github/command"),
    authentication=Claim.declared(Authentication(mode=E.AuthMode.API_KEY)),
    crosses_trust_boundary=Claim.declared(True), env_var_names=["GITHUB_TOKEN"],
)
tool = ToolDefinition(
    id="tool:github/get_issue", server_ref="server:github", tool_name="get_issue",
    input_schema=raw_tool["inputSchema"], digest=tooldef_digest(raw_tool), source=E.ToolSource.APPROVED_FILE,
)
doc = new_document(
    subject="agent:triager", producer=Producer(version="0.1.0"), kind=E.SnapshotKind.APPROVED,
    produced_at=datetime.now(UTC), agents=[agent], tool_servers=[server], tools=[tool],
    edges=[Edge(type=E.EdgeType.PROVIDES_TOOL, **{"from": "server:github", "to": "tool:github/get_issue"})],
)
bom = finalize(doc)                     # salted Merkle commitment; snapshot digest = root
assert verify_document(bom)
open("approved.agentbom.json", "wb").write(companion_bytes(bom))
```
