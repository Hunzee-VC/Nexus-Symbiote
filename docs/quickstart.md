# Quickstart

## Install

```bash
uv tool install symbiote        # or: pipx install symbiote
# from a checkout:
uv venv .venv && source .venv/bin/activate && uv pip install -e ".[dev]"
```

Optional extras: `symbiote[sign]` (Sigstore keyless signing), `symbiote[models]` (OpenSSF model-signing
manifests), `symbiote[mcp]` (live MCP collectors).

## Digest a tool definition exactly as a gateway would

Save the raw `tools/list` entry of an MCP tool as `tool.json` and run:

```bash
symbiote digest tooldef tool.json --json
```

```json
{
  "algorithm": "tooldef/v1",
  "value": "sha256:…",
  "status": "ok",
  "textFlags": []
}
```

The digest covers the model-visible surface — `name`, `title`, `description`, `inputSchema`, `outputSchema`,
`annotations` — over RFC 8785 canonical JSON. A definition that cannot be canonicalized (NaN, integers beyond
2^53, duplicate keys) is reported as `undigestable` and exits non-zero: Symbiote never guesses.

## Build, validate and verify a document (Python)

```python
from datetime import UTC, datetime

from symbiote.export.companion import companion_bytes
from symbiote.model import Claim, DigestResult, Edge, Producer, enums as E
from symbiote.model.entities import Agent, Authentication, ToolDefinition, ToolServer
from symbiote.snapshot import finalize, new_document, verify_document

agent = Agent(id="agent:triager", name="triager", version="1.0.0", role=E.AgentRole.ROOT)
server = ToolServer(
    id="server:github", kind=E.ToolServerKind.MCP,
    transport=Claim.declared(E.Transport.STDIO, locator=".mcp.json#/mcpServers/github/command"),
    authentication=Claim.declared(Authentication(mode=E.AuthMode.API_KEY)),
    crosses_trust_boundary=Claim.declared(True), env_var_names=["GITHUB_TOKEN"],
)
tool = ToolDefinition(
    id="tool:github/get_issue", server_ref="server:github", tool_name="get_issue",
    input_schema={"type": "object"}, digest=DigestResult(algorithm="tooldef/v1", value="sha256:" + "ab" * 32),
    source=E.ToolSource.DECLARED_CONFIG,
)
doc = new_document(
    subject="agent:triager", producer=Producer(version="0.1.0"), kind=E.SnapshotKind.DECLARED,
    produced_at=datetime.now(UTC), agents=[agent], tool_servers=[server], tools=[tool],
    edges=[Edge(type=E.EdgeType.PROVIDES_TOOL, **{"from": "server:github", "to": "tool:github/get_issue"})],
)
bom = finalize(doc)                     # salted Merkle commitment; snapshot digest = root
assert verify_document(bom)
open("agentbom.json", "wb").write(companion_bytes(bom))
```

```bash
symbiote validate agentbom.json
symbiote merkle verify agentbom.json
```

## Sign and verify the snapshot

```bash
openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt -out key.pem
openssl ec -in key.pem -pubout -out key.pub

symbiote attest snapshot agentbom.json --key key.pem -o snapshot.dsse.json
symbiote verify snapshot.dsse.json --public-key key.pub --companion agentbom.json
```

The statement is in-toto v1 with predicate type
`https://aisecnomad.github.io/symbiote/attestation/agentbom-snapshot/v1`; its subject is the Merkle root, so any
change to any entity invalidates it, while a redacted copy of the document still verifies.

## What comes next

`symbiote scan .` (zero-config collection from MCP client configs, skills, instruction files, framework
configs, models and SBOMs), CycloneDX 1.7 and SPDX 3.0.1 export, policy checks and conformance levels are being
built in parallel work packages — see the status table in the README.
