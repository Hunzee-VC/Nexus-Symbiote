# ShadowScan approved-inventory fixtures

`declared-agent.aibom.json` and `unnamed-agent.aibom.json` are native inventories that
`nexus-symbiote scan --no-project-policy --report-only` wrote for two synthetic projects.
Both projects hold this `.mcp.json`:

```json
{"mcpServers": {"docs": {"command": "npx", "args": ["-y", "docs-mcp@1.2.3"]}}}
```

The declared project also holds this `agent.yaml`; the unnamed project has none:

```yaml
id: acme:support-triager
name: support-triager
version: "1.4"
purpose: Triage inbound support tickets
framework: langgraph
owner: platform-security
autonomy_level: L2-agent
```

`simple-list.json` and `simple-list-unnamed.json` are the exact bytes that
`export-inventory` writes for them:

```sh
nexus-symbiote export-inventory declared-agent.aibom.json --format shadowscan-simple \
  --resource-prefix github:acme/support-triager -o simple-list.json
nexus-symbiote export-inventory unnamed-agent.aibom.json --format shadowscan-simple \
  --resource-prefix github:acme/support-triager --include-unnamed -o simple-list-unnamed.json
```

Each was loaded with `shadowscan.registry.Inventory.load` from Nexus-ShadowScan commit
`999bef1a277cfbcdc44fdbca925e54c07efa278d` while this change was developed; the tests do not
import ShadowScan. Never regenerate a golden file to make a test pass: a changed byte is a
changed approval.
