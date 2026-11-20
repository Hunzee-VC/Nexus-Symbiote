# ShadowScan code report fixtures

The files are unmodified output of `shadowscan code <tree>` from Nexus-ShadowScan
0.1.4 for a synthetic tree. They are compatibility fixtures, not
production scans or evidence of detection accuracy. Do not edit a report by hand:
regenerate it with ShadowScan, so that it stays what the producer writes.

`code-report-0.1.4.json` is described where it is used, in
`tests/test_scoped_collection.py`: a LangChain project with an MCP server, scanned
with ShadowScan commit `1a821e5763e9`.

## agent-framework-report-0.1.4.json

Produced by Nexus-ShadowScan 0.1.4 at commit
`2b80f199659a8de17ea9c7792c07940d5b747d72`. It holds one finding of each of the four
forms below, among them both that projection profile 6 adds, and nothing that stays
unmapped:

| Index | Kind | Resource type | Reported for | Becomes |
| --- | --- | --- | --- | --- |
| 0 | `mcp-server` | `mcp-config` | `.mcp.json` | `mcp-server` |
| 1 | `agent-config` | `coding-agent-config` | Claude Code in the repository root | `ide-agent` |
| 2 | `agent` | `project` | the repository root | `agent` |
| 3 | `framework-usage` | `project` | `services/summarizer` | `agent` |

### The tree

The directory `/work/agent-framework-demo` held these six files and nothing else.

`.mcp.json`

```json
{
  "mcpServers": {
    "docs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "docs"]
    }
  }
}
```

`CLAUDE.md`

```markdown
# Support agent

Answer support tickets from the files under `docs/`. Ask before changing a file.
```

`agent.py`

```python
from langchain.agents import create_agent

agent = create_agent("openai:gpt-4o", tools=[])
```

`requirements.txt`

```text
langchain==1.0.0
```

`services/summarizer/requirements.txt`

```text
openai==1.109.1
```

`services/summarizer/summarize.py`

```python
from openai import OpenAI

client = OpenAI()


def summarize(text: str) -> str:
    reply = client.responses.create(model="gpt-4o-mini", input="Summarize: " + text)
    return reply.output_text
```

Keep the tree free of credentials, infrastructure files and lockfiles. With a `.env`
file that holds a provider key, a Compose file with an Ollama service or a `uv.lock`
that lists `openai`, ShadowScan 0.1.4 adds a `secret` finding, an `infra` finding or
a `framework-usage` finding of resource type `lockfile-inventory`, and the importer
leaves each of them unmapped.

### The command

```sh
shadowscan code /work/agent-framework-demo --format json -o agent-framework-report-0.1.4.json
```

It ran without network access (`unshare -rn`) and with `HOME` set to an empty
directory. A second run produced the same report except for the four run times:
`started_at` and `finished_at`, at the top level and for the one connector.

### What the report records

- The absolute path of the tree, `/work/agent-framework-demo`, in each finding's
  `resource` and `metadata.scan_root`. The tree was built at that path so that the
  report names no directory of the machine or session that produced it.
- When it ran: `2026-11-18T21:48:26+00:00`.
- Lines of the six files above, as evidence snippets, and their paths and line
  numbers.
- No host name, user name, environment variable name or credential.

The evidence for finding 3 cites the model identifier `gpt-4o-mini` at
`services/summarizer/summarize.py:7`. A merged `scan` of the tree with this report
names that model; a project without the file counts the evidence as unconfirmed.

## agent-framework-report-0.1.4.cdx.json

The same tree in ShadowScan's CycloneDX format, from another run of the same commit:

```sh
shadowscan code /work/agent-framework-demo --format cyclonedx -o agent-framework-report-0.1.4.cdx.json
```

It holds the four findings, as three `application` components and one service, and
six entries without a `shadowscan:kind` that ShadowScan adds beside them: three
`framework` components, one `machine-learning-model`, the MCP server `docs` as a
service of group `mcp-server` and the provider `OpenAI` as a service. The importer
projects the four findings as it does from the native report, the model and the
`docs` service by their CycloneDX type and group, and leaves the other four entries
unmapped as `no kind`. Two of its `dependsOn` edges have both ends projected.

The report records the tree's path in `shadowscan:resource` properties and its run
time, `2026-11-18T22:41:23Z`, in `metadata.timestamp`, and no host name, user name or
credential.
