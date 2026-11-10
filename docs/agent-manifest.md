# Agent manifest (`agent.yaml`)

`agent.yaml` is an optional file at the root of a scanned project. It declares the
agent the repository defines: a stable identity, the instruction files it reads and
the models it uses. `scan`, `baseline`, `validate --project` and `risk --project`
read it when they assemble the repository agent. Everything in it is a declaration
by whoever can write to the repository; it never raises trust or assurance.

## Example

```yaml
id: acme:support-triager
name: support-triager
version: "1.4"
purpose: Triage inbound support tickets
framework: langgraph
owner: platform-security
autonomy_level: L2-agent
instructions:
  - CLAUDE.md
  - docs/agents/triage-rules.md
models:
  classifier:
    path: models/classifier
  planner:
    provider: openai
    requested_ref: gpt-4o
```

## Fields

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Agent name (non-empty) |
| `id` | no | Stable identity; the agent's reference is `agent:repository:` followed by the first 24 hexadecimal digits of the SHA-256 of `id` |
| `version`, `purpose`, `framework`, `owner` | no | Recorded as the agent's version, description, framework and supplier |
| `autonomy_level` | no | `L0-chatbot`, `L1-copilot`, `L2-agent`, `L3-autonomous` or `L4-fully-autonomous`; recorded as the property `declared_autonomy_level`, never as the agent's observed `autonomy_level` |
| `instructions` | no | Up to 1,024 paths of instruction files, relative to the project root |
| `models` | no | Up to 1,024 named models, each either `path` (a model file or the directory that holds it, relative to the project root) or both `provider` and `requested_ref` (a hosted model) |

Any other key is an error. The file must be a UTF-8 YAML mapping of at most 1 MiB
and 20,000 YAML tokens, without anchors, aliases or tags.
[`schemas/agent-manifest-1.0.schema.json`](../schemas/agent-manifest-1.0.schema.json)
describes the structure for editors and other tools; the path and file rules below
are checked only when a scan reads the manifest.

## What it changes

- **Identity.** Without `agent.yaml`, or without `id`, the repository agent is
  `agent:repository:inferred`, named `repository`, the same in every checkout.
  `id` gives it a reference of your own. Changing `id` replaces the agent, so
  `diff` reports it removed and added.
- **Instructions.** A listed file that the `prompt` collector already reads, such
  as `CLAUDE.md`, maps to that collector's record; it is not inventoried twice. Its
  bytes must still match what the collector recorded. Any other listed file is
  inventoried as `prompt:manifest:<digest of its path>` with its SHA-256 and the same
  hidden-character checks the collector applies to instruction files. This is how
  instruction files outside the fixed paths, such as nested or `docs/` files, enter
  the inventory.
- **Local models.** A `path` must match a model artifact the `model` collector
  recorded: the file itself, or a file directly in that directory. The manifest adds
  no model of its own; it confirms the declared artifact was collected.
- **Hosted models.** A `provider` and `requested_ref` add a model component with the
  requested alias, declared assurance and unknown trust. Its identity and integrity
  cannot be checked offline, so integrity validation reports them as unknown.
- **The risk gate.** A repository whose only local subject is the inferred agent
  fails with "no agent manifest or supported local inventory evidence was found".
  A manifest-declared agent, instruction or model is such evidence.

## Problems are recorded, not fatal

`scan` and `baseline` record each problem as a scan failure and still write the
inventory, so the default gate fails and the evidence stays available for review.

| Scan failure | Cause |
| --- | --- |
| `agent.yaml: does not conform to the agent manifest schema` | Not a YAML mapping, an unknown key, a missing `name`, a YAML anchor, alias or tag, or too many tokens. The inferred agent is recorded instead |
| `agent.yaml: read refused (...)` or `agent.yaml: invalid UTF-8` | A symlink, a non-regular file, a file over 1 MiB, or bytes that are not UTF-8. The inferred agent is recorded instead |
| `agent.yaml#/instructions/N: must be a relative path beneath the repository` | An absolute path, a `..` component, a backslash or a NUL character |
| `agent.yaml#/instructions/N: the declared instruction could not be collected safely` | Missing, a symlink, not a regular file, or over the 4 MiB read limit |
| `agent.yaml#/instructions/N: names a path inside a directory that collection never reads` | A path under `.git`, `node_modules`, `__pycache__`, `.venv` or `venv` |
| `agent.yaml#/instructions/N: instruction changed since scanner collection` | The file changed between collection and assembly |
| `agent.yaml#/instructions/N: declared instruction is not UTF-8 text` | It cannot be checked for hidden characters |
| `agent.yaml#/models/KEY: the declared local model has no collected model artifact` | No collected model at that path |
| `agent.yaml#/models/KEY: the declared local model is unavailable` | The artifact can no longer be opened safely |

`validate --project` and `risk --project` recollect the manifest and report any of
these as "Local agent manifest could not be reconciled."

The operator's `scan.exclude_paths` applies to `agent.yaml` and to every path it
names. An excluded path is never read or hashed; it is recorded as a coverage gap
(`PATH: excluded by collection policy`), so the default gate fails rather than
silently narrowing what was inventoried.

## Trust

`agent.yaml` is part of the checkout, so the change under review can edit it. It
can rename the agent, change its `id`, and add or drop declared instructions and
models; `diff` reports each of these against a reviewed baseline. It cannot make the
scan read outside the project root, follow a symlink, raise a trust tier or an
assurance level, or record a runtime observation: declared fields keep declared
assurance and the agent's runtime autonomy and deployment stay unknown.

A repository that already has an `agent.yaml` for another tool gets the
"does not conform" failure. Excluding the file with an operator policy keeps it
unread, at the cost of a recorded coverage gap.
