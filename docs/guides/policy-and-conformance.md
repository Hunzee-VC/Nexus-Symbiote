# Policy checks, conformance levels and the completeness score

Three commands read the companion document and say something about it. **`policy check`** evaluates the
built-in `SYM-*` checks (facts about the agent's configuration, mapped to OWASP ASI and MITRE ATLAS).
**`conformance`** evaluates the AgentBOM conformance requirements (facts about the *document*: what it covers and
what evidence it carries). **`score`** reports completeness. None of them is a safety score, and the CLI says so
in its output. The normative definitions are [`spec/checks.md`](../spec/checks.md) and
[`spec/conformance.md`](../spec/conformance.md); the outputs below come from the example agent.

## Facts in the BOM, judgments in policy

`symbiote scan` already runs the checks and records their results in the document (`derived.findings`,
`derived.flags`), because a consumer of the companion should see the same judgments the producer saw. Running
`policy check` afterwards recomputes them from the document alone; nothing is re-collected. Every check cites
its inputs (entity ids) so anyone can recompute it, and every check whose inputs are `unknown` reports
**`indeterminate`** rather than passing silently.

```text
$ symbiote policy check /tmp/out/agentbom.json
13 finding(s) from 60 checks; flags: lethal-trifecta=unknown, rule-of-two-violation=unknown, unpinned-tool=true, …
critical indeterminate SYM-AUTHZ-001  agent:triage-agent
           Trifecta assessment incomplete: untrusted input=true, sensitive access=true, exfiltration=unknown, state change=unknown.
high     fail          SYM-COV-001    agent:triage-agent
           Not fully covered: code, data, identity, instructions, model-gateway, network, policy, registry, runtime, tools.
high     indeterminate SYM-MCP-001    server:cursor-github
           Server 'github' crosses a trust boundary; its authentication or tool capabilities are unknown.
high     fail          SYM-MCP-002    server:claude-code-filesystem
           Server 'filesystem' launches pkg:npm/%40modelcontextprotocol/server-filesystem without pinning (dist-tag:latest): every start may fetch new code.
high     fail          SYM-MCP-002    server:gemini-cli-filesystem
           …
high     fail          SYM-TOOL-001   server:claude-code-filesystem
           Server 'filesystem': no tool definition is pinned (tools were never observed or approved).
…
medium   fail          SYM-MCP-006    agent:triage-agent
           Agent combines 2 ungated external server(s) with 4 internal/local server(s).
```

Reading this output:

- **State** is `fail` or `indeterminate`. `SYM-AUTHZ-001` (lethal trifecta) is indeterminate here because two of
  its legs are unknown: the declared scan knows the agent reads untrusted input and holds credentials, but no
  tool definitions were observed, so whether a tool can send data out is `unknown`. The check does not guess.
- **Severity** is the check's severity (`critical … info`), independent of state.
- **`SYM-TOOL-001` fires per server**: a server whose tools were never observed or approved has nothing pinned,
  so a gateway could not enforce anything for it. The remediation is to observe the server live and approve the
  toolset digest.
- **`SYM-MCP-002`** reads the launch command: `npx -y @modelcontextprotocol/server-filesystem@latest` floats on
  the `latest` dist-tag, so every start may fetch new code. An exact version (`@2025.8.21`) is pinned; an OCI
  image is pinned only by `@sha256:` digest.
- **Flags** are the computed summaries (`lethal-trifecta`, `unpinned-tool`, `floating-model-alias`, …) with
  values `true | false | unknown`; one flag is emitted per subject, which is why `unpinned-tool=true` repeats.

### Gating a pipeline

| Option | Effect |
|---|---|
| `--fail-on SEV` | exit 1 when any `fail` finding has severity ≥ `SEV` (default `high`) |
| `--fail-on-indeterminate` | also exit 1 for `indeterminate` findings at or above the threshold |
| `--select GLOB` (repeatable) | run only matching check ids, e.g. `--select 'SYM-MCP-*'` |
| `--exclude GLOB` (repeatable) | skip matching check ids |
| `--baseline FILE` | compare against an approved or earlier companion; enables `SYM-TOOL-002` (served ≠ approved) and `SYM-SUB-001` (undeclared sub-agent) and the `undeclared-component-observed` flag |
| `--sarif FILE` | write SARIF 2.1.0 |
| `--json` | records: `{companion, checksRun[], counts{fail, indeterminate}, findings[], flags[], errors[], sarif}` |

```text
$ symbiote policy check /tmp/out/agentbom.json --select 'SYM-MCP-*' --fail-on critical; echo $?
4 finding(s) from 8 checks; …
0
$ symbiote policy check /tmp/out/agentbom.json --select SYM-AUTHZ-001 --fail-on-indeterminate; echo $?
1 finding(s) from 1 checks; …
critical indeterminate SYM-AUTHZ-001  agent:triage-agent
1
$ symbiote policy check v2/agentbom.json --baseline v1/agentbom.json --select SYM-MCP-003
1 finding(s) from 3 checks; flags: … undeclared-component-observed=true
medium   fail          SYM-MCP-003    server:claude-code-jira
           Server 'jira' is reached over plaintext (http://jira.internal.example/mcp).
```

A finding record (from `--json`) carries everything a downstream system needs to recompute or triage it:

```json
{
  "checkId": "SYM-MCP-002",
  "severity": "high",
  "state": "fail",
  "subjectRefs": ["server:claude-code-filesystem"],
  "inputs": ["server:claude-code-filesystem"],
  "message": "Server 'filesystem' launches pkg:npm/%40modelcontextprotocol/server-filesystem without pinning (dist-tag:latest): every start may fetch new code.",
  "mappings": [{"framework": "owasp-asi-2025", "id": "ASI04"}, {"framework": "mitre-atlas", "id": "AML.T0010"}],
  "evidence": [],
  "locator": ".mcp.json#/mcpServers/filesystem"
}
```

### The checks

`symbiote policy list` prints all 60 checks; `symbiote policy explain ID` prints one check's description,
remediation, inputs, threat mappings and whether it is a 2026 extension (`extension: true`). The families:

| Family | Ids | What they look at |
|---|---|---|
| Tools | `SYM-TOOL-001…010` | unpinned or undigestable definitions, served ≠ approved, destructive + open-world without a gate, external `$ref`, hidden Unicode, absent annotations, name shadowing, cross-tool directives, secret-shaped text |
| MCP servers | `SYM-MCP-001…008` | unauthenticated across a trust boundary, floating package launch, plaintext transport, registry status, typosquat, mixed-trust composition, privileged container launch, project servers auto-enabled |
| Authorization | `SYM-AUTHZ-001…007` | lethal trifecta / Rule of Two, least-privilege gap, long-lived credentials for dangerous capabilities, unauthenticated write, unconstrained delegation, no enforcement point, undeclared egress |
| Models | `SYM-MODEL-001…006` | floating alias, unsafe serialization (pickle, `trust_remote_code`, executable chat template), unverified signature, unknown lineage parent, malicious indicators, format anomalies |
| Instructions, skills, memory, data | `SYM-INSTR-001…005`, `SYM-SKILL-001…002`, `SYM-MEM-001…002`, `SYM-DATA-001` | untrusted editors, remote includes, changed since approval, hidden Unicode in rules files, repository-supplied hooks, skills with shell access, unknown or untrusted memory writers, untrusted input feeding a privileged agent |
| CI and human-in-the-loop | `SYM-CI-001…003`, `SYM-HITL-001…002`, `SYM-CRED-001` | the Clinejection pattern (agent in CI on untrusted triggers, event text templated into a prompt, publish secrets reachable), approval disabled by client settings or CLI flags, plaintext credentials in configuration |
| Snapshots, coverage, trust, attestation, evaluation | `SYM-SNAP-001…003`, `SYM-COV-001…002`, `SYM-TRUST-001…002`, `SYM-ATT-001…002`, `SYM-EVAL-001`, `SYM-REG-001`, `SYM-A2A-001`, `SYM-SUB-001` | serial regression and chain gaps, surfaces not covered or absence claimed without coverage, revoked components or publishers, unconstrained signers and expired evidence, stale evaluations, resolutions without log inclusion, unsigned agent cards, undeclared sub-agents |

```text
$ symbiote policy explain SYM-CI-003
{
  "id": "SYM-CI-003",
  "title": "Untrusted event text interpolated into an agent prompt or command",
  "severity": "critical",
  "description": "The root cause of Clinejection: attacker-controlled event fields are templated into an agent's prompt.",
  "remediation": "Never place ${{ github.event.* }} text (issue or PR titles and bodies, comments, branch names) inside a prompt or run script. …",
  "inputs": ["identities.tags"],
  "mappings": [{"framework": "owasp-asi-2025", "id": "ASI01"}, {"framework": "mitre-atlas", "id": "AML.T0051"}],
  "extension": true,
  "rego": false
}
```

Several checks need inputs that only the pending static collectors (instructions, skills, models, frameworks,
identity) or an observed snapshot provide; on a scan that ran only `mcp-config` they are simply not triggered.
See the [collectors guide](collectors.md) for what is collected today.

## SARIF for code scanning

`--sarif FILE` writes a SARIF 2.1.0 run (`$schema: https://json.schemastore.org/sarif-2.1.0.json`) that GitHub
code scanning accepts. Mapping:

| Finding | SARIF |
|---|---|
| check id | `ruleId`; one `rules[]` entry per distinct check with `shortDescription`, `fullDescription`, `help.markdown` (the remediation), `helpUri`, `defaultConfiguration.level` |
| severity `critical`/`high` → `error`, `medium` → `warning`, `low`/`info` → `note` | `level`, plus `properties.security-severity` (9.5 / 8.0 / 5.5 / 3.0 / 1.0) for the code-scanning severity filter |
| state `indeterminate` | `level: note`, `kind: review` (never dropped); `fail` → `kind: fail` |
| locator `path#/json/pointer` or `path:line` | `locations[].physicalLocation.artifactLocation.uri` plus the pointer as a logical location of kind `member`; subject ids as logical locations of kind `object` |
| mappings | `properties.mappings` (`owasp-asi-2025:ASI04`, `mitre-atlas:AML.T0010`) and rule `tags` |
| identity | `partialFingerprints["symbiote/v1"]` = SHA-256 over check id, subjects and inputs, so re-runs de-duplicate |

```json
{
  "ruleId": "SYM-MCP-002",
  "ruleIndex": 3,
  "level": "error",
  "kind": "fail",
  "message": {"text": "Server 'filesystem' launches pkg:npm/%40modelcontextprotocol/server-filesystem without pinning (dist-tag:latest): every start may fetch new code."},
  "partialFingerprints": {"symbiote/v1": "e2f2bff1055d47f8956ee3f77c7bca35f71b85f716ee66f1ff6fe2ee64970b70"},
  "properties": {"state": "fail", "severity": "high", "security-severity": "8.0",
                 "subjects": ["server:claude-code-filesystem"], "inputs": ["server:claude-code-filesystem"],
                 "mappings": ["owasp-asi-2025:ASI04", "mitre-atlas:AML.T0010"]},
  "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".mcp.json"}},
                 "logicalLocations": [{"fullyQualifiedName": "/mcpServers/filesystem", "kind": "member"},
                                      {"fullyQualifiedName": "server:claude-code-filesystem", "kind": "object"}]}]
}
```

`originalUriBaseIds.SRCROOT` is set to the companion's directory; pass the companion that lives next to the
scanned repository (or rewrite the base id) so code scanning can link to `.mcp.json`. The upload step is in the
[CI guide](ci.md).

## Conformance levels

Conformance is a statement about the **document**. Three levels, each a list of requirements with stable ids;
each requirement evaluates to `pass`, `fail` or `unknown` with reasons, and a level is attained only when no
requirement of that level (or a lower one) is `fail` or `unknown`.

| Level | Meaning | Ids |
|---|---|---|
| **AgentBOM-Minimal** | static, offline: identities, digests or explicit `unknown` for every model, server, tool and instruction; coverage for all ten surfaces; schema-valid exports; no secret values | `AB-MIN-01…08` |
| **AgentBOM-Standard** | plus authority and runtime binding: declared grants with enforcement points, identities and credential bindings, name-resolution records, serial/prev/validity, computed flags, loss report, data trust tiers and memory writers, approval gates, served tool digests | `AB-STD-01…10` |
| **AgentBOM-Verified** | plus authenticated evidence: a signed snapshot verifying under an identity constraint, live toolset within `max_staleness`, verified model signatures, a current trust-status list, a recomputable Merkle root, evaluations bound to the current digests, all surfaces queried, an approval from a distinct identity | `AB-VER-01…08` |

```text
$ symbiote conformance /tmp/out/agentbom.json --level standard
requested standard; attained none — NOT ATTAINED
Conformance describes the document's completeness and evidence, not the agent's safety.
pass    AB-MIN-01  Agent identity
pass    AB-MIN-02  Every model has an identity or explicit unknown
pass    AB-MIN-03  Every tool server has transport and package or endpoint
pass    AB-MIN-04  Every tool definition has a digest or an undigestable reason
pass    AB-MIN-05  Every instruction file and skill is digested
pass    AB-MIN-06  Coverage statement for all ten surfaces
unknown AB-MIN-07  Exported documents validate against the official schemas  — no CycloneDX validation result supplied (run `symbiote validate`)
pass    AB-MIN-08  No secret values anywhere
unknown AB-STD-01  Companion linked by digest in every emitted format  — no exported format is linked yet
fail    AB-STD-02  Declared grant per tool server and tool  — server:claude-code-filesystem: no declared grant; …
pass    AB-STD-03  Identities and credential bindings for every grant
fail    AB-STD-04  Name-resolution record for every registry-sourced component  — server:claude-code-filesystem: registry-sourced without a resolution record; …
fail    AB-STD-05  Snapshot serial, prev link and validity window  — no validity window (not_after)
pass    AB-STD-06  Computed flags with cited inputs
unknown AB-STD-07  Loss report with no security-relevant item dropped  — no loss report attached
pass    AB-STD-08  Trust tier for every data source; writers for every memory store
pass    AB-STD-09  Approval gate and side-effect class for every tool
fail    AB-STD-10  Served tool digests for every reachable MCP server  — server:claude-code-filesystem: no served tool definitions; …
```

Exit codes: 1 when any requirement **fails**; 5 when nothing fails but something is **unknown** (coverage
insufficient for the level); 0 when the level is attained.

Two honest caveats about the current branch. First, the zero-config scan cannot reach Minimal yet: `AB-MIN-07`
stays `unknown` because `scan` validates the exported documents but does not record the result or the format
linkage (`links`) and loss report in the companion; the same gap keeps `AB-STD-01` and `AB-STD-07` unknown.
Second, Standard needs declared grants, resolution records, a validity window and served tool digests, which
come from the authorization policy collector, the registry collector, a validity option and the live collector —
none of which the CLI wires in yet. The levels are the contract the tool is converging on; the requirement ids
are stable.

## The completeness score

```text
$ symbiote score /tmp/out/agentbom.json
completeness 63/100 — BOM completeness, not a trust or safety score.
assurance: declared=100%, observed=0%, verified=0%
tools          20/28 (weight 25)  missing: server:claude-code-filesystem: toolset digest, server:claude-code-github: toolset digest, …
authorization  0/7 (weight 20)  missing: server:claude-code-filesystem: declared grant, server:claude-code-github: declared grant, …
models         0/0 (weight 15)
data           0/0 (weight 10)
identity       3/6 (weight 10)  missing: cred:claude-code-github-header-authorization: credential kind, …
instructions   0/0 (weight 10)
coverage       0/10 (weight 5)  missing: surface code queried, surface data queried, surface identity queried, …
evidence       14/14 (weight 5)
```

The score is Σ weight × field presence over eight areas (tools 25, authorization 20, models 15, data 10,
identity 10, instructions 10, coverage 5, evidence 5), with the missing fields named per entity. An area with no
entities scores as empty rather than as complete. The **assurance distribution** is always printed next to it:
63/100 made entirely of declared facts is a different document from 63/100 with observed tool digests, and the
score alone would hide that. `score` always exits 0.
