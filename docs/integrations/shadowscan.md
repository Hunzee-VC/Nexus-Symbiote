# Nexus ShadowScan

[Nexus ShadowScan](https://github.com/aisecnomad/Nexus-ShadowScan) finds evidence of AI agents across nine
surfaces — code repositories, identity providers, LLM gateway logs, low-code platforms, SaaS apps, cloud accounts,
endpoints, network logs and running processes — and asks one question of each finding: *is this in the inventory of
approved agents?* Symbiote answers a different question: *what exactly is this agent made of and allowed to do,
and can I prove it?* Together they close one loop:

| Question | Tool |
|---|---|
| What agents exist across the estate, who owns them, are they approved? | ShadowScan |
| What is *this* agent built from, what may it do, and does the deployed one still match? | Symbiote |

Symbiote integrates with ShadowScan natively and in both directions. The normative mapping is
[`spec/shadowscan-mapping.md`](../spec/shadowscan-mapping.md).

## 1. Make the AgentBOM the inventory

ShadowScan calls a finding **shadow** when nothing in the supplied inventory claims it. Export the AgentBOM as that
inventory and *shadow* means *not in the AgentBOM*:

```bash
symbiote scan . -o bom/                                   # declared snapshot of this agent
symbiote shadowscan inventory bom/agentbom.json -o inventory/ --scan-root "$PWD"
shadowscan code . --inventory inventory/ --format json -o shadowscan.json
```

Run against the bundled example, the 12 findings ShadowScan reports for `examples/triage-agent` all register to
`agent:triage-agent` (`shadow: false`, owner inherited from the AgentBOM's owner party) and the summary line reads
`12 findings • 0 shadow`. The generated Capability Card declares the approved autonomy level on ShadowScan's L0-L5
scale, the agent's purpose as a governance fact, the authorized tools with their `tooldef/v1` digests, and literal
`discovery.resources` bindings. Bindings are approvals — review them before use. Three formats are available:
`--format cards` (one `schema_version: 2` card per agent), `agents` (`agents.yaml`) and `csv`.

ShadowScan (PR #335 and later) also loads the companion document itself through `--inventory`; both paths bind
the same `agent_id` (`agent:<slug>`), so a finding registered through either reads the same.

## 2. Import a ShadowScan report as an observed snapshot

```bash
shadowscan code . --format json -o shadowscan.json
symbiote shadowscan import shadowscan.json -o observed/
```

The result is an **observed** AgentBOM (companion + CycloneDX 1.7 + SPDX 3.0.1): the MCP configurations
ShadowScan found become `ToolServer`s with the same ids `symbiote scan` would give them, inline secrets become
credential bindings and flags, identities and grants come from identity and cloud findings, discovered agents on
other surfaces become external agents with deployments, and every finding is pinned as `scan-report` evidence.
Assurance follows the surface: facts read from files are `declared`, facts read from live APIs, hosts and logs are
`observed`; nothing becomes `verified`. ShadowScan's `--format cyclonedx` output is accepted too, with the loss
report naming what that dialect cannot carry (the autonomy interval above all).

### The autonomy interval

ShadowScan reports autonomy as an interval: the **floor** is the lowest level the evidence proves, the **ceiling**
the highest level positive evidence has not ruled out. Symbiote keeps the interval as `autonomy_assessment` and
summarises the floor on the ISO/IEC 22989 ladder (`symbiote shadowscan levels` prints the table):

| ShadowScan | ISO/IEC 22989 |
|---|---|
| L0 chatbot | `notAutomated` |
| L1 copilot | `assistiveAutomation` |
| L2 supervised | `partialAutomation` |
| L3 semi-autonomous | `conditionalAutomation` |
| L4 high-autonomy | `highAutomation` |
| L5 fully-autonomous | `fullAutomation` |

A ceiling of L5 means "not ruled out", never a level; an owner's declared level is kept beside the observed
interval, and a declaration below the floor is a finding.

## 3. Reconcile declared with observed

```bash
symbiote shadowscan reconcile bom/agentbom.json shadowscan.json --sarif reconcile.sarif
```

The command matches observed tool servers against declared ones (by id, then by name and launch), reports
observed-but-undeclared servers (`SYM-SS-002`), declared-but-unobserved servers (`SYM-SS-003`, a failure only when
ShadowScan's code scan was complete, indeterminate otherwise), compares the declared automation level with the
observed interval (`SYM-SS-004` understated, `SYM-SS-005` above the ceiling), flags approval bypass
(`SYM-SS-006`) and shadow findings (`SYM-SS-001`), and never concludes anything from an incomplete scan
(`SYM-SS-007`). Exit code 1 at `--fail-on` (default `high`).

## 4. Fold a report into `symbiote scan`

```bash
symbiote scan . --shadowscan-report shadowscan.json -o bom/
```

The `shadowscan-report` collector adds ShadowScan's observations to the scan: servers it also found corroborate the
declared ones (one id, two citations), the root agent gains its autonomy interval, harness tags and approval-gate
facts, and ShadowScan's connector results become coverage. The same happens with `shadowscan: {report: …}` in
`symbiote.yaml` or a `shadowscan.report.json` next to the repository. Symbiote never runs ShadowScan itself.

## What stays honest

* `shadow: null` (ShadowScan ran without an inventory) is a flag with value `unknown`, never `false`.
* An incomplete connector is `partial` coverage; a report with no connector stats claims no `queried` surface.
* Network contacts and infrastructure definitions are evidence, not fabricated agents.
* Tool names without definitions get an `undigestable` digest rather than an invented one.
* Local model stores are models whose weights identity is explicitly unknown.
