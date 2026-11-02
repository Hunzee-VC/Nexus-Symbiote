# Nexus ShadowScan ↔ AgentBOM mapping

**Status:** normative for the `symbiote.shadowscan` package (profile 0.1). ShadowScan facts cited here were read
from the Nexus-ShadowScan source at tag `v0.1.4` (`docs/concepts/autonomy.md`, `docs/inventory.md`,
`docs/operations/ai-bom.md`, `shadowscan/models.py`, `shadowscan/reporters/cyclonedx.py`, PR #335
`shadowscan/agentbom.py`).

[Nexus ShadowScan](https://github.com/aisecnomad/Nexus-ShadowScan) **discovers** evidence of AI agents across
nine surfaces (code, identity, LLM gateways, low-code, SaaS, cloud, endpoints, network, processes) and reconciles
it against an inventory of approved agents. Symbiote **describes** one agent with per-claim assurance, digests and a
sealed snapshot. The two close one governance loop:

| Direction | Command | Result |
|---|---|---|
| AgentBOM → ShadowScan | `symbiote shadowscan inventory agentbom.json -o inventory/` | ShadowScan's inventory **is** the AgentBOM: a finding is *shadow* when nothing in the AgentBOM claims it (§4). ShadowScan ≥ PR #335 also loads the companion document directly. |
| ShadowScan → AgentBOM | `symbiote shadowscan import report.json` · `symbiote scan --shadowscan-report report.json` | An **observed** snapshot (or observed facts folded into a scan) with the autonomy interval, discovered servers, identities, grants and coverage (§2, §3). |
| Both | `symbiote shadowscan reconcile agentbom.json report.json` | Declared vs observed: shadow and stale tool servers, autonomy verdicts, `SYM-SS-*` findings (§5). |

Nothing in this integration executes ShadowScan or a discovered component; Symbiote reads reports and writes files.

## 1. Inputs

| Input | Recognised by | Fidelity |
|---|---|---|
| ShadowScan JSON report (`shadowscan … --format json`) | top-level `findings` + `finding_identity_schema` ∈ {`shadowscan.finding-identity/v2`, `…/v1`} | full: findings, evidence, risk, `metadata.autonomy`, `metadata.servers`, connector `stats`, `summary.complete`, inventory state |
| ShadowScan CycloneDX 1.6 (`--format cyclonedx`) | `metadata.tools.components[].name == "ShadowScan"` or any `shadowscan:*` property | lossy, recorded in the loss report: no autonomy interval, no evidence list, no credential findings; scan roots are inferred from `coding-agent-config` entries |

Reading is strict (mirrors ShadowScan's own `Finding.from_dict`): identity fields must be non-empty strings, numbers
finite and in range, `shadow` boolean or null; `NaN`/`Infinity` are refused. `[REDACTED]` placeholders are kept as
placeholders; evidence snippets are never copied into entities.

## 2. Findings → entities

Every finding becomes one `Evidence{kind: scan-report, media_type: application/vnd.shadowscan.finding+json,
digest: sha256(JSON of the published record, sorted keys), uri: shadowscan:finding:<id>}`; the report file is a
second `scan-report` evidence. Every derived entity cites its finding in `provenance.evidence` and carries the
finding's facts in `foreign` (`shadowscan:finding-id`, `:kind`, `:surface`, `:connector`, `:resource`,
`:resource-type`, `:discriminator`, `:confidence`, `:likelihood`, `:risk-level`, `:risk-score`, `:danger-score`,
`:shadow` (`true|false|unknown`), `:registry-match`, `:owner`, `:provider`, `:account`, `:region`,
`:capabilities`, `:tags`, `:threats`, `:controls`). ShadowScan tags become `ss:<tag>` tags; `shadow: true` adds the
tag `shadow`, a registry match the tag `registered`.

**Assurance follows the surface** (I1, I3): `code.*` findings are read from files the owner controls →
`declared` / `config`; `endpoint.*` → `observed` / `config`; `identity.*`, `cloud.*`, `lowcode.*`, `saas.*` →
`observed` / `live-query`; `gateway.*`, `network.*`, `runtime.*` → `observed` / `trace`. Nothing is `verified`.

**Root attachment.** Code-surface findings whose `metadata.scan_root` equals the dominant scan root (or
`--scan-root`) describe the scanned agent and attach to the root agent; everything else is *estate*. `--scope root`
keeps only root-attached findings.

| ShadowScan kind | AgentBOM |
|---|---|
| `agent-config` (root) | root facts: tag `harness:<client>`, `foreign["shadowscan:agent-config:<client>:approval-gate"]` ∈ {`every-action`, `some-actions`, `bypassed`, `none-recorded`} with the settings that set it; `autonomy_profile` entry `execute: approval-required` (every-action) or `execute: autonomous` (bypass) when the config has `code-exec`; autonomy interval widened into the root (§3) |
| `mcp-server` (MCP configuration) | one `ToolServer(kind=mcp)` per `metadata.servers[]`, **id `server:<client>-<name>`** — the scheme the `mcp-config` collector uses, so reconcile matches by id (client labels map `Claude Code→claude-code`, `VS Code / Copilot→vscode`, `OpenAI Codex→codex`, `Gemini CLI→gemini-cli`, …); transport from `command` (stdio) / `transport` / URL; `package` via the launcher parser (`npx`, `uvx`, `docker`, …) with `floating`; env-var and header **names**; `secrets_inline` → `Identity(api-key-ref)` + `CredentialBinding(static-long-lived, storage=file)` + tag `inline-secret-in-config` + flag `static-long-lived-credential`; risk `mcp-unpinned-package` → flag `unpinned-tool`; `auto_approve` → `client_trust_flags["shadowscan.autoApprove"]`; `registry` matches → `foreign["shadowscan:mcp:registry"]`; edge `dependsOn` from the owning agent (root only) |
| implemented MCP server (`mcp-server` capability, `metadata.mcp_tools`) | `ToolServer` tagged `implemented-server` + name-only `ToolDefinition`s whose digest is `undigestable` ("name-only …") — fail closed, never a fabricated digest; edges `providesTool` |
| `agent` (code, `agent-manifest` = A2A card) | `Agent(role=external-agent)` with A2A facts in `foreign["shadowscan:a2a:*"]`; edge `delegatesTo` from the root (the card found in a repository names a peer) |
| `agent` (code project) | `Agent(role=sub-agent, parent_ref=root)` + edge `spawns` (design scope) |
| `agent`, `workflow`, `bot-app`, `cloud-resource`, `ai-app`, `runtime-process`, `gateway-caller` (other surfaces) | `Agent(role=external-agent)` + `Deployment` (environment: cloud serverless/k8s/vm by resource type, endpoint/runtime → desktop with `host`, else other; `tenant` = account; `region`); platform `tools` → `ToolServer(kind=builtin)` + `ToolDefinition`s; `permissions` → `Grant`s (§2.1); `models` → hosted `Model`s with `resolved_ref` unknown + `usesModel`; `secret-in-env` → env credential bindings |
| `framework-usage` (root) | root `framework` claim (first `framework.*` signature), models, implemented server |
| `oauth-grant` | `Identity(oauth-client)` + `Grant` per scope + the consenting application as `Agent(external-agent)` with edge `actsAs` |
| `service-identity`, `iam-grant` | `Identity(service-account / oauth-client / iam-role / github-app / azure-managed-identity)` + `Grant` per permission |
| `token` | `Identity(oauth-client)` + `CredentialBinding(obo-token` when delegation is tagged, else `ephemeral-task-scoped)` with `lifetime`; `signature_verified` kept in `foreign` |
| `secret` | `Identity(api-key-ref)` + `CredentialBinding(static-long-lived, storage=file)` on the root, tags `hardcoded-credential`, `inline-secret-in-config`, flag `static-long-lived-credential` |
| `local-model` | `Model(kind=weights)` per listed model with `weights` **unknown** (`not-collected`): ShadowScan lists names, never manifests |
| `network-contact`, `infra` | observation-only: evidence + document-level `ForeignProperty` records; no agent is fabricated (loss item `no-native-construct`, preserved as embedded record) |

### 2.1 Permissions → grants
Each permission string (OAuth scope, IAM action, app permission) becomes one `Grant{layer: observed (live surfaces)
| declared (code), subject_ref, capability, scope.resources=[permission], approval_gate: unknown}`. Capability is a
documented heuristic: `exec|invoke|run|passrole|assume` → `execute`; `write|manage|admin|delete|modify|update|
create|*|all|readwrite` → `write`; otherwise `read`. The original string is kept in
`foreign["shadowscan:permission"]`.

### 2.2 Flags
`undeclared-component-observed` is set on every entity derived from a finding with `shadow` ∈ {true, false} with
the matching value, and **`unknown` when ShadowScan had no inventory** (`shadow: null`) — never `false`.
`unpinned-tool` and `static-long-lived-credential` as in the table. Flags carry `assurance: observed`.

### 2.3 Coverage (I2)
Connector `stats` drive coverage. ShadowScan surface → Symbiote surfaces: `code` → code, tools, instructions;
`endpoint` → tools, runtime; `identity` → identity; `cloud` → runtime, identity; `lowcode` → runtime; `saas` →
runtime, identity; `gateway` → model-gateway; `network` → network; `runtime` → runtime. A surface is `queried`
only when every contributing connector completed, `partial` when one failed, was incomplete or stopped early,
`not-attempted` otherwise (registry, data and policy are never claimed). Each connector becomes a `CollectorRun`
named `shadowscan:<connector>[<label>]`. A report without `stats` (hand-made or truncated) yields no `queried`
surface. `summary.complete == false` (ShadowScan exit 3) makes `SYM-SS-007` indeterminate.

### 2.4 Snapshot
`symbiote shadowscan import` produces an **observed** snapshot whose `observation_window` is the report's
`started_at`–`finished_at`, `producer.collectors = [shadowscan-report@<ShadowScan version>]`, a `loss_report`
(`shadowscan→model`) and the policy result (`run_policy`, `SYM-SS-*` included). The document validates against the
companion schema and exports to CycloneDX 1.7 / SPDX 3.0.1 like any other snapshot.

## 3. Autonomy: the interval and its ISO/IEC 22989 projection

ShadowScan assesses applicable findings on a six-step scale as an **interval** (`shadowscan.autonomy/v1`): the
`floor` is the lowest level the evidence proves, the `ceiling` the highest level positive restriction evidence has
not ruled out (5 unless a per-action approval setting was read), plus `oversight` ∈ {bypassed, gated, unknown},
`initiation` ∈ {schedule, event, human, unknown} and the closed set of rules (`basis`) that fired. Symbiote keeps
the interval intact as `Agent.autonomy_assessment`:

```
AutonomyAssessment = {scale, floor, ceiling, floor_level, ceiling_level, oversight, initiation,
                      basis: [{bound, rule, value}], declared?, declared_source?, assessor, assurance, evidence}
```

The agent-wide `automation_level` claim is the ISO/IEC 22989 projection of the **floor** (observed, method
heuristic, confidence = ShadowScan confidence). The projection is strictly increasing and injective, so a ShadowScan
level survives a round trip unchanged:

| ShadowScan | ISO/IEC 22989 (`isoAutomationLevel`) | Meaning on the ShadowScan scale |
|---|---|---|
| L0 chatbot | `notAutomated` | answers only; a person performs every action |
| L1 copilot | `assistiveAutomation` | drafts and read-only tools inside a person's session |
| L2 supervised | `partialAutomation` | side-effecting actions, each approved by a person |
| L3 semi-autonomous | `conditionalAutomation` | multi-step execution, approval at checkpoints |
| L4 high-autonomy | `highAutomation` | acts in a loop without per-action approval; supervision by exception |
| L5 fully-autonomous | `fullAutomation` | self-initiated, no approval gates |
| — | `autonomous` | no ShadowScan counterpart (a system that sets its own goals); exported to L5 **with a recorded loss** |

Rules: a malformed block yields **no** assessment (fail closed). Several findings about one agent are **widened**
with ShadowScan's merge semantics: highest floor, highest ceiling, the oversight and initiation admitting the most
autonomy (`bypassed > unknown > gated`; `schedule > event > unknown > human`), the union of basis rules, and the
**lowest** declared level. An owner's declared `automation_level` is never overwritten by an observation: the
observed interval lives beside it and `declared < floor` is a finding (§5). A ceiling of L5 means "not ruled out"
and is never collapsed into a level. The scale table is printed by `symbiote shadowscan levels`.

CycloneDX: `agentbom:agent:autonomy-assessment:{scale,floor,ceiling,floor-level,ceiling-level,oversight,
initiation,declared,declared-source,assessor,assurance,basis(repeated),evidence(repeated)}`. SPDX: fields
`autonomyAssessmentScale`, `autonomyFloor`, `autonomyCeiling`, `autonomyFloorLevel`, `autonomyCeilingLevel`,
`autonomyOversight`, `autonomyInitiation`, `autonomyDeclared`, `autonomyAssessor`, `autonomyBasis[]` on the
`AgentProfile` extension.

## 4. AgentBOM → ShadowScan inventory

`export_inventory(bom, fmt)` writes the formats ShadowScan's `--inventory` reads. Only the keys ShadowScan validates
strictly (`discovery`, `governance`) are restricted to its vocabulary; Symbiote facts live in top-level sections it
ignores.

| Card field | Source |
|---|---|
| `schema_version` | `2` (L0-L5 scale) |
| `metadata.agent_id` | the **full entity id** (`agent:<slug>`) — the identifier ShadowScan's own AgentBOM loader binds, so both ingestion paths register a finding to one agent |
| `metadata.name`, `version`, `owner_team`, `tags`, `classification` | agent name/version, owner party name, `symbiote` + `agentbom-snapshot:<digest12>`, `--classification` |
| `autonomy_profile.level` | `automation_level` → L-level (§3); else the assessment floor (source recorded); **omitted when unknown** — unknown never reads as low |
| `autonomy_profile.action_modes` | `autonomy_profile` entries (`capability: mode`) |
| `governance.intended_purpose` | `purpose` (≤ 500 chars); EU AI Act class is never guessed |
| `capability_surface.authorized_tools[]` | `{name, provider: server name, sha256: tooldef/v1 digest (bare hex), side_effect_class}` for tools with an `ok` digest |
| `capability_surface.tool_servers[]` | name, kind, client, transport, endpoint/command, package purl, server digest (descriptive) |
| `data_trust_zones` | data sources the agent reads/writes: trust tier → zone (`internal*`→1, `partner`→2, `untrusted-public`→3; unknown claims no zone) |
| `identity_and_delegation.spiffe_id` | the agent's SPIFFE identity, when present |
| `provenance` | `schema: symbiote-agentbom`, generator, `agentbom_ref`, spec version, snapshot id/digest/kind/serial, `autonomy_level_source`, `verification: not-verified`, `component_resources` (endpoints and purls — descriptive, **never** approval bindings) |
| `discovery.resources` | approvals, literal (glob characters escaped): `--resource` patterns; `--scan-root` → `<root>` and `<root>/*` (the resources ShadowScan's `code.filesystem` reports); `github:<owner>/<repo>` (+`/*`) from a GitHub `external_refs` URL; IAM-role / SPIFFE / GCP-SA identity refs; complete `k8s:<cluster>/<namespace>/<kind>/<name>` deployment identities (incomplete identities approve nothing); the A2A card URL |
| `discovery.names` | slug, agent name, A2A skill names — review suggestions only |
| `discovery.frameworks` | `framework.<name>` |

`agents.yaml` (`agents: [{id, name, owner, resources, names, autonomy_level}]`) and CSV (`agent_id,name,owner,
resources,names,autonomy_level`, pipe-separated lists) carry the same bindings. Root and sub-agents are exported;
external agents only with `--include-external`. Generated files are validated against ShadowScan 0.1.4
(`shadowscan inventory check`) in the optional interop test (`SYMBIOTE_SHADOWSCAN_BIN`).

## 5. Reconciliation and checks (`SYM-SS-*`)

`reconcile(bom, report)` imports the report with `scope=root` for the BOM's root agent and compares:

| Check | Sev | Fires when | Maps to |
|---|---|---|---|
| SYM-SS-001 shadow component observed | medium (high for critical/high risk) | an entity derived from a finding with `shadow: true` (tag `shadow`) | ASI10, ASI04; AML.T0010 |
| SYM-SS-002 tool server observed, not declared | high | an observed `server:<client>-<name>` has no counterpart in the baseline/declared BOM (id, then name+launch) | ASI04, ASI10; AML.T0010 |
| SYM-SS-003 declared tool server not observed | medium / **indeterminate** | a declared server has no observed counterpart; `fail` only when the report is complete and its code scan covers the root, otherwise indeterminate | ASI04 |
| SYM-SS-004 declared level below the observed floor | high | `automation_level` (ISO → L) < `autonomy_assessment.floor` | ASI09, ASI02 |
| SYM-SS-005 declared level above the observed ceiling | info | declared > ceiling (positive configuration evidence rules it out) | ASI09 |
| SYM-SS-006 approval bypass observed | high | `autonomy_assessment.oversight == bypassed` | ASI09, ASI02, ASI05 |
| SYM-SS-007 ShadowScan report incomplete | info / indeterminate | any `shadowscan:*` collector run partial or failed; `summary.complete == false` | — |

The same checks run inside `symbiote policy check` on an imported observed document (SS-002/003 need a
`baseline`), so the vocabulary is one whether reconciliation is run directly or through the engine. Exit code 1
when a failing finding reaches `--fail-on` (default `high`).

## 6. Collector

`shadowscan-report` (observed; surfaces code, tools, instructions, identity, model-gateway, runtime, network) runs
inside `symbiote scan` when a report is named: `--shadowscan-report FILE`, `shadowscan: {report: FILE, scope:
root|estate}` in `symbiote.yaml`, or `shadowscan.report.json` / `shadowscan.json` / `shadowscan.cdx.json` at the
repository root. It contributes the entities of §2, hands root facts (assessment, automation level, harness tags,
foreign facts, autonomy profile, framework) back to the runner through `CollectionResult.root_updates`, and
corroborates servers the `mcp-config` collector already declared: the same id keeps the declared record and gains
ShadowScan's evidence reference and tags (no duplicate, no silent drop). A report that does not parse is a
`failed` collector with `partial` coverage on its surfaces.

## 7. Compatibility
`symbiote.export.shadowscan` (`to_capability_card`, `to_simple_inventory`, `declared_level`,
`discovery_resources`) and `symbiote.imp.shadowscan` (`import_shadowscan`) remain as façades over
`symbiote.shadowscan`.
