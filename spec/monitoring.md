# Continuous assurance and the agent dependency bot

`symbiote monitor` re-scans and re-verifies each agent on a cadence set by its risk tier, and `symbiote update`
proposes safe changes to the agent's third-party dependencies, in the spirit of Dependabot but for what an agent
depends on: MCP servers (packages and remote endpoints), A2A peers, skills, tools and plugins, and models. Both
build on the snapshot chain (`agentbom-profile.md` §2), the digest-based diff (`digests.md`), the policy engine
(`checks.md`) and the attestation flow (`attestation.md`).

## 1. Risk tiers and cadence

| Tier | Default interval | Typical agent |
|---|---|---|
| `critical` | 10 minutes | production agent that can act on the world (write, execute, payment, credentials) or whose BOM shows the lethal trifecta / Rule-of-Two violation |
| `high` | 1 hour | other production agents with tool access |
| `medium` | 1 day | staging and internal agents |
| `low` | 14 days | development and read-only agents |

- Intervals are configurable per organisation (`cadence:`) and per agent (`interval:`); the floor is 1 minute.
- Each agent's due time carries a deterministic jitter of up to 10 % of its interval, derived from a hash of the
  agent name, so a fleet does not scan in lockstep.
- `risk: auto` derives the tier after every cycle from the agent's environment and its latest BOM:
  `critical` when `environment: production` and (flag `lethal-trifecta` or `rule-of-two-violation` is `true`, or
  any failing finding is critical); `high` for any other production agent or any failing high finding; `medium`
  for `staging`/`internal`; `low` otherwise. An explicit tier is never lowered by derivation.
- **Adaptive escalation.** A cycle that produces a new failing finding at or above `high`, a definition drift, a
  malicious-package or vulnerable-dependency signal, or a verification failure escalates the agent to the
  `critical` cadence until it has completed `deescalate_after` (default 3) consecutive clean cycles.
- Failed cycles retry with exponential backoff (1, 2, 4… minutes, capped at the tier interval) and are reported
  as errors, never as clean.

## 2. A monitoring cycle

For one agent, in order (each step records what it could not do as `not-attempted`/`unreachable`, never as clean):

1. **Collect.** `symbiote scan` of the agent's root (static collectors; live collectors only when the target
   enables them) produces a declared snapshot sealed onto the agent's chain in the monitor's store
   (anti-rollback: a serial regression or chain gap is a verification failure).
2. **Drift.** `diff(previous, current)` and, when a `baseline` (approved companion) is configured,
   `diff(baseline, current)`. Tool-definition, server-identity, instruction, skill and model events are recorded
   with their severities (`digests.md` §7 rug-pull attribution).
3. **Policy.** `run_policy(current, baseline=…)`. Findings are fingerprinted (`check_id` + sorted subjects); the
   cycle reports new and resolved findings relative to the previous cycle.
4. **Dependencies.** The dependency inventory (§3) is checked by the advisors when `advisories: true`.
5. **Verification.** The chain issues from step 1, snapshot expiry (`SYM-SNAP-002`), served-vs-approved
   (`SYM-TOOL-002` with the baseline), and, when `attestation:` is configured, verification of the approved
   snapshot's DSSE/Sigstore bundle against its identity policy and digest binding.
6. **Report.** A cycle record (JSON) is appended to the agent's history; events at or above the notification
   threshold are sent; the next due time is computed (tier, escalation, jitter).

## 3. Dependency inventory and advisories

The inventory is read from the AgentBOM: MCP server packages (`ToolServer.package`: npm, PyPI, OCI, NuGet) and
remote endpoints, A2A peers (`ToolServer(kind=a2a)` + card digest), skills (dirmanifest digest), software
components imported from SBOMs, hosted models (`Model.hosted`) and local models (`Model.weights`).

Advisors (network, bounded, cached, never executing content):

| Source | What it answers |
|---|---|
| npm registry (`registry.npmjs.org/<pkg>`) | versions, publish times, `dist.attestations` (provenance), lifecycle scripts, publisher, deprecation |
| PyPI JSON API (`pypi.org/pypi/<pkg>/json`) | versions, upload times, yanked releases |
| OSV (`api.osv.dev/v1/query`) | vulnerabilities and malicious-package records (`MAL-*`) for an exact version |
| MCP Registry (`registry.modelcontextprotocol.io/v0/servers`) | server status (`active`/`deprecated`/`deleted`), newer published versions |
| provider rule table (`providers.yaml`) | announced hosted-model retirements |

Signals (`symbiote.advisories.types.SignalKind`): `vulnerable`, `malicious`, `newer-version`, `fresh-release`
(newest release younger than the cooldown), `provenance-downgrade` (earlier releases carried build provenance and
this one does not: the `cline@2.3.0` pattern), `install-script-added`, `publisher-changed`, `deprecated`,
`yanked`, `not-published` (absent from the public registry: a private package exposed to dependency
confusion unless its public name is claimed, or a removed one), `floating`, `retiring-model`, `definition-drift`. A lookup that fails is `coverage: unreachable` and
produces no "clean" conclusion.

## 4. Update proposals (`symbiote update`)

For each dependency the planner chooses at most one proposal (`symbiote.update.types.UpdateProposal`):

- `security`: the current version is vulnerable or malicious → the lowest fixed version that passes the policy
  (security cooldown, default 2 days); if none exists, the proposal is to remove or replace the server.
- `pin`: a floating reference (`npx -y pkg`, `pkg@latest`, `uvx pkg`, unpinned OCI tag) → pin to the
  recommended version (or OCI digest).
- `version`: a newer release that passes the policy (cooldown, default 7 days; provenance continuity; no new
  install script; same major unless `allow_major`).
- `retire-model`: a hosted model with an announced retirement → its documented successor, as advice.

Every proposal carries the signals and evidence behind it and the review notes a human should act on (for
example: re-capture the served tool definitions after upgrading and re-approve the toolset digest). Edits are
minimal textual replacements in the declaring configuration file (formatting and comments preserved), rendered as
a unified diff. `--open-pr` creates a branch `symbiote/deps/<dependency>-<version>` and a pull request with the
`gh` CLI; it never pushes to the default branch and never merges.

## 5. Configuration

```yaml
# symbiote-monitor.yaml
state_dir: .symbiote/monitor
cadence: {critical: 10m, high: 1h, medium: 1d, low: 14d}
deescalate_after: 3
fail_on: high
advisories: true
update_policy: {cooldown_days: 7, security_cooldown_days: 2, require_provenance_continuity: true}
notify:
  - {type: webhook, url_env: SYMBIOTE_WEBHOOK_URL, min_severity: high}
agents:
  - name: triage-agent
    path: examples/triage-agent
    environment: production
    risk: auto            # or critical | high | medium | low
    baseline: approved/triage-agent.agentbom.json
    attestation: {bundle: approved/triage-agent.sigstore.json, policy: approved/verify-policy.yaml}
```

Secrets never appear in the file: webhook URLs and tokens are read from the environment variables it names.

## 6. Commands and exit codes

| Command | Purpose |
|---|---|
| `symbiote monitor tick [--config F]` | run every agent that is due now, then exit (for cron, systemd timers, Kubernetes CronJobs, scheduled CI) |
| `symbiote monitor run [--config F]` | long-running scheduler: sleep until the next due agent, run, repeat; stops cleanly on SIGINT/SIGTERM |
| `symbiote monitor plan` / `status` | due times and tiers / last result per agent |
| `symbiote update [PATH] [--diff] [--write] [--open-pr]` | dependency proposals for one agent: list, unified diff, apply, or open a pull request |

Exit codes follow `cli.md`: 0 nothing new at or above `fail_on`; 1 new failing findings, drift, vulnerable or
malicious dependencies, or verification failures at or above `fail_on`; 6 a cycle could not run; 7 a chain
conflict (anti-rollback).
