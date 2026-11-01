# Built-in policy checks and computed flags

`symbiote policy check` evaluates the companion document (Policy Input Document). Each check is a `CheckSpec`
with a stable id, severity, the inputs it reads, its logic and its threat mappings. Checks whose logic is a plain
predicate over the document also have a Rego rule: `symbiote policy export-rego` generates `package agentbom`
(§5), and a parity test asserts built-in findings == OPA findings over the fixtures for every exported check. A check whose inputs are `unknown` reports
`state: indeterminate` — it never passes silently. Severity ∈ {critical, high, medium, low, info}.

Threat mapping vocabularies: OWASP Top 10 for Agentic Applications (Dec 2025; ids `ASI01`–`ASI10`), OWASP Top 10
for LLM Applications 2025 (`LLM01`–`LLM10`), MITRE ATLAS technique ids (e.g. `AML.T0109` AI Supply Chain Rug
Pull, `AML.T0110` AI Agent Tool Poisoning, `AML.T0051` LLM Prompt Injection, `AML.T0070` RAG Poisoning,
`AML.T0080` AI Agent Context Poisoning, `AML.T0086` Exfiltration via AI Agent Tool Invocation, `AML.T0098` AI
Agent Tool Credential Harvesting, `AML.T0010` AI Supply Chain Compromise and sub-techniques). Ids are stable;
display titles are refreshed from the official sources.

## 1. Derived classifications (inputs to checks)
- `side_effect_class`: from `annotations` (declared) overridden by `side_effects` (observed/verified) when they
  conflict: `read-only` if `read_only_hint=true` and no observed writes; `destructive` if `destructive_hint≠false`
  (MCP default is true) or observed destructive effects; `financial` if payment capability; `communicate` if
  egress/communication capability; `state-modifying` otherwise; `unknown` when annotations are absent and nothing
  is observed.
- `capabilities`: union of declared grants' capabilities and the side-effect class.
- Trust tiers: `unknown` is treated as `3-untrusted-public` for the trifecta check (worst case) and the finding
  is `indeterminate`.

## 2. Checks
| ID | Sev | Fires when | Maps to |
|---|---|---|---|
| SYM-TOOL-001 unpinned tool | high | tool has no digest, or `status=undigestable`, or exists only `declared` with no served digest | ASI04; AML.T0109, AML.T0110 |
| SYM-TOOL-002 served ≠ approved | critical | any served tool digest ∉ approved toolset, or an approved tool is missing | ASI04; AML.T0109 |
| SYM-TOOL-003 destructive + open-world without gate | high | (`destructive_hint≠false` ∨ observed destructive) ∧ `open_world_hint≠false` ∧ no grant with `approval_gate≠none` | ASI02; AML.T0086 |
| SYM-TOOL-004 non-canonicalizable definition | critical | `digest.status = undigestable` | ASI04 |
| SYM-TOOL-005 external `$ref` | high | any `$ref` in a schema not starting with `#` | ASI04; AML.T0110 |
| SYM-TOOL-006 hidden Unicode in model-visible text | high | Cf/Co/Cn, bidi or tag code points in name/title/description/schema descriptions | ASI01; AML.T0051 |
| SYM-TOOL-007 annotations absent | medium | no `annotations` or all hints absent | ASI02 |
| SYM-TOOL-008 tool-name shadowing | medium | same tool name on ≥ 2 servers with different digests | ASI04; AML.T0110 |
| SYM-TOOL-009 cross-tool directive (heuristic) | info | description matches patterns such as "before using <tool>", "ignore previous", "do not tell the user" | ASI01; AML.T0051 |
| SYM-TOOL-010 oversized or secret-shaped text | medium | model-visible text contains credential-shaped tokens, or description > 4 KiB | ASI04 |
| SYM-MCP-001 unauthenticated across a trust boundary | high | `authentication.mode = none` ∧ `crosses_trust_boundary` ∧ any grant capability ∈ {write, execute, credentials, payment} | ASI03 |
| SYM-MCP-002 floating package | high | stdio launcher without pinned version/digest (`npx -y pkg`, `pkg@latest`, `uvx pkg`) | ASI04; AML.T0010 |
| SYM-MCP-003 insecure transport | medium | remote endpoint scheme ≠ `https` | ASI07 |
| SYM-MCP-004 registry status | high / medium | resolution status `deleted` (high) / `deprecated` (medium); `unknown` → indeterminate | ASI04 |
| SYM-MCP-005 typosquat or name/package mismatch | high | Levenshtein ≤ 2 to a more popular registry name, or registry package identity ≠ configured package | ASI04; AML.T0010 |
| SYM-MCP-006 mixed-trust composition | medium | tools from `external` and `internal` trust zones exposed to the same agent without per-server gates | ASI04, ASI01 |
| SYM-AUTHZ-001 lethal trifecta / Rule of Two | critical | A: agent reads a source with `trust_tier ≥ 3` or unknown that is `instruction_bearing`; B: a grant/tool reads data with `classification ∉ {public}` or `data_classes ∩ {PII, credentials, source-code}`; C: a capability ∈ {network-egress, communicate, payment, write (external)} or an open-world non-read-only tool — and no `approval_gate = required` on every C leg. Rule-of-Two variant: more than two of {untrusted input, sensitive access, external effect} without a human gate | ASI01, ASI02; AML.T0086, AML.T0051 |
| SYM-AUTHZ-002 least-privilege gap | high / medium | `granted − required ≠ ∅` (over-privilege, high); `required − granted ≠ ∅` (misconfiguration, medium) | ASI03 |
| SYM-AUTHZ-003 long-lived credential for destructive capability | high | `credential.kind = static-long-lived` ∧ capability ∈ {write, execute, payment, credentials} | ASI03; AML.T0098 |
| SYM-AUTHZ-004 unauthenticated write | high | `unauthenticated` binding ∧ non-read capability | ASI03 |
| SYM-AUTHZ-005 unconstrained delegation | high | a delegation hop without `scopes`, `constraints` or `expires` | ASI07, ASI03 |
| SYM-AUTHZ-006 no enforcement point | high | `enforcement_point.kind = none` on any non-read grant | ASI10 |
| SYM-AUTHZ-007 undeclared egress | high | observed egress destination ∉ any grant scope | ASI02; AML.T0086 |
| SYM-MODEL-001 floating model alias | medium | hosted model with `alias_pinning = floating`, or `resolved_ref` unknown and no fingerprint | ASI04; AML.T0010 |
| SYM-MODEL-002 unsafe serialization | critical / medium | `risk_class = code-exec-on-load` ∨ `trust_remote_code = true` (critical); `chat_template_executable` (medium) | ASI05; AML.T0010 |
| SYM-MODEL-003 model not verified | high | `signature.status ≠ verified` (outcome shown; `signature-valid-unconstrained` named explicitly) | ASI04 |
| SYM-MODEL-004 unknown parent in derivation | medium | any derivation parent with `state = unknown` | AML.T0010 |
| SYM-INSTR-001 instruction editable by untrusted principal | high | an editor is an agent fed by untrusted inputs, or `editors` unknown for a system prompt | ASI06 |
| SYM-INSTR-002 instruction loads remote content | high | `loads_remote` non-empty | ASI01; AML.T0051 |
| SYM-INSTR-003 instruction changed since approval | critical | instruction digest ∉ approved snapshot | ASI06 |
| SYM-DATA-001 untrusted input feeding a privileged agent | high | `readsContextFrom` with `trust_tier ≥ 3` ∧ any write/egress grant | ASI01, ASI06; AML.T0070 |
| SYM-MEM-001 memory writers unknown | high | memory store with `writers` state unknown | ASI06; AML.T0080 |
| SYM-MEM-002 untrusted memory writer | critical | a writer fed by untrusted inputs without quarantine | ASI06; AML.T0080 |
| SYM-SNAP-001 serial regression | critical | `serial ≤ last-seen` for `(agent, kind)` | anti-rollback |
| SYM-SNAP-002 snapshot expired or stale | high | `now ≥ not_after` or observed staleness > policy | — |
| SYM-SNAP-003 chain gap | medium | `prev ≠ last-seen digest` | — |
| SYM-COV-001 surface not covered | high | any required surface `≠ queried` (blocks Verified) | — |
| SYM-COV-002 absence claimed without coverage | critical | a `absent-verified` claim on a surface whose status ≠ `queried` | — |
| SYM-TRUST-001 revoked / quarantined component in use | critical / high | snapshot contains a subject with `revoked` (critical) / `quarantined` (high) | ASI04 |
| SYM-TRUST-002 revoked publisher | critical | a component resolved from a revoked publisher identity | ASI04 |
| SYM-ATT-001 unconstrained signer | medium | any `signature-valid-unconstrained` outcome | — |
| SYM-ATT-002 evidence expired | medium | expired evidence still cited | — |
| SYM-EVAL-001 stale evaluation | high | any `subject_config` digest differs from the deployed configuration | ASI01 |
| SYM-A2A-001 unpinned agent card | medium | card fetched without digest pin or signature | ASI07 |
| SYM-SUB-001 undeclared sub-agent | high | observed `spawns`/`delegatesTo` edge ∉ declared | ASI10, ASI08 |
| SYM-REG-001 resolution without log inclusion | low | signer present but no transparency-log inclusion proof | ASI04 |

### 2.1 Extensions from the 2026 source-document review (implemented in `symbiote.policy`)

These checks close gaps identified by the review of the source analysis (WP17, `docs/research/`): the
Clinejection CI pattern, disabled human-in-the-loop settings, plaintext credentials in client configuration,
privileged container launches, hidden Unicode in rules files, repository-supplied hooks and skills, and
scanner indicators from the static model-artefact analysis (WP3). `symbiote policy explain ID` marks them
`extension: true`.

| ID | Sev | Fires when | Maps to |
|---|---|---|---|
| SYM-MCP-007 privileged container | high | a server's container launch uses `--privileged`, host namespaces, a `docker.sock` or host-root mount, added capabilities or root user | ASI05, ASI03 |
| SYM-MCP-008 project servers auto-enabled | medium | Claude Code `enableAllProjectMcpServers=true` with project-scoped servers (a checkout starts processes without consent) | ASI04, ASI09 |
| SYM-HITL-001 approval disabled by client settings | high | a client setting removes the human from every call to a server: Claude Code `defaultMode=bypassPermissions`, VS Code `chat.tools.autoApprove`, Gemini `trust`, Codex `approval_policy=never` (per-tool allow rules are excluded) | ASI09, ASI02 |
| SYM-CRED-001 plaintext credential in configuration | high | a credential binding stored inline in a configuration file (`storage.kind=file`, tag `inline-secret-in-config`) | ASI03; AML.T0098 |
| SYM-CI-001 AI agent in CI on untrusted input | critical | a GitHub Actions job runs an AI-agent action on an untrusted trigger (`issues`, `issue_comment`, `pull_request_target`, …) while holding a write token, default token permissions, repository secrets or a shared cache | ASI01, ASI04, ASI03; AML.T0051 |
| SYM-CI-003 untrusted event text in an agent prompt | critical | a workflow templates attacker-controlled event fields (`${{ github.event.issue.title }}`, bodies, comments, branch names) into an agent prompt or command (tag `prompt-interpolates:*`); the root cause of Clinejection | ASI01; AML.T0051 |
| SYM-HITL-002 agent CLI with approval-bypass flags | high | a workflow or script runs an agent CLI with `--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`, `--dangerously-bypass-approvals-and-sandbox` or `--allow-all-tools` (tag `agent-cli-bypass:*`) | ASI09, ASI02, ASI05 |
| SYM-CI-002 publish secret on untrusted trigger | high | a job reachable from untrusted events can read a long-lived publish/release secret (`NPM_TOKEN`, PyPI, VSCE/OVSX, registry) | ASI04, ASI03; AML.T0010 |
| SYM-INSTR-004 hidden Unicode in instructions | high | an instruction, rules or skill file contains invisible, bidi or tag code points ("Rules File Backdoor") | ASI01, ASI06; AML.T0051 |
| SYM-INSTR-005 repository-supplied hook | medium | project-scope hook commands run automatically on agent events | ASI05, ASI04 |
| SYM-SKILL-001 skill metadata invalid | low | SKILL.md name differs from the directory or violates the Agent Skills naming rules | ASI04 |
| SYM-SKILL-002 skill scripts with shell access | medium | a skill bundles scripts and its `allowed-tools` grant shell execution | ASI05, ASI04 |
| SYM-MODEL-005 malicious indicators in model artefacts | critical | the models-local collector recorded scanner indicators (dangerous pickle globals, broken-stream evasion, chat-template SSTI gadgets) as `malicious-indicator:*` tags | ASI05; AML.T0010, AML.T0018 |
| SYM-MODEL-006 weights metadata anomalies | medium | safetensors/GGUF structural anomalies recorded as `format-anomaly:*` tags | ASI04 |

Clarifications applied by the implementation:
- `SYM-TOOL-001` also fails for a tool server with no observed or approved tool definitions (nothing is pinned).
- `capabilities(tool)` adds `write` when `readOnlyHint=false` is declared (the tool modifies its environment),
  in addition to the side-effect-class mapping; observed side effects override declared hints.
- `SYM-AUTHZ-001` legs may be set by labelled name heuristics for servers that ingest externally authored
  content, reach sensitive systems or send data out; findings say so, and an unknown leg yields `indeterminate`.
- A remote tool server with blanket auto-approval counts as an exfiltration leg: every call sends arguments
  across the trust boundary.

## 3. Computed flags
Flags are summaries of the checks above with inputs cited (`agentbom-profile.md §3.16`): `lethal-trifecta`,
`rule-of-two-violation` (SYM-AUTHZ-001), `unpinned-tool` (SYM-TOOL-001/004), `floating-model-alias`
(SYM-MODEL-001), `destructive-open-world-ungated` (SYM-TOOL-003), `unsigned-model` (SYM-MODEL-003),
`unsafe-serialization` (SYM-MODEL-002), `unauthenticated-tool-server` (SYM-MCP-001), `static-long-lived-credential`
(SYM-AUTHZ-003), `undeclared-component-observed` (SYM-TOOL-002, SYM-SUB-001). Value `unknown` when any input is
unknown.

## 4. Output
Findings are emitted as JSON (`Finding` records), as a rich table, and as **SARIF 2.1.0** (`--sarif`) for
GitHub code scanning, with `ruleId = check id`, `level` from severity, and `locations` from evidence locators.
Exit code 1 when any finding at or above `--fail-on` (default `high`) is `fail`; `indeterminate` findings are
reported and counted separately (`--fail-on-indeterminate` to treat them as failures).

## 5. Rego export
`symbiote policy export-rego DIR` writes `agentbom.rego` (`package agentbom`, Rego v1 syntax) and `manifest.json`.
The input is the companion document; fields whose value is null are omitted from it, so rules read optional
values through fallbacks and never treat a missing field as `false`.

- **Output.** `data.agentbom.findings` is a set of `{checkId, severity, state: "fail", subjectRefs, message}` with
  the same `checkId`, `severity` and `subjectRefs` the built-in engine reports. `data.agentbom.deny` holds one
  message per finding at `critical` or `high`, matching `--fail-on high`, for
  `conftest test --policy DIR --namespace agentbom agentbom.json`.
- **Coverage is explicit.** `manifest.json` lists the exported checks (`rego`) and the rest (`builtinOnly`). Checks
  that need graph reachability (SYM-AUTHZ-001), three-valued reasoning, a baseline or chain state (SYM-TOOL-002,
  SYM-INSTR-003, SYM-SNAP-001/003, SYM-SUB-001) or an ordered client decision table (SYM-HITL-001) stay
  built-in. A Rego rule never reports `pass` or `indeterminate`: no finding means only that the rule did not fire,
  so the bundle cannot stand in for `symbiote policy check`.
- **Organisation policy.** `symbiote policy check FILE --rego DIR` evaluates `data.agentbom.findings` from the Rego
  in `DIR` with the `opa` binary and merges the results into the same report, SARIF and exit code. Organisation
  rules use their own ids (for example `ORG-001`). A finding that duplicates a built-in one (same check id and
  subjects) is dropped, a malformed one is reported as a warning, and a missing `opa` or a failed evaluation
  exits 6.
- **Parity.** `tests/unit/policy/test_rego.py` pins every document path and enum literal the rules read to the
  published companion schema, and, where `opa` is installed, asserts that OPA's findings equal the built-in
  failing findings for the exported checks. The CI `rego-parity` job installs OPA and makes those tests mandatory.
