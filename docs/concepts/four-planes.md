# The four planes

An AgentBOM is organised around four questions. Each plane has its own entities, its own evidence and its own
failure modes; a document that answers only the first is a conventional SBOM with AI components attached.

## Composition — what was built or declared?
Agents (root, sub-agents, external peers), tool servers and **tool definitions** (the name, description and
JSON schema the model actually reads — content-addressed with `tooldef/v1`), instructions (system prompts,
`AGENTS.md`, `CLAUDE.md`, `SKILL.md`, rules files — exact-bytes digests), prompt templates, skills (directory
manifests compatible with OpenSSF model-signing), models (weights by per-file manifest root and per-tensor
manifest; hosted models by provider, requested alias and resolved snapshot), data sources (datasets, RAG
indexes, memory stores with trust tiers and writers), and the software layer imported from cdxgen or syft.

## Authorization — what is the agent permitted to do?
Grants bind a subject to a capability class (read, write, execute, network egress, filesystem, credentials,
payment, communicate, delegate, memory write) with a scope, a granter, an optional delegation chain, conditions,
a human approval gate, validity, a policy-bundle digest and the enforcement point that actually denies.
Identities and credential bindings are recorded by reference, never by value. Declared, policy-derived
*effective* and *observed* grants are kept distinguishable. Computed flags — lethal trifecta, Rule of Two,
unpinned tool, floating alias, destructive-and-open-world without a gate — cite their inputs.

## Observability — what is deployed and what has it done?
Four snapshot kinds over one graph: **declared** (configuration), **approved** (signed by a reviewer),
**deployed** (bound to a workload identity and environment) and **observed** (live `tools/list`, OpenTelemetry
GenAI traces, k8s-aibom inventories). Snapshots carry a monotone serial, a hash chain to the previous snapshot
and a validity window. The diff between kinds is the detection primitive.

## Assurance — why should each claim be trusted?
Every contestable fact is a claim with an assurance level — `declared`, `observed`, `verified` — and a state —
`present`, `absent-verified`, `unknown`. Coverage statements say which surfaces were examined and which could
not be. Evidence is referenced by digest. Evaluations are bound to the exact configuration digests they tested.
AI-VEX statements scope a weakness to a (model, configuration) tuple. Trust status (allowlisted, quarantined,
revoked) is keyed on identity digests, never display names.
