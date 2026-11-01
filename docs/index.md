# Symbiote

**The Agent Bill of Materials (AgentBOM) toolkit for the agentic-AI supply chain.**

Symbiote generates, validates, diffs, verifies, attests and enforces AgentBOMs — bills of materials for AI
agents that answer what a software SBOM cannot:

> Which agent is running, what can it access or change, where did its dependencies come from, who authorized it,
> and has any of that changed since approval?

It supports and extends **CycloneDX 1.7** and **SPDX 3.0.1** without forking either standard. Every document it
emits validates against the official schemas; agent-specific semantics travel through the standards' own
extension points under one tool-neutral `agentbom:` vocabulary; a companion document carries what neither
format can express.

## The four planes

| Plane | Question | What Symbiote records |
|---|---|---|
| **Composition** | What was built or declared? | Agents, tool servers and tool definitions (by content digest), instructions, prompts, skills, models (weights by manifest root, hosted by provider + alias + resolved snapshot), data sources, software layer |
| **Authorization** | What is the agent permitted to do? | Grants (capability, scope, granter, delegation chain, approval gate, enforcement point, credential binding), identities by reference, computed flags such as the lethal trifecta |
| **Observability** | What is deployed and what has it actually done? | Four snapshot kinds — declared, approved, deployed, observed — and the signed deltas between them; live `tools/list` and OpenTelemetry traces as observed sources |
| **Assurance** | Why should we trust each claim? | Per-claim assurance (declared / observed / verified), explicit unknowns, coverage statements, evidence by digest, evaluations bound to configuration digests, AI-VEX statements, trust status |

## Where to go next

- [Quickstart](quickstart.md) — install and run the first commands.
- [Concepts](concepts/four-planes.md) — the ideas behind the model.
- [Specification](spec/README.md) — the normative profile Symbiote implements.
- [Research](research/README.md) — the gap analysis of CycloneDX 1.7 and SPDX 3.0.1 for agents.
