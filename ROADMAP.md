# Roadmap

Nexus SymBiote is an early alpha focused on Agent Bill of Materials (AgentBOM) generation, validation, and review for agentic AI supply chains. This document tracks near-term work that addresses maturity, coverage, and usability gaps.

## Near term (alpha hardening)

- [x] Add a pinned CodeQL workflow for main and pull requests. Hosted analysis runs, and its high and critical policy is part of the required `Verified CI` check.
- [ ] Apply branch protection, private vulnerability reporting and secret scanning on GitHub (see [repository controls](docs/repository-controls.md#operator-prerequisites)).
- [ ] Public release of a reviewed 0.1.x (or 0.2.0) with signed provenance and PyPI trusted publishing.
- [ ] Decide which collectors, export formats and runtime adapters are supported for 0.1.x and which stay experimental. The project has a single maintainer, so a smaller supported surface is easier to keep correct.
- [ ] Expand security regression corpus and document known false-positive/negative classes.
- [ ] Deeper verification and BOM adapters for popular agent frameworks (LangGraph, CrewAI, OpenAI Agents SDK, Google ADK, etc.) and MCP configurations, with Nexus-ShadowScan as the primary discovery scanner.
- [ ] Stronger live-observation path documentation and operator guidance for isolated workers.
- [ ] Example repositories and end-to-end tutorials that combine Nexus-ShadowScan discovery with SymBiote inventory and policy.
- [ ] Record a short terminal demo of the [offline walkthrough](examples/README.md) and link it from the README once v0.1.0 is tagged.

## Medium term

- Broader ecosystem coverage (more package managers, model registries, skill registries, A2A implementations).
- Optional runtime-assurance adapters with clear mediation boundaries.
- Community contribution guidelines and issue templates refined from real usage.
- Benchmarks against public agent projects to measure coverage and noise.

## Non-goals for the near term

- Claiming that an inventory or low risk score proves an agent or model is benign.
- Default execution of untrusted project code, MCP launchers, or model loaders.
- Long-term support commitments while the project remains alpha.

Contributions that advance the items above (especially tested scanner coverage, documentation, and regression fixtures) are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Historical experimental work

The [closed-PR audit](docs/audits/closed-pr-review-2026-11-02.md) records what reached the supported package and what remains separate. The experimental foundation's salted Merkle disclosure protocol, full snapshot chain format, OPA/Rego export and parity suite, and Kubernetes/trace import contracts are not supported interfaces on `main`. Evaluate any future port against the current threat model and version its wire format; a merge into an experimental branch does not establish shipped compatibility. Discovery expansion should continue through Nexus-ShadowScan.
