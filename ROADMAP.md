# Roadmap

Nexus SymBiote is an early alpha focused on Agent Bill of Materials (AgentBOM) generation, validation, and review for agentic AI supply chains. This document tracks near-term work that addresses maturity, coverage, and usability gaps.

## Near term (alpha hardening)

- [x] CodeQL code scanning on main and pull requests.
- [ ] Public release of a reviewed 0.1.x (or 0.2.0) with signed provenance and PyPI trusted publishing.
- [ ] Expand security regression corpus and document known false-positive/negative classes.
- [ ] Additional scanners or deeper support for popular agent frameworks (LangGraph, CrewAI, OpenAI Agents SDK, Google ADK, etc.) and more MCP client/host configurations.
- [ ] Stronger live-observation path documentation and operator guidance for isolated workers.
- [ ] Example repositories and end-to-end tutorials that combine Nexus-ShadowScan discovery with SymBiote inventory and policy.

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
