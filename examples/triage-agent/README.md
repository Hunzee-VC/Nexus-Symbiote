# Example: `triage-agent`

A realistic (and deliberately imperfect) issue-triage agent used as the golden fixture for Symbiote's
documentation and tests. Everything here is synthetic; credentials are placeholders that the secret scanner
must still redact.

What it contains:

| Surface | Files | Deliberate findings |
|---|---|---|
| MCP client configs | `.mcp.json` (Claude Code), `.cursor/mcp.json`, `.vscode/mcp.json`, `.codex/config.toml`, `.gemini/settings.json` | `filesystem` server launched with `npx -y … @latest` (floating, `SYM-MCP-002`); `github` server authenticated via an env-var token (name recorded, value never) |
| Instructions | `AGENTS.md`, `CLAUDE.md`, `prompts/system.md` (Jinja), `.cursor/rules/triage.mdc` | `prompts/system.md` includes a remote URL (`SYM-INSTR-002`) |
| Skill | `.claude/skills/issue-triage/SKILL.md` + `scripts/label.sh` | skill with an executable script; `allowed-tools` grants `Bash(gh:*)` |
| Models | `models/reranker-mini/` (tiny safetensors + a pickle file + chat template), hosted `claude-sonnet-4-5` alias in `agent.yaml` | pickle ⇒ `SYM-MODEL-002`; floating alias ⇒ `SYM-MODEL-001` |
| Data | `agent.yaml` RAG index over public GitHub issues (untrusted, instruction-bearing) + a memory store | lethal-trifecta candidate: untrusted input + private repo read + `communicate` via `send_comment` |
| Sub-agent | `agent-card.json` (A2A peer `release-notes-writer`) | delegation without scopes (`SYM-AUTHZ-005`) |
| Policy | `policy/authz.yaml` | declared grants, one `create_pull_request` gate `required` |
| Traces | `traces/otel-genai.json` | observed `execute_tool` spans incl. an undeclared tool (`SYM-TOOL-002` when diffed) |
| Software layer | `sbom.cdx.json` (tiny CycloneDX 1.6 SBOM) | imported verbatim |

Run (once the collectors land): `symbiote scan examples/triage-agent --profile standard -o out/`.
