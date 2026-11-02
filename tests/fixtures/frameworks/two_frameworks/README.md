# Framework fixture: three agent frameworks in one repository

Used by `tests/unit/collect/test_frameworks.py::test_scan_end_to_end_two_frameworks`. Nothing here is imported or
executed by the tests: the `frameworks` collector parses it statically.

- `support/` — OpenAI Agents SDK: a triage agent that hands off to a refunds agent (same file) and a billing
  agent (imported from `billing.py`), a function tool that needs approval and a hosted web-search tool.
- `ops/options.py` — Claude Agent SDK options with `permission_mode="bypassPermissions"`, an MCP server and a
  reviewer sub-agent.
- `crew/config/` — CrewAI `agents.yaml` / `tasks.yaml` with delegation and a human-reviewed task.
