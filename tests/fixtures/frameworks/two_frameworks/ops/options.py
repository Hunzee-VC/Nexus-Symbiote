"""An operations agent run with the Claude Agent SDK."""

from claude_agent_sdk import AgentDefinition, ClaudeAgentOptions

options = ClaudeAgentOptions(
    system_prompt={"type": "preset", "preset": "claude_code", "append": "Never touch production."},
    model="claude-sonnet-4-5",
    allowed_tools=["Read", "Bash(git status:*)", "mcp__tickets__list_tickets"],
    permission_mode="bypassPermissions",
    mcp_servers={
        "tickets": {"type": "stdio", "command": "npx", "args": ["-y", "@example/tickets-mcp@2.1.0"]},
    },
    agents={
        "reviewer": AgentDefinition(
            description="Reviews diffs before merge",
            prompt="Review the diff and list risks.",
            tools=["Read", "Grep"],
            model="haiku",
        ),
    },
)
