"""Discovery cases for agent components: MCP servers, skills, instructions, settings and agents."""

from __future__ import annotations

from .artifacts import hex40, hex64
from .build import ML_MODEL, as_json, case, decoy, edge, ex, has, loc, purl, sha, text, typ, ver
from .model import Case


def project_mcp_config() -> Case:
    config = {
        "mcpServers": {
            "fs-workspace": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "./workspace"],
            },
            "git-history": {
                "command": "uvx",
                "args": ["mcp-server-git==2025.9.25", "--repository", "."],
            },
            "linear-remote": {
                "type": "http",
                "url": "https://mcp.linear.app/mcp",
                "headers": {"Authorization": "Bearer ${LINEAR_API_KEY}"},
            },
        }
    }
    guide = text(
        """
        # Adding an MCP server

        Copy this example into `.mcp.json` and change the name:

        ```json
        {
          "mcpServers": {
            "decoy-example-server": {
              "command": "npx",
              "args": ["-y", "@example/decoy-mcp@9.9.9"]
            }
          }
        }
        ```
        """
    )
    return case(
        "a01-project-mcp-config",
        "Project MCP configuration with npx, uvx and remote servers",
        {".mcp.json": as_json(config), "docs/mcp-setup.md": guide},
        [
            ex(
                "a01.fs",
                "agent",
                "mcp-server",
                "fs-workspace",
                attrs=[has("launcher", "npx"), ver("2025.8.21"), loc(".mcp.json")],
            ),
            ex(
                "a01.fs.package",
                "platform",
                "mcp-server-package",
                "server-filesystem",
                attrs=[
                    ver("2025.8.21"),
                    purl("pkg:npm/%40modelcontextprotocol/server-filesystem@2025.8.21"),
                ],
            ),
            ex(
                "a01.git",
                "agent",
                "mcp-server",
                "git-history",
                attrs=[has("launcher", "uvx"), ver("2025.9.25"), loc(".mcp.json")],
            ),
            ex(
                "a01.git.package",
                "platform",
                "mcp-server-package",
                "mcp-server-git",
                attrs=[ver("2025.9.25"), purl("pkg:pypi/mcp-server-git@2025.9.25")],
            ),
            ex(
                "a01.linear",
                "agent",
                "mcp-server",
                "linear-remote",
                attrs=[
                    has("endpoint", "https://mcp.linear.app/mcp"),
                    has("transport", "http"),
                    loc(".mcp.json"),
                ],
            ),
        ],
        edges=[
            edge("a01.fs", "a01.fs.package", "launches"),
            edge("a01.git", "a01.git.package", "launches"),
        ],
        decoys=[
            decoy(
                "a01.docs",
                "decoy-mcp",
                "a01.fs",
                "a configuration example in documentation is not a configured server",
            )
        ],
        surface="project-scoped .mcp.json",
        sources=("MCP", "Claude Code", "agent-bom", "cdxgen", "Trusera", "Cisco"),
    )


def other_client_configs() -> Case:
    digest = hex64("a02:postgres")
    cursor = {
        "mcpServers": {
            "postgres-ro": {
                "command": "docker",
                "args": [
                    "run",
                    "-i",
                    "--rm",
                    f"mcp/postgres@sha256:{digest}",
                    "postgresql://readonly@db.internal:5432/app",
                ],
            }
        }
    }
    vscode = {"servers": {"sentry-issues": {"type": "sse", "url": "https://mcp.sentry.dev/sse"}}}
    codex = text(
        """
        [mcp_servers.jira-cloud]
        command = "npx"
        args = ["-y", "mcp-remote@0.1.29", "https://mcp.atlassian.com/v1/sse"]
        """
    )
    gemini = {
        "mcpServers": {"browser-tools": {"command": "npx", "args": ["@playwright/mcp@0.0.41"]}}
    }
    return case(
        "a02-other-client-configs",
        "MCP servers configured for Cursor, VS Code, Codex and Gemini CLI",
        {
            ".cursor/mcp.json": as_json(cursor),
            ".vscode/mcp.json": as_json(vscode),
            ".codex/config.toml": codex,
            ".gemini/settings.json": as_json(gemini),
        },
        [
            ex(
                "a02.postgres",
                "agent",
                "mcp-server",
                "postgres-ro",
                attrs=[has("image digest", digest), loc(".cursor/mcp.json")],
            ),
            ex(
                "a02.sentry",
                "agent",
                "mcp-server",
                "sentry-issues",
                attrs=[has("endpoint", "https://mcp.sentry.dev/sse"), loc(".vscode/mcp.json")],
            ),
            ex(
                "a02.jira",
                "agent",
                "mcp-server",
                "jira-cloud",
                attrs=[
                    ver("0.1.29"),
                    has("endpoint", "https://mcp.atlassian.com/v1/sse"),
                    loc(".codex/config.toml"),
                ],
            ),
            ex(
                "a02.browser",
                "agent",
                "mcp-server",
                "browser-tools",
                attrs=[ver("0.0.41"), loc(".gemini/settings.json")],
            ),
        ],
        surface="client-specific MCP configuration files in a project",
        sources=("Cursor", "VS Code", "Codex CLI", "Gemini CLI", "agent-bom"),
    )


def user_scope_configs() -> Case:
    claude = {
        "mcpServers": {
            "slack-notify": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-slack@2025.4.25"],
                "env": {"SLACK_TEAM_ID": "T0000000"},
            }
        },
        "projects": {},
    }
    cursor = {"mcpServers": {"notion-wiki": {"url": "https://mcp.notion.com/mcp"}}}
    desktop = {
        "mcpServers": {
            "brave-search": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-brave-search@0.6.2"],
            }
        }
    }
    codex = text(
        """
        [mcp_servers.k8s-admin]
        command = "uvx"
        args = ["kubernetes-mcp-server==0.0.52"]
        """
    )
    return case(
        "a03-user-scope-configs",
        "MCP servers configured in the user's home directory",
        {
            ".claude.json": as_json(claude),
            ".cursor/mcp.json": as_json(cursor),
            ".config/Claude/claude_desktop_config.json": as_json(desktop),
            ".codex/config.toml": codex,
        },
        [
            ex(
                "a03.slack",
                "agent",
                "mcp-server",
                "slack-notify",
                attrs=[ver("2025.4.25"), loc(".claude.json")],
            ),
            ex(
                "a03.notion",
                "agent",
                "mcp-server",
                "notion-wiki",
                attrs=[has("endpoint", "https://mcp.notion.com/mcp"), loc(".cursor/mcp.json")],
            ),
            ex(
                "a03.brave",
                "agent",
                "mcp-server",
                "brave-search",
                attrs=[ver("0.6.2"), loc("claude_desktop_config.json")],
            ),
            ex(
                "a03.k8s",
                "agent",
                "mcp-server",
                "k8s-admin",
                attrs=[ver("0.0.52"), loc(".codex/config.toml")],
            ),
        ],
        home_scope=True,
        surface="user-scoped agent configuration (the scan target is the home directory)",
        sources=("Claude Code", "Claude Desktop", "Cursor", "Codex CLI", "agent-bom"),
    )


def skills() -> Case:
    pdf = text(
        """
        ---
        name: pdf-forms
        description: Fill and validate PDF forms from structured data.
        allowed-tools: Read, Bash(python:*)
        ---

        # PDF forms

        Run `scripts/fill_form.py` with the field mapping in `reference/FIELDS.md`.
        """
    )
    script = text(
        """
        import json
        import sys

        mapping = json.load(sys.stdin)
        print(sorted(mapping))
        """
    )
    release = text(
        """
        ---
        name: release-notes
        description: Draft release notes from merged pull requests.
        ---

        # Release notes

        Group changes by area and link each pull request.
        """
    )
    cleaning = text(
        """
        ---
        name: data-cleaning
        description: Normalize CSV exports before analysis.
        ---

        # Data cleaning

        Trim whitespace, normalize dates to ISO 8601 and drop empty rows.
        """
    )
    authoring = text(
        """
        # Writing a skill

        A skill is a directory with a `SKILL.md` file. For example:

        ```markdown
        ---
        name: decoy-skill-example
        description: Replace this description.
        ---
        ```
        """
    )
    root = ".claude/skills/pdf-forms"
    return case(
        "a04-skills",
        "Agent skills with a bundled script",
        {
            f"{root}/SKILL.md": pdf,
            f"{root}/scripts/fill_form.py": script,
            f"{root}/reference/FIELDS.md": text("# Fields\n\n- `name`\n- `date_of_birth`"),
            ".claude/skills/release-notes/SKILL.md": release,
            "skills/data-cleaning/SKILL.md": cleaning,
            "docs/SKILL-AUTHORING.md": authoring,
        },
        [
            ex(
                "a04.pdf",
                "agent",
                "skill",
                "pdf-forms",
                attrs=[
                    sha(f"{root}/SKILL.md"),
                    has("description", "validate PDF forms"),
                    loc(root),
                ],
            ),
            ex(
                "a04.release",
                "agent",
                "skill",
                "release-notes",
                attrs=[
                    sha(".claude/skills/release-notes/SKILL.md"),
                    has("description", "merged pull requests"),
                ],
            ),
            ex(
                "a04.cleaning",
                "agent",
                "skill",
                "data-cleaning",
                attrs=[
                    sha("skills/data-cleaning/SKILL.md"),
                    has("description", "Normalize CSV exports"),
                ],
            ),
            ex(
                "a04.script",
                "agent",
                "skill-script",
                "fill_form.py",
                attrs=[sha(f"{root}/scripts/fill_form.py")],
            ),
        ],
        edges=[edge("a04.pdf", "a04.script", "bundles")],
        decoys=[
            decoy(
                "a04.docs",
                "decoy-skill-example",
                "a04.pdf",
                "a skill shown as an example in documentation is not installed",
            )
        ],
        surface="SKILL.md directories",
        sources=("Agent Skills", "agent-bom", "cdxgen", "Cisco"),
    )


def instruction_files() -> Case:
    files = {
        "CLAUDE.md": text(
            """
            # Project guidance

            Follow @docs/style.md for naming.

            - Run `make test` before committing.
            """
        ),
        "docs/style.md": text("# Style\n\nUse snake_case for Python and kebab-case for files."),
        "AGENTS.md": text("# Agents\n\nKeep changes small and explain each one."),
        ".cursorrules": text("Prefer composition over inheritance.\nNever edit generated files."),
        ".github/copilot-instructions.md": text("Write tests with pytest and name them test_*.py."),
        ".windsurfrules": text("Ask before adding a dependency."),
        "GEMINI.md": text("# Gemini\n\nUse the project formatter before finishing."),
    }
    names = {
        "a05.claude": ("claude.md", "CLAUDE.md"),
        "a05.agents": ("agents.md", "AGENTS.md"),
        "a05.cursorrules": (".cursorrules", ".cursorrules"),
        "a05.copilot": ("copilot-instructions.md", ".github/copilot-instructions.md"),
        "a05.windsurf": (".windsurfrules", ".windsurfrules"),
        "a05.gemini": ("gemini.md", "GEMINI.md"),
    }
    expects = [
        ex(expect_id, "agent", "instruction-file", token, attrs=[sha(path)])
        for expect_id, (token, path) in names.items()
    ]
    expects.append(
        ex(
            "a05.import",
            "agent",
            "imported-instruction",
            "docs/style.md",
            attrs=[sha("docs/style.md")],
        )
    )
    return case(
        "a05-instruction-files",
        "Instruction files for six coding agents, one with an import",
        files,
        expects,
        edges=[edge("a05.claude", "a05.import", "imports")],
        surface="agent instruction files",
        sources=("Claude Code", "AGENTS.md", "Cursor", "GitHub Copilot", "agent-bom", "cdxgen"),
    )


def coding_agent_settings() -> Case:
    settings = {
        "permissions": {
            "allow": ["Bash(npm run test:*)", "Read(./src/**)"],
            "deny": ["Read(./.env)", "Bash(curl:*)"],
            "defaultMode": "acceptEdits",
        },
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "./.claude/hooks/guard.sh"}],
                }
            ]
        },
        "enabledMcpjsonServers": ["fs-workspace"],
        "env": {"NODE_ENV": "development"},
    }
    reviewer = text(
        """
        ---
        name: code-reviewer
        description: Reviews diffs for correctness and missing tests.
        tools: Read, Grep, Glob
        model: sonnet
        ---

        Review the staged diff. Report defects first, then missing tests.
        """
    )
    command = text(
        """
        ---
        description: Run the release checklist and open a pull request.
        allowed-tools: Bash(git status:*), Bash(gh pr create:*)
        ---

        Run the checklist in `docs/release.md`, then open a pull request.
        """
    )
    return case(
        "a06-coding-agent-settings",
        "Coding-agent settings with a hook, a subagent and a command",
        {
            ".claude/settings.json": as_json(settings),
            ".claude/hooks/guard.sh": text("#!/bin/sh\ncat >/dev/null\nexit 0"),
            ".claude/agents/code-reviewer.md": reviewer,
            ".claude/commands/ship.md": command,
        },
        [
            ex(
                "a06.settings",
                "agent",
                "coding-agent-settings",
                ".claude/settings.json",
                "claude code",
                "claude-code",
                attrs=[has("hook event", "PreToolUse"), has("permission mode", "acceptEdits")],
            ),
            ex("a06.hook", "agent", "hook", "guard.sh", attrs=[sha(".claude/hooks/guard.sh")]),
            ex(
                "a06.subagent",
                "agent",
                "subagent",
                "code-reviewer",
                attrs=[
                    has("model", "sonnet"),
                    has("description", "missing tests"),
                    sha(".claude/agents/code-reviewer.md"),
                ],
            ),
            ex(
                "a06.command",
                "agent",
                "command",
                "commands/ship",
                "ship.md",
                attrs=[has("description", "release checklist"), sha(".claude/commands/ship.md")],
            ),
        ],
        edges=[edge("a06.settings", "a06.hook", "runs")],
        executable=(".claude/hooks/guard.sh",),
        surface="Claude Code project settings, hooks, subagents and commands",
        sources=("Claude Code", "agent-bom", "Cisco"),
    )


def a2a_agent() -> Case:
    card = {
        "protocolVersion": "0.3.0",
        "name": "invoice-reconciler",
        "description": "Matches supplier invoices against ledger entries.",
        "url": "https://agents.acme.example/a2a/invoices",
        "version": "2.3.0",
        "preferredTransport": "JSONRPC",
        "capabilities": {"streaming": True, "pushNotifications": False},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": "match-ledger-entries",
                "name": "Match ledger entries",
                "description": "Match invoice lines to ledger entries.",
                "tags": ["finance"],
            }
        ],
        "securitySchemes": {
            "oauth": {
                "type": "oauth2",
                "flows": {
                    "clientCredentials": {
                        "tokenUrl": "https://login.acme.example/oauth/token",
                        "scopes": {"invoices.read": "Read invoices"},
                    }
                },
            }
        },
        "security": [{"oauth": ["invoices.read"]}],
    }
    client = text(
        """
        import httpx
        from a2a.client import A2ACardResolver

        SHIPPING_AGENT_URL = "https://agents.partner.example/a2a/shipping"


        async def resolve() -> object:
            async with httpx.AsyncClient() as http:
                resolver = A2ACardResolver(httpx_client=http, base_url=SHIPPING_AGENT_URL)
                return await resolver.get_agent_card()
        """
    )
    return case(
        "a07-a2a-agent",
        "A2A agent card and a client of a remote agent",
        {".well-known/agent-card.json": as_json(card), "src/orchestrator.py": client},
        [
            ex(
                "a07.card",
                "agent",
                "a2a-agent",
                "invoice-reconciler",
                attrs=[
                    ver("2.3.0"),
                    has("endpoint", "https://agents.acme.example/a2a/invoices"),
                    loc(".well-known/agent-card.json"),
                ],
            ),
            ex("a07.skill", "agent", "a2a-skill", "match-ledger-entries"),
            ex(
                "a07.remote",
                "agent",
                "remote-a2a-agent",
                "agents.partner.example",
                attrs=[loc("src/orchestrator.py")],
            ),
        ],
        edges=[edge("a07.card", "a07.skill", "offers")],
        surface="A2A agent card and SDK client",
        sources=("A2A protocol", "Trusera", "Cisco", "agent-bom"),
    )


def framework_agents() -> Case:
    requirements = text(
        """
        langgraph==0.2.50
        crewai==0.80.0
        openai-agents==0.0.7
        autogen-agentchat==0.4.0
        """
    )
    refunds = text(
        """
        from langchain_openai import ChatOpenAI
        from langgraph.prebuilt import create_react_agent

        from .tools import lookup_policy

        refund_agent = create_react_agent(
            ChatOpenAI(model="gpt-4o"),
            tools=[lookup_policy],
            name="refund-desk-agent",
        )
        """
    )
    fraud = text(
        """
        from crewai import Agent, Crew, Task

        analyst = Agent(
            role="Fraud Analyst",
            goal="Flag unusual refund patterns",
            backstory="You have audited payment disputes for ten years.",
            llm="claude-3-5-haiku-20241022",
        )
        audit = Task(description="Review this week's refunds.", expected_output="A list", agent=analyst)
        crew = Crew(agents=[analyst], tasks=[audit])
        """
    )
    triage = text(
        """
        from agents import Agent

        triage = Agent(
            name="Triage Router",
            instructions="Route each request to the right specialist.",
            model="gpt-4.1",
        )
        """
    )
    planner = text(
        """
        from autogen_agentchat.agents import AssistantAgent
        from autogen_ext.models.openai import OpenAIChatCompletionClient

        planner = AssistantAgent(
            "planner_bot",
            model_client=OpenAIChatCompletionClient(model="o3-mini"),
        )
        """
    )
    tools = text(
        '''
        from langchain_core.tools import tool


        @tool
        def lookup_policy(section: str) -> str:
            """Return one section of the refund policy."""
            return section
        '''
    )
    packages = [
        ("a08.langgraph", "langgraph", "0.2.50"),
        ("a08.crewai", "crewai", "0.80.0"),
        ("a08.openai-agents", "openai-agents", "0.0.7"),
        ("a08.autogen", "autogen-agentchat", "0.4.0"),
    ]
    expects = [
        ex(
            "a08.refund",
            "agent",
            "framework-agent",
            "refund-desk-agent",
            attrs=[has("model", "gpt-4o"), loc("agents/refunds.py")],
        ),
        ex(
            "a08.fraud", "agent", "framework-agent", "Fraud Analyst", attrs=[loc("agents/fraud.py")]
        ),
        ex(
            "a08.triage",
            "agent",
            "framework-agent",
            "Triage Router",
            attrs=[loc("agents/triage.py")],
        ),
        ex(
            "a08.planner",
            "agent",
            "framework-agent",
            "planner_bot",
            attrs=[loc("agents/planner.py")],
        ),
    ]
    expects += [
        ex(
            expect_id,
            "platform",
            "agent-framework-package",
            name,
            attrs=[ver(version), purl(f"pkg:pypi/{name}@{version}")],
        )
        for expect_id, name, version in packages
    ]
    return case(
        "a08-framework-agents",
        "Agents defined with LangGraph, CrewAI, OpenAI Agents SDK and AutoGen",
        {
            "requirements.txt": requirements,
            "agents/__init__.py": b"",
            "agents/refunds.py": refunds,
            "agents/fraud.py": fraud,
            "agents/triage.py": triage,
            "agents/planner.py": planner,
            "agents/tools.py": tools,
        },
        expects,
        surface="agent definitions in framework code",
        sources=("LangGraph", "CrewAI", "OpenAI Agents SDK", "AutoGen", "Cisco", "Trusera"),
    )


def prompt_files() -> Case:
    files = {
        "prompts/system_prompt.md": text(
            """
            You are the support assistant for Acme Parcel.
            Answer from the policy documents only and cite the section you used.
            """
        ),
        "prompts/classifier.jinja2": text(
            """
            Classify the ticket below as one of: {{ labels | join(", ") }}.

            Ticket: {{ ticket }}
            """
        ),
        "prompts/judge.prompt.yaml": text(
            """
            name: answer-judge
            input_variables: [question, answer]
            template: |
              Rate the answer from 1 to 5 for faithfulness to the policy.
              Question: {question}
              Answer: {answer}
            """
        ),
        "src/prompts.py": text(
            """
            from pathlib import Path

            SYSTEM_PROMPT = Path("prompts/system_prompt.md").read_text()
            """
        ),
    }
    return case(
        "a09-prompt-files",
        "Prompt templates kept as files",
        files,
        [
            ex(
                "a09.system",
                "agent",
                "prompt",
                "system_prompt.md",
                attrs=[sha("prompts/system_prompt.md")],
            ),
            ex(
                "a09.classifier",
                "agent",
                "prompt",
                "classifier.jinja2",
                attrs=[sha("prompts/classifier.jinja2")],
            ),
            ex(
                "a09.judge",
                "agent",
                "prompt",
                "judge.prompt.yaml",
                attrs=[sha("prompts/judge.prompt.yaml")],
            ),
        ],
        surface="prompt template files",
        sources=("cdxgen", "Cisco", "OWASP LLM Top 10"),
    )


def guardrails_and_memory() -> Case:
    config = text(
        """
        models:
          - type: main
            engine: openai
            model: gpt-4o-mini
        rails:
          input:
            flows:
              - self check input
          output:
            flows:
              - self check output
        """
    )
    rails = text(
        """
        define flow self check input
          $allowed = execute self_check_input
          if not $allowed
            bot refuse to respond
            stop
        """
    )
    memory = text(
        """
        from langgraph.checkpoint.sqlite import SqliteSaver
        from mem0 import Memory

        checkpointer = SqliteSaver.from_conn_string("state/checkpoints.db")
        memory = Memory.from_config(
            {
                "vector_store": {
                    "provider": "redis",
                    "config": {"redis_url": "redis://memory.internal:6379"},
                }
            }
        )
        """
    )
    return case(
        "a10-guardrails-memory",
        "Guardrail configuration and agent memory stores",
        {"guardrails/config.yml": config, "guardrails/rails.co": rails, "src/memory.py": memory},
        [
            ex(
                "a10.guardrail",
                "agent",
                "guardrail",
                "guardrails/config.yml",
                "nemoguardrails",
                "nemo guardrails",
                attrs=[has("rail", "self check input")],
            ),
            ex(
                "a10.memory",
                "agent",
                "memory-store",
                "checkpoints.db",
                "memory.internal",
                attrs=[loc("src/memory.py")],
            ),
        ],
        surface="guardrail configuration and memory backends",
        sources=("NeMo Guardrails", "LangGraph", "Cisco", "OWASP Agentic Top 10"),
    )


def workflow_agent() -> Case:
    def node(
        node_id: str, name: str, kind: str, parameters: dict[str, object]
    ) -> dict[str, object]:
        return {
            "id": node_id,
            "name": name,
            "type": f"@n8n/n8n-nodes-langchain.{kind}",
            "typeVersion": 1,
            "position": [220 * int(node_id), 0],
            "parameters": parameters,
        }

    def link(kind: str) -> dict[str, object]:
        return {kind: [[{"node": "Triage Agent", "type": kind, "index": 0}]]}

    workflow = {
        "name": "support-triage",
        "nodes": [
            node("1", "Chat Trigger", "chatTrigger", {}),
            node(
                "2",
                "Triage Agent",
                "agent",
                {"options": {"systemMessage": "Classify the request and call a tool when needed."}},
            ),
            node(
                "3",
                "OpenAI Chat Model",
                "lmChatOpenAi",
                {"model": {"__rl": True, "value": "gpt-4o", "mode": "list"}},
            ),
            node(
                "4",
                "crm_lookup",
                "toolHttpRequest",
                {
                    "toolDescription": "Look up a customer in the CRM by email.",
                    "url": "https://crm.acme.example/api/customers",
                },
            ),
            node(
                "5",
                "Ticket MCP",
                "mcpClientTool",
                {"sseEndpoint": "https://mcp.tickets.acme.example/sse"},
            ),
        ],
        "connections": {
            "Chat Trigger": link("main"),
            "OpenAI Chat Model": link("ai_languageModel"),
            "crm_lookup": link("ai_tool"),
            "Ticket MCP": link("ai_tool"),
        },
        "settings": {"executionOrder": "v1"},
    }
    path = "workflows/support-triage.json"
    return case(
        "a11-workflow-agent",
        "n8n workflow with an agent node, a model, a tool and an MCP client",
        {path: as_json(workflow)},
        [
            ex(
                "a11.agent",
                "agent",
                "workflow-agent",
                "Triage Agent",
                "support-triage",
                attrs=[loc(path)],
            ),
            ex("a11.model", "model", "api-model", "gpt-4o", attrs=[typ(ML_MODEL)]),
            ex(
                "a11.tool",
                "tool",
                "workflow-tool",
                "crm_lookup",
                attrs=[has("endpoint", "https://crm.acme.example/api/customers")],
            ),
            ex("a11.mcp", "agent", "mcp-server", "mcp.tickets.acme.example"),
        ],
        edges=[
            edge("a11.agent", "a11.model", "uses"),
            edge("a11.agent", "a11.tool", "uses"),
            edge("a11.agent", "a11.mcp", "uses"),
        ],
        surface="n8n workflow export",
        sources=("n8n", "Trusera"),
    )


def plugin() -> Case:
    manifest = {
        "name": "deploy-helper",
        "version": "0.9.1",
        "description": "Commands and checks for staged deployments.",
        "author": {"name": "Acme Platform"},
    }
    marketplace = {
        "name": "acme-internal",
        "owner": {"name": "Acme Platform"},
        "plugins": [
            {
                "name": "deploy-helper",
                "source": "./",
                "description": "Commands and checks for staged deployments.",
            }
        ],
    }
    hooks = {
        "hooks": {
            "PostToolUse": [
                {
                    "matcher": "Write|Edit",
                    "hooks": [
                        {"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/scripts/lint.sh"}
                    ],
                }
            ]
        }
    }
    planner = text(
        """
        ---
        name: rollback-planner
        description: Plans a rollback when a staged deployment fails its checks.
        tools: Read, Grep
        ---

        List the steps to restore the previous release, newest change first.
        """
    )
    servers = {
        "mcpServers": {
            "artifact-store": {"command": "npx", "args": ["-y", "@acme/artifact-mcp@3.2.0"]}
        }
    }
    return case(
        "a12-plugin",
        "Coding-agent plugin bundling a command, a subagent, a hook and an MCP server",
        {
            ".claude-plugin/plugin.json": as_json(manifest),
            ".claude-plugin/marketplace.json": as_json(marketplace),
            "commands/deploy.md": text(
                "---\ndescription: Deploy the current branch to staging.\n---\n\nRun the staging pipeline."
            ),
            "agents/rollback-planner.md": planner,
            "hooks/hooks.json": as_json(hooks),
            "scripts/lint.sh": text("#!/bin/sh\nexit 0"),
            ".mcp.json": as_json(servers),
        },
        [
            ex(
                "a12.plugin",
                "agent",
                "plugin",
                "deploy-helper",
                attrs=[ver("0.9.1"), loc(".claude-plugin/plugin.json")],
            ),
            ex("a12.server", "agent", "mcp-server", "artifact-store", attrs=[ver("3.2.0")]),
            ex("a12.subagent", "agent", "subagent", "rollback-planner"),
            ex(
                "a12.hook",
                "agent",
                "hook",
                "hooks/hooks.json",
                "lint.sh",
                attrs=[has("hook event", "PostToolUse")],
            ),
        ],
        edges=[
            edge("a12.plugin", "a12.server", "bundles"),
            edge("a12.plugin", "a12.subagent", "bundles"),
        ],
        executable=("scripts/lint.sh",),
        surface="Claude Code plugin manifest and components",
        sources=("Claude Code plugins", "Cisco"),
    )


def ci_agent_action() -> Case:
    checkout = hex40("a14:checkout")
    workflow = text(
        """
        name: Automated review
        on:
          pull_request:
        permissions:
          contents: read
          pull-requests: write
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@CHECKOUT_SHA
              - uses: anthropics/claude-code-action@v1
                with:
                  anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
                  claude_args: --model claude-sonnet-4-5
                  prompt: Review this pull request for correctness.
        """
    ).replace(b"CHECKOUT_SHA", checkout.encode())
    path = ".github/workflows/review.yml"
    return case(
        "a14-ci-agent-action",
        "Coding agent run from a CI workflow",
        {path: workflow},
        [
            ex(
                "a14.action",
                "agent",
                "ci-agent-action",
                "claude-code-action",
                attrs=[ver("v1"), loc(path)],
            ),
            ex("a14.model", "model", "api-model", "claude-sonnet-4-5", attrs=[typ(ML_MODEL)]),
        ],
        edges=[edge("a14.action", "a14.model", "uses")],
        surface="GitHub Actions workflow that runs an AI agent",
        sources=("GitHub Actions", "Trusera", "Cisco"),
    )


def cases() -> list[Case]:
    return [
        project_mcp_config(),
        other_client_configs(),
        user_scope_configs(),
        skills(),
        instruction_files(),
        coding_agent_settings(),
        a2a_agent(),
        framework_agents(),
        prompt_files(),
        guardrails_and_memory(),
        workflow_agent(),
        plugin(),
        ci_agent_action(),
    ]
