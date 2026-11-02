"""frameworks collector: agent definitions from framework code and config, parsed statically."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import time
from pathlib import Path

import pytest

from symbiote.collect import frameworks as fw
from symbiote.collect import models_hosted
from symbiote.collect.base import CollectContext, CollectionResult, run_collectors
from symbiote.collect.frameworks import (
    HOSTED_OWNED_KEYWORDS,
    NON_LITERAL,
    FrameworksCollector,
    claude_tool_gate,
    literal,
    split_provider_prefix,
    ts_object,
)
from symbiote.collect.models_hosted import ModelsHostedCollector
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    Agent,
    Instruction,
    Model,
    PromptTemplate,
    ToolDefinition,
    ToolServer,
)
from symbiote.model.enums import (
    AgentRole,
    AliasPinning,
    ApprovalGate,
    CapabilityClass,
    CoverageStatus,
    EdgeType,
    InstructionKind,
    Surface,
    TemplateEngine,
    TemplateRiskClass,
    Transport,
)

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "frameworks" / "two_frameworks"
FAKE_KEY = "sk-ant-api03-" + "A" * 80 + "-" + "B" * 12  # credential-shaped, never a real key
FAKE_GH = "ghp_" + "Z" * 36


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run(root: Path, **kwargs: object) -> CollectionResult:
    ctx = CollectContext(root=root, platform="linux", agent_id="agent:root", **kwargs)  # type: ignore[arg-type]
    return run_collectors(ctx, [FrameworksCollector()])[0]


def _agents(result: CollectionResult) -> dict[str, Agent]:
    return {e.id: e for e in result.entities if isinstance(e, Agent)}


def _tools(result: CollectionResult) -> dict[str, ToolDefinition]:
    return {e.id: e for e in result.entities if isinstance(e, ToolDefinition)}


def _servers(result: CollectionResult) -> dict[str, ToolServer]:
    return {e.id: e for e in result.entities if isinstance(e, ToolServer)}


def _models(result: CollectionResult) -> dict[str, Model]:
    return {e.id: e for e in result.entities if isinstance(e, Model)}


def _instructions(result: CollectionResult) -> dict[str, Instruction]:
    return {e.id: e for e in result.entities if isinstance(e, Instruction)}


def _edges(result: CollectionResult, kind: EdgeType) -> set[tuple[str, str]]:
    return {(e.from_ref, e.to_ref) for e in result.edges if e.type is kind}


def _edge(result: CollectionResult, kind: EdgeType, src: str, dst: str) -> Edge:
    return next(e for e in result.edges if e.type is kind and e.from_ref == src and e.to_ref == dst)


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _dump(result: CollectionResult) -> str:
    return json.dumps(
        [e.model_dump(mode="json", by_alias=True) for e in result.entities]
        + [e.model_dump(mode="json", by_alias=True) for e in result.edges]
        + [c.model_dump(mode="json") for c in result.coverage.values()]
        + [r.model_dump(mode="json") for r in result.redactions]
        + list(result.warnings),
        sort_keys=True,
        default=str,
    )


# --------------------------------------------------------------------------------------------- contract


def test_collector_contract_and_empty_repository(tmp_path: Path) -> None:
    collector = FrameworksCollector()
    assert collector.name == "frameworks"
    assert collector.surfaces == (Surface.CODE,)
    result = _run(tmp_path)
    assert collector.detect(CollectContext(root=tmp_path)) is True
    assert result.entities == [] and result.edges == []
    assert result.coverage[Surface.CODE].status is CoverageStatus.QUERIED


def test_hosted_owned_keywords_match_models_hosted() -> None:
    assert frozenset(models_hosted._MODEL_KWARGS) == HOSTED_OWNED_KEYWORDS


# --------------------------------------------------------------------------------------------- OpenAI Agents SDK


def test_openai_agents_sdk_agents_handoffs_tools_and_prompts() -> None:
    result = _run(FIXTURE)
    agents = _agents(result)
    triage = agents["agent:openai-agents/triage"]
    assert triage.role is AgentRole.SUB_AGENT and triage.parent_ref == "agent:root"
    assert triage.framework is not None and triage.framework.value is not None
    assert triage.framework.value.name == "openai-agents"
    assert triage.provenance.locator == "support/agents.py:30"
    # handoffs: one agent in the same file, one imported through a relative import
    delegated = _edges(result, EdgeType.DELEGATES_TO)
    assert ("agent:openai-agents/triage", "agent:openai-agents/refunds") in delegated
    assert ("agent:openai-agents/triage", "agent:openai-agents/billing") in delegated
    assert (
        _edge(result, EdgeType.DELEGATES_TO, triage.id, "agent:openai-agents/billing").qualifiers["mode"]
        == "handoff"
    )
    assert agents["agent:openai-agents/billing"].description == "Answers invoice questions"
    # the prompt is a module constant: digested exactly, never stored
    prompt = "You are the first point of contact.\nRoute refund requests to Refunds and invoices to Billing."
    instr = _instructions(result)["instr:openai-agents/triage/instructions"]
    assert instr.digest == _sha(prompt) and instr.size == len(prompt.encode())
    assert instr.instruction_kind is InstructionKind.SYSTEM_PROMPT
    assert [r.ref for r in triage.instructions] == [instr.id]
    assert (triage.id, instr.id) in _edges(result, EdgeType.LOADS_INSTRUCTION)
    assert prompt not in _dump(result)
    # tools: decorated function tools carry their approval setting; the framework default is "no approval"
    tools = _tools(result)
    refund = tools["tool:openai-agents/refunds/tools/issue_refund"]
    assert refund.approval_gate is ApprovalGate.REQUIRED
    assert tools["tool:openai-agents/refunds/tools/lookup_order"].approval_gate is ApprovalGate.NONE
    search = tools["tool:openai-agents/triage/tools/WebSearchTool"]
    assert CapabilityClass.NETWORK_EGRESS in search.capabilities and "hosted-tool" in search.tags
    assert (triage.id, search.id) in _edges(result, EdgeType.INVOKES_TOOL)
    assert refund.digest.reason is not None and refund.digest.reason.startswith("declared-without-definition")
    server = _servers(result)["server:openai-agents/refunds/tools"]
    assert server.transport.value is Transport.IN_PROCESS and server.crosses_trust_boundary.value is False


def test_models_in_hosted_positions_are_edges_to_the_models_hosted_entity() -> None:
    frameworks = _run(FIXTURE)
    uses = _edges(frameworks, EdgeType.USES_MODEL)
    assert ("agent:openai-agents/triage", "model:hosted/openai/gpt-4o") in uses
    assert ("agent:claude-agent-sdk/options.options", "model:hosted/anthropic/claude-sonnet-4-5") in uses
    # ``model="gpt-4o"`` is a models-hosted code literal: this collector emits no Model for it
    assert "model:hosted/openai/gpt-4o" not in _models(frameworks)
    hosted_ctx = CollectContext(root=FIXTURE, platform="linux", agent_id="agent:root")
    hosted = run_collectors(hosted_ctx, [ModelsHostedCollector()])[0]
    hosted_ids = {e.id for e in hosted.entities if isinstance(e, Model)}
    owned_here = set(_models(frameworks))
    for _, model_id in uses:
        assert model_id in hosted_ids or model_id in owned_here, model_id
    assert not owned_here & hosted_ids  # never two producers for one model id
    # CrewAI's YAML ``llm`` is not read by models-hosted: this collector owns that Model
    crew_model = _models(frameworks)["model:hosted/openai/openai-gpt-4o"]
    assert crew_model.hosted is not None and crew_model.hosted.value is not None
    assert crew_model.hosted.value.alias_pinning is AliasPinning.FLOATING
    assert "source:frameworks" in crew_model.tags


def test_dynamic_values_are_unknown_with_locators(tmp_path: Path) -> None:
    _write(
        tmp_path / "app.py",
        "from agents import Agent\n"
        "def build(user, cfg, extra):\n"
        "    return Agent(name=cfg.name, instructions=f'hi {user}', model=cfg.model, tools=extra,\n"
        "                 handoffs=[unknown_agent, *more], **cfg.kwargs)\n",
    )
    result = _run(tmp_path)
    (agent,) = _agents(result).values()
    assert agent.name == "build" and "name-from:function" in agent.tags
    for field in ("instructions", "model", "tools", "kwargs", "handoffs"):
        assert f"unknown:{field}" in agent.tags, field
        assert agent.foreign[f"frameworks:unknown:{field}"].startswith("app.py:"), field
    assert "dynamic-instructions:f-string" in agent.tags and "partial-definition" in agent.tags
    assert not _edges(result, EdgeType.USES_MODEL)


def test_tool_wrappers_mcp_servers_and_agent_as_tool(tmp_path: Path) -> None:
    _write(
        tmp_path / "pkg" / "tools.py",
        "from agents import function_tool\n"
        "@function_tool(name_override='wipe_disk', needs_approval=lambda ctx, p, c: True)\n"
        "def wipe(path: str) -> None: ...\n",
    )
    _write(
        tmp_path / "pkg" / "main.py",
        "import agents\n"
        "from agents import Agent, HostedMCPTool, function_tool\n"
        "from agents.mcp import MCPServerStreamableHttp, MCPServerStdio\n"
        "from pkg.tools import wipe\n"
        "from pkg.helpers import helper_fn\n"
        "remote = MCPServerStreamableHttp(params={'url': 'https://user:pw@mcp.example.com/mcp?token=abc',\n"
        "                                         'headers': {'Authorization': 'Bearer ${TOKEN}'}},\n"
        "                                 require_approval={'never': {'tool_names': ['read']}})\n"
        "unused = MCPServerStdio(params={'command': 'uvx', 'args': ['mcp-server-time==1.0.0']}, name='clock')\n"
        "expert = Agent(name='Expert', instructions='Answer.')\n"
        "main = agents.Agent(\n"
        "    name='Main',\n"
        "    tools=[wipe, helper_fn, expert.as_tool(tool_name='ask', needs_approval=True), 'raw-name',\n"
        "           function_tool(helper_fn, needs_approval=False), lambda: None,\n"
        "           HostedMCPTool(tool_config={'type': 'mcp', 'server_label': 'deepwiki',\n"
        "                                      'server_url': 'https://mcp.deepwiki.com/mcp',\n"
        "                                      'require_approval': 'always', 'allowed_tools': ['ask_question']})],\n"
        "    mcp_servers=[remote, make_server()],\n"
        "    prompt={'id': 'pmpt_1'},\n"
        "    input_guardrails=[check],\n"
        ")\n",
    )
    result = _run(tmp_path)
    agents = _agents(result)
    main = agents["agent:openai-agents/main"]
    tools = _tools(result)
    wipe = tools["tool:openai-agents/main/tools/wipe_disk"]
    assert wipe.approval_gate is ApprovalGate.CONDITIONAL  # imported tool function keeps its decorator facts
    helper_fn = tools["tool:openai-agents/main/tools/helper_fn"]  # listed twice: the explicit wrapper is kept
    assert helper_fn.approval_gate is ApprovalGate.NONE and "tool-wrapper:function_tool" in helper_fn.tags
    assert "tool:openai-agents/main/tools/raw-name" in tools
    ask = _edge(result, EdgeType.DELEGATES_TO, main.id, "agent:openai-agents/expert")
    assert ask.qualifiers["mode"] == "agent-as-tool" and ask.qualifiers["constraints"] == "approval:required"
    assert {
        "unknown:tools",
        "unknown:mcp_servers",
        "unknown:prompt",
        "remote-prompt-ref",
        "control:guardrails",
    } <= set(main.tags)
    servers = _servers(result)
    http = servers["server:openai-agents-remote"]
    assert http.transport.value is Transport.STREAMABLE_HTTP
    assert http.endpoint is not None and http.endpoint.value == "https://mcp.example.com/mcp"
    assert (
        http.header_names == ["Authorization"]
        and http.client_trust_flags["openai-agents.approval"] == "conditional"
    )
    deepwiki = servers["server:openai-agents-deepwiki"]
    ask_q = tools["tool:openai-agents-deepwiki/ask_question"]
    assert ask_q.approval_gate is ApprovalGate.REQUIRED and ask_q.server_ref == deepwiki.id
    assert (main.id, deepwiki.id) in _edges(result, EdgeType.DEPENDS_ON)
    # a server no agent references belongs to the scanned agent itself
    assert ("agent:root", "server:openai-agents-clock") in _edges(result, EdgeType.DEPENDS_ON)
    clock = servers["server:openai-agents-clock"]
    assert (
        clock.package is not None
        and clock.package.value is not None
        and clock.package.value.floating is False
    )
    assert "pw@" not in _dump(result) and "token=abc" not in _dump(result)
    assert sum(r.count for r in result.redactions) >= 1


# --------------------------------------------------------------------------------------------- Claude Agent SDK


@pytest.mark.parametrize(
    ("tool", "mode", "allowed", "callback", "gate"),
    [
        ("Bash", "bypassPermissions", None, False, ApprovalGate.NONE),
        ("Bash", None, ["Bash"], False, ApprovalGate.NONE),
        ("Bash(git status:*)", None, ["Bash(git status:*)"], False, ApprovalGate.CONDITIONAL),
        ("Bash", "acceptEdits", ["Bash(npm test:*)", "Read"], False, ApprovalGate.CONDITIONAL),
        ("Read", None, ["Read(./src/**)"], False, ApprovalGate.NONE),
        ("Edit", "acceptEdits", None, False, ApprovalGate.NONE),
        ("Bash", "acceptEdits", None, False, ApprovalGate.REQUIRED),
        ("Bash", "auto", None, False, ApprovalGate.CONDITIONAL),
        ("Bash", "default", None, True, ApprovalGate.CONDITIONAL),
        ("Bash", "<non-literal>", None, False, ApprovalGate.UNKNOWN),
        ("Read", None, None, False, ApprovalGate.NONE),
        ("WebFetch", "plan", [], False, ApprovalGate.REQUIRED),
    ],
)
def test_claude_tool_gate(
    tool: str, mode: str | None, allowed: list[str] | None, callback: bool, gate: ApprovalGate
) -> None:
    assert claude_tool_gate(tool, mode, allowed, callback=callback)[0] is gate


def test_claude_agent_sdk_bypass_mcp_flags_and_subagents() -> None:
    result = _run(FIXTURE)
    agents = _agents(result)
    options = agents["agent:claude-agent-sdk/options.options"]
    assert {
        "permission-mode:bypassPermissions",
        "approval-bypass:permission_mode",
        "system-prompt:preset:claude_code",
    } <= set(options.tags)
    assert _instructions(result)[
        "instr:claude-agent-sdk/options.options/system_prompt_append"
    ].digest == _sha("Never touch production.")
    reviewer = agents["agent:claude-agent-sdk/reviewer"]
    assert reviewer.parent_ref == options.id and reviewer.description == "Reviews diffs before merge"
    link = _edge(result, EdgeType.DELEGATES_TO, options.id, reviewer.id)
    assert link.qualifiers["mode"] == "subagent" and link.qualifiers["constraints"] == "tools:Grep,Read"
    assert ("agent:claude-agent-sdk/reviewer", "model:hosted/anthropic/haiku") in _edges(
        result, EdgeType.USES_MODEL
    )
    tickets = _servers(result)["server:claude-agent-sdk-tickets"]
    assert tickets.client_trust_flags["claude-code.defaultMode.agent-sdk"] == "bypassPermissions"
    assert tickets.client_trust_flags["claude-code.permissions.allow"] == "list_tickets"
    tools = _tools(result)
    assert tools["tool:claude-agent-sdk-tickets/list_tickets"].approval_gate is ApprovalGate.NONE
    for name in ("Read", "Bash"):  # under bypassPermissions nothing prompts, for the sub-agent too
        assert tools[f"tool:claude-agent-sdk/options.options/tools/{name}"].approval_gate is ApprovalGate.NONE
    assert tools["tool:claude-agent-sdk/reviewer/tools/Grep"].approval_gate is ApprovalGate.NONE
    assert CapabilityClass.EXECUTE in tools["tool:claude-agent-sdk/options.options/tools/Bash"].capabilities


def test_claude_agent_sdk_modes_and_dict_subagents(tmp_path: Path) -> None:
    _write(
        tmp_path / "run.py",
        "from claude_agent_sdk import ClaudeAgentOptions, AgentDefinition, create_sdk_mcp_server, tool\n"
        "@tool('add', 'Add numbers', {'a': int})\n"
        "async def add(args): ...\n"
        "calc = create_sdk_mcp_server(name='calc', tools=[add])\n"
        "helper_def = AgentDefinition(description='helps', prompt='Help.', permissionMode='plan')\n"
        "def opts(mode):\n"
        "    strict = ClaudeAgentOptions(system_prompt='Be strict.', permission_mode='dontAsk',\n"
        "        tools=['Read', 'Bash', 'Write'], allowed_tools=['Read', 'mcp__calc', 'mcp__elsewhere__x'],\n"
        "        disallowed_tools=['Write'], mcp_servers={'calc': calc, 'bad': cfg}, fallback_model='claude-haiku-4-5',\n"
        "        agents={'helper': helper_def, 'inline': {'description': 'Inline', 'prompt': 'Do it.',\n"
        "                'tools': ['Read'], 'disallowedTools': ['Bash'], 'model': 'opus', 'permissionMode': 'acceptEdits'},\n"
        "                'dyn': make_def()})\n"
        "    loose = ClaudeAgentOptions(permission_mode=mode, tools={'type': 'preset', 'preset': 'claude_code'},\n"
        "        system_prompt={'type': 'file', 'path': 'p.md'}, mcp_servers='mcp.json', can_use_tool=check,\n"
        "        allowed_tools=tools_list, disallowed_tools=other, agents=agent_map)\n"
        "    edits = ClaudeAgentOptions(permission_mode='acceptEdits', tools=['Edit', 'Bash'], system_prompt=None)\n"
        "    return strict, loose, edits\n",
    )
    result = _run(tmp_path)
    agents = _agents(result)
    strict = agents["agent:claude-agent-sdk/run.strict"]
    assert {"tool-removed:Write", "tool-denied:Bash", "allowed-mcp:mcp__elsewhere__x"} <= set(strict.tags)
    tools = _tools(result)
    assert tools["tool:claude-agent-sdk/run.strict/tools/Read"].approval_gate is ApprovalGate.NONE
    assert "tool:claude-agent-sdk/run.strict/tools/Bash" not in tools
    calc = _servers(result)["server:claude-agent-sdk-calc"]
    assert calc.transport.value is Transport.IN_PROCESS
    assert calc.client_trust_flags["claude-code.permissions.allow"] == "*"
    assert tools["tool:claude-agent-sdk-calc/add"].approval_gate is ApprovalGate.NONE
    assert ("agent:claude-agent-sdk/run.strict", "model:hosted/anthropic/claude-haiku-4-5") in _edges(
        result, EdgeType.USES_MODEL
    )
    helper = agents["agent:claude-agent-sdk/helper"]
    assert (
        helper.parent_ref == strict.id
        and "permission-mode:plan" in helper.tags
        and "tools:inherited" in helper.tags
    )
    inline = agents["agent:claude-agent-sdk/inline"]
    assert "permission-mode:acceptEdits" in inline.tags
    assert ("agent:claude-agent-sdk/inline", "model:hosted/anthropic/opus") in _edges(
        result, EdgeType.USES_MODEL
    )
    assert "unknown:definition" in agents["agent:claude-agent-sdk/dyn"].tags
    assert "unknown:mcp_servers" in strict.tags
    loose = agents["agent:claude-agent-sdk/run.loose"]
    for field in (
        "permission_mode",
        "system_prompt",
        "mcp_servers",
        "allowed_tools",
        "disallowed_tools",
        "agents",
    ):
        assert f"unknown:{field}" in loose.tags, field
    assert {"tools:preset:claude_code", "system-prompt:file", "mcp-config-file", "approval:callback"} <= set(
        loose.tags
    )
    edits = agents["agent:claude-agent-sdk/run.edits"]
    assert tools["tool:claude-agent-sdk/run.edits/tools/Edit"].approval_gate is ApprovalGate.NONE
    assert tools["tool:claude-agent-sdk/run.edits/tools/Bash"].approval_gate is ApprovalGate.REQUIRED
    assert not edits.instructions


# --------------------------------------------------------------------------------------------- LangGraph / LangChain


def test_langgraph_json_graphs_dependencies_env_and_hitl(tmp_path: Path) -> None:
    _write(
        tmp_path / "svc" / "langgraph.json",
        json.dumps(
            {
                "dependencies": [".", "langchain-anthropic"],
                "graphs": {
                    "support": "./agent.py:graph",
                    "custom": {"path": "./custom.py:app", "description": "hand-built"},
                    "broken": "no-colon",
                },
                "env": {"ANTHROPIC_API_KEY": FAKE_KEY, "LOG_LEVEL": "info"},
                "auth": {"path": "./auth.py:auth"},
                "http": {"disable_mcp": True},
            }
        ),
    )
    _write(
        tmp_path / "svc" / "agent.py",
        "from langchain.agents import create_agent\n"
        "from langchain.agents.middleware import HumanInTheLoopMiddleware, ToolCallLimitMiddleware\n"
        "from langchain.chat_models import init_chat_model\n"
        "def delete_file(p): ...\n"
        "def read_file(p): ...\n"
        "def other(p): ...\n"
        "graph = create_agent(init_chat_model('anthropic:claude-sonnet-4-5', configurable_fields='any'),\n"
        "    [delete_file, read_file, other], system_prompt='You manage files.',\n"
        "    middleware=[HumanInTheLoopMiddleware(interrupt_on={'delete_file': True, 'read_file': False}),\n"
        "                ToolCallLimitMiddleware(run_limit=3), limiter])\n",
    )
    _write(
        tmp_path / "svc" / "custom.py",
        "from langgraph.graph import StateGraph\napp = StateGraph(dict).compile()\n",
    )
    result = _run(tmp_path)
    agents = _agents(result)
    support = agents["agent:langgraph/support"]
    assert support.entrypoint == "svc/agent.py:graph"
    assert {"langgraph:graph", "dependency:langchain-anthropic", "env:ANTHROPIC_API_KEY", "env:LOG_LEVEL",
            "inline-secret-in-config", "auth:custom-handler", "http:disable_mcp", "implemented-with:langchain",
            "model-reroutable", "approval:human-in-the-loop"} <= set(support.tags)  # fmt: skip
    assert "agent:langchain/graph" not in agents  # merged into the graph agent
    tools = _tools(result)
    assert tools["tool:langgraph/support/tools/delete_file"].approval_gate is ApprovalGate.REQUIRED
    assert tools["tool:langgraph/support/tools/read_file"].approval_gate is ApprovalGate.NONE
    assert tools["tool:langgraph/support/tools/other"].approval_gate is ApprovalGate.NONE
    model = _models(result)["model:hosted/anthropic/anthropic-claude-sonnet-4-5"]
    assert "attributed-by:provider-prefix" in model.tags
    custom = agents["agent:langgraph/custom"]
    assert custom.description == "hand-built" and "langgraph:unresolved-graph" in custom.tags
    assert custom.foreign["frameworks:unknown:model"] == "svc/custom.py:app"
    assert "unknown:graph" in agents["agent:langgraph/broken"].tags
    assert FAKE_KEY not in _dump(result)
    assert (
        sum(r.count for r in result.redactions) == 1 and "agent:langgraph/support" in result.redactions[0].ids
    )


def test_langgraph_prebuilt_and_invalid_configs(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "from langgraph.prebuilt import create_react_agent\n"
        "from langchain_openai import ChatOpenAI\n"
        "agent = create_react_agent(ChatOpenAI(temperature=0), tools=[], prompt='Plan.', name='planner',\n"
        "                           interrupt_before=['tools'])\n"
        "other = create_react_agent(ChatOpenAI(model='gpt-4o', api_key='literal'), [], interrupt_after=nodes,\n"
        "                           middleware=mw)\n",
    )
    _write(tmp_path / "bad" / "langgraph.json", "{not json")
    _write(tmp_path / "list" / "langgraph.json", "[]")
    _write(tmp_path / "nographs" / "langgraph.json", '{"dependencies": ["."], "env": ".env"}')
    result = _run(tmp_path)
    agents = _agents(result)
    planner = agents["agent:langgraph/planner"]
    assert "model:implicit-default:openai" in planner.tags and "approval:graph-interrupt" in planner.tags
    other = agents["agent:langgraph/other"]
    assert {"inline-api-key", "unknown:interrupt", "redacted:credential-shaped-token"} <= set(other.tags)
    failed = {(s.locator, s.error_class) for s in result.coverage[Surface.CODE].sources if not s.ok}
    assert ("bad/langgraph.json", "parse-error") in failed
    assert ("list/langgraph.json", "invalid-config") in failed
    assert ("nographs/langgraph.json", "invalid-config") in failed
    assert result.coverage[Surface.CODE].status is CoverageStatus.PARTIAL


# --------------------------------------------------------------------------------------------- CrewAI


def test_crewai_yaml_agents_tasks_and_delegation() -> None:
    result = _run(FIXTURE)
    agents = _agents(result)
    researcher, writer = agents["agent:crewai/researcher"], agents["agent:crewai/writer"]
    assert "allow-delegation" in researcher.tags and "human-review:task-output" in writer.tags
    assert (
        _edge(result, EdgeType.DELEGATES_TO, researcher.id, writer.id).qualifiers["mode"] == "crew-delegation"
    )
    assert (writer.id, researcher.id) not in _edges(result, EdgeType.DELEGATES_TO)
    instr = _instructions(result)
    role = instr["instr:crewai/researcher/role"]
    assert role.digest == _sha("Senior researcher on {topic}") and "template:braces" in role.tags
    assert role.path == "crew/config/agents.yaml"
    assert role.provenance.locator == "crew/config/agents.yaml#/researcher/role"
    task = instr["instr:crewai/researcher/task-research_task-description"]
    assert task.instruction_kind is InstructionKind.OTHER
    assert ("agent:crewai/writer", "model:hosted/anthropic/anthropic-claude-sonnet-4-5") in _edges(
        result, EdgeType.USES_MODEL
    )


def test_crewai_python_crewbase_merges_with_yaml(tmp_path: Path) -> None:
    proj = tmp_path / "src" / "demo"
    _write(
        proj / "config" / "agents.yaml",
        "researcher:\n  role: Researcher\n  goal: Find\n  backstory: Digs\n  allow_code_execution: true\n"
        "  code_execution_mode: unsafe\n  tools: 5\n  llm: {model: gpt-4o}\n"
        "analyst:\n  role: Analyst\n  goal: Analyse\n  backstory: Thinks\n  function_calling_llm: gpt-4o-mini\n"
        "  system_template: 'System {role}'\n",
    )
    _write(
        proj / "config" / "tasks.yaml",
        "t1:\n  description: Do {x}\n  expected_output: Done\n  agent: researcher\n  tools: [FileReadTool]\n"
        "t2:\n  description: Orphan\n  agent: nobody\nlist: [1]\n",
    )
    _write(
        proj / "crew.py",
        "from crewai import Agent, Crew, Task, Process, LLM\n"
        "from crewai.project import CrewBase, agent, crew, task\n"
        "from crewai_tools import SerperDevTool\n"
        "@CrewBase\n"
        "class Demo:\n"
        "    @agent\n"
        "    def researcher(self) -> Agent:\n"
        "        return Agent(config=self.agents_config['researcher'], tools=[SerperDevTool()], verbose=True)\n"
        "    @agent\n"
        "    def reviewer(self) -> Agent:\n"
        "        return Agent(role='Reviewer', goal='Review', backstory='Strict', llm=LLM(model='gpt-4o'),\n"
        "                     allow_delegation=True, mcps=['https://mcp.example.com/mcp', 'notion', unknown])\n"
        "    @task\n"
        "    def review(self) -> Task:\n"
        "        return Task(description='Review it', expected_output=summary, agent=self.reviewer(), human_input=True)\n"
        "    @crew\n"
        "    def crew(self) -> Crew:\n"
        "        return Crew(agents=self.agents, tasks=self.tasks, process=Process.hierarchical, manager_llm='gpt-4o',\n"
        "                    manager_agent=boss)\n"
        "editor = Agent(role='Editor', goal='Edit', backstory=story, allow_delegation=flag, mcps=refs)\n"
        "t = Task(description='Edit {doc}', expected_output='Edited', agent=editor, tools=[SerperDevTool()],\n"
        "         human_input=True, name='edit')\n",
    )
    result = _run(tmp_path)
    agents = _agents(result)
    researcher = agents["agent:crewai/researcher"]
    assert researcher.entrypoint == "src/demo/crew.py:8"  # the @agent method that refines the YAML agent
    assert {"capability:execute", "code-execution:host", "unknown:tools"} <= set(researcher.tags)
    assert "tool:crewai/researcher/tools/SerperDevTool" in _tools(result)
    assert "tool:crewai/researcher/tools/FileReadTool" in _tools(result)
    assert not any(a.name == "researcher" and a.id != researcher.id for a in agents.values())
    analyst = agents["agent:crewai/analyst"]
    assert ("agent:crewai/analyst", "model:hosted/openai/gpt-4o-mini") in _edges(result, EdgeType.USES_MODEL)
    assert "instr:crewai/analyst/system_template" in _instructions(result)
    assert analyst.parent_ref == "agent:root"
    reviewer = agents["agent:crewai/reviewer"]
    assert "human-review:task-output" not in reviewer.tags  # self.reviewer() is not resolvable statically
    assert "mcp-ref:notion" in reviewer.tags and "unknown:mcps" in reviewer.tags
    assert ("agent:crewai/reviewer", "server:crewai-mcp.example.com") in _edges(result, EdgeType.DEPENDS_ON)
    crew = agents["agent:crewai/crew"]
    assert {"process:hierarchical", "unknown:sub_agents", "unknown:delegation"} <= set(crew.tags)
    editor = agents["agent:crewai/editor"]
    assert {
        "human-review:task-output",
        "unknown:allow_delegation",
        "unknown:mcps",
        "unknown:backstory",
    } <= set(editor.tags)
    assert "instr:crewai/editor/task-edit-description" in _instructions(result)
    assert any("task agent not found" in w for w in result.warnings)


# --------------------------------------------------------------------------------------------- AutoGen / AG2


def test_autogen_agentchat_classic_and_config_list(tmp_path: Path) -> None:
    _write(
        tmp_path / "team.py",
        "from autogen_agentchat.agents import AssistantAgent, CodeExecutorAgent\n"
        "from autogen_agentchat.base import Handoff\n"
        "from autogen_ext.models.openai import OpenAIChatCompletionClient\n"
        "from autogen_ext.tools.mcp import McpWorkbench, StdioServerParams\n"
        "import autogen\n"
        "import ag2\n"
        "from ag2.config import OpenAIConfig\n"
        "client = OpenAIChatCompletionClient(model='gpt-4o')\n"
        "params = StdioServerParams(command='uvx', args=['mcp-server-fetch'])\n"
        "travel = AssistantAgent('travel', model_client=client, handoffs=['refunds', Handoff(target='flights')],\n"
        "                        system_message='Plan trips.', workbench=McpWorkbench(params))\n"
        "refunds = AssistantAgent('refunds', client, system_message='Refund.')\n"
        "flights = AssistantAgent(name='flights', model_client=client)\n"
        "runner = CodeExecutorAgent('runner', executor, approval_func=approve)\n"
        "LLM = {'config_list': [{'model': 'gpt-4', 'api_key': '" + FAKE_KEY + "'}]}\n"
        "old = autogen.AssistantAgent(name='old', llm_config=LLM, human_input_mode='ALWAYS',\n"
        "                             code_execution_config={'use_docker': False})\n"
        "never = autogen.ConversableAgent('never', llm_config=False, human_input_mode='NEVER')\n"
        "term = autogen.UserProxyAgent('term', llm_config={'config_list': cfg}, human_input_mode='TERMINATE')\n"
        "odd = autogen.ConversableAgent('odd', llm_config=autogen.LLMConfig({'model': 'gpt-4o-mini'}), human_input_mode=mode)\n"
        "weird = autogen.ConversableAgent('weird', llm_config=cfg, human_input_mode='SOMETIMES')\n"
        "new = ag2.Agent('assistant', prompt='Be brief.', config=OpenAIConfig(model='gpt-4o'))\n",
    )
    _write(
        tmp_path / "OAI_CONFIG_LIST",
        json.dumps(
            [
                {"model": "gpt-4o", "api_key": FAKE_KEY},
                {
                    "model": "claude-3-5-sonnet-20241022",
                    "api_type": "anthropic",
                    "base_url": "https://proxy.internal/v1",
                },
                "junk",
                {"api_type": "openai"},
            ]
        ),
    )
    _write(tmp_path / "bad" / "OAI_CONFIG_LIST.json", '{"model": "x"}')
    result = _run(tmp_path)
    agents = _agents(result)
    travel = agents["agent:autogen/travel"]
    delegated = _edges(result, EdgeType.DELEGATES_TO)
    assert (travel.id, "agent:autogen/refunds") in delegated and (
        travel.id,
        "agent:autogen/flights",
    ) in delegated
    assert (
        len([s for s in _servers(result).values() if "framework:autogen" in s.tags]) == 1
    )  # params is part of the workbench
    assert (travel.id, "server:autogen-mcp-server-fetch") in _edges(result, EdgeType.DEPENDS_ON)
    assert ("agent:autogen/refunds", "model:hosted/openai/gpt-4o") in _edges(result, EdgeType.USES_MODEL)
    assert "approval:callback" in agents["agent:autogen/runner"].tags
    old = agents["agent:autogen/old"]
    assert {"human-input-mode:ALWAYS", "inline-api-key", "capability:execute", "code-execution:host"} <= set(
        old.tags
    )
    assert ("agent:autogen/old", "model:hosted/openai/gpt-4") in _edges(result, EdgeType.USES_MODEL)
    assert "llm:none" in agents["agent:autogen/never"].tags
    assert "unknown:model" in agents["agent:autogen/term"].tags
    assert {"unknown:human_input_mode"} <= set(agents["agent:autogen/odd"].tags)
    assert ("agent:autogen/odd", "model:hosted/openai/gpt-4o-mini") in _edges(result, EdgeType.USES_MODEL)
    assert "human-input-mode:SOMETIMES" in agents["agent:autogen/weird"].tags
    assert ("agent:ag2/assistant", "model:hosted/openai/gpt-4o") in _edges(result, EdgeType.USES_MODEL)
    uses = _edges(result, EdgeType.USES_MODEL)
    assert ("agent:root", "model:hosted/anthropic/claude-3-5-sonnet-20241022") in uses
    claude = _models(result)["model:hosted/anthropic/claude-3-5-sonnet-20241022"]
    assert claude.hosted is not None and claude.hosted.value is not None
    assert claude.hosted.value.endpoint_origin == "https://proxy.internal/v1"
    assert "model:hosted/openai/gpt-4o" not in _models(result)  # a models-hosted literal elsewhere: edge only
    assert FAKE_KEY not in _dump(result)
    failed = {(s.locator, s.error_class) for s in result.coverage[Surface.CODE].sources if not s.ok}
    assert ("bad/OAI_CONFIG_LIST.json", "invalid-config") in failed


# --------------------------------------------------------------------------------------------- Google ADK


def test_google_adk_python_and_yaml_agent_config(tmp_path: Path) -> None:
    _write(
        tmp_path / "py" / "adk_agents.py",
        "from google.adk.agents import LlmAgent, SequentialAgent\n"
        "from google.adk.tools import FunctionTool, AgentTool, google_search\n"
        "from google.adk.tools.mcp_tool import McpToolset, StdioConnectionParams, SseConnectionParams\n"
        "from google.adk.models.lite_llm import LiteLlm\n"
        "from mcp import StdioServerParameters\n"
        "def transfer_money(amount: int) -> str: ...\n"
        "code_agent = LlmAgent(name='code_agent', model=LiteLlm(model='openai/gpt-4o'), instruction='Write code.',\n"
        "                      disallow_transfer_to_parent=True, code_executor=BuiltInCodeExecutor())\n"
        "checker = LlmAgent(name='checker', model='gemini-2.5-flash', instruction='Check {item}.',\n"
        "    before_tool_callback=guard,\n"
        "    tools=[FunctionTool(transfer_money, require_confirmation=True), AgentTool(agent=code_agent), google_search,\n"
        "           FunctionTool(func=unknown_func, require_confirmation=decide), FunctionTool(),\n"
        "           McpToolset(connection_params=StdioConnectionParams(server_params=StdioServerParameters(\n"
        "               command='npx', args=['-y', '@modelcontextprotocol/server-filesystem@1.2.3'])),\n"
        "               tool_filter=['read_file'], require_confirmation=True),\n"
        "           McpToolset(connection_params=SseConnectionParams(url='https://sse.example.com/sse')),\n"
        "           McpToolset(connection_params=dynamic_params)],\n"
        "    sub_agents=[code_agent])\n"
        "pipeline = SequentialAgent(name='pipeline', sub_agents=[checker, 'not-an-agent-ref', 42])\n",
    )
    _write(
        tmp_path / "adk" / "my_agent" / "root_agent.yaml",
        "# yaml-language-server: $schema=https://raw.githubusercontent.com/google/adk-python/main/AgentConfig.json\n"
        "agent_class: LlmAgent\nname: coordinator\nmodel: gemini-2.5-flash\ninstruction: Route {topic}.\n"
        "model_code: {name: x}\ntools:\n  - name: google_search\n  - name: my_pkg.tools.lookup\n  - 7\n"
        "before_tool_callbacks:\n  - name: my_pkg.guard\n"
        "sub_agents:\n  - config_path: ./helper.yaml\n  - code: py.adk_agents.code_agent\n"
        "  - config_path: ../../../../outside.yaml\n  - config_path: ./missing.yaml\n  - config_path: ./bad.yaml\n"
        "  - {other: 1}\n  - config_path: ./helper.yaml\n",
    )
    _write(
        tmp_path / "adk" / "my_agent" / "helper.yaml",
        "agent_class: LlmAgent\nname: helper\nmodel: gemini-2.5-pro\ninstruction: Help.\n"
        "disallow_transfer_to_parent: true\nsub_agents:\n  - config_path: ./root_agent.yaml\n",
    )
    _write(tmp_path / "adk" / "my_agent" / "bad.yaml", "agent_class: [unclosed\n")
    _write(
        tmp_path / "adk" / "lone.yaml", "agent_class: LoopAgent\nname: looper\nstatic_instruction: Loop.\n"
    )
    result = _run(tmp_path)
    agents = _agents(result)
    coord, helper = agents["agent:google-adk/coordinator"], agents["agent:google-adk/helper"]
    assert helper.parent_ref == coord.id and "agent-class:LlmAgent" in coord.tags
    assert (
        _edge(result, EdgeType.DELEGATES_TO, coord.id, helper.id).qualifiers["constraints"]
        == "no-transfer-back-to-parent"
    )
    assert (coord.id, "agent:google-adk/code_agent") in _edges(result, EdgeType.DELEGATES_TO)
    assert (helper.id, coord.id) in _edges(result, EdgeType.DELEGATES_TO)  # a cycle is linked, not re-read
    assert coord.foreign["frameworks:unknown:sub_agents"].startswith(
        "adk/my_agent/root_agent.yaml#/sub_agents/"
    )
    assert "unknown:model" in coord.tags
    tools = _tools(result)
    # a before_tool_callback may block or only log: the gate is unknown, never claimed as conditional
    assert tools["tool:google-adk/coordinator/tools/lookup"].approval_gate is ApprovalGate.UNKNOWN
    assert tools["tool:google-adk/checker/tools/transfer_money"].approval_gate is ApprovalGate.REQUIRED
    assert tools["tool:google-adk/checker/tools/unknown_func"].approval_gate is ApprovalGate.UNKNOWN
    assert CapabilityClass.NETWORK_EGRESS in tools["tool:google-adk/checker/tools/google_search"].capabilities
    assert (agents["agent:google-adk/checker"].id, "agent:google-adk/code_agent") in _edges(
        result, EdgeType.DELEGATES_TO
    )
    fs = _servers(result)["server:google-adk-server-filesystem"]
    assert fs.client_trust_flags["google-adk.approval"] == "required"
    assert tools["tool:google-adk-server-filesystem/read_file"].approval_gate is ApprovalGate.REQUIRED
    assert _servers(result)["server:google-adk-sse.example.com"].transport.value is Transport.SSE
    assert "capability:execute" in agents["agent:google-adk/code_agent"].tags
    assert ("agent:google-adk/code_agent", "model:hosted/openai/openai-gpt-4o") in _edges(
        result, EdgeType.USES_MODEL
    )
    assert agents["agent:google-adk/checker"].parent_ref == agents["agent:google-adk/pipeline"].id
    assert "unknown:sub_agents" in agents["agent:google-adk/pipeline"].tags
    assert "agent:google-adk/looper" in agents
    failed = {(s.locator, s.error_class) for s in result.coverage[Surface.CODE].sources if not s.ok}
    assert ("adk/my_agent/bad.yaml", "parse-error") in failed
    assert any("no literal command or URL" in w for w in result.warnings)


# --------------------------------------------------------------------------------------------- Semantic Kernel


def test_semantic_kernel_prompt_yaml_plugin_dirs_and_agents(tmp_path: Path) -> None:
    skprompt = "Write a poem about {{$topic}}.\r\n"
    (tmp_path / "plugins" / "Writer" / "Poem").mkdir(parents=True)
    (tmp_path / "plugins" / "Writer" / "Poem" / "skprompt.txt").write_bytes(skprompt.encode())
    _write(
        tmp_path / "plugins" / "Writer" / "Poem" / "config.json",
        json.dumps({"description": "Writes poems", "template_format": "semantic-kernel",
                    "execution_settings": {"default": {"model_id": "gpt-4o"}, "bad": 1}}),
    )  # fmt: skip
    (tmp_path / "plugins" / "Writer" / "Joke").mkdir(parents=True)
    (tmp_path / "plugins" / "Writer" / "Joke" / "skprompt.txt").write_bytes(b"Tell a joke")
    _write(
        tmp_path / "prompts" / "summarize.yaml",
        "name: Summarize\ndescription: Summaries\ntemplate: |\n  Summarize {{input}}\ntemplate_format: handlebars\n"
        "allow_dangerously_set_content: true\nexecution_settings:\n  default:\n    ai_model_id: gpt-4o-mini\n",
    )
    _write(
        tmp_path / "agents" / "declarative.yaml",
        "type: chat_completion_agent\nname: Helper\ndescription: Helps\ninstructions: Help with {{$task}}.\n"
        "model:\n  id: gpt-4.1\ntools:\n  - id: Search.Find\n    type: function\n  - nope\n",
    )
    _write(tmp_path / "other.yaml", "plain: config\ntemplate_format: none\n")
    _write(tmp_path / "list.yaml", "- template: x\n  template_format: y\n")
    _write(
        tmp_path / "agent.py",
        "from semantic_kernel.agents import ChatCompletionAgent\n"
        "from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion, AzureChatCompletion\n"
        "from semantic_kernel.connectors.ai import FunctionChoiceBehavior\n"
        "from semantic_kernel.connectors.mcp import MCPStdioPlugin, MCPStreamableHttpPlugin\n"
        "async def main():\n"
        "    async with MCPStdioPlugin(name='github', command='docker', args=['run', '-i', 'ghcr.io/github/github-mcp-server']) as gh, \\\n"
        "               MCPStreamableHttpPlugin(name='docs', url='https://docs.example.com/mcp') as docs:\n"
        "        manual = ChatCompletionAgent(service=OpenAIChatCompletion(ai_model_id='gpt-4o'), name='Manual',\n"
        "            instructions='Answer.', plugins=[gh, docs],\n"
        "            function_choice_behavior=FunctionChoiceBehavior.Auto(auto_invoke=False))\n"
        "        auto = ChatCompletionAgent(service=AzureChatCompletion(deployment_name='prod-gpt4o'), name='Auto',\n"
        "            function_choice_behavior=FunctionChoiceBehavior.Required(), plugins=registry)\n"
        "        odd = ChatCompletionAgent(name='Odd', function_choice_behavior=behaviour,\n"
        "            service=OpenAIChatCompletion())\n"
        "        weird = ChatCompletionAgent(name='Weird', function_choice_behavior=FunctionChoiceBehavior.Auto(auto_invoke=x))\n",
    )
    result = _run(tmp_path)
    agents = _agents(result)
    poem = agents["agent:semantic-kernel/writer.poem"]
    assert "semantic-kernel:prompt-function" in poem.tags and poem.description == "Writes poems"
    templates = {e.id: e for e in result.entities if isinstance(e, PromptTemplate)}
    poem_t = templates["prompt:semantic-kernel/writer.poem/skprompt"]
    assert poem_t.template_digest == _sha(skprompt)  # exact file bytes, CRLF preserved
    assert poem_t.engine is TemplateEngine.OTHER and poem_t.risk_class is TemplateRiskClass.NONE
    assert (poem.id, poem_t.id) in _edges(result, EdgeType.LOADS_INSTRUCTION)
    assert (poem.id, "model:hosted/openai/gpt-4o") in _edges(result, EdgeType.USES_MODEL)
    assert "agent:semantic-kernel/writer.joke" in agents
    summarize = templates["prompt:semantic-kernel/summarize/template"]
    assert (
        summarize.engine is TemplateEngine.HANDLEBARS
        and summarize.risk_class is TemplateRiskClass.TEMPLATE_EXECUTION
    )
    assert "allow-dangerously-set-content" in agents["agent:semantic-kernel/summarize"].tags
    helper = agents["agent:semantic-kernel/helper"]
    assert "agent-type:chat_completion_agent" in helper.tags
    assert "tool:semantic-kernel/helper/tools/Search.Find" in _tools(result)
    instr = _instructions(result)["instr:semantic-kernel/helper/instructions"]
    assert "template:semantic-kernel" in instr.tags
    manual = agents["agent:semantic-kernel/manual"]
    assert {
        (manual.id, "server:semantic-kernel-github"),
        (manual.id, "server:semantic-kernel-docs"),
    } <= _edges(result, EdgeType.DEPENDS_ON)
    assert "function-choice:Auto" in manual.tags
    assert (manual.id, "model:hosted/openai/gpt-4o") in _edges(result, EdgeType.USES_MODEL)
    auto = agents["agent:semantic-kernel/auto"]
    assert "unknown:tools" in auto.tags and "function-choice:Required" in auto.tags
    assert ("agent:semantic-kernel/auto", "model:hosted/azure-openai/prod-gpt4o") not in _models(result)
    assert "unknown:function_choice_behavior" in agents["agent:semantic-kernel/odd"].tags
    assert "model:implicit-default:openai" in agents["agent:semantic-kernel/odd"].tags
    assert "unknown:function_choice_behavior" in agents["agent:semantic-kernel/weird"].tags


# --------------------------------------------------------------------------------------------- Pydantic AI, LlamaIndex, Strands, MAF


def test_pydantic_ai_agents_tools_and_toolsets(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyd.py",
        "from pydantic_ai import Agent, Tool\n"
        "from pydantic_ai.mcp import MCPServerStdio, MCPServerStreamableHTTP\n"
        "import textwrap\n"
        "def wipe(path: str) -> None: ...\n"
        "PROMPT = textwrap.dedent('''\n    Be concise.\n    Cite sources.\n''').strip()\n"
        "agent = Agent('openai:gpt-4o', instructions=PROMPT, system_prompt=['One.', 'Two.'],\n"
        "    tools=[Tool(wipe, requires_approval=True), Tool(wipe, name='wipe2'), Tool(lambda: 1)],\n"
        "    toolsets=[MCPServerStdio('npx', args=['-y', '@acme/mcp']), MCPServerStreamableHTTP('https://mcp.example.com/mcp')])\n"
        "plain = Agent(model='anthropic:claude-sonnet-4-5', name='plain', toolsets=FunctionToolset([wipe]))\n"
        "MODEL_NAME = 'gpt-4o-mini'\n"
        "named = Agent(model=MODEL_NAME, name='named', instructions=None)\n"
        "@agent.tool(requires_approval=True)\n"
        "def deploy(ctx) -> str: ...\n"
        "@agent.tool_plain\n"
        "def ping() -> str: ...\n"
        "@agent.system_prompt\n"
        "def dyn(ctx) -> str: ...\n"
        "@nobody.tool\n"
        "def lost(ctx) -> str: ...\n",
    )
    result = _run(tmp_path)
    agents = _agents(result)
    agent = agents["agent:pydantic-ai/agent"]
    instr = _instructions(result)
    assert instr["instr:pydantic-ai/agent/instructions"].digest == _sha("Be concise.\nCite sources.")
    assert {"instr:pydantic-ai/agent/system_prompt-0", "instr:pydantic-ai/agent/system_prompt-1"} <= set(
        instr
    )
    assert "unknown:instructions" in agent.tags and "dynamic-instructions" in agent.tags
    tools = _tools(result)
    assert tools["tool:pydantic-ai/agent/tools/wipe"].approval_gate is ApprovalGate.REQUIRED
    assert tools["tool:pydantic-ai/agent/tools/wipe2"].approval_gate is ApprovalGate.NONE
    assert tools["tool:pydantic-ai/agent/tools/deploy"].approval_gate is ApprovalGate.REQUIRED
    assert tools["tool:pydantic-ai/agent/tools/ping"].approval_gate is ApprovalGate.NONE
    assert "unknown:tools" in agent.tags
    assert ("agent:pydantic-ai/agent", "model:hosted/openai/openai-gpt-4o") in _edges(
        result, EdgeType.USES_MODEL
    )
    assert "model:hosted/openai/openai-gpt-4o" in _models(
        result
    )  # a positional ``provider:model``: owned here
    assert ("agent:pydantic-ai/plain", "model:hosted/anthropic/anthropic-claude-sonnet-4-5") in _edges(
        result, EdgeType.USES_MODEL
    )
    assert ("agent:pydantic-ai/named", "model:hosted/openai/gpt-4o-mini") in _edges(
        result, EdgeType.USES_MODEL
    )
    assert "model:hosted/openai/gpt-4o-mini" not in _models(
        result
    )  # MODEL_NAME constant: a models-hosted literal
    servers = _servers(result)
    assert servers["server:pydantic-ai-mcp"].transport.value is Transport.STDIO
    assert servers["server:pydantic-ai-mcp.example.com"].transport.value is Transport.STREAMABLE_HTTP


def test_llama_index_strands_and_agent_framework(tmp_path: Path) -> None:
    _write(
        tmp_path / "others.py",
        "from llama_index.core.agent.workflow import FunctionAgent, AgentWorkflow, ReActAgent\n"
        "from llama_index.llms.anthropic import Anthropic\n"
        "from llama_index.tools.mcp import BasicMCPClient\n"
        "from strands import Agent as StrandsAgent\n"
        "from strands.models import BedrockModel\n"
        "from strands.tools.mcp import MCPClient\n"
        "from mcp import stdio_client, StdioServerParameters\n"
        "from strands_tools import calculator, shell\n"
        "from agent_framework import ChatAgent, MCPStdioTool, ai_function\n"
        "from agent_framework.openai import OpenAIChatClient\n"
        "import os\n"
        "research = FunctionAgent(name='ResearchAgent', description='Researches', system_prompt='Research.',\n"
        "    llm=Anthropic(model='claude-sonnet-4-5'), tools=[], can_handoff_to=['WriteAgent', 'Ghost'])\n"
        "write = ReActAgent(name='WriteAgent', system_prompt='Write.', llm=Anthropic(model=os.getenv('MODEL', 'claude-opus-4-1')))\n"
        "flow = AgentWorkflow(agents=[research, write], root_agent='ResearchAgent')\n"
        "client = BasicMCPClient('https://mcp.example.com/sse')\n"
        "aws_docs = MCPClient(lambda: stdio_client(StdioServerParameters(command='uvx',\n"
        "    args=['awslabs.aws-documentation-mcp-server@latest'])))\n"
        "helper = StrandsAgent(name='helper', system_prompt='Help.', interventions=[confirm])\n"
        "ops = StrandsAgent(model=BedrockModel(model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0'), name='ops',\n"
        "    system_prompt='Ops.', tools=[calculator, shell, helper, aws_docs, 'retrieve'])\n"
        "@ai_function(approval_mode='always_require')\n"
        "def rm(path: str) -> None: ...\n"
        "maf = ChatAgent(chat_client=OpenAIChatClient(model_id='gpt-4o'), instructions='MAF.', name='maf',\n"
        "    tools=[rm, MCPStdioTool(name='git', command='uvx', args=['mcp-server-git'], approval_mode='never_require',\n"
        "                            allowed_tools=['git_status'])])\n",
    )
    result = _run(tmp_path)
    agents = _agents(result)
    delegated = _edges(result, EdgeType.DELEGATES_TO)
    research, write = agents["agent:llama-index/researchagent"], agents["agent:llama-index/writeagent"]
    assert (research.id, write.id) in delegated and "unknown:handoffs" in research.tags
    flow = agents["agent:llama-index/flow"]
    assert {(flow.id, research.id), (flow.id, write.id)} <= delegated and research.parent_ref == flow.id
    assert "model-env-override:MODEL" in write.tags
    assert (write.id, "model:hosted/anthropic/claude-opus-4-1") in _edges(result, EdgeType.USES_MODEL)
    assert ("agent:root", "server:llama-index-client") in _edges(result, EdgeType.DEPENDS_ON)
    assert _servers(result)["server:llama-index-client"].transport.value is Transport.SSE
    ops = agents["agent:strands-agents/ops"]
    assert (ops.id, "agent:strands-agents/helper") in delegated
    assert (ops.id, "server:strands-agents-aws_docs") in _edges(result, EdgeType.DEPENDS_ON)
    tools = _tools(result)
    assert CapabilityClass.EXECUTE in tools["tool:strands-agents/ops/tools/shell"].capabilities
    assert tools["tool:strands-agents/ops/tools/retrieve"].approval_gate is ApprovalGate.UNKNOWN
    assert "control:interventions" in agents["agent:strands-agents/helper"].tags
    uses = _edges(result, EdgeType.USES_MODEL)
    assert (ops.id, "model:hosted/aws-bedrock/us.anthropic.claude-3-7-sonnet-20250219-v1-0") in uses
    maf = agents["agent:agent-framework/maf"]
    assert tools["tool:agent-framework/maf/tools/rm"].approval_gate is ApprovalGate.REQUIRED
    git_status = tools["tool:agent-framework-git/git_status"]
    assert git_status.approval_gate is ApprovalGate.NONE
    assert (maf.id, "server:agent-framework-git") in _edges(result, EdgeType.DEPENDS_ON)


# --------------------------------------------------------------------------------------------- TypeScript


def test_typescript_frameworks_with_literal_configuration(tmp_path: Path) -> None:
    _write(
        tmp_path / "ts" / "mastra.ts",
        'import { Agent } from "@mastra/core/agent";\n'
        'import { openai } from "@ai-sdk/openai";\n'
        "// a comment with { braces } and new Agent({ in it\n"
        "/* block comment */\n"
        "export const weatherAgent = new Agent({\n"
        '  id: "weather-agent",\n'
        "  name: 'Weather Agent',\n"
        "  description: `Weather`,\n"
        "  instructions: `You are a helpful weather assistant.\\nUse tools.`,\n"
        '  model: openai("gpt-4o"),\n'
        "  tools: { weatherTool, forecast: forecastTool, ...more },\n"
        "  agents: { helperAgent, inline: { name: 'x', instructions: 'Inline helper.' } },\n"
        "});\n"
        'export const dyn = new Agent({ name: "Dyn", instructions: `Hi ${name}`, model: "openai/gpt-4.1", ...rest });\n'
        "export const broken = new Agent({ name: 'Broken', instructions: 'unterminated\n",
    )
    _write(
        tmp_path / "ts" / "claude.ts",
        'import { query } from "@anthropic-ai/claude-agent-sdk";\n'
        "for await (const m of query({\n"
        '  prompt: "Fix it",\n'
        "  options: {\n"
        '    model: "claude-opus-4-1",\n'
        '    fallbackModel: "sonnet",\n'
        '    permissionMode: "bypassPermissions",\n'
        "    allowDangerouslySkipPermissions: true,\n"
        '    allowedTools: ["Read", "Edit", "mcp__files"],\n'
        "    disallowedTools: blocked,\n"
        "    canUseTool: async () => ({ behavior: 'allow' }),\n"
        '    systemPrompt: { type: "preset", preset: "claude_code", append: "Be safe." },\n'
        '    agents: { reviewer: { description: "Reviews", prompt: "Review it.", tools: ["Read"], model: "haiku" }, ref: other },\n'
        '    mcpServers: { files: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem"] }, bad: 3 },\n'
        "  },\n"
        "})) {}\n"
        "query({ prompt: 'x', options: opts });\n"
        "query({ prompt: 'y', options: { permissionMode: mode, agents: list, mcpServers: srv, model: pick() } });\n",
    )
    _write(
        tmp_path / "ts" / "vercel.mts",
        'import { generateText, ToolLoopAgent } from "ai";\n'
        'import { anthropic } from "@ai-sdk/anthropic";\n'
        'const r = await generateText({ model: anthropic("claude-sonnet-4-5"), prompt: "hi" });\n'
        'const s = await generateText({ model: "gpt-4.1-mini", system: "Answer.", tools: [search, "lookup", 5] });\n'
        "const agent = new ToolLoopAgent({ model: anthropic('claude-sonnet-4-5'), instructions: \"Loop.\", tools: search });\n",
    )
    _write(
        tmp_path / "ts" / "lc.js",
        "const { createAgent } = require('langchain');\n"
        "const agent = createAgent({ model: 'anthropic:claude-sonnet-4-5', systemPrompt: 'Help.', name: 'lc', tools: [a, b] });\n",
    )
    _write(tmp_path / "ts" / "only_import.ts", 'import type { Agent } from "@mastra/core/agent";\n')
    _write(
        tmp_path / "ts" / "types.d.ts", 'import { Agent } from "@mastra/core";\nnew Agent({ name: "decl" })\n'
    )
    _write(tmp_path / "ts" / "other.ts", 'import x from "left-pad";\n')
    result = _run(tmp_path)
    agents = _agents(result)
    weather = agents["agent:mastra/weather-agent"]
    assert weather.description == "Weather"
    assert _instructions(result)["instr:mastra/weather-agent/instructions"].digest == _sha(
        "You are a helpful weather assistant.\nUse tools."
    )
    assert "model:hosted/openai/gpt-4o" in _models(result)  # factory call: models-hosted cannot see it
    assert {"tool:mastra/weather-agent/tools/forecast", "tool:mastra/weather-agent/tools/weatherTool"} <= set(
        _tools(result)
    )
    assert agents["agent:mastra/helperagent"].parent_ref == weather.id
    assert "unknown:definition" in agents["agent:mastra/helperagent"].tags
    assert agents["agent:mastra/inline"].parent_ref == weather.id  # a sub-agent is named by its key

    dyn = agents["agent:mastra/dyn"]
    assert {"unknown:instructions", "unknown:spread", "partial-definition"} <= set(dyn.tags)
    assert (dyn.id, "model:hosted/openai/openai-gpt-4.1") in _edges(result, EdgeType.USES_MODEL)
    assert "model:hosted/openai/openai-gpt-4.1" not in _models(
        result
    )  # a JS ``model:`` literal models-hosted owns
    broken = next(a for a in agents.values() if a.name.startswith("mastra-L"))
    assert {"unknown:instructions", "unknown:model", "unknown:tools"} <= set(broken.tags)
    claude = next(a for a in agents.values() if a.id.startswith("agent:claude-agent-sdk/claude-l"))
    assert {
        "approval-bypass:allowDangerouslySkipPermissions",
        "permission-mode:bypassPermissions",
        "unknown:disallowedTools",
    } <= set(claude.tags)
    reviewer = agents["agent:claude-agent-sdk/reviewer"]
    link = _edge(result, EdgeType.DELEGATES_TO, claude.id, reviewer.id)
    assert link.qualifiers["constraints"] == "tools:Read"
    files = _servers(result)["server:claude-agent-sdk-files"]
    assert files.client_trust_flags["claude-code.permissions.allow"] == "*"
    assert (claude.id, "model:hosted/anthropic/sonnet") in _edges(result, EdgeType.USES_MODEL)
    unknown_opts = [a for a in agents.values() if "unknown:options" in a.tags]
    assert len(unknown_opts) == 1
    dynamic = next(a for a in agents.values() if "unknown:permissionMode" in a.tags)
    assert {"unknown:agents", "unknown:mcpServers", "unknown:model"} <= set(dynamic.tags)
    vercel = [a for a in agents.values() if a.id.startswith("agent:vercel-ai-sdk/")]
    assert len(vercel) == 2  # the tool-less generateText call is a model call, not an agent
    assert any("unknown:tools" in a.tags for a in vercel)
    lc = agents["agent:langchain/lc"]
    assert (lc.id, "model:hosted/anthropic/anthropic-claude-sonnet-4-5") in _edges(
        result, EdgeType.USES_MODEL
    )
    assert not any(a.name == "decl" for a in agents.values())
    assert any("only_import.ts" in w for w in result.warnings)
    sources = {
        s.locator for s in result.coverage[Surface.CODE].sources if s.source == "frameworks:typescript"
    }
    assert "ts/other.ts" not in sources and "ts/only_import.ts" in sources


def test_ts_object_scanner_edge_cases() -> None:
    text = (
        "{ a: 'x\\'y', 'b': [1, 'two', [3], {c: 4}], d: f('m'), e: g(h), ...s, k, /* c */ m: `t`, n: true }"
    )
    props, end = ts_object(text, 0)
    assert props is not None and end == len(text)
    assert props["a"].value == "x'y" and props["b"].kind == "list" and props["d"].kind == "call"
    assert props["e"].kind == "call" and props["k"].kind == "ident" and props["m"].value == "t"
    assert props["n"].kind == "ident" and "..." in props
    assert ts_object("no brace", 0) == (None, 0)
    assert ts_object("{ a: 1", 0)[0] is None  # unterminated
    assert ts_object("{ a: [1, 2 }", 0)[0] is not None
    recovered = ts_object("{ 1: 2, ) , b: 3 }", 0)[0]
    assert recovered is not None and "b" in recovered
    assert (
        ts_object("{ 'q\n': 3 }", 0)[0] is None
    )  # an unterminated string swallows the rest: unknown, not a crash
    assert ts_object("{ a: x.y, b: 'c' }", 0)[0]["b"].value == "c"  # type: ignore[index]


# --------------------------------------------------------------------------------------------- literals


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("'a' + 'b'", "ab"),
        ("['a', 1, None, True]", ["a", 1, None, True]),
        ("{'k': ('v',)}", {"k": ["v"]}),
        ("dedent('''\n  x\n  y''')", "\nx\ny"),
        ("inspect.cleandoc('  a\\n  b')", "a\nb"),
        ("'  p  '.strip()", "p"),
        ("C", "constant"),
        ("f'{x}'", NON_LITERAL),
        ("{**x}", NON_LITERAL),
        ("{1: 'a'}", NON_LITERAL),
        ("['a', b]", NON_LITERAL),
        ("'a' + 1", NON_LITERAL),
        ("dedent(x)", NON_LITERAL),
        ("str('x')", NON_LITERAL),
        ("x.strip()", NON_LITERAL),
        ("b'bytes'", NON_LITERAL),
        ("unknown_name", NON_LITERAL),
    ],
)
def test_literal_evaluator(source: str, expected: object) -> None:
    node = ast.parse(source, mode="eval").body
    consts = {"C": ast.parse("'constant'", mode="eval").body}
    assert literal(node, consts) == expected


def test_literal_evaluator_bounds() -> None:
    big = ast.parse("[" + ",".join(["1"] * (fw.MAX_ITEMS + 1)) + "]", mode="eval").body
    assert literal(big) is NON_LITERAL
    big_dict = ast.parse(
        "{" + ",".join(f"'k{i}': 1" for i in range(fw.MAX_ITEMS + 1)) + "}", mode="eval"
    ).body
    assert literal(big_dict) is NON_LITERAL
    loop = {"A": ast.Name(id="B"), "B": ast.Name(id="A")}
    assert literal(ast.Name(id="A"), loop) is NON_LITERAL
    assert literal(None) is NON_LITERAL
    assert split_provider_prefix("openai:gpt-4o") == ("openai", "gpt-4o")
    assert split_provider_prefix("custom:thing") == (None, "custom:thing")


# --------------------------------------------------------------------------------------------- safety


def test_secrets_are_never_recorded(tmp_path: Path) -> None:
    _write(
        tmp_path / "leaky.py",
        "from agents import Agent\n"
        "from agents.mcp import MCPServerStdio\n"
        "from langchain_anthropic import ChatAnthropic\n"
        "srv = MCPServerStdio(params={'command': 'npx', 'args': ['-y', 'pkg', '--token', '"
        + FAKE_GH
        + "'],\n"
        "                            'env': {'GITHUB_TOKEN': '" + FAKE_GH + "', 'MODE': 'x'}})\n"
        "a = Agent(name='" + FAKE_KEY + "', instructions='use key " + FAKE_KEY + "',\n"
        "          handoff_description='" + FAKE_KEY + "', model='" + FAKE_KEY + "', mcp_servers=[srv])\n"
        "b = Agent(name='b', model=ChatAnthropic(model='claude-sonnet-4-5', api_key='" + FAKE_KEY + "'))\n",
    )
    _write(
        tmp_path / "prompts" / "p.yaml",
        "name: P\ntemplate: 'key " + FAKE_KEY + "'\ntemplate_format: jinja2\n",
    )
    result = _run(tmp_path)
    dumped = _dump(result)
    assert FAKE_KEY not in dumped and FAKE_GH not in dumped
    (instr,) = [i for i in _instructions(result).values() if i.contains_secret_like]
    assert instr.digest == _sha("use key " + FAKE_KEY)
    server = next(
        s for s in _servers(result).values() if s.client == "openai-agents" and s.server_kind.value == "mcp"
    )
    assert server.env_var_names == ["GITHUB_TOKEN", "MODE"] and "inline-secret-in-config" in server.tags
    assert sum(r.count for r in result.redactions) >= 6
    redaction = result.redactions[0]
    assert server.id in redaction.ids and instr.id in redaction.ids
    templates = [e for e in result.entities if isinstance(e, PromptTemplate)]
    assert (
        "contains-secret-like" in templates[0].tags
        and templates[0].risk_class is TemplateRiskClass.TEMPLATE_EXECUTION
    )


def test_hostile_and_unreadable_inputs_become_coverage_facts(tmp_path: Path) -> None:
    _write(tmp_path / "syntax.py", "from agents import Agent\nAgent(name='x'\n")
    _write(tmp_path / "deep.py", "from agents import Agent\nx = " + "(" * 2000 + "1" + ")" * 2000 + "\n")
    _write(tmp_path / "huge.py", "from agents import Agent\n" + "#" * (fw.MAX_SOURCE_BYTES + 10))
    _write(tmp_path / "huge.ts", 'import { Agent } from "@mastra/core";\n' + "/" * (fw.MAX_SOURCE_BYTES + 10))
    _write(tmp_path / "agents.yaml", "researcher:\n  role: [unclosed\n")
    _write(tmp_path / "root_agent.yaml", "x" * (fw.MAX_SOURCE_BYTES + 10))
    _write(
        tmp_path / "bomb" / "agents.yaml",
        "a: &a [x, x]\nb: &b [*a, *a]\nrole: [*b, *b, *b]\n" + "c: [*b]\n" * 2000,
    )
    _write(tmp_path / "notdict" / "agents.yaml", "- role: x\n")
    _write(tmp_path / "noimports.py", "import os\nagents = 1\n")
    _write(tmp_path / "tasks.yaml", "not: [valid\n")
    _write(tmp_path / "list" / "tasks.yaml", "- 1\n")
    result = _run(tmp_path)
    failed = {(s.locator, s.error_class) for s in result.coverage[Surface.CODE].sources if not s.ok}
    assert ("syntax.py", "parse-error") in failed
    assert ("huge.py", "too-large") in failed and ("huge.ts", "too-large") in failed
    assert ("root_agent.yaml", "too-large") in failed
    assert ("agents.yaml", "parse-error") in failed and ("bomb/agents.yaml", "parse-error") in failed
    assert ("tasks.yaml", "parse-error") in failed
    assert result.coverage[Surface.CODE].status is CoverageStatus.PARTIAL
    assert result.status.value == "ok"
    assert not _agents(result)


def test_budget_truncation_is_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for i in range(3):
        _write(tmp_path / f"m{i}.py", f"from agents import Agent\na{i} = Agent(name='a{i}')\n")
    _write(tmp_path / "late.ts", 'import { Agent } from "@mastra/core";\n')
    monkeypatch.setattr(fw, "MAX_CODE_FILES", 1)
    result = _run(tmp_path)
    truncated = [s for s in result.coverage[Surface.CODE].sources if s.error_class == "truncated"]
    assert truncated and truncated[0].items == 2
    assert len(_agents(result)) == 1
    monkeypatch.setattr(fw, "MAX_CODE_FILES", 4000)
    monkeypatch.setattr(fw, "CODE_TIME_SHARE", 0.0)
    slow = _run(tmp_path)

    assert any(s.error_class == "truncated" for s in slow.coverage[Surface.CODE].sources)


def test_walk_limits_are_reported(tmp_path: Path) -> None:
    for i in range(5):
        _write(tmp_path / f"f{i}.txt", "x")
    result = _run(tmp_path, max_files=2)
    assert result.coverage[Surface.CODE].status is CoverageStatus.TRUNCATED


_PATHOLOGICAL = [
    "{" * 5000,
    "{a:" * 3000,
    "'" * 5000,
    "`${" * 3000,
    "/*" * 3000,
    "//\n" * 3000,
    "new Agent(" * 2000,
    "new Agent({" + "a: [" * 3000,
    "{ a: f(" * 3000,
    "from '" + "@mastra/core/" * 500,
    "{" + "x" * 10000 + "}",
]


def test_regexes_and_scanner_are_linear_on_hostile_input() -> None:
    patterns = [
        fw._TS_IMPORT,
        fw._TS_IDENT,
        *fw._TS_CALLS.values(),
        re.compile(r"\{[A-Za-z_][A-Za-z0-9_.?]{0,100}\}"),
        fw._LINE_SUFFIX,
    ]
    for text in _PATHOLOGICAL:
        for pattern in patterns:
            start = time.perf_counter()
            list(pattern.finditer(text))
            assert time.perf_counter() - start < 0.05, (pattern.pattern, text[:30])
        start = time.perf_counter()
        for i in (0, 1, len(text) // 2):
            ts_object(text, i)
        assert time.perf_counter() - start < 0.5, text[:30]
        start = time.perf_counter()
        fw._template_style("crewai", text)
        assert time.perf_counter() - start < 0.05


def test_output_is_deterministic(tmp_path: Path) -> None:
    first = _run(FIXTURE)
    second = _run(FIXTURE)
    strip = re.compile(r'"(?:observed_at|observedAt|applied_at)": "[^"]*"')
    assert strip.sub("", _dump(first)) == strip.sub("", _dump(second))
    ids = [e.id for e in first.entities]
    assert len(ids) == len(set(ids))


def test_ambiguous_and_colliding_names(tmp_path: Path) -> None:
    for name in ("a", "b"):
        _write(
            tmp_path / name / "agent.py",
            "from agents import Agent\n"
            "helper = Agent(name='Helper')\n"
            "main = Agent(name='Main', handoffs=[helper])\n",
        )
    _write(
        tmp_path / "c" / "use.py",
        "from agents import Agent\nfrom agent import helper\nfrom nowhere import ghost\n"
        "x = Agent(name='X', handoffs=[helper, ghost], tools=[helper])\n",
    )
    _write(
        tmp_path / "d" / "same.py",
        "from autogen_agentchat.agents import AssistantAgent\n"
        "a = AssistantAgent('dup', client, handoffs=['dup', 'solo'])\n"
        "b = AssistantAgent('dup', client)\n"
        "c = AssistantAgent('solo', client)\n",
    )
    result = _run(tmp_path)
    agents = _agents(result)
    mains = [a for a in agents.values() if a.name == "Main"]
    assert len(mains) == 2 and len({a.id for a in mains}) == 2
    x = agents["agent:openai-agents/x"]
    assert "unknown:handoffs" in x.tags  # `helper` is ambiguous across two modules, `ghost` is not an agent
    assert any(
        t.startswith("tool-ref:import") for t in _tools(result)["tool:openai-agents/x/tools/helper"].tags
    )
    dup = [a for a in agents.values() if a.name == "dup"]
    assert len(dup) == 2
    assert any((d.id, "agent:autogen/solo") in _edges(result, EdgeType.DELEGATES_TO) for d in dup)


# --------------------------------------------------------------------------------------------- end to end


def test_scan_end_to_end_two_frameworks() -> None:
    from symbiote.scan import scan

    outcome = scan(FIXTURE, deterministic=True)
    bom = outcome.bom
    assert not [w for w in outcome.warnings if "dangling" in w or "duplicate entity" in w]
    root = bom.subject
    agents = {a.id: a for a in bom.agents}
    expected = {
        "agent:openai-agents/triage",
        "agent:openai-agents/refunds",
        "agent:openai-agents/billing",
        "agent:claude-agent-sdk/options.options",
        "agent:claude-agent-sdk/reviewer",
        "agent:crewai/researcher",
        "agent:crewai/writer",
    }
    assert expected <= set(agents)
    assert all(agents[a].role is AgentRole.SUB_AGENT for a in expected)
    assert agents["agent:claude-agent-sdk/reviewer"].parent_ref == "agent:claude-agent-sdk/options.options"
    assert agents["agent:openai-agents/triage"].parent_ref == root
    edges = {(e.type, e.from_ref, e.to_ref) for e in bom.edges}
    assert (EdgeType.DELEGATES_TO, "agent:openai-agents/triage", "agent:openai-agents/billing") in edges
    assert (
        EdgeType.DELEGATES_TO,
        "agent:claude-agent-sdk/options.options",
        "agent:claude-agent-sdk/reviewer",
    ) in edges
    assert (EdgeType.DELEGATES_TO, "agent:crewai/researcher", "agent:crewai/writer") in edges
    models = {m.id for m in bom.models}
    for kind, src, dst in edges:
        if kind is EdgeType.USES_MODEL and src in expected:
            assert dst in models
    assert (EdgeType.USES_MODEL, "agent:openai-agents/triage", "model:hosted/openai/gpt-4o") in edges
    assert (
        EdgeType.USES_MODEL,
        "agent:crewai/writer",
        "model:hosted/anthropic/anthropic-claude-sonnet-4-5",
    ) in edges
    tools = {t.id: t for t in bom.tools}
    assert tools["tool:openai-agents/refunds/tools/issue_refund"].approval_gate is ApprovalGate.REQUIRED
    assert tools["tool:claude-agent-sdk/options.options/tools/Bash"].approval_gate is ApprovalGate.NONE
    findings = {(f.check_id, tuple(f.subject_refs)) for f in bom.derived.findings}
    assert ("SYM-HITL-001", ("server:claude-agent-sdk-tickets",)) in findings
    assert ("SYM-HITL-001", ("server:claude-agent-sdk/options.options/tools",)) in findings
    run = next(c for c in bom.coverage.collectors if c.name == "frameworks")
    assert run.status.value == "ok"


# --------------------------------------------------------------------------------------------- review regressions


def _sources(result: CollectionResult) -> list[tuple[str, str | None, bool, str | None, int]]:
    return [
        (s.source, s.locator, s.ok, s.error_class, s.items) for s in result.coverage[Surface.CODE].sources
    ]


def _bomb(width: int, levels: int) -> str:
    body = "L0 = [" + ",".join(['"a"'] * width) + "]\n"
    for k in range(1, levels + 1):
        body += f"L{k} = [" + ",".join([f"L{k - 1}"] * width) + "]\n"
    return body


def test_literal_work_is_bounded_on_constant_bombs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Finding 0: constants that refer to each other cannot make one evaluation exponential."""
    tree = ast.parse(_bomb(40, 6))
    consts = fw._Consts({t.targets[0].id: t.value for t in tree.body if isinstance(t, ast.Assign)})  # type: ignore[union-attr]
    start = time.monotonic()
    assert literal(ast.Name(id="L6"), consts) is NON_LITERAL
    assert literal(ast.Name(id="L4"), dict(consts)) is NON_LITERAL  # bounded without the memo too
    assert literal(ast.Name(id="L1"), consts) == [["a"] * 40] * 40
    assert time.monotonic() - start < 2.0
    _write(
        tmp_path / "bomb.py",
        "from agents import Agent\n" + _bomb(40, 6) + "x = Agent(name='x', instructions=L6)\n",
    )
    _write(tmp_path / "ok_agent.py", "from agents import Agent\nok = Agent(name='ok', instructions='hi')\n")
    start = time.monotonic()
    result = _run(tmp_path, budget_seconds=5)
    assert time.monotonic() - start < 3.0
    assert result.status == "ok"
    agents = _agents(result)
    assert (
        "agent:openai-agents/ok" in agents and "unknown:instructions" in agents["agent:openai-agents/x"].tags
    )
    # one file cannot use the whole budget: past its time share it is reported, not half-described
    monkeypatch.setattr(fw, "FILE_TIME_SHARE", 0.0)
    cut = _run(tmp_path)
    assert ("frameworks:python", "bomb.py", False, "truncated", 1) in _sources(cut)
    assert not _agents(cut) and cut.coverage[Surface.CODE].status is CoverageStatus.TRUNCATED


def test_config_handler_errors_stay_inside_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Finding 1: a non-string ADK key, or any handler failure, is one file's coverage error."""
    _write(tmp_path / "adk" / "root_agent.yaml", "name: a\nmodel: gemini-2.0-flash\n1: x\n")
    _write(tmp_path / "ok.py", "from agents import Agent\nok = Agent(name='ok')\n")
    result = _run(tmp_path)
    assert result.status == "ok"
    assert {"agent:google-adk/a", "agent:openai-agents/ok"} <= set(_agents(result))

    def boom(*_args: object) -> None:
        raise RuntimeError("/secret/host/path " + FAKE_KEY)

    _write(tmp_path / "lg" / "langgraph.json", '{"graphs": {}}')
    monkeypatch.setattr(FrameworksCollector, "_langgraph", boom)
    broken = _run(tmp_path)
    assert broken.status == "ok" and "agent:openai-agents/ok" in _agents(broken)
    assert ("frameworks:config", "lg/langgraph.json", False, "parse-error", 0) in _sources(broken)
    assert FAKE_KEY not in _dump(broken) and "/secret/host" not in _dump(broken)


def test_config_paths_with_nul_or_overlong_names_stay_unknown(tmp_path: Path) -> None:
    """Finding 2: hostile ``config_path``/graph paths never reach the filesystem or the collector reason."""
    _write(
        tmp_path / "adk" / "root_agent.yaml",
        'name: root\nsub_agents:\n  - config_path: "a\\0b.yaml"\n  - config_path: '
        + "x" * 5000
        + FAKE_KEY * 3
        + "\n",
    )
    _write(
        tmp_path / "lg" / "langgraph.json",
        '{"graphs": {"g": "./a\\u0000.py:graph", "h": "./' + "y" * 5000 + '.py:graph"}}',
    )
    result = _run(tmp_path)
    assert result.status == "ok"
    agents = _agents(result)
    assert "unknown:sub_agents" in agents["agent:google-adk/root"].tags
    assert (
        "unknown:graph" in agents["agent:langgraph/g"].tags and agents["agent:langgraph/g"].entrypoint is None
    )
    assert "unknown:graph" in agents["agent:langgraph/h"].tags
    dumped = _dump(result)
    assert FAKE_KEY not in dumped and str(tmp_path) not in dumped and "\\u0000" not in dumped


def test_secret_shaped_tool_names_are_dropped_and_counted(tmp_path: Path) -> None:
    """Finding 3: no tool-name source puts a credential into an id, a name, an edge or a qualifier."""
    _write(
        tmp_path / "m.ts",
        f"import {{ Agent }} from '@mastra/core';\nnew Agent({{ name: 'm', tools: {{ '{FAKE_KEY}': t, ok }} }});\n",
    )
    _write(
        tmp_path / "q.ts",
        "import { query } from '@anthropic-ai/claude-agent-sdk';\n"
        f"query({{ prompt: 'x', options: {{ allowedTools: ['{FAKE_GH}', 'Read'] }} }});\n",
    )
    _write(
        tmp_path / "c.py",
        "from claude_agent_sdk import ClaudeAgentOptions, AgentDefinition\n"
        f'o = ClaudeAgentOptions(tools=["{FAKE_GH}", "Bash"], allowed_tools=["{FAKE_KEY}", "mcp__{FAKE_GH}"],\n'
        f'    agents={{"r": AgentDefinition(description="d", prompt="p", tools=["{FAKE_GH}x", "Read"])}})\n',
    )
    result = _run(tmp_path)
    dumped = _dump(result)
    assert FAKE_KEY not in dumped and FAKE_GH not in dumped
    assert {"ok", "Read", "Bash"} <= {t.name for t in _tools(result).values()}
    reviewer = next(a for a in _agents(result).values() if a.name == "r")
    link = next(e for e in result.edges if e.type is EdgeType.DELEGATES_TO and e.to_ref == reviewer.id)
    assert link.qualifiers["constraints"] == "tools:Read"
    assert result.redactions and result.redactions[0].count >= 5


def test_secret_values_never_reach_tags_or_entrypoints(tmp_path: Path) -> None:
    """Finding 4: every tag, foreign value and entrypoint built from a literal is filtered."""
    _write(
        tmp_path / "a.py",
        "from crewai import Crew\nfrom autogen import ConversableAgent\n"
        "from claude_agent_sdk import ClaudeAgentOptions\n"
        f'c = Crew(agents=[], process="{FAKE_KEY}")\n'
        f'h = ConversableAgent("h", human_input_mode="{FAKE_GH.upper()}")\n'
        f'o = ClaudeAgentOptions(system_prompt={{"type": "preset", "preset": "{FAKE_KEY}"}},\n'
        f'    allowed_tools=["mcp__{FAKE_GH}"], tools={{"type": "preset", "preset": "{FAKE_GH}"}})\n',
    )
    _write(tmp_path / "lg" / "langgraph.json", '{"graphs": {"g": "./g.py:' + FAKE_GH + '"}}')
    result = _run(tmp_path)
    dumped = _dump(result)
    assert FAKE_KEY not in dumped and FAKE_GH not in dumped and FAKE_GH.upper() not in dumped
    agents = _agents(result)
    assert "unknown:human_input_mode" in agents["agent:autogen/h"].tags
    assert agents["agent:langgraph/g"].entrypoint is None
    assert result.redactions and result.redactions[0].count >= 6


def test_typescript_scan_is_bounded_per_file(tmp_path: Path) -> None:
    """Finding 5: many constructor matches in one file cost linear time; the cut is reported."""
    hostile = "import { Agent } from '@mastra/core';\n" + "new Agent({a: new x " * 20000
    _write(tmp_path / "a.ts", hostile)
    lines = (
        "import { Agent } from '@mastra/core';\n"
        + "\n" * 5000
        + "export const z = new Agent({ name: 'z' });\n"
    )
    _write(tmp_path / "b.ts", lines)
    start = time.monotonic()
    result = _run(tmp_path)
    assert time.monotonic() - start < 5.0
    assert any(s[1] == "a.ts" and s[3] == "truncated" for s in _sources(result))
    assert result.coverage[Surface.CODE].status is CoverageStatus.TRUNCATED
    assert _agents(result)["agent:mastra/z"].provenance.locator == "b.ts:5002"


def test_same_named_agents_and_shared_handoffs_scale(tmp_path: Path) -> None:
    """Findings 6 and 14: id claims and by-name links are indexed, not quadratic."""
    _write(tmp_path / "same.py", "from agents import Agent\n" + "Agent(name='x')\n" * 4000)
    many = "[" + ",".join(f"'h{i}'" for i in range(256)) + "]"
    _write(
        tmp_path / "hand.py",
        f"from agents import Agent\nH = {many}\n"
        + "".join(f"a{i} = Agent(name='a{i}', handoffs=H)\n" for i in range(800)),
    )
    for i in range(300):
        _write(
            tmp_path / "ag" / f"m{i:04d}.py",
            "from autogen_agentchat.agents import AssistantAgent\n"
            + "".join(
                f"x{k} = AssistantAgent('n{i}_{k}', c, handoffs=['n{(i + 1) % 300}_{k}', 'zz{k}'])\n"
                for k in range(5)
            ),
        )
    start = time.monotonic()
    result = _run(tmp_path, budget_seconds=60)
    assert time.monotonic() - start < 20.0
    assert result.coverage[Surface.CODE].status is CoverageStatus.QUERIED
    agents = _agents(result)
    assert len([a for a in agents.values() if a.name == "x"]) == 4000
    assert ("agent:autogen/n0_0", "agent:autogen/n1_0") in _edges(result, EdgeType.DELEGATES_TO)


@pytest.mark.parametrize(
    ("parent", "child", "gate"),
    [
        ("bypassPermissions", "default", ApprovalGate.NONE),
        ("acceptEdits", "default", ApprovalGate.REQUIRED),  # Bash is not an edit
        ("auto", "default", ApprovalGate.CONDITIONAL),
        ("plan", "bypassPermissions", ApprovalGate.REQUIRED),
        ("default", "bypassPermissions", ApprovalGate.REQUIRED),  # a sub-agent cannot raise itself to bypass
        ("dontAsk", "bypassPermissions", None),  # falls back to dontAsk: Bash would prompt, so it is denied
        ("default", "auto", ApprovalGate.CONDITIONAL),
        ("default", None, ApprovalGate.REQUIRED),
    ],
)
def test_claude_subagent_permission_mode_follows_parent(
    tmp_path: Path, parent: str, child: str | None, gate: ApprovalGate | None
) -> None:
    """Finding 7: the parent's bypassPermissions/acceptEdits/auto/plan wins over the sub-agent's mode."""
    mode = f', permissionMode="{child}"' if child else ""
    _write(
        tmp_path / "app.py",
        "from claude_agent_sdk import ClaudeAgentOptions, AgentDefinition\n"
        f'opts = ClaudeAgentOptions(permission_mode="{parent}",\n'
        f'    agents={{"careful": AgentDefinition(description="c", prompt="q", tools=["Bash"]{mode})}})\n',
    )
    result = _run(tmp_path)
    tool = _tools(result).get("tool:claude-agent-sdk/careful/tools/Bash")
    assert (tool.approval_gate if tool else None) is gate


def test_imported_agent_definition_is_the_options_subagent(tmp_path: Path) -> None:
    """Finding 8: an AgentDefinition from another module is one sub-agent, under the options, with its mode."""
    _write(tmp_path / "pkg" / "__init__.py", "")
    _write(
        tmp_path / "pkg" / "subs.py",
        "from claude_agent_sdk import AgentDefinition\n"
        'reviewer = AgentDefinition(description="r", prompt="Review.", tools=["Bash"])\n',
    )
    _write(
        tmp_path / "pkg" / "main.py",
        "from claude_agent_sdk import ClaudeAgentOptions\nfrom pkg.subs import reviewer, missing\n"
        'opts = ClaudeAgentOptions(permission_mode="bypassPermissions", agents={"reviewer": reviewer, "m": missing})\n',
    )
    result = _run(tmp_path)
    subs = {a.id: a for a in _agents(result).values() if "kind:subagent" in a.tags}
    assert set(subs) == {"agent:claude-agent-sdk/reviewer", "agent:claude-agent-sdk/m"}
    reviewer = subs["agent:claude-agent-sdk/reviewer"]
    assert (
        reviewer.parent_ref == "agent:claude-agent-sdk/main.opts"
        and "unknown:definition" not in reviewer.tags
    )
    assert "unknown:definition" in subs["agent:claude-agent-sdk/m"].tags
    assert [i.ref for i in reviewer.instructions] == ["instr:claude-agent-sdk/reviewer/prompt"]
    assert _tools(result)["tool:claude-agent-sdk/reviewer/tools/Bash"].approval_gate is ApprovalGate.NONE
    # a second options object sharing the definition gets its own sub-agent under its own (default) mode
    _write(
        tmp_path / "pkg" / "other.py",
        "from claude_agent_sdk import ClaudeAgentOptions\nfrom pkg.subs import reviewer\n"
        'b = ClaudeAgentOptions(agents={"rev": reviewer})\n',
    )
    shared = _run(tmp_path)
    tools = _tools(shared)
    assert tools["tool:claude-agent-sdk/reviewer/tools/Bash"].approval_gate is ApprovalGate.NONE
    assert tools["tool:claude-agent-sdk/rev/tools/Bash"].approval_gate is ApprovalGate.REQUIRED
    assert _agents(shared)["agent:claude-agent-sdk/rev"].parent_ref == "agent:claude-agent-sdk/other.b"


def test_typescript_tool_approval_settings(tmp_path: Path) -> None:
    """Finding 9: Mastra requireApproval and Vercel needsApproval/toolApproval set the tool gate."""
    _write(
        tmp_path / "m.ts",
        "import { Agent } from '@mastra/core/agent';\nimport { createTool } from '@mastra/core/tools';\n"
        "const deleteRecord = createTool({ id: 'delete-record', requireApproval: true, execute: async () => 1 });\n"
        "const readRecord = createTool({ id: 'read-record', execute: async () => 1 });\n"
        "export const sup = new Agent({ name: 'Sup', instructions: 'C.', tools: { deleteRecord, readRecord, imported } });\n",
    )
    _write(
        tmp_path / "v.ts",
        "import { ToolLoopAgent, tool } from 'ai';\n"
        "const deleteFile = tool({ description: 'd', needsApproval: true, execute: async () => 1 });\n"
        "const maybe = tool({ needsApproval: async ({ path }) => path.startsWith('/'), execute: async () => 1 });\n"
        "export const agent = new ToolLoopAgent({ id: 'ops', instructions: 'Ops.',\n"
        "  tools: { deleteFile, maybe, inline: tool({ needsApproval: false }), listFiles },\n"
        "  toolApproval: { listFiles: 'user-approval' } });\n",
    )
    gates = {t.id: t.approval_gate for t in _tools(_run(tmp_path)).values()}
    assert gates["tool:mastra/sup/tools/deleteRecord"] is ApprovalGate.REQUIRED
    assert (
        gates["tool:mastra/sup/tools/readRecord"] is ApprovalGate.NONE
    )  # framework default, definition read
    assert gates["tool:mastra/sup/tools/imported"] is ApprovalGate.UNKNOWN  # definition not in this file
    assert gates["tool:vercel-ai-sdk/ops/tools/deleteFile"] is ApprovalGate.REQUIRED
    assert gates["tool:vercel-ai-sdk/ops/tools/maybe"] is ApprovalGate.CONDITIONAL
    assert gates["tool:vercel-ai-sdk/ops/tools/inline"] is ApprovalGate.NONE
    assert gates["tool:vercel-ai-sdk/ops/tools/listFiles"] is ApprovalGate.REQUIRED


def test_mcp_server_with_non_literal_header_keeps_literal_parts(tmp_path: Path) -> None:
    """Finding 10: an f-string header keeps the server's URL, approval and header names."""
    _write(
        tmp_path / "app.py",
        "import os\nfrom agents import Agent\nfrom agents.mcp import MCPServerStreamableHttp\n"
        'crm = MCPServerStreamableHttp(name="crm",\n'
        '    params={"url": "https://crm.example.com/mcp", "headers": {"Authorization": f"Bearer {os.environ[\'T\']}"}},\n'
        '    require_approval="always")\n'
        'triage = Agent(name="Triage", instructions="Route.", mcp_servers=[crm])\n',
    )
    _write(
        tmp_path / "claude.py",
        "import os\nfrom claude_agent_sdk import ClaudeAgentOptions\n"
        'o = ClaudeAgentOptions(mcp_servers={"gh": {"type": "http", "url": "https://api.example.com/mcp",\n'
        '    "headers": {"Authorization": f"Bearer {os.environ[\'GH\']}"}}})\n',
    )
    result = _run(tmp_path)
    servers = {s.name: s for s in _servers(result).values()}
    crm = servers["crm"]
    assert crm.header_names == ["Authorization"] and "approval:required" in crm.tags
    assert crm.endpoint is not None and "crm.example.com" in str(crm.endpoint.value)
    assert (_agents(result)["agent:openai-agents/triage"].id, crm.id) in _edges(result, EdgeType.DEPENDS_ON)
    assert servers["gh"].header_names == ["Authorization"]
    assert "inline-secret-in-config" not in crm.tags and not result.redactions


def test_dont_ask_keeps_read_only_builtins(tmp_path: Path) -> None:
    """Finding 11: dontAsk denies only tools that would prompt; read-only built-ins still run."""
    _write(
        tmp_path / "app.py",
        "from claude_agent_sdk import ClaudeAgentOptions\n"
        'ro = ClaudeAgentOptions(permission_mode="dontAsk", tools=["Read", "Grep", "Bash", "Edit"], allowed_tools=["Edit"])\n',
    )
    result = _run(tmp_path)
    gates = {t.name: t.approval_gate for t in _tools(result).values()}
    assert gates == {"Read": ApprovalGate.NONE, "Grep": ApprovalGate.NONE, "Edit": ApprovalGate.NONE}
    tags = next(iter(_agents(result).values())).tags
    assert "tool-denied:Bash" in tags and "tool-denied:Read" not in tags


def test_mastra_variable_subagent_links_to_declared_agent(tmp_path: Path) -> None:
    """Finding 12: ``agents: { researcher }`` and ``{ r: researcher }`` link to the agent declared in the file."""
    _write(
        tmp_path / "index.ts",
        "import { Agent } from '@mastra/core/agent';\n"
        "const researcher = new Agent({ id: 'researcher', name: 'Researcher', instructions: 'Find.' });\n"
        "export const writer: Agent = new Agent({ id: 'writer', instructions: 'Write.' });\n"
        "export const sup = new Agent({ id: 'sup', instructions: 'Coord.', agents: { researcher, w: writer, gone } });\n",
    )
    result = _run(tmp_path)
    agents = _agents(result)
    assert set(agents) == {
        "agent:mastra/researcher",
        "agent:mastra/writer",
        "agent:mastra/sup",
        "agent:mastra/gone",
    }
    sup = agents["agent:mastra/sup"]
    assert {(sup.id, "agent:mastra/researcher"), (sup.id, "agent:mastra/writer")} <= _edges(
        result, EdgeType.DELEGATES_TO
    )
    assert agents["agent:mastra/researcher"].parent_ref == sup.id
    assert "unknown:definition" in agents["agent:mastra/gone"].tags


def test_pydantic_ai_v2_and_other_mcp_toolsets(tmp_path: Path) -> None:
    """Finding 13: MCPToolset, load_mcp_toolsets, AG2 MCPToolkit and LlamaIndex MCP helpers are servers."""
    _write(
        tmp_path / "pyd.py",
        "from pydantic_ai import Agent\nfrom pydantic_ai.mcp import MCPToolset, load_mcp_toolsets\n"
        "github = MCPToolset('https://api.githubcopilot.com/mcp/', id='github', headers={'Authorization': 'Bearer ${GH}'})\n"
        "agent = Agent('anthropic:claude-sonnet-4-5', name='repo_helper', toolsets=[github])\n"
        "cfg = Agent('openai:gpt-4o', name='cfg', toolsets=load_mcp_toolsets('mcp.json'))\n"
        "odd = Agent('openai:gpt-4o', name='odd', toolsets=[SomeMCPThing('x')])\n",
    )
    _write(
        tmp_path / "ag2app.py",
        "from ag2 import Agent\nfrom ag2.tools import MCPStdioServerConfig, MCPToolkit\n"
        "fetch = MCPToolkit(MCPStdioServerConfig(command='uvx', args=['mcp-server-fetch']))\n"
        "a = Agent('helper', tools=[fetch])\n",
    )
    _write(
        tmp_path / "llama.py",
        "from llama_index.core.agent.workflow import FunctionAgent\n"
        "from llama_index.tools.mcp import get_tools_from_mcp_url\n"
        "f = FunctionAgent(name='f', tools=get_tools_from_mcp_url('https://mcp.example.org/mcp'))\n",
    )
    result = _run(tmp_path)
    servers = {s.name: s for s in _servers(result).values() if s.server_kind.value == "mcp"}
    assert {"github", "fetch", "mcp.example.org"} <= set(servers)
    assert servers["github"].header_names == ["Authorization"]
    agents = _agents(result)
    assert (agents["agent:pydantic-ai/repo_helper"].id, servers["github"].id) in _edges(
        result, EdgeType.DEPENDS_ON
    )
    assert {"unknown:mcp_servers", "mcp-config-file:mcp.json"} <= set(agents["agent:pydantic-ai/cfg"].tags)
    assert "unknown:mcp_servers" in agents["agent:pydantic-ai/odd"].tags
    assert not any("MCP" in t.name or "Mcp" in t.name for t in _tools(result).values())


def test_linking_and_emission_stop_at_their_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Finding 14: past the emission deadline the result is truncated and self-consistent, never discarded."""
    for i in range(3):
        _write(
            tmp_path / f"m{i}.py", f"from agents import Agent\na{i} = Agent(name='a{i}', handoffs=['a0'])\n"
        )
    monkeypatch.setattr(fw, "EMIT_TIME_SHARE", 0.0)
    result = _run(tmp_path)
    assert result.status == "ok"
    cov = result.coverage[Surface.CODE]
    assert cov.status is CoverageStatus.TRUNCATED
    assert any(s.source == "frameworks:emit-budget" and s.error_class == "truncated" for s in cov.sources)
    ids = {e.id for e in result.entities} | {"agent:root"}
    assert all(
        e.from_ref in ids and e.to_ref in ids for e in result.edges if e.type is not EdgeType.USES_MODEL
    )


def test_agent_ids_do_not_depend_on_other_files(tmp_path: Path) -> None:
    """Finding 15: a colliding name never moves one agent's id onto another agent."""
    _write(
        tmp_path / "z" / "support.py",
        "from agents import Agent\ntriage = Agent(name='triage', instructions='z')\n",
    )
    first = _agents(_run(tmp_path))
    assert set(first) == {"agent:openai-agents/triage"}
    _write(
        tmp_path / "a" / "other.py",
        "from agents import Agent\ntriage = Agent(name='triage', instructions='a')\n",
    )
    _write(
        tmp_path / "b" / "more.py",
        "from agents import Agent\ntriage = Agent(name='triage', instructions='b')\n",
    )
    both = {a.provenance.locator: a.id for a in _agents(_run(tmp_path)).values()}
    (tmp_path / "b" / "more.py").unlink()
    again = {a.provenance.locator: a.id for a in _agents(_run(tmp_path)).values()}
    assert "agent:openai-agents/triage" not in both.values()
    assert both["z/support.py:2"] == again["z/support.py:2"] and both["a/other.py:2"] == again["a/other.py:2"]
    instr = sorted(i for i in _instructions(_run(tmp_path)) if i.startswith("instr:openai-agents/triage"))
    assert len(instr) == 2 and "instr:openai-agents/triage/instructions" not in instr


def test_non_literal_mcp_params_mark_the_agent_unknown_once(tmp_path: Path) -> None:
    """Finding 16: a server without a literal command/URL makes the agent's MCP servers unknown, warned once."""
    _write(
        tmp_path / "a.py",
        "from agents import Agent\nfrom agents.mcp import MCPServerStdio\n"
        "srv = MCPServerStdio(params=load_params())\na = Agent(name='A', mcp_servers=[srv])\n",
    )
    result = _run(tmp_path)
    agent = _agents(result)["agent:openai-agents/a"]
    assert {"unknown:mcp_servers", "mcp-server:non-literal"} <= set(agent.tags)
    assert agent.foreign["frameworks:unknown:mcp_servers"] == "a.py:4"
    assert len([w for w in result.warnings if "no literal command or URL" in w]) == 1


def test_python_framework_file_not_understood_is_reported(tmp_path: Path) -> None:
    """Finding 17: an imported agent constructor with nothing recognised is not reported as fully understood."""
    _write(tmp_path / "b.py", "from agents import Agent\nbase = Agent[Ctx](name='base', instructions='x')\n")
    _write(tmp_path / "c.py", "import agents\nmk = getattr(agents, 'Agent')\nx = mk(name='x')\n")
    _write(tmp_path / "d.py", "from agents import Agent\nmake = Agent\nx = make(name='x')\n")
    _write(tmp_path / "tools.py", "from agents import function_tool, RunContextWrapper\n")
    result = _run(tmp_path)
    assert "agent:openai-agents/base" in _agents(result)  # a generic alias is the class
    sources = _sources(result)
    assert ("frameworks:python", "c.py", False, "not-understood", 0) in sources
    assert ("frameworks:python", "d.py", False, "not-understood", 0) in sources
    assert ("frameworks:python", "tools.py", True, None, 0) in sources
    assert any(w.startswith("c.py: imports agents") for w in result.warnings)


def test_symlinked_framework_files_are_coverage_gaps(tmp_path: Path) -> None:
    """Finding 18: symlinks the walk does not follow are reported, not silently complete."""
    (tmp_path / "shared").mkdir()
    (tmp_path / "shared" / "real_agent.txt").write_text(
        "from agents import Agent\na = Agent(name='linked')\n"
    )
    (tmp_path / "agent.py").symlink_to(tmp_path / "shared" / "real_agent.txt")
    (tmp_path / "pkg").symlink_to(tmp_path / "shared")
    (tmp_path / "notes.md").symlink_to(tmp_path / "shared" / "real_agent.txt")
    result = _run(tmp_path)
    gaps = {s[1] for s in _sources(result) if s[3] == "symlink-not-followed"}
    assert gaps == {"agent.py", "pkg"}
    assert result.coverage[Surface.CODE].status is CoverageStatus.PARTIAL
    assert any("symlinked" in w for w in result.warnings)


def test_crewai_mcps_server_objects_and_tool_fragments(tmp_path: Path) -> None:
    """Finding 19: an MCP server object in ``mcps`` belongs to the agent; ``#tool`` names a tool."""
    _write(
        tmp_path / "crew.py",
        "from crewai import Agent\nfrom crewai.mcp import MCPServerStdio\n"
        "researcher = Agent(role='R', goal='G', backstory='B',\n"
        "    mcps=['https://mcp.example.com/mcp#search_docs', MCPServerStdio(command='uvx', args=['mcp-server-fetch'])])\n",
    )
    result = _run(tmp_path)
    agent = _agents(result)["agent:crewai/r"]
    assert "unknown:mcps" not in agent.tags
    deps = {t for f, t in _edges(result, EdgeType.DEPENDS_ON) if f == agent.id}
    assert any("fetch" in t for t in deps) and any("mcp.example.com" in t for t in deps)
    assert ("agent:root", next(t for t in deps if "fetch" in t)) not in _edges(result, EdgeType.DEPENDS_ON)
    assert any(t.name == "search_docs" for t in _tools(result).values())


def test_non_literal_permission_mode_is_not_written_as_a_flag(tmp_path: Path) -> None:
    """Finding 20: an unknown mode makes gates unknown and is never a ``defaultMode`` flag value."""
    _write(
        tmp_path / "app.py",
        "from claude_agent_sdk import ClaudeAgentOptions\n"
        'dyn = ClaudeAgentOptions(permission_mode=MODE, tools=["Bash"], mcp_servers={"f": {"command": "npx"}})\n',
    )
    _write(
        tmp_path / "q.ts",
        "import { query } from '@anthropic-ai/claude-agent-sdk';\n"
        "query({ prompt: 'x', options: { permissionMode: mode, allowedTools: ['Edit'] } });\n",
    )
    result = _run(tmp_path)
    for server in _servers(result).values():
        assert "claude-code.defaultMode.agent-sdk" not in server.client_trust_flags
    assert _tools(result)["tool:claude-agent-sdk/app.dyn/tools/Bash"].approval_gate is ApprovalGate.UNKNOWN
    assert "<non-literal>" not in _dump(result)


def test_oversized_framework_yaml_is_reported(tmp_path: Path) -> None:
    """Finding 21: a framework YAML too large to parse is a coverage gap whatever its name."""
    big = "agent_class: LlmAgent\nname: helper\ninstruction: |\n" + "  x\n" * 400000
    _write(tmp_path / "agents" / "standalone.yaml", big)
    _write(tmp_path / "ci" / "big.yaml", "steps:\n" + "  - run: echo\n" * 100000)
    result = _run(tmp_path)
    assert ("frameworks:config", "agents/standalone.yaml", False, "too-large", 0) in _sources(result)
    assert not any(s[1] == "ci/big.yaml" for s in _sources(result))
    assert result.coverage[Surface.CODE].status is CoverageStatus.PARTIAL


def test_config_lists_longer_than_max_items_are_not_silently_cut(tmp_path: Path) -> None:
    """Finding 22: lists past MAX_ITEMS in config files are a truncated source or an unknown field."""
    _write(tmp_path / "OAI_CONFIG_LIST", json.dumps([{"model": f"gpt-4o-{i:03d}"} for i in range(300)]))
    tools = "".join(f"  - t{i}\n" for i in range(300))
    _write(tmp_path / "adk" / "root_agent.yaml", "name: root\ntools:\n" + tools)
    _write(
        tmp_path / "crew" / "agents.yaml",
        "r:\n  role: R\n  goal: G\n  tools:\n" + tools.replace("  -", "    -"),
    )
    result = _run(tmp_path)
    assert ("frameworks:config", "OAI_CONFIG_LIST", False, "truncated", 44) in _sources(result)
    agents = _agents(result)
    assert "unknown:tools" in agents["agent:google-adk/root"].tags
    assert "unknown:tools" in agents["agent:crewai/r"].tags
    assert len([w for w in result.warnings if "beyond 256" in w]) == 3


def test_budget_expiry_sets_truncated_status_and_stops_all_readers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 23: an expired budget is TRUNCATED coverage and no reader runs after it."""
    _write(tmp_path / "m.py", "from agents import Agent\na = Agent(name='a')\n")
    _write(tmp_path / "plugins" / "P" / "F" / "skprompt.txt", "hello {{$input}}")
    _write(tmp_path / "crew" / "config" / "agents.yaml", "researcher:\n  role: r\n  goal: g\n")
    _write(tmp_path / "crew" / "config" / "tasks.yaml", "t1:\n  description: d\n  agent: researcher\n")
    monkeypatch.setattr(fw, "CODE_TIME_SHARE", 0.0)
    result = _run(tmp_path)
    assert not _agents(result)
    cov = result.coverage[Surface.CODE]
    assert cov.status is CoverageStatus.TRUNCATED and cov.truncated_at == 0
    assert ("frameworks:code-budget", "plugins/P/F/skprompt.txt", False, "truncated", 1) in _sources(result)


# --------------------------------------------------------------------------------------------- review regressions


def _alias_bomb(levels: int) -> list[str]:
    lines = ['a0: &a0 ["x","x","x","x","x","x","x","x","x","x"]']
    lines += [f"a{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 10) + "]" for i in range(1, levels + 1)]
    return lines


def test_yaml_alias_bomb_values_are_never_str_expanded(tmp_path: Path) -> None:
    _write(
        tmp_path / "p.yaml",
        "\n".join([*_alias_bomb(7), "template: hello", "execution_settings: {}", "template_format: *a7"]),
    )
    _write(
        tmp_path / "s" / "agent.yaml",
        "\n".join([*_alias_bomb(7), "name: x", "instructions: hi", "type: *a7", "_agent: 1"]),
    )
    _write(tmp_path / "c" / "agents.yaml", "r:\n  role: r\n  goal: g\n  backstory: b\n")
    _write(tmp_path / "c" / "tasks.yaml", "\n".join([*_alias_bomb(7), "t:\n  description: d\n  agent: *a7"]))
    start = time.monotonic()
    result = _run(tmp_path, budget_seconds=5)
    assert time.monotonic() - start < 3
    assert result.status.value == "ok" and "agent:semantic-kernel/p" in _agents(result)


@pytest.mark.parametrize(
    "tools", ['["a b"]', '["a:b"]', '["\\u00e9"]', '{"url": "http://h"}', '["web/search"]']
)
def test_hostile_tool_names_get_valid_ids(tmp_path: Path, tools: str) -> None:
    _write(tmp_path / "a.py", f"from agents import Agent\na = Agent(name='a', tools={tools})\n")
    result = _run(tmp_path)
    assert result.status.value == "ok" and "agent:openai-agents/a" in _agents(result)
    assert all(t.id.startswith("tool:openai-agents/a/tools/") for t in _tools(result).values())


@pytest.mark.parametrize(
    "bad",
    [
        'from agents import Agent\nx = Agent(name="x", instructions="hello \\ud800")\n',
        "from claude_agent_sdk import ClaudeAgentOptions\n"
        'o = ClaudeAgentOptions(mcp_servers={"s": {"type": "http", "url": "http://[::1"}})\n',
        'from crewai import Agent\na = Agent(role="r", goal="g", backstory="b", mcps=["http://h:99999/"])\n',
    ],
)
def test_hostile_literals_never_abort_the_collector(tmp_path: Path, bad: str) -> None:
    _write(tmp_path / "good.py", 'from agents import Agent\ngood = Agent(name="good", instructions="hi")\n')
    _write(tmp_path / "bad.py", bad)
    _write(tmp_path / "root_agent.yaml", 'agent_class: LlmAgent\nname: root\ninstruction: "hi \\ud800"\n')
    result = _run(tmp_path)
    assert result.status.value == "ok" and "agent:openai-agents/good" in _agents(result)
    for entity in result.entities:
        entity.model_dump_json()
    assert any("invalid-unicode:lone-surrogate" in i.tags for i in _instructions(result).values())


def test_mcp_command_with_inline_key_is_redacted(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "from agents import Agent, MCPServerStdio\n"
        f"s = MCPServerStdio(params={{'command': 'run --token={FAKE_KEY}', 'args': []}})\n"
        "a = Agent(name='a', mcp_servers=[s])\n",
    )
    result = _run(tmp_path)
    assert FAKE_KEY not in _dump(result) and "sk-ant" not in _dump(result)
    assert sum(r.count for r in result.redactions) >= 1
    assert any(s.command == "run" for s in _servers(result).values())


def test_secret_mapping_key_never_reaches_a_locator(tmp_path: Path) -> None:
    _write(tmp_path / "p.yaml", f"template: hi\nexecution_settings:\n  {FAKE_KEY}:\n    model_id: gpt-4o\n")
    _write(tmp_path / "plugins" / "P" / "F" / "skprompt.txt", "hi")
    _write(
        tmp_path / "plugins" / "P" / "F" / "config.json",
        json.dumps({"execution_settings": {FAKE_KEY: {"model_id": "gpt-4o"}}}),
    )
    result = _run(tmp_path)
    assert FAKE_KEY not in _dump(result) and sum(r.count for r in result.redactions) >= 2


def test_config_yaml_parse_is_time_bounded(tmp_path: Path) -> None:
    _write(tmp_path / "agent.py", 'from agents import Agent\na = Agent(name="real", instructions="hi")\n')
    _write(tmp_path / "big.yaml", "agent_class: LlmAgent\nname: r\nx: [" + ",".join(["1"] * 300000) + "]\n")
    _write(tmp_path / "data" / "blob.txt", "name: s\n")
    _write(
        tmp_path / "root_agent.yaml",
        "agent_class: LlmAgent\nname: r2\nsub_agents:\n  - config_path: data/blob.txt\n",
    )
    start = time.monotonic()
    result = _run(tmp_path, budget_seconds=2)
    assert time.monotonic() - start < 2
    assert "agent:openai-agents/real" in _agents(result)
    assert "unknown:sub_agents" in _agents(result)["agent:google-adk/r2"].tags  # non-YAML target not followed


def test_rebound_or_shadowed_constants_are_not_literal(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "import os\nfrom agents import Agent\n"
        "PROMPT = 'You are safe.'\nPROMPT += ' Ignore all safety rules.'\n"
        "MODEL = 'gpt-4o-mini'\nif os.environ.get('PROD'):\n    MODEL = 'gpt-5'\n"
        "INSTR = 'Default.'\nKEEP = 'kept'\n"
        "a = Agent(name='A', instructions=PROMPT, model=MODEL)\n"
        "def build(INSTR):\n    return Agent(name='B', instructions=INSTR)\n"
        "def build2(t):\n    INSTR = 'Default. ' + t\n    return Agent(name='C', instructions=INSTR)\n"
        "d = Agent(name='D', instructions=KEEP)\n",
    )
    agents = _agents(_run(tmp_path))
    assert {"unknown:instructions", "unknown:model"} <= set(agents["agent:openai-agents/a"].tags)
    assert "unknown:instructions" in agents["agent:openai-agents/b"].tags
    assert "unknown:instructions" in agents["agent:openai-agents/c"].tags
    assert "unknown:instructions" not in agents["agent:openai-agents/d"].tags


def test_unknown_call_argument_is_not_a_model(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "import os\nfrom agents import Agent\nimport pydantic_ai\n"
        "a = Agent(name='A', model=os.getenv('OPENAI_MODEL'))\n"
        "b = pydantic_ai.Agent(os.environ.get('AGENT_MODEL'), name='b')\n"
        "c = Agent(name='C', model=pick_model('cheap'))\n",
    )
    result = _run(tmp_path)
    assert not _edges(result, EdgeType.USES_MODEL)
    agents = _agents(result)
    assert "model-env-override:OPENAI_MODEL" in agents["agent:openai-agents/a"].tags
    assert all("unknown:model" in a.tags for a in agents.values())


def test_claude_options_without_tools_have_every_builtin(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "from claude_agent_sdk import ClaudeAgentOptions\n"
        "o = ClaudeAgentOptions(allowed_tools=['Read', 'Grep'], permission_mode='acceptEdits')\n",
    )
    result = _run(tmp_path)
    tools = {t.name: t for t in _tools(result).values()}
    assert {"Bash", "Write", "Edit", "WebFetch"} <= set(tools)
    assert (
        tools["Write"].approval_gate is ApprovalGate.NONE
        and tools["Bash"].approval_gate is ApprovalGate.REQUIRED
    )
    assert "tools:default-preset" in _agents(result)["agent:claude-agent-sdk/a.o"].tags


def test_claude_scoped_allowed_rule_is_conditional(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "from claude_agent_sdk import ClaudeAgentOptions\n"
        "o = ClaudeAgentOptions(allowed_tools=['Bash(npm test:*)', 'Read'], permission_mode='acceptEdits')\n",
    )
    tools = {t.name: t for t in _tools(_run(tmp_path)).values()}
    assert tools["Bash"].approval_gate is ApprovalGate.CONDITIONAL


def test_claude_disallowed_mcp_tools_and_servers_win(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "from claude_agent_sdk import ClaudeAgentOptions\n"
        "S = {'type': 'http', 'url': 'https://api.githubcopilot.com/mcp/'}\n"
        "o1 = ClaudeAgentOptions(mcp_servers={'github': S}, allowed_tools=['mcp__github__delete_repo'],"
        " disallowed_tools=['mcp__github__delete_repo'])\n",
    )
    _write(
        tmp_path / "b.py",
        "from claude_agent_sdk import ClaudeAgentOptions\n"
        "o2 = ClaudeAgentOptions(mcp_servers={'gh': {'type': 'http', 'url': 'https://x.example/mcp'}},"
        " allowed_tools=['mcp__gh__get_issue'], disallowed_tools=['mcp__gh'])\n",
    )
    result = _run(tmp_path)
    names = {t.name for t in _tools(result).values()}
    assert "delete_repo" not in names and "get_issue" not in names
    o2 = _agents(result)["agent:claude-agent-sdk/b.o2"]
    assert "mcp-server-denied:gh" in o2.tags
    assert not any(
        s == o2.id and "gh" in d for s, d in _edges(result, EdgeType.DEPENDS_ON) if "tools" not in d
    )


def test_policy_callbacks_are_controls_not_gates(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "from google.adk.agents import LlmAgent\nfrom strands import Agent\n"
        "def run_shell(c): ...\ndef log_call(*a): print(a)\n"
        "adk = LlmAgent(name='adk', tools=[run_shell], before_tool_callback=log_call)\n"
        "st = Agent(name='st', tools=[run_shell], interventions=[log_call])\n",
    )
    result = _run(tmp_path)
    assert all(t.approval_gate is ApprovalGate.UNKNOWN for t in _tools(result).values())
    assert "control:before_tool_callback" in _agents(result)["agent:google-adk/adk"].tags


def test_code_executor_agent_reports_host_execution(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "from autogen_agentchat.agents import CodeExecutorAgent\n"
        "from autogen_ext.code_executors.local import LocalCommandLineCodeExecutor\n"
        "runner = CodeExecutorAgent('runner', code_executor=LocalCommandLineCodeExecutor(work_dir='out'))\n",
    )
    tags = set(_agents(_run(tmp_path))["agent:autogen/runner"].tags)
    assert {"capability:execute", "code-execution:host", "code-execution:approval:none"} <= tags


def test_scan_merges_hosted_models_from_two_collectors(tmp_path: Path) -> None:
    from symbiote.scan import scan

    _write(tmp_path / "config" / "agents.yaml", "w:\n  role: r\n  goal: g\n  backstory: b\n  llm: gpt-4o\n")
    _write(
        tmp_path / "chat.py",
        "import openai\nc = openai.OpenAI()\nc.chat.completions.create(model='gpt-4o')\n",
    )
    out = scan(tmp_path, deterministic=True, home=tmp_path / "_nohome")
    assert not any("duplicate entity" in w for w in out.warnings)


def test_provider_prefix_gets_one_model_id_in_both_positions(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "import anthropic\nfrom pydantic_ai import Agent\n"
        "w = Agent('anthropic:claude-sonnet-4-5', name='writer')\n"
        "e = Agent(model='anthropic:claude-sonnet-4-5', name='editor')\n",
    )
    ctx = CollectContext(root=tmp_path, platform="linux", agent_id="agent:root")
    fw_result, mh_result = run_collectors(ctx, [FrameworksCollector(), ModelsHostedCollector()])
    targets = {d for _, d in _edges(fw_result, EdgeType.USES_MODEL)}
    assert targets == {"model:hosted/anthropic/anthropic-claude-sonnet-4-5"}
    assert set(_models(mh_result)) <= targets


def test_framework_mcp_server_has_mcp_config_auth_and_credentials(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "from claude_agent_sdk import ClaudeAgentOptions\n"
        "o = ClaudeAgentOptions(mcp_servers={'gitlab': {'type': 'http', 'url': 'https://gitlab.example.com/mcp',"
        " 'headers': {'PRIVATE-TOKEN': '${GITLAB_TOKEN}'}}})\n",
    )
    result = _run(tmp_path)
    server = _servers(result)["server:claude-agent-sdk-gitlab"]
    assert server.authentication.value is not None and server.authentication.value.mode.value == "api-key"
    assert _edges(result, EdgeType.HOLDS_CREDENTIAL)


def test_emission_fits_the_budget_with_many_agents(tmp_path: Path) -> None:
    for i in range(60):
        _write(
            tmp_path / f"m{i}" / "a.ts",
            "import { Agent } from '@mastra/core/agent';\n"
            + "new Agent({name:'h',model:'openai/gpt-4o'});\n" * 256,
        )
    start = time.monotonic()
    result = _run(tmp_path, budget_seconds=6)
    assert time.monotonic() - start < 6
    assert result.status.value == "ok" and len(_agents(result)) >= 1000
    assert result.coverage[Surface.CODE].status is CoverageStatus.TRUNCATED


def test_ts_file_with_unrecognised_constructor_is_not_understood(tmp_path: Path) -> None:
    _write(
        tmp_path / "a" / "agent.ts",
        "import { Agent } from '@mastra/core/agent';\nexport const r = Reflect.construct(Agent, [cfg]);\n",
    )
    result = _run(tmp_path)
    assert result.coverage[Surface.CODE].status is CoverageStatus.PARTIAL


def test_suffixed_ids_are_never_taken_by_a_literal_name(tmp_path: Path) -> None:
    _write(tmp_path / "a" / "x.py", "from agents import Agent\na = Agent(name='H', instructions='one')\n")
    _write(tmp_path / "b" / "x.py", "from agents import Agent\na = Agent(name='H', instructions='two')\n")
    before = {a.id for a in _agents(_run(tmp_path)).values()}
    taken = sorted(before)[0].split("/", 1)[1]
    _write(
        tmp_path / "0" / "x.py", f"from agents import Agent\nz = Agent(name='{taken}', instructions='evil')\n"
    )
    after = _agents(_run(tmp_path))
    assert before <= set(after) and all(after[i].name == "H" for i in before)


def test_sk_dangerous_content_per_variable_and_plugin_config(tmp_path: Path) -> None:
    _write(
        tmp_path / "s.yaml",
        "template: '{{$input}}'\ninput_variables:\n  - name: input\n    allow_dangerously_set_content: true\n",
    )
    _write(tmp_path / "plugins" / "P" / "F" / "skprompt.txt", "{{$input}}")
    _write(
        tmp_path / "plugins" / "P" / "F" / "config.json", json.dumps({"allow_dangerously_set_content": True})
    )
    agents = _agents(_run(tmp_path))
    assert "allow-dangerously-set-content:var:input" in agents["agent:semantic-kernel/s"].tags
    assert "allow-dangerously-set-content" in agents["agent:semantic-kernel/p.f"].tags


def test_api_key_placeholder_is_not_an_inline_key(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.py",
        "from autogen import AssistantAgent\n"
        "a = AssistantAgent('a', llm_config={'config_list': [{'model': 'gpt-4o-mini', 'api_key': '${OPENAI_API_KEY}'}]})\n",
    )
    result = _run(tmp_path)
    tags = set(_agents(result)["agent:autogen/a"].tags)
    assert "inline-api-key" not in tags and "api-key:placeholder" in tags and not result.redactions


def test_excluded_build_dir_with_agents_is_a_coverage_gap(tmp_path: Path) -> None:
    _write(tmp_path / "app" / "build" / "agent.py", "from agents import Agent\nr = Agent(name='Releaser')\n")
    result = _run(tmp_path)
    assert result.coverage[Surface.CODE].status is CoverageStatus.PARTIAL


def test_truncated_at_is_kept_from_a_later_truncation(tmp_path: Path) -> None:
    from symbiote.collect.frameworks import _Run

    ctx = CollectContext(root=tmp_path, platform="linux")
    run = _Run(ctx=ctx, result=FrameworksCollector().new_result())
    run.truncate("a.py", "frameworks:python", 3)
    run.truncate("z.py", "frameworks:code-budget", 3, 7)
    assert run.result.coverage[Surface.CODE].truncated_at == 7
