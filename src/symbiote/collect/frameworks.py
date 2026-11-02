"""``frameworks`` collector: agents declared with agent frameworks (``spec/collectors.md``).

Agent frameworks declare an agent's prompt, model, tools, sub-agents and approval settings in code or in a
framework config file. This collector reads those declarations **statically** and turns each framework agent
into a sub-agent of the scanned agent:

* Python is parsed with :func:`ast.parse` (never imported or executed). A conservative visitor resolves each
  call through the file's imports and recognises the constructors in :data:`PY_CONSTRUCTORS` (OpenAI Agents
  SDK, Claude Agent SDK, LangChain/LangGraph, CrewAI, AutoGen AgentChat and classic/AG2, Google ADK, Semantic
  Kernel, Pydantic AI, LlamaIndex, Strands, Microsoft Agent Framework). Only literal arguments are recorded:
  strings, lists, dicts, ``+`` concatenation, ``textwrap.dedent`` and module-level constants. Anything else
  is ``unknown`` and the agent says where (tag ``unknown:<field>``, ``foreign["frameworks:unknown:<field>"]``
  = ``path:line``).
* Config files are parsed with the safe parsers: LangGraph ``langgraph.json`` (``graphs``, ``dependencies``,
  ``env`` names), CrewAI ``agents.yaml``/``tasks.yaml``, Google ADK agent YAML (``root_agent.yaml``, files
  with ``agent_class`` or reached through ``sub_agents[].config_path``), Semantic Kernel prompt YAML,
  declarative agent YAML and plugin directories (``<Function>/skprompt.txt`` + ``config.json``), and the
  AutoGen ``OAI_CONFIG_LIST``.
* TypeScript/JavaScript (Mastra, Vercel AI SDK, LangChain.js, Claude Agent SDK) is read with a small, linear
  object-literal scanner and only inside a recognised constructor call; other properties stay unknown.

Mapping: each agent becomes an ``Agent(role=sub-agent)`` with ``framework`` and ``parent_ref``; literal prompts
become ``Instruction`` entities (SHA-256 of the literal's UTF-8 bytes; the text is never stored) linked with
``loadsInstruction``; ``handoffs``/``sub_agents``/agent-as-tool/crew delegation become ``delegatesTo``; models
become ``usesModel`` edges to ``model:hosted/<provider>/<ref>`` ids built exactly like ``models-hosted``; named
tools become declared ``ToolDefinition`` records on a per-agent in-process ``ToolServer`` with an
``approval_gate`` derived from the framework's approval settings (``needs_approval``, ``require_confirmation``,
``requires_approval``, ``approval_mode``, LangChain human-in-the-loop middleware, Claude ``permission_mode`` and
``allowed_tools``, AG2 ``human_input_mode``); MCP servers declared in code become ``ToolServer(kind=mcp)``.

Hosted ``Model`` entities belong to ``models-hosted`` whenever that collector sees the same string (a literal
under one of its keyword names in code, or a JS ``model:`` literal it attributes); this collector then emits
only the edge. For every other reference (framework config files, ``llm=``, ``ai_model_id=``, positional model
arguments, ``provider:model`` strings models-hosted cannot attribute) it emits the ``Model`` itself, built the
same way, so the edge never dangles.

Bounded and hostile-input safe: file count, bytes and a deadline from ``ctx.budget_seconds``; truncation and
parse failures are coverage sources with an error class; secret-shaped values are never recorded (a
``Redaction`` is counted instead); every regular expression is linear.
"""

from __future__ import annotations

import ast
import bisect
import inspect
import itertools
import re
import textwrap
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Any, Final

import yaml

from symbiote.collect._common import (
    _BoundedSafeLoader,
    classify_env_value,
    locator,
    parse_jsonc,
    read_bounded,
    url_facts,
)
from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult, WalkReport
from symbiote.collect.instructions import TOOL_CAPABILITIES
from symbiote.collect.launchers import parse_launch
from symbiote.collect.mcp_config import (
    ClientSpec,
    ConfigLocation,
    ServerDecl,
    emit_server_credentials,
    parse_client_config,
    server_args_digest,
    server_authentication,
)
from symbiote.collect.models_hosted import (
    _ENV_MODEL_KEY,
    _IMPORT_HINTS,
    _MODEL_KWARGS,
    _MODEL_NAME_RE,
    _MODULE_HINTS,
)
from symbiote.confined import open_scoped_file
from symbiote.digest import (
    bytes_digest,
    hidden_code_points,
    line_endings,
    prompt_digest,
    server_identity_digest,
    triage_digest,
)
from symbiote.model.common import Claim, DigestResult, Provenance, looks_like_secret
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    Agent,
    Authentication,
    FrameworkRef,
    Instruction,
    InstructionRef,
    Model,
    PackageRef,
    PromptTemplate,
    Redaction,
    ToolDefinition,
    ToolServer,
)
from symbiote.model.enums import (
    AgentRole,
    ApprovalGate,
    AuthMode,
    CapabilityClass,
    ClaimMethod,
    CollectorMode,
    CoverageStatus,
    DigestStatus,
    EdgeScope,
    EdgeType,
    InstructionKind,
    ModelKind,
    PromptRole,
    RedactionClass,
    Surface,
    TemplateEngine,
    TemplateRiskClass,
    ToolServerKind,
    ToolSource,
    Transport,
    TrustZone,
)
from symbiote.model.ids import make_id, tool_id
from symbiote.models_identity.hosted import (
    MAX_MODEL_REF,
    PROVIDER_PREFIXES,
    HostedRef,
    classify_model_ref,
    hosted_identity,
    provider_for_endpoint,
    split_provider_prefix,
)

__all__ = [
    "FRAMEWORK_TITLES",
    "HOSTED_OWNED_KEYWORDS",
    "MAX_CODE_FILES",
    "MAX_SOURCE_BYTES",
    "NON_LITERAL",
    "PY_CONSTRUCTORS",
    "FrameworksCollector",
    "PyCtor",
    "claude_tool_gate",
    "literal",
    "split_provider_prefix",
    "ts_object",
]

# --------------------------------------------------------------------------------------------- limits

#: Source and config files larger than this are not parsed (coverage source ``too-large``).
MAX_SOURCE_BYTES: Final = 1024 * 1024
#: At most this many code files are parsed per scan; the rest are reported as truncated coverage.
MAX_CODE_FILES: Final = 4000
#: Total bytes parsed per scan and the share of the collector's time budget spent on code.
MAX_CODE_BYTES: Final = 64 * 1024 * 1024
CODE_TIME_SHARE: Final = 0.7
#: One file may use at most this share of the code budget (a hostile file cannot starve the others).
FILE_TIME_SHARE: Final = 0.25
#: Linking and emission stop at this share of the collector's budget (the rest is reported as truncated).
EMIT_TIME_SHARE: Final = 0.9
#: List items considered per argument (tools, handoffs, sub-agents); the rest make the field ``unknown``.
MAX_ITEMS: Final = 256
#: Literal evaluation depth (nested containers, constant indirections).
MAX_LITERAL_DEPTH: Final = 12
#: Longest concatenated literal string evaluated (larger prompts stay unknown).
MAX_LITERAL_CHARS: Final = 512 * 1024
#: Work bound of one literal evaluation: AST nodes visited and characters built (constants included).
MAX_LITERAL_NODES: Final = 10_000
MAX_LITERAL_WORK_CHARS: Final = 2 * MAX_LITERAL_CHARS
#: Names and descriptions longer than this are not recorded.
MAX_NAME_CHARS: Final = 200
MAX_DESCRIPTION_CHARS: Final = 1024
#: ADK ``config_path`` chains followed per root file.
MAX_CONFIG_HOPS: Final = 64
#: Longest ``config_path`` / graph path followed (longer values, or values with NUL bytes, stay unknown).
MAX_CONFIG_PATH_CHARS: Final = 512
#: TypeScript object scanner bounds (characters scanned per call, nesting).
MAX_TS_WINDOW: Final = 64 * 1024
MAX_TS_DEPTH: Final = 8
#: Constructor matches read per TypeScript file (the rest are reported as truncated).
MAX_TS_MATCHES: Final = 256
#: Agent declarations read per scan: past this, reading stops with a truncated source, so linking and emission
#: (which cost time per declaration) always fit in the rest of the budget.
MAX_DECLS: Final = 10_000
#: Linking stops at this share of the collector's budget (emission continues until :data:`EMIT_TIME_SHARE`).
LINK_TIME_SHARE: Final = 0.8
#: YAML nodes composed between two deadline checks while one config file is parsed.
_YAML_CHECK_EVERY: Final = 64

_SOURCE: Final = "frameworks"
_VERSION_UNKNOWN: Final = "unversioned"

FRAMEWORK_TITLES: Final[Mapping[str, str]] = {
    "openai-agents": "OpenAI Agents SDK",
    "claude-agent-sdk": "Claude Agent SDK",
    "langgraph": "LangGraph",
    "langchain": "LangChain",
    "crewai": "CrewAI",
    "autogen": "AutoGen",
    "ag2": "AG2",
    "google-adk": "Google Agent Development Kit",
    "semantic-kernel": "Semantic Kernel",
    "pydantic-ai": "Pydantic AI",
    "llama-index": "LlamaIndex",
    "strands-agents": "Strands Agents",
    "agent-framework": "Microsoft Agent Framework",
    "mastra": "Mastra",
    "vercel-ai-sdk": "Vercel AI SDK",
}

#: Keyword (and dict key) names whose string literals ``models-hosted`` records from code; a model reference
#: in one of these positions is that collector's ``Model`` (kept equal to its table by a unit test).
HOSTED_OWNED_KEYWORDS: Final = frozenset(_MODEL_KWARGS)

# --------------------------------------------------------------------------------------------- Python constructors


@dataclass(frozen=True, slots=True)
class PyCtor:
    """A recognised constructor: ``<package>.….<name>(…)`` and what each argument means.

    ``kind``: ``agent`` (an agent definition), ``options`` (Claude ``ClaudeAgentOptions``), ``subagent``
    (Claude ``AgentDefinition``), ``task``/``crew`` (CrewAI), ``workflow`` (LlamaIndex ``AgentWorkflow``) or
    ``mcp`` (an MCP server or client). ``fields`` maps keyword -> role; ``positional`` gives the roles of the
    leading positional arguments.
    """

    framework: str
    package: str
    names: frozenset[str]
    kind: str
    fields: Mapping[str, str]
    positional: tuple[str, ...] = ()
    api: str | None = None


def _ctor(
    framework: str,
    package: str,
    names: Iterable[str],
    kind: str,
    fields: Mapping[str, str],
    *,
    positional: tuple[str, ...] = (),
    api: str | None = None,
) -> PyCtor:
    return PyCtor(framework, package, frozenset(names), kind, dict(fields), positional, api)


_MCP_FIELDS: Final[Mapping[str, str]] = {
    "params": "mcp-entry",
    "tool_config": "mcp-entry",
    "connection_params": "mcp-entry",
    "server_params": "mcp-entry",
    "transport_callable": "mcp-entry",
    "command": "mcp-command",
    "args": "mcp-args",
    "env": "mcp-env",
    "url": "mcp-url",
    "server_url": "mcp-url",
    "headers": "mcp-headers",
    "name": "mcp-name",
    "server_label": "mcp-name",
    "id": "mcp-name",
    "require_approval": "approval",
    "require_confirmation": "approval",
    "approval_mode": "approval",
    "requireToolApproval": "approval",
    "tool_filter": "tool-filter",
    "allowed_tools": "tool-filter",
}

PY_CONSTRUCTORS: Final[tuple[PyCtor, ...]] = (
    # OpenAI Agents SDK (openai-agents)
    _ctor("openai-agents", "agents", ("Agent", "SandboxAgent"), "agent", {
        "name": "name", "instructions": "prompt:instructions", "handoff_description": "description",
        "model": "model:primary", "tools": "tools", "handoffs": "handoffs", "mcp_servers": "mcp-list",
        "input_guardrails": "control:guardrails", "output_guardrails": "control:guardrails",
        "prompt": "unknown-prompt:prompt",
    }),
    _ctor("openai-agents", "agents", ("MCPServerStdio", "MCPServerSse", "MCPServerStreamableHttp", "HostedMCPTool"), "mcp", _MCP_FIELDS),
    # Claude Agent SDK (claude-agent-sdk)
    _ctor("claude-agent-sdk", "claude_agent_sdk", ("ClaudeAgentOptions",), "options", {
        "system_prompt": "claude-system-prompt", "model": "model:primary", "fallback_model": "model:fallback",
        "tools": "base-tools", "allowed_tools": "allowed-tools", "disallowed_tools": "disallowed-tools",
        "mcp_servers": "mcp-map", "permission_mode": "permission-mode", "agents": "claude-agents",
        "can_use_tool": "approval-callback", "permission_prompt_tool_name": "approval-callback",
        "hooks": "control:hooks", "sandbox": "control:sandbox",
    }),
    _ctor("claude-agent-sdk", "claude_agent_sdk", ("AgentDefinition",), "subagent", {
        "description": "description", "prompt": "prompt:prompt", "tools": "base-tools",
        "disallowedTools": "disallowed-tools", "model": "model:primary", "mcpServers": "mcp-names",
        "permissionMode": "permission-mode",
    }),
    # LangChain v1 / LangGraph prebuilt
    _ctor("langchain", "langchain", ("create_agent",), "agent", {
        "model": "model:primary", "tools": "tools", "system_prompt": "prompt:system_prompt",
        "middleware": "middleware", "name": "name", "interrupt_before": "interrupt", "interrupt_after": "interrupt",
    }, positional=("model:primary", "tools")),
    _ctor("langgraph", "langgraph", ("create_react_agent",), "agent", {
        "model": "model:primary", "tools": "tools", "prompt": "prompt:prompt", "name": "name",
        "interrupt_before": "interrupt", "interrupt_after": "interrupt",
    }, positional=("model:primary", "tools")),
    _ctor("langchain", "langchain_mcp_adapters", ("MultiServerMCPClient",), "mcp-multi", {"connections": "mcp-map"}, positional=("mcp-map",)),
    # CrewAI
    _ctor("crewai", "crewai", ("Agent",), "agent", {
        "role": "prompt:role", "goal": "prompt:goal", "backstory": "prompt:backstory", "llm": "model:primary",
        "function_calling_llm": "model:tool-calling", "tools": "tools", "allow_delegation": "allow-delegation",
        "allow_code_execution": "code-execution", "config": "crewai-config", "mcps": "mcp-refs",
    }),
    _ctor("crewai", "crewai", ("Task",), "task", {
        "description": "prompt:description", "expected_output": "prompt:expected_output", "agent": "task-agent",
        "tools": "tools", "human_input": "human-input", "name": "name",
    }),
    _ctor("crewai", "crewai", ("Crew",), "crew", {
        "agents": "members", "process": "process", "manager_llm": "model:manager",
        "planning_llm": "model:planning", "manager_agent": "manager", "name": "name",
    }),
    _ctor("crewai", "crewai", ("MCPServerStdio", "MCPServerHTTP", "MCPServerSSE"), "mcp", _MCP_FIELDS),
    # AutoGen AgentChat (0.4+)
    _ctor("autogen", "autogen_agentchat", ("AssistantAgent",), "agent", {
        "name": "name", "model_client": "model:primary", "system_message": "prompt:system_message",
        "tools": "tools", "workbench": "mcp-list", "handoffs": "handoffs", "description": "description",
    }, positional=("name", "model:primary"), api="agentchat"),
    _ctor("autogen", "autogen_agentchat", ("CodeExecutorAgent",), "agent", {
        "name": "name", "approval_func": "approval-callback", "description": "description",
        "model_client": "model:primary", "system_message": "prompt:system_message",
        "code_executor": "code-execution",
    }, positional=("name", "code-execution"), api="agentchat"),
    _ctor("autogen", "autogen_ext", ("McpWorkbench", "StdioServerParams", "SseServerParams", "StreamableHttpServerParams"), "mcp", _MCP_FIELDS),
    # AutoGen classic API (``autogen`` namespace, maintained as AG2) and AG2 v1
    _ctor("autogen", "autogen", ("ConversableAgent", "AssistantAgent", "UserProxyAgent"), "agent", {
        "name": "name", "system_message": "prompt:system_message", "llm_config": "llm-config",
        "human_input_mode": "human-input-mode", "code_execution_config": "code-execution", "description": "description",
    }, positional=("name",), api="classic"),
    _ctor("ag2", "ag2", ("Agent",), "agent", {"name": "name", "prompt": "prompt:prompt", "config": "model:primary", "tools": "tools"}, positional=("name",)),
    _ctor("ag2", "ag2", ("MCPToolkit", "MCPServerConfig", "MCPStdioServerConfig"), "mcp", _MCP_FIELDS),
    # Google ADK
    _ctor("google-adk", "google.adk", ("LlmAgent", "Agent"), "agent", {
        "name": "name", "model": "model:primary", "instruction": "prompt:instruction",
        "global_instruction": "prompt:global_instruction", "static_instruction": "prompt:static_instruction",
        "description": "description", "tools": "tools", "sub_agents": "sub-agents",
        "disallow_transfer_to_parent": "transfer-parent", "disallow_transfer_to_peers": "transfer-peers",
        "code_executor": "code-execution", "before_tool_callback": "policy-callback:before_tool_callback",
    }),
    _ctor("google-adk", "google.adk", ("SequentialAgent", "ParallelAgent", "LoopAgent"), "agent", {
        "name": "name", "description": "description", "sub_agents": "sub-agents",
    }),
    _ctor("google-adk", "google.adk", ("McpToolset", "MCPToolset"), "mcp", _MCP_FIELDS),
    # Semantic Kernel
    _ctor("semantic-kernel", "semantic_kernel", ("ChatCompletionAgent",), "agent", {
        "name": "name", "description": "description", "instructions": "prompt:instructions",
        "service": "model:primary", "plugins": "tools", "function_choice_behavior": "function-choice",
    }),
    _ctor("semantic-kernel", "semantic_kernel", ("MCPStdioPlugin", "MCPStreamableHttpPlugin", "MCPSsePlugin"), "mcp", _MCP_FIELDS),
    # Pydantic AI
    _ctor("pydantic-ai", "pydantic_ai", ("Agent",), "agent", {
        "model": "model:primary", "instructions": "prompt:instructions", "system_prompt": "prompt:system_prompt",
        "name": "name", "description": "description", "tools": "tools", "toolsets": "tools",
    }, positional=("model:primary",)),
    _ctor("pydantic-ai", "pydantic_ai", ("MCPServerStdio", "MCPServerStreamableHTTP", "MCPServerSSE", "MCPServerHTTP", "MCPToolset"), "mcp", _MCP_FIELDS),
    # LlamaIndex
    _ctor("llama-index", "llama_index", ("FunctionAgent", "ReActAgent", "CodeActAgent"), "agent", {
        "name": "name", "description": "description", "system_prompt": "prompt:system_prompt", "llm": "model:primary",
        "tools": "tools", "can_handoff_to": "handoffs",
    }),
    _ctor("llama-index", "llama_index", ("AgentWorkflow",), "workflow", {"agents": "members", "root_agent": "root-agent"}),
    _ctor("llama-index", "llama_index", ("BasicMCPClient", "get_tools_from_mcp_url", "aget_tools_from_mcp_url"), "mcp", _MCP_FIELDS),
    # Strands Agents
    _ctor("strands-agents", "strands", ("Agent",), "agent", {
        "model": "model:primary", "system_prompt": "prompt:system_prompt", "tools": "tools", "name": "name",
        "description": "description", "interventions": "policy-callback:interventions",
    }),
    _ctor("strands-agents", "strands", ("MCPClient",), "mcp", _MCP_FIELDS),
    # Microsoft Agent Framework
    _ctor("agent-framework", "agent_framework", ("ChatAgent", "Agent"), "agent", {
        "chat_client": "model:primary", "client": "model:primary", "instructions": "prompt:instructions",
        "name": "name", "description": "description", "tools": "tools",
    }, positional=("model:primary",)),
    _ctor("agent-framework", "agent_framework", ("MCPStdioTool", "MCPStreamableHTTPTool", "MCPWebsocketTool"), "mcp", _MCP_FIELDS),
)  # fmt: skip

#: Model client/wrapper classes whose provider is fixed (the string inside names a model of that provider).
_WRAPPER_PROVIDERS: Final[Mapping[str, str]] = {
    "ChatAnthropic": "anthropic",
    "Anthropic": "anthropic",
    "AnthropicModel": "anthropic",
    "AnthropicConfig": "anthropic",
    "AnthropicChatCompletionClient": "anthropic",
    "ChatOpenAI": "openai",
    "OpenAI": "openai",
    "OpenAIModel": "openai",
    "OpenAIChatModel": "openai",
    "OpenAIResponsesModel": "openai",
    "OpenAIChatCompletionsModel": "openai",
    "OpenAIChatCompletionClient": "openai",
    "OpenAIChatCompletion": "openai",
    "OpenAIChatClient": "openai",
    "OpenAIResponsesClient": "openai",
    "OpenAIConfig": "openai",
    "AzureChatOpenAI": "azure-openai",
    "AzureOpenAIChatCompletionClient": "azure-openai",
    "AzureChatCompletion": "azure-openai",
    "AzureOpenAIChatClient": "azure-openai",
    "BedrockModel": "aws-bedrock",
    "ChatBedrock": "aws-bedrock",
    "ChatBedrockConverse": "aws-bedrock",
    "Gemini": "google-gemini",
    "GeminiModel": "google-gemini",
    "GoogleModel": "google-gemini",
    "GeminiConfig": "google-gemini",
    "ChatGoogleGenerativeAI": "google-gemini",
    "ChatVertexAI": "google-vertex",
    "VertexAIConfig": "google-vertex",
    "MistralModel": "mistral",
    "ChatMistralAI": "mistral",
    "OllamaModel": "ollama",
    "ChatOllama": "ollama",
    "Ollama": "ollama",
}
#: Model wrappers without a fixed provider whose first positional argument is the model (``LiteLlm("…")``).
_PROVIDERLESS_WRAPPERS: Final = frozenset(
    {"LiteLlm", "LitellmModel", "LiteLLMModel", "LiteLLM", "init_chat_model"}
)
#: Keywords that name the model inside a wrapper call, in precedence order.
_WRAPPER_MODEL_KEYS: Final = (
    "model",
    "model_id",
    "model_name",
    "ai_model_id",
    "deployment_name",
    "azure_deployment",
)
#: ``provider:model`` prefixes (Pydantic AI, LangChain ``init_chat_model``) -> provider ids (one table, shared
#: with ``models-hosted`` through :func:`classify_model_ref`).
_COLON_PROVIDERS: Final = PROVIDER_PREFIXES
#: Weak provider hints when a framework's default model client is fixed (used only if the shape is ambiguous).
_FRAMEWORK_HINTS: Final[Mapping[str, tuple[str, ...]]] = {
    "openai-agents": ("openai",),
    "claude-agent-sdk": ("anthropic",),
    "google-adk": ("google-gemini",),
    "strands-agents": ("aws-bedrock",),
}
#: Claude Code's tier aliases are resolved in this client context (``providers.yaml`` context rules).
_MODEL_CONTEXT: Final[Mapping[str, str]] = {"claude-agent-sdk": "claude-code"}

#: Capability hints for well-known tool names (built-in, hosted and toolkit tools).
_TOOL_CAPS: Final[Mapping[str, tuple[CapabilityClass, ...]]] = {
    **{name: (cap,) for name, cap in TOOL_CAPABILITIES.items()},
    "Read": (CapabilityClass.READ, CapabilityClass.FILESYSTEM),
    "Glob": (CapabilityClass.READ, CapabilityClass.FILESYSTEM),
    "Grep": (CapabilityClass.READ, CapabilityClass.FILESYSTEM),
    "Write": (CapabilityClass.WRITE, CapabilityClass.FILESYSTEM),
    "Edit": (CapabilityClass.WRITE, CapabilityClass.FILESYSTEM),
    "Task": (CapabilityClass.DELEGATE,),
    "Agent": (CapabilityClass.DELEGATE,),
    "CodeInterpreterTool": (CapabilityClass.EXECUTE,),
    "ShellTool": (CapabilityClass.EXECUTE,),
    "LocalShellTool": (CapabilityClass.EXECUTE,),
    "ComputerTool": (CapabilityClass.EXECUTE,),
    "ApplyPatchTool": (CapabilityClass.WRITE, CapabilityClass.FILESYSTEM),
    "WebSearchTool": (CapabilityClass.NETWORK_EGRESS,),
    "FileSearchTool": (CapabilityClass.READ,),
    "google_search": (CapabilityClass.NETWORK_EGRESS,),
    "url_context": (CapabilityClass.NETWORK_EGRESS,),
    "built_in_code_execution": (CapabilityClass.EXECUTE,),
    "BuiltInCodeExecutor": (CapabilityClass.EXECUTE,),
    "shell": (CapabilityClass.EXECUTE,),
    "python_repl": (CapabilityClass.EXECUTE,),
    "file_write": (CapabilityClass.WRITE, CapabilityClass.FILESYSTEM),
    "editor": (CapabilityClass.WRITE, CapabilityClass.FILESYSTEM),
    "file_read": (CapabilityClass.READ, CapabilityClass.FILESYSTEM),
    "http_request": (CapabilityClass.NETWORK_EGRESS,),
    "WebFetchTool": (CapabilityClass.NETWORK_EGRESS,),
    "SerperDevTool": (CapabilityClass.NETWORK_EGRESS,),
    "ScrapeWebsiteTool": (CapabilityClass.NETWORK_EGRESS,),
    "FileWriterTool": (CapabilityClass.WRITE, CapabilityClass.FILESYSTEM),
    "CodeInterpreter": (CapabilityClass.EXECUTE,),
}
#: Tools that run at the model provider rather than in the agent's process.
#: Frameworks whose tools run without asking unless an approval setting says otherwise (research 2026-11-01).
#: Functions that load MCP servers from a configuration file at run time.
_MCP_LOADERS: Final = frozenset({"load_mcp_toolsets", "load_mcp_servers"})
#: Stands in for a header/env value that is not a literal (classified as a reference, never as a secret).
_NON_LITERAL_VALUE: Final = "${NON_LITERAL}"
_NO_APPROVAL_BY_DEFAULT: Final = frozenset(
    {"openai-agents", "google-adk", "pydantic-ai", "crewai", "autogen", "langchain", "langgraph", "llama-index",
     "mastra", "vercel-ai-sdk"}
)  # fmt: skip
_HOSTED_TOOLS: Final = frozenset(
    {"WebSearchTool", "FileSearchTool", "CodeInterpreterTool", "ImageGenerationTool", "HostedMCPTool",
     "google_search", "url_context", "built_in_code_execution"}
)  # fmt: skip
#: Claude Code built-in tools that never prompt (read-only): they run without approval in ``default`` mode.
_CLAUDE_NO_PROMPT: Final = frozenset(
    {"Read", "Glob", "Grep", "LS", "NotebookRead", "TodoWrite", "Task", "Agent"}
)
_CLAUDE_EDIT_TOOLS: Final = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
#: Claude Code's built-in tools: the base set of an options agent without ``tools=`` (or with the ``claude_code``
#: preset). ``allowed_tools`` only pre-approves; it never narrows this set.
_CLAUDE_DEFAULT_TOOLS: Final = (
    "Bash", "Edit", "Glob", "Grep", "NotebookEdit", "Read", "Task", "TodoWrite", "WebFetch", "WebSearch", "Write",
)  # fmt: skip
_CLAUDE_MODES: Final = frozenset({"default", "acceptEdits", "plan", "bypassPermissions", "dontAsk", "auto"})
#: Internal marker for a ``permission_mode`` that is set but not literal (gates become ``UNKNOWN``).
_MODE_UNKNOWN: Final = "?"

#: Keywords on tool wrappers/decorators that set an approval gate.
_APPROVAL_KEYS: Final = (
    "needs_approval",
    "requires_approval",
    "require_confirmation",
    "approval_mode",
    "require_approval",
)
#: Calls that are pure functions of a literal string (evaluated locally, never by running scanned code).
_STRING_FUNCS: Final[Mapping[str, Any]] = {"dedent": textwrap.dedent, "cleandoc": inspect.cleandoc}
_STRING_METHODS: Final = frozenset({"strip", "lstrip", "rstrip"})

# --------------------------------------------------------------------------------------------- linear patterns

_CODE_SUFFIXES: Final = frozenset({".py"})
_TS_SUFFIXES: Final = frozenset({".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"})
_YAML_SUFFIXES: Final = frozenset({".yaml", ".yml"})
_PY_HINTS: Final = (
    b"agents", b"claude_agent_sdk", b"langchain", b"langgraph", b"crewai", b"autogen", b"ag2", b"adk",
    b"semantic_kernel", b"pydantic_ai", b"llama_index", b"strands", b"agent_framework",
)  # fmt: skip
#: ``import … from '<pkg>'`` / ``require('<pkg>')`` for the TypeScript packages recognised here.
_TS_IMPORT: Final = re.compile(
    r"""(?:\bfrom|\brequire\s*\(|\bimport)\s*['"](@mastra/core(?:/[\w./-]{0,80})?|ai|@anthropic-ai/claude-agent-sdk|"""
    r"""langchain(?:/[\w./-]{0,80})?|@langchain/langgraph(?:/[\w./-]{0,80})?)['"]"""
)
_TS_PACKAGE_FRAMEWORK: Final[tuple[tuple[str, str], ...]] = (
    ("@mastra/core", "mastra"),
    ("@anthropic-ai/claude-agent-sdk", "claude-agent-sdk"),
    ("@langchain/langgraph", "langgraph"),
    ("langchain", "langchain"),
    ("ai", "vercel-ai-sdk"),
)
#: Recognised TS constructor calls whose first argument is an object literal.
_TS_CALLS: Final[Mapping[str, re.Pattern[str]]] = {
    "mastra": re.compile(r"\bnew\s+Agent\s*\(\s*\{"),
    "vercel-ai-sdk": re.compile(
        r"(?:\bnew\s+(?:ToolLoopAgent|Experimental_Agent)|\bgenerateText|\bstreamText)\s*\(\s*\{"
    ),
    "langchain": re.compile(r"\bcreateAgent\s*\(\s*\{"),
    "langgraph": re.compile(r"\bcreateReactAgent\s*\(\s*\{"),
    "claude-agent-sdk": re.compile(r"\bquery\s*\(\s*\{"),
}
#: The constructor names each TS framework is recognised by (a file that names one but has no recognised call
#: is ``not-understood``; a file that only imports helpers from the package is not an agent file).
_TS_CTOR_NAMES: Final[Mapping[str, re.Pattern[str]]] = {
    "mastra": re.compile(r"\bAgent\b"),
    "vercel-ai-sdk": re.compile(r"\b(?:ToolLoopAgent|Experimental_Agent|generateText|streamText)\b"),
    "langchain": re.compile(r"\bcreateAgent\b"),
    "langgraph": re.compile(r"\bcreateReactAgent\b"),
    "claude-agent-sdk": re.compile(r"\bquery\b"),
}
_TS_IDENT: Final = re.compile(r"[A-Za-z_$][\w$]{0,200}")
_TS_PROVIDER_FACTORIES: Final[Mapping[str, str]] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google": "google-gemini",
    "vertex": "google-vertex",
    "bedrock": "aws-bedrock",
    "azure": "azure-openai",
    "mistral": "mistral",
    "xai": "xai",
    "cohere": "cohere",
    "deepseek": "deepseek",
    "ollama": "ollama",
    "openrouter": "openrouter",
}
#: ``models-hosted``'s JS literal rule (``model: "…"``) — such strings are that collector's ``Model``.
_TS_HOSTED_KEYS: Final = frozenset({"model", "modelId", "modelName"})
_SK_SKPROMPT: Final = "skprompt.txt"
_CREW_FILES: Final = frozenset({"agents.yaml", "agents.yml"})
_CREW_TASK_FILES: Final = frozenset({"tasks.yaml", "tasks.yml"})
_ADK_ROOT: Final = frozenset({"root_agent.yaml", "root_agent.yml"})
_OAI_CONFIG: Final = frozenset({"OAI_CONFIG_LIST", "OAI_CONFIG_LIST.json"})
_SK_TEMPLATE_ENGINES: Final[Mapping[str, TemplateEngine]] = {
    "semantic-kernel": TemplateEngine.OTHER,
    "handlebars": TemplateEngine.HANDLEBARS,
    "jinja2": TemplateEngine.JINJA2,
}

# --------------------------------------------------------------------------------------------- literals


class _NonLiteral:
    """Sentinel for a value that is not a compile-time literal."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<non-literal>"


NON_LITERAL: Final = _NonLiteral()


@dataclass(slots=True)
class _Work:
    """What one literal evaluation may still spend: AST nodes visited and characters built."""

    nodes: int = MAX_LITERAL_NODES
    chars: int = MAX_LITERAL_WORK_CHARS
    #: a depth limit cut the evaluation short, so its result depends on where it started (not memoised)
    limited: bool = False

    def spend(self, nodes: int = 1, chars: int = 0) -> bool:
        self.nodes -= nodes
        self.chars -= chars
        return self.nodes >= 0 and self.chars >= 0

    def spent(self) -> tuple[int, int]:
        return MAX_LITERAL_NODES - self.nodes, MAX_LITERAL_WORK_CHARS - self.chars


class _Consts(dict[str, ast.expr]):
    """A file's module-level constants plus the memoised literal value (and its cost) of each one."""

    __slots__ = ("memo", "shadowed")

    def __init__(self, items: Mapping[str, ast.expr] | None = None, shadowed: set[int] | None = None) -> None:
        super().__init__(items or {})
        self.memo: dict[str, tuple[Any, int, int]] = {}
        #: ids of ``Name`` loads inside a function whose parameter or local has the constant's name
        self.shadowed: set[int] = shadowed or set()

    def target(self, node: ast.AST) -> ast.expr | None:
        """The module-level value ``node`` (a ``Name``) refers to, when it is a constant at that position."""
        if not isinstance(node, ast.Name) or id(node) in self.shadowed:
            return None
        return self.get(node.id)


def literal(node: ast.AST | None, consts: Mapping[str, ast.expr] | None = None, depth: int = 0) -> Any:
    """The value of ``node`` when it is a literal (``NON_LITERAL`` otherwise); never evaluates scanned code.

    Accepted: constants, lists/tuples/sets/dicts of literals, ``+`` of literal strings, ``textwrap.dedent`` /
    ``inspect.cleandoc`` / ``.strip()`` applied to a literal string, and names bound once at module level to a
    literal (``consts``). f-strings, calls, comprehensions and everything else are not literals.

    The work is bounded: one call visits at most :data:`MAX_LITERAL_NODES` nodes and builds at most
    :data:`MAX_LITERAL_WORK_CHARS` characters, counting what each constant it refers to costs (a constant is
    evaluated once per file and its cost charged at every use), so constants that refer to each other cannot
    grow the work exponentially. Past the bound the value is ``NON_LITERAL``.
    """
    return _literal(node, consts, depth, _Work())


def _literal(node: ast.AST | None, consts: Mapping[str, ast.expr] | None, depth: int, work: _Work) -> Any:
    if node is None:
        return NON_LITERAL
    if depth > MAX_LITERAL_DEPTH:
        work.limited = True
        return NON_LITERAL
    if not work.spend():
        return NON_LITERAL
    if isinstance(node, ast.Constant):
        value = node.value
        return value if isinstance(value, str | int | float | bool) or value is None else NON_LITERAL
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        if len(node.elts) > MAX_ITEMS:
            return NON_LITERAL
        items: list[Any] = []
        for element in node.elts:
            item = _literal(element, consts, depth + 1, work)
            if item is NON_LITERAL:
                return NON_LITERAL
            items.append(item)
        return items
    if isinstance(node, ast.Dict):
        if len(node.keys) > MAX_ITEMS:
            return NON_LITERAL
        out: dict[str, Any] = {}
        for key_node, value_node in zip(node.keys, node.values, strict=True):
            k = _literal(key_node, consts, depth + 1, work) if key_node is not None else NON_LITERAL
            if not isinstance(k, str):
                return NON_LITERAL
            v = _literal(value_node, consts, depth + 1, work)
            if v is NON_LITERAL:
                return NON_LITERAL
            out[k] = v
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal(node.left, consts, depth + 1, work)
        if not isinstance(left, str):
            return NON_LITERAL
        right = _literal(node.right, consts, depth + 1, work)
        if (
            isinstance(right, str)
            and len(left) + len(right) <= MAX_LITERAL_CHARS
            and work.spend(0, len(left) + len(right))
        ):
            return left + right
        return NON_LITERAL
    if isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords:
        func = node.func
        fname = (
            func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else None
        )
        if isinstance(fname, str) and fname in _STRING_FUNCS:
            arg = _literal(node.args[0], consts, depth + 1, work)
            if isinstance(arg, str) and work.spend(0, len(arg)):
                return _STRING_FUNCS[fname](arg)
        return NON_LITERAL
    if (
        isinstance(node, ast.Call)
        and not node.args
        and not node.keywords
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _STRING_METHODS
    ):
        base = _literal(node.func.value, consts, depth + 1, work)
        if isinstance(base, str) and work.spend(0, len(base)):
            return getattr(base, node.func.attr)()
        return NON_LITERAL
    if isinstance(node, ast.Name) and consts is not None and node.id in consts:
        if isinstance(consts, _Consts) and id(node) in consts.shadowed:
            return NON_LITERAL  # a parameter or local of the enclosing function, not the module constant
        memo = consts.memo if isinstance(consts, _Consts) else None
        if memo is not None and node.id in memo:
            value, nodes, chars = memo[node.id]
            return value if work.spend(nodes, chars) else NON_LITERAL
        sub = _Work()  # a fresh budget, so the value of a constant does not depend on where it is used
        value = _literal(consts[node.id], consts, depth + 1, sub)
        nodes, chars = sub.spent()
        if sub.limited:
            work.limited = True
        elif memo is not None:
            memo[node.id] = (value, nodes, chars)
        return value if work.spend(nodes, chars) else NON_LITERAL
    return NON_LITERAL


def _short(value: object, limit: int = MAX_NAME_CHARS) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > limit or _surrogates(text) or _secretish(text) or hidden_code_points(text):
        return None
    return text


def _surrogates(text: str) -> bool:
    """True when ``text`` holds lone surrogates (``"\\ud800"`` from ``ast`` or YAML): not encodable as UTF-8."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


def _text_bytes(text: str) -> bytes:
    """UTF-8 bytes of a prompt; lone surrogates are kept (``surrogatepass``) so the digest still covers them."""
    return text.encode("utf-8", "surrogatepass")


_TOOL_ID_PART: Final = re.compile(r"[A-Za-z0-9._~@+-]{1,200}")


def _tool_part(name: str) -> str:
    """The tool-name part of a tool id: the name itself when it is id-safe, else a slug plus a digest of the name
    (``"web search"`` -> ``web-search-1a2b3c``), so two names never share an id; the name itself stays in
    ``ToolDefinition.name``."""
    if _TOOL_ID_PART.fullmatch(name):
        return name
    return make_id("x", name, collision_seed=name).split(":", 1)[1]


def _command_token(command: str | None) -> str | None:
    """What a server record keeps of a stdio command: its executable only (never a whole command line, which can
    carry an inline key), and nothing when that is an absolute path or credential-shaped."""
    if not command:
        return None
    token = command.split(None, 1)[0] if command.split() else ""
    if not token or token.startswith(("/", "\\")) or _secretish(token) or "=" in token:
        return None
    return _short(token)


def _url_display(url: str) -> str | None:
    """The credential-free display form of ``url`` (``None`` when malformed)."""
    try:
        return url_facts(url).display
    except ValueError:
        return None


def _url_host(url: str) -> str | None:
    """The host of ``url`` (``None`` when the URL is malformed: unbalanced IPv6 bracket, port out of range)."""
    try:
        return url_facts(url).host
    except ValueError:
        return None


_SECRET_SPLIT: Final = re.compile(r"__|[^A-Za-z0-9_-]")


def _safe_names(run: _Run, decl: _Decl | None, values: Iterable[object]) -> list[str]:
    """Tool names and permission rules that may be recorded: secret-shaped ones are dropped and counted."""
    out: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        name = _short(value)
        if name is not None and not _secretish(name):
            out.append(name)
        elif _secretish(value):
            run.redact(decl)
    return out


def _secretish(value: object) -> bool:
    """A credential-shaped string, also when upper-cased or embedded after ``__``/``_`` (``mcp__ghp_…``)."""
    if not isinstance(value, str):
        return False
    if looks_like_secret(value) or looks_like_secret(value.lower()):
        return True
    return any(
        looks_like_secret(part) or looks_like_secret(part.lower())
        for part in _SECRET_SPLIT.split(value)
        if part
    )


# --------------------------------------------------------------------------------------------- declarations


@dataclass(slots=True)
class _Prompt:
    label: str
    text: str
    locator: str
    kind: InstructionKind = InstructionKind.SYSTEM_PROMPT
    template: str | None = None


@dataclass(slots=True)
class _ModelRef:
    value: str
    role: str
    locator: str
    #: ``models-hosted`` sees this exact string (it owns the ``Model``); this collector emits only the edge
    hosted_owned: bool
    provider: str | None = None
    endpoint: str | None = None
    hints: tuple[str, ...] = ()
    context: str | None = None
    js: bool = False


@dataclass(slots=True)
class _Tool:
    name: str
    locator: str
    gate: ApprovalGate | None = None
    gate_source: str | None = None
    capabilities: set[CapabilityClass] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)


@dataclass(slots=True)
class _Ref:
    """A reference to another agent: resolved key, a Python name (local or imported) or an agent name."""

    locator: str
    mode: str
    key: str | None = None
    var: str | None = None
    qualname: str | None = None
    agent_name: str | None = None
    constraints: str | None = None
    path: str | None = None


@dataclass(slots=True)
class _Mcp:
    key: str
    framework: str
    name: str
    entry: dict[str, Any]
    locator: str
    display: str
    gate: ApprovalGate | None = None
    gate_source: str | None = None
    tools: list[str] = field(default_factory=list)
    flags: dict[str, str] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)
    in_process: bool = False


@dataclass(slots=True)
class _Decl:
    """One framework agent as declared (values already reduced to safe forms)."""

    framework: str
    name: str
    display: str
    locator: str
    key: str
    description: str | None = None
    prompts: list[_Prompt] = field(default_factory=list)
    templates: list[tuple[str, str, TemplateEngine, str, bytes | None]] = field(default_factory=list)
    models: list[_ModelRef] = field(default_factory=list)
    tools: list[_Tool] = field(default_factory=list)
    delegates: list[_Ref] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    unknown: dict[str, str] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)
    parent: str | None = None
    entrypoint: str | None = None
    permission_mode: str | None = None
    #: ``permission_mode`` is set but not a literal mode
    mode_unknown: bool = False
    allowed: list[str] | None = None
    disallowed: list[str] = field(default_factory=list)
    base_tools: list[str] | None = None
    gate: ApprovalGate | None = None
    gate_source: str | None = None
    tool_gates: dict[str, ApprovalGate] = field(default_factory=dict)
    crew_scope: str | None = None
    allow_delegation: bool = False
    config_key: str | None = None
    redacted: int = 0
    order: tuple[str, int, int] = ("", 0, 0)

    def mark_unknown(self, name: str, where: str) -> None:
        self.unknown.setdefault(name, where)


@dataclass(slots=True)
class _Run:
    """Per-scan state shared by every reader."""

    ctx: CollectContext
    result: CollectionResult
    decls: dict[str, _Decl] = field(default_factory=dict)
    servers: dict[str, _Mcp] = field(default_factory=dict)
    root_servers: list[str] = field(default_factory=list)
    root_models: list[_ModelRef] = field(default_factory=list)
    #: (module, variable) -> agent key, for references across Python files
    module_vars: dict[tuple[str, str], str] = field(default_factory=dict)
    #: (module, function) -> tool facts for decorated tool functions, for tools imported from other files
    module_tools: dict[tuple[str, str], _Tool] = field(default_factory=dict)
    #: (display, variable) -> agent key (LangGraph graph targets)
    file_vars: dict[tuple[str, str], str] = field(default_factory=dict)
    pending_tools: list[tuple[str, str, str, str]] = field(default_factory=list)
    redacted: int = 0
    redacted_ids: set[str] = field(default_factory=set)
    deadline: float = 0.0
    #: seconds one file may spend (a share of the code budget)
    file_seconds: float = 0.0
    #: emission stops here
    emit_deadline: float = 0.0
    #: linking stops here (the agents read are still emitted; unresolved delegation becomes ``unknown``)
    link_deadline: float = 0.0
    #: config bytes parsed (ADK ``config_path`` targets count against :data:`MAX_CODE_BYTES`)
    config_bytes: int = 0
    #: ADK agent YAML already parsed in the first pass, by display path (never parsed twice)
    adk_parsed: dict[str, Any] = field(default_factory=dict)
    #: decl keys merged into another declaration -> that declaration's key
    aliases: dict[str, str] = field(default_factory=dict)
    #: declarations merged away (still readable for later references to the same definition)
    retired: dict[str, _Decl] = field(default_factory=dict)
    #: (Claude options sub-agent key, qualified name of an imported ``AgentDefinition``)
    pending_defs: list[tuple[str, str]] = field(default_factory=list)
    #: MCP server constructor calls already found unusable (warned once)
    failed_servers: set[str] = field(default_factory=set)
    truncated: bool = False
    failures: set[tuple[str, str, str]] = field(default_factory=set)
    #: keys of declarations whose agent id collides with another's (their ids carry a key-derived suffix)
    colliding: set[str] = field(default_factory=set)
    #: variable -> [(module, agent key)], built once from ``module_vars`` for cross-file lookups
    vars_by_name: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    #: linking/emission ran out of time (reported once)
    emit_stopped: bool = False
    #: :data:`MAX_DECLS` was reached: no further file is read
    capped: bool = False
    #: linking ran out of time (reported once)
    link_stopped: bool = False
    #: an entity failed to emit (its partial output was removed; references to it are pruned)
    emit_failed: bool = False

    def add(self, decl: _Decl) -> _Decl:
        self.decls[decl.key] = decl
        return decl

    def canon(self, key: str) -> str:
        """The live declaration ``key`` now refers to (following merges)."""
        for _ in range(64):
            nxt = self.aliases.get(key)
            if nxt is None:
                return key
            key = nxt
        return key

    def late(self, where: str, remaining: int) -> bool:
        """True once linking/emission is past its deadline (recorded as a truncated source the first time)."""
        if self.emit_stopped:
            return True
        if time.monotonic() <= self.emit_deadline:
            return False
        self.emit_stopped = True
        self.truncate(where, "frameworks:emit-budget", remaining)
        return True

    def link_late(self, where: str, remaining: int) -> bool:
        """True once linking is past its deadline (a ``frameworks:link-budget`` truncation, recorded once). Agents
        are still emitted: references not resolved by then stay ``unknown``."""
        if self.link_stopped:
            return True
        if time.monotonic() <= self.link_deadline:
            return False
        self.link_stopped = True
        self.truncate(where, "frameworks:link-budget", remaining)
        return True

    def truncate(self, display: str, source: str, remaining: int, at: int | None = None) -> None:
        """Record a budget truncation honestly: a ``truncated`` source, a warning and ``TRUNCATED`` coverage.

        ``truncated_at`` is the first position known: a later truncation that carries one fills it in when an
        earlier (per-file) truncation did not, and a position already set (by the walk) is never replaced.
        """
        self.result.add_source(
            Surface.CODE, source, locator=display, ok=False, error_class="truncated", items=remaining
        )
        self.result.warnings.append(
            f"framework scan stopped at {display}: {remaining} item(s) not read (budget)"
        )
        coverage = self.result.coverage.get(Surface.CODE)
        current = coverage.truncated_at if coverage is not None else None
        if not self.truncated or (current is None and at is not None):
            self.truncated = True
            self.result.set_status(
                Surface.CODE, CoverageStatus.TRUNCATED, truncated_at=current if current is not None else at
            )

    def full(self) -> bool:
        """True once :data:`MAX_DECLS` agent declarations have been read (then reading stops for good)."""
        if not self.capped and len(self.decls) >= MAX_DECLS:
            self.capped = True
        return self.capped

    def redact(self, decl: _Decl | None = None, count: int = 1) -> None:
        self.redacted += count
        if decl is not None:
            decl.redacted += count

    def fail(self, display: str, error_class: str, source: str = _SOURCE, detail: str | None = None) -> None:
        if (display, error_class, source) in self.failures:
            return  # one file reached two ways (e.g. a too-large ADK file that is also a sub-agent) is one fact
        self.failures.add((display, error_class, source))
        self.result.add_source(Surface.CODE, source, locator=display, ok=False, error_class=error_class)
        self.result.warnings.append(f"{display}: {error_class}" + (f" ({detail})" if detail else ""))


# --------------------------------------------------------------------------------------------- ids


@dataclass(slots=True)
class _Ids:
    """Collision-free entity ids whose suffixes do not depend on claim order.

    A declaration whose agent id would collide with another's gets ``-<digest6>`` derived from its own key
    (file, line and column, or config locator) on every id it owns, so adding an unrelated file never moves an
    existing agent's id onto another agent. Any residual clash is resolved with a per-id counter (constant
    time per claim, not a linear probe from the first attempt).
    """

    used: set[str] = field(default_factory=set)
    attempts: dict[str, int] = field(default_factory=dict)

    def claim(self, kind: str, *parts: str, seed: str | None = None) -> str:
        entity_id = make_id(kind, *parts, collision_seed=seed)
        if entity_id in self.used:
            first = entity_id
            base_seed = seed or "\x00".join(parts)
            attempt = self.attempts.get(first, 0)
            while entity_id in self.used:
                attempt += 1
                entity_id = make_id(kind, *parts, collision_seed=f"{base_seed}\x00{attempt}")
            self.attempts[first] = attempt
        self.used.add(entity_id)
        return entity_id


def _colliding(pairs: Iterable[tuple[str, str]]) -> set[str]:
    """Keys whose candidate id is shared with at least one other key."""
    by_id: dict[str, list[str]] = {}
    for key, candidate in pairs:
        by_id.setdefault(candidate, []).append(key)
    return {key for keys in by_id.values() if len(keys) > 1 for key in keys}


def _seed(run: _Run, key: str) -> str | None:
    return key if key in run.colliding else None


# --------------------------------------------------------------------------------------------- gates


def _gate_from(value: Any, *, key: str = "") -> ApprovalGate:
    """Approval gate for a literal approval setting (``True``, ``'always'``, ``'never_require'``, a mapping …)."""
    if value is NON_LITERAL:
        return ApprovalGate.UNKNOWN
    if isinstance(value, bool):
        return ApprovalGate.REQUIRED if value else ApprovalGate.NONE
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in {"always", "always_require", "always_ask", "true", "required"}:
            return ApprovalGate.REQUIRED
        if lowered in {"never", "never_require", "always_allow", "false", "none"}:
            return ApprovalGate.NONE
        return ApprovalGate.UNKNOWN
    if isinstance(value, dict | list):
        return ApprovalGate.CONDITIONAL
    del key
    return ApprovalGate.UNKNOWN


def _call_gate(node: ast.AST | None, consts: Mapping[str, ast.expr]) -> tuple[ApprovalGate, str] | None:
    """Gate from an approval keyword on a tool wrapper/decorator call (``None`` when no such keyword)."""
    if not isinstance(node, ast.Call):
        return None
    for kw in node.keywords:
        if kw.arg in _APPROVAL_KEYS:
            if isinstance(kw.value, ast.Lambda | ast.FunctionDef):
                return ApprovalGate.CONDITIONAL, kw.arg
            return _gate_from(literal(kw.value, consts)), kw.arg
    return None


def claude_tool_gate(
    tool: str, mode: str | None, allowed: Sequence[str] | None, *, callback: bool = False
) -> tuple[ApprovalGate, str]:
    """Approval gate of a Claude Agent SDK tool under ``permission_mode`` and ``allowed_tools``.

    ``bypassPermissions`` removes every prompt; an ``allowed_tools`` entry that is the bare tool name pre-approves
    the tool, while a scoped rule (``Bash(npm test:*)``) pre-approves only matching calls (``CONDITIONAL``: every
    other call still follows the mode); ``acceptEdits`` auto-accepts file edits; ``auto`` and a ``can_use_tool``
    callback decide per call; ``plan`` runs no tools that change anything; read-only built-ins never prompt;
    everything else prompts in ``default``. Under ``dontAsk`` a tool that would prompt is denied instead (the
    collector leaves it out); the tools that remain, pre-approved or read-only, run without a prompt.
    """
    base = tool.split("(", 1)[0]
    if mode == "bypassPermissions":
        return ApprovalGate.NONE, "permission_mode=bypassPermissions"
    if allowed is not None and base in allowed:
        return ApprovalGate.NONE, "allowed_tools pre-approves it"
    if mode == "acceptEdits" and base in _CLAUDE_EDIT_TOOLS:
        return ApprovalGate.NONE, "permission_mode=acceptEdits"
    if mode == "auto" or callback:
        return ApprovalGate.CONDITIONAL, "decided per call" + (
            " (can_use_tool)" if callback else " (auto mode)"
        )
    if mode is not None and mode not in _CLAUDE_MODES:
        return ApprovalGate.UNKNOWN, "permission_mode not literal"
    if base in _CLAUDE_NO_PROMPT:
        return ApprovalGate.NONE, "read-only built-in tool (never prompts)"
    scoped = sorted(rule for rule in allowed or () if rule.startswith(base + "("))
    if scoped:
        return ApprovalGate.CONDITIONAL, f"allowed_tools pre-approves {scoped[0]} only"
    return ApprovalGate.REQUIRED, f"permission_mode={mode or 'default'} prompts"


# --------------------------------------------------------------------------------------------- Python files


def _module_name(display: str) -> tuple[str, bool]:
    """Dotted module name of a repository-relative ``*.py`` path and whether it is a package ``__init__``."""
    parts = list(PurePosixPath(display).with_suffix("").parts)
    is_pkg = bool(parts) and parts[-1] == "__init__"
    if is_pkg:
        parts = parts[:-1]
    return ".".join(parts), is_pkg


def _resolve_from(module: str, is_pkg: bool, target: str | None, level: int) -> str | None:
    if level == 0:
        return target or ""
    parts = module.split(".") if module else []
    if not is_pkg:
        parts = parts[:-1]
    if level - 1 > len(parts):
        return None
    base = parts[: len(parts) - (level - 1)]
    if target:
        base = [*base, *target.split(".")]
    return ".".join(base)


@dataclass(slots=True)
class _PyFile:
    display: str
    module: str
    tree: ast.Module
    imports: dict[str, str] = field(default_factory=dict)
    consts: _Consts = field(default_factory=_Consts)
    assigned: dict[int, str] = field(default_factory=dict)
    var_calls: dict[str, list[ast.Call]] = field(default_factory=dict)
    returned: dict[int, str] = field(default_factory=dict)
    funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = field(default_factory=dict)
    tool_funcs: dict[str, _Tool] = field(default_factory=dict)
    attached: dict[str, list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef, ast.expr]]] = field(
        default_factory=dict
    )
    node_keys: dict[int, str] = field(default_factory=dict)
    hints: tuple[str, ...] = ()
    endpoint: str | None = None

    def loc(self, node: ast.AST) -> str:
        return f"{self.display}:{getattr(node, 'lineno', 0)}"

    def qualname(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Subscript):  # ``Agent[Context](...)``: a generic alias of the class
            node = node.value
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        base = self.imports.get(node.id)
        if base is None:
            return None
        return ".".join([base, *reversed(parts)]) if parts else base


def _index_python(display: str, tree: ast.Module) -> _PyFile:
    module, is_pkg = _module_name(display)
    py = _PyFile(display=display, module=module, tree=tree)
    counts, shadowed = _bindings(tree)
    for stmt in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(stmt, ast.Assign):
            targets, value = stmt.targets, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets, value = [stmt.target], stmt.value
        for target in targets:
            if isinstance(target, ast.Name) and value is not None:
                py.consts[target.id] = value
    # a constant is a name bound exactly once in the whole file: any rebinding (``+=``, an assignment inside an
    # ``if``/``try``/function, a parameter or local of the same name, ``global``, a loop target …) makes it
    # non-literal, so a value the agent may not use is never digested or reported as its prompt or model
    py.consts = _Consts({k: v for k, v in py.consts.items() if counts.get(k) == 1}, shadowed)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    py.imports[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    py.imports.setdefault(top, top)
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_from(module, is_pkg, node.module, node.level)
            if base is None:
                continue
            for alias in node.names:
                if alias.name != "*":
                    py.imports[alias.asname or alias.name] = f"{base}.{alias.name}" if base else alias.name
        elif isinstance(node, ast.Assign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name) and isinstance(node.value, ast.Call):
                py.assigned[id(node.value)] = targets[0].id
                py.var_calls.setdefault(targets[0].id, []).append(node.value)
        elif isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:  # ``async with MCPServerStdio(...) as server:``
                if isinstance(item.optional_vars, ast.Name) and isinstance(item.context_expr, ast.Call):
                    py.assigned[id(item.context_expr)] = item.optional_vars.id
                    py.var_calls.setdefault(item.optional_vars.id, []).append(item.context_expr)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            py.funcs.setdefault(node.name, node)
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Call):
                    py.returned.setdefault(id(sub.value), node.name)
    py.hints, py.endpoint = _hosted_hints(tree)
    return py


_FUNCTION_SCOPES: Final = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_INNER_SCOPES: Final = (
    *_FUNCTION_SCOPES,
    ast.ClassDef,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)


def _scope_bindings(nodes: Iterable[ast.AST]) -> tuple[dict[str, int], set[str]]:
    """Names bound directly in one scope (``nodes`` are its statements; nested function, class and comprehension
    scopes are not entered, but the names of nested functions and classes bind here) and its ``global`` names."""
    counts: dict[str, int] = {}
    declared: set[str] = set()

    def bump(name: str) -> None:
        counts[name] = counts.get(name, 0) + 1

    stack = list(nodes)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Global):
            declared.update(node.names)
            continue
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            bump(node.name)
            stack.extend(node.decorator_list)  # evaluated in this scope
            continue
        if isinstance(node, _INNER_SCOPES):
            continue
        if isinstance(node, ast.AnnAssign) and node.value is None and isinstance(node.target, ast.Name):
            continue  # ``x: int`` declares, it does not bind
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
            bump(node.id)
        elif isinstance(node, ast.Import | ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    bump(alias.asname or alias.name.split(".", 1)[0])
        elif (isinstance(node, ast.ExceptHandler) and node.name) or (
            isinstance(node, ast.MatchAs | ast.MatchStar) and node.name
        ):
            bump(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bump(node.rest)
        stack.extend(ast.iter_child_nodes(node))
    return counts, declared


def _function_locals(func: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> tuple[set[str], set[str]]:
    """``(locals, globals)`` of one function: its parameters and the names its body binds, minus ``global``s."""
    args = func.args
    params = {
        a.arg
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg)
        if a is not None
    }
    body: list[ast.AST] = [func.body] if isinstance(func, ast.Lambda) else list(func.body)
    bound, declared = _scope_bindings(body)
    return (params | set(bound)) - declared, declared


def _bindings(tree: ast.Module) -> tuple[dict[str, int], set[int]]:
    """Module-scope binding counts and the ``Name`` loads inside functions that a local binding shadows.

    A module constant is literal only where it is bound exactly once at module level (``+=``, a second assignment
    inside a module-level ``if``/``try``/loop, an import, or a ``global`` rebinding in a function all count) and,
    inside a function, only where no parameter or local of that function (or an enclosing one) has its name.
    """
    counts, _ = _scope_bindings(tree.body)
    shadowed: set[int] = set()
    stack: list[tuple[ast.AST, frozenset[str]]] = [(tree, frozenset())]
    while stack:
        node, enclosing = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _FUNCTION_SCOPES):
                local, declared = _function_locals(child)
                for name in declared:  # ``global X`` + assignment in a function: X is rebound at run time
                    counts[name] = counts.get(name, 0) + 2
                stack.append((child, enclosing | local))
            elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                if child.id in enclosing:
                    shadowed.add(id(child))
            else:
                stack.append((child, enclosing))
    return counts, shadowed


def _hosted_hints(tree: ast.Module) -> tuple[tuple[str, ...], str | None]:
    """Provider hints and the file's single attributable endpoint, computed exactly as ``models-hosted`` does."""
    hints: set[str] = set()
    endpoints: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            top = node.module
            if top in _MODULE_HINTS or top.split(".")[0] in _MODULE_HINTS:
                hints.add(_MODULE_HINTS.get(top, _MODULE_HINTS.get(top.split(".")[0], "")))
            hints.update(_IMPORT_HINTS[a.name] for a in node.names if a.name in _IMPORT_HINTS)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                for candidate in (alias.name, alias.name.split(".")[0]):
                    if candidate in _MODULE_HINTS:
                        hints.add(_MODULE_HINTS[candidate])
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if (
                    kw.arg in ("base_url", "api_base", "azure_endpoint", "endpoint")
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    endpoints.add(kw.value.value)
    hints.discard("")
    if any(h in hints for h in ("azure-openai", "aws-bedrock", "google-vertex")):
        hints = {h for h in hints if h in ("azure-openai", "aws-bedrock", "google-vertex")}
    attributed = {p for p in (provider_for_endpoint(e) for e in endpoints) if p}
    endpoint = next(iter(endpoints)) if len(attributed) == 1 and len(endpoints) == 1 else None
    return tuple(sorted(hints)), endpoint


def _match_ctor(qualname: str | None) -> PyCtor | None:
    if qualname is None:
        return None
    last = qualname.rsplit(".", 1)[-1]
    for spec in PY_CONSTRUCTORS:
        if last in spec.names and qualname.startswith(spec.package + "."):
            return spec
    return None


def _getenv_call(call: ast.Call) -> bool:
    """``os.getenv(…)`` / ``os.environ.get(…)`` / ``getenv(…)``."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id == "getenv"
    if isinstance(func, ast.Attribute):
        if func.attr == "getenv":
            return True
        return func.attr == "get" and (
            (isinstance(func.value, ast.Attribute) and func.value.attr == "environ")
            or (isinstance(func.value, ast.Name) and func.value.id == "environ")
        )
    return False


def _callee_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _decorator_name(dec: ast.expr) -> tuple[str | None, ast.Call | None, ast.expr]:
    """``(name, call-or-None, base)`` of a decorator (``@x``, ``@x(...)``, ``@obj.x``, ``@obj.x(...)``)."""
    call = dec if isinstance(dec, ast.Call) else None
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Name):
        return target.id, call, target
    if isinstance(target, ast.Attribute):
        return target.attr, call, target.value
    return None, call, target


class _PythonReader:
    """Extracts agent declarations from one parsed Python file."""

    def __init__(self, run: _Run, py: _PyFile, collector_ref: str) -> None:
        self.run = run
        self.py = py
        self.ref = collector_ref
        self.deadline = min(run.deadline, time.monotonic() + run.file_seconds)
        #: framework calls not read because the file used up its time share (``None``: all read)
        self.truncated: int | None = None
        self.matched: list[tuple[ast.Call, PyCtor]] = []

    # ---------------------------------------------------------------------------------------- entry

    def _out_of_time(self, remaining: int) -> bool:
        if time.monotonic() <= self.deadline and not self.run.full():
            return False
        self.truncated = remaining
        self._drop_file()
        return True

    def _drop_file(self) -> None:
        """Forget this file's partial declarations: a truncated file is reported, never half-described."""
        run, display = self.run, self.py.display
        gone = {k for k, d in run.decls.items() if d.display == display}
        for key in gone:
            del run.decls[key]
        for key in [k for k, m in run.servers.items() if m.display == display]:
            del run.servers[key]
        run.root_servers[:] = [k for k in run.root_servers if k in run.servers]
        run.pending_tools[:] = [p for p in run.pending_tools if p[0] not in gone]
        run.pending_defs[:] = [p for p in run.pending_defs if p[0] not in gone]

    def understood(self) -> bool:
        """False when the file imports an agent constructor but nothing here was recognised (the agent is built
        in a form this reader does not follow, e.g. through an alias or ``getattr``), so its facts are unknown."""
        if self.matched or self.py.tool_funcs:
            return True
        modules: set[str] = set()
        for local, qual in self.py.imports.items():
            if not _framework_package(qual):
                continue
            spec = _match_ctor(qual)
            if spec is not None and spec.kind in _AGENT_KINDS:
                return False
            if "." not in qual:
                modules.add(local)
        if not modules:
            return True
        for node in ast.walk(self.py.tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in modules
                and node.attr in _AGENT_CTOR_NAMES
            ):
                return False
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in modules
            ):
                return False
        return True

    def frameworks(self) -> list[str]:
        return sorted({q.split(".", 1)[0] for q in self.py.imports.values() if _framework_package(q)})

    def read(self) -> int:
        py = self.py
        self._index_tool_functions()
        calls = sorted(
            (n for n in ast.walk(py.tree) if isinstance(n, ast.Call)),
            key=lambda n: (n.lineno, n.col_offset),
        )
        matched = self.matched
        for call in calls:
            spec = _match_ctor(py.qualname(call.func))
            if spec is not None:
                matched.append((call, spec))
        # first give every agent a key, so references between them resolve regardless of order
        agents: list[tuple[ast.Call, PyCtor, _Decl]] = []
        for index, (call, spec) in enumerate(matched):
            if self._out_of_time(len(matched) - index):
                return 0
            if spec.kind in ("agent", "options", "crew", "workflow"):
                decl = self._new_decl(call, spec)
                agents.append((call, spec, decl))
        for index, (call, spec, decl) in enumerate(agents):
            if self._out_of_time(len(agents) - index):
                return 0
            self._fill(call, spec, decl)
        mcp_calls = [(c, s) for c, s in matched if s.kind in ("mcp", "mcp-multi")]
        nested = {i for c, _ in mcp_calls for i in self._inner_calls(c)}
        for index, (call, spec) in enumerate(matched):
            if self._out_of_time(len(matched) - index):
                return 0
            if spec.kind == "subagent" and id(call) not in py.node_keys:
                decl = self._new_decl(call, spec)
                self._fill(call, spec, decl)
                agents.append((call, spec, decl))
            elif spec.kind == "task":
                self._task(call)
            elif (
                spec.kind in ("mcp", "mcp-multi")
                and id(call) not in nested
                and not self._server_used(call)
                and self._node_key(call) not in self.run.failed_servers
            ):
                # a server no agent here references (tools loaded at run time): the scanned agent's own
                self.run.root_servers.extend(self._servers_from_call(call, spec))
        self._attach_decorated_tools()
        return len(agents)

    def _inner_calls(self, call: ast.Call) -> set[int]:
        """Ids of calls nested in ``call``'s arguments (directly or through a variable): parts of one server."""
        inner: set[int] = set()
        for node in ast.walk(call):
            if node is call:
                continue
            if isinstance(node, ast.Call):
                inner.add(id(node))
            elif isinstance(node, ast.Name):
                inner.update(id(c) for c in self.py.var_calls.get(node.id, []))
                target = self.py.consts.target(node)
                if isinstance(target, ast.Call):
                    inner.add(id(target))
        return inner

    def _server_used(self, call: ast.Call) -> bool:
        return self._node_key(call) in self.run.servers

    def _node_key(self, node: ast.AST) -> str:
        return f"{self.py.display}:{getattr(node, 'lineno', 0)}:{getattr(node, 'col_offset', 0)}"

    # ---------------------------------------------------------------------------------------- tools defined here

    def _index_tool_functions(self) -> None:
        py = self.py
        for name, func in sorted(py.funcs.items()):
            for dec in func.decorator_list:
                dname, call, base = _decorator_name(dec)
                if dname is None:
                    continue
                if (
                    dname in ("tool", "tool_plain")
                    and isinstance(base, ast.Name)
                    and base.id not in py.imports
                ):
                    py.attached.setdefault(base.id, []).append((dname, func, dec))
                    continue
                if dname in ("system_prompt", "instructions") and isinstance(base, ast.Name):
                    py.attached.setdefault(base.id, []).append((dname, func, dec))
                    continue
                if dname in ("function_tool", "tool", "ai_function", "kernel_function"):
                    tool_name = name
                    if call is not None:
                        first = literal(call.args[0], py.consts) if call.args else NON_LITERAL
                        for kw in call.keywords:
                            if kw.arg in ("name_override", "name"):
                                first = literal(kw.value, py.consts)
                        tool_name = _short(first) or name
                    info = _Tool(tool_name, py.loc(func), tags={f"tool-decorator:{dname}"})
                    gate = _call_gate(call, py.consts)
                    if gate is not None:
                        info.gate, info.gate_source = gate
                    py.tool_funcs[name] = info
                    self.run.module_tools[(py.module, name)] = info

    def _attach_decorated_tools(self) -> None:
        """Pydantic AI ``@agent.tool`` / ``@agent.system_prompt`` decorators attach to that agent variable."""
        py = self.py
        for var, entries in sorted(py.attached.items()):
            calls = py.var_calls.get(var, [])
            keys = [py.node_keys[id(c)] for c in calls if id(c) in py.node_keys]
            if len(keys) != 1:
                continue
            decl = self.run.decls[keys[0]]
            for kind, func, dec in entries:
                if kind in ("system_prompt", "instructions"):
                    decl.mark_unknown("instructions", py.loc(func))
                    decl.tags.add("dynamic-instructions")
                    continue
                info = _Tool(func.name, py.loc(func), tags={f"tool-decorator:{kind}"})
                gate = _call_gate(dec, py.consts)
                if gate is not None:
                    info.gate, info.gate_source = gate
                decl.tools.append(info)

    # ---------------------------------------------------------------------------------------- agent decls

    def _new_decl(self, call: ast.Call, spec: PyCtor) -> _Decl:
        py = self.py
        var = py.assigned.get(id(call))
        name: str | None = None
        for role_name, value in self._args(call, spec):
            if role_name == "name":
                name = _short(literal(value, py.consts))
                if name is None:
                    break
        if name is None and spec.framework == "crewai" and spec.kind == "agent":
            role = next((v for r, v in self._args(call, spec) if r == "prompt:role"), None)
            name = _short(literal(role, py.consts), 80) if role is not None else None
        fallback = var or py.returned.get(id(call)) or f"{PurePosixPath(py.display).stem}-L{call.lineno}"
        if spec.kind == "options":
            fallback = f"{PurePosixPath(py.display).stem}.{var or 'L' + str(call.lineno)}"
        key = self._node_key(call)
        decl = _Decl(
            framework=spec.framework,
            name=name or fallback,
            display=py.display,
            locator=py.loc(call),
            key=key,
            order=(py.display, call.lineno, call.col_offset),
        )
        if name is None:
            decl.tags.add(
                "name-from:" + ("variable" if var else "function" if id(call) in py.returned else "location")
            )
        if spec.api:
            decl.tags.add(f"api:{spec.api}")
        decl.tags.add(f"kind:{spec.kind}")
        decl.crew_scope = py.display
        py.node_keys[id(call)] = key
        if var is not None:
            self.run.module_vars.setdefault((py.module, var), key)
            self.run.file_vars.setdefault((py.display, var), key)
        self.run.add(decl)
        return decl

    def _args(self, call: ast.Call, spec: PyCtor) -> Iterator[tuple[str, ast.expr]]:
        for index, arg in enumerate(call.args):
            if isinstance(arg, ast.Starred):
                yield "**", arg
            elif index < len(spec.positional):
                yield spec.positional[index], arg
        for kw in call.keywords:
            if kw.arg is None:
                yield "**", kw.value
            elif kw.arg in spec.fields:
                yield spec.fields[kw.arg], kw.value

    def _fill(self, call: ast.Call, spec: PyCtor, decl: _Decl) -> None:
        py = self.py
        for role, value in self._args(call, spec):
            loc = py.loc(value)
            if role == "**":
                decl.mark_unknown("kwargs", loc)
                decl.tags.add("partial-definition")
            elif role == "description":
                text = literal(value, py.consts)
                decl.description = _short(text, MAX_DESCRIPTION_CHARS)
                if isinstance(text, str) and looks_like_secret(text):
                    self.run.redact(decl)
            elif role.startswith("prompt:"):
                self._prompt(decl, role.split(":", 1)[1], value)
            elif role.startswith("unknown-prompt:"):
                decl.mark_unknown(role.split(":", 1)[1], loc)
                decl.tags.add("remote-prompt-ref")
            elif role.startswith("model:"):
                self._model(decl, value, role.split(":", 1)[1], keyword=self._keyword_of(call, value))
            elif role == "tools":
                self._tools(decl, value)
            elif role in ("handoffs", "sub-agents", "members"):
                mode = {"handoffs": "handoff", "sub-agents": "sub-agent", "members": "member"}[role]
                self._delegates(decl, value, mode)
            elif role == "mcp-list":
                self._mcp_list(decl, value)
            elif role == "mcp-map":
                self._mcp_map(decl, value)
            elif role.startswith("control:"):
                decl.tags.add(f"control:{role.split(':', 1)[1]}")
            elif role == "approval-callback":
                decl.gate, decl.gate_source = ApprovalGate.CONDITIONAL, "programmatic approval callback"
                decl.tags.add("approval:callback")
            elif role.startswith("policy-callback:"):
                # a callback that runs before each tool call may block it, or may only log: not an approval gate
                _policy_callback(decl, role.split(":", 1)[1])
            else:
                self._fill_special(call, spec, decl, role, value)

    def _keyword_of(self, call: ast.Call, value: ast.expr) -> str | None:
        for kw in call.keywords:
            if kw.value is value:
                return kw.arg
        return None

    def _fill_special(self, call: ast.Call, spec: PyCtor, decl: _Decl, role: str, value: ast.expr) -> None:
        py = self.py
        loc = py.loc(value)
        lit = literal(value, py.consts)
        if role == "claude-system-prompt":
            self._claude_system_prompt(decl, value, lit)
        elif role == "base-tools":
            if isinstance(lit, list):
                decl.base_tools = _safe_names(self.run, decl, lit)
            elif isinstance(lit, dict):
                decl.tags.add(f"tools:preset:{self._safe_value(decl, lit.get('preset')) or 'unknown'}")
            else:
                decl.mark_unknown("tools", loc)
        elif role == "allowed-tools":
            if isinstance(lit, list):
                decl.allowed = _safe_names(self.run, decl, lit)
            else:
                decl.mark_unknown("allowed_tools", loc)
        elif role == "disallowed-tools":
            if isinstance(lit, list):
                decl.disallowed = _safe_names(self.run, decl, lit)
            else:
                decl.mark_unknown("disallowed_tools", loc)
        elif role == "permission-mode":
            if isinstance(lit, str) and lit in _CLAUDE_MODES:
                decl.permission_mode = lit
                decl.tags.add(f"permission-mode:{lit}")
                if lit == "bypassPermissions":
                    decl.tags.add("approval-bypass:permission_mode")
            else:
                decl.mode_unknown = True
                decl.mark_unknown("permission_mode", loc)
        elif role == "claude-agents":
            self._claude_agents(decl, value)
        elif role == "mcp-names":
            if isinstance(lit, list):
                decl.tags.update(f"mcp-server-ref:{n}" for n in lit if isinstance(n, str) and _short(n))
            else:
                decl.mark_unknown("mcp_servers", loc)
        elif role == "middleware":
            self._middleware(decl, value)
        elif role == "interrupt":
            if isinstance(lit, list) and "tools" in lit:
                decl.gate, decl.gate_source = (
                    ApprovalGate.REQUIRED,
                    "graph interrupts before/after the tools node",
                )
                decl.tags.add("approval:graph-interrupt")
            elif not isinstance(lit, list):
                decl.mark_unknown("interrupt", loc)
        elif role == "allow-delegation":
            if lit is True:
                decl.allow_delegation = True
                decl.tags.add("allow-delegation")
            elif lit is NON_LITERAL:
                decl.mark_unknown("allow_delegation", loc)
        elif role == "code-execution":
            if lit is not False and lit is not None:
                decl.tags.add("capability:execute")
                if isinstance(lit, dict) and lit.get("use_docker") is False:
                    decl.tags.add("code-execution:host")
                executor = self._resolve_node(value)
                if isinstance(executor, ast.Call):
                    self._code_executor(decl, executor)
                if "CodeExecutorAgent" in spec.names:
                    approved = any(kw.arg == "approval_func" for kw in call.keywords)
                    decl.tags.add("code-execution:approval:" + ("conditional" if approved else "none"))
                    if not approved:
                        decl.gate, decl.gate_source = (
                            ApprovalGate.NONE,
                            "no approval_func: code runs unreviewed",
                        )
        elif role == "crewai-config":
            decl.config_key = self._config_key(value)
            if decl.config_key is not None and any(t.startswith("name-from:") for t in decl.tags):
                decl.name = decl.config_key
        elif role == "mcp-refs":
            node = self._resolve_node(value)
            elements = node.elts if isinstance(node, ast.List | ast.Tuple) else [node]
            if len(elements) > MAX_ITEMS:
                decl.mark_unknown("mcps", loc)
            for element in elements[:MAX_ITEMS]:
                ref = literal(element, py.consts)
                if isinstance(ref, str) and ref.startswith(("http://", "https://")):
                    # ``https://host/mcp#tool`` names one tool of that server
                    url, _, tool = ref.partition("#")
                    host = _short(_url_host(url)) or "mcp"
                    key = self._server(decl.framework, host, {"url": url}, py.loc(element), py.display)
                    if _short(tool) and tool not in self.run.servers[key].tools:
                        self.run.servers[key].tools.append(tool)
                    decl.servers.append(key)
                elif isinstance(ref, str) and _short(ref):
                    decl.tags.add(f"mcp-ref:{ref}")
                elif ref is NON_LITERAL and self._mcp_item(decl, element):
                    continue
                else:
                    decl.mark_unknown("mcps", py.loc(element))

        elif role == "llm-config":
            self._llm_config(decl, value, lit)
        elif role == "human-input-mode":
            if isinstance(lit, str) and _secretish(lit):
                self.run.redact(decl)
                decl.mark_unknown("human_input_mode", loc)
            elif isinstance(lit, str):
                mode = lit.upper()
                decl.tags.add(f"human-input-mode:{mode}")
                decl.gate, decl.gate_source = {
                    "ALWAYS": (ApprovalGate.REQUIRED, "human_input_mode=ALWAYS"),
                    "NEVER": (ApprovalGate.NONE, "human_input_mode=NEVER"),
                    "TERMINATE": (
                        ApprovalGate.CONDITIONAL,
                        "human_input_mode=TERMINATE asks only at termination",
                    ),
                }.get(mode, (ApprovalGate.UNKNOWN, "human_input_mode not recognised"))
                if _short(lit) is None:  # too long or hidden characters: not a tag
                    decl.tags.discard(f"human-input-mode:{mode}")
            else:
                decl.mark_unknown("human_input_mode", loc)
        elif role == "function-choice":
            self._function_choice(decl, value)
        elif role in ("transfer-parent", "transfer-peers"):
            if lit is True:
                decl.tags.add(f"disallow-transfer-to-{role.split('-', 1)[1]}")
        elif role == "process":
            name = value.attr if isinstance(value, ast.Attribute) else lit if isinstance(lit, str) else None
            process = self._safe_value(decl, name)
            if process is not None:
                decl.tags.add(f"process:{process}")
        elif role == "manager":
            ref = self._agent_ref(value, "manager")
            if ref is not None:
                decl.delegates.append(ref)
            else:
                decl.mark_unknown("manager_agent", loc)
        elif role == "root-agent" and isinstance(lit, str):
            decl.delegates.append(_Ref(loc, "root-agent", agent_name=lit))
        del call, spec

    @staticmethod
    def _code_executor(decl: _Decl, call: ast.Call) -> None:
        """Where an executor object runs code: the host (``Local…``), a container (``Docker…``) or the provider."""
        name = _callee_name(call) or ""
        if _short(name):
            decl.tags.add(f"code-executor:{name}")
        lowered = name.lower()
        if "docker" in lowered or "container" in lowered:
            decl.tags.add("code-execution:container")
        elif "local" in lowered or "jupyter" in lowered or "unsafe" in lowered:
            decl.tags.add("code-execution:host")
        elif "builtin" in lowered:
            decl.tags.add("code-execution:provider")

    def _safe_value(self, decl: _Decl | None, value: object) -> str | None:
        """A short literal that may appear in a tag; a secret-shaped one is counted as a redaction instead."""
        if _secretish(value):
            self.run.redact(decl)
            return None
        return _short(value)

    def _config_key(self, value: ast.expr) -> str | None:
        """``self.agents_config["researcher"]`` -> ``researcher`` (CrewAI ``@CrewBase`` agents)."""
        if isinstance(value, ast.Subscript):
            key = literal(value.slice, self.py.consts)
            return key if isinstance(key, str) else None
        return None

    # ---------------------------------------------------------------------------------------- prompts

    def _prompt(self, decl: _Decl, label: str, value: ast.expr) -> None:
        text = literal(value, self.py.consts)
        loc = self.py.loc(value)
        if isinstance(text, str):
            if text:
                decl.prompts.append(_Prompt(label, text, loc, template=_template_style(decl.framework, text)))
        elif isinstance(text, list) and all(isinstance(t, str) for t in text):
            for index, part in enumerate(text):
                decl.prompts.append(_Prompt(f"{label}-{index}", part, loc))
        elif text is None:
            return
        else:
            decl.mark_unknown(label, loc)
            if isinstance(value, ast.JoinedStr):
                decl.tags.add("dynamic-instructions:f-string")
            elif isinstance(value, ast.Lambda | ast.Name | ast.Attribute):
                decl.tags.add("dynamic-instructions")

    def _claude_system_prompt(self, decl: _Decl, value: ast.expr, lit: Any) -> None:
        loc = self.py.loc(value)
        if isinstance(lit, str):
            decl.prompts.append(_Prompt("system_prompt", lit, loc))
        elif isinstance(lit, dict):
            kind = self._safe_value(decl, lit.get("type")) or "unknown"
            preset = self._safe_value(decl, lit.get("preset"))
            decl.tags.add(f"system-prompt:{kind}" + (f":{preset}" if preset else ""))
            for key in ("append", "prompt"):
                if isinstance(lit.get(key), str) and lit[key]:
                    decl.prompts.append(_Prompt(f"system_prompt_{key}", lit[key], loc))
            if kind == "file":
                decl.mark_unknown("system_prompt", loc)
        elif lit is not None:
            decl.mark_unknown("system_prompt", loc)

    # ---------------------------------------------------------------------------------------- models

    def _model(self, decl: _Decl, value: ast.expr, role: str, *, keyword: str | None, depth: int = 0) -> None:
        py = self.py
        loc = py.loc(value)
        target = py.consts.target(value)
        if depth < 3 and isinstance(target, ast.Call):
            self._model(decl, target, role, keyword=None, depth=depth + 1)
            return
        lit = literal(value, py.consts)
        if isinstance(lit, str):
            self._add_model(decl, lit, role, loc, hosted=self._hosted_position(value, keyword))
            return
        if lit is None:
            return
        if isinstance(value, ast.Call) and self._env_default(decl, value, role):
            return
        if isinstance(value, ast.Call):
            name = _callee_name(value)
            if name == "init_chat_model":
                first = value.args[0] if value.args else None
                provider = None
                for kw in value.keywords:
                    if kw.arg == "model":
                        first = kw.value
                    elif kw.arg == "model_provider":
                        p = literal(kw.value, py.consts)
                        provider = _COLON_PROVIDERS.get(p.lower()) if isinstance(p, str) else None
                    elif kw.arg == "configurable_fields":
                        decl.tags.add("model-reroutable")
                self._wrapped_model(decl, first, role, loc, provider, keyword=None)
                return
            if self._env_only(decl, value):
                return
            provider = _WRAPPER_PROVIDERS.get(name or "")
            for key in _WRAPPER_MODEL_KEYS:
                for kw in value.keywords:
                    if kw.arg == key:
                        self._wrapped_model(decl, kw.value, role, loc, provider, keyword=key)
                        self._api_key_literals(decl, value)
                        return
            if value.args and (provider is not None or name in _PROVIDERLESS_WRAPPERS):
                # only a known model wrapper's first argument names a model; ``pick_model("cheap")`` does not
                self._wrapped_model(decl, value.args[0], role, loc, provider, keyword=None)
                self._api_key_literals(decl, value)
                return
            if provider is not None:  # a provider client without a model argument: the SDK default applies
                decl.tags.add(f"model:implicit-default:{provider}")
                decl.mark_unknown("model", loc)
                return
        decl.mark_unknown("model", loc)

    def _hosted_position(self, node: ast.expr | None, keyword: str | None) -> bool:
        """True where ``models-hosted`` reads the same string: a constant under one of its keyword names, or a
        module constant whose name looks like a model selector (``MODEL_NAME = "…"``)."""
        if isinstance(node, ast.Constant):
            return keyword in HOSTED_OWNED_KEYWORDS
        if isinstance(node, ast.Name) and _MODEL_NAME_RE.match(node.id):
            target = self.py.consts.target(node)
            return isinstance(target, ast.Constant) and isinstance(target.value, str)
        return False

    def _env_only(self, decl: _Decl, call: ast.Call) -> bool:
        """``os.getenv("OPENAI_MODEL")`` without a default: the model is chosen at run time (unknown, tagged)."""
        if not _getenv_call(call) or len(call.args) != 1 or call.keywords:
            return False
        name = literal(call.args[0], self.py.consts)
        if isinstance(name, str) and _short(name):
            decl.tags.add(f"model-env-override:{name}")
        decl.mark_unknown("model", self.py.loc(call))
        return True

    def _env_default(self, decl: _Decl, call: ast.Call, role: str) -> bool:
        """``os.getenv("OPENAI_MODEL", "gpt-4o")``: the default is the declared model, the variable may override it."""
        if not _getenv_call(call) or len(call.args) != 2:
            return False
        name, default = literal(call.args[0], self.py.consts), call.args[1]
        value = literal(default, self.py.consts)
        if not isinstance(name, str) or not isinstance(value, str):
            return False
        hosted = bool(_ENV_MODEL_KEY.match(name)) and isinstance(default, ast.Constant)
        self._add_model(decl, value, role, self.py.loc(default), hosted=hosted)
        if _short(name):
            decl.tags.add(f"model-env-override:{name}")
        return True

    def _wrapped_model(
        self,
        decl: _Decl,
        node: ast.expr | None,
        role: str,
        loc: str,
        provider: str | None,
        *,
        keyword: str | None,
    ) -> None:
        lit = literal(node, self.py.consts) if node is not None else NON_LITERAL
        if isinstance(lit, str):
            hosted = self._hosted_position(node, keyword)
            self._add_model(decl, lit, role, loc, hosted=hosted, provider=None if hosted else provider)
        elif isinstance(node, ast.Call) and (
            self._env_default(decl, node, role) or self._env_only(decl, node)
        ):
            return
        else:
            decl.mark_unknown("model", loc)

    def _api_key_literals(self, decl: _Decl, call: ast.Call) -> None:
        for kw in call.keywords:
            if kw.arg in ("api_key", "openai_api_key", "anthropic_api_key") and isinstance(
                kw.value, ast.Constant
            ):
                self._api_key(decl, kw.arg, kw.value.value)

    def _api_key(self, decl: _Decl, key: str, value: object) -> None:
        """A constant API key: only a literal secret is an inline key (counted and redacted); a placeholder such as
        ``"${OPENAI_API_KEY}"`` is a reference, and an empty value is nothing."""
        kind = classify_env_value(key, value)
        if kind == "literal-secret":
            decl.tags.add("inline-api-key")
            self.run.redact(decl)
        elif kind == "placeholder":
            decl.tags.add("api-key:placeholder")

    def _add_model(
        self, decl: _Decl, value: str, role: str, loc: str, *, hosted: bool, provider: str | None = None
    ) -> None:
        py = self.py
        decl.models.append(
            _ModelRef(
                value=value,
                role=role,
                locator=loc,
                hosted_owned=hosted,
                provider=provider,
                endpoint=py.endpoint,
                hints=py.hints,
                context=_MODEL_CONTEXT.get(decl.framework),
            )
        )

    def _llm_config(self, decl: _Decl, value: ast.expr, lit: Any) -> None:
        """AG2/AutoGen classic ``llm_config``: ``{"config_list": [{"model": …}], "model": …}`` or ``False``."""
        loc = self.py.loc(value)
        if lit is False:
            decl.tags.add("llm:none")
            return
        node: ast.AST = self.py.consts.target(value) or value
        entries: list[ast.Dict] = []
        if isinstance(node, ast.Dict):
            entries.append(node)
            for k, v in zip(node.keys, node.values, strict=True):
                if (
                    isinstance(k, ast.Constant)
                    and k.value == "config_list"
                    and isinstance(v, ast.List | ast.Tuple)
                ):
                    entries.extend(e for e in v.elts[:MAX_ITEMS] if isinstance(e, ast.Dict))
                elif isinstance(k, ast.Constant) and k.value == "config_list":
                    decl.mark_unknown("model", self.py.loc(v))
        elif isinstance(node, ast.Call):
            entries.extend(a for a in node.args if isinstance(a, ast.Dict))
        if not entries:
            decl.mark_unknown("model", loc)
            return
        for entry in entries:
            for k, v in zip(entry.keys, entry.values, strict=True):
                if isinstance(k, ast.Constant) and k.value == "model":
                    model = literal(v, self.py.consts)
                    if isinstance(model, str):
                        self._add_model(
                            decl, model, "primary", self.py.loc(v), hosted=isinstance(v, ast.Constant)
                        )
                    else:
                        decl.mark_unknown("model", self.py.loc(v))
                elif isinstance(k, ast.Constant) and k.value == "api_key" and isinstance(v, ast.Constant):
                    self._api_key(decl, "api_key", v.value)

    # ---------------------------------------------------------------------------------------- tools

    def _resolve_node(self, node: ast.expr, depth: int = 0) -> ast.expr:
        """Follow a module-level name to its single assignment (lists of tools, server objects)."""
        target = self.py.consts.target(node)
        if target is not None and depth < 3:
            return self._resolve_node(target, depth + 1)
        return node

    def _tools(self, decl: _Decl, value: ast.expr) -> None:
        node = self._resolve_node(value)
        loc = self.py.loc(value)
        if isinstance(node, ast.Constant) and node.value is None:
            return
        if isinstance(node, ast.Call) and self._mcp_item(decl, node):  # ``tools=get_tools_from_mcp_url(…)``
            return
        if (
            isinstance(node, ast.Call) and _callee_name(node) in _MCP_LOADERS
        ):  # ``toolsets=load_mcp_toolsets(…)``
            self._tool_call(decl, node)
            return
        if isinstance(node, ast.Dict):  # Vercel-style name -> tool maps are not Python, but tolerate dicts
            items: list[ast.expr] = [v for v in node.values if v is not None]
        elif isinstance(node, ast.List | ast.Tuple):
            items = list(node.elts)
        else:
            decl.mark_unknown("tools", loc)
            return
        if len(items) > MAX_ITEMS:
            decl.mark_unknown("tools", loc)
            items = items[:MAX_ITEMS]
        for item in items:
            self._tool_item(decl, item)

    def _tool_item(self, decl: _Decl, item: ast.expr) -> None:
        py = self.py
        loc = py.loc(item)
        if isinstance(item, ast.Starred):
            decl.mark_unknown("tools", loc)
            return
        lit = literal(item, py.consts)
        if isinstance(lit, str):
            name = _short(lit)
            if name:
                decl.tools.append(_Tool(name, loc))
            return
        if isinstance(item, ast.Name):
            key = self._agent_key_for_name(item.id)
            if key is not None:
                decl.delegates.append(_Ref(loc, "agent-as-tool", key=key))
                return
            if item.id in py.tool_funcs:
                info = py.tool_funcs[item.id]
                decl.tools.append(
                    _Tool(info.name, loc, info.gate, info.gate_source, set(info.capabilities), set(info.tags))
                )
                return
            target = py.consts.target(item)
            calls = py.var_calls.get(item.id, [])
            if not isinstance(target, ast.Call) and len(calls) == 1:
                target = calls[0]
            if isinstance(target, ast.Call):
                self._tool_call(decl, target)
                return
            qual = py.imports.get(item.id)
            if qual is not None and "." in qual:
                # resolved after every file is read: an imported agent (agent-as-tool) or tool function
                self.run.pending_tools.append((decl.key, qual, item.id, loc))
                return
            decl.tools.append(_Tool(item.id, loc, tags={"tool-ref:name"}))
            return
        if isinstance(item, ast.Attribute):
            decl.tools.append(_Tool(item.attr, loc, tags={"tool-ref:attribute"}))
            return
        if isinstance(item, ast.Call):
            self._tool_call(decl, item)
            return
        decl.mark_unknown("tools", loc)

    def _tool_call(self, decl: _Decl, call: ast.Call) -> None:
        py = self.py
        loc = py.loc(call)
        spec = _match_ctor(py.qualname(call.func))
        if spec is not None and spec.kind in ("agent", "options") and id(call) in py.node_keys:
            decl.delegates.append(_Ref(loc, "agent-as-tool", key=py.node_keys[id(call)]))
            return
        if spec is not None and spec.kind in ("mcp", "mcp-multi"):
            self._mcp_item(decl, call)
            return
        name = _callee_name(call)
        if name in _MCP_LOADERS:  # Pydantic AI ``load_mcp_toolsets("mcp.json")``: servers come from a file
            path = literal(call.args[0], py.consts) if call.args else NON_LITERAL
            decl.tags.add("mcp-config-file")
            if _short(path):
                decl.tags.add(f"mcp-config-file:{path}")
            decl.mark_unknown("mcp_servers", loc)
            return
        if name is not None and "mcp" in name.lower():  # an MCP client class this reader does not know
            decl.tags.add(f"mcp-server:unrecognised:{name}")
            decl.mark_unknown("mcp_servers", loc)
            return
        if name == "as_tool" and isinstance(call.func, ast.Attribute):
            target = call.func.value
            ref = self._agent_ref(target, "agent-as-tool")
            if ref is not None:
                gate = _call_gate(call, py.consts)
                if gate is not None:
                    ref.constraints = f"approval:{gate[0].value}"
                decl.delegates.append(ref)
                return
        if name in ("AgentTool",):
            agent_node = next(
                (kw.value for kw in call.keywords if kw.arg == "agent"), call.args[0] if call.args else None
            )
            ref = self._agent_ref(agent_node, "agent-as-tool") if agent_node is not None else None
            if ref is not None:
                decl.delegates.append(ref)
                return
        if name in ("FunctionTool", "Tool", "function_tool", "from_function", "FunctionToolset"):
            func = (
                call.args[0]
                if call.args
                else next((kw.value for kw in call.keywords if kw.arg in ("func", "function")), None)
            )
            fname = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else None
            )
            if fname is None and name == "FunctionToolset":
                fset = literal(func, py.consts) if func is not None else NON_LITERAL
                if not isinstance(fset, list):
                    decl.mark_unknown("tools", loc)
                return
            if fname is None:
                decl.mark_unknown("tools", loc)
                return
            base = py.tool_funcs.get(fname)
            tool = _Tool(base.name if base else fname, loc, tags={f"tool-wrapper:{name}"})
            gate = _call_gate(call, py.consts) or (
                (base.gate, base.gate_source or "") if base and base.gate else None
            )
            if gate is not None:
                tool.gate, tool.gate_source = gate
            for kw in call.keywords:
                if kw.arg in ("name", "name_override"):
                    tool.name = _short(literal(kw.value, py.consts)) or tool.name
            decl.tools.append(tool)
            return
        if name is None:
            decl.mark_unknown("tools", loc)
            return
        tool = _Tool(name, loc, tags={"tool-ref:instance"})
        gate = _call_gate(call, py.consts)
        if gate is not None:
            tool.gate, tool.gate_source = gate
        decl.tools.append(tool)

    # ---------------------------------------------------------------------------------------- delegation

    def _agent_key_for_name(self, name: str) -> str | None:
        keys = {
            self.py.node_keys[id(c)] for c in self.py.var_calls.get(name, []) if id(c) in self.py.node_keys
        }
        return keys.pop() if len(keys) == 1 else None

    def _agent_ref(self, node: ast.expr | None, mode: str) -> _Ref | None:
        py = self.py
        if node is None:
            return None
        loc = py.loc(node)
        if isinstance(node, ast.Name):
            key = self._agent_key_for_name(node.id)
            if key is not None:
                return _Ref(loc, mode, key=key)
            qual = py.imports.get(node.id)
            if qual is not None:
                return _Ref(loc, mode, qualname=qual)
            return _Ref(loc, mode, var=node.id)
        if isinstance(node, ast.Call):
            if id(node) in py.node_keys:
                return _Ref(loc, mode, key=py.node_keys[id(node)])
            name = _callee_name(node)
            if name in ("handoff", "Handoff"):
                target = next(
                    (kw.value for kw in node.keywords if kw.arg in ("agent", "target")),
                    node.args[0] if node.args else None,
                )
                return self._agent_ref(target, mode)
        lit = literal(node, py.consts)
        if isinstance(lit, str) and _short(lit):
            return _Ref(loc, mode, agent_name=lit)
        return None

    def _delegates(self, decl: _Decl, value: ast.expr, mode: str) -> None:
        node = self._resolve_node(value)
        loc = self.py.loc(value)
        if isinstance(node, ast.Constant) and node.value is None:
            return
        if not isinstance(node, ast.List | ast.Tuple):
            decl.mark_unknown("handoffs" if mode == "handoff" else "sub_agents", loc)
            return
        for item in node.elts[:MAX_ITEMS]:
            ref = self._agent_ref(item, mode)
            if ref is None:
                decl.mark_unknown("handoffs" if mode == "handoff" else "sub_agents", self.py.loc(item))
                continue
            decl.delegates.append(ref)
        if len(node.elts) > MAX_ITEMS:
            decl.mark_unknown("handoffs", loc)

    def _task(self, call: ast.Call) -> None:
        """CrewAI ``Task(description=…, agent=…, human_input=…)``: prompts and review flags land on the agent."""
        py = self.py
        agent_node = next((kw.value for kw in call.keywords if kw.arg == "agent"), None)
        ref = self._agent_ref(agent_node, "task") if agent_node is not None else None
        if ref is None or ref.key is None:
            return
        decl = self.run.decls[ref.key]
        name = _short(next((literal(kw.value, py.consts) for kw in call.keywords if kw.arg == "name"), None))
        label = f"task:{name or 'L' + str(call.lineno)}"
        for kw in call.keywords:
            if kw.arg in ("description", "expected_output"):
                text = literal(kw.value, py.consts)
                if isinstance(text, str) and text:
                    decl.prompts.append(
                        _Prompt(
                            f"{label}:{kw.arg}",
                            text,
                            py.loc(kw.value),
                            InstructionKind.OTHER,
                            _template_style("crewai", text),
                        )
                    )
                elif text is NON_LITERAL:
                    decl.mark_unknown(f"{label}:{kw.arg}", py.loc(kw.value))
            elif kw.arg == "tools":
                self._tools(decl, kw.value)
            elif kw.arg == "human_input" and literal(kw.value, py.consts) is True:
                decl.tags.add("human-review:task-output")

    # ---------------------------------------------------------------------------------------- approval settings

    def _middleware(self, decl: _Decl, value: ast.expr) -> None:
        node = self._resolve_node(value)
        if not isinstance(node, ast.List | ast.Tuple):
            decl.mark_unknown("middleware", self.py.loc(value))
            return
        for element in node.elts[:MAX_ITEMS]:
            item = self._resolve_node(element)
            if not isinstance(item, ast.Call):
                decl.mark_unknown("middleware", self.py.loc(element))
                continue
            name = _callee_name(item) or "middleware"
            decl.tags.add(f"middleware:{name}")
            if name != "HumanInTheLoopMiddleware":
                continue
            interrupt = next(
                (kw.value for kw in item.keywords if kw.arg == "interrupt_on"),
                item.args[0] if item.args else None,
            )
            config = literal(interrupt, self.py.consts) if interrupt is not None else NON_LITERAL
            if not isinstance(config, dict):
                decl.gate, decl.gate_source = (
                    ApprovalGate.CONDITIONAL,
                    "human-in-the-loop middleware (non-literal)",
                )
                decl.mark_unknown("interrupt_on", self.py.loc(item))
                continue
            for tool, setting in sorted(config.items()):
                gate = (
                    ApprovalGate.REQUIRED
                    if setting is True or isinstance(setting, dict)
                    else ApprovalGate.NONE
                )
                decl.tool_gates[tool] = gate
            decl.tags.add("approval:human-in-the-loop")

    def _function_choice(self, decl: _Decl, value: ast.expr) -> None:
        """Semantic Kernel ``FunctionChoiceBehavior.Auto(auto_invoke=False)`` / ``NoneInvoke()``: no automatic calls."""
        loc = self.py.loc(value)
        if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
            decl.mark_unknown("function_choice_behavior", loc)
            return
        kind = value.func.attr
        auto = next(
            (literal(kw.value, self.py.consts) for kw in value.keywords if kw.arg == "auto_invoke"), True
        )
        decl.tags.add(f"function-choice:{kind}")
        if kind == "NoneInvoke" or auto is False:
            decl.gate, decl.gate_source = ApprovalGate.CONDITIONAL, "functions are not invoked automatically"
        elif auto is True:
            decl.gate, decl.gate_source = ApprovalGate.NONE, f"FunctionChoiceBehavior.{kind} auto-invokes"
        else:
            decl.mark_unknown("function_choice_behavior", loc)

    # ---------------------------------------------------------------------------------------- Claude sub-agents

    def _claude_agents(self, decl: _Decl, value: ast.expr) -> None:
        py = self.py
        node = self._resolve_node(value)
        loc = py.loc(value)
        if not isinstance(node, ast.Dict):
            decl.mark_unknown("agents", loc)
            return
        for key_node, val in zip(node.keys, node.values, strict=True):
            name = _short(literal(key_node, py.consts)) if key_node is not None else None
            if name is None:
                decl.mark_unknown("agents", py.loc(val))
                continue
            target = self._resolve_node(val)
            if isinstance(val, ast.Name) and isinstance(target, ast.Name):
                calls = py.var_calls.get(val.id, [])
                target = calls[0] if len(calls) == 1 else target
            sub = _Decl(
                framework="claude-agent-sdk",
                name=name,
                display=py.display,
                locator=py.loc(val),
                key=f"{decl.key}/agents/{name}",
                parent=decl.key,
                order=(py.display, val.lineno, val.col_offset),
                tags={"kind:subagent"},
            )
            self.run.add(sub)
            spec = _match_ctor(py.qualname(target.func)) if isinstance(target, ast.Call) else None
            if isinstance(target, ast.Call) and spec is not None and spec.kind == "subagent":
                py.node_keys[id(target)] = sub.key
                self._fill(target, spec, sub)
            elif isinstance(target, ast.Dict):
                lit = literal(target, py.consts)
                if not isinstance(lit, dict):
                    sub.mark_unknown("definition", py.loc(target))
                else:
                    self._claude_dict_agent(sub, lit, py.loc(target))
            elif isinstance(val, ast.Name | ast.Attribute) and "." in (py.qualname(val) or ""):
                # an ``AgentDefinition`` imported from another module: merged into this sub-agent once every
                # file is read (it inherits this options' permission settings)
                self.run.pending_defs.append((sub.key, py.qualname(val) or ""))
            else:
                sub.mark_unknown("definition", py.loc(val))
            decl.delegates.append(_Ref(py.loc(val), "subagent", key=sub.key))

    def _claude_dict_agent(self, sub: _Decl, lit: Mapping[str, Any], loc: str) -> None:
        sub.description = _short(lit.get("description"), MAX_DESCRIPTION_CHARS)
        if isinstance(lit.get("prompt"), str) and lit["prompt"]:
            sub.prompts.append(_Prompt("prompt", lit["prompt"], loc))
        if isinstance(lit.get("tools"), list):
            sub.base_tools = _safe_names(self.run, sub, lit["tools"])
        if isinstance(lit.get("disallowedTools"), list):
            sub.disallowed = _safe_names(self.run, sub, lit["disallowedTools"])
        if isinstance(lit.get("model"), str):
            self._add_model(sub, lit["model"], "primary", loc, hosted=False)
        mode = lit.get("permissionMode")
        if isinstance(mode, str) and mode in _CLAUDE_MODES:
            sub.permission_mode = mode
            sub.tags.add(f"permission-mode:{mode}")

    # ---------------------------------------------------------------------------------------- MCP servers

    def _mcp_list(self, decl: _Decl, value: ast.expr, fieldname: str = "mcp_servers") -> None:
        node = self._resolve_node(value)
        items = list(node.elts) if isinstance(node, ast.List | ast.Tuple) else [node]
        if len(items) > MAX_ITEMS:
            decl.mark_unknown(fieldname, self.py.loc(value))
        for item in items[:MAX_ITEMS]:
            if not self._mcp_item(decl, item):
                decl.mark_unknown(fieldname, self.py.loc(item))

    def _mcp_item(self, decl: _Decl, item: ast.expr) -> bool:
        """Attach the MCP server ``item`` builds (a constructor call, or a variable bound to one); ``False`` when
        ``item`` is not a recognised server constructor. A recognised one without a literal command or URL makes
        the agent's MCP servers unknown (tag ``mcp-server:non-literal``)."""
        target = self._resolve_node(item)
        if isinstance(item, ast.Name) and not isinstance(target, ast.Call):
            calls = self.py.var_calls.get(item.id, [])
            target = calls[0] if len(calls) == 1 else target
        spec = _match_ctor(self.py.qualname(target.func)) if isinstance(target, ast.Call) else None
        if not isinstance(target, ast.Call) or spec is None or spec.kind not in ("mcp", "mcp-multi"):
            return False
        servers = self._servers_from_call(target, spec)
        if servers:
            decl.servers.extend(servers)
        else:
            decl.mark_unknown("mcp_servers", self.py.loc(item))
            decl.tags.add("mcp-server:non-literal")
        return True

    def _mcp_map(self, decl: _Decl | None, value: ast.expr) -> list[str]:
        """``{"name": {command|url …}}`` (Claude ``mcp_servers``, LangChain ``MultiServerMCPClient``)."""
        py = self.py
        node = self._resolve_node(value)
        loc = py.loc(value)
        keys: list[str] = []
        lit = literal(node, py.consts)
        if isinstance(lit, str):
            if decl is not None:
                decl.tags.add("mcp-config-file")
                decl.mark_unknown("mcp_servers", loc)
            return keys
        if not isinstance(node, ast.Dict):
            if decl is not None:
                decl.mark_unknown("mcp_servers", loc)
            return keys
        framework = decl.framework if decl is not None else "langchain"
        for key_node, val in zip(node.keys, node.values, strict=True):
            name = _short(literal(key_node, py.consts)) if key_node is not None else None
            entry = literal(val, py.consts)
            target = self._resolve_node(val)
            if name is not None and isinstance(entry, dict):
                keys.append(self._server(framework, name, entry, py.loc(val), py.display))
            elif (
                name is not None
                and isinstance(target, ast.Call)
                and _callee_name(target) == "create_sdk_mcp_server"
            ):
                keys.append(self._sdk_server(framework, name, target))
            elif (
                name is not None and isinstance(target, ast.Dict) and (server := self._partial_entry(target))
            ):
                server_key = self._server(framework, name, server[0], py.loc(val), py.display)
                if server[1]:
                    self.run.servers[server_key].tags.add(f"unknown:{server[1]}")
                keys.append(server_key)
            elif decl is not None:
                decl.mark_unknown("mcp_servers", py.loc(val))
        if decl is not None:
            decl.servers.extend(keys)
        return keys

    def _partial_entry(self, node: ast.Dict) -> tuple[dict[str, Any], str | None] | None:
        """A server entry dict with some non-literal values: its literal command/URL and header/env names."""
        entry: dict[str, Any] = {}
        meta: dict[str, Any] = {}
        self._mcp_dict(node, entry, meta)
        if not entry.get("command") and not entry.get("url"):
            return None
        return entry, meta.get("unknown")

    def _sdk_server(self, framework: str, name: str, call: ast.Call) -> str:
        py = self.py
        key = self._server(framework, name, {}, py.loc(call), py.display, in_process=True)
        tools = next((kw.value for kw in call.keywords if kw.arg == "tools"), None)
        server = self.run.servers[key]
        if isinstance(tools, ast.List | ast.Tuple):
            for item in tools.elts[:MAX_ITEMS]:
                if isinstance(item, ast.Name):
                    info = py.tool_funcs.get(item.id)
                    server.tools.append(info.name if info else item.id)
        return key

    def _servers_from_call(self, call: ast.Call, spec: PyCtor) -> list[str]:
        py = self.py
        key = self._node_key(call)
        if key in self.run.servers:
            return [key]
        if spec.kind == "mcp-multi":
            arg = next(
                (kw.value for kw in call.keywords if kw.arg == "connections"),
                call.args[0] if call.args else None,
            )
            return self._mcp_map(None, arg) if arg is not None else []
        entry: dict[str, Any] = {}
        meta: dict[str, Any] = {}
        self._collect_mcp(call, entry, meta, 0)
        if entry.get("command"):
            entry.pop("type", None)
        name = (
            _short(meta.get("name"))
            or py.assigned.get(id(call))
            or (_short(_url_host(entry["url"])) if isinstance(entry.get("url"), str) else None)
            or self._safe_value(None, _package_label(entry))
            or "mcp"
        )
        if not entry.get("command") and not entry.get("url"):
            if key not in self.run.failed_servers:
                self.run.failed_servers.add(key)
                self.run.result.warnings.append(
                    f"{py.loc(call)}: MCP server with no literal command or URL; not recorded"
                )
            return []
        self._server(spec.framework, name, entry, py.loc(call), py.display, key=key)
        server = self.run.servers[key]
        if meta.get("unknown"):
            server.tags.add(f"unknown:{meta['unknown']}")
        if "approval" in meta:
            server.gate, server.gate_source = meta["approval"]
            server.flags[f"{spec.framework}.approval"] = server.gate.value
        if isinstance(meta.get("tools"), list):
            server.tools.extend(t for t in meta["tools"] if isinstance(t, str))
        return [key]

    def _collect_mcp(self, node: ast.AST, entry: dict[str, Any], meta: dict[str, Any], depth: int) -> None:
        """Gather ``command``/``args``/``env``/``url``/``headers`` from a server constructor and nested params."""
        py = self.py
        if depth > 4:
            return
        if isinstance(node, ast.Lambda):
            self._collect_mcp(node.body, entry, meta, depth + 1)
            return
        if (target := py.consts.target(node)) is not None:
            self._collect_mcp(target, entry, meta, depth + 1)
            return
        if isinstance(node, ast.Dict):
            self._mcp_dict(node, entry, meta)
            return
        if not isinstance(node, ast.Call):
            return
        fields = _MCP_FIELDS
        lower = (_callee_name(node) or "").lower()
        for marker, kind in (
            ("sse", "sse"),
            ("websocket", "websocket"),
            ("streamable", "http"),
            ("http", "http"),
        ):
            if marker in lower:
                entry.setdefault("type", kind)
                break
        if node.args:
            first = literal(node.args[0], py.consts)
            if isinstance(first, str):
                key = "url" if first.startswith(("http://", "https://", "ws://", "wss://")) else "command"
                entry.setdefault(key, first)
            elif isinstance(node.args[0], ast.Call | ast.Lambda | ast.Dict | ast.Name):
                self._collect_mcp(node.args[0], entry, meta, depth + 1)
        for kw in node.keywords:
            role = fields.get(kw.arg or "")
            if role is None:
                continue
            lit = literal(kw.value, py.consts)
            if role == "mcp-entry":
                self._collect_mcp(kw.value, entry, meta, depth + 1)
            elif role == "mcp-name" and isinstance(lit, str):
                meta.setdefault("name", lit)
            elif role == "approval":
                if isinstance(kw.value, ast.Lambda | ast.Name | ast.Attribute) and lit is NON_LITERAL:
                    meta.setdefault("approval", (ApprovalGate.CONDITIONAL, kw.arg or "approval"))
                else:
                    meta.setdefault("approval", (_gate_from(lit), kw.arg or "approval"))
            elif role == "tool-filter" and isinstance(lit, list):
                meta.setdefault("tools", lit)
            elif role.startswith("mcp-") and lit is not NON_LITERAL:
                entry.setdefault(role.split("-", 1)[1], lit)
            elif role.startswith("mcp-"):
                meta.setdefault("unknown", kw.arg)

    def _mcp_dict(self, node: ast.Dict, entry: dict[str, Any], meta: dict[str, Any]) -> None:
        """A server parameter dict read key by key: literal parts are kept even when others are not (an
        ``Authorization`` header built with an f-string keeps the URL; its value is recorded as non-literal)."""
        py = self.py
        values: dict[str, Any] = {}
        for key_node, value_node in zip(node.keys, node.values, strict=True):
            key = literal(key_node, py.consts) if key_node is not None else NON_LITERAL
            if not isinstance(key, str):
                meta.setdefault("unknown", "params")
                continue
            value = literal(value_node, py.consts)
            if value is NON_LITERAL and key in ("headers", "env") and isinstance(value_node, ast.Dict):
                value = self._names_only(value_node, meta)
            if value is NON_LITERAL and key == "require_approval":
                dynamic = isinstance(value_node, ast.Lambda | ast.Name | ast.Attribute)
                meta.setdefault(
                    "approval", (ApprovalGate.CONDITIONAL if dynamic else ApprovalGate.UNKNOWN, key)
                )
            elif value is NON_LITERAL:
                meta.setdefault("unknown", key)
            else:
                values[key] = value
        for key in ("command", "args", "env", "url", "headers", "type", "transport"):
            if key in values:
                entry.setdefault(key, values[key])
        if "server_url" in values:
            entry.setdefault("url", values["server_url"])
        for key in ("server_label", "name"):
            if isinstance(values.get(key), str):
                meta.setdefault("name", values[key])
        if "require_approval" in values:
            meta.setdefault("approval", (_gate_from(values["require_approval"]), "require_approval"))
        if isinstance(values.get("allowed_tools"), list):
            meta.setdefault("tools", values["allowed_tools"])

    def _names_only(self, node: ast.Dict, meta: dict[str, Any]) -> dict[str, Any]:
        """Header/env names of a dict whose values are not all literal (non-literal values become a
        placeholder, so they are classified as references, never as inline secrets)."""
        out: dict[str, Any] = {}
        for key_node, value_node in zip(node.keys, node.values, strict=True):
            name = literal(key_node, self.py.consts) if key_node is not None else NON_LITERAL
            if not isinstance(name, str):
                meta.setdefault("unknown", "headers")
                continue
            value = literal(value_node, self.py.consts)
            out[name] = _NON_LITERAL_VALUE if value is NON_LITERAL else value
        return out

    def _server(
        self,
        framework: str,
        name: str,
        entry: Mapping[str, Any],
        loc: str,
        display: str,
        *,
        key: str | None = None,
        in_process: bool = False,
    ) -> str:
        key = key or f"{loc}#{name}"
        if key not in self.run.servers:
            self.run.servers[key] = _Mcp(
                key=key, framework=framework, name=name, entry=dict(entry), locator=loc, display=display,
                in_process=in_process,
            )  # fmt: skip
        return key


class _YamlTimeout(yaml.YAMLError):
    """A config file's YAML parse ran past its time share."""


class _DeadlineLoader(_BoundedSafeLoader):
    """The bounded safe loader (aliases and merge keys capped) that also stops at a deadline."""

    def __init__(self, stream: str, *, deadline: float) -> None:
        super().__init__(stream, allow_aliases=True)
        self._deadline = deadline
        self._nodes = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        self._nodes += 1
        if self._nodes % _YAML_CHECK_EVERY == 0 and time.monotonic() > self._deadline:
            raise _YamlTimeout("YAML parse exceeded its time share")
        return super().compose_node(parent, index)


def _load_yaml_until(text: str, deadline: float) -> Any:
    """:func:`load_yaml` with a deadline (raises :class:`_YamlTimeout` past it; other failures are ``YAMLError``)."""
    if time.monotonic() > deadline:
        raise _YamlTimeout("no time left for this file")
    loader = _DeadlineLoader(text, deadline=deadline)
    try:
        return loader.get_single_data()
    except yaml.YAMLError:
        raise
    except (
        KeyError,
        IndexError,
        AttributeError,
        OverflowError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise yaml.YAMLError(type(exc).__name__) from None
    finally:
        loader.dispose()


def _str_of(value: object) -> str:
    """``value`` when it is a string, else ``""``. Parsed config values are never passed to ``str()``: a YAML alias
    bomb (a list of lists sharing nodes) costs nothing to hold but its ``repr`` is exponential, in C, under the GIL."""
    return value if isinstance(value, str) else ""


def _sk_dangerous_content(decl: _Decl, data: Mapping[str, Any]) -> None:
    """Semantic Kernel ``allow_dangerously_set_content`` (no encoding of inserted values): on the function and on
    each ``input_variables`` entry, in prompt YAML and in a plugin's ``config.json``."""
    if data.get("allow_dangerously_set_content") is True:
        decl.tags.add("allow-dangerously-set-content")
    variables = data.get("input_variables")
    if not isinstance(variables, list):
        return
    for variable in variables[:MAX_ITEMS]:
        if isinstance(variable, dict) and variable.get("allow_dangerously_set_content") is True:
            decl.tags.add("allow-dangerously-set-content")
            name = _short(variable.get("name"))
            decl.tags.add(f"allow-dangerously-set-content:var:{name or 'unnamed'}")


def _policy_callback(decl: _Decl, name: str) -> None:
    """ADK ``before_tool_callback(s)`` / Strands ``interventions``: a control that runs before tool calls. It may
    block a call or only log, so the tools' approval is unknown (never claimed as a per-call gate)."""
    decl.tags.add(f"control:{name}")
    if decl.gate is None:
        decl.gate, decl.gate_source = ApprovalGate.UNKNOWN, f"policy callback may block ({name})"


def _template_style(framework: str, text: str) -> str | None:
    """Placeholder syntax a framework fills at run time (the digest covers the template, not the rendering)."""
    if framework in ("crewai", "google-adk") and re.search(r"\{[A-Za-z_][A-Za-z0-9_.?]{0,100}\}", text):
        return "braces"
    if framework == "semantic-kernel" and "{{" in text:
        return "semantic-kernel"
    return None


# --------------------------------------------------------------------------------------------- TypeScript scanner


@dataclass(slots=True)
class _TsVal:
    kind: str  # str | list | obj | call | ident | other
    value: Any
    offset: int


def _skip_ws(text: str, i: int, end: int) -> int:
    while i < end:
        ch = text[i]
        if ch in " \t\r\n":
            i += 1
        elif text.startswith("//", i):
            nl = text.find("\n", i, end)
            i = end if nl == -1 else nl + 1
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2, end)
            i = end if close == -1 else close + 2
        else:
            break
    return i


def _ts_string(text: str, i: int, end: int) -> tuple[str | None, int]:
    """A quoted string starting at ``i``; ``None`` for a template literal with ``${…}`` substitutions."""
    quote = text[i]
    out: list[str] = []
    j = i + 1
    dynamic = False
    while j < end:
        ch = text[j]
        if ch == "\\" and j + 1 < end:
            nxt = text[j + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
            j += 2
            continue
        if ch == quote:
            return (None if dynamic else "".join(out)), j + 1
        if quote == "`" and ch == "$" and j + 1 < end and text[j + 1] == "{":
            dynamic = True
        if quote != "`" and ch == "\n":
            return None, j
        out.append(ch)
        j += 1
    return None, end


def _ts_skip_value(text: str, i: int, end: int) -> int:
    """Skip an arbitrary expression up to the next top-level ``,`` or closing bracket (linear)."""
    depth = 0
    while i < end:
        ch = text[i]
        if ch in "'\"`":
            _, i = _ts_string(text, i, end)
            continue
        if text.startswith("//", i) or text.startswith("/*", i):
            i = _skip_ws(text, i, end)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif ch == "," and depth == 0:
            return i
        i += 1
    return end


def _ts_value(text: str, i: int, end: int, depth: int) -> tuple[_TsVal, int]:
    i = _skip_ws(text, i, end)
    if i >= end:
        return _TsVal("other", None, i), i
    ch = text[i]
    start = i
    if ch in "'\"`":
        value, j = _ts_string(text, i, end)
        return (_TsVal("str", value, start) if value is not None else _TsVal("other", None, start)), j
    if ch == "{" and depth < MAX_TS_DEPTH:
        props, j = ts_object(text, i, end, depth + 1)
        if props is not None:
            return _TsVal("obj", props, start), j
    if ch == "[" and depth < MAX_TS_DEPTH:
        items: list[_TsVal] = []
        j = i + 1
        while j < end:
            j = _skip_ws(text, j, end)
            if j < end and text[j] == "]":
                return _TsVal("list", items, start), j + 1
            item, j = _ts_value(text, j, end, depth + 1)
            j = _ts_skip_value(text, j, end) if item.kind == "other" else _skip_ws(text, j, end)
            items.append(item)
            if j < end and text[j] == ",":
                j += 1
            elif j < end and text[j] != "]":
                break
        return _TsVal("other", None, start), _ts_skip_value(text, j, end)
    m = _TS_IDENT.match(text, i, end)
    if m is not None:
        j = _skip_ws(text, m.end(), end)
        if j < end and text[j] == "(":
            arg, k = _ts_value(text, j + 1, end, depth + 1)
            k = _skip_ws(text, k, end)
            if k < end and text[k] == ")":
                return _TsVal("call", (m.group(0), arg), start), k + 1
            return _TsVal("other", None, start), _ts_skip_value(text, k, end)
        nxt = j
        if nxt < end and text[nxt] in ",}]":
            return _TsVal("ident", m.group(0), start), nxt
    return _TsVal("other", None, start), _ts_skip_value(text, i, end)


def ts_object(
    text: str, i: int, end: int | None = None, depth: int = 0
) -> tuple[dict[str, _TsVal] | None, int]:
    """Parse the object literal whose ``{`` is at ``i``: ``{key: value, shorthand, ...}`` (values kept shallow).

    Linear in the input: every character is consumed once; nesting is capped at :data:`MAX_TS_DEPTH`.
    """
    end = min(len(text), end if end is not None else i + MAX_TS_WINDOW)
    if i >= end or text[i] != "{":
        return None, i
    props: dict[str, _TsVal] = {}
    j = i + 1
    while j < end:
        j = _skip_ws(text, j, end)
        if j >= end:
            break
        ch = text[j]
        if ch == "}":
            return props, j + 1
        if ch == ",":
            j += 1
            continue
        if text.startswith("...", j):
            props.setdefault("...", _TsVal("other", None, j))
            j = _ts_skip_value(text, j + 3, end)
            continue
        if ch in "'\"":
            key, j = _ts_string(text, j, end)
        else:
            m = _TS_IDENT.match(text, j, end)
            if m is None:
                j = _ts_skip_value(text, j + 1, end)
                continue
            key, j = m.group(0), m.end()
        j = _skip_ws(text, j, end)
        if j < end and text[j] == ":" and key is not None:
            value, j = _ts_value(text, j + 1, end, depth)
            props[key] = value
            j = _skip_ws(text, j, end)
            if j < end and text[j] not in ",}":
                j = _ts_skip_value(text, j, end)
        elif key is not None and j < end and text[j] in ",}":
            props[key] = _TsVal("ident", key, j)
        else:
            j = _ts_skip_value(text, j, end)
    return None, end


#: ``const x = …`` / ``let x: T = await …``: the variable a TypeScript expression is bound to (linear: every
#: quantifier is bounded or separated by a fixed token).
_TS_BINDING: Final = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]{0,200})\s{0,20}(?::[^=;\n]{0,200})?=\s{0,20}(?:await\s{1,20})?"
)
#: Mastra ``createTool({…})`` and Vercel AI SDK ``tool({…})`` tool definitions.
_TS_TOOL_DEF: Final = re.compile(r"\b(?:createTool|tool)\s*\(\s*\{")
_TS_TOOL_FACTORIES: Final = frozenset({"createTool", "tool"})


def _ts_key(display: str, line: int, brace: int) -> str:
    return f"{display}:{line}:{brace}"


def _ts_gate(props: Mapping[str, _TsVal]) -> tuple[ApprovalGate | None, str | None]:
    """Mastra ``requireApproval`` / Vercel ``needsApproval`` on a tool definition (``None``: not set)."""
    for key in ("requireApproval", "needsApproval"):
        value = props.get(key)
        if value is None:
            continue
        if value.kind == "ident" and value.value in ("true", "false"):
            return (
                ApprovalGate.REQUIRED if value.value == "true" else ApprovalGate.NONE
            ), f"{key}={value.value}"
        return ApprovalGate.CONDITIONAL, f"{key} decided per call"
    if "..." in props:
        return ApprovalGate.UNKNOWN, "tool definition has a spread"
    return None, None


@dataclass(slots=True)
class _TsFile:
    """One TypeScript/JavaScript file: text, line table and the variables bound to agents and tools."""

    display: str
    text: str
    newlines: list[int]
    #: expression start offset -> the variable it is assigned to
    bindings: dict[int, str]
    #: variable -> key of the agent declared by the call bound to it
    agent_keys: dict[str, str] = field(default_factory=dict)
    #: variable -> approval setting of the ``createTool``/``tool`` definition bound to it
    tool_defs: dict[str, tuple[ApprovalGate | None, str | None]] = field(default_factory=dict)

    @classmethod
    def index(cls, display: str, text: str) -> _TsFile:
        newlines: list[int] = []
        at = text.find("\n")
        while at != -1:
            newlines.append(at)
            at = text.find("\n", at + 1)
        bindings = {m.end(): m.group(1) for m in _TS_BINDING.finditer(text)}
        tsf = cls(display=display, text=text, newlines=newlines, bindings=bindings)
        for count, match in enumerate(_TS_TOOL_DEF.finditer(text)):
            if count >= MAX_TS_MATCHES:
                break
            var = bindings.get(match.start())
            if var is None or var in tsf.tool_defs:
                continue
            props, _ = ts_object(text, match.end() - 1)
            tsf.tool_defs[var] = (
                _ts_gate(props) if props is not None else (ApprovalGate.UNKNOWN, "tool definition not parsed")
            )
        return tsf

    def line(self, offset: int) -> int:
        """1-based line of ``offset`` (binary search over the newline table; linear overall)."""
        return bisect.bisect_left(self.newlines, offset) + 1


def _ts_tool_gate(value: _TsVal, tsf: _TsFile) -> tuple[ApprovalGate | None, str | None]:
    """Approval setting of a tool in an agent's ``tools`` object; ``UNKNOWN`` when its definition is not here."""
    if value.kind == "ident":
        found = tsf.tool_defs.get(str(value.value))
        return (
            found
            if found is not None
            else (ApprovalGate.UNKNOWN, "tool definition not read (defined elsewhere)")
        )
    if value.kind == "call" and value.value[0] in _TS_TOOL_FACTORIES and value.value[1].kind == "obj":
        return _ts_gate(value.value[1].value)
    return ApprovalGate.UNKNOWN, "tool definition not read"


# --------------------------------------------------------------------------------------------- collector


class FrameworksCollector(BaseCollector):
    """Agents, prompts, models, tools, sub-agents and approval settings declared with agent frameworks."""

    name = "frameworks"
    version = "0.1.0"
    surfaces = (Surface.CODE,)
    mode = CollectorMode.DECLARED

    def detect(self, ctx: CollectContext) -> bool:
        del ctx
        return True  # "no framework agents here" is itself a recorded fact (queried, 0 items)

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        start = time.monotonic()
        code_seconds = ctx.budget_seconds * CODE_TIME_SHARE
        run = _Run(
            ctx=ctx,
            result=result,
            deadline=start + code_seconds,
            file_seconds=code_seconds * FILE_TIME_SHARE,
            emit_deadline=start + ctx.budget_seconds * EMIT_TIME_SHARE,
            link_deadline=start + ctx.budget_seconds * LINK_TIME_SHARE,
        )
        report = WalkReport()
        py_files: list[Path] = []
        ts_files: list[Path] = []
        configs: list[Path] = []
        sk_prompts: list[Path] = []
        for path in ctx.walk(report=report):
            name = path.name
            if path.suffix in _CODE_SUFFIXES:
                py_files.append(path)
            elif path.suffix in _TS_SUFFIXES and not name.endswith(".d.ts"):
                ts_files.append(path)
            elif name == "langgraph.json" or name in _OAI_CONFIG or path.suffix in _YAML_SUFFIXES:
                configs.append(path)
            elif name == _SK_SKPROMPT:
                sk_prompts.append(path)
        result.record_walk(Surface.CODE, report, source="frameworks:repo-walk")
        run.truncated = (
            report.truncated_at is not None
        )  # the walk's position is kept, never reset by a later cut
        self._symlinks(run, report)
        self._excluded(run, report)
        self._python(run, py_files)
        self._typescript(run, ts_files)
        self._configs(run, configs)
        self._sk_plugins(run, sk_prompts)
        self._resolve(run)
        self._emit(run)
        if run.redacted:
            result.redactions.append(
                Redaction(
                    redaction_class=RedactionClass.CREDENTIAL_SHAPED_TOKEN.value,
                    count=run.redacted,
                    applied_by=self.ref,
                    applied_at=ctx.now,
                    ids=sorted(run.redacted_ids),
                )
            )
        return result

    # ----------------------------------------------------------------------------------------- reading

    @staticmethod
    def _symlinks(run: _Run, report: WalkReport) -> None:
        """Symlinks are never followed by the walk: a linked framework file or directory is a coverage gap."""
        flagged = 0
        for display in report.symlink_paths:
            path = PurePosixPath(display)
            relevant = (
                path.suffix in _CODE_SUFFIXES | _TS_SUFFIXES | _YAML_SUFFIXES
                or path.name in _OAI_CONFIG | {"langgraph.json", _SK_SKPROMPT}
                or _is_dir(run.ctx.root / display)  # a linked directory may hold any of them
            )
            if relevant:
                flagged += 1
                run.result.add_source(
                    Surface.CODE, "frameworks:repo-walk", locator=display, ok=False,
                    error_class="symlink-not-followed",
                )  # fmt: skip
        unlisted = report.symlinks - len(report.symlink_paths)
        if unlisted > 0:
            flagged += unlisted
            run.result.add_source(
                Surface.CODE, "frameworks:repo-walk", locator=".", ok=False, error_class="symlink-not-followed",
                items=unlisted,
            )  # fmt: skip
        if flagged:
            run.result.warnings.append(
                f"{flagged} symlinked file(s) or director(ies) that may hold framework definitions were not followed"
            )

    @staticmethod
    def _excluded(run: _Run, report: WalkReport) -> None:
        """Directories the walk skips by policy (``build``, ``dist``, environments, VCS): a build or dist
        directory that holds framework code is a coverage gap (its agents are not read); the rest are counted."""
        flagged = 0
        for display in report.excluded_paths:
            path = run.ctx.root / display
            if PurePosixPath(display).name in _BUILD_DIRS and _has_framework_code(path, run.ctx.root):
                flagged += 1
                run.result.add_source(
                    Surface.CODE,
                    "frameworks:repo-walk",
                    locator=display,
                    ok=False,
                    error_class="excluded-dir",
                )
        if flagged:
            run.result.warnings.append(
                f"{flagged} excluded build/dist director(ies) hold framework code that was not read"
            )

    def _budget(self, run: _Run, files: Sequence[Path], index: int, parsed: int, parsed_bytes: int) -> bool:
        if (
            parsed >= MAX_CODE_FILES
            or parsed_bytes >= MAX_CODE_BYTES
            or run.config_bytes >= MAX_CODE_BYTES
            or time.monotonic() > run.deadline
            or run.full()
        ):
            run.truncate(run.ctx.display(files[index]), "frameworks:code-budget", len(files) - index, index)
            return False
        return True

    def _guarded(self, run: _Run, path: Path, source: str, handler: Callable[[], None]) -> None:
        """Run one file's handler; an unexpected error is that file's coverage failure, never the collector's.

        Only the error class is recorded: exception messages can carry absolute paths or scanned values.
        """
        decls, servers = len(run.decls), len(run.servers)
        try:
            handler()
        except Exception:  # any failure on hostile input stays inside this file's coverage record
            # forget what the file declared before it failed (dicts keep insertion order: new keys are last)
            for key in list(itertools.islice(run.decls, decls, None)):
                del run.decls[key]
            for key in list(itertools.islice(run.servers, servers, None)):
                del run.servers[key]
            run.root_servers[:] = [k for k in run.root_servers if k in run.servers]
            run.fail(run.ctx.display(path), "parse-error", source)

    def _read(self, run: _Run, path: Path, source: str) -> bytes | None:
        display = run.ctx.display(path)
        try:
            size = path.stat().st_size
        except OSError:
            run.fail(display, "unreadable", source)
            return None
        if size > MAX_SOURCE_BYTES:
            run.fail(display, "too-large", source)
            return None
        outcome = read_bounded(path, MAX_SOURCE_BYTES, root=run.ctx.root)
        if not outcome.ok or outcome.data is None:
            run.fail(display, outcome.error_class or "unreadable", source)
            return None
        return outcome.data

    def _python(self, run: _Run, files: list[Path]) -> None:
        parsed = parsed_bytes = 0
        for index, path in enumerate(files):
            if not self._budget(run, files, index, parsed, parsed_bytes):
                return
            data = self._read(run, path, "frameworks:python")
            if data is None:
                continue
            if not any(hint in data for hint in _PY_HINTS):
                continue
            parsed += 1
            parsed_bytes += len(data)
            display = run.ctx.display(path)
            reader: _PythonReader | None = None
            try:
                tree = ast.parse(data.decode("utf-8", errors="replace"), filename=path.name)
                py = _index_python(display, tree)
                if not any(_framework_package(q) for q in py.imports.values()):
                    continue
                reader = _PythonReader(run, py, self.ref)
                items = reader.read()
            except (
                Exception
            ):  # hostile input: this file's coverage failure (error class only), never the scan's
                if reader is not None:
                    reader._drop_file()  # never half-described
                run.fail(display, "parse-error", "frameworks:python")
                continue
            if reader.truncated is not None:  # the file used up its time share: reported, not half-described
                run.truncate(display, "frameworks:python", reader.truncated)
                continue
            if not items and not reader.understood():
                run.result.add_source(
                    Surface.CODE, "frameworks:python", locator=display, ok=False, error_class="not-understood"
                )
                run.result.warnings.append(
                    f"{display}: imports {', '.join(reader.frameworks())} but no recognised constructor with "
                    "literal configuration; facts unknown"
                )
                continue
            run.result.add_source(Surface.CODE, "frameworks:python", locator=display, ok=True, items=items)

    def _typescript(self, run: _Run, files: list[Path]) -> None:
        for index, path in enumerate(files):
            if not self._budget(run, files, index, 0, 0):
                return
            self._guarded(run, path, "frameworks:typescript", partial(self._ts_file, run, path))

    def _ts_file(self, run: _Run, path: Path) -> None:
        data = self._read(run, path, "frameworks:typescript")
        if data is None:
            return
        text = data.decode("utf-8", errors="replace")
        frameworks = sorted({fw for m in _TS_IMPORT.finditer(text) if (fw := _ts_framework(m.group(1)))})
        if not frameworks:
            return
        tsf = _TsFile.index(run.ctx.display(path), text)
        display = tsf.display
        # every recognised call, in text order; agents bound to a variable get their key up front so that a
        # sub-agent written as ``agents: { researcher }`` links to the agent declared in this file
        calls: list[tuple[int, str]] = []
        for framework in frameworks:
            pattern = _TS_CALLS.get(framework)
            if pattern is not None:
                for match in pattern.finditer(text):
                    brace = match.end() - 1
                    calls.append((brace, framework))
                    var = tsf.bindings.get(match.start())
                    if var is not None:
                        tsf.agent_keys.setdefault(var, _ts_key(display, tsf.line(brace), brace))
        calls.sort()
        deadline = min(run.deadline, time.monotonic() + run.file_seconds)
        scan_budget = 4 * len(text) + MAX_TS_WINDOW
        items = 0
        for index, (brace, framework) in enumerate(calls):
            if index >= MAX_TS_MATCHES or scan_budget <= 0 or time.monotonic() > deadline or run.full():
                run.truncate(display, "frameworks:typescript", len(calls) - index)
                break
            count, end = self._ts_call(run, framework, tsf, brace)
            items += count
            scan_budget -= max(end - brace, 1)  # bounds the total scanned at a few times the file size
        if not items and (calls or any(_TS_CTOR_NAMES[fw].search(text) for fw in frameworks)):
            if calls and all(fw == "vercel-ai-sdk" for _, fw in calls):
                # plain generateText/streamText model calls (no tools): understood, and not an agent
                run.result.add_source(Surface.CODE, "frameworks:typescript", locator=display, ok=True)
                return
            # a constructor is named but none was read (built through Reflect, a wrapper, an alias …)
            run.result.add_source(
                Surface.CODE, "frameworks:typescript", locator=display, ok=False, error_class="not-understood"
            )
            run.result.warnings.append(
                f"{display}: imports {', '.join(frameworks)} but no recognised constructor with a literal "
                "configuration; facts unknown"
            )
            return
        run.result.add_source(Surface.CODE, "frameworks:typescript", locator=display, ok=True, items=items)

    def _ts_call(self, run: _Run, framework: str, tsf: _TsFile, brace: int) -> tuple[int, int]:
        """Read one constructor call; returns (agents recorded, end offset scanned)."""
        text, display = tsf.text, tsf.display
        props, end = ts_object(text, brace)
        line = tsf.line(brace)
        loop_call = text[max(0, brace - 40) : brace].rstrip(" \t\r\n(").endswith("Agent")
        if framework == "vercel-ai-sdk" and not loop_call and (props is None or "tools" not in props):
            return 0, end  # a single generateText/streamText call without tools is a model call

        loc = f"{display}:{line}"
        key = _ts_key(display, line, brace)
        decl = _Decl(
            framework=framework, name="", display=display, locator=loc, key=key, order=(display, line, brace)
        )
        decl.crew_scope = display
        if props is None:
            decl.name = f"{PurePosixPath(display).stem}-L{line}"
            decl.tags.add("name-from:location")
            for fieldname in ("instructions", "model", "tools"):
                decl.mark_unknown(fieldname, loc)
            run.add(decl)
            return 1, end
        if framework == "claude-agent-sdk":
            options = props.get("options")
            if options is None or options.kind != "obj":
                decl.mark_unknown("options", loc)
                props = {}
            else:
                props = options.value
        self._ts_fill(run, decl, props, tsf)
        if not decl.name:
            decl.name = f"{PurePosixPath(display).stem}-L{line}"
            decl.tags.add("name-from:location")
        run.add(decl)
        return 1, end

    def _ts_fill(self, run: _Run, decl: _Decl, props: Mapping[str, _TsVal], tsf: _TsFile) -> None:
        def where(v: _TsVal) -> str:
            return f"{decl.display}:{tsf.line(v.offset)}"

        if "..." in props:
            decl.mark_unknown("spread", where(props["..."]))
            decl.tags.add("partial-definition")
        for key in ("name", "id"):
            v = props.get(key)
            if v is not None and v.kind == "str" and _short(v.value):
                decl.name = decl.name or str(v.value)
        desc = props.get("description")
        if desc is not None and desc.kind == "str":
            decl.description = _short(desc.value, MAX_DESCRIPTION_CHARS)
        for key in ("instructions", "systemPrompt", "system", "prompt"):
            v = props.get(key)
            if v is None or (key == "prompt" and decl.framework != "claude-agent-sdk"):
                continue
            if v.kind == "str" and v.value:
                decl.prompts.append(_Prompt(key, v.value, where(v)))
            elif (
                v.kind == "obj"
                and isinstance(v.value.get("append"), _TsVal)
                and v.value["append"].kind == "str"
            ):
                decl.prompts.append(_Prompt(f"{key}_append", v.value["append"].value, where(v)))
                decl.tags.add("system-prompt:preset")
            else:
                decl.mark_unknown(key, where(v))
        for key, role in (("model", "primary"), ("fallbackModel", "fallback")):
            v = props.get(key)
            if v is None:
                continue
            if v.kind == "str":
                decl.models.append(
                    _ModelRef(
                        v.value,
                        role,
                        where(v),
                        hosted_owned=key in _TS_HOSTED_KEYS,
                        js=True,
                        context=_MODEL_CONTEXT.get(decl.framework),
                    )
                )
            elif v.kind == "call" and v.value[1].kind == "str":
                factory = v.value[0]
                decl.models.append(
                    _ModelRef(
                        v.value[1].value,
                        role,
                        where(v),
                        hosted_owned=False,
                        provider=_TS_PROVIDER_FACTORIES.get(factory),
                        js=True,
                    )
                )
            else:
                decl.mark_unknown("model", where(v))
        approvals = self._ts_tool_approval(decl, props.get("toolApproval"), where)
        tools = props.get("tools")
        if tools is not None and decl.framework == "claude-agent-sdk" and tools.kind == "obj":
            preset = tools.value.get("preset")
            if preset is not None and preset.kind == "str" and preset.value == "claude_code":
                decl.tags.add("tools:preset:claude_code")
            else:
                decl.mark_unknown("tools", where(tools))
        elif tools is not None:
            if tools.kind == "obj":
                for tname, tval in sorted(tools.value.items()):
                    if tname == "...":
                        continue
                    if _short(tname) is None:
                        run.redact(decl)
                        continue
                    tool = _Tool(tname, where(tval))
                    tool.gate, tool.gate_source = approvals.get(tname) or _ts_tool_gate(tval, tsf)
                    decl.tools.append(tool)
            elif tools.kind == "list":
                names: list[str] = []
                for item in tools.value:
                    if item.kind in ("str", "ident") and _short(item.value):
                        names.append(str(item.value))
                        decl.tools.append(_Tool(str(item.value), where(item)))
                    elif item.kind == "str" and isinstance(item.value, str) and looks_like_secret(item.value):
                        run.redact(decl)
                    else:
                        decl.mark_unknown("tools", where(item))
                if decl.framework == "claude-agent-sdk":  # a sub-agent's tools are its available set
                    decl.base_tools, decl.tools = names, []
            else:
                decl.mark_unknown("tools", where(tools))
        for key, attr in (("allowedTools", "allowed"), ("disallowedTools", "disallowed")):
            v = props.get(key)
            if v is not None and v.kind == "list":
                names = _safe_names(run, decl, [i.value for i in v.value if i.kind == "str"])
                if attr == "allowed":
                    decl.allowed = names
                else:
                    decl.disallowed = names
            elif v is not None:
                decl.mark_unknown(key, where(v))
        mode = props.get("permissionMode")
        if mode is not None and mode.kind == "str" and mode.value in _CLAUDE_MODES:
            decl.permission_mode = mode.value
            decl.tags.add(f"permission-mode:{mode.value}")
            if mode.value == "bypassPermissions":
                decl.tags.add("approval-bypass:permission_mode")
        elif mode is not None:
            decl.mode_unknown = True
            decl.mark_unknown("permissionMode", where(mode))
        skip = props.get("allowDangerouslySkipPermissions")
        if skip is not None and skip.kind == "ident" and skip.value == "true":
            decl.tags.add("approval-bypass:allowDangerouslySkipPermissions")
        if "canUseTool" in props:
            decl.gate, decl.gate_source = ApprovalGate.CONDITIONAL, "programmatic approval callback"
        agents = props.get("agents")
        if agents is not None and agents.kind == "obj":
            for aname, aval in sorted(agents.value.items()):
                if aname == "..." or not _short(aname):
                    continue
                ref_mode = "subagent" if decl.framework == "claude-agent-sdk" else "sub-agent"
                bound = tsf.agent_keys.get(str(aval.value)) if aval.kind == "ident" else None
                if bound is not None and bound != decl.key:
                    # ``agents: { researcher }``: the agent declared in this file under that variable
                    decl.delegates.append(_Ref(where(aval), ref_mode, key=bound))
                    continue
                sub = _Decl(
                    framework=decl.framework, name=aname, display=decl.display, locator=where(aval),
                    key=f"{decl.key}/agents/{aname}", parent=decl.key,
                    order=(decl.display, tsf.line(aval.offset), aval.offset), tags={"kind:subagent"},
                )  # fmt: skip
                sub.crew_scope = decl.display
                if aval.kind == "obj":
                    self._ts_fill(run, sub, aval.value, tsf)
                    sub.name = aname
                else:
                    sub.mark_unknown("definition", where(aval))
                run.add(sub)
                decl.delegates.append(_Ref(where(aval), ref_mode, key=sub.key))
        elif agents is not None:
            decl.mark_unknown("agents", where(agents))
        servers = props.get("mcpServers")
        if servers is not None and servers.kind == "obj":
            for sname, sval in sorted(servers.value.items()):
                if sval.kind != "obj" or not _short(sname):
                    continue
                entry = {
                    k: _ts_plain(v)
                    for k, v in sval.value.items()
                    if k in ("command", "args", "env", "url", "headers", "type")
                }
                key = f"{decl.key}#mcp/{sname}"
                run.servers.setdefault(
                    key,
                    _Mcp(
                        key=key,
                        framework=decl.framework,
                        name=sname,
                        entry=entry,
                        locator=where(sval),
                        display=decl.display,
                    ),
                )
                decl.servers.append(key)
        elif servers is not None:
            decl.mark_unknown("mcpServers", where(servers))

    @staticmethod
    def _ts_tool_approval(
        decl: _Decl, value: _TsVal | None, where: Callable[[_TsVal], str]
    ) -> dict[str, tuple[ApprovalGate, str]]:
        """Vercel AI SDK ``toolApproval: { name: 'user-approval' | 'approved' | … }`` per-tool settings."""
        if value is None:
            return {}
        if value.kind != "obj":
            decl.gate, decl.gate_source = ApprovalGate.CONDITIONAL, "toolApproval decided per call"
            decl.mark_unknown("toolApproval", where(value))
            return {}
        out: dict[str, tuple[ApprovalGate, str]] = {}
        for name, setting in value.value.items():
            if name == "...":
                decl.mark_unknown("toolApproval", where(setting))
                continue
            if setting.kind == "str" and setting.value == "user-approval":
                out[name] = (ApprovalGate.REQUIRED, "toolApproval=user-approval")
            elif setting.kind == "str" and setting.value == "approved":
                out[name] = (ApprovalGate.NONE, "toolApproval=approved")
            else:
                out[name] = (ApprovalGate.CONDITIONAL, "toolApproval decided per call")
        return out

    # ----------------------------------------------------------------------------------------- config files

    def _configs(self, run: _Run, files: list[Path]) -> None:
        crew_tasks: list[Path] = []
        adk: list[tuple[Path, dict[str, Any]]] = []
        ordered = sorted(files)
        source = "frameworks:config"
        for index, path in enumerate(ordered):
            name = path.name
            if name in _CREW_TASK_FILES:
                crew_tasks.append(path)
                continue
            if not self._budget(run, ordered, index, 0, 0):
                return
            if name == "langgraph.json":
                self._guarded(run, path, source, partial(self._langgraph, run, path))
            elif name in _OAI_CONFIG:
                self._guarded(run, path, source, partial(self._oai_config_list, run, path))
            elif path.suffix in _YAML_SUFFIXES:
                self._guarded(run, path, source, partial(self._yaml, run, path, adk))
        # ADK: root agents first, so a file reached through ``config_path`` is its parent's sub-agent
        seen: dict[str, str] = {}
        roots = sorted(adk, key=lambda pd: (pd[0].name not in _ADK_ROOT, pd[0]))
        root_paths = [p for p, _ in roots]
        for index, (path, data) in enumerate(roots):
            if not self._budget(run, root_paths, index, 0, 0):
                return
            if run.ctx.display(path) not in seen:
                self._guarded(run, path, source, partial(self._adk_root, run, path, data, seen))
        crew_index = self._crew_index(run)
        for index, path in enumerate(crew_tasks):
            if not self._budget(run, crew_tasks, index, 0, 0):
                return
            self._guarded(run, path, source, partial(self._crew_tasks, run, path, crew_index))

    def _parse(self, run: _Run, path: Path, data: bytes, source: str, *, fmt: str) -> Any:
        """Parse one config file. YAML parsing (pure Python) is bounded by the file's time share: past it the file
        is a ``truncated`` source, so one large hostile file cannot run the collector past its budget."""
        display = run.ctx.display(path)
        try:
            text = data.decode("utf-8-sig")
            if fmt != "yaml":
                return parse_jsonc(text)
            return _load_yaml_until(text, min(run.deadline, time.monotonic() + run.file_seconds))
        except _YamlTimeout:
            run.truncate(display, source, 1)
            return NON_LITERAL
        except (yaml.YAMLError, ValueError, RecursionError):
            run.fail(display, "parse-error", source)
            return NON_LITERAL

    def _load(self, run: _Run, path: Path, source: str, *, fmt: str) -> Any:
        data = self._read(run, path, source)
        return NON_LITERAL if data is None else self._parse(run, path, data, source, fmt=fmt)

    def _yaml(self, run: _Run, path: Path, adk: list[tuple[Path, dict[str, Any]]]) -> None:
        """CrewAI ``agents.yaml``, ADK agent YAML, Semantic Kernel prompt/agent YAML (cheap byte checks first)."""
        name = path.name
        known = name in _CREW_FILES or name in _ADK_ROOT
        display = run.ctx.display(path)
        try:
            size = path.stat().st_size
        except OSError:  # pragma: no cover - the walk just listed it
            return
        if size > MAX_SOURCE_BYTES:
            # too large to parse: still say so when the file looks like a framework definition
            sample = _read_head(path, run.ctx.root, _YAML_SNIFF_BYTES)
            if known or (sample is not None and _framework_yaml(name, sample)):
                run.fail(display, "too-large", "frameworks:config")
            return
        outcome = read_bounded(path, MAX_SOURCE_BYTES, root=run.ctx.root)
        if outcome.data is None:
            run.fail(display, outcome.error_class or "unreadable", "frameworks:config")
            return
        head = outcome.data
        is_crew, is_adk, is_sk, is_sk_agent = _yaml_kinds(name, head)
        if not (is_crew or is_adk or is_sk or is_sk_agent):
            return
        run.config_bytes += len(head)
        data = self._parse(run, path, head, "frameworks:config", fmt="yaml")
        if data is NON_LITERAL:
            return
        if not isinstance(data, dict):
            run.result.add_source(Surface.CODE, "frameworks:config", locator=display, ok=True, items=0)
            return
        items = 0
        if is_crew:
            items = self._crew_agents(run, display, data)
        elif is_adk and isinstance(data.get("name"), str):
            adk.append((path, data))
            run.adk_parsed[display] = data  # a ``config_path`` to this file reuses it (never parsed twice)
            return  # recorded when the agent tree is read
        elif is_sk and isinstance(data.get("template"), str):
            items = self._sk_prompt_yaml(run, display, data)
        elif is_sk_agent and _str_of(data.get("type")).endswith("_agent"):
            # values are never ``str()``-ed: an alias-bomb list would be expanded by its repr
            items = self._sk_agent_yaml(run, display, data)
        run.result.add_source(Surface.CODE, "frameworks:config", locator=display, ok=True, items=items)

    def _config_decl(
        self, run: _Run, framework: str, name: str, display: str, pointer: tuple[str | int, ...]
    ) -> _Decl:
        loc = locator(display, *pointer)
        decl = _Decl(
            framework=framework,
            name=name,
            display=display,
            locator=loc,
            key=loc,
            order=(display, 0, len(run.decls)),
        )
        decl.crew_scope = display
        return run.add(decl)

    def _config_prompt(
        self,
        decl: _Decl,
        label: str,
        value: Any,
        loc: str,
        kind: InstructionKind = InstructionKind.SYSTEM_PROMPT,
    ) -> None:
        if isinstance(value, str) and value:
            decl.prompts.append(_Prompt(label, value, loc, kind, _template_style(decl.framework, value)))
        elif value is not None:
            decl.mark_unknown(label, loc)

    def _config_model(
        self, decl: _Decl, value: Any, role: str, loc: str, provider: str | None = None
    ) -> None:
        if isinstance(value, str) and value:
            decl.models.append(
                _ModelRef(
                    value,
                    role,
                    loc,
                    hosted_owned=False,
                    provider=provider,
                    hints=_FRAMEWORK_HINTS.get(decl.framework, ()),
                )
            )
        elif isinstance(value, dict) and isinstance(value.get("model"), str):
            decl.models.append(
                _ModelRef(
                    value["model"],
                    role,
                    loc,
                    hosted_owned=False,
                    hints=_FRAMEWORK_HINTS.get(decl.framework, ()),
                )
            )
        elif value is not None:
            decl.mark_unknown("model", loc)

    def _crew_agents(self, run: _Run, display: str, data: Mapping[str, Any]) -> int:
        count = 0
        for agent_name in sorted(data, key=str):
            spec = data[agent_name]
            name = _short(agent_name)
            if name is None or not isinstance(spec, dict):
                continue
            decl = self._config_decl(run, "crewai", name, display, (agent_name,))
            decl.tags.add("crewai:yaml")
            for label in ("role", "goal", "backstory"):
                self._config_prompt(decl, label, spec.get(label), locator(display, agent_name, label))
            for label in ("system_template", "prompt_template"):
                if label in spec:
                    self._config_prompt(decl, label, spec.get(label), locator(display, agent_name, label))
            self._config_model(decl, spec.get("llm"), "primary", locator(display, agent_name, "llm"))
            self._config_model(
                decl,
                spec.get("function_calling_llm"),
                "tool-calling",
                locator(display, agent_name, "function_calling_llm"),
            )
            tools = spec.get("tools")
            if isinstance(tools, list):
                tools_loc = locator(display, agent_name, "tools")
                for i, t in enumerate(_capped(run, decl, tools, "tools", tools_loc)):
                    if isinstance(t, str) and _short(t):
                        decl.tools.append(_Tool(t, locator(display, agent_name, "tools", i)))
            elif tools is not None:
                decl.mark_unknown("tools", locator(display, agent_name, "tools"))
            if spec.get("allow_delegation") is True:
                decl.allow_delegation = True
                decl.tags.add("allow-delegation")
            if spec.get("allow_code_execution") is True:
                decl.tags.add("capability:execute")
                if spec.get("code_execution_mode") == "unsafe":
                    decl.tags.add("code-execution:host")
            decl.crew_scope = str(PurePosixPath(display).parent)
            count += 1
        return count

    @staticmethod
    def _crew_index(run: _Run) -> dict[str, dict[str, _Decl]]:
        """CrewAI agents by scope (directory or file) and name, built once for every ``tasks.yaml``."""
        index: dict[str, dict[str, _Decl]] = {}
        for decl in run.decls.values():
            if decl.framework == "crewai" and decl.crew_scope is not None:
                index.setdefault(decl.crew_scope, {})[decl.name] = decl
        return index

    def _crew_tasks(self, run: _Run, path: Path, crew_index: Mapping[str, Mapping[str, _Decl]]) -> None:
        data = self._load(run, path, "frameworks:config", fmt="yaml")
        display = run.ctx.display(path)
        if data is NON_LITERAL:
            return
        if not isinstance(data, dict):
            run.result.add_source(Surface.CODE, "frameworks:config", locator=display, ok=True, items=0)
            return
        scope = str(PurePosixPath(display).parent)
        by_name = crew_index.get(scope, {})
        items = 0
        for task_name in sorted(data, key=str):
            spec = data[task_name]
            if not isinstance(spec, dict) or not _short(task_name):
                continue
            agent_name = spec.get("agent")
            agent = by_name.get(agent_name) if isinstance(agent_name, str) else None
            if agent is None:
                run.result.warnings.append(
                    f"{locator(display, task_name)}: task agent not found among CrewAI agents"
                )
                continue
            items += 1
            label = f"task:{task_name}"
            for key in ("description", "expected_output"):
                self._config_prompt(
                    agent,
                    f"{label}:{key}",
                    spec.get(key),
                    locator(display, task_name, key),
                    InstructionKind.OTHER,
                )
            tools = spec.get("tools")
            if isinstance(tools, list):
                capped = _capped(run, agent, tools, "tools", locator(display, task_name, "tools"))
                agent.tools.extend(
                    _Tool(t, locator(display, task_name, "tools", i))
                    for i, t in enumerate(capped)
                    if isinstance(t, str) and _short(t)
                )
            if spec.get("human_input") is True:
                agent.tags.add("human-review:task-output")
        run.result.add_source(Surface.CODE, "frameworks:config", locator=display, ok=True, items=items)

    def _adk(
        self,
        run: _Run,
        path: Path,
        data: Mapping[str, Any],
        seen: dict[str, str],
        *,
        parent: str | None,
        hops: int = 0,
    ) -> str:
        """One ADK agent YAML and the sub-agent files it references; returns the agent's key."""
        display = run.ctx.display(path)
        name = _short(data.get("name")) or path.stem
        decl = self._config_decl(run, "google-adk", name, display, ())
        seen[display] = decl.key
        decl.parent = parent
        decl.tags.add("adk:yaml")
        agent_class = data.get("agent_class")
        if isinstance(agent_class, str) and _short(agent_class):
            decl.tags.add(f"agent-class:{agent_class}")
        decl.description = _short(data.get("description"), MAX_DESCRIPTION_CHARS)
        for label in ("instruction", "static_instruction", "global_instruction"):
            if label in data:
                self._config_prompt(decl, label, data.get(label), locator(display, label))
        self._config_model(decl, data.get("model"), "primary", locator(display, "model"))
        if "model_code" in data:
            decl.mark_unknown("model", locator(display, "model_code"))
        tools = data.get("tools")
        if isinstance(tools, list):
            for i, t in enumerate(_capped(run, decl, tools, "tools", locator(display, "tools"))):
                tname = t.get("name") if isinstance(t, dict) else t
                if isinstance(tname, str) and _short(tname):
                    decl.tools.append(
                        _Tool(
                            tname.rsplit(".", 1)[-1],
                            locator(display, "tools", i),
                            tags={f"tool-ref:{tname}"} if "." in tname else set(),
                        )
                    )
        for flag in ("disallow_transfer_to_parent", "disallow_transfer_to_peers"):
            if data.get(flag) is True:
                decl.tags.add(f"disallow-transfer-to-{flag.rsplit('_', 1)[-1]}")
        if any(isinstance(k, str) and k.startswith("before_tool_callback") for k in data):
            _policy_callback(decl, "before_tool_callbacks")
        run.result.add_source(Surface.CODE, "frameworks:config", locator=display, ok=True, items=1)
        subs = data.get("sub_agents")
        subs_list = (
            _capped(run, decl, subs, "sub_agents", locator(display, "sub_agents"))
            if isinstance(subs, list)
            else []
        )
        for i, sub in enumerate(subs_list):
            loc = locator(display, "sub_agents", i)
            if isinstance(sub, dict) and isinstance(sub.get("config_path"), str):
                target = _confined(path.parent, sub["config_path"], run.ctx.root)
                if target is None:
                    decl.mark_unknown("sub_agents", loc)
                    continue
                target_display = run.ctx.display(target)
                if target_display in seen:
                    decl.delegates.append(_Ref(loc, "sub-agent", key=seen[target_display]))
                    continue
                if hops >= MAX_CONFIG_HOPS or target.suffix not in _YAML_SUFFIXES or not _is_file(target):
                    decl.mark_unknown("sub_agents", loc)
                    continue
                sub_data = self._adk_target(run, target, target_display)
                if sub_data is None:  # out of budget: the rest of this tree is reported, not read
                    decl.mark_unknown("sub_agents", loc)
                    break
                if not isinstance(sub_data, dict):
                    decl.mark_unknown("sub_agents", loc)
                    continue
                child = self._adk(run, target, sub_data, seen, parent=decl.key, hops=hops + 1)
                decl.delegates.append(_Ref(loc, "sub-agent", key=child))
            elif isinstance(sub, dict) and isinstance(sub.get("code"), str):
                decl.delegates.append(_Ref(loc, "sub-agent", qualname=sub["code"]))
            else:
                decl.mark_unknown("sub_agents", loc)
        return decl.key

    def _adk_target(self, run: _Run, target: Path, display: str) -> Any:
        """The parsed YAML of a ``config_path`` target: the first pass's result when it parsed the file, else a
        bounded read charged to the code budget. ``None`` once the budget is spent (recorded as truncation)."""
        if display in run.adk_parsed:
            return run.adk_parsed[display]
        if time.monotonic() > run.deadline or run.config_bytes >= MAX_CODE_BYTES:
            run.truncate(display, "frameworks:config", 1)
            return None
        data = self._read(run, target, "frameworks:config")
        if data is None:
            return NON_LITERAL
        run.config_bytes += len(data)
        parsed = self._parse(run, target, data, "frameworks:config", fmt="yaml")
        run.adk_parsed[display] = parsed
        return parsed

    def _adk_root(self, run: _Run, path: Path, data: Mapping[str, Any], seen: dict[str, str]) -> None:
        self._adk(run, path, data, seen, parent=None)

    def _sk_prompt_yaml(self, run: _Run, display: str, data: Mapping[str, Any]) -> int:
        name = _short(data.get("name")) or PurePosixPath(display).stem
        decl = self._config_decl(run, "semantic-kernel", name, display, ())
        decl.tags.add("semantic-kernel:prompt-function")
        decl.description = _short(data.get("description"), MAX_DESCRIPTION_CHARS)
        fmt = _str_of(data.get("template_format")) or "semantic-kernel"
        engine = _SK_TEMPLATE_ENGINES.get(fmt, TemplateEngine.OTHER)
        decl.templates.append(("template", data["template"], engine, locator(display, "template"), None))
        _sk_dangerous_content(decl, data)
        self._sk_execution_settings(
            run, decl, data.get("execution_settings"), display, ("execution_settings",)
        )
        return 1

    def _sk_execution_settings(
        self, run: _Run, decl: _Decl, settings: Any, display: str, pointer: tuple[str, ...]
    ) -> None:
        if not isinstance(settings, dict):
            return
        for service in sorted(settings, key=str):
            entry = settings[service]
            if not isinstance(entry, dict):
                continue
            # a service key is scanned text: it reaches the locator only when it is a short, safe name
            part = _short(service)
            if part is None:
                if _secretish(service):
                    run.redact(decl)
                    continue
                part = "~service"
            for key in ("model_id", "ai_model_id", "model", "deployment_name"):
                if isinstance(entry.get(key), str):
                    self._config_model(decl, entry[key], "primary", locator(display, *pointer, part, key))
                    break

    def _sk_agent_yaml(self, run: _Run, display: str, data: Mapping[str, Any]) -> int:
        name = _short(data.get("name")) or PurePosixPath(display).stem
        decl = self._config_decl(run, "semantic-kernel", name, display, ())
        decl.tags.add(f"agent-type:{_short(data.get('type')) or 'unknown'}")
        decl.description = _short(data.get("description"), MAX_DESCRIPTION_CHARS)
        self._config_prompt(decl, "instructions", data.get("instructions"), locator(display, "instructions"))
        model = data.get("model")
        if isinstance(model, dict):
            self._config_model(decl, model.get("id"), "primary", locator(display, "model", "id"))
        tools = data.get("tools")
        if isinstance(tools, list):
            for i, t in enumerate(_capped(run, decl, tools, "tools", locator(display, "tools"))):
                tid = t.get("id") if isinstance(t, dict) else None
                if isinstance(tid, str) and _short(tid):
                    decl.tools.append(_Tool(tid, locator(display, "tools", i)))
        return 1

    def _sk_plugins(self, run: _Run, files: list[Path]) -> None:
        """``plugins/<Plugin>/<Function>/skprompt.txt`` (+ ``config.json``): one prompt function per directory."""
        ordered = sorted(files)
        for index, path in enumerate(ordered):
            if not self._budget(run, ordered, index, 0, 0):
                return
            self._guarded(run, path, "frameworks:config", partial(self._sk_plugin, run, path))

    def _sk_plugin(self, run: _Run, path: Path) -> None:
        data = self._read(run, path, "frameworks:config")
        if data is not None:
            display = run.ctx.display(path)
            function_dir = path.parent
            name = f"{function_dir.parent.name}.{function_dir.name}"
            decl = self._config_decl(run, "semantic-kernel", name, display, ())
            decl.tags.add("semantic-kernel:prompt-function")
            config_path = function_dir / "config.json"
            fmt = "semantic-kernel"
            if config_path.is_file() and not config_path.is_symlink():
                config = self._load(run, config_path, "frameworks:config", fmt="json")
                if isinstance(config, dict):
                    decl.description = _short(config.get("description"), MAX_DESCRIPTION_CHARS)
                    fmt = _str_of(config.get("template_format")) or fmt
                    _sk_dangerous_content(decl, config)
                    self._sk_execution_settings(
                        run,
                        decl,
                        config.get("execution_settings"),
                        run.ctx.display(config_path),
                        ("execution_settings",),
                    )
            text = data.decode("utf-8", errors="replace")
            decl.templates.append(
                ("skprompt", text, _SK_TEMPLATE_ENGINES.get(fmt, TemplateEngine.OTHER), display, data)
            )
            run.result.add_source(Surface.CODE, "frameworks:config", locator=display, ok=True, items=1)

    def _langgraph(self, run: _Run, path: Path) -> None:
        data = self._load(run, path, "frameworks:config", fmt="json")
        display = run.ctx.display(path)
        if data is NON_LITERAL:
            return
        if not isinstance(data, dict):
            run.fail(display, "invalid-config", "frameworks:config")
            return
        tags: set[str] = set()
        deps = data.get("dependencies")
        if isinstance(deps, list):
            tags.update(f"dependency:{d}" for d in deps[:50] if isinstance(d, str) and _short(d))
            if len(deps) > 50:
                tags.add("dependencies:truncated")
        env = data.get("env")
        if isinstance(env, dict):
            for key in sorted(env, key=str):
                if isinstance(key, str) and _short(key) and "=" not in key:
                    tags.add(f"env:{key}")
                    if classify_env_value(key, env[key]) == "literal-secret":
                        tags.add("inline-secret-in-config")
                        run.redact()
        elif isinstance(env, str) and _short(env):
            tags.add(f"env-file:{env}")
        auth = data.get("auth")
        if isinstance(auth, dict) and isinstance(auth.get("path"), str):
            tags.add("auth:custom-handler")
        http = data.get("http")
        if isinstance(http, dict):
            for flag in ("disable_mcp", "disable_a2a"):
                if http.get(flag) is True:
                    tags.add(f"http:{flag}")
        graphs = data.get("graphs")
        items = 0
        if isinstance(graphs, dict):
            base = path.parent
            for graph_id in sorted(graphs, key=str):
                spec = graphs[graph_id]
                target = spec.get("path") if isinstance(spec, dict) else spec
                name = _short(graph_id)
                if name is None:
                    continue
                decl = self._config_decl(run, "langgraph", name, display, ("graphs", graph_id))
                decl.tags.update(tags | {"langgraph:graph"})
                if isinstance(spec, dict):
                    decl.description = _short(spec.get("description"), MAX_DESCRIPTION_CHARS)
                file_part, _, var = target.rpartition(":") if isinstance(target, str) else ("", "", "")
                if "\x00" in file_part or len(file_part) > MAX_CONFIG_PATH_CHARS:
                    file_part = ""  # never a path: the graph stays unknown
                file_path = _confined(base, file_part, run.ctx.root) if file_part else None
                if isinstance(target, str) and (looks_like_secret(target) or hidden_code_points(target)):
                    run.redact(decl)
                    decl.mark_unknown("graph", decl.locator)
                elif file_part and _short(var):
                    inside = run.ctx.display(file_path) if file_path is not None else None
                    decl.entrypoint = f"{inside}:{var}" if inside is not None else _short(target)
                    decl.delegates.append(_Ref(decl.locator, "graph", var=var, path=inside))
                else:
                    decl.mark_unknown("graph", decl.locator)
                items += 1
        else:
            run.fail(display, "invalid-config", "frameworks:config", "no graphs")
            return
        run.result.add_source(Surface.CODE, "frameworks:config", locator=display, ok=True, items=items)

    def _oai_config_list(self, run: _Run, path: Path) -> None:
        data = self._load(run, path, "frameworks:config", fmt="json")
        display = run.ctx.display(path)
        if data is NON_LITERAL:
            return
        if not isinstance(data, list):
            run.fail(display, "invalid-config", "frameworks:config")
            return
        items = 0
        for i, entry in enumerate(_capped(run, None, data, "model", display)):
            if not isinstance(entry, dict):
                continue
            if classify_env_value("api_key", entry.get("api_key")) == "literal-secret":
                run.redact()
            model = entry.get("model")
            if not isinstance(model, str):
                continue
            provider = {"anthropic": "anthropic", "openai": "openai", "azure": "azure-openai", "google": "google-gemini", "bedrock": "aws-bedrock", "mistral": "mistral", "ollama": "ollama"}.get(_str_of(entry.get("api_type")).lower())  # fmt: skip
            endpoint = entry.get("base_url") if isinstance(entry.get("base_url"), str) else None
            run.root_models.append(
                _ModelRef(
                    model,
                    "config-list",
                    locator(display, i, "model"),
                    hosted_owned=False,
                    provider=provider,
                    endpoint=endpoint,
                )
            )
            items += 1
        run.result.add_source(Surface.CODE, "frameworks:config", locator=display, ok=True, items=items)

    # ----------------------------------------------------------------------------------------- linking

    def _resolve(self, run: _Run) -> None:
        """Resolve references across files: imported agents and tools, CrewAI YAML/code, LangGraph targets.

        Every lookup goes through an index built once (no scan of all declarations per reference), and the
        linking deadline is checked as it goes.
        """
        decls = run.decls
        run.vars_by_name = {}
        for (module, var), key in sorted(run.module_vars.items()):
            run.vars_by_name.setdefault(var, []).append((module, key))
        tools_by_func: dict[str, list[tuple[str, _Tool]]] = {}
        for (module, func), info in sorted(run.module_tools.items()):
            tools_by_func.setdefault(func, []).append((module, info))
        for index, (decl_key, qual, ident, loc) in enumerate(run.pending_tools):
            if run.link_late(loc, len(run.pending_tools) - index):
                for later_key, _, _, later_loc in run.pending_tools[index:]:
                    later = decls.get(later_key)
                    if later is not None:
                        later.mark_unknown("tools", later_loc)
                return
            pending = decls.get(decl_key)
            if pending is None:
                continue
            agent_key = self._qual_agent(run, qual)
            if agent_key is not None:
                pending.delegates.append(_Ref(loc, "agent-as-tool", key=agent_key))
                continue
            module, _, func = qual.rpartition(".")
            found = next((i for m, i in tools_by_func.get(func, []) if _module_matches(m, module)), None)
            if found is not None:
                pending.tools.append(
                    _Tool(
                        found.name,
                        loc,
                        found.gate,
                        found.gate_source,
                        set(found.capabilities),
                        set(found.tags),
                    )
                )
            else:
                pending.tools.append(_Tool(ident, loc, tags={"tool-ref:import"}))
        # Claude: ``agents={"x": x}`` where ``x = AgentDefinition(...)`` lives in another module
        for sub_key, qual in run.pending_defs:
            sub = decls.get(sub_key)
            if sub is None:
                continue
            module, _, var = qual.rpartition(".")
            raw = {k for m, k in run.vars_by_name.get(var, []) if _module_matches(m, module)}
            target = raw.pop() if len(raw) == 1 else None  # the definition itself, even once merged elsewhere
            source = (decls.get(target) or run.retired.get(target)) if target is not None else None
            if source is None or source is sub or "kind:subagent" not in source.tags:
                sub.mark_unknown("definition", sub.locator)
                continue
            self._merge_definition(source, sub)
            if source.key in decls:
                self._alias(run, source.key, sub.key)
        # CrewAI: ``Agent(config=self.agents_config["x"])`` refines the YAML agent ``x``
        crew_yaml: dict[str, list[_Decl]] = {}
        for d in decls.values():
            if d.framework == "crewai" and "crewai:yaml" in d.tags:
                crew_yaml.setdefault(d.name, []).append(d)
        for key in sorted(decls):
            crew_decl = decls.get(key)
            if crew_decl is None or crew_decl.framework != "crewai" or crew_decl.config_key is None:
                continue
            if run.link_late(crew_decl.locator, 1):
                return
            target_decl = self._crew_yaml_agent(crew_decl, crew_yaml.get(crew_decl.config_key, []))
            if target_decl is not None:
                self._merge(crew_decl, target_decl)
                target_decl.entrypoint = target_decl.entrypoint or crew_decl.locator
                self._alias(run, key, target_decl.key)
        # LangGraph graphs: the agent bound to the graph's variable is the graph's implementation
        for key in sorted(decls):
            graph = decls.get(key)
            if graph is None or "langgraph:graph" not in graph.tags:
                continue
            ref = next((r for r in graph.delegates if r.mode == "graph"), None)
            if ref is None:
                continue
            if run.link_late(graph.locator, 1):
                return
            graph.delegates.remove(ref)
            target_key = run.file_vars.get((ref.path or "", ref.var or ""))
            impl = decls.get(run.canon(target_key)) if target_key else None
            if impl is None or impl is graph:
                graph.tags.add("langgraph:unresolved-graph")
                for fieldname in ("instructions", "model", "tools"):
                    graph.mark_unknown(fieldname, graph.entrypoint or graph.locator)
                continue
            self._merge(impl, graph)
            graph.gate, graph.gate_source = impl.gate, impl.gate_source
            if impl.framework != "langgraph":
                graph.tags.add(f"implemented-with:{impl.framework}")
            self._alias(run, impl.key, graph.key)

    @staticmethod
    def _merge(source: _Decl, into: _Decl) -> None:
        into.prompts.extend(source.prompts)
        into.models.extend(source.models)
        into.tools.extend(source.tools)
        into.delegates.extend(source.delegates)
        into.servers.extend(source.servers)
        into.tool_gates.update(source.tool_gates)
        into.unknown = {**source.unknown, **into.unknown}
        into.tags.update(t for t in source.tags if not t.startswith(("name-from:", "kind:")))
        into.allow_delegation = into.allow_delegation or source.allow_delegation
        into.redacted += source.redacted

    @classmethod
    def _merge_definition(cls, source: _Decl, into: _Decl) -> None:
        """A Claude ``AgentDefinition`` declared elsewhere becomes the options' sub-agent of that name."""
        cls._merge(source, into)
        into.description = into.description or source.description
        into.base_tools = into.base_tools if into.base_tools is not None else source.base_tools
        into.disallowed = into.disallowed or list(source.disallowed)
        into.permission_mode = into.permission_mode or source.permission_mode
        into.mode_unknown = into.mode_unknown or source.mode_unknown
        into.entrypoint = into.entrypoint or source.locator
        into.unknown.pop("definition", None)

    @staticmethod
    def _alias(run: _Run, old: str, new: str) -> None:
        """Retire ``old``: every reference to it (key, parent, module/file variable) now means ``new``."""
        decl = run.decls.pop(old, None)
        if decl is not None:
            run.retired[old] = decl
        if old != new:
            run.aliases[old] = new

    @staticmethod
    def _crew_yaml_agent(decl: _Decl, candidates: Sequence[_Decl]) -> _Decl | None:
        """The YAML agent a CrewAI ``config=`` key names, nearest to the Python file (unique or ``None``)."""
        here = PurePosixPath(decl.display).parts

        def shared(d: _Decl) -> int:
            n = 0
            for a, b in zip(here, PurePosixPath(d.display).parts, strict=False):
                if a != b:
                    break
                n += 1
            return n

        best = max((shared(d) for d in candidates), default=-1)
        top = [d for d in candidates if shared(d) == best]
        return top[0] if len(top) == 1 else None

    @staticmethod
    def _qual_agent(run: _Run, qual: str) -> str | None:
        module, _, var = qual.rpartition(".")
        hits = {run.canon(k) for m, k in run.vars_by_name.get(var, []) if _module_matches(m, module)}
        hits &= run.decls.keys()  # a declaration dropped with a truncated file is not a target
        return hits.pop() if len(hits) == 1 else None

    def _target(
        self, run: _Run, decl: _Decl, ref: _Ref, names: Mapping[tuple[str, str], Sequence[str]]
    ) -> str | None:
        if ref.key is not None:
            key = run.canon(ref.key)
            return key if key in run.decls else None
        if ref.qualname is not None:
            return self._qual_agent(run, ref.qualname)
        if ref.agent_name is not None:
            named = names.get((decl.framework, ref.agent_name), ())
            local = [k for k in named if run.decls[k].display == decl.display]
            if len(local) == 1:
                return local[0]
            return named[0] if len(named) == 1 else None
        return None

    def _links(self, run: _Run) -> dict[str, list[tuple[str, str, _Ref]]]:
        """Resolved delegation targets per agent (and sub-agent parents), before anything is emitted."""
        links: dict[str, list[tuple[str, str, _Ref]]] = {}
        crew: dict[str, list[str]] = {}
        names: dict[tuple[str, str], list[str]] = {}
        for decl in sorted(run.decls.values(), key=lambda d: (d.order, d.key)):
            names.setdefault((decl.framework, decl.name), []).append(decl.key)
            if decl.framework == "crewai" and decl.crew_scope and "kind:crew" not in decl.tags:
                crew.setdefault(decl.crew_scope, []).append(decl.key)
        keys = sorted(run.decls)
        for index, key in enumerate(keys):
            decl = run.decls[key]
            if run.link_late(decl.locator, len(keys) - index):
                # agents not linked in time are still emitted; their delegation is unknown, not dropped
                for rest in keys[index:]:
                    pending = run.decls[rest]
                    for ref in pending.delegates:
                        pending.mark_unknown("delegation", ref.locator)
                    if pending.allow_delegation:
                        pending.mark_unknown("delegation", pending.locator)
                break
            found: dict[str, tuple[str, _Ref]] = {}
            for ref in decl.delegates:
                target = self._target(run, decl, ref, names)
                if target is None or target == key:
                    decl.mark_unknown("handoffs" if ref.mode == "handoff" else "delegation", ref.locator)
                    continue
                found.setdefault(target, (ref.mode, ref))
                child = run.decls[target]
                if ref.mode in ("sub-agent", "member", "subagent") and child.parent is None:
                    child.parent = key
            if decl.allow_delegation and decl.crew_scope:
                for other in crew.get(decl.crew_scope, []):
                    if other != key:
                        found.setdefault(other, ("crew-delegation", _Ref(decl.locator, "crew-delegation")))
            links[key] = [(target, mode, ref) for target, (mode, ref) in found.items()]
        return links

    # ----------------------------------------------------------------------------------------- emission

    def _emit(self, run: _Run) -> None:
        """Emit every declaration read. Reading stops at :data:`MAX_DECLS`, so each pass here is bounded; each
        pass still checks the emission deadline, and one entity that fails to emit is that entity's coverage
        failure (its partial output removed), never the collector's."""
        ctx = run.ctx
        ids = _Ids()
        decls = sorted(run.decls.values(), key=lambda d: (d.order, d.key))
        for index, decl in enumerate(decls):
            if index % 256 == 0 and run.late(decl.locator, len(decls) - index):
                break
            if _secretish(decl.name):  # a variable or key named like a credential is never an id or a name
                run.redact(decl)
                decl.name = f"{PurePosixPath(decl.display).stem}-L{decl.order[1]}"
                decl.tags.add("name-from:location")
        links = self._links(run)
        agent_ids = self._agent_ids(run, decls, ids)
        servers = sorted(run.servers)
        server_parts = {key: f"{run.servers[key].framework}-{run.servers[key].name}" for key in servers}
        server_groups = _colliding((key, make_id("server", part)) for key, part in server_parts.items())
        server_ids = {
            key: ids.claim("server", server_parts[key], seed=key if key in server_groups else None)
            for key in servers
        }
        # a model id models-hosted emits from a code literal is never also emitted here (scan merges the rest)
        emitted: set[str] = set()
        for index, decl in enumerate(decls):
            if index % 256 == 0 and run.late(decl.locator, len(decls) - index):
                break
            for model in decl.models:
                hosted, elsewhere = self._classify(model)
                if hosted is not None and elsewhere:
                    emitted.add(
                        make_id("model", "hosted", hosted.provider or "unknown", hosted.requested_ref)
                    )
        for index, decl in enumerate(decls):
            if run.late(decl.locator, len(decls) - index):
                break
            self._guarded_emit(
                run,
                decl.display,
                partial(
                    self._emit_agent,
                    run,
                    decl,
                    [link for link in links.get(decl.key, []) if link[0] in agent_ids],
                    agent_ids=agent_ids,
                    server_ids=server_ids,
                    ids=ids,
                    emitted=emitted,
                ),
            )
        else:
            for key in servers:
                server = run.servers[key]
                self._guarded_emit(
                    run, server.display, partial(self._emit_server, run, server, server_ids[key])
                )
            for key in sorted(set(run.root_servers)):
                server = run.servers[key]
                self._edge(
                    run.result,
                    EdgeType.DEPENDS_ON,
                    ctx.agent_id,
                    server_ids[key],
                    declared_by=server.locator,
                    qualifiers={"relation": "mcp-server", "client": server.framework},
                )
            for ref in run.root_models:
                self._guarded_emit(
                    run,
                    _file_of(ref.locator),
                    partial(self._emit_model, run, ctx.agent_id, ref, "autogen", emitted),
                )
            if run.emit_failed:
                self._prune_truncated(run)
            return
        self._prune_truncated(run)

    @staticmethod
    def _agent_ids(run: _Run, decls: Sequence[_Decl], ids: _Ids) -> dict[str, str]:
        """Agent ids: a declaration whose id collides with another's takes its key-derived suffixed id first, so
        an agent elsewhere whose literal name equals that suffixed id never takes it (it gets a residual suffix)."""
        run.colliding = _colliding((decl.key, make_id("agent", decl.framework, decl.name)) for decl in decls)
        agent_ids: dict[str, str] = {}
        for decl in decls:
            if decl.key in run.colliding:
                agent_ids[decl.key] = ids.claim("agent", decl.framework, decl.name, seed=decl.key)
        for decl in decls:
            if decl.key not in run.colliding:
                agent_ids[decl.key] = ids.claim("agent", decl.framework, decl.name)
        return agent_ids

    @staticmethod
    def _guarded_emit(run: _Run, display: str, emit: Callable[[], None]) -> None:
        """Emit one agent or server; a failure on hostile input removes what it had emitted and is recorded as a
        coverage source with the error class only (exception text can carry scanned values)."""
        result = run.result
        entities, edges = len(result.entities), len(result.edges)
        try:
            emit()
        except Exception:
            del result.entities[entities:]
            del result.edges[edges:]
            run.emit_failed = True
            run.fail(display, "emit-error", "frameworks:emit")

    @staticmethod
    def _prune_truncated(run: _Run) -> None:
        """After an emission cut-off, keep the result self-consistent: no edge to an entity never emitted, and
        no agent whose parent was not emitted points at it (it hangs off the scanned agent instead)."""
        result = run.result
        present = {e.id for e in result.entities} | {run.ctx.agent_id}
        result.edges[:] = [
            e
            for e in result.edges
            if e.type is EdgeType.USES_MODEL or (e.from_ref in present and e.to_ref in present)
        ]
        for index, entity in enumerate(result.entities):
            if isinstance(entity, Agent) and entity.parent_ref not in present:
                result.entities[index] = entity.model_copy(update={"parent_ref": run.ctx.agent_id})

    def _emit_agent(
        self,
        run: _Run,
        decl: _Decl,
        links: list[tuple[str, str, _Ref]],
        *,
        agent_ids: Mapping[str, str],
        server_ids: Mapping[str, str],
        ids: _Ids,
        emitted: set[str],
    ) -> None:
        ctx, result = run.ctx, run.result
        agent_id = agent_ids[decl.key]
        instructions: list[InstructionRef] = []
        for prompt in decl.prompts:
            iid = self._emit_instruction(run, decl, prompt, ids)
            instructions.append(InstructionRef(ref=iid, precedence=0))
            self._edge(
                result,
                EdgeType.LOADS_INSTRUCTION,
                agent_id,
                iid,
                declared_by=prompt.locator,
                qualifiers={"precedence": 0, "field": prompt.label},
            )
        for label, template, engine, loc, raw in decl.templates:
            pid = self._emit_template(
                run, decl, ids, label=label, template=template, engine=engine, loc=loc, raw=raw
            )
            self._edge(
                result,
                EdgeType.LOADS_INSTRUCTION,
                agent_id,
                pid,
                declared_by=loc,
                qualifiers={"precedence": 0, "field": label},
            )
        for model in decl.models:
            self._emit_model(run, agent_id, model, decl.framework, emitted)
        self._emit_tools(run, decl, agent_id, ids)

        for key in dict.fromkeys(decl.servers):
            server = run.servers[key]
            if not self._apply_claude_flags(run, decl, server):
                continue  # denied as a whole (``disallowed_tools=["mcp__<server>"]``): not available to the agent
            self._edge(
                result,
                EdgeType.DEPENDS_ON,
                agent_id,
                server_ids[key],
                declared_by=server.locator,
                qualifiers={"relation": "mcp-server", "client": decl.framework},
            )
        for target, mode, ref in sorted(links, key=lambda t: agent_ids[t[0]]):
            qualifiers: dict[str, Any] = {"protocol": "in-process", "mode": mode, "framework": decl.framework}
            constraints = self._constraints(run.decls[target], ref)
            if constraints:
                qualifiers["constraints"] = constraints
            self._edge(
                result,
                EdgeType.DELEGATES_TO,
                agent_id,
                agent_ids[target],
                declared_by=ref.locator,
                qualifiers=qualifiers,
            )
        tags = set(decl.tags) | {f"framework:{decl.framework}"}
        tags.update(f"unknown:{k}" for k in decl.unknown)
        leaked = {t for t in tags if _secretish(t)}  # last line of defence: no tag ever carries a credential
        if leaked:
            tags -= leaked
            run.redact(decl, len(leaked))
        entrypoint = decl.entrypoint
        if _secretish(entrypoint):
            entrypoint = None
            run.redact(decl)
        if decl.redacted or "inline-secret-in-config" in decl.tags:
            tags.add("redacted:credential-shaped-token")
            run.redacted_ids.add(agent_id)
        parent = run.canon(decl.parent) if decl.parent else None
        parent = parent if parent in run.decls and parent != decl.key else None
        result.entities.append(
            Agent(
                id=agent_id,
                name=decl.name,
                description=decl.description,
                provenance=Provenance(
                    method=ClaimMethod.CONFIG, locator=decl.locator, collector=self.ref, observed_at=ctx.now
                ),
                tags=sorted(tags),
                foreign={f"frameworks:unknown:{k}": v for k, v in sorted(decl.unknown.items())},
                version=_VERSION_UNKNOWN,
                role=AgentRole.SUB_AGENT,
                framework=Claim.declared(
                    FrameworkRef(name=decl.framework),
                    locator=decl.locator,
                    collector=self.ref,
                    observed_at=ctx.now,
                ),
                instructions=instructions,
                entrypoint=entrypoint,
                parent_ref=agent_ids[parent] if parent is not None else ctx.agent_id,
            )
        )

    @staticmethod
    def _constraints(target: _Decl, ref: _Ref) -> str | None:
        parts: list[str] = [ref.constraints] if ref.constraints else []
        if ref.mode == "sub-agent" and "disallow-transfer-to-parent" in target.tags:
            parts.append("no-transfer-back-to-parent")
        if ref.mode == "subagent" and target.base_tools is not None:
            safe = [t for t in target.base_tools if _short(t) and not _secretish(t)]
            parts.append("tools:" + ",".join(sorted(safe)[:20]))
        return "; ".join(parts) or None

    @staticmethod
    def _claude_settings(run: _Run, decl: _Decl) -> tuple[str | None, list[str] | None]:
        """Effective ``permission_mode`` and ``allowed_tools`` of a Claude Agent SDK agent.

        A sub-agent runs under its parent's mode when the parent is in ``bypassPermissions``, ``acceptEdits`` or
        ``auto`` (the sub-agent's own ``permissionMode`` is ignored), and under ``plan`` when the parent plans.
        Otherwise the sub-agent's own mode applies, except that a sub-agent cannot raise itself to
        ``bypassPermissions`` (Claude Code docs, "Subagents", permission modes). An unknown mode is returned as
        :data:`_MODE_UNKNOWN` (gates ``UNKNOWN``; never written as a flag).
        """
        mode = _MODE_UNKNOWN if decl.mode_unknown else decl.permission_mode
        allowed = decl.allowed
        parent = run.decls.get(run.canon(decl.parent)) if decl.parent else None
        if parent is not None and parent.framework == "claude-agent-sdk":
            parent_mode = _MODE_UNKNOWN if parent.mode_unknown else parent.permission_mode
            parent_wins = parent_mode in (_MODE_UNKNOWN, "bypassPermissions", "acceptEdits", "auto", "plan")
            if parent_wins or mode in (None, "bypassPermissions"):
                mode = parent_mode
            allowed = allowed if allowed is not None else parent.allowed
        return mode, allowed

    def _apply_claude_flags(self, run: _Run, decl: _Decl, server: _Mcp) -> bool:
        """Claude Agent SDK options run Claude Code's permission engine: record its settings as trust flags.

        Deny rules win over allow rules: ``disallowed_tools`` entries for this server (``mcp__<server>__<tool>``)
        are recorded as ``claude-code.permissions.deny`` and those tools are not emitted; a server-level deny
        (``mcp__<server>`` / ``mcp__<server>__*``) removes the server from the agent (``False``)."""
        if decl.framework != "claude-agent-sdk":
            return True
        mode, allowed = self._claude_settings(run, decl)
        denied = self._server_rules(server, decl.disallowed)
        if "*" in denied:
            decl.tags.add(f"mcp-server-denied:{server.name}")
            server.flags["claude-code.permissions.deny"] = "*"
            return False
        if mode in _CLAUDE_MODES:
            server.flags["claude-code.defaultMode.agent-sdk"] = str(mode)
        rules = self._server_rules(server, allowed or [])
        if rules:
            server.flags["claude-code.permissions.allow"] = ",".join(rules)
        if denied:
            server.flags["claude-code.permissions.deny"] = ",".join(denied)
            decl.tags.update(f"tool-removed:mcp__{server.name}__{name}" for name in denied)
        return True

    @staticmethod
    def _server_rules(server: _Mcp, rules: Sequence[str]) -> list[str]:
        """Tool names (``*`` for the whole server) that Claude permission rules name on ``server``."""
        prefix = f"mcp__{server.name}"
        return sorted(
            {"*" if rule in (prefix, prefix + "__*") else rule[len(prefix) + 2 :] for rule in rules if rule == prefix or rule.startswith(prefix + "__")}
        )  # fmt: skip

    def _emit_instruction(self, run: _Run, decl: _Decl, prompt: _Prompt, ids: _Ids) -> str:
        data = _text_bytes(prompt.text)
        seed = _seed(run, decl.key)
        iid = ids.claim(
            "instr", decl.framework, decl.name, prompt.label, seed=seed and f"{seed}\x00{prompt.label}"
        )
        secret = looks_like_secret(prompt.text)
        tags = {
            f"framework:{decl.framework}",
            f"field:{prompt.label}",
            "source:config" if "#" in prompt.locator else "source:code",
        }
        if prompt.template:
            tags.add(f"template:{prompt.template}")
        if hidden_code_points(prompt.text):
            tags.add("hidden-unicode")
        if _surrogates(prompt.text):
            tags.update({"hidden-unicode", "invalid-unicode:lone-surrogate"})
        if secret:
            run.redact(decl)
            run.redacted_ids.add(iid)
        run.result.entities.append(
            Instruction(
                id=iid,
                name=f"{decl.name} {prompt.label}",
                provenance=Provenance(
                    method=ClaimMethod.CONFIG,
                    locator=prompt.locator,
                    collector=self.ref,
                    observed_at=run.ctx.now,
                ),
                tags=sorted(tags),
                instruction_kind=prompt.kind,
                path=_file_of(prompt.locator),
                media_type="text/plain",
                size=len(data),
                digest=bytes_digest(data),
                normalized_digest=triage_digest(data),
                line_endings=line_endings(data),
                contains_secret_like=secret,
            )
        )
        return iid

    def _emit_template(
        self,
        run: _Run,
        decl: _Decl,
        ids: _Ids,
        *,
        label: str,
        template: str,
        engine: TemplateEngine,
        loc: str,
        raw: bytes | None,
    ) -> str:
        seed = _seed(run, decl.key)
        pid = ids.claim("prompt", decl.framework, decl.name, label, seed=seed and f"{seed}\x00{label}")
        data = raw if raw is not None else _text_bytes(template)
        tags = {f"framework:{decl.framework}"}
        if _surrogates(template):
            # the canonical digest covers text; lone surrogates are kept as escapes there (and flagged)
            tags.update({"hidden-unicode", "invalid-unicode:lone-surrogate"})
            template = template.encode("utf-8", "backslashreplace").decode("utf-8")
        tags.update(t for t in decl.tags if t.startswith("allow-dangerously-set-content"))
        if raw is not None:
            tags.add("template:file-bytes")
        if looks_like_secret(template):
            tags.add("contains-secret-like")
            run.redact(decl)
            run.redacted_ids.add(pid)
        if hidden_code_points(template):
            tags.add("hidden-unicode")
        run.result.entities.append(
            PromptTemplate(
                id=pid,
                name=f"{decl.name} {label}",
                provenance=Provenance(
                    method=ClaimMethod.CONFIG, locator=loc, collector=self.ref, observed_at=run.ctx.now
                ),
                tags=sorted(tags),
                engine=engine,
                role=PromptRole.SYSTEM,
                digest=prompt_digest(
                    engine=engine.value,
                    role=PromptRole.SYSTEM.value,
                    template=template,
                    variables_schema=None,
                ),
                template_digest=bytes_digest(data),
                path=loc.split("#", 1)[0],
                risk_class=TemplateRiskClass.TEMPLATE_EXECUTION
                if engine in (TemplateEngine.JINJA2, TemplateEngine.HANDLEBARS)
                else TemplateRiskClass.NONE,
            )
        )
        return pid

    @staticmethod
    def _classify(ref: _ModelRef) -> tuple[HostedRef | None, bool]:
        """``(classification, models-hosted owns the Model)``; ``None`` when no model id applies."""
        value = ref.value.strip()
        if not value or len(value) > MAX_MODEL_REF or "${" in value or "{env:" in value or value == "inherit":
            return None, False
        if _surrogates(value) or hidden_code_points(value):
            return None, False
        if ref.hosted_owned:
            # exactly the inputs models-hosted uses for a code literal (no explicit provider, file hints/endpoint)
            if ref.js:
                hosted = classify_model_ref(value)
                if hosted.provider is not None and hosted.attribution in (
                    "shape",
                    "litellm-prefix",
                    "provider-prefix",
                ):
                    return hosted, True
            else:
                hosted = classify_model_ref(value, endpoint=ref.endpoint, packages=ref.hints)
                if hosted.provider is not None:
                    return hosted, True
        # ``provider:model`` prefixes are split by the classifier itself (the same function models-hosted uses), so
        # a positional and a keyword ``"anthropic:claude-…"`` get one id
        own = classify_model_ref(
            value, provider=ref.provider, endpoint=ref.endpoint, context=ref.context, packages=ref.hints
        )
        return own, False

    def _emit_model(
        self, run: _Run, agent_id: str, ref: _ModelRef, framework: str, emitted: set[str]
    ) -> None:
        if looks_like_secret(ref.value):
            run.redact()
            return
        hosted, owned_elsewhere = self._classify(ref)
        if hosted is None:
            return
        provider = hosted.provider or "unknown"
        model_id = make_id("model", "hosted", provider, hosted.requested_ref)
        if not owned_elsewhere and model_id not in emitted:
            emitted.add(model_id)
            tags = {
                f"source:{_SOURCE}",
                f"framework:{framework}",
                f"role:{ref.role}",
                f"provider:{provider}",
                f"pinning:{hosted.alias_pinning.value}",
                f"attributed-by:{hosted.attribution}",
            }
            if hosted.expected_resolution:
                tags.add(f"alias-resolves-to:{hosted.expected_resolution.split(' ', 1)[0]}")
            origin = _url_display(ref.endpoint) if ref.endpoint else None
            identity = hosted_identity(
                hosted, endpoint_origin=origin, locator=ref.locator, collector=self.ref
            )
            run.result.entities.append(
                Model(
                    id=model_id,
                    name=hosted.requested_ref,
                    description=hosted.reason,
                    provenance=Provenance(
                        method=ClaimMethod.CONFIG,
                        locator=ref.locator,
                        collector=self.ref,
                        observed_at=run.ctx.now,
                    ),
                    tags=sorted(tags),
                    model_kind=ModelKind.HOSTED,
                    hosted=Claim.declared(
                        identity, locator=ref.locator, collector=self.ref, observed_at=run.ctx.now
                    ),
                )
            )
        self._edge(
            run.result,
            EdgeType.USES_MODEL,
            agent_id,
            model_id,
            declared_by=ref.locator,
            qualifiers={"role": ref.role, "source": _SOURCE, "framework": framework},
        )

    def _tool_gate(self, run: _Run, decl: _Decl, tool: _Tool) -> tuple[ApprovalGate, str]:
        if decl.framework == "claude-agent-sdk":
            mode, allowed = self._claude_settings(run, decl)
            base = tool.name.split("(", 1)[0]
            return claude_tool_gate(base, mode, allowed, callback=decl.gate is ApprovalGate.CONDITIONAL)
        if tool.name in decl.tool_gates:
            return decl.tool_gates[tool.name], "human-in-the-loop interrupt_on"
        if tool.gate is not None and tool.gate is not ApprovalGate.UNKNOWN:
            return tool.gate, tool.gate_source or "tool setting"
        if decl.gate is not None:
            return decl.gate, decl.gate_source or "agent setting"
        if tool.gate is ApprovalGate.UNKNOWN:
            return ApprovalGate.UNKNOWN, tool.gate_source or "non-literal approval setting"
        if decl.tool_gates:
            return ApprovalGate.NONE, "not listed in interrupt_on"
        if decl.framework in _NO_APPROVAL_BY_DEFAULT and "api:classic" not in decl.tags:
            return ApprovalGate.NONE, "framework default: tool calls run without approval"
        return ApprovalGate.UNKNOWN, "no approval setting declared"

    def _emit_tools(self, run: _Run, decl: _Decl, agent_id: str, ids: _Ids) -> None:
        tools = list(decl.tools)
        if decl.framework == "claude-agent-sdk":
            base_tools = decl.base_tools
            if base_tools is None and "kind:subagent" not in decl.tags and "tools" not in decl.unknown:
                # no ``tools=``: the agent has every Claude Code built-in (``allowed_tools`` only pre-approves)
                base_tools = list(_CLAUDE_DEFAULT_TOOLS)
                decl.tags.add("tools:default-preset")
            names = list(base_tools or []) + [t for t in decl.allowed or [] if not t.startswith("mcp__")]
            tools.extend(_Tool(n, decl.locator) for n in names)
            if decl.base_tools is None and "kind:subagent" in decl.tags:
                decl.tags.add("tools:inherited")
            linked = {run.servers[k].name for k in decl.servers if k in run.servers}
            decl.tags.update(
                f"allowed-mcp:{t}"
                for t in decl.allowed or []
                if t.startswith("mcp__") and t.split("__")[1] not in linked and not _secretish(t)
            )
        mode, allowed = self._claude_settings(run, decl)
        seen: dict[str, _Tool] = {}
        for tool in tools:
            base = tool.name.split("(", 1)[0]
            if _short(base) is None or _secretish(tool.name):
                if _secretish(tool.name):
                    run.redact(decl)
                continue
            if decl.framework == "claude-agent-sdk":
                if tool.name in decl.disallowed or base in decl.disallowed:
                    decl.tags.add(f"tool-removed:{base}")
                    continue
                pre_approved = allowed is not None and (tool.name in allowed or base in allowed)
                # dontAsk denies only what would prompt: read-only built-ins still run
                if mode == "dontAsk" and not pre_approved and base not in _CLAUDE_NO_PROMPT:
                    decl.tags.add(f"tool-denied:{base}")
                    continue
            seen.setdefault(base, tool)
        if not seen:
            return
        server_id = ids.claim("server", decl.framework, decl.name, "tools", seed=_seed(run, decl.key))
        flags = (
            {"claude-code.defaultMode.agent-sdk": str(mode)}
            if decl.framework == "claude-agent-sdk" and mode in _CLAUDE_MODES
            else {}
        )
        self._emit_in_process_server(
            run, server_id, f"{decl.name} tools", decl.framework, loc=decl.locator, flags=flags
        )
        self._edge(
            run.result,
            EdgeType.DEPENDS_ON,
            agent_id,
            server_id,
            declared_by=decl.locator,
            qualifiers={"relation": "tool-server", "client": decl.framework},
        )
        for base in sorted(seen):
            tool = seen[base]
            gate, why = self._tool_gate(run, decl, tool)
            tid = tool_id(server_id, _tool_part(base))
            caps = set(tool.capabilities) | set(_TOOL_CAPS.get(base, ()))
            tags = set(tool.tags) | {f"framework:{decl.framework}", f"approval-source:{why}"[:200]}
            if base in _HOSTED_TOOLS:
                tags.add("hosted-tool")
            run.result.entities.append(
                ToolDefinition(
                    id=tid,
                    name=base,
                    provenance=Provenance(
                        method=ClaimMethod.CONFIG,
                        locator=tool.locator,
                        collector=self.ref,
                        observed_at=run.ctx.now,
                    ),
                    tags=sorted(tags),
                    server_ref=server_id,
                    tool_name=base,
                    input_schema={},
                    digest=DigestResult(
                        algorithm="tooldef/v1",
                        status=DigestStatus.UNDIGESTABLE,
                        reason="declared-without-definition: named in framework code or config; its schema is built at run time",
                    ),
                    source=ToolSource.DECLARED_CONFIG,
                    capabilities=sorted(caps, key=lambda c: c.value),
                    approval_gate=gate,
                )
            )
            self._edge(
                run.result, EdgeType.PROVIDES_TOOL, server_id, tid, declared_by=tool.locator, qualifiers={}
            )
            self._edge(
                run.result,
                EdgeType.INVOKES_TOOL,
                agent_id,
                tid,
                declared_by=tool.locator,
                qualifiers={"mode": "declared"},
            )

    def _declared(self, run: _Run, value: Any, loc: str) -> Claim[Any]:
        return Claim.declared(value, locator=loc, collector=self.ref, observed_at=run.ctx.now)

    def _emit_in_process_server(
        self, run: _Run, server_id: str, name: str, framework: str, *, loc: str, flags: Mapping[str, str]
    ) -> None:
        run.result.entities.append(
            ToolServer(
                id=server_id,
                name=name,
                provenance=Provenance(
                    method=ClaimMethod.CONFIG, locator=loc, collector=self.ref, observed_at=run.ctx.now
                ),
                tags=[f"framework:{framework}", "in-process-tools"],
                server_kind=ToolServerKind.BUILTIN,
                client=framework,
                transport=self._declared(run, Transport.IN_PROCESS, loc),
                authentication=self._declared(run, Authentication(mode=AuthMode.NONE), loc),
                trust_zone=TrustZone.LOCAL_PROCESS,
                crosses_trust_boundary=self._declared(run, False, loc),
                client_trust_flags=dict(flags),
            )
        )

    def _emit_server(self, run: _Run, server: _Mcp, server_id: str) -> None:
        loc = server.locator
        if server.in_process:
            self._emit_in_process_server(
                run, server_id, server.name, server.framework, loc=loc, flags=server.flags
            )
            self._server_tools(run, server, server_id)
            return
        decl = self._parse_server(server)
        if decl is None:
            run.result.warnings.append(
                f"{loc}: MCP server {server.name!r} has no usable command or URL; not recorded"
            )
            return
        secrets = sum(1 for kind in (*decl.env.values(), *decl.headers.values()) if kind == "literal-secret")
        tags = {f"framework:{server.framework}", *server.tags}
        command = _command_token(decl.command)
        if _secretish(decl.command):  # an inline key in the command line (``run --token=…``, ``KEY=… npx …``)
            secrets += 1
        if decl.redactions or secrets:
            run.redact(None, decl.redactions + secrets)
            run.redacted_ids.add(server_id)
        if secrets:
            tags.add("inline-secret-in-config")
        if server.gate is not None:
            tags.add(f"approval:{server.gate.value}")
        package: Claim[PackageRef] | None = None
        package_ident: dict[str, str | None] | None = None
        launch = decl.launch
        if launch is not None and launch.package_name is not None:
            ref = PackageRef(
                purl=launch.purl,
                digest=launch.digest or None,
                floating=not launch.pinned,
                launcher=launch.launcher,
            )
            package = self._declared(run, ref, loc)
            package_ident = {"purl": launch.purl or launch.package_name, "digest": launch.digest}
            if launch.float_reason:
                tags.add(f"float:{launch.float_reason}")
        stdio = decl.transport is Transport.STDIO
        identity = server_identity_digest(
            kind=ToolServerKind.MCP.value,
            transport=decl.transport.value,
            endpoint=decl.url_display if not stdio else None,
            package=package_ident,
        )
        # the same ServerDecl yields the same auth, credential and argument facts as in ``mcp-config``
        auth = server_authentication(decl, self.ref)
        prov = Provenance(method=ClaimMethod.CONFIG, locator=loc, collector=self.ref, observed_at=run.ctx.now)
        run.result.entities.append(
            ToolServer(
                id=server_id,
                name=server.name,
                provenance=prov,
                tags=sorted(tags),
                server_kind=ToolServerKind.MCP,
                digest=identity.value if identity.ok else None,
                client=server.framework,
                transport=self._declared(run, decl.transport, loc),
                endpoint=self._declared(run, decl.url_display, loc)
                if decl.url_display and not stdio
                else None,
                package=package,
                command=command,
                args_digest=server_args_digest(decl),
                env_var_names=sorted(decl.env),
                header_names=sorted(decl.headers),
                authentication=auth,
                trust_zone=TrustZone.LOCAL_PROCESS if stdio else decl.url_zone or TrustZone.UNKNOWN,
                crosses_trust_boundary=self._declared(run, False if stdio else bool(decl.url_crosses), loc),
                client_trust_flags={**decl.trust_flags, **server.flags},
            )
        )
        emit_server_credentials(run.result, decl, server_id, prov)
        self._server_tools(run, server, server_id)

    def _server_tools(self, run: _Run, server: _Mcp, server_id: str) -> None:
        allowed = [n for n in server.flags.get("claude-code.permissions.allow", "").split(",") if n]
        denied = {n for n in server.flags.get("claude-code.permissions.deny", "").split(",") if n}
        if "*" in denied:
            return  # the agent's deny rules remove every tool of this server
        bypass = server.flags.get("claude-code.defaultMode.agent-sdk") == "bypassPermissions"
        names = list(dict.fromkeys([*server.tools, *(n for n in allowed if n != "*")]))
        for name in names[:MAX_ITEMS]:
            if not _short(name) or name in denied:  # deny rules win over allow rules
                continue
            gate = (
                ApprovalGate.NONE
                if bypass or name in allowed or "*" in allowed
                else server.gate or ApprovalGate.UNKNOWN
            )
            tid = tool_id(server_id, _tool_part(name))
            run.result.entities.append(
                ToolDefinition(
                    id=tid,
                    name=name,
                    provenance=Provenance(
                        method=ClaimMethod.CONFIG,
                        locator=server.locator,
                        collector=self.ref,
                        observed_at=run.ctx.now,
                    ),
                    tags=[f"framework:{server.framework}"],
                    server_ref=server_id,
                    tool_name=name,
                    input_schema={},
                    digest=DigestResult(
                        algorithm="tooldef/v1",
                        status=DigestStatus.UNDIGESTABLE,
                        reason="declared-without-definition: only the name is configured; observe it live to pin",
                    ),
                    source=ToolSource.DECLARED_CONFIG,
                    approval_gate=gate,
                )
            )
            self._edge(
                run.result, EdgeType.PROVIDES_TOOL, server_id, tid, declared_by=server.locator, qualifiers={}
            )

    @staticmethod
    def _parse_server(server: _Mcp) -> ServerDecl | None:
        """Describe an MCP server entry with the ``mcp-config`` parser (pure; values reduced to names/redactions)."""
        entry = dict(server.entry)
        if isinstance(entry.get("transport"), str) and "type" not in entry:
            entry["type"] = entry["transport"]
        spec = ClientSpec(client=server.framework, locations=())
        loc = ConfigLocation("project", "root", "", "json", ("mcpServers",))
        try:
            decls = parse_client_config(
                spec, loc, {"mcpServers": {server.name: entry}}, server.display, Path("/")
            )
        except ValueError:  # a malformed URL (unbalanced IPv6 bracket, port out of range): not usable
            return None
        if not decls:
            return None
        decl = decls[0]
        if decl.transport is not Transport.STDIO and not decl.url_display:
            return None
        if decl.transport is Transport.STDIO and not decl.command:
            return None
        decl.locator = server.locator
        return decl

    @staticmethod
    def _edge(
        result: CollectionResult,
        kind: EdgeType,
        source: str,
        target: str,
        *,
        declared_by: str,
        qualifiers: Mapping[str, Any],
    ) -> None:
        result.edges.append(
            Edge.model_validate(
                {
                    "type": kind,
                    "from": source,
                    "to": target,
                    "scope": EdgeScope.RUNTIME,
                    "qualifiers": dict(qualifiers),
                    "declaredBy": declared_by,
                }
            )
        )


# --------------------------------------------------------------------------------------------- helpers


_FRAMEWORK_PACKAGES: Final = frozenset(spec.package.split(".")[0] for spec in PY_CONSTRUCTORS)
_AGENT_KINDS: Final = frozenset({"agent", "options", "subagent", "crew", "workflow"})
_AGENT_CTOR_NAMES: Final = frozenset(
    n for spec in PY_CONSTRUCTORS if spec.kind in _AGENT_KINDS for n in spec.names
)


def _framework_package(qualname: str) -> bool:
    top = qualname.split(".", 1)[0]
    if top == "google":
        return qualname.startswith("google.adk")
    return top in _FRAMEWORK_PACKAGES


def _module_matches(module: str, wanted: str) -> bool:
    """``src.app.agents`` matches an import of ``app.agents`` (repository roots such as ``src/`` vary)."""
    return module == wanted or module.endswith("." + wanted) or (not wanted and not module)


def _ts_framework(package: str) -> str | None:
    for prefix, framework in _TS_PACKAGE_FRAMEWORK:
        if package == prefix or package.startswith(prefix + "/"):
            return framework
    return None


def _ts_plain(value: _TsVal) -> Any:
    """A JSON-like value from the TS scanner (strings, lists, objects); anything else is ``None``."""
    if value.kind == "str":
        return value.value
    if value.kind == "list":
        return [_ts_plain(v) for v in value.value]
    if value.kind == "obj":
        return {k: _ts_plain(v) for k, v in value.value.items() if k != "..."}
    return None


def _package_label(entry: Mapping[str, Any]) -> str:
    """A readable server name from its launch command: the package (``server-filesystem``) or the command."""
    command = entry.get("command")
    if not isinstance(command, str) or not command:
        return "mcp"
    args = entry.get("args")
    launch = parse_launch(command, [str(a) for a in args] if isinstance(args, list) else [])
    if launch.package_name:
        return launch.package_name.rsplit("/", 1)[-1].split("?", 1)[0] or "mcp"
    return PurePosixPath(command).name or "mcp"


_YAML_SNIFF_BYTES: Final = 16 * 1024


def _yaml_kinds(name: str, head: bytes) -> tuple[bool, bool, bool, bool]:
    """Cheap byte checks: (CrewAI agents, ADK agent, Semantic Kernel prompt, Semantic Kernel agent)."""
    is_crew = name in _CREW_FILES and b"role" in head
    is_adk = name in _ADK_ROOT or b"agent_class" in head or b"adk-python" in head
    is_sk = b"template" in head and any(
        m in head for m in (b"template_format", b"execution_settings", b"input_variables")
    )
    is_sk_agent = b"_agent" in head and b"instructions" in head and b"type" in head
    return is_crew, is_adk, is_sk, is_sk_agent


def _framework_yaml(name: str, head: bytes) -> bool:
    return any(_yaml_kinds(name, head)) or (b"role" in head and b"goal" in head)


#: Excluded directories whose content may be the project's own agents (build output), not vendored code.
_BUILD_DIRS: Final = frozenset({"build", "dist"})
#: Entries looked at per excluded directory (a bounded sample, not a second walk).
_EXCLUDED_SAMPLE: Final = 200
_PY_FRAMEWORK_IMPORT: Final = re.compile(
    rb"(?m)^[ \t]*(?:from|import)[ \t]+(?:agents|claude_agent_sdk|langchain|langchain_mcp_adapters|langgraph|crewai|"
    rb"autogen|autogen_agentchat|autogen_ext|ag2|google\.adk|semantic_kernel|pydantic_ai|llama_index|strands|"
    rb"agent_framework)\b"
)


def _has_framework_code(directory: Path, root: Path) -> bool:
    """A bounded sample of ``directory`` (symlinks not followed) holds Python or TS/JS that imports a framework."""
    stack: list[tuple[Path, int]] = [(directory, 0)]
    seen = 0
    while stack and seen < _EXCLUDED_SAMPLE:
        current, depth = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > _EXCLUDED_SAMPLE:
                break
            if entry.is_symlink():
                continue
            if _is_dir(entry):
                if depth < 4:
                    stack.append((entry, depth + 1))
                continue
            if entry.suffix not in _CODE_SUFFIXES | _TS_SUFFIXES:
                continue
            head = _read_head(entry, root, _YAML_SNIFF_BYTES)
            if head is None:
                continue
            if entry.suffix in _CODE_SUFFIXES and _PY_FRAMEWORK_IMPORT.search(head):
                return True
            if entry.suffix in _TS_SUFFIXES and _TS_IMPORT.search(head.decode("utf-8", errors="replace")):
                return True
    return False


def _read_head(path: Path, root: Path, limit: int) -> bytes | None:
    """At most ``limit`` leading bytes of a file inside ``root`` (confined like every other read)."""
    try:
        with open_scoped_file(root, path) as fh:
            return fh.read(limit)
    except (OSError, ValueError):
        return None


def _confined(base: Path, relative: str, root: Path) -> Path | None:
    """``base / relative`` resolved, when it stays inside the scanned ``root``; ``None`` for anything else.

    Values with NUL bytes or longer than :data:`MAX_CONFIG_PATH_CHARS` are refused before any filesystem call,
    and resolution errors (loops, over-long names) are ``None``, never exceptions.
    """
    if not relative or "\x00" in relative or len(relative) > MAX_CONFIG_PATH_CHARS:
        return None
    try:
        target = (base / relative).resolve()
        bounds = root.resolve()
    except (OSError, ValueError, RuntimeError):
        return None
    return target if target.is_relative_to(bounds) else None


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except (OSError, ValueError):
        return False


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except (OSError, ValueError):
        return False


def _capped(run: _Run, decl: _Decl | None, items: Sequence[Any], fieldname: str, loc: str) -> Sequence[Any]:
    """The first :data:`MAX_ITEMS` of a configured list; a longer list makes the field ``unknown`` (or, without a
    declaration, a ``truncated`` source) and a warning, never a silent cut."""
    if len(items) <= MAX_ITEMS:
        return items
    extra = len(items) - MAX_ITEMS
    if decl is not None:
        decl.mark_unknown(fieldname, loc)
    else:
        run.result.add_source(
            Surface.CODE, "frameworks:config", locator=loc, ok=False, error_class="truncated", items=extra
        )
    run.result.warnings.append(f"{loc}: {extra} {fieldname} entr(ies) beyond {MAX_ITEMS} not read")
    return items[:MAX_ITEMS]


_LINE_SUFFIX: Final = re.compile(r":\d{1,9}$")


def _file_of(loc: str) -> str:
    """The file part of a locator (``a.py:12`` -> ``a.py``; ``x.yaml#/k`` -> ``x.yaml``)."""
    return _LINE_SUFFIX.sub("", loc.split("#", 1)[0])
