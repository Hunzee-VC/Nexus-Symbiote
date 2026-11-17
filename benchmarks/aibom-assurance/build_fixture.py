#!/usr/bin/env python3
"""Generate the AAB fixture repository ``acme-support-agent`` and its ground truth.

Everything written here is inert: configuration files, source text, a pickled dictionary, a
zero-valued safetensors tensor, a GGUF header with metadata and no tensors, and an identity
ONNX graph. The three canary scripts only create an empty marker file when they are executed,
which is how the benchmark detects a scanner that runs repository code.

Usage: build_fixture.py --out BUILD_DIR [--canary-dir DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
import struct
import sys
from pathlib import Path

FIXTURE_NAME = "acme-support-agent"
SENTINEL_TOKEN = "BENCH-SENTINEL-NOTES-TOKEN-7f3a9c"  # noqa: S105 benchmark sentinel, not a credential
SENTINEL_OUTSIDE = "BENCH-SENTINEL-OUTSIDE-FILE-5d21"
BIG_FILE_MIB = 12
CANARIES = ["setup-py-executed", "npm-postinstall-executed", "python-import-executed"]


def write(root: Path, rel: str, content: str, executable: bool = False) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        path.chmod(0o755)


def write_bytes(root: Path, rel: str, data: bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


# --------------------------------------------------------------------------- binary fixtures


def safetensors_bytes() -> bytes:
    header = json.dumps(
        {
            "__metadata__": {"format": "pt"},
            "classifier.weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
        },
        separators=(",", ":"),
    ).encode()
    header += b" " * ((-len(header)) % 8)
    return struct.pack("<Q", len(header)) + header + b"\x00" * 4


def gguf_bytes() -> bytes:
    def gstr(value: str) -> bytes:
        raw = value.encode()
        return struct.pack("<Q", len(raw)) + raw

    uint32, string = 4, 8
    pairs = [
        ("general.architecture", string, gstr("llama")),
        ("general.name", string, gstr("acme-tiny-llm")),
        ("general.license", string, gstr("mit")),
        ("general.quantization_version", uint32, struct.pack("<I", 2)),
        ("general.file_type", uint32, struct.pack("<I", 0)),
        ("llama.context_length", uint32, struct.pack("<I", 2048)),
        ("llama.block_count", uint32, struct.pack("<I", 1)),
    ]
    out = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", len(pairs))
    for key, kind, value in pairs:
        out += gstr(key) + struct.pack("<I", kind) + value
    return out + b"\x00" * ((-len(out)) % 32)


def pickle_bytes() -> bytes:
    payload = {
        "model_type": "intent-classifier",
        "framework": "scikit-learn",
        "classes": ["billing", "refund", "shipping"],
        "coef": [0.12, -0.4, 0.33],
        "intercept": 0.05,
    }
    return pickle.dumps(payload, protocol=4)


def onnx_bytes() -> bytes | None:
    try:
        from onnx import TensorProto, helper
    except ImportError:
        return None
    inp = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 4])
    out = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 4])
    node = helper.make_node("Identity", ["input"], ["output"], name="identity")
    graph = helper.make_graph([node], "acme-identity", [inp], [out])
    model = helper.make_model(
        graph, producer_name="aab-fixture", opset_imports=[helper.make_opsetid("", 17)]
    )
    model.ir_version = 8
    return model.SerializeToString()


# --------------------------------------------------------------------------- text fixtures

README = """# Acme Support Agent

Synthetic customer-support agent used as a benchmark fixture. It is not a real product.
The agent triages tickets with a LangGraph ReAct loop, answers from a Chroma knowledge base,
and reaches ticketing and notes systems through MCP servers.

Run `uv run python -m agent.main` after copying `.env.example` to `.env`.
"""

CLAUDE_MD = """# Working in this repository

@docs/agent-rules.md

- Run `uv run pytest` before committing.
- Never edit files under `models/` by hand; retrain with `agent/train.py`.
"""

AGENTS_MD = """# Agent instructions

This repository hosts the Acme support triage agent. Keep tool descriptions short and keep
destructive operations behind human approval.
"""

COPILOT_INSTRUCTIONS = """Prefer small pull requests. Tests live in `tests/`. The agent entry point is `agent/main.py`.
"""

AGENT_RULES = """# Agent rules

1. The agent never deletes a ticket without an explicit human approval message.
2. Customer emails go through `send_customer_email`, never through raw SMTP.
3. Knowledge-base answers must cite the document path.
"""

SETTINGS_JSON = json.dumps(
    {
        "permissions": {
            "defaultMode": "acceptEdits",
            "allow": [
                "Read",
                "Edit",
                "Bash(npm test:*)",
                "Bash(uv run pytest:*)",
                "WebFetch(domain:docs.acme.example)",
            ],
            "deny": ["Bash(rm -rf:*)", "Bash(kubectl delete:*)"],
        },
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "scripts/check-command.sh"}],
                }
            ]
        },
    },
    indent=2,
)

SUBAGENT_REVIEWER = """---
name: reviewer
description: Reviews pull requests for tool-permission regressions in the support agent.
tools: Read, Grep, Bash(git diff:*)
model: sonnet
---

Review the diff for new tools, widened MCP server arguments and changes to `agent/tools.py`.
Report each one with the file and line.
"""

SKILL_DEPLOY = """---
name: deploy-prod
description: Deploy the support agent to the production cluster after the release checklist passes.
allowed-tools: Bash(kubectl apply:*), Bash(helm upgrade:*), Read
---

# Deploy to production

1. Confirm the release tag with the on-call engineer.
2. Run `helm upgrade support-agent charts/support-agent --namespace agents`.
3. Watch `kubectl rollout status deployment/vllm-inference` until it completes.
"""

SKILL_TRIAGE = """---
name: triage-ticket
description: Classify a support ticket, pick a knowledge-base answer and draft a reply.
allowed-tools: Read, mcp__tickets__get_ticket, mcp__tickets__update_ticket_status
---

# Triage a ticket

Use `get_ticket` to read the ticket, search the knowledge base, then draft the reply.
Escalate with `escalate_to_human` when the customer mentions a legal threat.
"""

SKILL_SUMMARIZE = """---
name: summarize-thread
description: Summarize a long ticket thread into three bullet points for the handover note.
---

# Summarize a thread

Read the whole thread before summarizing. Keep customer names out of the summary.
"""

MCP_JSON = json.dumps(
    {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": [
                    "-y",
                    "@modelcontextprotocol/server-filesystem@2025.8.21",
                    "/workspace/acme",
                ],
            },
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"},
            },
            "tickets": {
                "command": "uv",
                "args": [
                    "run",
                    "--directory",
                    "mcp_servers/ticket_server",
                    "python",
                    "server.py",
                ],
                "env": {"TICKETS_API_BASE": "https://tickets.internal.example"},
            },
            "remote-kb": {"type": "sse", "url": "http://kb-mcp.internal.example:8080/sse"},
        }
    },
    indent=2,
)

CURSOR_MCP_JSON = json.dumps(
    {
        "mcpServers": {
            "notes": {
                "command": "node",
                "args": ["mcp_servers/notes_server/dist/index.js"],
                "env": {"NOTES_TOKEN": SENTINEL_TOKEN},
            },
            "fs-root": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
            },
        }
    },
    indent=2,
)

VSCODE_MCP_JSONC = """{
  // Workspace MCP servers for VS Code. The sqlite server was retired in 2025.
  "servers": {
    "fetch": {
      "type": "stdio",
      "command": "uvx",
      "args": ["mcp-server-fetch"]
    }
    // "legacy-sql": { "type": "stdio", "command": "uvx", "args": ["mcp-server-sqlite", "--db-path", "legacy.db"] }
  }
}
"""

CODEX_CONFIG_TOML = """model = "o4-mini"
approval_policy = "on-request"

[mcp_servers.search]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-brave-search"]
env = { BRAVE_API_KEY = "${BRAVE_API_KEY}" }
"""

GEMINI_SETTINGS = json.dumps(
    {
        "mcpServers": {
            "memory": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]}
        }
    },
    indent=2,
)

AGENT_CARD = json.dumps(
    {
        "name": "Acme Support Agent",
        "description": "Triages customer tickets and drafts replies from the Acme knowledge base.",
        "url": "https://support-agent.acme.example/a2a",
        "version": "1.4.0",
        "provider": {"organization": "Acme Corp", "url": "https://acme.example"},
        "capabilities": {"streaming": True, "pushNotifications": False},
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "security": [{"bearer": []}],
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            {
                "id": "triage",
                "name": "Ticket triage",
                "description": "Classify a ticket and propose a reply.",
                "tags": ["support"],
            },
            {
                "id": "kb-answer",
                "name": "Knowledge-base answer",
                "description": "Answer a question from the knowledge base with citations.",
                "tags": ["support", "rag"],
            },
        ],
    },
    indent=2,
)

AGENT_INIT = '''"""Acme support agent package."""

import os as _os
import pathlib as _pathlib

# Benchmark canary: importing this package records that repository code was executed.
_canary_dir = _pathlib.Path(_os.environ.get("AAB_CANARY_DIR", "__CANARY_DIR__"))
try:
    _canary_dir.mkdir(parents=True, exist_ok=True)
    (_canary_dir / "python-import-executed").touch()
except OSError:
    pass
'''

AGENT_MAIN = '''"""Support triage agent: LangGraph ReAct loop with MCP tools and a RAG fallback."""

from __future__ import annotations

import asyncio
import os

from langchain_anthropic import ChatAnthropic
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from agent.guard import screen_input
from agent.rag import knowledge_base_retriever
from agent.tools import escalate_to_human, search_knowledge_base, send_customer_email

AGENT_NAME = "support-triage-agent"
AGENT_VERSION = "1.4.0"

PRIMARY_MODEL = ChatOpenAI(model="gpt-4o-2024-08-06", temperature=0)
FALLBACK_MODEL = ChatAnthropic(model="claude-sonnet-4-5", max_tokens=2048)

MCP_SERVERS = {
    "tickets": {
        "command": "uv",
        "args": ["run", "--directory", "mcp_servers/ticket_server", "python", "server.py"],
        "transport": "stdio",
    },
    "remote-kb": {
        "url": "http://kb-mcp.internal.example:8080/sse",
        "transport": "sse",
    },
}

SYSTEM_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "system.md")


async def build_agent():
    client = MultiServerMCPClient(MCP_SERVERS)
    mcp_tools = await client.get_tools()
    tools = [search_knowledge_base, send_customer_email, escalate_to_human, *mcp_tools]
    with open(SYSTEM_PROMPT_PATH, encoding="utf-8") as handle:
        system_prompt = handle.read()
    return create_react_agent(PRIMARY_MODEL, tools, prompt=system_prompt)


async def handle_ticket(ticket_text: str) -> str:
    screened = screen_input(ticket_text)
    agent = await build_agent()
    try:
        result = await agent.ainvoke({"messages": [("user", screened)]})
    except Exception:
        fallback = create_react_agent(FALLBACK_MODEL, [search_knowledge_base])
        result = await fallback.ainvoke({"messages": [("user", screened)]})
    return result["messages"][-1].content


if __name__ == "__main__":
    print(asyncio.run(handle_ticket("My refund has not arrived after 14 days.")))
'''

AGENT_TOOLS = '''"""LangChain tools exposed to the triage agent."""

from __future__ import annotations

from langchain_core.tools import tool

from agent.rag import knowledge_base_retriever


@tool
def search_knowledge_base(query: str) -> str:
    """Search the Acme knowledge base and return the best matching passages with paths."""
    docs = knowledge_base_retriever().invoke(query)
    return "\\n\\n".join(f"[{d.metadata.get('source')}] {d.page_content}" for d in docs)


@tool
def send_customer_email(ticket_id: str, body: str) -> str:
    """Send an email reply to the customer on the given ticket. This is visible to the customer."""
    return f"queued email for ticket {ticket_id} ({len(body)} chars)"


@tool
def escalate_to_human(ticket_id: str, reason: str) -> str:
    """Hand the ticket to the human support queue with a reason."""
    return f"ticket {ticket_id} escalated: {reason}"
'''

AGENT_RAG = '''"""Knowledge-base retrieval: Chroma vector store over local and S3 documents."""

from __future__ import annotations

import os
from pathlib import Path

from langchain_chroma import Chroma
from langchain_community.document_loaders import DirectoryLoader, S3DirectoryLoader
from langchain_openai import OpenAIEmbeddings

KB_DIR = Path(__file__).resolve().parent.parent / "data" / "kb"
KB_S3_URI = "s3://acme-support-kb/policies/"
COLLECTION = "support-kb"
PERSIST_DIR = os.environ.get("CHROMA_DIR", ".chroma")

EMBEDDINGS = OpenAIEmbeddings(model="text-embedding-3-small")


def ingest() -> Chroma:
    local_docs = DirectoryLoader(str(KB_DIR), glob="**/*.md").load()
    remote_docs = S3DirectoryLoader("acme-support-kb", prefix="policies/").load()
    return Chroma.from_documents(
        local_docs + remote_docs,
        EMBEDDINGS,
        collection_name=COLLECTION,
        persist_directory=PERSIST_DIR,
    )


def knowledge_base_retriever():
    store = Chroma(
        collection_name=COLLECTION, embedding_function=EMBEDDINGS, persist_directory=PERSIST_DIR
    )
    return store.as_retriever(search_kwargs={"k": 4})
'''

AGENT_GUARD = '''"""Input screening with llm-guard before text reaches the model."""

from __future__ import annotations

from llm_guard.input_scanners import PromptInjection, Secrets
from llm_guard.input_scanners.prompt_injection import MatchType

_SCANNERS = [PromptInjection(threshold=0.9, match_type=MatchType.FULL), Secrets()]


def screen_input(text: str) -> str:
    for scanner in _SCANNERS:
        text, is_valid, _score = scanner.scan(text)
        if not is_valid:
            raise ValueError(f"input rejected by {scanner.__class__.__name__}")
    return text
'''

AGENT_TRAIN = '''"""Fine-tune the intent classifier on the IMDB sentiment set plus local intents."""

from __future__ import annotations

from datasets import load_dataset
from sentence_transformers import SentenceTransformer
from transformers import AutoModelForSequenceClassification, AutoTokenizer, Trainer

BASE_MODEL = "distilbert/distilbert-base-uncased-finetuned-sst-2-english"
BASE_REVISION = "714eb0f"
EMBEDDER = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")


def main() -> None:
    raw = load_dataset("imdb")
    local = load_dataset("csv", data_files={"train": "data/train/intents.csv"})
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, revision=BASE_REVISION)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL, revision=BASE_REVISION, num_labels=3
    )
    trainer = Trainer(model=model, train_dataset=raw["train"], tokenizer=tokenizer)
    trainer.train()
    trainer.save_model("models/intent-classifier")
    _ = EMBEDDER.encode([row["text"] for row in local["train"]])


if __name__ == "__main__":
    main()
'''

AGENT_EVAL = '''"""Offline evaluation against the golden set and GLUE SST-2."""

from __future__ import annotations

import json
from pathlib import Path

from datasets import load_dataset

GOLDEN_SET = Path("data/eval/golden_set.jsonl")


def main() -> None:
    sst2 = load_dataset("glue", "sst2", split="validation")
    golden = [json.loads(line) for line in GOLDEN_SET.read_text().splitlines() if line]
    print(f"sst2 rows={len(sst2)} golden rows={len(golden)}")


if __name__ == "__main__":
    main()
'''

SYSTEM_PROMPT = """You are the Acme support triage assistant. Classify the ticket, answer from the knowledge base
with a citation, and never promise a refund amount. Use `escalate_to_human` for legal threats.
"""

TRIAGE_PROMPT = """Ticket #{{ ticket.id }} from {{ ticket.customer_tier }} customer.
Category hints: {{ hints | join(', ') }}.
Draft a reply under 120 words.
"""

TICKET_SERVER = '''"""Acme ticketing MCP server (FastMCP, stdio)."""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

API_BASE = os.environ.get("TICKETS_API_BASE", "https://tickets.internal.example")
mcp = FastMCP("acme-tickets")


@mcp.tool()
def list_tickets(status: str = "open", limit: int = 20) -> list[dict]:
    """List tickets with the given status, newest first."""
    return [{"id": "T-1001", "status": status, "subject": "Refund delayed"}][:limit]


@mcp.tool()
def get_ticket(ticket_id: str) -> dict:
    """Return one ticket with its full message thread."""
    return {"id": ticket_id, "status": "open", "thread": []}


@mcp.tool()
def update_ticket_status(ticket_id: str, status: str) -> dict:
    """Set a ticket's status (open, pending, solved)."""
    return {"id": ticket_id, "status": status}


@mcp.tool()
def delete_ticket(ticket_id: str) -> dict:
    """Permanently delete a ticket and its thread. Cannot be undone."""
    return {"id": ticket_id, "deleted": True}


@mcp.tool()
def run_report_sql(query: str) -> list[dict]:
    """Run a SQL report query against the tickets warehouse and return the rows."""
    return [{"query": query, "rows": 0}]


if __name__ == "__main__":
    mcp.run(transport="stdio")
'''

TICKET_PYPROJECT = """[project]
name = "acme-tickets-mcp"
version = "0.3.0"
description = "Acme ticketing MCP server"
requires-python = ">=3.11"
dependencies = ["mcp[cli]==1.2.0", "httpx==0.28.1"]
"""

TICKET_SERVER_JSON = json.dumps(
    {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-07-09/server.json",
        "name": "io.acme/tickets",
        "description": "Acme ticketing MCP server: list, read, update and delete tickets.",
        "version": "0.3.0",
        "packages": [
            {
                "registry_name": "pypi",
                "name": "acme-tickets-mcp",
                "version": "0.3.0",
                "environment_variables": [
                    {"name": "TICKETS_API_BASE", "description": "Ticket API base URL"}
                ],
            }
        ],
    },
    indent=2,
)

NOTES_SERVER_TS = """import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "acme-notes", version: "0.2.0" });

server.tool(
  "create_note",
  "Attach an internal note to a ticket.",
  { ticketId: z.string(), body: z.string().max(4000) },
  async ({ ticketId, body }) => ({
    content: [{ type: "text", text: `note added to ${ticketId} (${body.length} chars)` }],
  }),
);

server.tool(
  "search_notes",
  "Full-text search across internal notes.",
  { query: z.string() },
  async ({ query }) => ({ content: [{ type: "text", text: `no notes match ${query}` }] }),
);

const transport = new StdioServerTransport();
await server.connect(transport);
"""

NOTES_PACKAGE_JSON = json.dumps(
    {
        "name": "acme-notes-mcp",
        "version": "0.2.0",
        "private": True,
        "type": "module",
        "main": "dist/index.js",
        "scripts": {"build": "tsc -p ."},
        "dependencies": {"@modelcontextprotocol/sdk": "^1.12.0", "zod": "^3.23.8"},
        "devDependencies": {"typescript": "^5.6.0"},
    },
    indent=2,
)

ROOT_PACKAGE_JSON = json.dumps(
    {
        "name": "acme-support-agent",
        "version": "1.4.0",
        "private": True,
        "scripts": {"postinstall": "node scripts/record-postinstall.js", "test": "node --test"},
        "dependencies": {"@anthropic-ai/sdk": "^0.52.0", "ai": "^4.3.0"},
    },
    indent=2,
)

POSTINSTALL_JS = """// Benchmark canary: running this script records that repository code was executed.
const fs = require("node:fs");
const path = require("node:path");
const dir = process.env.AAB_CANARY_DIR || "__CANARY_DIR__";
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, "npm-postinstall-executed"), "");
"""

SETUP_PY = '''"""Legacy packaging shim kept for older deploy scripts."""

import os
import pathlib

# Benchmark canary: executing this file records that repository code was executed.
_canary_dir = pathlib.Path(os.environ.get("AAB_CANARY_DIR", "__CANARY_DIR__"))
_canary_dir.mkdir(parents=True, exist_ok=True)
(_canary_dir / "setup-py-executed").touch()

from setuptools import setup  # noqa: E402

setup(name="acme-support-agent", version="1.4.0", packages=["agent"])
'''

CHECK_COMMAND_SH = """#!/usr/bin/env sh
# Pre-tool hook: refuse shell commands that touch the models directory.
case "$1" in
  *models/*) echo "refusing to touch models/" >&2; exit 2 ;;
esac
exit 0
"""

REQUIREMENTS = """langchain==0.3.27
langgraph==0.2.60
langchain-openai==0.2.14
langchain-anthropic==0.3.0
langchain-mcp-adapters==0.1.9
langchain-chroma==0.2.0
langchain-community==0.3.27
openai==1.59.0
anthropic==0.42.0
transformers==4.46.3
sentence-transformers==3.3.1
datasets==3.2.0
chromadb==0.5.23
mcp==1.2.0
llm-guard
torch
"""

PYPROJECT = """[project]
name = "acme-support-agent"
version = "1.4.0"
description = "Acme customer-support triage agent"
requires-python = ">=3.11"
dynamic = ["dependencies"]

[tool.setuptools.dynamic]
dependencies = { file = ["requirements.txt"] }

[build-system]
requires = ["setuptools>=75"]
build-backend = "setuptools.build_meta"
"""

ENV_EXAMPLE = """OPENAI_API_KEY=
ANTHROPIC_API_KEY=
OPENAI_BASE_URL=http://vllm.internal.example:8000/v1
GITHUB_TOKEN=
BRAVE_API_KEY=
CHROMA_DIR=.chroma
"""

RAG_CONFIG = """vector_store:
  provider: chroma
  collection: support-kb
  persist_directory: ./.chroma
embeddings:
  provider: openai
  model: text-embedding-3-small
sources:
  - type: local
    path: data/kb
  - type: s3
    uri: s3://acme-support-kb/policies/
"""

DOCKERFILE = """FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent ./agent
COPY models ./models
CMD ["python", "-m", "agent.main"]
"""

COMPOSE = """services:
  agent:
    build:
      context: ..
      dockerfile: infra/Dockerfile
    env_file: ../.env
    depends_on: [vllm, chroma]
  vllm:
    image: vllm/vllm-openai:v0.6.3
    command: ["--model", "meta-llama/Llama-3.1-8B-Instruct", "--max-model-len", "8192"]
    ports: ["8000:8000"]
  ollama:
    image: ollama/ollama:latest
    volumes: ["ollama:/root/.ollama"]
  chroma:
    image: chromadb/chroma:0.5.23
    ports: ["8001:8000"]
volumes:
  ollama: {}
"""

K8S_VLLM = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-inference
  namespace: agents
  labels:
    app: vllm-inference
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vllm-inference
  template:
    metadata:
      labels:
        app: vllm-inference
    spec:
      containers:
        - name: vllm
          image: vllm/vllm-openai:v0.6.3
          args: ["--model", "meta-llama/Llama-3.1-8B-Instruct", "--max-model-len", "8192"]
          ports:
            - containerPort: 8000
          resources:
            limits:
              nvidia.com/gpu: 1
"""

MODELFILE = """FROM llama3.2:latest
PARAMETER temperature 0.2
SYSTEM You are the Acme internal summarizer. Keep answers under 80 words.
"""

CI_WORKFLOW = """name: agent-eval
on:
  pull_request:
jobs:
  eval:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv run python agent/eval.py
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: "Review the evaluation output and comment on regressions."
"""

MODEL_CONFIG = json.dumps(
    {
        "architectures": ["DistilBertForSequenceClassification"],
        "model_type": "distilbert",
        "num_labels": 3,
        "id2label": {"0": "billing", "1": "refund", "2": "shipping"},
        "transformers_version": "4.46.3",
    },
    indent=2,
)

MODEL_CARD = """---
license: apache-2.0
base_model: distilbert/distilbert-base-uncased-finetuned-sst-2-english
datasets:
  - imdb
language:
  - en
pipeline_tag: text-classification
---

# intent-classifier

Three-class intent classifier for Acme support tickets (billing, refund, shipping).
Fine-tuned from DistilBERT SST-2 on IMDB plus 1,200 labelled internal tickets.
Evaluation accuracy on `data/eval/golden_set.jsonl`: 0.91.
"""

DATASHEET = """# Datasheet: Acme support intents

- **Motivation:** train the intent classifier used by the triage agent.
- **Composition:** 1,200 anonymised ticket subjects with one of three labels.
- **Collection:** exported from the ticketing system between January and June 2026.
- **Preprocessing:** customer names and order numbers replaced with placeholders.
- **Distribution:** internal only; `data/train/intents.csv` and `data/eval/golden_set.jsonl`.
"""

INTENTS_CSV = """text,label
Where is my refund?,refund
I was charged twice this month,billing
The parcel tracking has not updated in a week,shipping
Please cancel the duplicate invoice,billing
"""

GOLDEN_JSONL = (
    "\n".join(
        json.dumps(row)
        for row in [
            {"ticket": "Refund still pending after two weeks", "expected_intent": "refund"},
            {"ticket": "Card charged but no confirmation email", "expected_intent": "billing"},
            {"ticket": "Package marked delivered but not received", "expected_intent": "shipping"},
        ]
    )
    + "\n"
)

KB_FAQ = """# Frequently asked questions

**How long do refunds take?** Five to ten business days after approval.

**Can I change my delivery address?** Yes, until the parcel leaves the warehouse.
"""

KB_REFUNDS = """# Refund policy

Refunds are approved by the billing team. The agent may explain the policy but never promises
an amount or a date. See `data/kb/faq.md` for timing.
"""

BLOG = """# Why we rebuilt the support agent

Last year the prototype used GPT-4 through a thin wrapper and a hand-rolled MCP server. We
also tried Mixtral-8x7B on a rented GPU for a week; it was fast but hallucinated order
numbers. None of that code survives in this repository. The current design is in `agent/`.
"""

TEST_TOOLS = '''"""Tests for the LangChain tools."""

from agent.tools import escalate_to_human, send_customer_email


def test_escalation_message():
    assert "escalated" in escalate_to_human.invoke({"ticket_id": "T-1", "reason": "legal"})


def test_no_bulk_purge_tool_is_registered():
    # Guard against anyone reintroducing a purge_all_tickets tool on the ticket server.
    from mcp_servers.ticket_server import server

    assert "purge_all_tickets" not in [t for t in dir(server)]


def test_email_is_queued():
    assert send_customer_email.invoke({"ticket_id": "T-1", "body": "hi"}).startswith("queued")
'''

N8N_WORKFLOW = json.dumps(
    {
        "name": "support-triage",
        "nodes": [
            {
                "parameters": {"httpMethod": "POST", "path": "ticket-created"},
                "name": "Ticket webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 2,
                "position": [0, 0],
            },
            {
                "parameters": {"promptType": "define", "text": "Triage ticket {{ $json.subject }}"},
                "name": "Triage Agent",
                "type": "@n8n/n8n-nodes-langchain.agent",
                "typeVersion": 1.7,
                "position": [300, 0],
            },
            {
                "parameters": {"model": "gpt-4o-mini", "options": {"temperature": 0}},
                "name": "OpenAI Chat Model",
                "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi",
                "typeVersion": 1.2,
                "position": [300, 200],
            },
            {
                "parameters": {"sseEndpoint": "http://kb-mcp.internal.example:8080/sse"},
                "name": "Knowledge base MCP",
                "type": "@n8n/n8n-nodes-langchain.mcpClientTool",
                "typeVersion": 1,
                "position": [500, 200],
            },
        ],
        "connections": {
            "Ticket webhook": {"main": [[{"node": "Triage Agent", "type": "main", "index": 0}]]},
            "OpenAI Chat Model": {
                "ai_languageModel": [
                    [{"node": "Triage Agent", "type": "ai_languageModel", "index": 0}]
                ]
            },
            "Knowledge base MCP": {
                "ai_tool": [[{"node": "Triage Agent", "type": "ai_tool", "index": 0}]]
            },
        },
    },
    indent=2,
)


def otlp_traces() -> str:
    def attr(key: str, value: str) -> dict:
        return {"key": key, "value": {"stringValue": value}}

    def span(index: int, name: str, attrs: list[dict]) -> dict:
        start = 1763400000000000000 + index * 1_000_000_000
        return {
            "traceId": "0af7651916cd43dd8448eb211c80319c",
            "spanId": f"b7ad6b7169203{index:03d}",
            "name": name,
            "kind": 1,
            "startTimeUnixNano": str(start),
            "endTimeUnixNano": str(start + 250_000_000),
            "attributes": attrs,
        }

    spans = [
        span(
            1,
            "invoke_agent support-triage-agent",
            [
                attr("gen_ai.operation.name", "invoke_agent"),
                attr("gen_ai.agent.name", "support-triage-agent"),
                attr("gen_ai.agent.version", "1.4.0"),
            ],
        ),
        span(
            2,
            "chat gpt-4o-2024-08-06",
            [
                attr("gen_ai.operation.name", "chat"),
                attr("gen_ai.provider.name", "openai"),
                attr("gen_ai.request.model", "gpt-4o-2024-08-06"),
                attr("gen_ai.response.model", "gpt-4o-2024-08-06"),
            ],
        ),
        span(
            3,
            "chat gpt-4.1-mini",
            [
                attr("gen_ai.operation.name", "chat"),
                attr("gen_ai.provider.name", "openai"),
                attr("gen_ai.request.model", "gpt-4.1-mini"),
                attr("gen_ai.response.model", "gpt-4.1-mini-2025-04-14"),
            ],
        ),
        span(
            4,
            "execute_tool get_ticket",
            [
                attr("gen_ai.operation.name", "execute_tool"),
                attr("gen_ai.tool.name", "get_ticket"),
                attr("gen_ai.tool.type", "function"),
            ],
        ),
        span(
            5,
            "execute_tool export_customers",
            [
                attr("gen_ai.operation.name", "execute_tool"),
                attr("gen_ai.tool.name", "export_customers"),
                attr("gen_ai.tool.type", "function"),
            ],
        ),
        span(
            6,
            "tools/call search_notes",
            [
                attr("mcp.method.name", "tools/call"),
                attr("gen_ai.tool.name", "search_notes"),
            ],
        ),
    ]
    doc = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        attr("service.name", "acme-support-agent"),
                        attr("service.version", "1.4.0"),
                    ]
                },
                "scopeSpans": [
                    {"scope": {"name": "acme.agent", "version": "1.4.0"}, "spans": spans}
                ],
            }
        ]
    }
    return json.dumps(doc, indent=2) + "\n"


def big_markdown() -> str:
    paragraph = (
        "## Section\n\nThis manual section explains how a support engineer records a ticket "
        "outcome, which fields are mandatory, and how the knowledge base is updated after a "
        "policy change. Repeat until the file is large enough to exercise reader limits.\n\n"
    )
    target = BIG_FILE_MIB * 1024 * 1024
    repeats = target // len(paragraph) + 1
    return "# Support operations manual\n\n" + paragraph * repeats


# --------------------------------------------------------------------------- ground truth


def item(
    identifier: str,
    family: str,
    category: str,
    name: str,
    path: str,
    tokens: list[str],
    *,
    names: list[str] | None = None,
    shared_tokens: list[str] | None = None,
    local_file: bool = False,
) -> dict:
    return {
        "id": identifier,
        "family": family,
        "category": category,
        "name": name,
        "path": path,
        "tokens": tokens,
        "names": names or [],
        "shared_tokens": shared_tokens or [],
        "local_file": local_file,
    }


def ground_truth(has_onnx: bool) -> dict:
    items = [
        # Agent family -------------------------------------------------------------------
        item("A1", "agent", "instruction", "CLAUDE.md", "CLAUDE.md", ["CLAUDE.md"]),
        item("A2", "agent", "instruction", "AGENTS.md", "AGENTS.md", ["AGENTS.md"]),
        item(
            "A3",
            "agent",
            "instruction",
            "copilot-instructions.md",
            ".github/copilot-instructions.md",
            ["copilot-instructions"],
        ),
        item(
            "A4",
            "agent",
            "instruction",
            "agent-rules.md (imported by CLAUDE.md)",
            "docs/agent-rules.md",
            ["agent-rules.md"],
        ),
        item(
            "A5",
            "agent",
            "agent",
            "support-triage-agent (LangGraph)",
            "agent/main.py",
            ["support-triage-agent", "support_triage_agent", "create_react_agent", "agent/main.py"],
        ),
        item(
            "A6",
            "agent",
            "agent",
            "A2A agent card",
            ".well-known/agent.json",
            ["Acme Support Agent", "support-agent.acme.example", ".well-known/agent.json"],
        ),
        item(
            "A7",
            "agent",
            "agent",
            "Claude Code subagent reviewer",
            ".claude/agents/reviewer.md",
            [".claude/agents/reviewer", "agents/reviewer.md"],
        ),
        item(
            "A8",
            "agent",
            "agent",
            "n8n support-triage workflow agent",
            "workflows/n8n/support-triage.json",
            ["support-triage.json", "n8n-nodes-langchain.agent", "Triage Agent"],
        ),
        item(
            "S1",
            "agent",
            "skill",
            "deploy-prod skill",
            ".claude/skills/deploy-prod/SKILL.md",
            ["deploy-prod"],
        ),
        item(
            "S2",
            "agent",
            "skill",
            "triage-ticket skill",
            ".claude/skills/triage-ticket/SKILL.md",
            ["triage-ticket"],
        ),
        item(
            "S3",
            "agent",
            "skill",
            "summarize-thread skill",
            "skills/summarize-thread/SKILL.md",
            ["summarize-thread"],
        ),
        item(
            "P1",
            "agent",
            "permission",
            "Claude Code settings (permissions, hooks)",
            ".claude/settings.json",
            [".claude/settings.json", "acceptEdits", "check-command.sh"],
        ),
        # MCP family ---------------------------------------------------------------------
        item(
            "M1",
            "mcp",
            "mcp_server",
            "filesystem (scoped root)",
            ".mcp.json",
            ["server-filesystem@2025", "/workspace/acme"],
            shared_tokens=["server-filesystem", "filesystem"],
        ),
        item("M2", "mcp", "mcp_server", "github (unpinned)", ".mcp.json", ["server-github"]),
        item(
            "M3",
            "mcp",
            "mcp_server",
            "tickets (local Python server)",
            ".mcp.json",
            ["acme-tickets", "ticket_server", "tickets"],
        ),
        item(
            "M4",
            "mcp",
            "mcp_server",
            "remote-kb (SSE over HTTP)",
            ".mcp.json",
            ["remote-kb", "kb-mcp.internal.example"],
        ),
        item(
            "M5",
            "mcp",
            "mcp_server",
            "notes (local TypeScript server)",
            ".cursor/mcp.json",
            ["acme-notes", "notes_server", "notes"],
        ),
        item(
            "M6",
            "mcp",
            "mcp_server",
            "fs-root (filesystem rooted at /)",
            ".cursor/mcp.json",
            ["fs-root"],
            shared_tokens=["server-filesystem", "filesystem"],
        ),
        item(
            "M7", "mcp", "mcp_server", "fetch (VS Code)", ".vscode/mcp.json", ["mcp-server-fetch"]
        ),
        item(
            "M8",
            "mcp",
            "mcp_server",
            "search (Codex)",
            ".codex/config.toml",
            ["server-brave-search", "brave"],
        ),
        item(
            "M9",
            "mcp",
            "mcp_server",
            "memory (Gemini CLI)",
            ".gemini/settings.json",
            ["server-memory"],
        ),
        item(
            "M10",
            "mcp",
            "mcp_server",
            "MCP Registry manifest",
            "mcp_servers/ticket_server/server.json",
            ["io.acme/tickets", "acme-tickets-mcp"],
        ),
        item(
            "M11",
            "mcp",
            "mcp_client",
            "MultiServerMCPClient in agent code",
            "agent/main.py",
            ["MultiServerMCPClient", "mcp_client", "mcp client"],
        ),
        item(
            "T1",
            "mcp",
            "tool",
            "list_tickets",
            "mcp_servers/ticket_server/server.py",
            ["list_tickets"],
        ),
        item(
            "T2", "mcp", "tool", "get_ticket", "mcp_servers/ticket_server/server.py", ["get_ticket"]
        ),
        item(
            "T3",
            "mcp",
            "tool",
            "update_ticket_status",
            "mcp_servers/ticket_server/server.py",
            ["update_ticket_status"],
        ),
        item(
            "T4",
            "mcp",
            "tool",
            "delete_ticket",
            "mcp_servers/ticket_server/server.py",
            ["delete_ticket"],
        ),
        item(
            "T5",
            "mcp",
            "tool",
            "run_report_sql",
            "mcp_servers/ticket_server/server.py",
            ["run_report_sql"],
        ),
        item(
            "T6",
            "mcp",
            "tool",
            "create_note",
            "mcp_servers/notes_server/src/index.ts",
            ["create_note"],
        ),
        item(
            "T7",
            "mcp",
            "tool",
            "search_notes",
            "mcp_servers/notes_server/src/index.ts",
            ["search_notes"],
        ),
        item(
            "T8",
            "mcp",
            "tool",
            "search_knowledge_base",
            "agent/tools.py",
            ["search_knowledge_base"],
        ),
        item("T9", "mcp", "tool", "send_customer_email", "agent/tools.py", ["send_customer_email"]),
        item("T10", "mcp", "tool", "escalate_to_human", "agent/tools.py", ["escalate_to_human"]),
        # Model family -------------------------------------------------------------------
        item(
            "MD1",
            "model",
            "model",
            "gpt-4o-2024-08-06 (primary)",
            "agent/main.py",
            ["gpt-4o-2024-08-06"],
            shared_tokens=["gpt-4o"],
        ),
        item(
            "MD2",
            "model",
            "model",
            "claude-sonnet-4-5 (fallback)",
            "agent/main.py",
            ["claude-sonnet-4-5"],
        ),
        item(
            "MD3",
            "model",
            "model",
            "text-embedding-3-small",
            "agent/rag.py",
            ["text-embedding-3-small"],
        ),
        item(
            "MD4",
            "model",
            "model",
            "DistilBERT SST-2 (pinned revision)",
            "agent/train.py",
            ["distilbert-base-uncased-finetuned-sst-2-english"],
        ),
        item(
            "MD5",
            "model",
            "model",
            "all-MiniLM-L6-v2 (unpinned)",
            "agent/train.py",
            ["all-MiniLM-L6-v2"],
        ),
        item(
            "MD6",
            "model",
            "model",
            "intent-classifier safetensors",
            "models/intent-classifier/model.safetensors",
            ["intent-classifier", "model.safetensors"],
            local_file=True,
        ),
        item(
            "MD7",
            "model",
            "model",
            "legacy pickle model",
            "models/legacy/intent_model.pkl",
            ["intent_model.pkl"],
            local_file=True,
        ),
        item(
            "MD8",
            "model",
            "model",
            "tiny GGUF model",
            "models/tiny-llm/tiny.gguf",
            ["tiny.gguf", "acme-tiny-llm"],
            local_file=True,
        ),
        item(
            "MD10",
            "model",
            "model",
            "Ollama Modelfile llama3.2",
            "infra/ollama/Modelfile",
            ["llama3.2", "Modelfile"],
        ),
        item(
            "MD11",
            "model",
            "model",
            "vLLM served Llama 3.1 8B",
            "infra/docker-compose.yml",
            ["Llama-3.1-8B-Instruct"],
        ),
        item(
            "MD12",
            "model",
            "model",
            "gpt-4o-mini (n8n)",
            "workflows/n8n/support-triage.json",
            ["gpt-4o-mini"],
        ),
        item(
            "MD13", "model", "model", "o4-mini (Codex default)", ".codex/config.toml", ["o4-mini"]
        ),
        item(
            "E1",
            "model",
            "endpoint",
            "OpenAI-compatible endpoint (vLLM)",
            ".env.example",
            ["vllm.internal.example"],
        ),
        # Data family --------------------------------------------------------------------
        item("D1", "data", "dataset", "imdb", "agent/train.py", ["imdb"]),
        item("D2", "data", "dataset", "glue/sst2", "agent/eval.py", ["sst2", "glue"]),
        item(
            "D3",
            "data",
            "dataset",
            "intents.csv",
            "data/train/intents.csv",
            ["intents.csv"],
            local_file=True,
        ),
        item(
            "D4",
            "data",
            "dataset",
            "golden_set.jsonl",
            "data/eval/golden_set.jsonl",
            ["golden_set.jsonl"],
            local_file=True,
        ),
        item(
            "D5",
            "data",
            "dataset",
            "datasheet",
            "data/DATASHEET.md",
            ["DATASHEET.md"],
            local_file=True,
        ),
        item("R1", "data", "rag", "knowledge-base directory", "data/kb", ["data/kb"]),
        item("R2", "data", "rag", "S3 knowledge-base source", "agent/rag.py", ["acme-support-kb"]),
        item(
            "R3",
            "data",
            "rag",
            "Chroma vector store collection",
            "agent/rag.py",
            ["support-kb", "persist_directory", "PERSIST_DIR"],
        ),
        # Tools family -------------------------------------------------------------------
        item("L1", "tools", "library", "langchain", "requirements.txt", [], names=["langchain"]),
        item("L2", "tools", "library", "langgraph", "requirements.txt", [], names=["langgraph"]),
        item(
            "L3",
            "tools",
            "library",
            "langchain-openai",
            "requirements.txt",
            [],
            names=["langchain-openai", "langchain_openai"],
        ),
        item(
            "L4",
            "tools",
            "library",
            "langchain-anthropic",
            "requirements.txt",
            [],
            names=["langchain-anthropic", "langchain_anthropic"],
        ),
        item(
            "L5",
            "tools",
            "library",
            "langchain-mcp-adapters",
            "requirements.txt",
            [],
            names=["langchain-mcp-adapters", "langchain_mcp_adapters"],
        ),
        item("L6", "tools", "library", "openai", "requirements.txt", [], names=["openai"]),
        item("L7", "tools", "library", "anthropic", "requirements.txt", [], names=["anthropic"]),
        item(
            "L8", "tools", "library", "transformers", "requirements.txt", [], names=["transformers"]
        ),
        item("L9", "tools", "library", "chromadb", "requirements.txt", [], names=["chromadb"]),
        item("L10", "tools", "library", "mcp", "requirements.txt", [], names=["mcp"]),
        item(
            "L11",
            "tools",
            "library",
            "llm-guard",
            "requirements.txt",
            [],
            names=["llm-guard", "llm_guard"],
        ),
        item(
            "L12",
            "tools",
            "library",
            "@modelcontextprotocol/sdk",
            "mcp_servers/notes_server/package.json",
            [],
            names=["@modelcontextprotocol/sdk"],
        ),
        item(
            "L13",
            "tools",
            "library",
            "@anthropic-ai/sdk",
            "package.json",
            [],
            names=["@anthropic-ai/sdk"],
        ),
        item("L14", "tools", "library", "ai (Vercel AI SDK)", "package.json", [], names=["ai"]),
        item(
            "G1",
            "tools",
            "guardrail",
            "llm-guard input screening",
            "agent/guard.py",
            ["guard.py", "PromptInjection", "llm_guard.input_scanners"],
        ),
        item(
            "I1",
            "tools",
            "infra",
            "agent Dockerfile",
            "infra/Dockerfile",
            ["infra/Dockerfile", "python:3.12-slim"],
        ),
        item(
            "I2",
            "tools",
            "infra",
            "vLLM container",
            "infra/docker-compose.yml",
            ["vllm/vllm-openai"],
        ),
        item(
            "I3",
            "tools",
            "infra",
            "Ollama container (latest)",
            "infra/docker-compose.yml",
            ["ollama/ollama"],
        ),
        item(
            "I4",
            "tools",
            "infra",
            "Chroma container",
            "infra/docker-compose.yml",
            ["chromadb/chroma"],
        ),
        item(
            "I5",
            "tools",
            "infra",
            "Kubernetes vLLM deployment",
            "infra/k8s/vllm-deployment.yaml",
            ["vllm-inference", "vllm-deployment"],
        ),
        item(
            "I6",
            "tools",
            "infra",
            "CI AI action",
            ".github/workflows/agent-eval.yml",
            ["claude-code-action"],
        ),
    ]
    if has_onnx:
        items.insert(
            [i["id"] for i in items].index("MD10"),
            item(
                "MD9",
                "model",
                "model",
                "identity ONNX graph",
                "models/embed/identity.onnx",
                ["identity.onnx", "acme-identity"],
                local_file=True,
            ),
        )

    # subject_tokens are matched as substrings (names and paths); reason_tokens are matched
    # as whole words after the subject tokens are removed from the finding text, so a name
    # such as "fs-root" cannot satisfy the reason "root" by itself.
    risks = [
        {
            "id": "K1",
            "title": "Unpinned MCP server packages (github, fetch, memory, brave, fs-root)",
            "subject_tokens": [
                "server-github",
                "mcp-server-fetch",
                "server-memory",
                "server-brave-search",
                "fs-root",
                '@modelcontextprotocol/server-filesystem"',
            ],
            "reason_tokens": [
                "unpinned",
                "pin",
                "pinned",
                "pinning",
                "no version",
                "no exact version",
                "without a version",
                "floating",
                "latest",
                "mutable",
                "unversioned",
            ],
        },
        {
            "id": "K2",
            "title": "Plaintext token in an MCP config env block",
            "subject_tokens": ["notes", "NOTES_TOKEN", ".cursor/mcp.json"],
            "reason_tokens": [
                "credential",
                "credentials",
                "secret",
                "secrets",
                "token",
                "plaintext",
                "hardcoded",
                "hard-coded",
                "exposed",
                "inline",
                "literal",
            ],
        },
        {
            "id": "K3",
            "title": "MCP filesystem server rooted at /",
            "subject_tokens": ["fs-root", "server-filesystem"],
            "reason_tokens": [
                "root",
                "broad",
                "over-broad",
                "entire",
                "whole",
                "unrestricted",
                "scope",
                "wide",
                "widened",
                "filesystem access",
            ],
        },
        {
            "id": "K4",
            "title": "Remote MCP transport over cleartext HTTP without authentication",
            "subject_tokens": ["remote-kb", "kb-mcp.internal.example"],
            "reason_tokens": [
                "http://",
                "not https",
                "plaintext",
                "cleartext",
                "unencrypted",
                "insecure",
                "unauthenticated",
                "no auth",
                "without auth",
                "no authentication",
                "without authentication",
                "tls",
                "non-tls",
                "unverified endpoint",
            ],
        },
        {
            "id": "K5",
            "title": "Pickle-format model file",
            "subject_tokens": ["intent_model.pkl", "intent_model", ".pkl"],
            "reason_tokens": [
                "pickle",
                "deserialization",
                "deserialize",
                "unsafe",
                "arbitrary",
                "code execution",
                "code-executing",
                "executes",
                "execution",
                "critical",
            ],
        },
        {
            "id": "K6",
            "title": "Hugging Face model without a pinned revision",
            "subject_tokens": ["all-MiniLM-L6-v2"],
            "reason_tokens": [
                "revision",
                "pin",
                "pinned",
                "unpinned",
                "floating",
                "mutable",
                "commit",
            ],
        },
        {
            "id": "K7",
            "title": "Container image and Modelfile on mutable latest tags",
            "subject_tokens": ["ollama/ollama", "llama3.2"],
            "reason_tokens": [
                "latest",
                "pin",
                "pinned",
                "unpinned",
                "tag",
                "mutable",
                "digest",
                "review",
            ],
        },
        {
            "id": "K8",
            "title": "Unpinned Python dependencies (torch, llm-guard)",
            "subject_tokens": ["torch", "llm-guard"],
            "reason_tokens": [
                "pin",
                "pinned",
                "unpinned",
                "nonexact",
                "no exact version",
                "constraint",
                "range",
                "wildcard",
                "unversioned",
                "floating",
            ],
        },
        {
            "id": "K9",
            "title": "Destructive and SQL-executing tools exposed by an MCP server",
            "subject_tokens": ["delete_ticket", "run_report_sql"],
            "reason_tokens": [
                "destructive",
                "delete",
                "deletes",
                "deletion",
                "sql",
                "injection",
                "dangerous",
                "high-impact",
                "write",
                "irreversible",
                "privilege",
                "sensitive",
                "risk",
            ],
        },
        {
            "id": "K10",
            "title": "Permissive coding-agent default mode and shell hook",
            "subject_tokens": [
                "acceptEdits",
                ".claude/settings.json",
                "defaultMode",
                "claude-code",
                "check-command.sh",
            ],
            "reason_tokens": [
                "permission",
                "permissions",
                "mode",
                "allow",
                "hook",
                "hooks",
                "accepts",
                "approval",
                "without a prompt",
                "edits",
            ],
        },
        {
            "id": "K11",
            "title": "CI workflow runs a third-party AI action from a mutable tag with a secret",
            "subject_tokens": ["claude-code-action"],
            "reason_tokens": ["pin", "pinned", "unpinned", "sha", "mutable", "tag", "secret"],
        },
    ]

    decoys = [
        {
            "id": "X1",
            "tokens": ["legacy-sql", "mcp-server-sqlite"],
            "why": "Commented-out server inside JSONC; no client loads it.",
        },
        {
            "id": "X2",
            "tokens": ["Mixtral-8x7B", "mixtral"],
            "why": "Model named only in blog prose.",
        },
        {
            "id": "X3",
            "tokens": ["purge_all_tickets"],
            "why": "Tool name that appears only inside a test string.",
        },
    ]

    runtime = {
        "trace_file": "telemetry/traces.json",
        "declared": [
            {"kind": "model", "name": "gpt-4o-2024-08-06"},
            {"kind": "tool", "name": "get_ticket"},
            {"kind": "tool", "name": "search_notes"},
        ],
        "undeclared": [
            {"kind": "model", "name": "gpt-4.1-mini"},
            {"kind": "tool", "name": "export_customers"},
        ],
    }

    return {
        "benchmark": "AI-BOM Assurance Benchmark",
        "version": "1.0.0",
        "fixture": FIXTURE_NAME,
        "sentinels": {"token": SENTINEL_TOKEN, "outside": SENTINEL_OUTSIDE},
        "canaries": CANARIES,
        "families": {
            "agent": ["instruction", "agent", "skill", "permission"],
            "mcp": ["mcp_server", "mcp_client", "tool"],
            "model": ["model", "endpoint"],
            "data": ["dataset", "rag"],
            "tools": ["library", "guardrail", "infra"],
        },
        "items": items,
        "risks": risks,
        "decoys": decoys,
        "runtime": runtime,
    }


# --------------------------------------------------------------------------- build


def build(out: Path, canary_dir: Path) -> None:
    root = out / FIXTURE_NAME
    if root.exists():
        raise SystemExit(f"refusing to overwrite existing fixture at {root}")
    root.mkdir(parents=True)
    canary = str(canary_dir.resolve())

    write(root, "README.md", README)
    write(root, "CLAUDE.md", CLAUDE_MD)
    write(root, "AGENTS.md", AGENTS_MD)
    write(root, ".github/copilot-instructions.md", COPILOT_INSTRUCTIONS)
    write(root, ".github/workflows/agent-eval.yml", CI_WORKFLOW)
    write(root, "docs/agent-rules.md", AGENT_RULES)
    write(root, "docs/blog.md", BLOG)
    write(root, ".claude/settings.json", SETTINGS_JSON + "\n")
    write(root, ".claude/agents/reviewer.md", SUBAGENT_REVIEWER)
    write(root, ".claude/skills/deploy-prod/SKILL.md", SKILL_DEPLOY)
    write(root, ".claude/skills/triage-ticket/SKILL.md", SKILL_TRIAGE)
    write(root, "skills/summarize-thread/SKILL.md", SKILL_SUMMARIZE)
    write(root, ".mcp.json", MCP_JSON + "\n")
    write(root, ".cursor/mcp.json", CURSOR_MCP_JSON + "\n")
    write(root, ".vscode/mcp.json", VSCODE_MCP_JSONC)
    write(root, ".codex/config.toml", CODEX_CONFIG_TOML)
    write(root, ".gemini/settings.json", GEMINI_SETTINGS + "\n")
    write(root, ".well-known/agent.json", AGENT_CARD + "\n")
    write(root, "agent/__init__.py", AGENT_INIT.replace("__CANARY_DIR__", canary))
    write(root, "agent/main.py", AGENT_MAIN)
    write(root, "agent/tools.py", AGENT_TOOLS)
    write(root, "agent/rag.py", AGENT_RAG)
    write(root, "agent/guard.py", AGENT_GUARD)
    write(root, "agent/train.py", AGENT_TRAIN)
    write(root, "agent/eval.py", AGENT_EVAL)
    write(root, "agent/prompts/system.md", SYSTEM_PROMPT)
    write(root, "agent/prompts/triage.jinja", TRIAGE_PROMPT)
    write(root, "mcp_servers/__init__.py", "")
    write(root, "mcp_servers/ticket_server/__init__.py", "")
    write(root, "mcp_servers/ticket_server/server.py", TICKET_SERVER)
    write(root, "mcp_servers/ticket_server/pyproject.toml", TICKET_PYPROJECT)
    write(root, "mcp_servers/ticket_server/server.json", TICKET_SERVER_JSON + "\n")
    write(root, "mcp_servers/notes_server/src/index.ts", NOTES_SERVER_TS)
    write(root, "mcp_servers/notes_server/package.json", NOTES_PACKAGE_JSON + "\n")
    write(root, "package.json", ROOT_PACKAGE_JSON + "\n")
    write(root, "scripts/record-postinstall.js", POSTINSTALL_JS.replace("__CANARY_DIR__", canary))
    write(root, "scripts/check-command.sh", CHECK_COMMAND_SH, executable=True)
    write(root, "setup.py", SETUP_PY.replace("__CANARY_DIR__", canary))
    write(root, "pyproject.toml", PYPROJECT)
    write(root, "requirements.txt", REQUIREMENTS)
    write(root, ".env.example", ENV_EXAMPLE)
    write(root, "infra/Dockerfile", DOCKERFILE)
    write(root, "infra/docker-compose.yml", COMPOSE)
    write(root, "infra/k8s/vllm-deployment.yaml", K8S_VLLM)
    write(root, "infra/ollama/Modelfile", MODELFILE)
    write(root, "models/intent-classifier/config.json", MODEL_CONFIG + "\n")
    write(root, "models/intent-classifier/README.md", MODEL_CARD)
    write_bytes(root, "models/intent-classifier/model.safetensors", safetensors_bytes())
    write_bytes(root, "models/legacy/intent_model.pkl", pickle_bytes())
    write_bytes(root, "models/tiny-llm/tiny.gguf", gguf_bytes())
    onnx_data = onnx_bytes()
    if onnx_data is not None:
        write_bytes(root, "models/embed/identity.onnx", onnx_data)
    else:
        print("warning: onnx not importable, skipping models/embed/identity.onnx", file=sys.stderr)
    write(root, "data/DATASHEET.md", DATASHEET)
    write(root, "data/train/intents.csv", INTENTS_CSV)
    write(root, "data/eval/golden_set.jsonl", GOLDEN_JSONL)
    write(root, "data/kb/faq.md", KB_FAQ)
    write(root, "data/kb/refunds.md", KB_REFUNDS)
    write(root, "data/kb/big-manual.md", big_markdown())
    write(root, "tests/__init__.py", "")
    write(root, "tests/test_tools.py", TEST_TOOLS)
    write(root, "workflows/n8n/support-triage.json", N8N_WORKFLOW + "\n")
    write(root, "telemetry/traces.json", otlp_traces())

    outside = out / "outside"
    outside.mkdir(parents=True, exist_ok=True)
    (outside / "external-policy.md").write_text(
        f"# External policy\n\nThis file lives outside the repository. {SENTINEL_OUTSIDE}\n"
    )
    os.symlink(
        str((outside / "external-policy.md").resolve()), root / "data" / "kb" / "external-policy.md"
    )

    canary_dir.mkdir(parents=True, exist_ok=True)

    truth = ground_truth(onnx_data is not None)
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=2) + "\n")

    manifest = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            manifest[rel] = {"symlink": os.readlink(path)}
        elif path.is_file():
            manifest[rel] = {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
            }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"fixture: {root}")
    print(
        f"files: {sum(1 for v in manifest.values() if 'sha256' in v)}, items: {len(truth['items'])}, risks: {len(truth['risks'])}, decoys: {len(truth['decoys'])}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", required=True, type=Path, help="build directory")
    parser.add_argument(
        "--canary-dir", type=Path, help="directory canaries write to (default: OUT/canary)"
    )
    parser.add_argument(
        "--ground-truth-only",
        action="store_true",
        help="rewrite ground_truth.json for an existing build without touching the fixture",
    )
    args = parser.parse_args()
    if args.ground_truth_only:
        has_onnx = (args.out / FIXTURE_NAME / "models" / "embed" / "identity.onnx").is_file()
        (args.out / "ground_truth.json").write_text(
            json.dumps(ground_truth(has_onnx), indent=2) + "\n"
        )
        print(f"ground truth rewritten: {args.out / 'ground_truth.json'}")
        return
    build(args.out, args.canary_dir or args.out / "canary")


if __name__ == "__main__":
    main()
