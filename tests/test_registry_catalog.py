"""Which packages and images the registry collector inventories, after normalisation."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.registry import (
    AI_IMAGE_KEYWORDS,
    AI_IMAGE_WORDS,
    AI_PACKAGE_NAMES,
    AI_PACKAGE_PREFIXES,
    AI_PACKAGE_SCOPES,
    AI_PACKAGE_WORDS,
    RegistryScanner,
    is_ai_image,
)

# One catalog serves PyPI and npm names alike.
is_ai_package = RegistryScanner._is_ai_package
CATALOG = (AI_PACKAGE_NAMES, AI_PACKAGE_PREFIXES, AI_PACKAGE_WORDS, AI_PACKAGE_SCOPES)

DOCS = Path(__file__).parents[1] / "docs" / "registry-collector.md"

# The agent stack as it is published on PyPI: SDKs, frameworks, model runtimes,
# vector stores and guardrails.
PYPI_AI = [
    "mcp",
    "fastmcp",
    "anthropic",
    "openai",
    "openai-agents",
    "langchain",
    "langchain-core",
    "langchain-openai",
    "langgraph",
    "langgraph-checkpoint-postgres",
    "langsmith",
    "llama-index",
    "llama-index-core",
    "llamaindex",
    "crewai",
    "crewai-tools",
    "autogen-agentchat",
    "ag2",
    "pyautogen",
    "semantic-kernel",
    "smolagents",
    "pydantic-ai",
    "pydantic-ai-slim",
    "google-genai",
    "google-generativeai",
    "google-adk",
    "mistralai",
    "cohere",
    "transformers",
    "torch",
    "torchvision",
    "tensorflow",
    "safetensors",
    "tokenizers",
    "sentence-transformers",
    "huggingface-hub",
    "vllm",
    "litellm",
    "ollama",
    "llama-cpp-python",
    "chromadb",
    "pinecone",
    "pinecone-client",
    "qdrant-client",
    "weaviate-client",
    "pgvector",
    "faiss-cpu",
    "faiss-gpu",
    "guardrails-ai",
    "nemoguardrails",
    "rebuff",
    "dspy",
    "dspy-ai",
    "haystack-ai",
    "instructor",
    "strands-agents",
    "a2a-sdk",
    "claude-agent-sdk",
    "mcp-server-fetch",
    "awslabs.aws-documentation-mcp-server",
    "fastapi-mcp",
    "llm",
]
PYPI_OTHER = [
    "requests",
    "numpy",
    "fastapi",
    "agnostic",
    "user-agents",
    "pytest",
    "opena1",
    "langchian",
    "transformer",
    "mcpx",
]

NPM_AI = [
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-filesystem",
    "@anthropic-ai/sdk",
    "@anthropic-ai/claude-agent-sdk",
    "@openai/agents",
    "@langchain/core",
    "@langchain/langgraph",
    "@huggingface/inference",
    "@google/genai",
    "@google/generative-ai",
    "@mistralai/mistralai",
    "@ai-sdk/openai",
    "@ai-sdk/google",
    "@pinecone-database/pinecone",
    "@qdrant/js-client-rest",
    "@tensorflow/tfjs",
    "@xenova/transformers",
    "@llamaindex/core",
    "@mastra/core",
    "openai",
    "anthropic",
    "langchain",
    "llamaindex",
    "ai",
    "ollama",
    "chromadb",
    "@playwright/mcp",
    "@upstash/context7-mcp",
    "firecrawl-mcp",
    "chrome-devtools-mcp",
    "mcp-remote",
    "@foo/openai",
]
NPM_OTHER = [
    "express",
    "@types/node",
    "@google/maps",
    "react",
    "aim",
    "lodash",
    "@scope/ai",
    "mcpx",
]


def _spellings(name: str) -> list[str]:
    # pip, uv and Poetry treat runs of "-", "_" and "." alike, in any letter case.
    return [name, name.upper(), name.replace("-", "_"), name.replace("-", "."), name.title()]


@pytest.mark.parametrize("name", PYPI_AI)
def test_pypi_agent_stack_is_recognised_in_every_equivalent_spelling(name):
    for spelling in _spellings(name):
        assert is_ai_package(spelling), spelling


@pytest.mark.parametrize("name", PYPI_OTHER)
def test_other_pypi_packages_are_not_inventoried(name):
    assert not is_ai_package(name)


@pytest.mark.parametrize("name", NPM_AI)
def test_npm_agent_stack_is_recognised_with_and_without_scopes(name):
    assert is_ai_package(name)
    assert is_ai_package(name.upper())


@pytest.mark.parametrize("name", NPM_OTHER)
def test_other_npm_packages_are_not_inventoried(name):
    assert not is_ai_package(name)


# Names the upstream catalog matched on npm as well as on PyPI; one catalog keeps them.
@pytest.mark.parametrize(
    "name",
    [
        "@a2a-js/sdk",
        "langsmith",
        "mastra",
        "mem0ai",
        "instructor",
        "lancedb",
        "mistralai",
        "claude-agent-sdk",
        "fastmcp-proxy",
        "pydantic-ai-slim",
        "smolagents",
        "semantic-kernel",
    ],
)
def test_names_matched_before_the_catalogs_were_merged_still_match(name):
    assert is_ai_package(name)
    assert is_ai_package(name.upper())


@pytest.mark.parametrize(
    "image",
    [
        "ollama/ollama:latest",
        "vllm/vllm-openai:v0.6.0",
        "ghcr.io/huggingface/text-generation-inference:2.0",
        "ghcr.io/huggingface/text-embeddings-inference:cpu-1.5",
        "nvcr.io/nvidia/tritonserver:24.01-py3",
        "localai/localai:latest",
        "openmmlab/lmdeploy:latest",
        "lmsysorg/sglang:latest",
        "ghcr.io/ggml-org/llama.cpp:server",
        "mcp/fetch",
        "ghcr.io/github/github-mcp-server",
        "ghcr.io/modelcontextprotocol/inspector",
        "qdrant/qdrant:v1.9.0",
        "chromadb/chroma:0.5.5",
        "pgvector/pgvector:pg16",
        "ghcr.io/berriai/litellm:main-stable",
        "corp/tei:1.0",
    ],
)
def test_model_server_and_mcp_images_are_recognised(image):
    assert is_ai_image(image)


@pytest.mark.parametrize("image", ["nginx:1.27", "postgres:16", "redis:7", "python:3.12-slim"])
def test_other_images_are_not_inventoried(image):
    assert not is_ai_image(image)


def test_first_party_sdks_are_inventoried_with_complete_coverage(tmp_path):
    # These defined the agent but produced no component, while the collector
    # reported complete coverage and "no AI-related dependencies found".
    (tmp_path / "requirements.txt").write_text("mcp[cli]==1.2.0\nfastmcp==2.0.0\n")
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "@anthropic-ai/sdk": "0.30.1",
                    "@openai/agents": "0.1.0",
                    "@langchain/core": "^0.3.0",
                    "express": "^4.0.0",
                }
            }
        )
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert sorted(c.bom_ref for c in result.components) == [
        "registry:npm/@anthropic-ai/sdk",
        "registry:npm/@langchain/core",
        "registry:npm/@openai/agents",
        "registry:pypi/fastmcp",
        "registry:pypi/mcp",
    ]
    by_ref = {c.bom_ref: c for c in result.components}
    assert by_ref["registry:pypi/mcp"].package_url == "pkg:pypi/mcp@1.2.0"
    assert by_ref["registry:npm/@anthropic-ai/sdk"].package_url == (
        "pkg:npm/%40anthropic-ai/sdk@0.30.1"
    )
    assert "registry (no AI-related dependencies found)" not in result.surfaces_scanned


@pytest.mark.parametrize("spelling", ["llama.index.core", "LLAMA_INDEX_CORE", "llama--index-core"])
def test_an_equivalent_spelling_is_the_same_component(tmp_path, spelling):
    # pip installs llama-index-core for every spelling, so rewriting the name must be
    # a version change of one component, not a removal that raises no alert.
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    requirements = project / "requirements.txt"
    runner = CliRunner()
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o"]
    requirements.write_text("llama-index-core==0.10.68\n")
    assert runner.invoke(main, [*args, str(tmp_path / "a.json")]).exit_code == 0
    requirements.write_text(f"{spelling}==0.10.1\n")
    assert runner.invoke(main, [*args, str(tmp_path / "b.json")]).exit_code == 0
    after = json.loads((tmp_path / "b.json").read_text())
    assert [c["bom_ref"] for c in after["components"] if c.get("registry_type")] == [
        "registry:pypi/llama-index-core"
    ]
    diff = runner.invoke(
        main, ["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json"), "--fail-on-alert"]
    )
    assert diff.exit_code == 1, diff.output
    assert "==0.10.68" in diff.output and "==0.10.1" in diff.output


def test_poetry_and_uv_keys_are_classified_after_normalisation(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\npython = "^3.11"\n"Llama.Index" = "0.10.1"\nmcp = "1.2.0"\n'
    )
    result = RegistryScanner().scan(tmp_path)
    assert sorted(c.bom_ref for c in result.components) == [
        "registry:pypi/llama-index",
        "registry:pypi/mcp",
    ]


def _documented() -> str:
    return DOCS.read_text(encoding="utf-8")


def test_every_catalog_entry_is_documented():
    # The documentation lists what the collector inventories; a change to the
    # catalog must change the list, so a baseline's scope is visible to readers.
    text = _documented()
    entries = {f"`{entry}`" for entry in AI_IMAGE_KEYWORDS} | {f"`{w}`" for w in AI_IMAGE_WORDS}
    for group in CATALOG:
        entries.update(f"`{entry}`" for entry in group)
    missing = sorted(entry for entry in entries if entry not in text)
    assert missing == []


def test_the_documented_catalog_lists_nothing_the_collector_does_not_match():
    section = _documented().split("## AI package catalog", 1)[1].split("\n## ", 1)[0]
    listed = set(re.findall(r"`([^`]+)`", section))
    known = set(AI_IMAGE_KEYWORDS) | set(AI_IMAGE_WORDS)
    for group in CATALOG:
        known |= set(group)
    assert listed <= known | {"-", "_", "."}
