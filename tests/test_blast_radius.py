"""blast-radius answers for packages and images, reports dependents, and stays linear."""

from __future__ import annotations

import json
import tracemalloc
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.models import (
    AgentComponent,
    MCPServerComponent,
    RegistryEntryComponent,
    ToolComponent,
)
from nexus_symbiote.graph import (
    INFERRED_AGENT_REF,
    MAX_GRAPH_ISSUES,
    assemble_repository_agent,
    blast_radius,
    validate_graph,
)


def _scanned(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("openai==1.30.0\n")
    (project / "Dockerfile").write_text("FROM ollama/ollama:0.3.0\n")
    (project / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/server-filesystem": "2025.8.21"}})
    )
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "files": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21"],
                    }
                }
            }
        )
    )
    output = tmp_path / "bom.json"
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    return output


@pytest.mark.parametrize(
    "subject",
    [
        "registry:pypi/openai",
        "registry:docker/ollama/ollama:0.3.0",
        "registry:npm/@modelcontextprotocol/server-filesystem",
    ],
)
def test_a_compromised_package_or_image_reaches_the_repository_agent(tmp_path, subject):
    bom = AIBOM.load(_scanned(tmp_path))
    agent = next(c.bom_ref for c in bom.components if c.component_type.value == "agent")
    result = blast_radius(bom, subject)
    assert result["affected_agents"] == [agent]
    assert agent in result["dependent_components"]
    assert result["linked"] is True


def test_a_launcher_package_links_its_mcp_server(tmp_path):
    bom = AIBOM.load(_scanned(tmp_path))
    server = next(c for c in bom.components if isinstance(c, MCPServerComponent))
    target = "registry:npm/@modelcontextprotocol/server-filesystem"
    assert any(
        e.source_ref == server.bom_ref
        and e.target_ref == target
        and e.relationship == "registered-as"
        for e in bom.dependencies
    )
    assert server.bom_ref in blast_radius(bom, target)["dependent_components"]


def test_cli_prints_dependents(tmp_path):
    output = _scanned(tmp_path)
    result = CliRunner().invoke(main, ["blast-radius", str(output), "registry:pypi/openai"])
    assert result.exit_code == 0, result.output
    assert f"Agents: {INFERRED_AGENT_REF}" in result.output
    assert f"Dependents: {INFERRED_AGENT_REF}" in result.output


def test_dependents_are_reported_without_any_agent():
    bom = AIBOM(
        components=[
            ToolComponent(bom_ref="s", name="s"),
            ToolComponent(bom_ref="t", name="t"),
        ],
        dependencies=[DependencyEdge(source_ref="s", target_ref="t", relationship="depends-on")],
    )
    result = blast_radius(bom, "t")
    assert result["affected_agents"] == []
    assert result["dependent_components"] == ["s"]


def test_an_unlinked_component_is_unknown_not_empty(tmp_path):
    bom = AIBOM(components=[RegistryEntryComponent(bom_ref="r", name="r")])
    result = blast_radius(bom, "r")
    assert result["linked"] is False
    assert any("reachability is unknown" in item for item in result["limitations"])
    bom.save(tmp_path / "bom.json")
    printed = CliRunner().invoke(main, ["blast-radius", str(tmp_path / "bom.json"), "r"])
    assert printed.exit_code == 0, printed.output
    assert (
        "Note: The component has no recorded relationships: reachability is unknown, not empty."
        in printed.output
    )


def test_several_agents_and_a_cycle():
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="a1", name="a1", sub_agent_refs=["a2"]),
            AgentComponent(bom_ref="a2", name="a2", sub_agent_refs=["a1"], tool_refs=["t"]),
            AgentComponent(bom_ref="a3", name="a3", tool_refs=["t"]),
            ToolComponent(bom_ref="t", name="t"),
            ToolComponent(bom_ref="u", name="u"),
        ]
    )
    result = blast_radius(bom, "t")
    assert result["affected_agents"] == ["a1", "a2", "a3"]
    assert result["reachable_components"] == ["a1", "a2", "a3", "t"]


def test_blast_radius_memory_is_linear_in_upstream_agents():
    # Before: one full forward walk per affected agent, all held at once.
    hub = AgentComponent(bom_ref="hub", name="hub", tool_refs=[f"t{i}" for i in range(1500)])
    agents = [
        AgentComponent(bom_ref=f"a{i}", name="a", sub_agent_refs=["hub"]) for i in range(1500)
    ]
    tools = [ToolComponent(bom_ref=f"t{i}", name="t") for i in range(1500)]
    bom = AIBOM(components=[hub, *agents, *tools])
    tracemalloc.start()
    try:
        result = blast_radius(bom, "t0")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(result["affected_agents"]) == 1501
    assert peak < 16 * 1024 * 1024


def test_graph_issues_are_bounded_and_identifiers_shortened():
    agent = AgentComponent(
        bom_ref="a" * 100_000, name="a", tool_refs=[f"missing-{i}" for i in range(5000)]
    )
    issues = validate_graph(AIBOM(components=[agent]))
    assert len(issues) == MAX_GRAPH_ISSUES + 1
    assert issues[-1] == f"{5000 - MAX_GRAPH_ISSUES} further graph issues not shown"
    assert max(len(issue) for issue in issues) < 1000


def test_assembly_does_not_search_the_inventory_per_tool(monkeypatch):
    calls = 0
    original = AIBOM.get_component

    def counted(self, ref):
        nonlocal calls
        calls += 1
        return original(self, ref)

    monkeypatch.setattr(AIBOM, "get_component", counted)
    bom = AIBOM()
    for server in range(200):
        bom.components.append(MCPServerComponent(bom_ref=f"s{server}", name="s"))
        for tool in range(50):
            bom.components.append(
                ToolComponent(bom_ref=f"s{server}/t{tool}", name="t", mcp_server_ref=f"s{server}")
            )
    assemble_repository_agent(bom, Path("/nonexistent-root-for-test"), failures=[])
    assert calls == 0
    assert sum(e.relationship == "provides-tool" for e in bom.dependencies) == 200 * 50
