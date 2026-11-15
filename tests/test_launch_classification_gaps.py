"""Host API delegation and renamed card constructors retain their security meaning."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import A2AServerComponent, MCPServerComponent
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.mcp import MCPScanner

IMAGE = "example/agent@sha256:" + "a" * 64


def _docker_config(root, options):
    (root / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"agent": {"command": "docker", "args": ["run", *options, IMAGE]}}}
        )
    )


@pytest.mark.parametrize(
    "options,enabled",
    [
        (["--use-api-socket"], True),
        (["--use-api-socket=true"], True),
        (["--use-api-socket=TRUE"], True),
        (["--use-api-socket=1"], True),
        (["--use-api-socket=false", "--use-api-socket"], True),
        ([], False),
        (["--use-api-socket=false"], False),
        (["--use-api-socket=0"], False),
        (["--use-api-socket", "--use-api-socket=false"], False),
    ],
)
def test_docker_api_socket_includes_runtime_and_credential_delegation(tmp_path, options, enabled):
    _docker_config(tmp_path, options)
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert not result.scan_failures and not result.surfaces_excluded
    (server,) = [c for c in result.components if isinstance(c, MCPServerComponent)]
    assert server.version_pinned is True
    context = server.properties.get("launch_context", {})
    assert bool(context.get("runtime_socket_mount")) is enabled
    assert bool(context.get("runtime_credentials_forwarded")) is enabled
    findings = [r for r in server.risks if r.category == "launch_context"]
    if enabled:
        assert len(findings) == 1
        assert findings[0].severity.value == "high"
        assert "container runtime socket" in findings[0].detail
        assert "forwarded client credentials" in findings[0].detail
    else:
        assert not findings


@pytest.mark.parametrize("enabled", [False, True])
def test_api_socket_delegation_fails_reconciled_high_risk_gate(tmp_path, enabled):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Be helpful.\n")
    _docker_config(project, ["--use-api-socket"] if enabled else [])
    output = tmp_path / "bom.json"
    runner = CliRunner()
    scan = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert scan.exit_code == 0, scan.output
    risk = runner.invoke(
        main,
        [
            "risk",
            str(output),
            "--project",
            str(project),
            "--no-project-policy",
            "--fail-on-severity",
            "high",
            "--json-output",
        ],
    )
    assert risk.exit_code == int(enabled), risk.output
    report = json.loads(risk.output)
    assert report["assessment_basis"] == "project-reconciled"


@pytest.mark.parametrize("name", ["AgentCard", "Card"])
@pytest.mark.parametrize(
    "expression,kind",
    [
        ("{name}(name='agent', url='http://example.test', skills=[])", "built"),
        ("{name}.model_construct(name='agent', url='http://example.test')", "built"),
        ("{name}.construct(name='agent')", "built"),
        ("{name}(**data)", "loaded"),
        ("{name}.model_validate(data)", "loaded"),
        ("{name}.model_validate_json(raw)", "loaded"),
        ("{name}.model_validate_strings(data)", "loaded"),
        ("{name}.parse_obj(data)", "loaded"),
        ("{name}.parse_raw(raw)", "loaded"),
    ],
)
def test_import_alias_card_constructors_have_the_same_gap(tmp_path, name, expression, kind):
    source = f"from a2a.types import AgentCard as {name}\ncard = {expression.format(name=name)}\n"
    (tmp_path / "server.py").write_text(source)
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    assert result.surfaces_excluded == [
        f"server.py: A2A agent card {kind} in Python code is not inventoried"
    ]
    (server,) = result.components
    assert isinstance(server, A2AServerComponent)


@pytest.mark.parametrize(
    "source",
    [
        "from a2a.types import AgentCard as Card\n",
        "from unrelated.types import AgentCard as Card\ncard = Card(name='shape')\n",
    ],
)
def test_unused_or_unrelated_card_alias_is_not_a_construction_gap(tmp_path, source):
    (tmp_path / "server.py").write_text(source)
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded


@pytest.mark.parametrize("loaded", [False, True])
def test_static_card_covers_only_a_loaded_alias_card(tmp_path, loaded):
    (tmp_path / "agent-card.json").write_text(
        json.dumps({"name": "agent", "url": "https://example.test", "skills": []})
    )
    expression = "Card.model_validate(data)" if loaded else "Card(name='other')"
    (tmp_path / "server.py").write_text(
        f"from a2a.types import AgentCard as Card\ncard = {expression}\n"
    )
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    assert result.surfaces_excluded == (
        [] if loaded else ["server.py: A2A agent card built in Python code is not inventoried"]
    )


@pytest.mark.parametrize("name", ["AgentCard", "Card"])
def test_alias_card_gap_fails_scan_validate_and_risk_with_source_binding(
    tmp_path, monkeypatch, name
):
    monkeypatch.setenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", "a" * 40)
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Be helpful.\n")
    (project / "server.py").write_text(
        f"from a2a.types import AgentCard as {name}\n"
        f"card = {name}(name='agent', url='https://example.test', skills=[])\n"
    )
    output = tmp_path / "bom.json"
    runner = CliRunner()
    scan = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert scan.exit_code == 1, scan.output
    completeness = json.loads(output.read_text())["metadata"]["completeness"]
    assert completeness["scanner_status"]["a2a"] == "partial"
    assert completeness["surfaces_excluded"] == [
        "server.py: A2A agent card built in Python code is not inventoried"
    ]
    for command in ("validate", "risk"):
        result = runner.invoke(
            main, [command, str(output), "--project", str(project), "--no-project-policy"]
        )
        assert result.exit_code == 1, result.output
        assert "A2A agent card built in Python code is not inventoried" in result.output
