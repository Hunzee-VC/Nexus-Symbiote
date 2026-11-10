"""An inventory describes the project, not the directory it was checked out into."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import NATIVE_SPEC_VERSION

DEMO = Path(__file__).resolve().parents[1] / "examples" / "demo-agent"


def _scan(project: Path, output: Path) -> dict:
    result = CliRunner().invoke(main, ["scan", str(project), "--report-only", "-o", str(output)])
    assert result.exit_code == 0, result.output
    return json.loads(output.read_text())


def _checkouts(tmp_path: Path, second: str) -> tuple[Path, Path]:
    first = tmp_path / "laptop" / "demo-agent"
    other = tmp_path / "runner" / "work" / second
    shutil.copytree(DEMO, first)
    shutil.copytree(DEMO, other)
    return first, other


def test_inventory_records_no_checkout_path(tmp_path):
    project, _ = _checkouts(tmp_path, "demo-agent")
    output = tmp_path / "bom.json"
    bom = _scan(project, output)
    assert str(tmp_path) not in output.read_text()
    sources = {c["source_path"] for c in bom["components"] if c.get("source_path")}
    assert ".mcp.json" in sources
    assert all(not Path(source).is_absolute() for source in sources if "://" not in source)


def test_same_project_in_another_directory_is_not_drift(tmp_path):
    first, other = _checkouts(tmp_path, "demo-agent")
    _scan(first, tmp_path / "baseline.json")
    _scan(other, tmp_path / "current.json")
    result = CliRunner().invoke(
        main,
        [
            "diff",
            str(tmp_path / "baseline.json"),
            str(tmp_path / "current.json"),
            "--fail-on-alert",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "No changes detected" in result.output


def test_renamed_checkout_is_not_drift(tmp_path):
    first, other = _checkouts(tmp_path, "renamed")
    _scan(first, tmp_path / "baseline.json")
    _scan(other, tmp_path / "current.json")
    result = CliRunner().invoke(
        main,
        [
            "diff",
            str(tmp_path / "baseline.json"),
            str(tmp_path / "current.json"),
            "--fail-on-alert",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "No changes detected" in result.output


def test_baseline_reconciles_with_another_checkout(tmp_path):
    first, other = _checkouts(tmp_path, "renamed")
    _scan(first, tmp_path / "bom.json")
    result = CliRunner().invoke(
        main, ["validate", str(tmp_path / "bom.json"), "--project", str(other)]
    )
    completeness = result.output.split("Completeness check", 1)[1].split("Integrity check", 1)[0]
    assert "Status: PASS" in completeness, result.output
    assert "Hashes verified: 4, failed: 0" in result.output


def _every_collector_project(project: Path) -> None:
    """A checkout that gives every built-in collector, and agent.yaml, something to record."""
    (project / "models").mkdir(parents=True)
    shutil.copy(
        DEMO / "models" / "intent-classifier.safetensors", project / "models" / "c.safetensors"
    )
    shutil.copytree(DEMO / ".well-known", project / ".well-known")
    shutil.copy(DEMO / "rag_config.json", project / "rag_config.json")
    (project / "agent.yaml").write_text(
        "name: support\ninstructions:\n  - docs/agents/rules.md\n"
        "models:\n  classifier:\n    path: models/c.safetensors\n"
    )
    (project / "docs" / "agents").mkdir(parents=True)
    (project / "docs" / "agents" / "rules.md").write_text("Answer politely.")
    (project / "AGENTS.md").write_text("Use the configured tools.")
    (project / "pkg").mkdir()
    (project / "pkg" / "AGENTS.md").write_text("Package rules.")
    skill = project / ".claude" / "skills" / "review"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: review\ndescription: Review code\n---\nReview.")
    (skill / "run.sh").write_text("#!/bin/sh\necho review\n")
    (project / ".claude" / "settings.json").write_text(
        json.dumps({"permissions": {"defaultMode": "default", "deny": ["Bash(rm:*)"]}})
    )
    tool = {"name": "lookup", "description": "Look up a record", "inputSchema": {"type": "object"}}
    server = {"command": "npx", "args": ["-y", "lookup-mcp@1.2.3"], "tools": [tool]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"lookup": server}}))
    (project / ".vscode").mkdir()
    fetch = {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]}
    (project / ".vscode" / "mcp.json").write_text(json.dumps({"servers": {"fetch": fetch}}))
    (project / "requirements.txt").write_text("openai==1.2.3\nmcp==1.9.0\n")
    (project / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('demo')\n\n\n"
        "@mcp.tool()\ndef lookup_order(order_id: str) -> str:\n"
        '    """Return an order."""\n    return order_id\n'
    )


def test_format_1_1_records_only_root_relative_locations(tmp_path):
    """Native format 1.1.0 promises root-relative paths wherever a collector records one."""
    project = tmp_path / "checkout" / "agent"
    _every_collector_project(project)
    output = tmp_path / "bom.json"
    bom = _scan(project, output)
    assert bom["metadata"]["spec_version"] == NATIVE_SPEC_VERSION
    assert str(tmp_path) not in output.read_text()
    assert {component["component_type"] for component in bom["components"]} >= {
        "agent",
        "mcp-client",
        "mcp-server",
        "tool",
        "model",
        "prompt-template",
        "skill-package",
        "registry-entry",
        "rag-source",
        "a2a-server",
        "ide-agent",
    }

    def relative(value: str) -> bool:
        return "://" in value or not (value.startswith("/") or Path(value).is_absolute())

    claim = bom["metadata"]["completeness"]
    for key in ("surfaces_scanned", "surfaces_excluded", "scan_failures"):
        assert all(not record.startswith("/") for record in claim.get(key, [])), key
    for component in bom["components"]:
        if component.get("source_path"):
            assert relative(component["source_path"]), component["bom_ref"]
        for name, evidence in component.get("claims", {}).items():
            if evidence.get("locator"):
                assert relative(evidence["locator"]), (component["bom_ref"], name)


_COLLECTION_EVENT = frozenset({"serial_number", "timestamp", "observed_at"})


def _without_collection_event(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _without_collection_event(item)
            for key, item in value.items()
            if key not in _COLLECTION_EVENT
        }
    if isinstance(value, list):
        return [_without_collection_event(item) for item in value]
    return value


def test_every_collector_records_the_same_inventory_at_two_locations(tmp_path):
    """Apart from when it was collected, an inventory depends only on the checkout's content."""
    first = tmp_path / "laptop" / "agent"
    second = tmp_path / "ci" / "runner" / "renamed-clone"
    _every_collector_project(first)
    _every_collector_project(second)
    left = _scan(first, tmp_path / "first.json")
    right = _scan(second, tmp_path / "second.json")
    assert _without_collection_event(left) == _without_collection_event(right)
    for output in (tmp_path / "first.json", tmp_path / "second.json"):
        text = output.read_text()
        assert "laptop" not in text and "renamed-clone" not in text


def test_unrelated_source_files_leave_the_inventory_unchanged(tmp_path):
    """Adding code that declares nothing an agent uses must not change any record or gap."""
    project = tmp_path / "agent"
    _every_collector_project(project)
    before = _scan(project, tmp_path / "before.json")
    (project / "helpers").mkdir()
    (project / "helpers" / "strings.py").write_text("def shout(text):\n    return text.upper()\n")
    (project / "helpers" / "format.ts").write_text("export const greet = (n: string) => n;\n")
    (project / "notes.js").write_text("module.exports = { greeting: 'hello' };\n")
    after = _scan(project, tmp_path / "after.json")
    assert _without_collection_event(before) == _without_collection_event(after)


def test_risk_reconciles_an_inventory_collected_in_another_checkout(tmp_path):
    first, other = _checkouts(tmp_path, "renamed")
    _scan(first, tmp_path / "supplied.json")
    result = CliRunner().invoke(
        main,
        [
            "risk",
            str(tmp_path / "supplied.json"),
            "--project",
            str(other),
            "--no-project-policy",
            "--json-output",
        ],
    )
    report = json.loads(result.stdout)
    assert report["assessment_basis"] == "project-reconciled", report
