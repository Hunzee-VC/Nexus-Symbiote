"""Project validation must corroborate a supplied inventory with local observations."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.validators.completeness import CompletenessValidator


def _claimed_complete(project: Path, target: Path) -> AIBOM:
    run = CliRunner().invoke(
        main, ["scan", "--report-only", "--no-project-policy", str(project), "-o", str(target)]
    )
    assert run.exit_code == 0, run.output
    bom = AIBOM.load(target)
    claim = bom.metadata.completeness
    assert claim is not None
    claim.scanner_status = dict.fromkeys(BUILTIN_SCANNER_NAMES, "complete")
    claim.collectors_completed = claim.collectors_requested = sorted(BUILTIN_SCANNER_NAMES)
    claim.scan_failures = []
    claim.surfaces_excluded = []
    return bom


def test_cli_rejects_omitted_instruction_with_forged_complete_coverage(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Safe instructions.")
    (project / "AGENTS.md").write_text("hidden\u202edirective")
    target = tmp_path / "bom.json"
    bom = _claimed_complete(project, target)
    hidden = "prompt:AGENTS.md"
    bom.components = [component for component in bom.components if component.bom_ref != hidden]
    for component in bom.components:
        if hidden in getattr(component, "prompt_refs", ()):
            component.prompt_refs.remove(hidden)
    bom.dependencies = [edge for edge in bom.dependencies if edge.target_ref != hidden]
    bom.metadata.completeness.exclusions = ["AGENTS.md"]
    assert not bom.graph_issues()
    bom.save(target)

    run = CliRunner().invoke(
        main, ["validate", "--no-project-policy", str(target), "--project", str(project)]
    )
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output
    assert hidden in run.output


def test_source_substitution_cannot_satisfy_a_collector_reference(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    for name in ("CLAUDE.md", "AGENTS.md"):
        (project / name).write_text("Identical bytes.")
    bom = _claimed_complete(project, tmp_path / "bom.json")
    component = bom.get_component("prompt:AGENTS.md")
    assert component is not None
    component.source_path = "AGENTS.md"  # Relative form of the actual in-root subject.
    validator = CompletenessValidator()
    assert not any(
        i.surface == component.bom_ref
        for i in validator.validate_against_project(bom, project).issues
    )
    component.source_path = "CLAUDE.md"
    report = validator.validate_against_project(bom, project)
    assert not report.is_complete
    assert any(i.surface == component.bom_ref for i in report.issues)


def test_new_server_in_existing_mcp_config_is_detected(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    config = project / ".mcp.json"
    servers = {"first": {"command": "local-first"}}
    config.write_text(json.dumps({"mcpServers": servers}))
    bom = _claimed_complete(project, tmp_path / "bom.json")
    servers["second"] = {"command": "local-second"}
    config.write_text(json.dumps({"mcpServers": servers}))

    report = CompletenessValidator().validate_against_project(bom, project)
    assert not report.is_complete
    assert any(i.surface.startswith("mcp-server:") for i in report.issues)


def test_local_read_failure_overrides_claimed_complete_status(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("original")
    bom = _claimed_complete(project, tmp_path / "bom.json")
    (project / ".mcp.json").write_text("{ malformed")
    report = CompletenessValidator().validate_against_project(bom, project)
    assert not report.is_complete
    assert any(i.surface == "mcp" and ".mcp.json" in i.description for i in report.issues)


def test_same_server_reference_cannot_substitute_a_different_configured_origin(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"mail": {"url": "https://mail.example.test/mcp"}}})
    )
    bom = _claimed_complete(project, tmp_path / "bom.json")
    server = next(c for c in bom.components if c.component_type.value == "mcp-server")
    server.endpoint_url = "https://elsewhere.example.test"

    report = CompletenessValidator().validate_against_project(bom, project)
    assert not report.is_complete
    assert any(i.surface == server.bom_ref for i in report.issues)


def test_recorded_empty_discovery_report_cannot_disappear(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    report_file = project / "shadowscan-report.json"
    report_file.write_text(
        json.dumps(
            {
                "version": "1.0",
                "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
                "stats": [{"errors": [], "skipped": False, "incomplete": False}],
                "findings": [],
            }
        )
    )
    bom = _claimed_complete(project, tmp_path / "bom.json")
    report_file.unlink()

    report = CompletenessValidator().validate_against_project(bom, project)
    assert not report.is_complete
    assert any(i.surface == "shadowscan" and "digest" in i.description for i in report.issues)


@pytest.mark.parametrize(
    "edit", ["trust", "risk", "extra-ref", "claim", "scope", "unmapped", "limitations"]
)
def test_cli_rejects_forged_discovery_projection_in_combined_bom(tmp_path, edit):
    root = tmp_path / "project"
    root.mkdir()
    (root / "CLAUDE.md").write_text("Check all requests.")
    (root / "shadowscan.json").write_text(
        json.dumps(
            {
                "version": "1",
                "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
                "stats": [{"errors": [], "skipped": False, "incomplete": False}],
                "findings": [
                    {
                        "id": "reported",
                        "surface": "code",
                        "kind": "agent",
                        "risk": {"level": "high"},
                    }
                ],
            }
        )
    )
    target = tmp_path / "bom.json"
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--report-only", str(root), "-o", str(target)])
    assert result.exit_code == 0, result.output
    args = ["validate", "--project", str(root), "--no-project-policy", str(target)]
    original = runner.invoke(main, args)
    assert original.exit_code == 0, original.output
    doc = json.loads(target.read_bytes())
    imported = next(c for c in doc["components"] if c["bom_ref"].startswith("shadowscan:"))
    scope = doc["metadata"]["completeness"]
    if edit == "trust":
        imported.update(assurance_level="verified", trust_tier="third-party-signed")
    elif edit == "risk":
        assert imported["risks"]
        imported["risks"] = []
    elif edit == "extra-ref":
        doc["components"].append({**imported, "bom_ref": "shadowscan:invented"})
    elif edit == "claim":
        imported["claims"]["discovery_report_entry"]["assurance"] = "observed"
    elif edit == "scope":
        scope["scope"] = "runtime"
    elif edit == "unmapped":
        scope["source_unmapped_count"] = 1
        scope["source_unmapped_indexes"] = [9]
    else:
        scope["source_projection_limitations"] = []
    target.write_text(json.dumps(doc))
    altered = runner.invoke(main, args)
    assert altered.exit_code == 1, altered.output
    assert "discovery report" in altered.output


def test_known_package_url_cannot_be_replaced_with_another_package(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "requirements.txt").write_text("langchain==1.2.3\n")
    bom = _claimed_complete(root, tmp_path / "bom.json")
    package = bom.get_component("registry:pypi/langchain")
    assert package.package_url == "pkg:pypi/langchain@1.2.3"
    package.package_url = "pkg:pypi/other@1.2.3"

    checked = CompletenessValidator().validate_against_project(bom, root)
    assert not checked.is_complete
    assert any(i.surface == package.bom_ref for i in checked.issues)
