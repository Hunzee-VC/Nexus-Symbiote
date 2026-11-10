"""Project validation must corroborate a supplied inventory with local observations."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.graph import validate_graph
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
    assert not validate_graph(bom)
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


def _scanned(tmp_path: Path) -> tuple[Path, Path, dict]:
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Use the configured tools.")
    tool = {"name": "lookup", "description": "Look up a record", "inputSchema": {"type": "object"}}
    server = {"command": "npx", "args": ["-y", "lookup-mcp@1.2.3"], "tools": [tool]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"lookup": server}}))
    target = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", "--no-project-policy", str(project), "-o", str(target)])
    assert run.exit_code == 0, run.output
    return project, target, json.loads(target.read_text())


def _agent(doc: dict) -> dict:
    return next(c for c in doc["components"] if c["component_type"] == "agent")


def _server_ref(doc: dict) -> str:
    return next(c["bom_ref"] for c in doc["components"] if c["component_type"] == "mcp-server")


def _tool(doc: dict) -> dict:
    return next(c for c in doc["components"] if c["component_type"] == "tool")


VERIFIED_RUNTIME_CLAIM = {"method": "sigstore", "scope": "runtime", "assurance": "verified"}


def _validate(project: Path, target: Path, doc: dict):
    target.write_text(json.dumps(doc))
    args = ["validate", "--no-project-policy", str(target), "--project", str(project)]
    return CliRunner().invoke(main, args)


@pytest.mark.parametrize(
    "edit",
    [
        "edge-removed",
        "edge-added-verified",
        "edge-altered",
        "agent-profile-forged",
        "agent-refs-emptied",
        "extra-verified-component",
        "extra-internal-trust-component",
        "local-tool-verified-claim",
        "agent-gap-filled-with-verified-claim",
    ],
)
def test_reconciliation_compares_relationships_agent_and_extras(tmp_path, edit):
    project, target, doc = _scanned(tmp_path)
    assert _validate(project, target, doc).exit_code == 0
    agent = _agent(doc)
    if edit == "edge-removed":
        doc["dependencies"] = []
        agent["tool_refs"] = []
        agent["prompt_refs"] = []
    elif edit == "edge-added-verified":
        doc["dependencies"].append(
            {
                "source_ref": agent["bom_ref"],
                "target_ref": _server_ref(doc),
                "relationship": "approved-under",
                "assurance_level": "verified",
            }
        )
    elif edit == "edge-altered":
        doc["dependencies"][0]["conditions"] = None
    elif edit == "agent-profile-forged":
        agent["autonomy_level"] = "L0-chatbot"
    elif edit == "agent-refs-emptied":
        agent["tool_refs"] = []
    elif edit == "local-tool-verified-claim":
        _tool(doc)["claims"]["attestation"] = VERIFIED_RUNTIME_CLAIM
    elif edit == "agent-gap-filled-with-verified-claim":
        # The collector records deployment as not collected. A supplier may fill that
        # gap with its own claim, which is listed, but never with verified assurance.
        agent["claims"]["deployment"] = VERIFIED_RUNTIME_CLAIM
    else:
        verified = edit == "extra-verified-component"
        doc["components"].append(
            {
                "bom_ref": "guardrail:prod",
                "component_type": "guardrail-policy",
                "name": "prod",
                "assurance_level": "verified" if verified else "declared",
                "trust_tier": "internal-verified",
                "claims": {
                    "deployment": {
                        "method": "attested",
                        "scope": "runtime",
                        "assurance": "verified" if verified else "declared",
                    }
                },
            }
        )
    result = _validate(project, target, doc)
    assert result.exit_code == 1, result.output
    assert "Basis: project-reconciliation-failed" in result.output
    risk = CliRunner().invoke(
        main,
        ["risk", str(target), "--project", str(project), "--no-project-policy", "--json-output"],
    )
    assert risk.exit_code == 1
    assert json.loads(risk.stdout)["assessment_basis"] == "project-reconciliation-failed"


def test_supplier_enrichment_is_reported_as_supplier_claims_not_reconciled(tmp_path):
    project, target, doc = _scanned(tmp_path)
    risk_args = ["risk", str(target), "--project", str(project), "--no-project-policy"]
    original = CliRunner().invoke(main, [*risk_args, "--json-output"])
    assert json.loads(original.stdout)["assessment_basis"] == "project-reconciled"
    assert json.loads(original.stdout)["supplier_claims"] == []
    agent = _agent(doc)
    agent["capabilities"] = {"human_in_the_loop": "required"}
    agent["authorizations"] = [{"principal": "ciso", "action": "deploy"}]
    agent["claims"]["deployment"] = {"method": "change-ticket", "scope": "runtime"}
    _tool(doc)["claims"]["attestation"] = {
        "method": "sigstore",
        "scope": "runtime",
        "assurance": "observed",
    }
    result = _validate(project, target, doc)
    assert result.exit_code == 0, result.output
    assert "Basis: project-reconciled-with-supplier-claims" in result.output
    assert "SUPPLIER-CLAIM" in result.output
    doc["components"].append(
        {
            "bom_ref": "tool:observed",
            "component_type": "tool",
            "name": "observed",
            "claims": {"tool_definition": {"scope": "served-descriptor", "method": "live"}},
        }
    )
    result = _validate(project, target, doc)
    # Completeness accepts the observation as a supplier claim; integrity has no evidence.
    assert result.exit_code == 1, result.output
    assert "UNKNOWN [tool:observed]" in result.output
    payload = json.loads(CliRunner().invoke(main, [*risk_args, "--json-output"]).stdout)
    assert payload["assessment_basis"] == "project-reconciled-with-supplier-claims"
    claimed = {(c["subject"], c["kind"], c["detail"]) for c in payload["supplier_claims"]}
    assert {
        (agent["bom_ref"], "field", "capabilities"),
        (agent["bom_ref"], "field", "authorizations"),
        (agent["bom_ref"], "claim", "deployment"),
        (_tool(doc)["bom_ref"], "claim", "attestation"),
        ("tool:observed", "component", "supplementary observation"),
    } <= claimed
    assert payload["supplier_claims_omitted"] == 0


def test_risk_json_counts_supplier_claims_beyond_the_listed_ones(tmp_path):
    from nexus_symbiote.validators.completeness import MAX_REPORTED_SUPPLIER_CLAIMS

    project, target, doc = _scanned(tmp_path)
    _agent(doc)["properties"].update(
        {f"supplier-note-{index}": index for index in range(MAX_REPORTED_SUPPLIER_CLAIMS + 5)}
    )
    result = _validate(project, target, doc)
    assert result.exit_code == 0, result.output
    assert "5 further supplier claims omitted" in result.output
    args = ["risk", str(target), "--project", str(project), "--no-project-policy"]
    payload = json.loads(CliRunner().invoke(main, [*args, "--json-output"]).stdout)
    assert len(payload["supplier_claims"]) == MAX_REPORTED_SUPPLIER_CLAIMS
    assert payload["supplier_claims_omitted"] == 5


def test_repository_agent_from_another_checkout_location_is_matched_by_identity(tmp_path):
    project, target, doc = _scanned(tmp_path)
    agent = _agent(doc)
    original = agent["bom_ref"]
    moved = "agent:repository:" + "0" * 24
    agent["bom_ref"] = moved
    agent["name"] = "checkout-elsewhere"
    for edge in doc["dependencies"]:
        edge["source_ref"] = moved if edge["source_ref"] == original else edge["source_ref"]
    result = _validate(project, target, doc)
    assert result.exit_code == 0, result.output
    second = {**agent, "bom_ref": "agent:repository:" + "1" * 24}
    doc["components"].append(second)
    result = _validate(project, target, doc)
    assert result.exit_code == 1, result.output


def test_validate_project_requires_a_local_subject(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    claim = {
        "scope": "supplier",
        "surfaces_scanned": ["supplier-pipeline"],
        "scanner_status": dict.fromkeys(BUILTIN_SCANNER_NAMES, "complete"),
    }
    supplied = {
        "metadata": {"completeness": claim},
        "components": [
            {
                "bom_ref": "tool:x",
                "component_type": "tool",
                "name": "x",
                "description_text": "d",
                "definition_hash": hash_tool_definition("x", "d"),
                "definition_hash_version": "rfc8785-jcs-v2",
                "claims": {"tool_definition": {"method": "supplier", "scope": "runtime"}},
            }
        ],
    }
    target = tmp_path / "supplied.json"
    result = _validate(empty, target, supplied)
    assert result.exit_code == 1, result.output
    assert "No local project subject was available to reconcile." in result.output
    report = CompletenessValidator().validate_against_project(AIBOM.load(target), empty)
    assert report.local_subjects == 0 and not report.is_complete
