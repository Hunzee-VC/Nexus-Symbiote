"""Every gate says why it failed, results go to standard output, and validate states its basis."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

import nexus_symbiote.cli as cli
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import (
    AIBOMMetadata,
    CompletenessClaim,
    MCPServerComponent,
    PromptComponent,
)
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES


def _lines(output: str) -> list[str]:
    return output.splitlines()


def _agent(root: Path, *, pickle: bool = False) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.yaml").write_text("name: Demo\ninstructions: [CLAUDE.md]\n")
    (root / "CLAUDE.md").write_text("Use the configured tools.\n")
    if pickle:
        (root / "classifier.pkl").write_bytes(b"unsafe-format-fixture")
    return root


def test_an_empty_project_fails_the_scan_gate_with_its_reason(tmp_path):
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--no-project-policy", "--check"])
    assert result.exit_code == 1
    lines = _lines(result.stderr)
    assert "Scan gate failed" in lines
    assert "  - no agent manifest or supported local inventory evidence was found" in lines


def test_a_scoped_scan_names_the_collectors_it_left_out(tmp_path):
    result = CliRunner().invoke(
        main, ["scan", str(_agent(tmp_path / "p")), "--no-project-policy", "--scanner", "prompt"]
    )
    assert result.exit_code == 1
    lines = _lines(result.stderr)
    assert "  - collection coverage is unknown or incomplete" in lines
    assert any(line.startswith("  - not collected: a2a, ide_agents, mcp") for line in lines)
    # Standard output carries only the inventory.
    assert json.loads(result.stdout)["components"]


def test_a_symlink_names_its_collector_and_failure(tmp_path):
    project = _agent(tmp_path / "p")
    (project / "AGENTS.md").symlink_to(project / "CLAUDE.md")
    result = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    assert result.exit_code == 1
    failures = [line for line in _lines(result.stderr) if line.startswith("  - collection: ")]
    assert "  - collection: AGENTS.md: symlink excluded (from mcp)" in failures
    assert any(
        line.startswith("  - collection: AGENTS.md: ") and line.endswith(" (from prompt)")
        for line in failures
    )


def test_a_critical_finding_fails_the_scan_gate_and_is_listed(tmp_path):
    project = _agent(tmp_path / "p", pickle=True)
    result = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    assert result.exit_code == 1
    lines = _lines(result.stderr)
    assert "  - finding at or above critical" in lines
    assert any(
        line.startswith("  - finding: critical ")
        and "classifier.pkl [serialization_format] " in line
        for line in lines
    )
    assert "  - score: 17.0 (fail threshold 50)" in lines


def test_report_only_prints_the_same_reasons_and_passes(tmp_path):
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "--report-only", "--check"]
    )
    assert result.exit_code == 0
    assert "Scan gate failed (report only: exit status 0)" in _lines(result.stderr)
    assert any(line.startswith("  - ") for line in _lines(result.stderr))


def test_check_writes_nothing_and_refuses_an_output(tmp_path):
    project = _agent(tmp_path / "p")
    before = sorted(project.iterdir())
    result = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    assert result.exit_code == 0, result.output
    assert result.stdout == "" and "Scan gate passed" in result.stderr
    assert sorted(project.iterdir()) == before
    refused = CliRunner().invoke(
        main, ["scan", str(project), "--check", "-o", str(tmp_path / "bom.json")]
    )
    assert refused.exit_code == 2 and not (tmp_path / "bom.json").exists()


def test_a_repeated_collector_is_refused(tmp_path):
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--scanner", "mcp", "--scanner", "mcp", "--check"]
    )
    assert result.exit_code == 2
    assert "each collector may be selected only once" in result.output


@pytest.mark.parametrize("command", ["scan", "baseline"])
def test_a_project_path_that_is_a_file_is_a_usage_error(tmp_path, command):
    target = tmp_path / "file.txt"
    target.write_text("x")
    output = tmp_path / "out.json"
    result = CliRunner().invoke(main, [command, str(target), "-o", str(output)])
    assert result.exit_code == 2 and not output.exists()


def _linked(root: Path, count: int) -> Path:
    (root / "target").mkdir(parents=True)
    for index in range(count):
        (root / f"link{index}").symlink_to(root / "target", target_is_directory=True)
    return root


def _more(output: str) -> str:
    (line,) = [line for line in _lines(output) if re.match(r"  - collection: \d+ more", line)]
    return line


def test_a_gate_that_lists_some_gaps_says_where_the_rest_are(tmp_path):
    project = _linked(tmp_path / "p", 11)
    runner = CliRunner()
    output = tmp_path / "bom.json"
    written = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert written.exit_code == 1
    assert _more(written.stderr).endswith(" more in metadata.completeness.scan_failures")
    failures = AIBOM.load(output).metadata.completeness.scan_failures
    assert all(any(f"link{index}:" in failure for failure in failures) for index in range(11))
    # --check (the pre-commit hooks) and baseline keep no inventory to look in.
    checked = runner.invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    target = tmp_path / "baseline.json"
    staged = runner.invoke(main, ["baseline", str(project), "-o", str(target)])
    for result in (checked, staged):
        assert result.exit_code == 1
        assert "this run keeps no inventory: scan with -o FILE records them all" in _more(
            result.stderr
        )
        assert " more in metadata.completeness" not in result.stderr
    assert not any(line.startswith("Saved ") for line in _lines(staged.stderr))
    assert sorted(path.name for path in tmp_path.iterdir()) == ["bom.json", "p"]


def _risky_bom(tmp_path: Path, *, complete: bool = True) -> Path:
    status = dict.fromkeys(BUILTIN_SCANNER_NAMES, "complete")
    if not complete:
        status["a2a"] = "unknown"
    bom = AIBOM(
        metadata=AIBOMMetadata(
            completeness=CompletenessClaim(
                scope="full-agent",
                surfaces_scanned=["prompts"],
                assurance_level=AssuranceLevel.OBSERVED,
                scanner_status=status,
            )
        ),
        components=[PromptComponent(bom_ref="prompt:1", name="CLAUDE.md", content_hash="x")],
    )
    path = tmp_path / "risk.json"
    bom.save(path)
    return path


def test_risk_names_the_reason_a_low_score_still_fails(tmp_path):
    result = CliRunner().invoke(main, ["risk", str(_risky_bom(tmp_path, complete=False))])
    assert result.exit_code == 1
    lines = _lines(result.stdout)
    assert "Gate: FAILED" in lines
    assert "  - collection coverage is unknown or incomplete" in lines
    assert "  - score: 0.0 (fail threshold 50)" in lines
    assert "Gate (threshold" not in result.output


def test_risk_json_carries_the_verdict_threshold_and_cutoff(tmp_path):
    result = CliRunner().invoke(main, ["risk", str(_risky_bom(tmp_path)), "--json-output"])
    document = json.loads(result.stdout)
    assert result.exit_code == 0 and document["passed"] is True
    assert document["score_threshold"] == 50.0 and document["fail_on_severity"] == "critical"
    assert result.stderr == ""


def test_no_score_threshold_keeps_the_severity_and_coverage_gates(tmp_path):
    runner = CliRunner()
    path = _risky_bom(tmp_path, complete=False)
    result = runner.invoke(main, ["risk", str(path), "--no-score-threshold", "--json-output"])
    document = json.loads(result.stdout)
    assert result.exit_code == 1 and document["score_threshold"] is None
    assert document["gate_reasons"] == ["collection coverage is unknown or incomplete"]
    both = runner.invoke(main, ["risk", str(path), "--no-score-threshold", "--threshold", "5"])
    assert both.exit_code == 2


def test_failed_reconciliation_json_has_the_scored_shape(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    bom = tmp_path / "bom.json"
    bom.write_text(AIBOM().to_json())
    result = CliRunner().invoke(
        main, ["risk", str(bom), "--project", str(project), "--json-output", "--no-project-policy"]
    )
    assert result.exit_code == 1
    document = json.loads(result.stdout)
    assert document["assessment_basis"] == "project-reconciliation-failed"
    assert document["overall_score"] is None and document["passed"] is False
    assert {"findings", "severity_counts", "total_components"} <= document.keys()


def test_validate_without_project_says_it_checked_only_the_inventorys_claims(tmp_path):
    path = _risky_bom(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["validate", str(path), "--no-project-policy"])
    lines = _lines(result.stdout)
    assert any(
        line.startswith("Assessment basis: supplied-bom: only the inventory's own claims")
        for line in lines
    )
    document = json.loads(
        runner.invoke(main, ["validate", str(path), "--no-project-policy", "--json-output"]).stdout
    )
    assert document["assessment_basis"] == "supplied-bom"
    assert document["passed"] is (result.exit_code == 0)


def test_validate_with_project_says_what_was_reconciled(tmp_path):
    project = _agent(tmp_path / "project")
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(project), "-o", str(bom)]).exit_code == 0
    result = runner.invoke(main, ["validate", str(bom), "--project", str(project)])
    assert result.exit_code == 0, result.output
    assert (
        "Assessment basis: project-reconciled: the inventory was compared with a fresh local "
        f"collection of {project}"
    ) in _lines(result.stdout)
    assert _lines(result.stdout)[-1] == "Validation: PASSED"
    document = json.loads(
        runner.invoke(
            main, ["validate", str(bom), "--project", str(project), "--json-output"]
        ).stdout
    )
    assert document["passed"] is True and document["assessment_basis"] == "project-reconciled"
    assert document["completeness"]["status"] == "pass"
    assert document["integrity"]["status"] == "pass"


def test_unknown_integrity_is_named_and_explained(tmp_path):
    bom = AIBOM(
        metadata=AIBOMMetadata(
            completeness=CompletenessClaim(
                scope="full-agent",
                surfaces_scanned=["prompts"],
                scanner_status=dict.fromkeys(BUILTIN_SCANNER_NAMES, "complete"),
            )
        )
    )
    path = tmp_path / "empty.json"
    bom.save(path)
    result = CliRunner().invoke(main, ["validate", str(path), "--no-project-policy"])
    assert result.exit_code == 1
    lines = _lines(result.stdout)
    assert "  Status: UNKNOWN" in lines
    # The integrity validator names the gap itself; the report adds a line only when no
    # issue explains an unknown verdict.
    assert (
        "  UNKNOWN [inventory] No artifact hash or signature could be verified against local "
        "evidence"
    ) in lines
    assert "  UNKNOWN: no hash or signature could be verified" not in lines
    from nexus_symbiote.reporting import validation_report_lines

    unexplained = validation_report_lines(
        {"passed": False, "integrity": {"status": "unknown", "issues": []}}
    )
    assert ("  UNKNOWN: no hash or signature could be verified", None) in unexplained


def test_skip_integrity_checks_completeness_only_and_says_so(tmp_path):
    project = _agent(tmp_path / "project", pickle=True)
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    runner.invoke(main, ["scan", str(project), "--report-only", "-o", str(bom)])
    args = ["validate", str(bom), "--project", str(project), "--no-project-policy"]
    assert runner.invoke(main, args).exit_code == 1
    skipped = runner.invoke(main, [*args, "--skip-integrity"])
    assert skipped.exit_code == 0, skipped.output
    assert "  SKIPPED by --skip-integrity: no hash or signature was checked" in _lines(
        skipped.stdout
    )
    document = json.loads(runner.invoke(main, [*args, "--skip-integrity", "--json-output"]).stdout)
    assert document["integrity"] == {"status": "skipped", "skipped_by": "--skip-integrity"}


def test_results_go_to_standard_output_and_diagnostics_to_standard_error(tmp_path):
    project = _agent(tmp_path / "project")
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    scanned = runner.invoke(main, ["scan", str(project), "-o", str(bom)])
    assert scanned.stdout == "" and "Scanning" in scanned.stderr
    for args in (
        ["summary", str(bom)],
        ["validate", str(bom), "--no-project-policy"],
        ["risk", str(bom), "--no-project-policy"],
        ["diff", str(bom), str(bom)],
    ):
        result = runner.invoke(main, args)
        assert result.stdout.strip() and result.stderr == "", args
    summary = json.loads(runner.invoke(main, ["summary", str(bom), "--json-output"]).stdout)
    assert summary["total_components"] == len(AIBOM.load(bom).components)
    assert summary["completeness"]["scope"] == "repository"


def test_diff_lists_a_relationship_only_change(tmp_path):
    components = [
        MCPServerComponent(bom_ref="mcp:a", name="a"),
        MCPServerComponent(bom_ref="mcp:b", name="b"),
    ]
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    AIBOM(components=components).save(old)
    edged = AIBOM(components=components)
    edged.add_dependency(
        DependencyEdge(source_ref="mcp:a", target_ref="mcp:b", relationship="delegates-to")
    )
    edged.save(new)
    result = CliRunner().invoke(main, ["diff", str(old), str(new)])
    assert "1 changes detected" in result.stdout
    assert "+1 relationships added" in _lines(result.stdout)
    assert "  + [HIGH] mcp:a delegates-to mcp:b" in _lines(result.stdout)


def test_unreadable_inventories_name_the_class_of_problem(tmp_path):
    cases = {
        "schema": '{"metadata": "x"}',
        "json": '{"metadata": ',
        "strict": '{"a": 1, "a": 2}',
    }
    # The reader's NativeFormatError names the class of problem, never the content.
    expected = {
        "schema": "It does not match the native AgentBOM schema.",
        "json": "It is not strict UTF-8 JSON",
        "strict": "duplicate keys",
    }
    for name, content in cases.items():
        path = tmp_path / f"{name}.json"
        path.write_text(content)
        result = CliRunner().invoke(main, ["summary", str(path)])
        assert result.exit_code == 1
        assert f"{path} is not a valid native AIBOM file. It " in result.output
        assert expected[name] in result.output


def test_an_unexpected_error_is_a_clean_failure_with_an_opt_in_traceback(tmp_path, monkeypatch):
    path = tmp_path / "bom.json"
    path.write_text(AIBOM().to_json())

    def broken(self: AIBOM) -> dict[str, object]:
        raise KeyError("canary ##[set-output name=x]y")

    monkeypatch.setattr(AIBOM, "summary", broken)
    result = CliRunner().invoke(main, ["summary", str(path)])
    assert result.exit_code == 1 and result.exception.__class__ is SystemExit
    assert "Error: internal error (KeyError)" in result.output
    assert "canary" not in result.output and "Traceback" not in result.output
    debug = CliRunner().invoke(main, ["--debug", "summary", str(path)])
    assert debug.exit_code == 1
    assert all(line.startswith(("Debug: ", "Error: ")) for line in _lines(debug.stderr))
    assert "Debug: KeyError raised at:" in _lines(debug.stderr)
    assert any(line.endswith(" in broken") for line in _lines(debug.stderr))
    # Where it was raised, never the message, which can quote input.
    assert "canary" not in debug.stderr and "##[" not in debug.stderr


def test_an_export_failure_names_the_format_not_the_values(tmp_path, monkeypatch):
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

    def invalid(self: object, bom: AIBOM) -> str:
        raise ValueError("invalid cyclonedx export: version: '##[set-output name=a]canary'")

    monkeypatch.setattr(CycloneDXGenerator, "generate_json", invalid)
    project = _agent(tmp_path / "project")
    result = CliRunner().invoke(main, ["scan", str(project), "-f", "cyclonedx"])
    assert result.exit_code == 1
    assert "cannot be exported as cyclonedx" in result.output
    assert "canary" not in result.output


def test_shell_completion_cannot_short_circuit_a_gate(tmp_path):
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--check"],
        env={"_NEXUS_SYMBIOTE_COMPLETE": "bash_source"},
        prog_name="nexus-symbiote",
    )
    assert result.exit_code == 1 and "Scan gate failed" in result.output


def test_a_short_binding_key_is_a_usage_error_before_collection(tmp_path, monkeypatch):
    collected = []
    monkeypatch.setattr(cli, "_get_scanners", lambda: collected.append(1) or {})
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--check"],
        env={"NEXUS_SYMBIOTE_SOURCE_BINDING_KEY": "too-short"},
    )
    assert result.exit_code == 2 and not collected
    assert "must contain at least 32 characters" in result.output
    assert "too-short" not in result.output


def test_a_relative_project_that_a_link_leads_elsewhere_is_refused(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    elsewhere = _agent(tmp_path / "elsewhere")
    (checkout / "my-agent").symlink_to(elsewhere, target_is_directory=True)
    monkeypatch.chdir(checkout)
    runner = CliRunner()
    refused = runner.invoke(main, ["scan", "my-agent", "--check"])
    assert refused.exit_code == 2
    assert "leads outside the current directory through a symbolic link" in refused.output
    named = runner.invoke(main, ["scan", str(checkout / "my-agent"), "--check"])
    assert named.exit_code == 0, named.output
    assert (
        f"Note: PROJECT_PATH {checkout / 'my-agent'} resolves through a symbolic link to {elsewhere}"
        in _lines(named.stderr)
    )


def test_import_with_markup_in_the_output_path_reports_success(tmp_path):
    report = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
    # Rich read "[/]" in this path as a closing tag and failed after the file was written.
    (tmp_path / "out[").mkdir()
    output = tmp_path / "out[" / "]bom.json"
    assert "[/]" in str(output)
    result = CliRunner().invoke(
        main, ["import-shadowscan", str(report), "-o", str(output), "--report-only"]
    )
    assert result.exit_code == 0, result.output
    assert str(output) in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["--sha256", "sha256:XYZ"],
        ["--sha256", "sha256:" + "0" * 64, "--signer-identity", "x"],
    ],
)
def test_verify_artifact_misuse_is_a_usage_error(tmp_path, args):
    (tmp_path / "a.bin").write_bytes(b"x")
    result = CliRunner().invoke(
        main, ["verify-artifact", "a.bin", "--project", str(tmp_path), *args]
    )
    assert result.exit_code == 2


def test_verify_discovery_names_the_input_that_failed(tmp_path):
    bom, report = tmp_path / "bom.json", tmp_path / "report.json"
    bom.write_text("{")
    report.write_text("{}")
    result = CliRunner().invoke(main, ["verify-discovery", str(bom), str(report)])
    assert result.exit_code == 1
    assert "Cannot safely read the BOM: it is not valid JSON" in result.output


def test_no_color_and_a_pipe_print_no_escape_sequences(tmp_path):
    bom = _risky_bom(tmp_path)
    result = CliRunner().invoke(main, ["risk", str(bom)], env={"NO_COLOR": "1"}, color=True)
    assert "\x1b" not in result.output
    colored = CliRunner().invoke(main, ["risk", str(bom)], color=True)
    assert "\x1b[" in colored.output


def test_baseline_names_why_the_built_in_gate_refused_it(tmp_path):
    project = _agent(tmp_path / "project", pickle=True)
    # The checkout's policy turns the scan gate into a report; the baseline gate holds.
    (project / ".nexus-symbiote.yaml").write_text("scan: {failure_mode: report-only}\n")
    target = tmp_path / "baseline.json"
    result = CliRunner().invoke(main, ["baseline", str(project), "-o", str(target)])
    assert result.exit_code == 1 and not target.exists()
    lines = _lines(result.stderr)
    assert "Built-in scan gate failed; a project policy cannot relax it here:" in lines
    assert "  - finding at or above critical" in lines
    assert "Error: Baseline was not written: static scan gate failed" in lines


def test_sarif_locations_are_relative_to_the_scanned_project(tmp_path, monkeypatch):
    project = tmp_path / "repo" / "services" / "bot"
    (project / "models").mkdir(parents=True)
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"docs": {"command": "npx", "args": ["-y", "docs-mcp"]}}})
    )
    (project / "models" / "classifier.pkl").write_bytes(b"unsafe-format-fixture")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    output = tmp_path / "out.sarif"
    result = CliRunner().invoke(
        main, ["scan", str(project), "--report-only", "-f", "sarif", "-o", str(output)]
    )
    assert result.exit_code == 0, result.output
    uris = [
        location["physicalLocation"]["artifactLocation"]["uri"]
        for run in json.loads(output.read_text())["runs"]
        for finding in run["results"]
        for location in finding.get("locations", [])
    ]
    assert uris and all((project / uri).exists() for uri in uris), uris


def test_reports_show_coverage_gaps_suppressions_and_omitted_issues():
    from nexus_symbiote.reporting import risk_report_lines, validation_report_lines

    risk = [
        text
        for text, _ in risk_report_lines(
            {
                "passed": False,
                "overall_score": 4.0,
                "gate_reasons": ["collection coverage is unknown or incomplete"],
                "coverage_gaps": ["::error::collector a2a was not run"],
                "suppressed_findings": [{"component_ref": "x", "category": "y"}],
            }
        )
    ]
    assert "  - coverage gap: ::error::collector a2a was not run" in risk
    assert (
        "  - suppressed by project policy: 1 findings (reasons, owners and expiry in --json-output)"
        in risk
    )
    validation = [
        text
        for text, _ in validation_report_lines(
            {
                "passed": False,
                "completeness": {"status": "fail", "issues": [], "issues_omitted": 3},
                "integrity": {"status": "skipped", "skipped_by": "policy"},
            }
        )
    ]
    assert "  ... and 3 more issues, counted in --json-output" in validation


def test_a_missing_choice_option_lists_its_choices_on_their_own_lines(tmp_path):
    envelope, key = tmp_path / "envelope.json", tmp_path / "key.pem"
    envelope.write_text("{}")
    key.write_text("")
    result = CliRunner().invoke(
        main, ["runtime", "verify", str(envelope), "--public-key", str(key)]
    )
    assert result.exit_code == 2
    assert "\ufffd" not in result.output
    lines = _lines(result.output)
    assert "Error: Missing option '--kind'. Choose from:" in lines
    assert {"\tsnapshot,", "\tapproval,", "\ttrust,", "\tmodel"} <= set(lines)


def test_a_command_group_without_arguments_still_prints_its_help():
    result = CliRunner().invoke(main, ["runtime"], prog_name="nexus-symbiote")
    assert result.output.startswith("Usage: nexus-symbiote runtime")
    assert "Commands:" in result.output and "�" not in result.output
