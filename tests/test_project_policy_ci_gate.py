"""In CI a project policy that weakens a gate is a choice someone has to make.

Outside CI such a policy warns, as before. With a CI variable set, `scan`, `validate`
and `risk` refuse it unless `--no-project-policy` ignores it or `--accept-project-policy`
accepts it, as unsigned discovery evidence needs `--allow-unsigned-discovery`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main

REFUSAL = "weakens the built-in gates and this run looks like CI"


def _project(root: Path, policy: str) -> Path:
    root.mkdir()
    (root / ".nexus-symbiote.yaml").write_text(policy)
    (root / "models").mkdir()
    (root / "models" / "classifier.pkl").write_bytes(b"unsafe-format-fixture")
    return root


def _inventory(tmp_path: Path, project: Path) -> Path:
    output = tmp_path / "inventory.json"
    run = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    )
    assert run.exit_code == 0, run.output
    assert json.loads(output.read_text())["components"]
    return output


def test_outside_ci_a_weakening_policy_still_only_warns(tmp_path: Path) -> None:
    project = _project(tmp_path / "project", "scan:\n  failure_mode: report-only\n")
    run = CliRunner().invoke(main, ["scan", str(project), "-o", str(tmp_path / "out.json")])
    assert run.exit_code == 0, run.output
    assert "WARNING: policy" in run.output
    assert REFUSAL not in run.output


def test_in_ci_scan_refuses_a_weakening_policy_without_an_explicit_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CI", "true")
    project = _project(tmp_path / "project", "scan:\n  failure_mode: report-only\n")
    output = tmp_path / "out.json"
    run = CliRunner().invoke(main, ["scan", str(project), "-o", str(output)])
    assert run.exit_code == 1, run.output
    assert REFUSAL in run.output
    assert not output.exists()


@pytest.mark.parametrize("flag", ["--accept-project-policy", "--no-project-policy"])
def test_in_ci_an_explicit_choice_lets_scan_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    monkeypatch.setenv("CI", "true")
    project = _project(tmp_path / "project", "scan:\n  failure_mode: report-only\n")
    output = tmp_path / "out.json"
    run = CliRunner().invoke(main, ["scan", str(project), flag, "-o", str(output)])
    assert REFUSAL not in run.output
    assert output.exists()
    # The accepted policy is still reported as weakened; the ignored one is not applied.
    weakened = json.loads(output.read_text())["metadata"].get("policy_weakened") or []
    assert bool(weakened) == (flag == "--accept-project-policy")


@pytest.mark.parametrize("command", ["validate", "risk"])
def test_in_ci_validate_and_risk_refuse_a_weakening_project_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    project = _project(tmp_path / "project", "risk:\n  fail_threshold: 1000000\n")
    inventory = _inventory(tmp_path, project)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    refused = CliRunner().invoke(main, [command, str(inventory), "--project", str(project)])
    assert refused.exit_code == 1, refused.output
    assert REFUSAL in refused.output
    accepted = CliRunner().invoke(
        main, [command, str(inventory), "--project", str(project), "--accept-project-policy"]
    )
    assert REFUSAL not in accepted.output
    assert "WARNING: policy" in accepted.output


def test_a_stricter_project_policy_is_never_refused_in_ci(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CI", "true")
    project = _project(tmp_path / "project", "risk:\n  fail_threshold: 20\n")
    run = CliRunner().invoke(
        main, ["scan", str(project), "--report-only", "-o", str(tmp_path / "out.json")]
    )
    assert run.exit_code == 0, run.output
    assert REFUSAL not in run.output
