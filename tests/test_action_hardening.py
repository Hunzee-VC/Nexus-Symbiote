"""Security regressions for the composite Action's data-only Python runner."""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

from tests.support import load_script

ROOT = Path(__file__).resolve().parents[1]
runner = load_script("run_action")


def action_steps() -> list[dict]:
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    return action["runs"]["steps"]


def test_scan_inputs_are_data_not_shell(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    step = next(step for step in action_steps() if step.get("id") == "scan")
    assert step["env"]["SYMBIOTE_SCAN_PATH"] == "${{ inputs.scan-path }}"
    assert "${{" not in step["run"]
    assert (
        step["run"] == '"$SYMBIOTE_ACTION_PYTHON" -I "$SYMBIOTE_ACTION_PATH/scripts/run_action.py"'
    )
    payload = "$(touch PWNED)'quoted space"
    (tmp_path / payload).mkdir()
    config = runner.Config.from_env(
        {
            "GITHUB_WORKSPACE": str(tmp_path),
            "SYMBIOTE_SCAN_PATH": payload,
            "SYMBIOTE_VALIDATE": "false",
            "SYMBIOTE_RISK_CHECK": "false",
        }
    )
    calls = []

    def command(args):
        calls.append(args)
        Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 0, "", "")

    assert runner.run(config, command=command) == 0
    assert len(calls) == 1
    assert calls[0][-2:] == ["--", str(tmp_path / payload)]
    assert not (tmp_path / "PWNED").exists() and not Path("PWNED").exists()


def test_validation_failure_is_not_suppressed(tmp_path: Path) -> None:
    for step in action_steps():
        if "run" in step:
            assert "|| true" not in step["run"]
    config = runner.Config.from_env({"GITHUB_WORKSPACE": str(tmp_path)})
    calls = []

    def command(args):
        calls.append(args[0])
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        if args[0] == "risk":
            return subprocess.CompletedProcess(args, 0, '{"overall_score": 0, "passed": true}', "")
        return subprocess.CompletedProcess(args, 7 if args[0] == "validate" else 0, "", "")

    assert runner.run(config, command=command) == 1
    assert calls == ["scan", "validate", "risk"]
    assert config.output.read_text() == "{}"
