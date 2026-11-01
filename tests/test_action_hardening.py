"""Security regressions for the composite action shell steps."""

import os
import subprocess
from pathlib import Path

import yaml


def action_steps() -> dict[str, dict]:
    action = yaml.safe_load((Path(__file__).resolve().parents[1] / "action.yml").read_text())
    return {step["name"]: step for step in action["runs"]["steps"]}


def test_scan_inputs_are_data_not_shell(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    symbiote = bin_dir / "symbiote"
    symbiote.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARG_LOG"\n')
    symbiote.chmod(0o755)
    fake_python = bin_dir / "python"
    fake_python.write_text("#!/bin/sh\ncat >/dev/null\n")
    fake_python.chmod(0o755)
    output = tmp_path / "github_output"
    output.touch()
    marker = tmp_path / "pwned"
    payload = f"$(touch {marker})"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "ARG_LOG": str(tmp_path / "args"),
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(output),
        "SCAN_PATH": payload,
        "OUTPUT_FILE": str(tmp_path / "bom.json"),
        "OUTPUT_FORMAT": "json",
        "SCANNERS": "",
    }
    result = subprocess.run(  # noqa: S603
        ["/bin/bash", "-e", "-c", action_steps()["Scan once and export"]["run"]],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert payload in (tmp_path / "args").read_text().splitlines()


def test_validation_failure_is_not_suppressed(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    command = bin_dir / "symbiote"
    command.write_text("#!/bin/sh\nexit 7\n")
    command.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "NATIVE_BOM": "bom.json",
        "SCAN_PATH": ".",
    }
    result = subprocess.run(  # noqa: S603
        ["/bin/bash", "-e", "-c", action_steps()["Validate"]["run"]],
        env=env,
        check=False,
    )
    assert result.returncode == 7
