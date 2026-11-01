"""Security regressions for the composite action shell steps."""

import os
import re
import subprocess
from pathlib import Path

import yaml

from nexus_symbiote.core.vocab import SCANNER_NAMES

REPO_ROOT = Path(__file__).resolve().parents[1]


def action_steps() -> dict[str, dict]:
    action = yaml.safe_load((Path(__file__).resolve().parents[1] / "action.yml").read_text())
    return {step["name"]: step for step in action["runs"]["steps"]}


def test_scan_inputs_are_data_not_shell(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    symbiote = bin_dir / "nexus-symbiote"
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
    command = bin_dir / "nexus-symbiote"
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


def test_scanner_allowlist_matches_registry() -> None:
    run = action_steps()["Scan once and export"]["run"]
    match = re.search(r'case "\$name" in ([a-z_|]+)\) ;;', run)
    assert match is not None
    assert set(match.group(1).split("|")) == set(SCANNER_NAMES)


def test_action_inputs_exist() -> None:
    action = yaml.safe_load((REPO_ROOT / "action.yml").read_text())
    inputs = action["inputs"]
    for name in ("fail-on-validation-error", "upload-artifact", "policy-file"):
        assert name in inputs


def test_precommit_hooks_have_no_fixed_tmp_path() -> None:
    text = (REPO_ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
    hooks = yaml.safe_load(text)
    assert hooks
    assert "/tmp/" not in text
    assert all("entry" in hook for hook in hooks)
