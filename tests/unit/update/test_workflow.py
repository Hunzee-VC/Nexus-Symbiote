"""The example GitHub Actions workflow: hash-locked install, scoped token and strict exit handling."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[3] / "examples" / "github-actions" / "symbiote-agent-deps.yml"


def _load() -> dict[str, Any]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _steps(job: str) -> list[dict[str, Any]]:
    steps = _load()["jobs"][job]["steps"]
    assert isinstance(steps, list)
    return steps


def test_toolkit_is_never_installed_by_bare_name() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "symbiote==" not in text
    for job in ("monitor", "update"):
        installs = [s["run"] for s in _steps(job) if "pip install" in str(s.get("run", ""))]
        assert installs, job
        for run in installs:
            assert "--require-hashes" in run and "-r " in run


def test_update_job_does_not_persist_the_token() -> None:
    checkout = next(s for s in _steps("update") if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
    with_token = [s for s in _steps("update") if "GH_TOKEN" in (s.get("env") or {})]
    assert len(with_token) == 1


def _status_script() -> str:
    run = next(s["run"] for s in _steps("update") if "symbiote update" in str(s.get("run", "")))
    assert isinstance(run, str)
    return 'status="$1"\n' + run.split("set -e\n", 1)[1]


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")
@pytest.mark.parametrize(
    ("status", "report", "ok"),
    [
        (0, {"proposals": []}, True),
        (1, {"proposals": [{"kind": "security"}]}, True),
        (1, {"proposals": []}, False),  # exit 1 must be backed by a finding
        (2, {"proposals": []}, False),  # usage error is not swallowed
        (6, {"proposals": []}, False),
        (0, ["not", "a", "report"], False),
    ],
)
def test_update_step_fails_on_anything_but_findings(
    tmp_path: Path, status: int, report: object, ok: bool
) -> None:
    (tmp_path / "symbiote-update.json").write_text(json.dumps(report))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "python").symlink_to(sys.executable)
    proc = subprocess.run(
        ["bash", "-e", "-c", _status_script(), "step", str(status)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={"PATH": f"{bindir}:/usr/bin:/bin"},
        check=False,
        timeout=60,
    )
    assert (proc.returncode == 0) is ok, proc.stdout + proc.stderr
