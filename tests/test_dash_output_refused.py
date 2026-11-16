"""``-o -`` is refused instead of writing a file named ``-``.

Audit 2026-11-14 (information): ``-o -`` created a file named ``-``, where many tools
mean standard output, so a pipeline that read standard output read nothing.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.utils.terminal import DASH_OUTPUT

SHADOWSCAN_REPORT = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"

ARGUMENTS = {
    "scan": ["scan", "project", "--no-project-policy", "-o", "-"],
    "scan-dot": ["scan", "project", "--no-project-policy", "-o", "./-"],
    "baseline": ["baseline", "project", "--no-project-policy", "-o", "-"],
    "vex": ["vex", "inventory.json", "-o", "-"],
    "import-shadowscan": ["import-shadowscan", str(SHADOWSCAN_REPORT), "-o", "-"],
}


@pytest.mark.parametrize("command", sorted(ARGUMENTS))
def test_dash_is_refused_and_no_file_is_written(tmp_path, monkeypatch, command):
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    (tmp_path / "project").mkdir()
    (tmp_path / "project/AGENTS.md").write_text("Keep receipts.")
    scanned = runner.invoke(
        main, ["scan", "project", "--no-project-policy", "-o", "inventory.json"]
    )
    assert scanned.exit_code == 0, scanned.output
    before = sorted(os.listdir(tmp_path))
    result = runner.invoke(main, ARGUMENTS[command])
    assert result.exit_code == 1, result.output
    assert DASH_OUTPUT in " ".join(result.output.split())
    assert sorted(os.listdir(tmp_path)) == before
    assert not os.path.lexists(tmp_path / "-")


def test_an_absolute_path_still_writes_a_file_named_dash(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    output = tmp_path / "-"
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(output)]
    )
    assert result.exit_code == 0, result.output
    assert output.is_file()
