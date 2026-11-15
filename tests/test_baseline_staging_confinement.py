"""``baseline`` stages its inventory without reaching through a linked output directory.

Audit 2026-11-14 (information): ``baseline`` created its staging file with
``tempfile.mkstemp(dir=target.parent)``, which follows a symbolic link anywhere on the
path, and only the later confined write refused the link. A file was created, and then
removed, in the link's target directory: outside the location the output rules allow.
"""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.utils.terminal import OUTPUT_REFUSED


def _project(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    return project


@pytest.mark.parametrize("below", ["", "sub"])
def test_a_linked_output_directory_is_refused_before_anything_is_staged(tmp_path, below):
    project = _project(tmp_path)
    real = tmp_path / "real"
    (real / below).mkdir(parents=True, exist_ok=True)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    watched = real / below
    # Any entry created or removed in the directory moves its modification time.
    os.utime(watched, ns=(0, 0))
    output = link / below / "baseline.json" if below else link / "baseline.json"
    result = CliRunner().invoke(
        main, ["baseline", str(project), "--no-project-policy", "-o", str(output)]
    )
    assert result.exit_code == 1, result.output
    assert OUTPUT_REFUSED in " ".join(result.output.split())
    assert list(watched.iterdir()) == []
    assert watched.stat().st_mtime_ns == 0


def test_a_baseline_beside_a_real_directory_leaves_no_staging_file(tmp_path):
    project = _project(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    result = CliRunner().invoke(
        main,
        ["baseline", str(project), "--no-project-policy", "-o", str(out / "baseline.json")],
    )
    assert result.exit_code == 0, result.output
    assert [path.name for path in out.iterdir()] == ["baseline.json"]
