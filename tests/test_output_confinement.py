from pathlib import Path

import pytest

from nexus_symbiote.utils.files import write_output_file


def test_output_replaces_link_without_modifying_target(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("keep")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = workspace / "report.json"
    output.symlink_to(outside)
    write_output_file(output, "report", root=workspace)
    assert outside.read_text() == "keep"
    assert output.read_text() == "report"
    assert not output.is_symlink()


def test_output_rejects_redirected_parent_before_creating_files(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "redirect").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        write_output_file(
            workspace / "redirect" / "new" / "report", "report", root=workspace, create_parents=True
        )
    assert list(outside.iterdir()) == []


def test_output_creates_confined_parents_and_rejects_traversal(tmp_path):
    write_output_file(tmp_path / "new" / "report", "report", root=tmp_path, create_parents=True)
    assert (tmp_path / "new" / "report").read_text() == "report"
    with pytest.raises(ValueError):
        write_output_file(Path("../outside"), "report", root=tmp_path)


def test_exclusive_output_preserves_existing_link_and_target(tmp_path):
    target = tmp_path / "target"
    target.write_text("keep")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        write_output_file(link, "replace", root=tmp_path, overwrite=False)
    assert target.read_text() == "keep" and link.is_symlink()


def test_scan_never_writes_through_output_link(tmp_path):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("keep")
    output = project / "report.json"
    output.symlink_to(outside)
    result = CliRunner().invoke(main, ["scan", str(project), "--report-only", "-o", str(output)])
    assert result.exit_code == 0, result.output
    assert outside.read_text() == "keep" and not output.is_symlink()
