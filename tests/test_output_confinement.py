import errno
import os
import sys
from pathlib import Path

import pytest

from nexus_symbiote.core.hashing import open_directory_nofollow
from nexus_symbiote.utils import files as files_mod
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


def test_output_requires_posix_o_nofollow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    with pytest.raises(OSError, match="no-symlink"):
        write_output_file(tmp_path / "report.json", "{}", root=tmp_path)


def test_output_propagates_non_missing_lstat_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_stat = os.stat

    def failing_lstat(
        path: str | os.PathLike[str],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        if path == "blocked.json" and not follow_symlinks:
            raise PermissionError(errno.EACCES, "permission denied")
        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", failing_lstat)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {failing_lstat})
    with pytest.raises(PermissionError):
        write_output_file(tmp_path / "blocked.json", "{}", root=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_exclusive_output_fallback_unlinks_partial_file_on_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_hardlink(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.EOPNOTSUPP, "Operation not supported")

    real_fsync = os.fsync
    fsync_calls = 0

    def failing_second_fsync(fd: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 2:
            raise OSError(errno.EIO, "simulated disk error")
        real_fsync(fd)

    monkeypatch.setattr(os, "link", no_hardlink)
    monkeypatch.setattr(os, "fsync", failing_second_fsync)
    destination = tmp_path / "report.json"
    with pytest.raises(OSError, match="simulated disk error"):
        write_output_file(destination, '{"ok": true}\n', root=tmp_path, overwrite=False)
    assert list(tmp_path.iterdir()) == []


def test_parent_follows_darwin_root_private_var_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_slash = tmp_path / "slash"
    (fake_slash / "private" / "var").mkdir(parents=True)
    anchor = Path(fake_slash.anchor)

    monkeypatch.setattr(
        files_mod,
        "open_directory_nofollow",
        lambda target: open_directory_nofollow(fake_slash if target == anchor else target),
    )
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(os.path, "islink", lambda candidate: candidate == "/var")
    monkeypatch.setattr(os, "readlink", lambda candidate: "private/var")

    write_output_file(anchor / "var" / "report.json", "ok\n", root=anchor)
    assert (fake_slash / "private" / "var" / "report.json").read_text(encoding="utf-8") == "ok\n"
