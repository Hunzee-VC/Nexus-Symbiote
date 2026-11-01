"""Instruction and skill scans must not read symlinks or unbounded files."""

from pathlib import Path

from symbiote.scanners.prompt import PromptScanner


def test_prompt_symlink_reports_failure_without_hashing_external_content(tmp_path: Path) -> None:
    outside = tmp_path / "external"
    outside.write_text("CANARY", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").symlink_to(outside)
    result = PromptScanner().scan(project)
    assert result.scan_failures
    assert not result.components
    assert "CANARY" not in repr(result)


def test_skill_symlink_and_invalid_utf8_report_failures(tmp_path: Path) -> None:
    skill_dir = tmp_path / "skills"
    skill_dir.mkdir()
    external = tmp_path / "external"
    external.write_text("CANARY", encoding="utf-8")
    (skill_dir / "x.md").symlink_to(external)
    (skill_dir / "invalid.md").write_bytes(b"\xff")
    result = PromptScanner().scan(tmp_path)
    assert len(result.scan_failures) == 2
    assert not result.components


def test_oversized_prompt_reports_incomplete_collection(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    result = PromptScanner().scan(tmp_path)
    assert result.scan_failures
    assert not result.components
