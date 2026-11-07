"""Manifest forms the registry collector cannot read are coverage gaps, not silence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.registry import RegistryScanner

NOTHING_FOUND = "registry (no AI-related dependencies found)"


def _project(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "AGENTS.md").write_text("# Agents\n\nUse the tests before committing.\n")
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _scan(project: Path, out: Path, *extra: str) -> tuple[int, dict]:
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(out), *extra]
    )
    document = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    return result.exit_code, document


@pytest.mark.parametrize(
    "line",
    [
        "-r more.txt",
        "--requirement more.txt",
        "--requirement=more.txt",
        "-rmore.txt",
        "--requirem more.txt",
        "-r reqs/base.txt",
        "-r ../x.txt",
        "-r a/../requirements.txt",
        "-r /requirements.txt",
        "-r ${REQUIREMENTS}",
        "-r https://h.example/r.txt",
        "--index-url https://pypi.org/simple -r ../shared/ai.txt",
        "-c constraints.txt",
        "--cons=constraints.txt",
        "-e git+https://github.com/openai/openai-python@v1.0.0#egg=openai",
        "-e ./vendor/x",
        "-e file:./vendor/x",
        "-r 'unbalanced",
    ],
)
def test_requirements_option_reaching_beyond_the_read_files_is_partial(tmp_path, line):
    project = _project(
        tmp_path / "proj", {"requirements.txt": f"{line}\n", "more.txt": "openai==1.0.0\n"}
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded and result.scan_failures == []
    assert all(gap.startswith("requirements.txt: ") for gap in result.surfaces_excluded)
    assert NOTHING_FOUND not in result.surfaces_scanned
    code, document = _scan(project, tmp_path / "a.json")
    assert code == 1
    assert document["metadata"]["completeness"]["scanner_status"]["registry"] == "partial"
    code, _ = _scan(project, tmp_path / "b.json", "--report-only")
    assert code == 0


def test_hidden_include_fails_validate_and_risk(tmp_path):
    project = _project(
        tmp_path / "proj", {"requirements.txt": "-r more.txt\n", "more.txt": "openai==1.0.0\n"}
    )
    _scan(project, tmp_path / "a.json", "--report-only")
    runner = CliRunner()
    for command in ("validate", "risk"):
        result = runner.invoke(
            main,
            [command, str(tmp_path / "a.json"), "--project", str(project), "--no-project-policy"],
        )
        assert result.exit_code == 1, (command, result.output)


def test_include_gap_names_no_target(tmp_path):
    project = _project(
        tmp_path / "proj",
        {"requirements.txt": "openai==1.0.0\n-r https://alice:S3CR1@h.example/S3CR2/r.txt\n"},
    )
    for fmt in ("json", "cyclonedx", "spdx", "sarif"):
        out = tmp_path / f"out.{fmt}"
        result = CliRunner().invoke(
            main,
            ["scan", str(project), "--no-project-policy", "--report-only", "-f", fmt]
            + ["-o", str(out)],
        )
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8") + result.output
        assert "S3CR" not in text and "alice" not in text, fmt


def test_one_gap_per_file_and_option(tmp_path):
    project = _project(
        tmp_path,
        {"requirements.txt": "-r a.txt\n-r b.txt\n-c c.txt\n-r requirements-ml.txt\n"},
    )
    assert RegistryScanner().scan(project).surfaces_excluded == [
        "requirements.txt: requirements include not followed",
        "requirements.txt: constraints file not followed",
    ]


@pytest.mark.parametrize(
    "line",
    [
        "-r requirements.txt",
        "-r ./requirements.txt",
        "--requirement=.//requirements.txt",
        "-c requirements.txt",
        "-e .",
        "-e ./",
        "-e .[dev]",
        "-e file:.",
        "-e 'file:.[dev,test]'",
        "--index-url https://pypi.org/simple",
        "--extra-index-url https://${TOKEN}@h.example/simple --pre",
        "--hash=sha256:" + "0" * 64,
        "-- -r more.txt",
    ],
)
def test_options_that_add_nothing_unread_stay_complete(tmp_path, line):
    project = _project(
        tmp_path,
        {"requirements.txt": "openai==1.0.0\n", "requirements-dev.txt": f"﻿{line}\n"},
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    assert [c.name for c in result.components] == ["openai"]


def test_editable_file_url_is_not_the_project_when_a_directory_shadows_it(tmp_path):
    # pip installs an existing directory named "file:." rather than the project.
    project = _project(tmp_path, {"requirements.txt": "-e file:.\n"})
    try:
        (project / "file:.").mkdir()
    except OSError:
        pytest.skip("file system rejects the name")
    assert RegistryScanner().scan(project).surfaces_excluded == [
        "requirements.txt: editable install not followed"
    ]
