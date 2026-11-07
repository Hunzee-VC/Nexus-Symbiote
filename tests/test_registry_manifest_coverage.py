"""Manifest forms the registry collector cannot read are coverage gaps, not silence."""

from __future__ import annotations

import json
import time
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


@pytest.mark.parametrize(
    ("dockerfile", "image", "risk"),
    [
        (
            "FROM --platform=linux/amd64 ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        (
            "ARG BUILDPLATFORM\nFROM --platform=$BUILDPLATFORM ollama/ollama:0.1.0 AS builder\n"
            "FROM builder\n",
            "ollama/ollama:0.1.0",
            "mutable_image_tag",
        ),
        ("from ollama/ollama:latest\n", "ollama/ollama:latest", "version_pinning"),
        ("FROM \\\n  ollama/ollama:latest\n", "ollama/ollama:latest", "version_pinning"),
        ("FROM ollama/\\\n# note\n\nollama:0.5.7\n", "ollama/ollama:0.5.7", "mutable_image_tag"),
        (
            "﻿# syntax=docker/dockerfile:1\nFrom   ollama/ollama:0.5.7\n",
            "ollama/ollama:0.5.7",
            "mutable_image_tag",
        ),
    ],
)
def test_dockerfile_from_forms_name_the_image(tmp_path, dockerfile, image, risk):
    (tmp_path / "Dockerfile").write_text(dockerfile)
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    assert [(c.bom_ref, [r.category for r in c.risks]) for c in result.components] == [
        (f"registry:docker/{image}", [risk])
    ]


def test_stage_reference_is_not_an_image(tmp_path):
    (tmp_path / "Dockerfile.agent").write_text(
        "FROM python:3.12-slim AS Model-Builder\nRUN pip install vllm\nFROM model-builder\n"
        "FROM --platform=linux/arm64 vllm/vllm-openai:v0.4.0 AS serve\n"
    )
    assert [c.bom_ref for c in RegistryScanner().scan(tmp_path).components] == [
        "registry:docker/vllm/vllm-openai:v0.4.0"
    ]


def test_text_outside_a_from_instruction_is_not_an_image(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n# FROM ollama/ollama:1\nRUN echo FROM ollama/ollama:2\n"
        "LABEL image: ollama/ollama:3\n"
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.components == [] and result.surfaces_excluded == []


@pytest.mark.parametrize(
    ("dockerfile", "gap", "collected"),
    [
        (
            "ARG BASE=ollama/ollama:0.1.0\nFROM $BASE\n",
            "FROM image with an unresolved substitution not collected",
            [],
        ),
        (
            "ARG V=0.1.0\nFROM ollama/ollama:${V}\n",
            "FROM image with an unresolved substitution not collected",
            ["ollama/ollama:${V}"],
        ),
        ("FROM --platform=linux/amd64\n", "FROM instruction not parsed", []),
        ('FROM --platform="linux/amd64 x" ollama/ollama:1\n', "FROM instruction not parsed", []),
        ("# escape=`\nFROM ollama/ollama:latest\n", "escape parser directive not followed", []),
    ],
)
def test_unresolved_from_is_partial(tmp_path, dockerfile, gap, collected):
    (tmp_path / "Dockerfile").write_text(dockerfile)
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == [f"Dockerfile: {gap}"]
    assert [c.name for c in result.components] == collected
    out = tmp_path / "bom.json"
    scanned = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(out)]
    )
    assert scanned.exit_code == 1, scanned.output
    status = json.loads(out.read_text())["metadata"]["completeness"]["scanner_status"]
    assert status["registry"] == "partial"


def test_tag_change_behind_a_from_flag_is_drift(tmp_path):
    project = _project(tmp_path / "proj", {})
    dockerfile = project / "Dockerfile"
    runner = CliRunner()
    for tag, out in (("0.1.0", "a.json"), ("0.5.7", "b.json")):
        dockerfile.write_text(f"FROM --platform=linux/amd64 ollama/ollama:{tag}\n")
        scanned = runner.invoke(
            main,
            ["scan", str(project), "--no-project-policy", "--report-only"]
            + ["-o", str(tmp_path / out)],
        )
        assert scanned.exit_code == 0, scanned.output
    diff = runner.invoke(
        main, ["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json"), "--fail-on-alert"]
    )
    assert diff.exit_code == 1, diff.output
    assert "ollama/ollama:0.5.7" in diff.output


def test_dockerfile_parsing_is_linear(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM" + " " * 4_000_000)
    (tmp_path / "Dockerfile.agent").write_text("FROM a AS b \\\n" * 300_000 + "RUN x\n")
    started = time.monotonic()
    result = RegistryScanner().scan(tmp_path)
    assert time.monotonic() - started < 5
    assert result.surfaces_excluded == ["Dockerfile: FROM instruction not parsed"]
