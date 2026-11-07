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


POETRY = '[tool.poetry]\nname = "agent"\nversion = "0.1.0"\n[tool.poetry.dependencies]\npython = "^3.11"\n'


def _poetry(root: Path, body: str) -> RegistryScanner:
    _project(root, {"pyproject.toml": POETRY + body})
    return RegistryScanner()


@pytest.mark.parametrize(
    ("constraint", "specifier"),
    [
        ("2.3.1", "==2.3.1"),
        ("=2.3.1", "==2.3.1"),
        ("2.3.*", "==2.3.*"),
        ("*", ""),
        ("", ""),
        ("^1.2.3", ">=1.2.3,<2"),
        ("^1.2", ">=1.2,<2"),
        ("^1", ">=1,<2"),
        ("^0.2.3", ">=0.2.3,<0.3"),
        ("^0.0.3", ">=0.0.3,<0.0.4"),
        ("^0.0", ">=0.0,<0.1"),
        ("^0", ">=0,<1"),
        ("~1.2.3", ">=1.2.3,<1.3"),
        ("~1.2", ">=1.2,<1.3"),
        ("~1", ">=1,<2"),
        ("~=2.3", "~=2.3"),
        (">= 2.3, < 3.0", ">= 2.3,< 3.0"),
        ("^2.3,!=2.4.1", ">=2.3,<3,!=2.4.1"),
        ("^2.3 || ^3.0", None),
        (">=1.2 <1.5", None),
        ("^1.0.0a1", None),
        ("^" + "9" * 70, None),
        ("https://h.example/t.whl", None),
    ],
)
def test_poetry_constraints_translate_to_pep440(constraint, specifier):
    from nexus_symbiote.scanners.registry import _poetry_specifier

    assert _poetry_specifier(constraint) == specifier


@pytest.mark.parametrize(
    "line", ['torch = "2.3.1"', 'torch = {version = "2.3.1", optional = true}']
)
def test_poetry_bare_version_is_an_exact_pin(tmp_path, line):
    result = _poetry(tmp_path, line + "\n").scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (component,) = result.components
    assert component.bom_ref == "registry:pypi/torch"
    assert component.package_url == "pkg:pypi/torch@2.3.1" and component.risks == []


@pytest.mark.parametrize(
    ("value", "version"),
    [('"^2.3"', "<3,>=2.3"), ('"^0.2.3"', "<0.3,>=0.2.3"), ('"~2.3"', "<2.4,>=2.3"), ('"*"', None)],
)
def test_poetry_caret_tilde_and_wildcard_are_not_failures(tmp_path, value, version):
    result = _poetry(tmp_path, f"torch = {value}\n").scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert [(c.bom_ref, c.version) for c in result.components] == [("registry:pypi/torch", version)]
    code, _ = _scan(tmp_path, tmp_path / "bom.json")
    assert code == 0


def test_poetry_sources_are_recorded_by_name_as_a_gap(tmp_path):
    body = (
        'torch = {git = "https://alice:S3CR1@github.com/pytorch/S3CR2.git", rev = "v2.3.1"}\n'
        'openai = {url = "https://alice:S3CR1@h.example/S3CR2/openai.whl"}\n'
        'langchain = {path = "../vendor/S3CR2", develop = true}\n'
        'tokenizers = [{version = "0.19.1", platform = "linux"}, {version = "0.19.0", platform = "darwin"}]\n'
    )
    project = tmp_path / "proj"
    result = _poetry(project, body).scan(project)
    assert result.scan_failures == []
    assert result.surfaces_excluded == [
        "pyproject.toml: Poetry git, path or URL dependency not translated"
    ]
    by_ref = {c.bom_ref: c for c in result.components}
    assert sorted(by_ref) == [
        "registry:pypi/langchain",
        "registry:pypi/openai",
        "registry:pypi/tokenizers",
        "registry:pypi/torch",
    ]
    assert by_ref["registry:pypi/torch"].package_url is None
    tokenizers = by_ref["registry:pypi/tokenizers"]
    assert tokenizers.version == '==0.19.1; sys_platform == "linux"'
    assert tokenizers.package_url is None
    for fmt in ("json", "cyclonedx", "spdx", "sarif"):
        out = tmp_path / f"out.{fmt}"
        scanned = CliRunner().invoke(
            main,
            ["scan", str(project), "--no-project-policy", "--report-only", "-f", fmt]
            + ["-o", str(out)],
        )
        assert scanned.exit_code == 0, scanned.output
        text = out.read_text(encoding="utf-8") + scanned.output
        assert "S3CR" not in text and "alice" not in text, fmt


def test_poetry_markers_do_not_become_an_unconditional_pin(tmp_path):
    body = 'torch = {version = "==2.3.1", markers = "sys_platform == \'linux\'"}\n'
    (component,) = _poetry(tmp_path, body).scan(tmp_path).components
    assert component.package_url is None
    assert "sys_platform" in component.version
    assert "sys_platform" in component.properties["requested_requirement"]


def test_poetry_groups_and_dev_dependencies_are_read(tmp_path):
    body = (
        'torch = "2.3.1"\n[tool.poetry.group.ml.dependencies]\ncohere = "5.5.0"\ntorch = "2.2.0"\n'
        '[tool.poetry.dev-dependencies]\nopenai = "1.30.1"\n'
    )
    result = _poetry(tmp_path, body).scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    by_name = {c.name: c for c in result.components}
    assert by_name["cohere"].package_url == "pkg:pypi/cohere@5.5.0"
    assert by_name["openai"].package_url == "pkg:pypi/openai@1.30.1"
    assert by_name["torch"].risks == []


@pytest.mark.parametrize(
    "line",
    ['torch = "^2.3 || ^3.0"', 'torch = {version = "2.3.1", python = "^3.11"}'],
)
def test_untranslatable_poetry_condition_is_partial(tmp_path, line):
    result = _poetry(tmp_path, line + "\n").scan(tmp_path)
    assert result.surfaces_excluded == [
        "pyproject.toml: Poetry dependency condition not translated"
    ]
    assert result.scan_failures == []
    assert [(c.bom_ref, c.package_url) for c in result.components] == [
        ("registry:pypi/torch", None)
    ]
    code, document = _scan(tmp_path, tmp_path / "bom.json")
    assert code == 1
    assert document["metadata"]["completeness"]["scanner_status"]["registry"] == "partial"


@pytest.mark.parametrize(
    "line",
    [
        'torch = "https://h.example/t.whl"',
        "torch = 5",
        'torch = {version = "2.3.1", markers = "((("}',
        '"torch==2" = "*"',
    ],
)
def test_invalid_poetry_dependency_is_a_failure_without_a_mangled_name(tmp_path, line):
    result = _poetry(tmp_path, line + "\n").scan(tmp_path)
    assert result.scan_failures == ["pyproject.toml: invalid or unsupported Poetry dependency"]
    assert {c.bom_ref for c in result.components} <= {"registry:pypi/torch"}


def test_poetry_python_key_is_not_a_package(tmp_path):
    result = _poetry(tmp_path, "").scan(tmp_path)
    assert result.components == [] and result.scan_failures == []


def test_poetry_pin_change_is_a_version_change(tmp_path):
    project = _project(tmp_path / "proj", {})
    runner = CliRunner()
    for version, out in (("2.3.1", "a.json"), ("2.3.2", "b.json")):
        (project / "pyproject.toml").write_text(POETRY + f'torch = "{version}"\n')
        _scan(project, tmp_path / out, "--report-only")
    diff = runner.invoke(
        main, ["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json"), "--fail-on-alert"]
    )
    assert diff.exit_code == 1, diff.output
    assert "==2.3.1 → ==2.3.2" in diff.output and "torch2" not in diff.output
