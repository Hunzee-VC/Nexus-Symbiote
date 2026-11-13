"""docs/cli-reference.md documents every command and option the CLI exposes."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from nexus_symbiote import modes
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM

REFERENCE = Path(__file__).resolve().parents[1] / "docs" / "cli-reference.md"


def _commands(
    command: click.Command, path: tuple[str, ...] = ()
) -> Iterator[tuple[str, click.Command]]:
    if isinstance(command, click.Group):
        context = click.Context(command)
        for name in command.list_commands(context):
            sub = command.get_command(context, name)
            assert sub is not None
            yield from _commands(sub, (*path, name))
    else:
        yield " ".join(path), command


def test_every_command_and_option_is_documented():
    text = REFERENCE.read_text(encoding="utf-8")
    missing = []
    for name, command in _commands(main):
        section = re.search(rf"^### `{re.escape(name)}`$(.*?)(?=^### |\Z)", text, re.M | re.S)
        if section is None:
            missing.append(name)
            continue
        for param in command.params:
            if isinstance(param, click.Option):
                missing.extend(
                    f"{name} {opt}" for opt in param.opts if f"`{opt}`" not in section.group(1)
                )
    for option in main.params:
        if isinstance(option, click.Option):
            missing.extend(opt for opt in option.opts if f"`{opt}`" not in text)
    assert not missing, f"undocumented in {REFERENCE.name}: {missing}"


def test_every_environment_variable_the_package_reads_is_documented():
    source = Path(__file__).resolve().parents[1] / "src" / "nexus_symbiote"
    names: set[str] = set()
    for path in source.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        names.update(re.findall(r"\b(NEXUS_SYMBIOTE_[A-Z_]+)", text))
        names.update(re.findall(r"environ(?:\.get\(|\[)[\"']([A-Z][A-Z0-9_]*)[\"']", text))
        names.update(re.findall(r"getenv\([\"']([A-Z][A-Z0-9_]*)[\"']", text))
    section = REFERENCE.read_text(encoding="utf-8").split("## Environment variables", 1)[1]
    section = section.split("\n## ", 1)[0]
    missing = sorted(name for name in names if name not in section)
    assert {"NEXUS_SYMBIOTE_MODE", "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", "NO_COLOR"} <= names
    assert not missing, f"environment variables missing from {REFERENCE.name}: {missing}"


def test_command_table_marks_exactly_the_live_commands():
    rows = re.findall(
        r"^\| \[`([^`]+)`\]\(#[^)]+\) \| (\*\*live\*\*|offline) \|", REFERENCE.read_text(), re.M
    )
    documented = {name for name, _ in _commands(main)}
    assert {name for name, _ in rows} == documented
    assert {name for name, mode in rows if mode == "**live**"} == set(modes.LIVE_COMMANDS)


@pytest.mark.parametrize(
    ("row", "arguments"),
    [
        ("validate --json-output", ["validate", "{bom}", "--no-project-policy"]),
        ("risk --json-output", ["risk", "{bom}", "--no-project-policy"]),
        ("summary --json-output", ["summary", "{bom}"]),
        ("diff --json-output", ["diff", "{bom}", "{bom}"]),
    ],
)
def test_json_document_rows_name_every_top_level_key(tmp_path, row, arguments):
    bom = tmp_path / "aibom.json"
    AIBOM().save(bom)
    result = CliRunner().invoke(
        main, [argument.format(bom=bom) for argument in arguments] + ["--json-output"]
    )
    document = json.loads(result.stdout)
    match = re.search(rf"^\| `{re.escape(row)}` \|(.*)$", REFERENCE.read_text(), re.M)
    assert match is not None
    assert sorted(key for key in document if f"`{key}`" not in match.group(1)) == []
