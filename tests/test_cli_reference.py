"""docs/cli-reference.md documents every command and option the CLI exposes."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import click

from nexus_symbiote import modes
from nexus_symbiote.cli import main

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


def test_command_table_marks_exactly_the_live_commands():
    rows = re.findall(
        r"^\| \[`([^`]+)`\]\(#[^)]+\) \| (\*\*live\*\*|offline) \|", REFERENCE.read_text(), re.M
    )
    documented = {name for name, _ in _commands(main)}
    assert {name for name, _ in rows} == documented
    assert {name for name, mode in rows if mode == "**live**"} == set(modes.LIVE_COMMANDS)
