"""The README collector table names every path these collectors read."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_symbiote.scanners.a2a import A2A_CONFIG_FILES, AGENT_CARD_NAMES
from nexus_symbiote.scanners.prompt import (
    INSTRUCTION_DIRECTORIES,
    INSTRUCTION_FILES,
    SKILL_DIRECTORIES,
)
from nexus_symbiote.scanners.rag import ENV_FILES, RAG_CONFIG_PATTERNS

README = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")


def _row(collector: str) -> str:
    return next(line for line in README.splitlines() if line.startswith(f"| `{collector}` |"))


@pytest.mark.parametrize(
    ("collector", "paths"),
    [
        ("prompt", [*INSTRUCTION_FILES, *INSTRUCTION_DIRECTORIES, *SKILL_DIRECTORIES]),
        ("rag", [*RAG_CONFIG_PATTERNS, *ENV_FILES]),
        ("a2a", [*A2A_CONFIG_FILES, *AGENT_CARD_NAMES, "a2a/agent.json"]),
        ("ide_agents", [".codex/config.toml", ".vscode/extensions.json"]),
    ],
)
def test_readme_row_names_every_collected_path(collector, paths):
    row = _row(collector)
    missing = [path for path in paths if f"`{path}`" not in row]
    assert not missing, f"README `{collector}` row omits {missing}"
