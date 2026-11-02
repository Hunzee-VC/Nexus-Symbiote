"""The committed CLI reference must equal the page rendered from the command tree."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "generate_cli_reference.py"
PAGE = ROOT / "docs" / "reference" / "cli.md"


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_cli_reference", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_reference_matches_rendered_commands(generator: ModuleType) -> None:
    assert PAGE.read_text(encoding="utf-8") == generator.render()


def test_rendered_page_covers_every_command(generator: ModuleType) -> None:
    rendered = generator.render()
    for heading in (
        "## `nexus-symbiote`",
        "## `nexus-symbiote scan`",
        "## `nexus-symbiote runtime`",
        "## `nexus-symbiote runtime verify`",
        "## `nexus-symbiote verify-live`",
    ):
        assert heading in rendered
    assert "Usage: nexus-symbiote scan [OPTIONS] [PROJECT_PATH]" in rendered


def test_check_mode_reports_stale_page(
    generator: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    page = tmp_path / "cli.md"
    page.write_text("# stale\n", encoding="utf-8")
    assert generator.main(["--check", "--output", str(page)]) == 1
    captured = capsys.readouterr().out
    assert "-# stale" in captured and "+# CLI reference" in captured
    assert generator.main(["--write", "--output", str(page)]) == 0
    assert generator.main(["--check", "--output", str(page)]) == 0
    assert page.read_text(encoding="utf-8") == generator.render()
