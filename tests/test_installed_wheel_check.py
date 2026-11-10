"""scripts/check_installed_wheel.py: the published-range smoke reaches parsers, exports and gates."""

from __future__ import annotations

import shutil

from tests.support import ROOT, load_script

smoke = load_script("check_installed_wheel")


def test_the_demo_agent_with_a_typescript_server_is_inventoried_and_scored(tmp_path):
    assert smoke.exercise(ROOT, tmp_path, formats=("json", "cyclonedx")) == []


def test_a_fixture_whose_typescript_tools_are_lost_fails_the_smoke(tmp_path):
    source = tmp_path / "source"
    shutil.copytree(ROOT / "examples", source / "examples")
    fixture = source / smoke.TYPESCRIPT_FIXTURE
    fixture.parent.mkdir(parents=True)
    fixture.write_text("export const nothing = 1;\n")
    work = tmp_path / "work"
    work.mkdir()
    problems = smoke.exercise(source, work, formats=("json",))
    assert problems == ["the TypeScript MCP tools were not inventoried"]
