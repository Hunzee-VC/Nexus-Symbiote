"""Case variants of default-excluded names inside agent directories are named gaps.

`ConfinedCollection.excluded` treats `VENV`, `Node_Modules` and `.GIT` like `venv`,
`node_modules` and `.git`, as a case-insensitive file system does. The walk reported a
skipped entry only when its name was spelled exactly, so a skill under
`.claude/skills/VENV/` was left out with no gap and no failure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.graph import assemble_repository_agent
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.utils.confined import ConfinedCollection

GAP = "default-excluded name inside an agent configuration directory; not collected"
VARIANTS = ["VENV", "Venv", ".VENV", "Node_Modules", "NODE_MODULES", ".GIT", "__PyCache__", "venv."]


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.mark.parametrize("name", VARIANTS)
@pytest.mark.parametrize("directory", [".claude/skills", ".claude/rules", ".claude/agents"])
def test_a_case_variant_of_an_excluded_name_in_an_agent_directory_is_a_named_gap(
    tmp_path, directory, name
):
    _write(tmp_path, f"{directory}/{name}/deploy/SKILL.md", "Run it.")
    _write(tmp_path, f"{directory}/reviewed.md", "Reviewed.")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert result.surfaces_excluded == [f"{directory}/{name}: {GAP}"]
    assert not any(f"/{name}/" in component.bom_ref for component in result.components)


@pytest.mark.parametrize("name", VARIANTS)
def test_a_walk_lists_the_case_variant_it_skipped(tmp_path, name):
    _write(tmp_path, f"skills/{name}/SKILL.md", "Run it.")
    _write(tmp_path, "skills/kept/SKILL.md", "Kept.")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        skipped: list[Path] = []
        walked = list(files.iter_files("skills", skipped=skipped))
    assert not failures
    assert walked == [Path("skills/kept/SKILL.md")]
    assert skipped == [Path("skills") / name]


def test_a_name_excluded_by_policy_is_not_listed_as_a_default_exclusion(tmp_path):
    _write(tmp_path, "skills/vendor/SKILL.md", "Run it.")
    with ConfinedCollection(tmp_path, [], exclude_paths=["skills/vendor"]) as files:
        skipped: list[Path] = []
        assert list(files.iter_files("skills", skipped=skipped)) == []
    assert skipped == []


@pytest.mark.parametrize("entry", ["Node_Modules/pkg/AGENTS.md", ".GIT/notes.md", "VENV/AGENTS.md"])
def test_a_manifest_entry_under_a_case_variant_is_a_recorded_failure(tmp_path, entry):
    _write(tmp_path, entry, "Run it.")
    _write(tmp_path, "valid.md", "valid instruction\n")
    _write(tmp_path, "agent.yaml", f"name: demo\ninstructions: [valid.md, {entry}]\n")
    failures: list[str] = []
    assemble_repository_agent(AIBOM(), tmp_path, failures=failures)
    assert failures == [
        "agent.yaml#/instructions/1: names a path inside a directory that collection never reads"
    ]
