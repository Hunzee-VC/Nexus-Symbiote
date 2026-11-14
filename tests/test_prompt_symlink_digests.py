"""A file the prompt collector records whose bytes are not those of an instruction file,
whether a walk found it by name behind a symlink, in a rule or prompt directory, or an
@path import named it, carries no unkeyed content digest, so one inventory cannot
withhold the digest of a file under one name and publish it under another."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.scanners import prompt
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.scanners.source_binding import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.validators.integrity import IntegrityValidator

BINDING_KEY = "prompt-symlink-key-" + "0123456789abcdef" * 2
# A synthetic configuration line: nothing here is a real secret.
CONFIGURATION = "DB_URL=postgres://u:not-a-real-password-0007@db/x\n"


def _write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _link(root: Path, relative: str, target: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(os.path.relpath(root / target, path.parent))


def _components(result):
    return {component.bom_ref: component for component in result.components}


def _published(result) -> str:
    return AIBOM(components=result.components).to_json()


def _agents_linked_to_json(project: Path) -> None:
    _write(project, "config/app.json", CONFIGURATION)
    _link(project, "AGENTS.md", "config/app.json")
    _write(project, "CLAUDE.md", "@AGENTS.md @config/app.json\n")


def _nested_memory_linked_to_cfg(project: Path) -> None:
    _write(project, "sub/plain.cfg", CONFIGURATION)
    _link(project, "sub/CLAUDE.md", "sub/plain.cfg")


def _gemini_linked_to_a_rule(project: Path) -> None:
    _write(project, ".claude/rules/x.json", CONFIGURATION)
    _link(project, "GEMINI.md", ".claude/rules/x.json")


def _cursor_rule_json(project: Path) -> None:
    _write(project, ".cursor/rules/x.json", CONFIGURATION)


def _github_prompt_json(project: Path) -> None:
    _write(project, ".github/prompts/deploy.json", CONFIGURATION)


def _cursorrules_linked_to_txt(project: Path) -> None:
    _write(project, "config/app.txt", CONFIGURATION)
    _link(project, ".cursorrules", "config/app.txt")


# A symlink target named like an instruction file that has no Markdown suffix is still
# withheld: an @import of the same target is, so the walk must not publish its digest.
def _agents_linked_to_windsurfrules(project: Path) -> None:
    _write(project, "config/.windsurfrules", CONFIGURATION)
    _link(project, "AGENTS.md", "config/.windsurfrules")
    _write(project, "CLAUDE.md", "@AGENTS.md @config/.windsurfrules\n")


def _gemini_linked_to_system_prompt_txt(project: Path) -> None:
    _write(project, "config/system_prompt.txt", CONFIGURATION)
    _link(project, "GEMINI.md", "config/system_prompt.txt")
    _write(project, "CLAUDE.md", "@config/system_prompt.txt\n")


def _cursor_rule_linked_to_clinerules(project: Path) -> None:
    _write(project, "config/.clinerules", CONFIGURATION)
    _link(project, ".cursor/rules/a.mdc", "config/.clinerules")
    _write(project, "CLAUDE.md", "@config/.clinerules\n")


VARIANTS = [
    pytest.param(
        _agents_linked_to_json,
        ["prompt:AGENTS.md", "prompt:import:config/app.json"],
        id="agents-md-to-json-and-imported",
    ),
    pytest.param(_nested_memory_linked_to_cfg, ["prompt:sub/CLAUDE.md"], id="nested-claude-md"),
    pytest.param(
        _gemini_linked_to_a_rule,
        ["prompt:GEMINI.md", "prompt:.claude/rules/x.json"],
        id="gemini-md-to-rule-json",
    ),
    pytest.param(_cursor_rule_json, ["prompt:.cursor/rules/x.json"], id="cursor-rule-json"),
    pytest.param(
        _github_prompt_json, ["prompt:.github/prompts/deploy.json"], id="github-prompt-json"
    ),
    pytest.param(_cursorrules_linked_to_txt, ["prompt:.cursorrules"], id="cursorrules-to-txt"),
    pytest.param(
        _agents_linked_to_windsurfrules,
        ["prompt:AGENTS.md", "prompt:import:config/.windsurfrules"],
        id="agents-md-to-windsurfrules-and-imported",
    ),
    pytest.param(
        _gemini_linked_to_system_prompt_txt,
        ["prompt:GEMINI.md", "prompt:import:config/system_prompt.txt"],
        id="gemini-md-to-system-prompt-txt-and-imported",
    ),
    pytest.param(
        _cursor_rule_linked_to_clinerules,
        ["prompt:.cursor/rules/a.mdc", "prompt:import:config/.clinerules"],
        id="cursor-rule-to-clinerules-and-imported",
    ),
]


@pytest.mark.parametrize(("build", "refs"), VARIANTS)
def test_non_instruction_bytes_carry_no_unkeyed_digest(tmp_path, build, refs):
    project = tmp_path / "project"
    build(project)
    result = PromptScanner().scan(project)
    components = _components(result)
    assert hash_bytes(CONFIGURATION.encode()) not in _published(result)
    for ref in refs:
        component = components[ref]
        assert component.content_hash is None
        assert "content_hash_withheld" in component.properties
        assert prompt.withholds_content_hash(component)
        unbound = [risk for risk in component.risks if risk.category == "completeness"]
        assert [risk.severity.value for risk in unbound] == ["low"]
        assert "is not bound in this inventory" in unbound[0].detail
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert run.exit_code == 0, run.output
    assert hash_bytes(CONFIGURATION.encode()) not in output.read_text()


@pytest.mark.parametrize(("build", "refs"), VARIANTS)
def test_the_operator_key_binds_what_the_digest_does_not(tmp_path, monkeypatch, build, refs):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, BINDING_KEY)
    build(tmp_path)
    result = PromptScanner().scan(tmp_path)
    assert hash_bytes(CONFIGURATION.encode()) not in _published(result)
    components = _components(result)
    for ref in refs:
        component = components[ref]
        assert component.content_hash is None
        assert (
            component.properties["static_value_binding_profile"]
            == prompt.IMPORT_CONTENT_BINDING_PROFILE
        )
        assert not any(risk.category == "completeness" for risk in component.risks)
    report = IntegrityValidator().validate(AIBOM(components=result.components), tmp_path)
    assert report.status == "pass", report.issues
    assert report.hashes_unbound == 0


@pytest.mark.parametrize(("build", "refs"), VARIANTS)
def test_a_withheld_walk_digest_passes_project_validation(tmp_path, build, refs):
    project = tmp_path / "project"
    build(project)
    # A file whose digest validation verifies, so the inventory proves something.
    _write(project, "system_prompt.md", "# Project\n")
    bom = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(bom)])
    assert run.exit_code == 0, run.output
    run = CliRunner().invoke(
        main,
        ["validate", str(bom), "--project", str(project), "--no-project-policy", "--json-output"],
    )
    report = json.loads(run.output)
    assert run.exit_code == 0, run.output
    assert report["integrity"]["hashes_unbound"] == len(refs)
    unbound = {
        issue["component_ref"]
        for issue in report["integrity"]["issues"]
        if issue["category"] == "unbound_content"
    }
    assert unbound == set(refs)
    assert not any(
        "has no integrity hash" in issue["message"]
        for issue in report["completeness"]["issues"]
        if "message" in issue
    )


def test_a_withheld_digest_is_not_published_under_another_name(tmp_path):
    """The reviewer's repro: the import is withheld, and so is the file it links from."""
    _agents_linked_to_json(tmp_path)
    components = _components(PromptScanner().scan(tmp_path))
    assert components["prompt:AGENTS.md"].properties["symlink_target"] == "config/app.json"
    assert components["prompt:AGENTS.md"].content_hash is None
    assert components["prompt:import:config/app.json"].content_hash is None


def test_instruction_files_keep_their_digests(tmp_path):
    files = {
        "CLAUDE.md": "# Project\n",
        "docs/agents.md": "# Agents\n",
        ".cursor/rules/x.mdc": "---\nalwaysApply: true\n---\nUse tabs.\n",
        ".github/prompts/deploy.prompt.md": "Deploy carefully.\n",
        ".clinerules/style.md": "Use spaces.\n",
        ".claude/rules/style": "Prefer small diffs.\n",
        "pkg/.cursorrules": "Be brief.\n",
        "system_prompt.txt": "You are helpful.\n",
    }
    for name, content in files.items():
        _write(tmp_path, name, content)
    _link(tmp_path, "AGENTS.md", "docs/agents.md")
    components = _components(PromptScanner().scan(tmp_path))
    expected = {
        "prompt:CLAUDE.md": files["CLAUDE.md"],
        "prompt:AGENTS.md": files["docs/agents.md"],
        "prompt:pkg/.cursorrules": files["pkg/.cursorrules"],
        "prompt:system_prompt.txt": files["system_prompt.txt"],
        "prompt:.cursor/rules/x.mdc": files[".cursor/rules/x.mdc"],
        "prompt:.github/prompts/deploy.prompt.md": files[".github/prompts/deploy.prompt.md"],
        "prompt:.clinerules/style.md": files[".clinerules/style.md"],
        "prompt:.claude/rules/style": files[".claude/rules/style"],
    }
    for ref, content in expected.items():
        component = components[ref]
        assert component.content_hash == hash_bytes(content.encode()), ref
        assert "content_hash_withheld" not in component.properties
        assert not any(risk.category == "completeness" for risk in component.risks)


def test_a_claimed_withholding_on_an_instruction_file_is_missing_evidence(tmp_path):
    _write(tmp_path, ".cursor/rules/x.mdc", "Use tabs.\n")
    _write(tmp_path, "pkg/.cursorrules", "Be brief.\n")
    components = PromptScanner().scan(tmp_path).components
    for component in components:
        component.content_hash = None
        component.properties["content_hash_withheld"] = "claimed by the inventory"
        assert not prompt.withholds_content_hash(component)
    report = IntegrityValidator().validate(AIBOM(components=components), tmp_path)
    assert report.status == "unknown"
    assert report.hashes_unbound == 0


def test_a_symlink_keeps_its_digest_only_when_its_target_is_markdown(tmp_path):
    """A target named like an instruction file is not enough: an @import of that target
    is withheld, so the file linked to it is too. A nested ``.cursorrules`` a walk finds
    under its own name keeps its digest there."""
    _write(tmp_path, "shared/.cursorrules", "Be terse.\n")
    _link(tmp_path, ".cursorrules", "shared/.cursorrules")
    components = _components(PromptScanner().scan(tmp_path))
    linked = components["prompt:.cursorrules"]
    assert linked.properties["symlink_target"] == "shared/.cursorrules"
    assert linked.content_hash is None
    assert prompt.withholds_content_hash(linked)
    assert components["prompt:shared/.cursorrules"].content_hash == hash_bytes(b"Be terse.\n")


def test_a_suffixless_rule_reached_through_a_directory_symlink_keeps_its_digest(tmp_path):
    """The walk records the file under the path it resolves to, outside the rule
    directory; it is still a rule file of that directory, which the collector reads as
    Markdown, and project validation agrees."""
    _write(tmp_path, "shared/r/style", "Use tabs.\n")
    _write(tmp_path, "shared/r/x.json", CONFIGURATION)
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor/rules").symlink_to("../shared/r")
    result = PromptScanner().scan(tmp_path)
    components = _components(result)
    style = components["prompt:shared/r/style"]
    assert style.content_hash == hash_bytes(b"Use tabs.\n")
    assert style.properties["instruction_directory"] == ".cursor/rules"
    assert not prompt.withholds_content_hash(style)
    assert components["prompt:shared/r/x.json"].content_hash is None
    assert hash_bytes(CONFIGURATION.encode()) not in _published(result)
    report = IntegrityValidator().validate(AIBOM(components=result.components), tmp_path)
    assert report.hashes_failed == 0, report.issues


def test_a_changed_withheld_file_names_the_prompt_file_in_the_keyed_mismatch(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, BINDING_KEY)
    _write(tmp_path, ".clinerules/style.txt", "Use tabs.\n")
    components = PromptScanner().scan(tmp_path).components
    _write(tmp_path, ".clinerules/style.txt", "Use spaces.\n")
    report = IntegrityValidator().validate(AIBOM(components=components), tmp_path)
    assert report.hashes_failed == 1
    assert [issue.detail for issue in report.issues if issue.category == "hash_mismatch"] == [
        "Keyed content binding mismatch against the prompt file"
    ]


def test_a_skill_resource_linked_to_an_imported_file_keeps_its_documented_digest(tmp_path):
    """Skill and command files are resources bound by digest whatever their names; the
    release notes and guides must not promise that every recorded file is withheld."""
    _write(tmp_path, "config/app.json", CONFIGURATION)
    _write(tmp_path, "CLAUDE.md", "@config/app.json\n")
    _link(tmp_path, ".claude/skills/x/app.json", "config/app.json")
    components = _components(PromptScanner().scan(tmp_path))
    assert components["prompt:import:config/app.json"].content_hash is None
    skill = components["skill:.claude/skills/x/app.json"]
    assert skill.hashes["sha256"] == hash_bytes(CONFIGURATION.encode())
    root = Path(__file__).resolve().parents[1]
    for document in ("CHANGELOG.md", "docs/known-limitations.md"):
        text = " ".join((root / document).read_text(encoding="utf-8").split())
        assert "`.claude/skills/x/app.json` linked to `config/app.json`" in text, document
