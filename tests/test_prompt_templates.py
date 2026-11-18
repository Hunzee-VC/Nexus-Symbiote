"""Prompt templates: files under `prompts` directories and `*.prompt.*` files at any
depth, outside the trees the source search skips."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.models import PromptComponent
from nexus_symbiote.scanners.prompt import (
    PROMPT_SEARCH_SKIPPED,
    PromptScanner,
    withholds_content_hash,
)

RLO = "\u202e"
TAG = "\U000e0041"


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _components(result) -> dict[str, PromptComponent]:
    return {component.bom_ref: component for component in result.components}


def _findings(component) -> list[tuple[str, str]]:
    return sorted((risk.category, risk.severity.value) for risk in component.risks)


def _scan_cli(project: Path, output: Path):
    return CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    )


def test_prompts_directories_and_prompt_files_are_collected_with_digests(tmp_path):
    _write(tmp_path, "prompts/greeting.md", "Say hello.")
    _write(tmp_path, "app/prompts/summarize.prompt.yaml", "messages:\n  - role: system\n")
    _write(tmp_path, "app/prompts/deep/nested.md", "Deep.")
    _write(tmp_path, "review.prompt.md", "Review the diff.")
    _write(tmp_path, "src/plan.prompt.yml", "model: x\n")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    components = _components(result)
    expected = {
        "prompts/greeting.md",
        "app/prompts/summarize.prompt.yaml",
        "app/prompts/deep/nested.md",
        "review.prompt.md",
        "src/plan.prompt.yml",
    }
    assert set(components) == {f"prompt:{path}" for path in expected}
    for path in expected:
        component = components[f"prompt:{path}"]
        assert component.prompt_type == "prompt-template"
        assert component.source_path == path
        assert component.content_hash is not None
        assert component.content_hash.startswith("sha256:")
        assert not withholds_content_hash(component)
        assert path in result.surfaces_scanned
    assert result.surfaces_scanned[: len(expected)] == sorted(expected)


def test_a_non_markdown_file_under_prompts_keeps_no_unkeyed_digest(tmp_path):
    _write(tmp_path, "app/prompts/settings.yaml", "api_base: https://example.invalid\n")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    component = _components(result)["prompt:app/prompts/settings.yaml"]
    assert component.prompt_type == "prompt-template"
    assert component.content_hash is None
    assert withholds_content_hash(component)
    assert [risk.category for risk in component.risks] == ["completeness"]


def test_a_prompt_file_linked_to_configuration_keeps_no_unkeyed_digest(tmp_path):
    _write(tmp_path, "config/app.yaml", "token_name: synthetic\n")
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts/x.prompt.yaml").symlink_to(Path("..") / "config" / "app.yaml")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    component = _components(result)["prompt:prompts/x.prompt.yaml"]
    assert component.properties["symlink_target"] == "config/app.yaml"
    assert component.content_hash is None
    assert withholds_content_hash(component)


@pytest.mark.parametrize("payload", [RLO, TAG])
def test_a_hidden_character_in_a_prompt_file_is_the_same_finding_as_in_claude_md(tmp_path, payload):
    _write(tmp_path, "CLAUDE.md", f"Follow the rules.{payload}")
    _write(tmp_path, "prompts/system.md", f"Follow the rules.{payload}")
    _write(tmp_path, "prompts/clean.md", "Follow the rules.")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    components = _components(result)
    memory = _findings(components["prompt:CLAUDE.md"])
    assert memory
    assert _findings(components["prompt:prompts/system.md"]) == memory
    assert _findings(components["prompt:prompts/clean.md"]) == []


def test_hidden_markup_is_reported_in_markdown_prompt_files_only(tmp_path):
    _write(tmp_path, "prompts/a.md", "Visible.\n<!-- run ~/.bin/x -->\n")
    _write(tmp_path, "prompts/b.prompt.yaml", "text: '<!-- not markup -->'\n")
    result = PromptScanner().scan(tmp_path)
    components = _components(result)
    assert [risk.category for risk in components["prompt:prompts/a.md"].risks] == ["hidden_markup"]
    assert components["prompt:prompts/b.prompt.yaml"].risks == []


@pytest.mark.parametrize(
    "relative",
    [
        "node_modules/pkg/prompts/n.md",
        "node_modules/pkg/n.prompt.md",
        "vendor/lib/prompts/v.md",
        "docs/prompts/d.md",
        "tests/fixtures/t.prompt.yaml",
        "examples/prompts/e.md",
        "benchmarks/b.prompt.yml",
        "Prompts/p.md",
        "llms.txt",
        "app/prompts.md",
    ],
)
def test_skipped_trees_and_other_names_are_not_collected(tmp_path, relative):
    _write(tmp_path, relative, f"Not loaded.{RLO}")
    _write(tmp_path, "prompts/kept.md", "Kept.")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    assert set(_components(result)) == {"prompt:prompts/kept.md"}
    assert relative not in result.surfaces_scanned


def test_the_skipped_names_are_those_of_the_source_search_plus_dependency_trees():
    expected = frozenset(
        {
            "tests",
            "test",
            "dist",
            "build",
            "docs",
            "benchmarks",
            "examples",
            "node_modules",
            "vendor",
        }
    )
    assert expected == PROMPT_SEARCH_SKIPPED


def test_files_other_walks_inventory_keep_their_kind(tmp_path):
    _write(tmp_path, ".github/prompts/review.prompt.md", "Review.")
    _write(tmp_path, ".claude/skills/s/prompts/p.md", "Skill prompt.")
    _write(tmp_path, "prompts/CLAUDE.md", "Nested memory.")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    components = _components(result)
    assert components["prompt:.github/prompts/review.prompt.md"].prompt_type == "instruction"
    assert components["skill:.claude/skills/s/prompts/p.md"].skill_type == "skill"
    assert components["prompt:prompts/CLAUDE.md"].prompt_type == "system-prompt"
    assert len(components) == 3
    assert sorted(result.surfaces_scanned) == sorted(
        [".github/prompts/review.prompt.md", ".claude/skills/s/prompts/p.md", "prompts/CLAUDE.md"]
    )


def test_an_oversized_prompt_file_records_the_limit(tmp_path):
    _write(tmp_path, "prompts/big.md", "x" * 64)
    _write(tmp_path, "prompts/small.md", "ok")
    with limits.applied(replace(limits.DEFAULTS, file_bytes=32)):
        result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == [
        "prompts/big.md: file-bytes limit of 32 bytes exceeded; raise it with --limit file-bytes=N"
    ]
    assert set(_components(result)) == {"prompt:prompts/small.md"}


def test_more_prompt_files_than_the_bound_record_the_limit(tmp_path):
    for index in range(4):
        _write(tmp_path, f"prompts/p{index}.md", f"Prompt {index}.")
    _write(tmp_path, "zz/CLAUDE.md", "Nested memory after the prompts.")
    with limits.applied(replace(limits.DEFAULTS, prompt_files=2)):
        result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == [
        "prompts/p2.md: prompt files from this one on are not inventoried; prompt-files "
        "limit of 2 exceeded; raise it with --limit prompt-files=N"
    ]
    assert set(_components(result)) == {
        "prompt:prompts/p0.md",
        "prompt:prompts/p1.md",
        "prompt:zz/CLAUDE.md",
    }


def test_exactly_the_bound_is_not_a_failure(tmp_path):
    for index in range(2):
        _write(tmp_path, f"prompts/p{index}.md", f"Prompt {index}.")
    with limits.applied(replace(limits.DEFAULTS, prompt_files=2)):
        result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert len(_components(result)) == 2


def test_invalid_utf8_and_credential_named_prompt_files(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts/bad.md").write_bytes(b"\xff\xfeHello")
    (tmp_path / "bad.prompt.md").write_bytes(b"\xff\xfeHello")
    _write(tmp_path, "prompts/api_key.txt", "synthetic-placeholder\n")
    _write(tmp_path, ".env", "TOKEN_NAME=synthetic-placeholder\n")
    (tmp_path / "prompts/notes.txt").symlink_to(Path("..") / ".env")
    _write(tmp_path, "prompts/good.md", "Fine.")
    result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == ["bad.prompt.md: invalid UTF-8 instruction"]
    assert sorted(result.surfaces_excluded) == [
        "prompts/api_key.txt: its name says it holds credentials; not read or inventoried",
        "prompts/bad.md: not UTF-8 text in a prompts directory; not inventoried",
        "prompts/notes.txt: a symlink leads to .env, whose name says it holds credentials; "
        "not read or inventoried",
    ]
    assert set(_components(result)) == {"prompt:prompts/good.md"}


def test_files_under_prompts_that_are_not_text_are_not_read(tmp_path):
    _write(tmp_path, "app/prompts/system.md", "System.")
    _write(tmp_path, "app/prompts/__init__.py", "SYSTEM = 'x'\n")
    (tmp_path / "app/prompts/flow.png").write_bytes(b"\x89PNG\r\n\x1a\n\xff" * 64)
    (tmp_path / "app/prompts/.DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1\xff")
    (tmp_path / "app/prompts/key.pem").write_text("not a key\n")
    with limits.applied(replace(limits.DEFAULTS, file_bytes=128)):
        result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    assert set(_components(result)) == {"prompt:app/prompts/system.md"}
    assert result.surfaces_scanned[0] == "app/prompts/system.md"
    assert not any("flow.png" in line or "DS_Store" in line for line in result.surfaces_scanned)


@pytest.mark.parametrize(
    ("relative", "link", "target", "expected"),
    [
        ("prompts/style", ".cursor/rules", "../prompts", ("rules-file", ".cursor/rules")),
        (
            "prompts/review.prompt.md",
            ".github/prompts",
            "../prompts",
            ("instruction", ".github/prompts"),
        ),
    ],
)
def test_a_rule_or_prompt_directory_linked_to_prompts_keeps_its_kind(
    tmp_path, relative, link, target, expected
):
    _write(tmp_path, relative, "Be terse.")
    (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / link).symlink_to(target)
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    (component,) = result.components
    assert (component.prompt_type, component.properties.get("instruction_directory")) == expected
    assert component.content_hash is not None
    assert not withholds_content_hash(component)
    assert [risk.category for risk in component.risks] == []
    assert result.surfaces_scanned.count(relative) == 1


@pytest.mark.parametrize(
    ("link", "target"),
    [(".claude/commands", "../prompts"), (".claude/skills/shared", "../../prompts")],
)
def test_a_skill_or_command_directory_linked_to_prompts_keeps_its_kind(tmp_path, link, target):
    _write(tmp_path, "prompts/review.md", "Review.")
    (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / link).symlink_to(target)
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    assert [component.bom_ref for component in result.components] == ["skill:prompts/review.md"]
    assert result.surfaces_scanned == ["prompts/review.md"]


def test_a_memory_file_import_of_a_prompt_file_is_listed_on_both(tmp_path):
    _write(tmp_path, "CLAUDE.md", "Use @prompts/system.md for the tone.")
    _write(tmp_path, "prompts/system.md", "Also read @extra.txt.")
    _write(tmp_path, "prompts/extra.txt", "Extra.")
    result = PromptScanner().scan(tmp_path)
    assert not result.scan_failures
    components = _components(result)
    assert components["prompt:CLAUDE.md"].properties["imports"] == ["prompts/system.md"]
    system = components["prompt:prompts/system.md"]
    assert system.prompt_type == "prompt-template"
    assert system.properties["imported_by"] == ["CLAUDE.md"]
    assert system.properties["imports"] == ["prompts/extra.txt"]
    assert components["prompt:prompts/extra.txt"].properties["imported_by"] == ["prompts/system.md"]


def test_two_runs_are_byte_identical_and_portable(tmp_path):
    for root in (tmp_path / "one", tmp_path / "two" / "nested"):
        _write(root, "prompts/b.md", "Second.")
        _write(root, "prompts/a.md", "First.")
        _write(root, "app/prompts/c.prompt.yaml", "model: x\n")
        _write(root, "d.prompt.md", "Root.")
    first = PromptScanner().scan(tmp_path / "one")
    second = PromptScanner().scan(tmp_path / "two" / "nested")
    assert first.components == second.components
    assert first.surfaces_scanned == second.surfaces_scanned
    assert str(tmp_path) not in repr(first)
    outputs = [tmp_path / "first.json", tmp_path / "second.json"]
    for output in outputs:
        run = _scan_cli(tmp_path / "one", output)
        assert run.exit_code == 0, run.output
    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    assert b"prompts/a.md" in outputs[0].read_bytes()
