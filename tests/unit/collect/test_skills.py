"""skills collector: Agent Skills directories, frontmatter rules, scripts, lint facts and fail-closed digests."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from symbiote.collect import skills as mod
from symbiote.collect.base import CollectContext, CollectionResult, load_collectors, run_collectors
from symbiote.collect.instructions import FileFacts, FrontmatterSanitizer, InstructionsCollector
from symbiote.collect.skills import (
    MAX_DESCRIPTION_LENGTH,
    TEXT_SCAN_MAX_BYTES,
    SkillsCollector,
    find_skill_dirs,
    referenced_servers,
    script_ref,
    shebang_interpreter,
    skill_frontmatter,
    validate_frontmatter,
)
from symbiote.digest import build_dir_manifest
from symbiote.model import AgentBOM, Producer, Snapshot
from symbiote.model.entities import Agent, Instruction, ManifestItem, PromptTemplate, Skill
from symbiote.model.enums import (
    AgentRole,
    CollectorStatus,
    CoverageStatus,
    EdgeType,
    InstructionKind,
    LineEndings,
    SnapshotKind,
    Surface,
)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
D = "sha256:" + "ab" * 32
# Obviously fake credential shapes: flagged, never echoed.
GH_PAT = "ghp_" + "Z" * 36
AWS_KEY = "AKIA" + "Q" * 16
OPENAI_KEY = "sk-" + "x" * 24
ZWSP, RLO = "\u200b", "\u202e"
DIGEST = "sha256:" + "0" * 64

PDF_SKILL_MD = (
    "---\n"
    "name: pdf-tools\n"
    "description: Extract text and tables from PDF files.\n"
    "license: Apache-2.0\n"
    "compatibility: Requires python3 and poppler\n"
    'metadata:\n  author: example-org\n  version: "1.0"\n  nested: {a: 1}\n'
    "allowed-tools: Read Bash(python3 scripts/extract.py:*) WebFetch\n"
    "---\n"
    "# PDF tools\nCall mcp__github__create_issue to file bugs; mcp__slack posts updates.\n"
)

PROJECT: dict[str, str | bytes] = {
    ".claude/skills/pdf-tools/SKILL.md": PDF_SKILL_MD,
    ".claude/skills/pdf-tools/scripts/extract.py": "#!/usr/bin/env python3\nprint('x')\n",
    ".claude/skills/pdf-tools/scripts/run.sh": "echo run\n",
    ".claude/skills/pdf-tools/bin/tool": "#!/bin/bash\necho hi\n",
    ".claude/skills/pdf-tools/bin/native": b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
    ".claude/skills/pdf-tools/bin/tool.exe": b"MZ\x90\x00\x03",
    ".claude/skills/pdf-tools/references/REFERENCE.md": "Reference docs\n",
    ".claude/skills/pdf-tools/assets/logo.png": b"\x89PNG\r\n\x1a\n\x00\x00",
    ".claude/skills/list-tools/SKILL.md": "---\nname: list-tools\ndescription: d\nallowed-tools:\n  - Write\n  - Edit\n---\n",
    ".claude/skills/secrets/SKILL.md": "---\nname: secrets\ndescription: d\n---\nUses config.\n",
    ".claude/skills/secrets/config.txt": f"aws_access_key_id = {AWS_KEY}\n",
    ".claude/skills/hidden/SKILL.md": f"---\nname: hidden\ndescription: d\n---\nIgnore{ZWSP} this.\n",
    ".claude/skills/hidden-ref/SKILL.md": "---\nname: hidden-ref\ndescription: d\n---\nSee references.\n",
    ".claude/skills/hidden-ref/references/notes.md": f"notes{RLO}\n",
    ".claude/skills/badyaml/SKILL.md": "---\nname: [unclosed\n---\nBody.\n",
    ".claude/skills/secret-fm/SKILL.md": (
        f"---\nname: secret-fm\ndescription: d\nlicense: {OPENAI_KEY}\nmetadata:\n  token: {GH_PAT}\n  team: core\n---\n"
    ),
    "skills/Bad_Name/SKILL.md": "---\nname: Bad_Name\n---\nNo description.\n",
    "skills/category/nested-skill/SKILL.md": "---\nname: nested-skill\ndescription: d\n---\n",
    "skills/outer/SKILL.md": "---\nname: outer\ndescription: d\n---\n",
    "skills/outer/inner/SKILL.md": "---\nname: inner\ndescription: d\n---\n",
    ".agents/skills/mismatch/SKILL.md": "---\nname: other-name\ndescription: d\n---\n",
    ".github/skills/verbose/SKILL.md": (
        f"---\nname: verbose\ndescription: {'d' * 1500}\ncompatibility: {'c' * 600}\n---\n"
    ),
    ".codex/skills/nofm/SKILL.md": "Just text, no frontmatter.\n",
    "plugins/acme/.claude-plugin/plugin.json": json.dumps({"name": "acme"}),
    "plugins/acme/skills/deploy/SKILL.md": "---\nname: deploy\ndescription: Deploy.\n---\n",
    "node_modules/pkg/.claude-plugin/plugin.json": "{}",
    "node_modules/pkg/skills/vendored/SKILL.md": "---\nname: vendored\ndescription: d\n---\n",
    ".claude/skills/linky/SKILL.md": "---\nname: linky\ndescription: d\n---\n",
}
HOME: dict[str, str | bytes] = {
    ".claude/skills/pdf-tools/SKILL.md": "---\nname: pdf-tools\ndescription: Personal copy.\n---\n",
    "src/skills/linked/SKILL.md": "---\nname: linked\ndescription: d\n---\n",
    ".codex/skills/codex-skill/SKILL.md": "---\nname: codex-skill\ndescription: d\n---\n",
}

EXPECTED_PROJECT_SKILLS = {
    ".agents/skills/mismatch",
    ".claude/skills/badyaml",
    ".claude/skills/hidden",
    ".claude/skills/hidden-ref",
    ".claude/skills/list-tools",
    ".claude/skills/pdf-tools",
    ".claude/skills/secret-fm",
    ".claude/skills/secrets",
    ".codex/skills/nofm",
    ".github/skills/verbose",
    "plugins/acme/skills/deploy",
    "skills/Bad_Name",
    "skills/category/nested-skill",
    "skills/outer",
}


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return path


def _populate(base: Path, files: dict[str, str | bytes]) -> None:
    for rel, content in files.items():
        _write(base / rel, content)


@pytest.fixture
def scene(tmp_path: Path) -> tuple[Path, Path]:
    repo, home = tmp_path / "repo", tmp_path / "home"
    _populate(repo, PROJECT)
    os.chmod(repo / ".claude/skills/pdf-tools/bin/tool", 0o755)
    os.symlink("../pdf-tools/references", repo / ".claude/skills/linky/data")  # makes linky undigestable
    _populate(home, HOME)
    os.symlink(home / "src/skills/linked", home / ".claude/skills/linked")
    return repo, home


def _run(
    root: Path, home: Path | None = None, collector: SkillsCollector | None = None, **kw: Any
) -> CollectionResult:
    ctx = CollectContext(root=root, home=home, platform="linux", agent_id="agent:triage", now=NOW, **kw)
    result = run_collectors(ctx, [collector or SkillsCollector()])[0]
    assert result.status is CollectorStatus.OK, result.reason
    return result


def _skills(result: CollectionResult) -> dict[str, Skill]:
    return {e.path: e for e in result.entities if isinstance(e, Skill)}


def _instructions(result: CollectionResult) -> dict[str, Instruction]:
    return {e.id: e for e in result.entities if isinstance(e, Instruction)}


def _failed(result: CollectionResult) -> dict[str, str | None]:
    return {
        s.locator or s.source: s.error_class
        for s in result.coverage[Surface.INSTRUCTIONS].sources
        if not s.ok
    }


def _dump(result: CollectionResult) -> str:
    return json.dumps(
        [e.to_json_dict() for e in result.entities]
        + [e.to_json_dict() for e in result.edges]
        + [r.model_dump(mode="json") for r in result.redactions]
        + [result.coverage[Surface.INSTRUCTIONS].model_dump(mode="json")]
        + result.warnings
    )


# --------------------------------------------------------------------------------------------- inventory & identity


def test_inventory_digests_and_skill_md_instruction(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    result = _run(repo)
    skills = _skills(result)
    assert set(skills) == EXPECTED_PROJECT_SKILLS
    pdf = skills[".claude/skills/pdf-tools"]
    manifest = build_dir_manifest(repo / ".claude/skills/pdf-tools")
    assert pdf.id == "skill:claude-skills-pdf-tools"
    assert pdf.digest == manifest.root == pdf.manifest.root
    assert pdf.manifest == manifest
    assert pdf.name == "pdf-tools" and pdf.description == "Extract text and tables from PDF files."
    assert pdf.provenance.locator == ".claude/skills/pdf-tools/SKILL.md"
    assert pdf.provenance.collector == "collector:skills@0.1.0"
    md = _instructions(result)[pdf.skill_md_ref or ""]
    assert md.id == "instr:claude-skills-pdf-tools-skill.md"
    assert md.instruction_kind is InstructionKind.SKILL_MD
    assert md.path == ".claude/skills/pdf-tools/SKILL.md" and md.name == "SKILL.md"
    assert md.digest == "sha256:" + hashlib.sha256(PDF_SKILL_MD.encode()).hexdigest()
    assert md.precedence == 2 and md.line_endings is LineEndings.LF and md.media_type == "text/markdown"
    assert (
        md.frontmatter is not None
        and md.frontmatter["name"] == "pdf-tools"
        and "metadata" not in md.frontmatter
    )
    assert md.loads_remote is not None and md.loads_remote.value == []
    ids = [e.id for e in result.entities]
    assert len(ids) == len(set(ids))
    assert len([e for e in result.entities if isinstance(e, Instruction)]) == len(skills)


def test_frontmatter_fields_and_capabilities(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    skills = _skills(_run(repo))
    pdf = skills[".claude/skills/pdf-tools"]
    fm = pdf.frontmatter
    assert fm.name == "pdf-tools" and fm.license == "Apache-2.0"
    assert fm.compatibility == "Requires python3 and poppler"
    assert fm.allowed_tools == ["Read", "Bash(python3 scripts/extract.py:*)", "WebFetch"]
    assert fm.metadata == {"author": "example-org", "version": "1.0"}  # nested maps are dropped
    assert {"capability:execute", "capability:network-egress"} <= set(pdf.tags)
    assert "capability:write" not in pdf.tags
    listed = skills[".claude/skills/list-tools"]
    assert listed.frontmatter.allowed_tools == ["Write", "Edit"] and "capability:write" in listed.tags
    assert pdf.name_matches_directory and not any(t.startswith(("invalid-", "missing-")) for t in pdf.tags)


@pytest.mark.parametrize(
    ("path", "tags", "matches"),
    [
        ("skills/Bad_Name", {"invalid-name", "missing-description"}, True),
        (".agents/skills/mismatch", set(), False),
        (".github/skills/verbose", {"description-too-long", "compatibility-too-long"}, True),
        (".codex/skills/nofm", {"missing-frontmatter", "missing-name", "missing-description"}, False),
        (".claude/skills/badyaml", {"invalid-frontmatter", "missing-name", "missing-description"}, False),
    ],
)
def test_frontmatter_rule_violations(
    scene: tuple[Path, Path], path: str, tags: set[str], matches: bool
) -> None:
    repo, _ = scene
    skill = _skills(_run(repo))[path]
    problems = {t for t in skill.tags if t.startswith(("invalid-", "missing-")) or t.endswith("-too-long")}
    assert problems == tags
    assert skill.name_matches_directory is matches


def test_names_fall_back_to_the_directory(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    skills = _skills(_run(repo))
    assert skills[".codex/skills/nofm"].name == "nofm"
    assert skills[".agents/skills/mismatch"].name == "other-name"
    verbose = skills[".github/skills/verbose"]
    assert verbose.frontmatter.description is not None and len(verbose.frontmatter.description) == 1500


def test_scripts_and_interpreters(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    pdf = _skills(_run(repo))[".claude/skills/pdf-tools"]
    manifest = {i.name: i.digest for i in pdf.manifest.resources}
    assert {s.path: s.interpreter for s in pdf.scripts} == {
        "bin/native": "native",
        "bin/tool": "bash",
        "bin/tool.exe": "native",
        "scripts/extract.py": "python3",
        "scripts/run.sh": "sh",
    }
    assert all(s.digest == manifest[s.path] for s in pdf.scripts)
    assert pdf.has_scripts
    plain = _skills(_run(repo))[".claude/skills/list-tools"]
    assert plain.scripts == [] and not plain.has_scripts


def test_referenced_servers(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    skills = _skills(_run(repo))
    assert skills[".claude/skills/pdf-tools"].referenced_servers == ["github", "slack"]
    assert skills[".claude/skills/list-tools"].referenced_servers == []


def test_hidden_unicode_and_secrets_flagged_never_echoed(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    result = _run(repo)
    skills = _skills(result)
    instructions = _instructions(result)
    hidden = skills[".claude/skills/hidden"]
    assert "hidden-unicode" in hidden.tags
    assert "hidden-unicode" in instructions[hidden.skill_md_ref or ""].tags
    ref = skills[".claude/skills/hidden-ref"]
    assert "hidden-unicode" in ref.tags  # hidden text in a reference file the agent may load
    assert "hidden-unicode" not in instructions[ref.skill_md_ref or ""].tags
    secrets = skills[".claude/skills/secrets"]
    assert "secret-like" in secrets.tags
    assert not instructions[secrets.skill_md_ref or ""].contains_secret_like
    assert "secret-like" not in skills[".claude/skills/pdf-tools"].tags  # binary assets are not text-scanned
    dump = _dump(result)
    for secret in (AWS_KEY, GH_PAT, OPENAI_KEY):
        assert secret not in dump
    assert "Reference docs" not in dump and "Uses config." not in dump


def test_frontmatter_secrets_dropped_and_redacted(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    result = _run(repo)
    skill = _skills(result)[".claude/skills/secret-fm"]
    assert skill.frontmatter.license is None
    assert skill.frontmatter.metadata == {"team": "core"}
    md = _instructions(result)[skill.skill_md_ref or ""]
    assert md.frontmatter == {"name": "secret-fm", "description": "d"}
    assert md.contains_secret_like and "secret-like" in skill.tags
    (redaction,) = result.redactions
    assert redaction.redaction_class == "credential-shaped-token"
    assert set(redaction.ids) == {skill.id, md.id}
    assert redaction.count == 3  # license on the instruction, license and metadata.token on the skill


def test_symlink_inside_a_skill_fails_closed(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    result = _run(repo)
    assert ".claude/skills/linky" not in _skills(result)
    assert not any(
        (e.path or "").startswith(".claude/skills/linky")
        for e in result.entities
        if isinstance(e, Instruction)
    )
    assert _failed(result)[".claude/skills/linky"] == "undigestable"
    assert any("linky" in w and "fail closed" in w for w in result.warnings)
    assert result.coverage[Surface.INSTRUCTIONS].status is CoverageStatus.PARTIAL


def test_nested_and_misplaced_skill_files(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    _write(repo / "skills/SKILL.md", "---\nname: skills\n---\n")
    result = _run(repo)
    skills = _skills(result)
    assert "skills/outer/inner" not in skills  # part of the outer skill's manifest
    assert "inner/SKILL.md" in {i.name for i in skills["skills/outer"].manifest.resources}
    assert "skills" not in skills
    assert any("directly in a skills root" in w for w in result.warnings)


def test_plugin_skills_are_tagged_and_vendored_trees_pruned(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    result = _run(repo)
    deploy = _skills(result)["plugins/acme/skills/deploy"]
    assert "plugin:plugins/acme" in deploy.tags and "scope:project" in deploy.tags
    assert not any("node_modules" in path for path in _skills(result))
    sources = result.coverage[Surface.INSTRUCTIONS].sources
    assert any(
        s.source == "claude-plugin:project" and s.locator == "plugins/acme/.claude-plugin/plugin.json"
        for s in sources
    )


def test_plugin_at_repository_root_shares_skills_dir(tmp_path: Path) -> None:
    _populate(
        tmp_path,
        {
            ".claude-plugin/plugin.json": "{}",
            "skills/root-skill/SKILL.md": "---\nname: root-skill\ndescription: d\n---\n",
        },
    )
    (skill,) = _skills(_run(tmp_path)).values()
    assert "plugin:." in skill.tags  # found once, through the plugin root, not twice


def test_user_scope_collisions_and_symlinked_skill_dirs(scene: tuple[Path, Path]) -> None:
    repo, home = scene
    result = _run(repo, home)
    skills = _skills(result)
    user = {p: s for p, s in skills.items() if p.startswith("~/")}
    assert set(user) == {
        "~/.claude/skills/pdf-tools",
        "~/.claude/skills/linked",
        "~/.codex/skills/codex-skill",
    }
    assert all("scope:user" in s.tags for s in user.values())
    assert skills[".claude/skills/pdf-tools"].id == "skill:claude-skills-pdf-tools"
    assert user["~/.claude/skills/pdf-tools"].id.startswith("skill:claude-skills-pdf-tools-")
    linked = user["~/.claude/skills/linked"]
    assert "symlink-to:~/src/skills/linked" in linked.tags
    assert linked.digest == build_dir_manifest(home / "src/skills/linked").root
    instructions = _instructions(result)
    assert instructions[user["~/.claude/skills/pdf-tools"].skill_md_ref or ""].precedence == 3
    ids = [e.id for e in result.entities]
    assert len(ids) == len(set(ids))


def test_load_instruction_edges(scene: tuple[Path, Path]) -> None:
    repo, home = scene
    result = _run(repo, home)
    skills = {s.id: s for s in _skills(result).values()}
    assert {e.to_ref for e in result.edges} == set(skills)
    for edge in result.edges:
        skill = skills[edge.to_ref]
        assert edge.type is EdgeType.LOADS_INSTRUCTION and edge.from_ref == "agent:triage"
        assert edge.qualifiers == {"precedence": 3 if skill.path.startswith("~/") else 2}
        assert edge.declared_by == f"{skill.path}/SKILL.md"


def test_repo_only_scan_marks_user_scope_not_attempted(tmp_path: Path) -> None:
    _write(tmp_path / ".claude/skills/a/SKILL.md", "---\nname: a\ndescription: d\n---\n")
    result = _run(tmp_path)
    cov = result.coverage[Surface.INSTRUCTIONS]
    assert any(s.source == "user-scope" and s.error_class == "not-attempted" for s in cov.sources)
    assert cov.status is CoverageStatus.PARTIAL and cov.items_seen == 1


def test_empty_repo_is_queried_with_zero_items(tmp_path: Path) -> None:
    result = _run(tmp_path / "repo", tmp_path / "home")
    cov = result.coverage[Surface.INSTRUCTIONS]
    assert cov.status is CoverageStatus.QUERIED and cov.items_seen == 0
    assert not result.entities and not result.edges and not result.redactions


# --------------------------------------------------------------------------------------------- limits and hostile input


def test_too_large_skill_md_is_digested_not_analysed(tmp_path: Path) -> None:
    _write(tmp_path / ".claude/skills/big/SKILL.md", "---\nname: big\ndescription: d\n---\n" + "x" * 500)
    result = _run(tmp_path, max_file_bytes=128)
    (skill,) = _skills(result).values()
    assert "too-large-for-analysis" in skill.tags
    assert not skill.name_matches_directory  # unknown is not reported as a match
    assert not any(t.startswith("missing-") for t in skill.tags)
    assert skill.frontmatter.name is None and skill.name == "big"


def test_large_files_make_the_text_scan_partial(tmp_path: Path) -> None:
    _write(tmp_path / ".claude/skills/a/SKILL.md", "---\nname: a\ndescription: d\n---\n")
    _write(tmp_path / ".claude/skills/a/data.txt", b"y" * (TEXT_SCAN_MAX_BYTES + 1))
    (skill,) = _skills(_run(tmp_path)).values()
    assert "secret-scan-partial" in skill.tags


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_skill_md_that_is_not_a_regular_file(tmp_path: Path) -> None:
    (tmp_path / ".claude/skills/fifo").mkdir(parents=True)
    os.mkfifo(tmp_path / ".claude/skills/fifo/SKILL.md")  # excluded from the manifest, never opened
    result = _run(tmp_path)
    assert not result.entities
    assert _failed(result)[".claude/skills/fifo/SKILL.md"] == "not-a-regular-file"


def test_manifest_os_error_is_a_coverage_fact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / ".claude/skills/a/SKILL.md", "---\nname: a\ndescription: d\n---\n")

    def denied(root: Path, **_: Any) -> Any:
        raise PermissionError(root)

    monkeypatch.setattr(mod, "build_dir_manifest", denied)
    result = _run(tmp_path)
    assert not result.entities
    assert _failed(result)[".claude/skills/a"] == "permission-denied"


def test_skill_md_changed_during_scan_is_warned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / ".claude/skills/a/SKILL.md", "---\nname: a\ndescription: d\n---\n")
    real = mod.read_file_facts

    def swapped(path: Path, max_bytes: int) -> tuple[FileFacts | None, str | None]:
        facts, error = real(path, max_bytes)
        assert facts is not None
        return FileFacts(DIGEST, facts.size, facts.line_endings, facts.data), error

    monkeypatch.setattr(mod, "read_file_facts", swapped)
    result = _run(tmp_path)
    assert any("changed while the skill was being digested" in w for w in result.warnings)


def test_discovery_problems_are_coverage_facts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(tmp_path / "outside/escaped/SKILL.md", "---\nname: escaped\ndescription: d\n---\n")
    (repo / ".claude/skills").mkdir(parents=True)
    os.symlink(tmp_path / "outside/escaped", repo / ".claude/skills/escaped")
    os.symlink("missing", repo / ".claude/skills/broken")
    os.symlink(tmp_path / "outside", repo / "skills")  # a whole root outside the repository
    result = _run(repo)
    failed = _failed(result)
    assert failed[".claude/skills/escaped"] == "symlink-escape"
    assert failed[".claude/skills/broken"] == "broken-symlink"
    assert failed["skills"] == "symlink-escape"
    assert not _skills(result)


def test_unlistable_directory_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "skills"
    _write(root / "a/SKILL.md", "x")
    (root / "cat").mkdir()
    real = Path.iterdir

    def iterdir(self: Path) -> Any:
        if self.name == "cat":
            raise PermissionError(self)
        return real(self)

    monkeypatch.setattr(Path, "iterdir", iterdir)
    found, problems = find_skill_dirs(root, bounds=tmp_path.resolve())
    assert found == [root / "a"]
    assert problems == [(root / "cat", "permission-denied")]


def test_find_skill_dirs_limits(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    _write(root / "a/b/c/d/SKILL.md", "depth four: the deepest searched level")
    _write(root / "e/f/g/h/i/SKILL.md", "depth five: beyond the search depth")
    _write(root / "x/SKILL.md", "shallow")
    _write(root / "node_modules/y/SKILL.md", "excluded")
    os.symlink("x", root / "alias")
    found, problems = find_skill_dirs(root, bounds=tmp_path.resolve(), exclude=("node_modules",))
    assert found == [root / "alias", root / "x", root / "a/b/c/d"]  # aliases are kept as their own location
    assert problems == []
    found, problems = find_skill_dirs(root, bounds=tmp_path.resolve(), max_depth=5)
    assert root / "e/f/g/h/i" in found
    found, problems = find_skill_dirs(root, bounds=tmp_path.resolve(), max_dirs=1)
    assert problems == [(root, "truncated")]


def test_walk_truncation_marks_surface_truncated(tmp_path: Path) -> None:
    _populate(tmp_path, {"a.txt": "a", "b.txt": "b", "c.txt": "c"})
    cov = _run(tmp_path, max_files=2).coverage[Surface.INSTRUCTIONS]
    assert cov.status is CoverageStatus.TRUNCATED and cov.truncated_at == 2


def test_custom_roots(tmp_path: Path) -> None:
    _populate(
        tmp_path,
        {
            "agent/skills/a/SKILL.md": "---\nname: a\ndescription: d\n---\n",
            ".claude/skills/b/SKILL.md": "---\nname: b\ndescription: d\n---\n",
        },
    )
    skills = _skills(_run(tmp_path, collector=SkillsCollector(project_roots=("agent/skills",))))
    assert set(skills) == {"agent/skills/a"}


def test_deterministic_output(scene: tuple[Path, Path]) -> None:
    repo, home = scene
    assert _dump(_run(repo, home)) == _dump(_run(repo, home))


def test_registered_and_assembles_with_instructions_into_a_valid_document(scene: tuple[Path, Path]) -> None:
    (collector,) = load_collectors(["skills"], include_plugins=False)
    assert isinstance(collector, SkillsCollector)
    assert collector.detect(CollectContext(root=Path("/nonexistent")))
    repo, home = scene
    _write(repo / "AGENTS.md", "Agents\n")
    _write(repo / "prompts/system.j2", "{{ x }}")
    ctx = CollectContext(root=repo, home=home, platform="linux", agent_id="agent:triage", now=NOW)
    results = run_collectors(ctx, [InstructionsCollector(), SkillsCollector()])
    entities = [e for r in results for e in r.entities]
    bom = AgentBOM(
        snapshot=Snapshot(
            id=f"snap:1:{D[7:19]}",
            kind=SnapshotKind.DECLARED,
            digest=D,
            serial=1,
            agent_ref="agent:triage",
            produced_at=NOW,
        ),
        subject="agent:triage",
        producer=Producer(version="0.1.0"),
        agents=[Agent(id="agent:triage", name="triage", version="1.0.0", role=AgentRole.ROOT)],
        instructions=[e for e in entities if isinstance(e, Instruction)],
        prompts=[e for e in entities if isinstance(e, PromptTemplate)],
        skills=[e for e in entities if isinstance(e, Skill)],
        edges=[e for r in results for e in r.edges],
        redactions=[x for r in results for x in r.redactions],
    )
    assert len(bom.skills) == len(EXPECTED_PROJECT_SKILLS) + 3
    assert all(bom.entity(s.skill_md_ref or "") is not None for s in bom.skills)


# --------------------------------------------------------------------------------------------- helpers


def test_validate_frontmatter_table() -> None:
    assert validate_frontmatter(None, "x") == (
        ["missing-frontmatter", "missing-name", "missing-description"],
        False,
    )
    assert validate_frontmatter(None, "x", "oversized-frontmatter")[0][0] == "oversized-frontmatter"
    assert validate_frontmatter({"name": "x", "description": "d"}, "x") == ([], True)
    assert validate_frontmatter({"name": "  ", "description": ""}, "x")[0] == [
        "missing-name",
        "missing-description",
    ]
    assert validate_frontmatter({"name": 7, "description": ["d"]}, "7")[0] == [
        "invalid-name",
        "invalid-description",
    ]
    for bad in ("-lead", "trail-", "dou--ble", "UPPER", "a" * 65, "sp ace"):
        assert "invalid-name" in validate_frontmatter({"name": bad, "description": "d"}, bad)[0], bad
    assert validate_frontmatter(
        {"name": "a" * 64, "description": "d" * MAX_DESCRIPTION_LENGTH}, "a" * 64
    ) == (
        [],
        True,
    )
    tags, _ = validate_frontmatter(
        {"name": "x", "description": "d", "compatibility": 3, "metadata": "m"}, "x"
    )
    assert tags == ["invalid-compatibility", "invalid-metadata"]


def test_skill_frontmatter_without_mapping() -> None:
    sanitizer = FrontmatterSanitizer()
    assert skill_frontmatter(None, sanitizer).model_dump() == skill_frontmatter({}, sanitizer).model_dump()
    fm = skill_frontmatter({"allowed-tools": f"Read Bash(curl -H {OPENAI_KEY})", "metadata": "x"}, sanitizer)
    assert fm.allowed_tools == ["Read"] and fm.metadata == {}
    assert sanitizer.redacted == 1


def test_shebang_interpreter() -> None:
    assert shebang_interpreter(b"#!/usr/bin/env python3\n") == "python3"
    assert shebang_interpreter(b"#!/usr/bin/env -S deno run --allow-net\n") == "deno"
    assert shebang_interpreter(b"#!/usr/bin/env FOO=1 node\n") == "node"
    assert shebang_interpreter(b"#! /bin/bash -e\r\n") == "bash"
    assert shebang_interpreter(b"#!C:\\Python\\python.exe\n") == "python.exe"
    assert shebang_interpreter(b"#!/usr/bin/env\n") is None
    assert shebang_interpreter(b"#!/opt/we$ird --flag\n") is None
    assert shebang_interpreter(b"#!\n") is None
    assert shebang_interpreter(b"print(1)") is None


def test_script_ref() -> None:
    item = ManifestItem(name="tools/x", digest=DIGEST, size=1)
    assert script_ref(item, b"data", executable=False) is None
    ref = script_ref(item, b"data", executable=True)
    assert ref is not None and ref.interpreter is None and ref.path == "tools/x" and ref.digest == DIGEST
    weird = script_ref(item, b"#!/opt/we$ird", executable=False)
    assert weird is not None and weird.interpreter is None
    dll = script_ref(ManifestItem(name="lib.dll", digest=DIGEST), b"MZ\x90", executable=False)
    assert dll is not None and dll.interpreter == "native"
    assert (
        script_ref(ManifestItem(name="readme.txt", digest=DIGEST), b"MZ is a word", executable=False) is None
    )
    ps = script_ref(ManifestItem(name="Setup.PS1", digest=DIGEST), b"Write-Host", executable=False)
    assert ps is not None and ps.interpreter == "powershell"


def test_referenced_servers_helper() -> None:
    text = f"mcp__github__create_issue mcp__github mcp__my_server__do-thing xmcp__no mcp__{GH_PAT} mcp___ mcp__a__"
    assert referenced_servers(text) == ["a", "github", "my_server"]


def test_file_helpers_tolerate_os_errors(tmp_path: Path) -> None:
    assert mod._head(tmp_path / "missing") == b""
    assert mod._executable(tmp_path / "missing") is False
