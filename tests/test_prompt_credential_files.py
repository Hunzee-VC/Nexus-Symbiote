"""A file named as holding credentials is never read by the prompt collector, whether an
instruction file or a skill file is a symlink to it or a skill bundle holds it, so no
unkeyed digest of it reaches the inventory, where it could confirm guesses offline."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.utils.confined import ConfinedCollection

# Synthetic credential lines: nothing here is a real secret.
SYNTHETIC_CREDENTIAL = b"SYNTHETIC_API_TOKEN=not-a-real-credential-0004\n"
OTHER_CREDENTIAL = b"SYNTHETIC_DB_PASSWORD=not-a-real-credential-0005\n"
LINKED_CREDENTIAL = b"SYNTHETIC_DEPLOY_KEY=not-a-real-credential-0006\n"
LINKED = "a symlink leads to {}, whose name says it holds credentials; not read or inventoried"
NAMED = "its name says it holds credentials; not read or inventoried"


def _write(root: Path, relative: str, content: bytes | str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)


def _link(root: Path, relative: str, target: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(os.path.relpath(root / target, path.parent))


def _components(result):
    return {component.bom_ref: component for component in result.components}


def _published(result) -> str:
    return AIBOM(components=result.components).to_json()


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("CLAUDE.md", ".env"),
        ("AGENTS.md", ".env"),
        (".cursorrules", ".env"),
        ("GEMINI.md", "secrets/token.txt"),
    ],
)
def test_a_root_instruction_file_linked_to_a_credential_file_is_a_gap(tmp_path, name, target):
    project = tmp_path / "project"
    _write(project, target, SYNTHETIC_CREDENTIAL)
    _link(project, name, target)
    result = PromptScanner().scan(project)
    assert f"prompt:{name}" not in _components(result)
    assert result.surfaces_excluded == [f"{name}: " + LINKED.format(target)]
    assert not result.scan_failures
    assert hash_bytes(SYNTHETIC_CREDENTIAL) not in _published(result)
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert run.exit_code == 1, run.output
    assert hash_bytes(SYNTHETIC_CREDENTIAL) not in output.read_text()


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("pkg/CLAUDE.md", ".env"),
        ("pkg/.cursorrules", "config/.netrc"),
        (".claude/rules/style.md", ".env.production"),
        (".claude/agents/reviewer.md", "credentials/reviewer.json"),
    ],
)
def test_a_nested_or_rule_file_linked_to_a_credential_file_is_a_gap(tmp_path, name, target):
    _write(tmp_path, target, SYNTHETIC_CREDENTIAL)
    _link(tmp_path, name, target)
    result = PromptScanner().scan(tmp_path)
    assert name not in {component.source_path for component in result.components}
    assert result.surfaces_excluded == [f"{name}: " + LINKED.format(target)]
    assert hash_bytes(SYNTHETIC_CREDENTIAL) not in _published(result)


@pytest.mark.parametrize(
    "name", [".claude/rules/.env", ".github/prompts/api-key.txt", ".cursor/rules/secrets/x.txt"]
)
def test_a_credential_named_file_in_a_rule_directory_is_a_gap(tmp_path, name):
    _write(tmp_path, name, SYNTHETIC_CREDENTIAL)
    _write(tmp_path, ".claude/rules/style.md", "# Style\n")
    result = PromptScanner().scan(tmp_path)
    assert set(_components(result)) == {"prompt:.claude/rules/style.md"}
    assert result.surfaces_excluded == [f"{name}: {NAMED}"]
    assert hash_bytes(SYNTHETIC_CREDENTIAL) not in _published(result)


def test_instruction_links_to_other_files_keep_their_content_hash(tmp_path):
    files = {
        "AGENTS.md": "# Shared instructions\n",
        "docs/cursor-rules.txt": "Prefer small diffs.\n",
        "docs/secrets/README.md": "# How this project stores secrets\n",
    }
    for name, text in files.items():
        _write(tmp_path, name, text)
    _write(tmp_path, ".env", SYNTHETIC_CREDENTIAL)
    _link(tmp_path, "CLAUDE.md", "AGENTS.md")
    _link(tmp_path, ".cursorrules", "docs/cursor-rules.txt")
    _link(tmp_path, "GEMINI.md", "docs/secrets/README.md")
    _link(tmp_path, "AGENTS.override.md", ".env")
    result = PromptScanner().scan(tmp_path)
    components = _components(result)
    for name, target in (
        ("CLAUDE.md", "AGENTS.md"),
        (".cursorrules", "docs/cursor-rules.txt"),
        ("GEMINI.md", "docs/secrets/README.md"),
    ):
        linked = components[f"prompt:{name}"]
        assert linked.properties["symlink_target"] == target
        assert linked.content_hash == hash_bytes(files[target].encode())
    assert "prompt:AGENTS.override.md" not in components
    assert result.surfaces_excluded == ["AGENTS.override.md: " + LINKED.format(".env")]
    assert not result.scan_failures


def test_an_instruction_symlink_replaced_after_its_check_is_a_failure(tmp_path, monkeypatch):
    _write(tmp_path, "AGENTS.md", "# Shared instructions\n")
    _write(tmp_path, ".env", SYNTHETIC_CREDENTIAL)
    _link(tmp_path, "CLAUDE.md", "AGENTS.md")
    checked = ConfinedCollection.in_root_target

    def replaced_after_check(self, path):
        found = checked(self, path)
        if Path(path).as_posix() == "CLAUDE.md":
            (tmp_path / "CLAUDE.md").unlink()
            (tmp_path / "CLAUDE.md").symlink_to(".env")
        return found

    monkeypatch.setattr(ConfinedCollection, "in_root_target", replaced_after_check)
    result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == ["CLAUDE.md: file changed during collection"]
    assert set(_components(result)) == {"prompt:AGENTS.md"}
    assert hash_bytes(SYNTHETIC_CREDENTIAL) not in _published(result)


def test_an_import_from_a_credential_directory_is_a_gap(tmp_path):
    _write(tmp_path, "CLAUDE.md", "Load @secrets/token.txt and @secrets/README.md.\n")
    _write(tmp_path, "secrets/token.txt", SYNTHETIC_CREDENTIAL)
    _write(tmp_path, "secrets/README.md", "# How secrets are stored\n")
    result = PromptScanner().scan(tmp_path)
    components = _components(result)
    assert "prompt:import:secrets/token.txt" not in components
    readme = components["prompt:import:secrets/README.md"]
    assert readme.content_hash == hash_bytes(b"# How secrets are stored\n")
    assert result.surfaces_excluded == [f"secrets/token.txt: imported by CLAUDE.md but {NAMED}"]


SKILL = ".claude/skills/deploy"


def _skill_bundle(root: Path) -> dict[str, str]:
    """An ordinary skill and one named for what it scans, each with scripts and references."""
    files = {
        f"{SKILL}/SKILL.md": "---\nname: deploy\n---\nRun scripts/deploy.py.\n",
        f"{SKILL}/scripts/deploy.py": "print('deploy')\n",
        f"{SKILL}/references/runbook.md": "# Runbook\n",
        f"{SKILL}/references/secrets-handling.md": "# Never print secrets\n",
        ".claude/skills/secret-scanner/SKILL.md": "---\nname: secret-scanner\n---\nScan.\n",
        ".claude/skills/secret-scanner/scripts/scan.py": "print('scan')\n",
    }
    for name, text in files.items():
        _write(root, name, text)
    return files


def test_credential_files_are_left_out_of_a_skill_bundle(tmp_path):
    files = _skill_bundle(tmp_path)
    _write(tmp_path, f"{SKILL}/.env", SYNTHETIC_CREDENTIAL)
    _write(tmp_path, f"{SKILL}/secrets/token.txt", OTHER_CREDENTIAL)
    _write(tmp_path, "config/deploy-credentials.json", LINKED_CREDENTIAL)
    _link(tmp_path, f"{SKILL}/config.json", "config/deploy-credentials.json")
    result = PromptScanner().scan(tmp_path)
    components = _components(result)
    assert set(components) == {f"skill:{name}" for name in files}
    for name, text in files.items():
        assert components[f"skill:{name}"].hashes == {"sha256": hash_bytes(text.encode())}
    assert sorted(result.surfaces_excluded) == [
        f"{SKILL}/.env: {NAMED}",
        f"{SKILL}/config.json: " + LINKED.format("config/deploy-credentials.json"),
        f"{SKILL}/secrets/token.txt: {NAMED}",
    ]
    assert not result.scan_failures
    published = _published(result)
    for content in (SYNTHETIC_CREDENTIAL, OTHER_CREDENTIAL, LINKED_CREDENTIAL):
        assert hash_bytes(content) not in published


def test_a_large_skill_resource_linked_to_a_credential_file_is_not_streamed(tmp_path):
    _skill_bundle(tmp_path)
    # Both resources exceed the file-bytes limit, so a skill file leading to either
    # would be streamed and digested.
    sample, vault = b"\x00sample" * 16_384, SYNTHETIC_CREDENTIAL * 2048
    _write(tmp_path, "assets/sample.bin", sample)
    _write(tmp_path, "secrets/vault.bin", vault)
    _link(tmp_path, f"{SKILL}/assets/sample.bin", "assets/sample.bin")
    _link(tmp_path, f"{SKILL}/assets/vault.bin", "secrets/vault.bin")
    with limits.applied(limits.resolve(["file-bytes=64KiB"], {})):
        result = PromptScanner().scan(tmp_path)
    components = _components(result)
    assert components[f"skill:{SKILL}/assets/sample.bin"].hashes == {"sha256": hash_bytes(sample)}
    assert f"skill:{SKILL}/assets/vault.bin" not in components
    assert result.surfaces_excluded == [
        f"{SKILL}/assets/vault.bin: " + LINKED.format("secrets/vault.bin")
    ]
    assert hash_bytes(vault) not in _published(result)


def test_a_skill_symlink_replaced_after_its_check_is_a_failure(tmp_path, monkeypatch):
    _skill_bundle(tmp_path)
    _write(tmp_path, "config/deploy.toml", "mode = 'strict'\n")
    _write(tmp_path, ".env", SYNTHETIC_CREDENTIAL)
    link = tmp_path / SKILL / "config.toml"
    _link(tmp_path, f"{SKILL}/config.toml", "config/deploy.toml")
    checked = ConfinedCollection.regular_file

    def replaced_after_check(self, path):
        found = checked(self, path)
        if Path(path).as_posix() == f"{SKILL}/config.toml":
            link.unlink()
            link.symlink_to("../../../.env")
        return found

    monkeypatch.setattr(ConfinedCollection, "regular_file", replaced_after_check)
    result = PromptScanner().scan(tmp_path)
    assert result.scan_failures == [f"{SKILL}/config.toml: file changed during collection"]
    assert f"skill:{SKILL}/config.toml" not in _components(result)
    assert hash_bytes(SYNTHETIC_CREDENTIAL) not in _published(result)


def test_a_skill_memory_file_linked_to_a_credential_file_imports_nothing(tmp_path):
    # A host that opens .claude/commands/claude.md as CLAUDE.md expands its imports.
    _write(tmp_path, ".env", SYNTHETIC_CREDENTIAL + b"# see @../../docs/notes.md\n")
    _write(tmp_path, "docs/notes.md", "# Notes\n")
    _link(tmp_path, ".claude/commands/claude.md", ".env")
    result = PromptScanner().scan(tmp_path)
    assert not _components(result)
    assert result.surfaces_excluded == [".claude/commands/claude.md: " + LINKED.format(".env")]
    assert hash_bytes((tmp_path / ".env").read_bytes()) not in _published(result)


@pytest.mark.parametrize(
    ("name", "target"),
    [
        (".claude/rules/guide.md", ".env"),
        ("pkg/AGENTS.md", ".env"),
        ("pkg/CLAUDE.md", ".env"),
        ("CLAUDE.local.md", ".env"),
        (".cursorrules", ".env"),
        (".github/prompts/review.prompt.md", ".env"),
    ],
)
def test_an_import_of_a_walked_file_linked_to_a_credential_file_is_a_gap(tmp_path, name, target):
    # A walk reaches the file before the import does; neither records the credential file.
    _write(tmp_path, target, SYNTHETIC_CREDENTIAL)
    _write(tmp_path, "CLAUDE.md", f"Follow @{name}\n")
    _link(tmp_path, name, target)
    result = PromptScanner().scan(tmp_path)
    components = _components(result)
    assert {component.source_path for component in result.components} == {"CLAUDE.md"}
    assert components["prompt:CLAUDE.md"].properties.get("imports") is None
    assert f"{name}: " + LINKED.format(target) in result.surfaces_excluded
    assert hash_bytes(SYNTHETIC_CREDENTIAL) not in _published(result)


def test_a_walk_that_skips_the_credential_check_still_records_no_credential_file(
    tmp_path, monkeypatch
):
    from nexus_symbiote.scanners import prompt

    def unchecked(path, files, result, *, missing_ok=False, variants_read=(), **_):
        return files.read_bytes(path, missing_ok=missing_ok, variants_read=variants_read)

    monkeypatch.setattr(prompt, "_read_unless_credential", unchecked)
    _write(tmp_path, ".env", SYNTHETIC_CREDENTIAL)
    _write(tmp_path, "CLAUDE.md", "Follow @.claude/rules/guide.md\n")
    _link(tmp_path, ".claude/rules/guide.md", ".env")
    result = PromptScanner().scan(tmp_path)
    assert {component.source_path for component in result.components} == {"CLAUDE.md"}
    assert ".claude/rules/guide.md: " + LINKED.format(".env") in result.surfaces_excluded
    assert hash_bytes(SYNTHETIC_CREDENTIAL) not in _published(result)
