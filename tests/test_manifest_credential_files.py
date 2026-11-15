"""An agent.yaml instruction named as holding credentials, or a symlink to such a file, is
never read, so no unkeyed digest of it reaches the inventory or an export, where anyone
holding it could confirm a guess of a short secret offline."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import PromptComponent
from nexus_symbiote.graph import assemble_repository_agent
from nexus_symbiote.policy import PolicyError
from nexus_symbiote.utils.confined import ConfinedCollection

# Synthetic credential lines: nothing here is a real secret.
PIN = b"SYNTHETIC_PIN=0000-not-a-real-credential\n"
KEY = b"SYNTHETIC-KEY-MATERIAL-not-a-real-credential\n"
NAMED = "names a file whose name says it holds credentials; not read or inventoried"
LINKED = "names a symlink to a file whose name says it holds credentials; not read or inventoried"
UNSAFE = "the declared instruction could not be collected safely"
GUIDE = Path(__file__).parents[1] / "docs/agent-manifest.md"


def _write(root: Path, relative: str, content: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _link(root: Path, relative: str, target: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(os.path.relpath(root / target, path.parent))


def _manifest(root: Path, *entries: str) -> None:
    (root / "agent.yaml").write_text(json.dumps({"name": "demo", "instructions": list(entries)}))


def _assemble(root: Path) -> tuple[AIBOM, list[str], list[str]]:
    bom = AIBOM()
    failures: list[str] = []
    gaps: list[str] = []
    assemble_repository_agent(bom, root, failures=failures, exclusions=gaps)
    return bom, failures, gaps


def _digests(*contents: bytes) -> list[str]:
    return [hashlib.sha256(content).hexdigest() for content in contents]


def _prompts(bom: AIBOM) -> list[PromptComponent]:
    return [c for c in bom.components if isinstance(c, PromptComponent)]


@pytest.mark.parametrize(
    "entry",
    [
        ".env",
        ".env.production",
        "config/.env",
        "nested/a/b/.env.local",
        ".ENV",
        "keys/id_rsa",
        "ID_RSA",
        ".ssh/id_ed25519",
        ".npmrc",
        ".netrc",
        ".pypirc",
        "deploy/server.pem",
        "tls/server.KEY",
        "credentials.json",
        ".aws/credentials",
        "config/db_password.txt",
        "prompts/my-api-key.txt",
        "secrets/token.txt",
        ".secrets/notes.txt",
        "Secrets/notes.txt",
    ],
)
def test_a_declared_credential_file_is_a_gap_and_not_read(tmp_path, entry):
    _write(tmp_path, entry, PIN)
    _manifest(tmp_path, entry)
    bom, failures, gaps = _assemble(tmp_path)
    assert failures == []
    assert gaps == [f"agent.yaml#/instructions/0: {NAMED}"]
    assert _prompts(bom) == []
    assert _digests(PIN)[0] not in bom.to_json()


@pytest.mark.parametrize(
    "manifest",
    [
        'instructions: ["./.env"]',
        'instructions: [".//.env"]',
        'instructions: ["\\x2eenv"]',
        'instructions: ["\\u002eenv"]',
        "instructions: ['.env']",
        "instructions:\n  - .env\n",
        "instructions: [config/./.env]",
    ],
)
def test_another_spelling_of_a_credential_entry_is_a_gap(tmp_path, manifest):
    _write(tmp_path, ".env", PIN)
    _write(tmp_path, "config/.env", PIN)
    (tmp_path / "agent.yaml").write_text(f"name: demo\n{manifest}\n")
    bom, failures, gaps = _assemble(tmp_path)
    assert (failures, gaps) == ([], [f"agent.yaml#/instructions/0: {NAMED}"])
    assert _digests(PIN)[0] not in bom.to_json()


@pytest.mark.parametrize(
    ("entry", "target"),
    [
        ("docs/notes.md", ".env"),
        ("CLAUDE.md", ".env"),
        ("AGENTS.md", "config/.env.local"),
        ("prompts/system.txt", "keys/id_rsa"),
        ("docs/guide.md", "secrets/token.txt"),
        ("docs/rules.txt", "deploy/server.pem"),
    ],
)
def test_a_declared_symlink_to_a_credential_file_is_a_gap_and_not_read(tmp_path, entry, target):
    _write(tmp_path, target, KEY)
    _link(tmp_path, entry, target)
    _manifest(tmp_path, entry)
    bom, failures, gaps = _assemble(tmp_path)
    assert failures == []
    assert gaps == [f"agent.yaml#/instructions/0: {LINKED}"]
    assert _prompts(bom) == []
    assert _digests(KEY)[0] not in bom.to_json()


def test_a_declared_file_behind_a_directory_symlink_to_a_credential_directory_is_a_gap(tmp_path):
    _write(tmp_path, "secrets/notes.txt", PIN)
    (tmp_path / "ops").symlink_to("secrets")
    _manifest(tmp_path, "ops/notes.txt")
    bom, failures, gaps = _assemble(tmp_path)
    assert (failures, gaps) == ([], [f"agent.yaml#/instructions/0: {LINKED}"])
    assert _digests(PIN)[0] not in bom.to_json()


def test_the_finding_reproduction_publishes_no_credential_digest(tmp_path):
    # agent.yaml naming .env, id_rsa and a Markdown symlink to .env.
    _write(tmp_path, ".env", PIN)
    _write(tmp_path, "id_rsa", KEY)
    _link(tmp_path, "docs/link.md", ".env")
    _manifest(tmp_path, ".env", "id_rsa", "docs/link.md")
    bom, failures, gaps = _assemble(tmp_path)
    assert failures == []
    assert gaps == [
        f"agent.yaml#/instructions/0: {NAMED}",
        f"agent.yaml#/instructions/1: {NAMED}",
        f"agent.yaml#/instructions/2: {LINKED}",
    ]
    published = bom.to_json()
    assert not any(digest in published for digest in _digests(PIN, KEY))
    # Each record names the entry by its position only, never by its text.
    assert not any(".env" in gap or "id_rsa" in gap or "link.md" in gap for gap in gaps)


def test_credential_entries_are_gaps_wherever_they_appear_and_the_rest_is_kept(tmp_path):
    rules, system = b"Refund only when asked.\n", b"Answer briefly.\n"
    _write(tmp_path, "docs/agents/rules.md", rules)
    _write(tmp_path, "prompts/system.txt", system)
    _write(tmp_path, ".env", PIN)
    _manifest(tmp_path, "docs/agents/rules.md", ".env", "prompts/system.txt", ".env")
    bom, failures, gaps = _assemble(tmp_path)
    assert failures == []
    assert gaps == [f"agent.yaml#/instructions/{index}: {NAMED}" for index in (1, 3)]
    assert {(p.source_path, p.content_hash) for p in _prompts(bom)} == {
        ("docs/agents/rules.md", hash_bytes(rules)),
        ("prompts/system.txt", hash_bytes(system)),
    }
    assert _digests(PIN)[0] not in bom.to_json()


def test_a_credential_entry_is_never_echoed(tmp_path):
    entry = "secrets/sk-live-0123456789abcdef.txt"
    _write(tmp_path, entry, PIN)
    _manifest(tmp_path, entry)
    _, failures, gaps = _assemble(tmp_path)
    assert (failures, gaps) == ([], [f"agent.yaml#/instructions/0: {NAMED}"])


def test_strict_assembly_refuses_a_credential_entry(tmp_path):
    # validate --project and risk --project assemble without a failures list.
    _write(tmp_path, ".env", PIN)
    _manifest(tmp_path, ".env")
    with pytest.raises(PolicyError, match="says it holds credentials"):
        assemble_repository_agent(AIBOM(), tmp_path)


def test_a_symlink_swapped_in_after_the_check_is_a_failure_not_a_digest(tmp_path, monkeypatch):
    # The check saw no symlink to a credential file; the read then followed one.
    _write(tmp_path, ".env", PIN)
    _link(tmp_path, "docs/notes.md", ".env")
    _manifest(tmp_path, "docs/notes.md")
    monkeypatch.setattr(ConfinedCollection, "in_root_target", lambda self, path: None)
    bom, failures, gaps = _assemble(tmp_path)
    assert (failures, gaps) == ([f"agent.yaml#/instructions/0: {UNSAFE}"], [])
    assert _prompts(bom) == []
    assert _digests(PIN)[0] not in bom.to_json()


@pytest.mark.parametrize(
    ("entry", "content", "link"),
    [
        ("docs/agents/rules.md", b"Refund only when asked.\n", None),
        ("docs/secrets-handling.md", b"Never paste tokens into tickets.\n", None),
        ("secrets/README.md", b"Rotate keys quarterly.\n", None),
        ("prompts/system.txt", b"Answer briefly.\n", None),
        ("prompts/keywords.txt", b"refund, return\n", None),
        ("config/environment.txt", b"Use the staging tenant.\n", None),
        ("docs/guide.md", b"Escalate to a human.\n", "shared/guide.md"),
        ("docs/policy.md", b"Escalate to a human.\n", "secrets/policy.md"),
        ("prompts/linked.txt", b"Answer briefly.\n", "shared/system.txt"),
    ],
)
def test_ordinary_declared_instructions_are_still_inventoried(tmp_path, entry, content, link):
    if link is None:
        _write(tmp_path, entry, content)
    else:
        _write(tmp_path, link, content)
        _link(tmp_path, entry, link)
    _manifest(tmp_path, entry)
    bom, failures, gaps = _assemble(tmp_path)
    assert (failures, gaps) == ([], [])
    (prompt,) = _prompts(bom)
    assert (prompt.source_path, prompt.content_hash) == (entry, hash_bytes(content))


def _project(root: Path) -> Path:
    project = root / "project"
    _write(project, ".env", PIN)
    _write(project, "id_rsa", KEY)
    _write(project, ".npmrc", b"//registry.example.test/:_authToken=not-a-real-credential\n")
    _write(project, "docs/agents/rules.md", b"Refund only when asked.\n")
    _link(project, "docs/link.md", ".env")
    _link(project, "CLAUDE.md", ".env")
    _manifest(
        project, ".env", "id_rsa", ".npmrc", "docs/link.md", "CLAUDE.md", "docs/agents/rules.md"
    )
    return project


@pytest.mark.parametrize("output_format", ["json", "cyclonedx", "spdx", "sarif"])
def test_a_scan_fails_closed_and_exports_no_credential_digest(tmp_path, output_format):
    project = _project(tmp_path)
    output = tmp_path / "bom.out"
    result = CliRunner().invoke(
        main,
        ["scan", str(project), "--no-project-policy", "-f", output_format, "-o", str(output)],
    )
    assert result.exit_code == 1, result.output
    assert "Scan gate failed" in result.output
    assert "says it holds credentials" in result.output
    exported = output.read_text()
    secrets = _digests(PIN, KEY, (project / ".npmrc").read_bytes())
    assert not any(digest in exported for digest in secrets)


def test_a_credential_entry_alone_fails_the_scan_gate_and_project_validation(tmp_path):
    project = tmp_path / "project"
    _write(project, ".env", PIN)
    _write(project, "docs/agents/rules.md", b"Refund only when asked.\n")
    _manifest(project, "docs/agents/rules.md", ".env")
    output = tmp_path / "bom.json"
    scan = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(output)]
    )
    assert scan.exit_code == 1, scan.output
    assert f"excluded: agent.yaml#/instructions/1: {NAMED}" in scan.output
    assert _digests(PIN)[0] not in output.read_text()
    validate = CliRunner().invoke(
        main, ["validate", str(output), "--no-project-policy", "--project", str(project)]
    )
    assert validate.exit_code != 0, validate.output
    assert "Local agent manifest could not be reconciled." in validate.output


def test_the_scan_records_each_credential_entry_as_a_gap(tmp_path):
    project = _project(tmp_path)
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    )
    assert result.exit_code == 0, result.output
    bom = json.loads(output.read_text())
    excluded = bom["metadata"]["completeness"]["surfaces_excluded"]
    assert {
        f"agent.yaml#/instructions/{index}: {NAMED if index < 3 else LINKED}" for index in range(5)
    } <= set(excluded)
    declared = [c for c in bom["components"] if c["bom_ref"].startswith("prompt:manifest:")]
    assert [c["source_path"] for c in declared] == ["docs/agents/rules.md"]


def test_the_guide_documents_both_credential_gaps():
    guide = GUIDE.read_text()
    for reason in (NAMED, LINKED):
        assert f"`agent.yaml#/instructions/N: {reason}`" in guide
