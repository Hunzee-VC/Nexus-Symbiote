"""Regression coverage for the local collector boundary and secret output."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path

import pytest

from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.utils.confined import ConfinedCollection

SCANNERS = [MCPScanner, PromptScanner, RAGScanner, RegistryScanner]


def output(result) -> str:
    return json.dumps(
        {
            "components": [component.model_dump(mode="json") for component in result.components],
            "failures": result.scan_failures,
            "scanned": result.surfaces_scanned,
            "excluded": result.surfaces_excluded,
        }
    )


@pytest.mark.parametrize(
    "scanner,filename,content,marker",
    [
        (MCPScanner, "mcp.json", '{"mcpServers":{"outside":{"command":"npx"}}}', "outside"),
        (PromptScanner, "CLAUDE.md", "secret outside instructions", "secret outside"),
        (RAGScanner, "rag_config.json", '{"name":"outside-source"}', "outside-source"),
        (RegistryScanner, "package.json", '{"dependencies":{"openai":"1.0.0"}}', "openai"),
    ],
)
def test_symlink_file_not_read(tmp_path, scanner, filename, content, marker):
    outside = tmp_path / "outside"
    outside.write_text(content)
    root = tmp_path / "project"
    root.mkdir()
    (root / filename).symlink_to(outside)
    result = scanner().scan(root)
    assert result.components == []
    assert result.scan_failures
    assert marker not in output(result)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_symlink_root_rejected(tmp_path, scanner):
    source = tmp_path / "source"
    source.mkdir()
    (source / "CLAUDE.md").write_text("outside")
    root = tmp_path / "link"
    root.symlink_to(source, target_is_directory=True)
    result = scanner().scan(root)
    assert not result.components
    assert any("root" in message for message in result.scan_failures)


def test_symlink_directory_never_traversed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "rag_config.json").write_text('{"name":"outside-rag"}')
    root = tmp_path / "root"
    root.mkdir()
    (root / "nested").symlink_to(outside, target_is_directory=True)
    result = RAGScanner().scan(root)
    assert not result.components
    assert any("symlink" in message for message in result.scan_failures)


def test_race_directory_swapped_after_walk_does_not_escape(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    folder = root / "nested"
    folder.mkdir()
    (folder / "secret.txt").write_text("inside")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside secret")
    failures = []
    with ConfinedCollection(root, failures) as files:
        discovered = list(files.iter_files())
        folder.rename(root / "previous")
        folder.symlink_to(outside, target_is_directory=True)
        assert files.read_text(discovered[0]) is None
    assert failures


def test_parent_traversal_and_absolute_escape_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("outside")
    failures = []
    with ConfinedCollection(root, failures) as files:
        assert files.read_text("../secret.txt") is None
        assert files.read_text(outside) is None
    assert len(failures) == 2


def test_fifo_is_refused_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "mcp.json")
    result = MCPScanner().scan(tmp_path)
    assert not result.components
    assert result.scan_failures


def test_explicit_read_and_traversal_limits_are_failures(tmp_path):
    (tmp_path / "large.txt").write_bytes(b"a" * 20)
    failures = []
    with ConfinedCollection(tmp_path, failures, max_file_bytes=10) as files:
        assert files.read_bytes("large.txt") is None
    assert failures
    for index in range(5):
        (tmp_path / str(index)).write_text("")
    failures = []
    with ConfinedCollection(tmp_path, failures, max_entries=3) as files:
        assert list(files.iter_files()) == []
    assert any("entries limit of 3 exceeded" in message for message in failures)


def test_cumulative_byte_budget_and_bounded_stream(tmp_path):
    (tmp_path / "a").write_bytes(b"1234")
    (tmp_path / "b").write_bytes(b"5678")
    failures = []
    with ConfinedCollection(tmp_path, failures, max_total_bytes=6) as files:
        assert files.read_text("a") == "1234"
        assert files.read_text("b") is None
    assert failures
    with ConfinedCollection(tmp_path, []) as files:
        with files.open_regular("a", max_bytes=4) as stream:
            assert stream.read(4) == b"1234"
            assert stream.read(1) == b""
        assert files.hash_file("a") == "sha256:" + hashlib.sha256(b"1234").hexdigest()


def test_confined_stream_rejects_symlink_and_explicit_oversize(tmp_path):
    (tmp_path / "a").write_text("content")
    (tmp_path / "link").symlink_to(tmp_path / "a")
    failures = []
    with ConfinedCollection(tmp_path, failures) as files:
        with pytest.raises(OSError), files.open_regular("link"):
            pass
        with pytest.raises(OSError), files.open_regular("a", max_bytes=1):
            pass
    assert len(failures) == 2


@pytest.mark.parametrize(
    "scanner,filename,content",
    [
        (MCPScanner, "mcp.json", b"\xff"),
        (PromptScanner, "CLAUDE.md", b"\xff"),
        (RAGScanner, "rag_config.json", b"{not valid}"),
        (RegistryScanner, "package.json", b"{not valid}"),
        (RegistryScanner, "requirements.txt", b"\xff"),
    ],
)
def test_unreadable_format_reports_failure(tmp_path, scanner, filename, content):
    (tmp_path / filename).write_bytes(content)
    result = scanner().scan(tmp_path)
    assert not result.components
    assert result.scan_failures


def test_duplicate_json_key_does_not_silently_change_server(tmp_path):
    (tmp_path / "mcp.json").write_text('{"mcpServers":{},"mcpServers":{"hidden":{}}}')
    result = MCPScanner().scan(tmp_path)
    assert not result.components
    assert any("duplicate" in message for message in result.scan_failures)


@pytest.mark.parametrize(
    "scanner,filename,content",
    [
        (MCPScanner, "mcp.json", '{"mcpServers":{"hidden":{}}}'),
        (PromptScanner, "CLAUDE.md", "excluded"),
        (RAGScanner, "rag_config.json", '{"name":"hidden"}'),
        (RegistryScanner, "package.json", '{"dependencies":{"openai":"1.0.0"}}'),
    ],
)
def test_configure_exclusions_are_enforced(tmp_path, scanner, filename, content):
    (tmp_path / filename).write_text(content)
    instance = scanner()
    instance.configure(exclude_paths=[filename])
    result = instance.scan(tmp_path)
    assert not result.components
    assert any("excluded by collection policy" in item for item in result.surfaces_excluded)


def test_lexical_traversal_and_excluded_subtree(tmp_path):
    (tmp_path / "z").write_text("")
    (tmp_path / "a").write_text("")
    hidden = tmp_path / "omit"
    hidden.mkdir()
    (hidden / "b").write_text("")
    with ConfinedCollection(tmp_path, [], exclude_paths=["omit"]) as files:
        assert list(files.iter_files()) == [Path("a"), Path("z")]


def test_mcp_secret_values_omitted_from_components_and_risks(tmp_path):
    config = {
        "mcpServers": {
            "local": {
                "command": "sh -c 'echo command-secret-123'",
                "args": ["--token=arg-secret-123", "--password", "positional-secret-123"],
                "env": {"API_KEY": "env-secret-123"},
            },
            "remote": {
                "url": "http://user:userinfo-secret-123@remote.example/mcp?api_key=query-secret-123#fragment-secret-123",
            },
        }
    }
    (tmp_path / "mcp.json").write_text(json.dumps(config))
    result = MCPScanner().scan(tmp_path)
    serialized = output(result)
    assert len(result.components) == 2
    for secret in (
        "command-secret-123",
        "arg-secret-123",
        "positional-secret-123",
        "env-secret-123",
        "userinfo-secret-123",
        "query-secret-123",
        "fragment-secret-123",
    ):
        assert secret not in serialized
    remote = next(component for component in result.components if component.name == "remote")
    assert remote.endpoint_url == "http://remote.example"


def test_rag_url_credentials_omitted_from_risks(tmp_path):
    (tmp_path / "rag_config.json").write_text(
        json.dumps(
            {
                "name": "docs",
                "source_uris": ["http://u:pw-secret@host/docs?token=query-secret#fragment-secret"],
            }
        )
    )
    result = RAGScanner().scan(tmp_path)
    serialized = output(result)
    assert all(
        secret not in serialized for secret in ("pw-secret", "query-secret", "fragment-secret")
    )
    assert result.components[0].source_uris == ["http://host"]


def test_scanners_do_not_run_commands_retrieve_urls_or_import_project_code(tmp_path):
    marker = tmp_path / "executed"
    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "malicious": {
                        "command": "touch",
                        "args": [str(marker)],
                        "url": "http://127.0.0.1:1/secret",
                    }
                }
            }
        )
    )
    (tmp_path / "evil.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\nimport chromadb\n"
    )
    MCPScanner().scan(tmp_path)
    rag = RAGScanner().scan(tmp_path)
    assert not marker.exists()
    assert any("chroma" in component.name for component in rag.components)


def test_invalid_mcp_and_rag_field_types_are_failures(tmp_path):
    (tmp_path / "mcp.json").write_text('{"mcpServers":{"bad":{"args":false}}}')
    (tmp_path / "rag_config.json").write_text('{"sources":"not-a-list"}')
    assert MCPScanner().scan(tmp_path).scan_failures
    assert RAGScanner().scan(tmp_path).scan_failures


def test_comment_import_is_not_runtime_store_evidence(tmp_path):
    (tmp_path / "app.py").write_text('# import chromadb\nmessage = "import pinecone"\n')
    assert not RAGScanner().scan(tmp_path).components


def test_yaml_config_is_parsed(tmp_path):
    (tmp_path / "rag_config.yaml").write_text("name: docs\ntype: vector-store\n")
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    assert [component.name for component in result.components] == ["docs"]


def test_yaml_recursive_alias_is_not_loaded(tmp_path):
    (tmp_path / "rag_config.yaml").write_text("sources: &s [*s]\n")
    result = RAGScanner().scan(tmp_path)
    assert not result.components
    assert result.scan_failures


def test_localhost_prefix_does_not_hide_remote_cleartext_endpoint(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"remote": {"url": "http://localhost.attacker.example/mcp"}}})
    )
    result = MCPScanner().scan(tmp_path)
    assert any(
        r.severity.value == "high" and r.category == "transport_security"
        for r in result.components[0].risks
    )


def test_open_directory_nofollow_traverse_only_ancestor_and_symlink_rejection(
    tmp_path, monkeypatch
):
    from nexus_symbiote.core.hashing import open_directory_nofollow

    traverse_only = tmp_path / "traverse_only"
    traverse_only.mkdir()
    workspace = traverse_only / "workspace"
    workspace.mkdir()

    real_open = os.open

    def restricted_open(path, flags, *args, dir_fd=None):
        if dir_fd is None and Path(path) == traverse_only:
            raise PermissionError(13, "Permission denied", str(path))
        if dir_fd is not None and path == "traverse_only":
            raise PermissionError(13, "Permission denied", str(path))
        return real_open(path, flags, *args, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", restricted_open)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {restricted_open})
    fd = open_directory_nofollow(workspace)
    try:
        assert os.fstat(fd).st_ino == workspace.stat().st_ino
    finally:
        os.close(fd)

    linked_parent = tmp_path / "linked_parent"
    linked_parent.symlink_to(traverse_only, target_is_directory=True)
    with pytest.raises(OSError):
        os.close(open_directory_nofollow(linked_parent / "workspace"))


def _listing_refused(monkeypatch, *directories: Path) -> None:
    """Make these directories traverse-only: opening them fails, paths through them resolve."""
    real_open = os.open
    paths = set(directories)
    names = {directory.name for directory in directories}

    def restricted_open(path, flags, *args, dir_fd=None):
        if (dir_fd is None and Path(path) in paths) or (dir_fd is not None and path in names):
            raise PermissionError(13, "Permission denied", str(path))
        return real_open(path, flags, *args, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", restricted_open)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {restricted_open})


def test_consecutive_traverse_only_ancestors_still_reach_the_directory(tmp_path, monkeypatch):
    from nexus_symbiote.core.hashing import open_directory_nofollow

    outer = tmp_path / "outer_listing_refused"
    inner = outer / "inner_listing_refused"
    workspace = inner / "workspace"
    workspace.mkdir(parents=True)
    _listing_refused(monkeypatch, outer, inner)
    fd = open_directory_nofollow(workspace)
    try:
        assert os.fstat(fd).st_ino == workspace.stat().st_ino
    finally:
        os.close(fd)


@pytest.mark.parametrize("ancestors", [0, 1])
def test_the_directory_itself_must_open(tmp_path, monkeypatch, ancestors):
    from nexus_symbiote.core.hashing import open_directory_nofollow

    refused = [tmp_path / "outer_listing_refused"][:ancestors]
    workspace = (refused[0] if refused else tmp_path) / "workspace_listing_refused"
    workspace.mkdir(parents=True)
    _listing_refused(monkeypatch, *refused, workspace)
    with pytest.raises(PermissionError):
        open_directory_nofollow(workspace)


@pytest.mark.parametrize("refused", ["outer_listing_refused", "link"])
def test_a_link_at_or_below_a_traverse_only_ancestor_is_refused(tmp_path, monkeypatch, refused):
    from nexus_symbiote.core.hashing import open_directory_nofollow

    outer = tmp_path / "outer_listing_refused"
    (outer / "real" / "workspace").mkdir(parents=True)
    (outer / "link").symlink_to(outer / "real", target_is_directory=True)
    _listing_refused(monkeypatch, outer if refused == "outer_listing_refused" else outer / "link")
    with pytest.raises(OSError, match="Not a directory"):
        open_directory_nofollow(outer / "link" / "workspace")


def test_a_directory_replaced_between_its_check_and_its_open_is_refused(tmp_path, monkeypatch):
    from nexus_symbiote.core.hashing import open_directory_nofollow

    outer = tmp_path / "outer_listing_refused"
    workspace = outer / "workspace"
    workspace.mkdir(parents=True)
    other = tmp_path / "other"
    other.mkdir()
    _listing_refused(monkeypatch, outer)
    real_lstat = os.lstat

    def swapped(path, *args, **kwargs):
        # The check sees one directory; the open that follows gets another.
        return real_lstat(other if Path(path) == workspace else path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", swapped)
    with pytest.raises(OSError, match="changed during open"):
        open_directory_nofollow(workspace)


def test_directories_are_not_opened_without_descriptor_relative_no_follow_support(
    tmp_path, monkeypatch
):
    from nexus_symbiote.core.hashing import open_directory_nofollow

    monkeypatch.setattr(os, "supports_dir_fd", set())
    with pytest.raises(OSError, match="unavailable"):
        open_directory_nofollow(tmp_path)


@pytest.mark.parametrize("firmlink", [True, False])
def test_macos_root_firmlinks_are_opened_through_private(monkeypatch, firmlink):
    import sys

    from nexus_symbiote.core import hashing

    opened: list[str] = []
    real_open, real_islink, real_readlink = os.open, os.path.islink, os.readlink

    def recording_open(path, flags, *args, dir_fd=None):
        opened.append(str(path))
        return real_open(path, flags, *args, dir_fd=dir_fd)

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {recording_open})
    monkeypatch.setattr(os.path, "islink", lambda p: firmlink if p == "/etc" else real_islink(p))
    monkeypatch.setattr(
        os, "readlink", lambda p, *a, **k: "private/etc" if p == "/etc" else real_readlink(p)
    )
    # On macOS /etc is a symlink to private/etc, so the walk must take the real directory.
    # Only the path it takes matters here: a Linux host has no /private, and a macOS host
    # refuses /etc itself.
    with contextlib.suppress(OSError):
        os.close(hashing.open_directory_nofollow(Path("/etc")))
    assert opened[:2] == ["/", "private" if firmlink else "etc"]
