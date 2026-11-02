from __future__ import annotations

import os
from pathlib import Path

import pytest

from symbiote.advisories.types import DependencyKind, DependencyRef
from symbiote.update import (
    FileEdit,
    PatchError,
    UpdateProposal,
    apply_proposals,
    locate_edits,
    render_diff,
)
from symbiote.update.patch import rewrite_token

DIGEST = "sha256:" + "d" * 64


def proposal(
    name: str,
    proposed: str,
    *locators: str,
    ecosystem: str = "npm",
    kind: str = "pin",
    version: str | None = None,
) -> UpdateProposal:
    ref = DependencyRef(
        kind=DependencyKind.MCP_SERVER_PACKAGE,
        ecosystem=ecosystem,  # type: ignore[arg-type]
        name=name,
        version=version,
        locators=locators,
    )
    return UpdateProposal(
        kind=kind,  # type: ignore[arg-type]
        dependency=ref,
        current=version or "(floating)",
        proposed=proposed,
        title=f"Pin {name}",
        rationale="test",
    )


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return path


def roundtrip(root: Path, rel: str, text: str, p: UpdateProposal, old: str, new: str) -> None:
    """Apply ``p`` and assert the file equals the original with exactly one token replaced, byte for byte."""
    path = write(root, rel, text)
    edits = locate_edits(root, p)
    assert len(edits) == 1, p.review_notes
    assert (edits[0].before, edits[0].after) == (old, new)
    p.edits = edits
    diff = render_diff(root, [p])
    assert diff.startswith(f"--- a/{rel}\n+++ b/{rel}\n")
    assert "-" in diff and new in diff
    assert apply_proposals(root, [p]) == [rel]
    after = path.read_bytes().decode("utf-8")
    index = text.index(old) if text.count(old) == 1 else None
    if index is not None:
        assert after == text[:index] + new + text[index + len(old) :]
    assert len(after) == len(text) - len(old) + len(new)
    # everything outside the token is unchanged
    prefix_len = next(i for i, (a, b) in enumerate(zip(text, after, strict=False)) if a != b)
    assert text[:prefix_len] == after[:prefix_len]
    assert text[prefix_len + len(old) :] == after[prefix_len + len(new) :]


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("pkg", "pkg@1.2.3"),
        ("pkg@latest", "pkg@1.2.3"),
        ("--package=pkg@^1", "--package=pkg@1.2.3"),
    ],
)
def test_rewrite_npm(token: str, expected: str) -> None:
    assert rewrite_token("npm", "pkg", token, "1.2.3") == expected


def test_rewrite_tokens_other_ecosystems() -> None:
    assert rewrite_token("npm", "@scope/pkg", "@scope/pkg@^1", "1.4.2") == "@scope/pkg@1.4.2"
    assert rewrite_token("npm", "pkg", "pkg-extra", "1.0.0") is None
    assert rewrite_token("pypi", "mcp-server-fetch", "mcp_server_fetch", "1.0") == "mcp_server_fetch==1.0"
    assert rewrite_token("pypi", "srv", "srv[cli]>=1", "2.0") == "srv[cli]==2.0"
    assert rewrite_token("pypi", "srv", "--from=srv@0.1", "2.0") == "--from=srv==2.0"
    assert rewrite_token("pypi", "srv", "git+https://x/srv", "2.0") is None
    assert (
        rewrite_token("oci", "ghcr.io/acme/mcp", "ghcr.io/acme/mcp:1.2", DIGEST)
        == f"ghcr.io/acme/mcp@{DIGEST}"
    )
    assert rewrite_token("oci", "docker.io/mcp/fetch", "mcp/fetch", DIGEST) == f"mcp/fetch@{DIGEST}"
    with pytest.raises(PatchError):
        rewrite_token("oci", "ghcr.io/acme/mcp", "ghcr.io/acme/mcp:1.2", "1.3")


def test_claude_mcp_json_roundtrip(tmp_path: Path) -> None:
    text = (
        '{\n  "mcpServers": {\n'
        '    "github": {"command": "npx", "args": ["-y", "server-pkg"], "env": {"T": "${T}"}},\n'
        '    "other":  {"command": "npx", "args": ["-y", "server-pkg-two"]}\n'
        "  }\n}\n"
    )
    p = proposal("server-pkg", "1.4.2", ".mcp.json#/mcpServers/github")
    roundtrip(tmp_path, ".mcp.json", text, p, "server-pkg", "server-pkg@1.4.2")
    assert p.edits[0].locator == ".mcp.json#/mcpServers/github/args/1"


def test_same_token_in_two_servers_edits_only_the_located_one(tmp_path: Path) -> None:
    text = (
        '{"mcpServers": {\n'
        '  "a": {"command": "npx", "args": ["-y", "pkg@latest"]},\n'
        '  "b": {"command": "npx", "args": ["-y", "pkg@latest"]}\n'
        "}}\n"
    )
    write(tmp_path, ".mcp.json", text)
    p = proposal("pkg", "2.0.1", ".mcp.json#/mcpServers/b")
    p.edits = locate_edits(tmp_path, p)
    apply_proposals(tmp_path, [p])
    after = (tmp_path / ".mcp.json").read_text()
    assert after.count("pkg@latest") == 1
    assert '"b": {"command": "npx", "args": ["-y", "pkg@2.0.1"]}' in after


def test_vscode_jsonc_with_comments_roundtrip(tmp_path: Path) -> None:
    text = (
        "// VS Code MCP servers\r\n"
        "{\r\n"
        '  /* the scoped server; previously "@scope/pkg@^1" was fine */\r\n'
        '  "servers": {\r\n'
        '    "scoped": {\r\n'
        '      "type": "stdio",\r\n'
        '      "command": "npx",\r\n'
        '      "args": ["-y", "@scope/pkg@^1"], // keep -y\r\n'
        "    },\r\n"
        "  },\r\n"
        "}\r\n"
    )
    p = proposal("@scope/pkg", "1.4.2", ".vscode/mcp.json#/servers/scoped/args/1")
    path = write(tmp_path, ".vscode/mcp.json", text)
    p.edits = locate_edits(tmp_path, p)
    assert [(e.before, e.after) for e in p.edits] == [("@scope/pkg@^1", "@scope/pkg@1.4.2")]
    apply_proposals(tmp_path, [p])
    after = path.read_bytes().decode()
    expected = text.replace('"args": ["-y", "@scope/pkg@^1"]', '"args": ["-y", "@scope/pkg@1.4.2"]')
    assert after == expected  # the comment mentioning the token and CRLF line endings are untouched


def test_codex_toml_roundtrip(tmp_path: Path) -> None:
    text = (
        "# Codex configuration\n"
        'model = "gpt-x"\n\n'
        "[mcp_servers.fetch]\n"
        'command = "uvx"\n'
        "args = ['mcp-server-fetch']  # floating\n"
        "env = { A = 'b' }\n"
    )
    p = proposal("mcp-server-fetch", "2025.4.7", ".codex/config.toml#/mcp_servers/fetch", ecosystem="pypi")
    roundtrip(tmp_path, ".codex/config.toml", text, p, "mcp-server-fetch", "mcp-server-fetch==2025.4.7")


def test_yaml_docker_digest_roundtrip(tmp_path: Path) -> None:
    text = (
        "extensions:\n"
        "  # docker based server\n"
        "  fetch:\n"
        "    cmd: docker\n"
        "    args: [run, -i, --rm, ghcr.io/acme/mcp-fetch:1.2]\n"
        "    timeout: 300\n"
    )
    p = proposal("ghcr.io/acme/mcp-fetch", DIGEST, "goose/config.yaml#/extensions/fetch", ecosystem="oci")
    write(tmp_path, "goose/config.yaml", text)
    p.edits = locate_edits(tmp_path, p)
    assert len(p.edits) == 1, p.review_notes
    apply_proposals(tmp_path, [p])
    after = (tmp_path / "goose/config.yaml").read_text()
    assert after == text.replace("ghcr.io/acme/mcp-fetch:1.2", f"ghcr.io/acme/mcp-fetch@{DIGEST}")


def test_oci_without_known_digest_is_not_edited(tmp_path: Path) -> None:
    write(
        tmp_path, ".mcp.json", '{"mcpServers": {"d": {"command": "docker", "args": ["run", "acme/mcp:1"]}}}'
    )
    p = proposal("docker.io/acme/mcp", "1.2", ".mcp.json#/mcpServers/d", ecosystem="oci", kind="version")
    assert locate_edits(tmp_path, p) == []
    assert any("digest is not known" in n for n in p.review_notes)


def test_ambiguous_token_is_refused(tmp_path: Path) -> None:
    write(tmp_path, ".mcp.json", '{"mcpServers": {"x": {"command": "npx", "args": ["-p", "pkg", "pkg"]}}}')
    p = proposal("pkg", "1.0.0", ".mcp.json#/mcpServers/x")
    assert locate_edits(tmp_path, p) == []
    assert any("ambiguous" in n for n in p.review_notes)


def test_yaml_alias_makes_textual_edit_unsafe(tmp_path: Path) -> None:
    # The token is defined once and referenced twice through an alias: no single textual edit changes only
    # the located value, so the edit is refused.
    text = "base: &spec pkg@latest\nservers:\n  a: {command: npx, args: [*spec]}\n"
    write(tmp_path, "agent.yaml", text)
    p = proposal("pkg", "1.0.0", "agent.yaml#/servers/a/args/0")
    assert locate_edits(tmp_path, p) == []
    assert any("could not be located safely" in n for n in p.review_notes)


def test_missing_token_and_unknown_kind_add_notes(tmp_path: Path) -> None:
    write(tmp_path, ".mcp.json", '{"mcpServers": {"x": {"command": "npx", "args": ["-y", "other"]}}}')
    p = proposal("pkg", "1.0.0", ".mcp.json#/mcpServers/x", ".mcp.json#/mcpServers/missing")
    assert locate_edits(tmp_path, p) == []
    assert len(p.review_notes) == 2
    advice = proposal("pkg", "(remove or replace)", ".mcp.json#/mcpServers/x", kind="replace")
    assert locate_edits(tmp_path, advice) == []
    assert "advice" in advice.review_notes[0]


def test_symlinked_config_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    real = write(outside, "real.json", '{"mcpServers": {"x": {"command": "npx", "args": ["pkg"]}}}')
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(real, root / ".mcp.json")
    p = proposal("pkg", "1.0.0", ".mcp.json#/mcpServers/x")
    assert locate_edits(root, p) == []
    assert any("symbolic link" in n for n in p.review_notes)
    p.edits = [FileEdit(".mcp.json", ".mcp.json#/mcpServers/x/args/0", "pkg", "pkg@1.0.0")]
    with pytest.raises(PatchError, match="symbolic link"):
        apply_proposals(root, [p])
    assert real.read_text() == '{"mcpServers": {"x": {"command": "npx", "args": ["pkg"]}}}'
    # a symlinked directory on the way is refused too
    os.symlink(outside, root / "linked")
    q = proposal("pkg", "1.0.0", "linked/real.json#/mcpServers/x")
    assert locate_edits(root, q) == []


@pytest.mark.parametrize("rel", ["../outside.json", "/etc/passwd.json", "~/.claude.json", "a/../../x.json"])
def test_paths_outside_root_are_refused(tmp_path: Path, rel: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    write(tmp_path, "outside.json", '{"mcpServers": {"x": {"args": ["pkg"]}}}')
    p = proposal("pkg", "1.0.0", f"{rel}#/mcpServers/x")
    assert locate_edits(root, p) == []
    p.edits = [FileEdit(rel, f"{rel}#/mcpServers/x/args/0", "pkg", "pkg@1.0.0")]
    with pytest.raises(PatchError):
        apply_proposals(root, [p])
    assert (tmp_path / "outside.json").read_text() == '{"mcpServers": {"x": {"args": ["pkg"]}}}'


def test_apply_is_all_or_nothing_and_preserves_mode(tmp_path: Path) -> None:
    good = write(tmp_path, ".mcp.json", '{"mcpServers": {"x": {"command": "npx", "args": ["pkg"]}}}\n')
    good.chmod(0o640)
    p = proposal("pkg", "1.0.0", ".mcp.json#/mcpServers/x")
    p.edits = locate_edits(tmp_path, p)
    stale = proposal("pkg", "1.0.0", ".mcp.json#/mcpServers/x")
    stale.edits = [FileEdit(".mcp.json", ".mcp.json#/mcpServers/x/args/0", "pkg@0.9", "pkg@1.0.0")]
    with pytest.raises(PatchError):
        apply_proposals(tmp_path, [p, stale])
    assert "pkg@1.0.0" not in good.read_text()
    assert apply_proposals(tmp_path, [p]) == [".mcp.json"]
    assert good.stat().st_mode & 0o777 == 0o640
    assert not [f for f in tmp_path.iterdir() if f.name.endswith(".symbiote-tmp")]


def test_render_diff_without_trailing_newline(tmp_path: Path) -> None:
    write(tmp_path, ".mcp.json", '{"mcpServers": {"x": {"command": "npx", "args": ["pkg"]}}}')
    p = proposal("pkg", "1.0.0", ".mcp.json#/mcpServers/x")
    diff = render_diff(tmp_path, [p])
    assert diff.endswith("\\ No newline at end of file\n")
    assert '+{"mcpServers": {"x": {"command": "npx", "args": ["pkg@1.0.0"]}}}' in diff
