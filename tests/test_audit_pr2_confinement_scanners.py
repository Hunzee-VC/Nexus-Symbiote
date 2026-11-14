"""Regression tests for PR 2 audit fixes: confinement, MCP launchers/resolvers, SSE, secrets, JSONC, and templates."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path

import pytest

from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.policy import PolicyError, find_policy_path
from nexus_symbiote.scanners import live_mcp as live
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.jsonc import strip_jsonc
from nexus_symbiote.utils.model_formats import template_escape_markers
from nexus_symbiote.utils.secrets import REDACTED, redact_text, secret_like


def _scan_server(
    root: Path,
    server_config: dict[str, object],
    files: dict[str, str] | None = None,
) -> tuple[MCPServerComponent, list[str]]:
    if files:
        for rel, content in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"srv": server_config}}),
        encoding="utf-8",
    )
    result = MCPScanner().scan(root, config_only=True)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    return server, result.surfaces_excluded


def test_confined_exact_name_blocks_case_variant_open(tmp_path: Path) -> None:
    (tmp_path / ".MCP.json").write_text('{"mcpServers": {}}', encoding="utf-8")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as collection:
        assert collection.read_text(".mcp.json", missing_ok=True) is None
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert any("case variant" in msg for msg in (*result.scan_failures, *result.surfaces_excluded))


@pytest.mark.parametrize("relative", ["notes.txt", "nested/notes.txt"])
def test_a_failed_exact_name_check_closes_what_it_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("text", encoding="utf-8")
    opened: list[int] = []
    real_open = os.open

    def recording_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def unlistable(self: ConfinedCollection, directory_fd: int, name: str) -> bool:
        raise PermissionError(errno.EACCES, "the directory cannot be listed")

    with ConfinedCollection(tmp_path, []) as collection:
        with monkeypatch.context() as patch:
            patch.setattr(os, "open", recording_open)
            patch.setattr(ConfinedCollection, "_has_exact_name", unlistable)
            assert collection.hash_file(relative) is None
        assert opened
        for fd in opened:
            with pytest.raises(OSError):
                os.fstat(fd)


def test_confined_default_excludes_and_policy_excludes_match_case_folded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ConfinedCollection, "_detect_root_folding", lambda self: True)
    git_variant = tmp_path / ".GIT"
    git_variant.mkdir()
    (git_variant / "config").write_text("secret", encoding="utf-8")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, exclude_paths=["BuildOut"]) as collection:
        assert collection.excluded(".GIT/config")
        assert collection.excluded("buildout/artifact.json")


def test_find_policy_path_rejects_case_variant_policy_filename(tmp_path: Path) -> None:
    (tmp_path / ".Nexus-Symbiote.yaml").write_text("fail_on_severity: critical\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="case-variant"):
        find_policy_path(tmp_path)


@pytest.mark.parametrize(
    "config",
    [
        {"command": "npx", "args": ["-y", "-p", "@acme/mcp@1.0.0", "./evil.sh"]},
        {"command": "npx", "args": ["-y", "-p", "@acme/mcp@1.0.0", "node", "evil.js"]},
        {"command": "uvx", "args": ["--from", "mcp==1.0.0", "python", "local_script.py"]},
        {"command": "pipx", "args": ["run", "--spec", "mcp==1.0.0", "./run.py"]},
        {"command": "npm", "args": ["exec", "@acme/mcp@1.0.0", "--package=evil@latest"]},
    ],
)
def test_package_runners_refuse_local_scripts_interpreters_and_post_positional_flags(
    tmp_path: Path, config: dict[str, object]
) -> None:
    server, gaps = _scan_server(tmp_path, config)
    assert server.version_pinned is False
    assert server.package_url is None
    assert any(
        r.category == "launcher_identity" and r.severity.value == "high" for r in server.risks
    )
    assert any("launcher identity unknown" in gap for gap in gaps)


@pytest.mark.parametrize(
    "mount_arg,expected_key,expected_severity",
    [
        ("./local_dir:/app", "host_mounts", None),
        ("../parent:/app", "broad_host_mount", "medium"),
        ("/var/run/docker.sock/:/var/run/docker.sock", "runtime_socket_mount", "high"),
        ("/etc/..:/host", "host_root_mount", "high"),
    ],
)
def test_container_volume_mount_normalizes_relative_socket_and_dotdot_paths(
    tmp_path: Path,
    mount_arg: str,
    expected_key: str,
    expected_severity: str | None,
) -> None:
    case_dir = tmp_path / expected_key
    case_dir.mkdir(parents=True, exist_ok=True)
    server, _ = _scan_server(
        case_dir,
        {"command": "docker", "args": ["run", "-v", mount_arg, "img@sha256:" + "a" * 64]},
    )
    assert server.properties["launch_context"].get(expected_key) == 1
    if expected_severity is not None:
        assert any(
            r.category == "launch_context" and r.severity.value == expected_severity
            for r in server.risks
        )


def test_bunfig_preload_marks_launcher_identity_unknown(tmp_path: Path) -> None:
    server, gaps = _scan_server(
        tmp_path,
        {"command": "bunx", "args": ["@acme/mcp@1.0.0"]},
        {"bunfig.toml": 'preload = ["./hook.ts"]\n'},
    )
    assert server.version_pinned is False
    assert server.package_url is None
    assert any(
        r.category == "launcher_identity" and "bunfig.toml preload" in r.detail
        for r in server.risks
    )
    assert any("launcher identity unknown" in gap for gap in gaps)


def test_uvx_reads_project_uv_toml_redirect(tmp_path: Path) -> None:
    server, _ = _scan_server(
        tmp_path,
        {"command": "uvx", "args": ["mcp-server==1.2.3"]},
        {"uv.toml": 'index-url = "https://pypi.attacker.test/simple"\n'},
    )
    assert server.launcher_package is None
    assert server.package_url is None
    assert "uv.toml:index-url=https://pypi.attacker.test" in server.properties["package_sources"]


def test_deno_reads_deno_json_import_redirects(tmp_path: Path) -> None:
    server, _ = _scan_server(
        tmp_path,
        {"command": "deno", "args": ["run", "npm:@acme/mcp@1.0.0"]},
        {"deno.json": json.dumps({"imports": {"@acme/mcp": "npm:evil@9.9.9"}})},
    )
    assert server.launcher_package is None
    assert server.package_url is None
    assert any(s.startswith("deno.json:imports=") for s in server.properties["package_sources"])


def test_deno_reads_deno_json_import_redirect_fallback_arrays(tmp_path: Path) -> None:
    server, _ = _scan_server(
        tmp_path,
        {"command": "deno", "args": ["run", "npm:@acme/mcp@1.0.0"]},
        {
            "deno.json": json.dumps(
                {"imports": {"@acme/mcp": ["npm:evil@9.9.9", "npm:other@1.0.0"]}}
            )
        },
    )
    assert server.launcher_package is None
    assert server.package_url is None
    # Fallback addresses are recorded as a redirect surface (values are
    # redacted to [local] in package_sources); before the fix the array form
    # recorded nothing at all.
    assert any(s.startswith("deno.json:imports=") for s in server.properties["package_sources"])


def test_cr_delimited_sse_completes_without_waiting_for_lf_or_eof() -> None:
    class KeepAliveCRStream:
        """Delivers one CR-delimited JSON-RPC SSE event, then blocks if polled again."""

        def __init__(self, first_chunk: bytes) -> None:
            self._chunks = [first_chunk]
            self.reads = 0

        def read1(self, size: int = -1) -> bytes:
            self.reads += 1
            if not self._chunks:
                raise AssertionError("stream polled past completed CR-delimited SSE event")
            chunk = self._chunks.pop(0)
            return chunk[:size] if size >= 0 else chunk

    event = b'event: message\rdata: {"jsonrpc":"2.0","id":7,"result":{"tools":[]}}\r\r'
    stream = KeepAliveCRStream(event)
    transport = live.PinnedHTTPTransport()
    raw = transport._read_sse(  # type: ignore[arg-type]
        stream,
        b'{"jsonrpc":"2.0","id":7,"method":"tools/list"}',
        maximum=4096,
    )
    assert raw == event
    assert stream.reads == 1


def test_secrets_redact_hf_tokens_raw_authorization_and_cookies() -> None:
    hf_tok = "hf_" + "A1b2C3d4E5" * 4
    assert secret_like("UNRELATED", hf_tok)
    assert redact_text(f"token is {hf_tok}") == f"token is {REDACTED}"
    assert redact_text("Authorization: rawSecretToken_12345") == f"Authorization: {REDACTED}"
    assert redact_text("Authorization: required") == "Authorization: required"
    assert (
        redact_text("Set-Cookie: sid=mySecretSession99; Path=/; HttpOnly")
        == f"Set-Cookie: sid={REDACTED}; Path=/; HttpOnly"
    )
    assert redact_text("Cookie: policy") == "Cookie: policy"


@pytest.mark.parametrize(
    "payload",
    [
        b"{{ x['\\x5f\\x5fclass\\x5f\\x5f'] }}",
        b"{{ x['\\u005f\\u005fglobals\\u005f\\u005f'] }}",
        b"{{ x['\\137\\137subclasses\\137\\137'] }}",
        b"{% set k = '__' ~ 'class__' %}{{ x[k] }}",
        b"{% set k = '__cla' + 'ss__' %}{{ x[k] }}",
    ],
)
def test_template_escape_markers_detect_escaped_and_concatenated_dunders(payload: bytes) -> None:
    assert template_escape_markers(payload) is True


def test_template_escape_markers_preserve_benign_chat_templates() -> None:
    benign = b"{% for m in messages %}{{ '<|im_start|>' + m['role'] + '\\n' + m['content'] }}{% endfor %}"
    assert template_escape_markers(benign) is False


@pytest.mark.parametrize("malformed", ["[,]", "{,}", "[1,,]", "[1,,2]", '{"a": ,}', ","])
def test_strip_jsonc_does_not_turn_leading_or_double_commas_into_valid_json(
    malformed: str,
) -> None:
    with pytest.raises(json.JSONDecodeError):
        json.loads(strip_jsonc(malformed))


def test_strip_jsonc_accepts_nested_valid_trailing_commas() -> None:
    parsed = json.loads(strip_jsonc('{"items": [1, 2, /* ok */ ], "nested": {"k": "v",},}'))
    assert parsed == {"items": [1, 2], "nested": {"k": "v"}}
