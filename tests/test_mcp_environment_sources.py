"""Environment that moves, replaces or configures a package runner is never silent.

A runner reads its user and global configuration, caches and programs from locations
its environment names. The collector reads no files there, so a location that may lie
in the project makes the launcher identity unknown; any other location, a replacement
and the runner's own settings are package sources that withhold the package identity.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner

RELOCATED = "environment relocates resolver configuration into the project"
SEARCHED = "PATH may search the project for the runner"
REPLACED = "environment replaces or constrains the launched package"

DIGEST = "0" * 64
RUNNERS = {
    "npx": ["-y", "safe-mcp@1.2.3"],
    "uvx": ["mcp-server-fetch==1.2.3"],
    "pipx": ["run", "mcp-server-fetch==1.2.3"],
    "go": ["run", "github.com/acme/mcp@v1.2.3"],
    "docker": ["run", "-i", "--rm", f"mcp/fetch@sha256:{DIGEST}"],
}
JS_RUNNERS = {
    "npx": ["-y", "safe-mcp@1.2.3"],
    "pnpm": ["dlx", "safe-mcp@1.2.3"],
    "yarn": ["dlx", "safe-mcp@1.2.3"],
    "bunx": ["safe-mcp@1.2.3"],
    "deno": ["run", "npm:safe-mcp@1.2.3"],
}
NPX = {"command": "npx", "args": RUNNERS["npx"]}
UVX = {"command": "uvx", "args": RUNNERS["uvx"]}
PIPX = {"command": "pipx", "args": RUNNERS["pipx"]}
GO = {"command": "go", "args": RUNNERS["go"]}
DOCKER = {"command": "docker", "args": RUNNERS["docker"]}
# Claude Desktop starts servers with a short PATH; configurations commonly widen it.
DESKTOP_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"

# Each location variable with a value that may name a directory in the project.
IN_PROJECT = {
    "HOME": ".home",
    "USERPROFILE": "profile",
    "APPDATA": "AppData\\Roaming",
    "LOCALAPPDATA": "%USERPROFILE%\\AppData\\Local",
    "XDG_CONFIG_HOME": "${workspaceFolder}/c",
    "XDG_CONFIG_DIRS": "/etc/xdg:c",
    "XDG_CACHE_HOME": ".cache",
    "XDG_DATA_HOME": "",
    "ZDOTDIR": ".",
    "PYTHONUSERBASE": "~/.python",
    "PATH": "./bin:/usr/bin",
}


def collect(
    root: Path, server: dict[str, Any], files: dict[str, str] | None = None
) -> tuple[MCPServerComponent, list[str]]:
    root.mkdir(parents=True, exist_ok=True)
    for name, text in (files or {}).items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
    result = MCPScanner().scan(root, config_only=True)
    assert not result.scan_failures, result.scan_failures
    [record] = [c for c in result.components if isinstance(c, MCPServerComponent)]
    return record, result.surfaces_excluded


def forms(command: str, args: list[str], variable: str, value: str) -> dict[str, dict[str, Any]]:
    """One assignment in the env map, through an env wrapper and inside a sh -c script."""
    script = f"{variable}={shlex.quote(value)} {shlex.join([command, *args])}"
    return {
        "env-map": {"command": command, "args": args, "env": {variable: value}},
        "env-wrapper": {"command": "env", "args": [f"{variable}={value}", command, *args]},
        "shell": {"command": "sh", "args": ["-c", script]},
    }


def identity_unknown(record: MCPServerComponent, gaps: list[str]) -> str:
    assert record.package_url is None and record.launcher_package is None
    assert record.version_pinned is False
    assert any("launcher identity unknown" in gap for gap in gaps), gaps
    finding = next(r for r in record.risks if r.category == "launcher_identity")
    assert finding.severity.value == "high"
    return finding.detail


@pytest.mark.parametrize("runner", sorted({**RUNNERS, **JS_RUNNERS}))
def test_each_runner_has_an_identity_without_environment(tmp_path, runner):
    args = {**RUNNERS, **JS_RUNNERS}[runner]
    record, gaps = collect(tmp_path, {"command": runner, "args": args})
    assert not gaps and record.launcher_package is not None and record.version_pinned is True
    assert "package_sources" not in record.properties


@pytest.mark.parametrize("runner", sorted(RUNNERS))
@pytest.mark.parametrize("variable", sorted(IN_PROJECT))
def test_a_location_that_may_lie_in_the_project_makes_the_identity_unknown(
    tmp_path, runner, variable
):
    for form, server in forms(runner, RUNNERS[runner], variable, IN_PROJECT[variable]).items():
        record, gaps = collect(tmp_path / form, server)
        detail = identity_unknown(record, gaps)
        if form == "env-map":
            assert (SEARCHED if variable == "PATH" else RELOCATED) in detail


@pytest.mark.parametrize("runner", sorted(JS_RUNNERS))
@pytest.mark.parametrize("variable,value", [("PREFIX", "p"), ("DESTDIR", "d"), ("HOME", ".")])
def test_npm_family_prefix_and_home_in_the_project_make_the_identity_unknown(
    tmp_path, runner, variable, value
):
    for form, server in forms(runner, JS_RUNNERS[runner], variable, value).items():
        record, gaps = collect(tmp_path / form, server)
        identity_unknown(record, gaps)


def test_goenv_in_the_project_makes_the_identity_unknown(tmp_path):
    files = {"go.env": "GOPROXY=https://goproxy.attacker.test\nGONOSUMDB=*\n"}
    for form, server in forms("go", RUNNERS["go"], "GOENV", "go.env").items():
        record, gaps = collect(tmp_path / form, server, files)
        assert RELOCATED in identity_unknown(record, gaps)


@pytest.mark.parametrize(
    "server",
    [
        {**UVX, "env": {"PREFIX": "p", "DESTDIR": "d", "GOENV": "go.env"}},
        {**GO, "env": {"PREFIX": "p", "GOOGLE_API_KEY": "AIza-not-a-go-setting", "GO_ENV": "x"}},
        {**NPX, "env": {"NODE_ENV": "production", "UV_INDEX_URL": "https://pypi.attacker.test/"}},
        {**UVX, "env": {"npm_config_registry": "https://npm.attacker.test/", "LOG_LEVEL": "info"}},
        {**DOCKER, "env": {"GOPROXY": "https://goproxy.attacker.test", "MCP_PORT": "8080"}},
    ],
)
def test_names_another_runner_reads_keep_the_identity(tmp_path, server):
    record, gaps = collect(tmp_path, server)
    assert not gaps and record.launcher_package is not None
    assert "package_sources" not in record.properties


@pytest.mark.parametrize(
    "variable,value",
    [
        ("HOME", "/srv/agent-home"),
        ("XDG_CONFIG_HOME", "/srv/agent-home/.config"),
        ("XDG_CONFIG_DIRS", "/etc/xdg:/srv/xdg"),
        ("ZDOTDIR", "/srv/zsh"),
        ("APPDATA", "C:\\Users\\agent\\AppData\\Roaming\\"),
        ("USERPROFILE", "\\\\fileserver\\profiles\\agent"),
        ("PREFIX", "/usr/local"),
    ],
)
def test_an_absolute_location_is_a_package_source(tmp_path, variable, value):
    record, gaps = collect(tmp_path, {**NPX, "env": {variable: value}})
    assert not gaps
    assert record.launcher_package is None and record.package_url is None
    assert record.version == "1.2.3" and record.version_pinned is True
    assert f"env:{variable}=[local]" in record.properties["package_sources"]
    finding = next(r for r in record.risks if r.category == "package_source")
    assert finding.severity.value == "medium" and f"env:{variable}" in finding.detail
    assert value not in record.model_dump_json()


@pytest.mark.parametrize("runner", sorted({**RUNNERS, **JS_RUNNERS}))
def test_a_path_of_absolute_directories_keeps_the_identity(tmp_path, runner):
    args = {**RUNNERS, **JS_RUNNERS}[runner]
    plain, _ = collect(tmp_path / "plain", {"command": runner, "args": args})
    for form, server in forms(runner, args, "PATH", DESKTOP_PATH).items():
        record, gaps = collect(tmp_path / form, server)
        assert not gaps, form
        assert record.launcher_package == plain.launcher_package, form
        assert record.package_url == plain.package_url, form
        assert "package_sources" not in record.properties, form


@pytest.mark.parametrize(
    "value",
    [
        "bin",
        "/usr/bin:",
        ":/usr/bin",
        "/usr/bin::/bin",
        "",
        "~/bin:/usr/bin",
        "${workspaceFolder}/bin:/usr/bin",
        "/opt/homebrew/bin:${PATH}",
        "$PATH:/opt/homebrew/bin",
        "/usr/bin;tools",
        "C:\\Program Files\\nodejs;C:\\Windows\\system32",
        "C:\\Windows",
    ],
)
@pytest.mark.parametrize("variable", ["PATH", "Path"])
def test_a_path_that_may_search_the_project_makes_the_identity_unknown(tmp_path, variable, value):
    record, gaps = collect(tmp_path, {**NPX, "env": {variable: value}})
    assert SEARCHED in identity_unknown(record, gaps)


def test_any_in_project_assignment_wins_over_an_absolute_one(tmp_path):
    server = {
        "command": "env",
        "args": ["HOME=.home", "npx", *RUNNERS["npx"]],
        "env": {"HOME": "/srv/agent-home"},
    }
    record, gaps = collect(tmp_path, server)
    assert RELOCATED in identity_unknown(record, gaps)


@pytest.mark.parametrize(
    "server",
    [
        {**UVX, "env": {"UV_OVERRIDE": "o.txt"}},
        {**UVX, "env": {"UV_CONSTRAINT": "/srv/constraints.txt"}},
        {
            "command": "uv",
            "args": ["tool", "run", *RUNNERS["uvx"]],
            "env": {"uv_build_constraint": "b"},
        },
        {
            "command": "uv",
            "args": ["run", "--with", "mcp==1.2.3", "s.py"],
            "env": {"UV_OVERRIDE": "o"},
        },
        {**PIPX, "env": {"PIP_CONSTRAINT": "https://evil.example/c.txt"}},
        {**PIPX, "env": {"PIP_REQUIREMENT": "r.txt"}},
        {**PIPX, "env": {"PIP_BUILD_CONSTRAINT": "b.txt"}},
        {"command": "env", "args": ["UV_OVERRIDE=o.txt", "uvx", *RUNNERS["uvx"]]},
        {"command": "sh", "args": ["-c", "PIP_CONSTRAINT=c.txt pipx run mcp-server-fetch==1.2.3"]},
    ],
)
def test_environment_that_replaces_or_constrains_the_package_makes_it_unknown(tmp_path, server):
    record, gaps = collect(tmp_path, server)
    detail = identity_unknown(record, gaps)
    if server["command"] not in {"env", "sh"}:
        assert REPLACED in detail


@pytest.mark.parametrize(
    "server,label",
    [
        ({**UVX, "env": {"UV_EXCLUDE_NEWER": "2025-01-01"}}, "env:UV_[other]=[local]"),
        ({**UVX, "env": {"uv_python": "./python"}}, "env:UV_[other]=[local]"),
        ({**UVX, "env": {"UV_ghp_Zx8Yw6Vu4Ts2Rq0Po8Nm6Lk4Jh2Gf0Ed8Cb6": "1"}}, "env:UV_[other]"),
        ({**PIPX, "env": {"PIP_TIMEOUT": "60"}}, "env:PIP_[other]=[local]"),
        ({**PIPX, "env": {"PIPX_DEFAULT_PYTHON": "/usr/bin/python3"}}, "env:PIPX_[other]"),
        (
            {"command": "yarn", "args": JS_RUNNERS["yarn"], "env": {"YARN_CHECKSUM_BEHAVIOR": "x"}},
            "env:YARN_[other]",
        ),
        (
            {"command": "bunx", "args": JS_RUNNERS["bunx"], "env": {"BUN_OPTIONS": "-r x"}},
            "env:BUN_",
        ),
        (
            {"command": "deno", "args": JS_RUNNERS["deno"], "env": {"DENO_V8_FLAGS": "x"}},
            "env:DENO_",
        ),
        ({**GO, "env": {"GOTOOLCHAIN": "go1.99.0"}}, "env:GO[other]=[local]"),
        ({**GO, "env": {"GOAUTH": "git dir"}}, "env:GO[other]"),
        ({**DOCKER, "env": {"DOCKER_DEFAULT_PLATFORM": "linux/amd64"}}, "env:DOCKER_[other]"),
        (
            {
                "command": "podman",
                "args": RUNNERS["docker"],
                "env": {"CONTAINERS_CONF_OVERRIDE": "c"},
            },
            "env:CONTAINERS_[other]",
        ),
        (
            {
                "command": "pnpm",
                "args": JS_RUNNERS["pnpm"],
                "env": {"COREPACK_NPM_REGISTRY": "https://npm.attacker.test/"},
            },
            "env:COREPACK_[other]=https://npm.attacker.test",
        ),
        (
            {"command": "yarn", "args": JS_RUNNERS["yarn"], "env": {"COREPACK_HOME": "./corepack"}},
            "env:COREPACK_[other]",
        ),
        (
            {"command": "env", "args": ["UV_EXCLUDE_NEWER=2025-01-01", "uvx", *RUNNERS["uvx"]]},
            "env:UV_[other]",
        ),
    ],
)
def test_a_runner_setting_from_its_own_namespace_is_a_package_source(tmp_path, server, label):
    record, gaps = collect(tmp_path, server)
    assert not gaps
    assert record.launcher_package is None and record.package_url is None
    assert any(source.startswith(label) for source in record.properties["package_sources"])
    assert any(r.category == "package_source" for r in record.risks)
    assert "ghp_" not in json.dumps(record.properties["package_sources"])


@pytest.mark.parametrize(
    "server",
    [
        {**UVX, "env": {"UV_NO_PROGRESS": "1"}},
        {**PIPX, "env": {"PIP_QUIET": "1", "PIP_PROGRESS_BAR": "off", "PIP_NO_COLOR": "1"}},
        {
            "command": "yarn",
            "args": JS_RUNNERS["yarn"],
            "env": {"YARN_ENABLE_PROGRESS_BARS": "false", "YARN_ENABLE_COLORS": "0"},
        },
        {
            "command": "pnpm",
            "args": JS_RUNNERS["pnpm"],
            "env": {"COREPACK_ENABLE_DOWNLOAD_PROMPT": "0"},
        },
        {**DOCKER, "env": {"DOCKER_CLI_HINTS": "false"}},
    ],
)
def test_display_settings_of_a_runner_keep_the_identity(tmp_path, server):
    record, gaps = collect(tmp_path, server)
    assert not gaps and record.launcher_package is not None
    assert "package_sources" not in record.properties


def test_the_npm_view_does_not_hide_runner_environment(tmp_path):
    env = {
        "npm_config_registry": "https://npm.attacker.test/",
        "HOME": "/srv/agent-home",
        "COREPACK_NPM_REGISTRY": "https://corepack.attacker.test/",
    }
    record, gaps = collect(tmp_path, {**NPX, "env": env})
    assert not gaps
    assert record.properties["package_sources"] == [
        "env:COREPACK_[other]=https://corepack.attacker.test",
        "env:HOME=[local]",
        "env:npm_config_registry=https://npm.attacker.test",
    ]


@pytest.mark.parametrize(
    "server,gap",
    [
        ({"command": "bash", "args": ["-lc", "npx -y safe-mcp@1.2.3"], "env": {"HOME": "."}}, True),
        (
            {"command": "zsh", "args": ["-c", "npx -y safe-mcp@1.2.3"], "env": {"ZDOTDIR": "."}},
            True,
        ),
        (
            {"command": "fish", "args": ["-c", "npx -y safe-mcp@1.2.3"], "env": {"HOME": "/srv/h"}},
            False,
        ),
        (
            {"command": "bash", "args": ["-lc", "node server.js"], "env": {"XDG_CONFIG_HOME": "c"}},
            False,
        ),
        ({"command": "python3", "args": ["server.py"], "env": {"HOME": "."}}, False),
        ({"command": "python3", "args": ["server.py"], "env": {"PYTHONUSERBASE": "/srv/b"}}, False),
    ],
)
def test_home_and_shell_startup_locations_change_code_loading(tmp_path, server, gap):
    record, gaps = collect(tmp_path, server)
    finding = next(
        r for r in record.risks if r.category == "launch_context" and r.severity.value == "medium"
    )
    assert "environment that changes code loading" in finding.detail
    assert record.properties["launch_context"]["code_loading_environment"] == 1
    assert bool(gaps) is gap


def write_project(root: Path, server: dict[str, Any], files: dict[str, str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))


def scan_cli(root: Path, output: Path, *extra: str):
    return CliRunner().invoke(
        main, ["scan", "--no-project-policy", *extra, str(root), "-o", str(output)]
    )


@pytest.mark.parametrize(
    "server,files",
    [
        (
            {**NPX, "env": {"HOME": ".home"}},
            {".home/.npmrc": "registry=https://npm.attacker.test/\n"},
        ),
        (
            {**UVX, "env": {"XDG_CONFIG_HOME": "${workspaceFolder}/c"}},
            {"c/uv/uv.toml": 'index-url = "https://pypi.attacker.test/simple"\n'},
        ),
        ({**PIPX, "env": {"HOME": "h"}}, {"h/.config/pip/pip.conf": "[global]\nindex-url = x\n"}),
        ({**GO, "env": {"GOENV": "go.env"}}, {"go.env": "GOPROXY=https://goproxy.attacker.test\n"}),
        ({**DOCKER, "env": {"HOME": "h"}}, {"h/.docker/config.json": '{"currentContext": "e"}\n'}),
        (
            {"command": "env", "args": ["PATH=./bin:/usr/bin", "npx", *RUNNERS["npx"]]},
            {"bin/npx": "#!/bin/sh\necho replaced\n"},
        ),
        (
            {**UVX, "env": {"UV_OVERRIDE": "o.txt"}},
            {"o.txt": "mcp-server-fetch @ https://x.test/w\n"},
        ),
        ({**PIPX, "env": {"PIP_CONSTRAINT": "c.txt"}}, {"c.txt": "mcp-server-fetch @ https://x\n"}),
    ],
    ids=["npx-home", "uvx-xdg", "pipx-home", "go-goenv", "docker-home", "env-path", "uv", "pip"],
)
def test_the_scan_gate_fails_when_environment_moves_the_runner_into_the_project(
    tmp_path, server, files
):
    root = tmp_path / "project"
    write_project(root, server, files)
    output = tmp_path / "bom.json"
    result = scan_cli(root, output)
    assert result.exit_code == 1, result.output
    assert "Scan gate failed" in result.output
    exported = output.read_text()
    assert "pkg:npm/safe-mcp" not in exported and "pkg:pypi/mcp-server-fetch" not in exported
    assert "launcher identity unknown" in exported


def test_an_absolute_home_is_reported_and_passes_the_gate(tmp_path):
    root = tmp_path / "project"
    write_project(root, {**NPX, "env": {"HOME": "/srv/agent-home"}}, {})
    output = tmp_path / "bom.json"
    result = scan_cli(root, output)
    assert result.exit_code == 0, result.output
    [server] = [c for c in json.loads(output.read_text())["components"] if c["name"] == "s"]
    assert server.get("package_url") is None and server.get("launcher_package") is None
    assert server["properties"]["package_sources"] == ["env:HOME=[local]"]


def test_a_desktop_path_keeps_the_package_url_through_the_cli(tmp_path):
    root = tmp_path / "project"
    write_project(root, {**NPX, "env": {"PATH": DESKTOP_PATH}}, {})
    output = tmp_path / "bom.json"
    result = scan_cli(root, output)
    assert result.exit_code == 0, result.output
    [server] = [c for c in json.loads(output.read_text())["components"] if c["name"] == "s"]
    assert server["package_url"] == "pkg:npm/safe-mcp@1.2.3"


def test_a_relocated_configuration_cannot_drift_past_the_gates_unnoticed(tmp_path):
    root = tmp_path / "project"
    benign = {".home/.npmrc": "registry=https://registry.npmjs.org/\n"}
    write_project(root, {**NPX, "env": {"HOME": ".home"}}, benign)
    baseline = tmp_path / "baseline.json"
    gate = scan_cli(root, baseline)
    assert gate.exit_code == 1 and "Scan gate failed" in gate.output
    (root / ".home/.npmrc").write_text("registry=https://npm.attacker.test/\n")
    candidate = tmp_path / "candidate.json"
    assert scan_cli(root, candidate, "--report-only").exit_code == 0
    validated = CliRunner().invoke(
        main, ["validate", "--no-project-policy", str(baseline), "--project", str(root)]
    )
    assert validated.exit_code == 1, validated.output
    assert RELOCATED in validated.output
    compared = CliRunner().invoke(main, ["diff", str(baseline), str(candidate), "--json-output"])
    notes = json.loads(compared.stdout)["notes"]
    assert any("baseline was already incomplete" in note["detail"] for note in notes)
