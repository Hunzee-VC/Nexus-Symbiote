"""npm configuration that may lie in the project makes the launcher identity unknown.

npm reads its user configuration from ``userconfig`` and its global configuration from
``globalconfig``, by default ``<prefix>/etc/npmrc``, and pnpm also reads
``<workspace-prefix>/.npmrc``. The environment, the project ``.npmrc`` and the command
line can each move them, and npm resolves a relative path against the working directory.
The collector reads no file there, so ``call``, ``package`` or ``registry`` added to one
would change what runs with nothing in the inventory changing; such a setting is treated
like ``HOME`` or ``PREFIX`` in the project. npm also expands ``${...}`` in setting names,
so a name holding one may spell any of them.
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
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV, MCPScanner

MOVES = "relocates resolver configuration into the project"
KEY = "k" * 40
PINNED = ["-y", "safe-mcp@1.2.3"]
NPX = {"command": "npx", "args": PINNED}
# Runners that read npm configuration from the environment and the project .npmrc.
NPM_READERS = {
    "npx": PINNED,
    "npm": ["exec", "--yes", "--package=safe-mcp@1.2.3", "--", "safe-mcp"],
    "pnpm": ["dlx", "safe-mcp@1.2.3"],
    "bunx": ["safe-mcp@1.2.3"],
    "deno": ["run", "npm:safe-mcp@1.2.3"],
}
# Runners that read no npm configuration.
OTHER_RUNNERS = {
    "yarn": ["dlx", "safe-mcp@1.2.3"],
    "uvx": ["mcp-server-fetch==1.2.3"],
    "pipx": ["run", "mcp-server-fetch==1.2.3"],
    "go": ["run", "github.com/acme/mcp@v1.2.3"],
    "docker": ["run", "-i", "--rm", "mcp/fetch@sha256:" + "0" * 64],
}
# npm matches npm_config_ in any case and lower-cases the key; pnpm reads pnpm_config_.
VARIABLES = {
    "npm_config_userconfig": "userconfig",
    "NPM_CONFIG_USERCONFIG": "userconfig",
    "Npm_Config_UserConfig": "userconfig",
    "pnpm_config_userconfig": "userconfig",
    "npm_config_globalconfig": "globalconfig",
    "NPM_CONFIG_GLOBALCONFIG": "globalconfig",
    "npm_config_prefix": "prefix",
    "NPM_CONFIG_PREFIX": "prefix",
    "npm_config_workspace_prefix": "workspace-prefix",
    "NPM_CONFIG_WORKSPACE_PREFIX": "workspace-prefix",
    # pnpm's workspace directory, whose .npmrc and pnpm-workspace.yaml it reads.
    "NPM_CONFIG_WORKSPACE_DIR": "workspace-dir",
    "npm_config_workspace_dir": "workspace-dir",
}
LOCATIONS = ["userconfig", "globalconfig", "prefix", "workspace-prefix"]
# Values npm resolves against the working directory or that may name it.
IN_PROJECT = [
    ".npmrc-ci",
    "./ci/npmrc",
    "ci",
    " ",
    "~/work/repo/repo/.npmrc-ci",
    "${workspaceFolder}/.npmrc-ci",
    "${PWD}/.npmrc-ci",
    "$PWD/.npmrc-ci",
    "%CD%\\.npmrc-ci",
    "/proc/self/cwd/.npmrc-ci",
    "/dev/fd/../self/cwd/.npmrc-ci",
    "/etc/../proc/self/cwd/.npmrc-ci",
    "C:\\ci\\npmrc",
]


def moved(key: str, source: str = "the environment") -> str:
    return f"npm {key} setting from {source} {MOVES}"


def collect(
    root: Path, server: dict[str, Any], files: dict[str, str] | None = None
) -> tuple[MCPServerComponent, list[str]]:
    write_project(root, server, files or {})
    result = MCPScanner().scan(root, config_only=True)
    assert not result.scan_failures, result.scan_failures
    [record] = [c for c in result.components if isinstance(c, MCPServerComponent)]
    return record, result.surfaces_excluded


def write_project(root: Path, server: dict[str, Any], files: dict[str, str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode())
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))


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


def identity_kept(record: MCPServerComponent, gaps: list[str]) -> None:
    assert not gaps, gaps
    assert record.version_pinned is True
    assert not any(r.category == "launcher_identity" for r in record.risks)


def a_medium_source(record: MCPServerComponent, gaps: list[str], label: str) -> None:
    identity_kept(record, gaps)
    assert record.launcher_package is None and record.package_url is None
    assert label in record.properties["package_sources"]
    finding = next(r for r in record.risks if r.category == "package_source")
    assert finding.severity.value == "medium"


@pytest.mark.parametrize("variable", sorted(VARIABLES))
def test_an_npm_configuration_location_in_the_project_makes_the_identity_unknown(
    tmp_path, variable
):
    for form, server in forms("npx", PINNED, variable, ".npmrc-ci").items():
        record, gaps = collect(tmp_path / form, server)
        detail = identity_unknown(record, gaps)
        assert moved(VARIABLES[variable]) in detail, form


def variable(key: str) -> str:
    return "npm_config_" + key.replace("-", "_")


@pytest.mark.parametrize("value", IN_PROJECT)
@pytest.mark.parametrize("key", LOCATIONS)
def test_any_location_npm_may_resolve_into_the_project_is_relocation(tmp_path, key, value):
    record, gaps = collect(tmp_path, {**NPX, "env": {variable(key): value}})
    assert moved(key) in identity_unknown(record, gaps)


@pytest.mark.parametrize("runner", sorted(NPM_READERS))
@pytest.mark.parametrize("key", LOCATIONS)
def test_every_runner_that_reads_npm_configuration_is_covered(tmp_path, runner, key):
    server = {"command": runner, "args": NPM_READERS[runner], "env": {variable(key): "c"}}
    record, gaps = collect(tmp_path, server)
    assert moved(key) in identity_unknown(record, gaps)


def test_the_finding_reproduction_is_a_gap_like_home(tmp_path):
    files = {".npmrc-ci": "fund=false\ncall=node ./postinstall-helper.js\n"}
    server = {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.1.14", "/data"],
        "env": {"npm_config_userconfig": ".npmrc-ci"},
    }
    record, gaps = collect(tmp_path / "userconfig", server, files)
    home, home_gaps = collect(tmp_path / "home", {**server, "env": {"HOME": "."}})
    assert moved("userconfig") in identity_unknown(record, gaps)
    assert MOVES in identity_unknown(home, home_gaps)
    assert gaps == [f".mcp.json: MCP server 's' launcher identity unknown ({moved('userconfig')})"]
    assert len(home_gaps) == 1
    assert "env:npm_config_userconfig=[local]" in record.properties["package_sources"]


def test_an_in_project_assignment_wins_over_an_absolute_one(tmp_path):
    server = {
        "command": "env",
        "args": ["npm_config_userconfig=.npmrc-ci", "npx", *PINNED],
        "env": {"npm_config_userconfig": "/srv/agent/.npmrc"},
    }
    record, gaps = collect(tmp_path, server)
    assert moved("userconfig") in identity_unknown(record, gaps)


@pytest.mark.parametrize(
    "variable",
    [
        "npm_config_${e}userconfig",
        "npm_config_user${e}config",
        "NPM_CONFIG_${E}GLOBALCONFIG",
        "npm_config_${e}prefix",
        "npm_config_${key}",
        "npm_config_${e}call",
        "npm_config_${e}package",
    ],
)
def test_a_variable_name_npm_may_expand_to_what_runs_makes_the_identity_unknown(tmp_path, variable):
    # npm expands ${e} in the name after lower-casing it, so e="" spells the setting.
    server = {**NPX, "env": {variable: ".npmrc-ci", "e": "", "E": "", "key": "userconfig"}}
    record, gaps = collect(tmp_path, server)
    assert "npm setting name with ${...} from the environment" in identity_unknown(record, gaps)


@pytest.mark.parametrize(
    "variable,value",
    [
        ("npm_config_userconfig", "/srv/agent/.npmrc"),
        ("NPM_CONFIG_USERCONFIG", "/home/runner/work/_temp/.npmrc"),
        ("npm_config_globalconfig", "/etc/npmrc"),
        ("npm_config_prefix", "/usr/local"),
        ("npm_config_prefix", "/opt/node22/"),
        ("NPM_CONFIG_WORKSPACE_PREFIX", "/srv/agent/workspace"),
        ("NPM_CONFIG_WORKSPACE_DIR", "/srv/agent/workspace"),
    ],
)
def test_an_absolute_npm_configuration_location_is_a_package_source(tmp_path, variable, value):
    record, gaps = collect(tmp_path, {**NPX, "env": {variable: value}})
    a_medium_source(record, gaps, f"env:{variable}=[local]")
    assert value not in record.model_dump_json()


@pytest.mark.parametrize("key", [*LOCATIONS, "workspace-dir"])
def test_an_empty_variable_npm_ignores_keeps_the_identity(tmp_path, key):
    record, gaps = collect(tmp_path, {**NPX, "env": {variable(key): ""}})
    identity_kept(record, gaps)
    assert record.package_url == "pkg:npm/safe-mcp@1.2.3"


@pytest.mark.parametrize(
    "variable",
    [
        "npm_config_user_config",
        "npm_config__userconfig",
        "npm_config_userconfig_dir",
        "NPM_USERCONFIG",
        "npmconfig_userconfig",
        "npm_config_${e}registry",
        "npm_config_${e}save_exact",
        "npm_config_userconfig${e}x",
    ],
)
def test_names_npm_does_not_read_as_a_location_are_not_relocation(tmp_path, variable):
    record, gaps = collect(tmp_path, {**NPX, "env": {variable: ".npmrc-ci"}})
    assert not gaps, gaps
    assert not any(r.category == "launcher_identity" for r in record.risks)


@pytest.mark.parametrize("runner", sorted(OTHER_RUNNERS))
def test_runners_that_read_no_npm_configuration_keep_the_identity(tmp_path, runner):
    env = {
        "npm_config_userconfig": ".npmrc-ci",
        "npm_config_globalconfig": "g",
        "npm_config_prefix": ".",
    }
    server = {"command": runner, "args": OTHER_RUNNERS[runner], "env": env}
    record, gaps = collect(tmp_path, server)
    identity_kept(record, gaps)
    assert record.launcher_package is not None


@pytest.mark.parametrize(
    "npmrc,key",
    [
        ("userconfig=.npmrc-ci\n", "userconfig"),
        ("globalconfig=ci/npmrc\n", "globalconfig"),
        ("prefix=ci\n", "prefix"),
        # An empty prefix is the working directory, so npm reads ./etc/npmrc.
        ("prefix=\n", "prefix"),
        ("prefix\n", "prefix"),
        ('"userconfig" = "./.npmrc-ci"\n', "userconfig"),
        ("'globalconfig'='ci/npmrc'\n", "globalconfig"),
        ('"\\u0075serconfig"=.npmrc-ci\n', "userconfig"),
        ("\ufeffuserconfig=.npmrc-ci\n", "userconfig"),
        ("\tuserconfig\t=\t./ci/.npmrc ; trailing comment\n", "userconfig"),
        ("fund=false\rprefix=ci\r", "prefix"),
        ("userconfig=${CI_NPMRC}\n", "userconfig"),
        ("userconfig=~/work/repo/repo/.npmrc-ci\n", "userconfig"),
        ("userconfig=/proc/self/cwd/.npmrc-ci\n", "userconfig"),
        ("save-exact=true\nglobalconfig=g\nuserconfig=/etc/npmrc\n", "globalconfig"),
        ("workspace-prefix=cfg\n", "workspace-prefix"),
        ("workspace-prefix=\n", "workspace-prefix"),
    ],
)
def test_a_project_npmrc_that_moves_npm_configuration_makes_the_identity_unknown(
    tmp_path, npmrc, key
):
    record, gaps = collect(tmp_path, NPX, {".npmrc": npmrc})
    detail = identity_unknown(record, gaps)
    assert moved(key, ".npmrc") in detail
    assert f".npmrc:{key}=" in " ".join(record.properties["package_sources"])


@pytest.mark.parametrize(
    "npmrc",
    [
        "${E}userconfig=.npmrc-ci\n",
        "user${E}config=.npmrc-ci\n",
        "${KEY}=.npmrc-ci\n",
        "${E}globalconfig=/etc/npmrc\n",
        "${E}call=node ./postinstall-helper.js\n",
        "${E}package=evil-mcp@1.0.0\n",
        '"${E}userconfig"=.npmrc-ci\n',
        "save-exact=true\n${E}prefix=ci\n",
        "${E}workspace-prefix=cfg\n",
        "${E}-prefix=cfg\n",
    ],
)
def test_an_npmrc_name_npm_may_expand_to_what_runs_makes_the_identity_unknown(tmp_path, npmrc):
    server = {**NPX, "env": {"E": "", "KEY": "userconfig"}}
    record, gaps = collect(tmp_path, server, {".npmrc": npmrc})
    assert "npm setting name with ${...} from .npmrc" in identity_unknown(record, gaps)
    assert ".npmrc:key=[unresolved]" in record.properties["package_sources"]


@pytest.mark.parametrize("runner", sorted(NPM_READERS))
def test_every_runner_that_reads_the_project_npmrc_is_covered(tmp_path, runner):
    server = {"command": runner, "args": NPM_READERS[runner]}
    record, gaps = collect(tmp_path, server, {".npmrc": "userconfig=.npmrc-ci\n"})
    assert moved("userconfig", ".npmrc") in identity_unknown(record, gaps)


@pytest.mark.parametrize(
    "npmrc,label",
    [
        ("userconfig=/etc/ci/npmrc\n", ".npmrc:userconfig=[local]"),
        ("globalconfig=/etc/npmrc\n", ".npmrc:globalconfig=[local]"),
        ("prefix=/usr/local\n", ".npmrc:prefix=[local]"),
        ("workspace-prefix=/srv/agent/workspace\n", ".npmrc:workspace-prefix=[local]"),
        # pnpm reads its workspace directory from the environment only.
        ("workspace-dir=cfg\n", ".npmrc:workspace-dir=[local]"),
    ],
)
def test_an_absolute_location_in_the_project_npmrc_is_a_package_source(tmp_path, npmrc, label):
    record, gaps = collect(tmp_path, NPX, {".npmrc": npmrc})
    a_medium_source(record, gaps, label)


@pytest.mark.parametrize(
    "npmrc",
    [
        "[section]\nuserconfig=.npmrc-ci\n",
        "; userconfig=.npmrc-ci\n",
        "# prefix=ci\n",
        "//registry.npmjs.org/:userconfig=.npmrc-ci\n",
        "save-exact=true\nfund=false\n",
    ],
)
def test_npmrc_lines_npm_does_not_read_as_a_location_keep_the_identity(tmp_path, npmrc):
    record, gaps = collect(tmp_path, NPX, {".npmrc": npmrc})
    identity_kept(record, gaps)
    assert record.package_url == "pkg:npm/safe-mcp@1.2.3"


@pytest.mark.parametrize(
    "npmrc",
    [
        "//${NPM_REGISTRY_HOST}/:_authToken=${NPM_TOKEN}\n",
        "@${NPM_SCOPE}:registry=https://npm.acme.test/\n",
        "${NPM_SCOPE}:registry=https://npm.acme.test/\n",
        "${E}save-exact=true\n",
        "userconfig${E}x=.npmrc-ci\n",
        "\\${E}userconfig=.npmrc-ci\n",
    ],
)
def test_an_npmrc_name_that_cannot_expand_to_what_runs_stays_unresolved(tmp_path, npmrc):
    record, gaps = collect(tmp_path, NPX, {".npmrc": npmrc})
    identity_kept(record, gaps)
    assert ".npmrc:key=[unresolved]" in record.properties["package_sources"]


@pytest.mark.parametrize(
    "server,option",
    [
        ({"command": "npx", "args": ["--userconfig", ".npmrc-ci", *PINNED]}, "npx --userconfig"),
        ({"command": "npx", "args": ["--userconfig=.npmrc-ci", *PINNED]}, "npx --userconfig"),
        ({"command": "npx", "args": ["--globalconfig", "ci/npmrc", *PINNED]}, "npx --globalconfig"),
        ({"command": "npx", "args": ["--prefix", "ci", *PINNED]}, "npx --prefix"),
        ({"command": "npx", "args": ["--prefix=", *PINNED]}, "npx --prefix"),
        ({"command": "npx", "args": ["-C", ".", *PINNED]}, "npx -C"),
        (
            {"command": "npm", "args": ["--userconfig", "c", *NPM_READERS["npm"]]},
            "npm exec --userconfig",
        ),
        (
            {"command": "npm", "args": ["exec", "--prefix=ci", *NPM_READERS["npm"][1:]]},
            "npm exec --prefix",
        ),
        ({"command": "sh", "args": ["-c", "npx --userconfig c -y safe-mcp@1.2.3"]}, None),
        (
            {"command": "env", "args": ["npx", "--globalconfig", "${workspaceFolder}/g", *PINNED]},
            None,
        ),
    ],
)
def test_a_launcher_option_that_moves_npm_configuration_makes_the_identity_unknown(
    tmp_path, server, option
):
    record, gaps = collect(tmp_path, server)
    detail = identity_unknown(record, gaps)
    if option is not None:
        assert f"{option} {MOVES}" in detail


@pytest.mark.parametrize(
    "args", [[*PINNED, "--userconfig", ".npmrc-ci"], [*PINNED, "--prefix=."], [*PINNED, "-C", "."]]
)
def test_options_after_the_package_are_its_own_arguments(tmp_path, args):
    # npx puts -- before the first positional, so npm reads none of the words after it.
    record, gaps = collect(tmp_path, {"command": "npx", "args": args})
    identity_kept(record, gaps)
    assert record.package_url == "pkg:npm/safe-mcp@1.2.3"


@pytest.mark.parametrize(
    "args,label",
    [
        (["--userconfig", "/etc/ci/npmrc", *PINNED], "--userconfig=[local]"),
        (["--globalconfig=/etc/npmrc", *PINNED], "--globalconfig=[local]"),
        (["--prefix", "/usr/local", *PINNED], "--prefix=[local]"),
    ],
)
def test_an_absolute_launcher_option_is_a_package_source(tmp_path, args, label):
    record, gaps = collect(tmp_path, {"command": "npx", "args": args})
    a_medium_source(record, gaps, label)


def scan_cli(root: Path, output: Path, *extra: str):
    return CliRunner().invoke(
        main, ["scan", "--no-project-policy", *extra, str(root), "-o", str(output)]
    )


@pytest.mark.parametrize(
    "server,files",
    [
        ({**NPX, "env": {"npm_config_userconfig": ".npmrc-ci"}}, {".npmrc-ci": "fund=false\n"}),
        ({**NPX, "env": {"npm_config_globalconfig": "g"}}, {"g": "fund=false\n"}),
        ({**NPX, "env": {"NPM_CONFIG_PREFIX": "p"}}, {"p/etc/npmrc": "fund=false\n"}),
        (NPX, {".npmrc": "userconfig=.npmrc-ci\n", ".npmrc-ci": "fund=false\n"}),
        ({"command": "npx", "args": ["--userconfig", "c", *PINNED]}, {"c": "fund=false\n"}),
    ],
    ids=["env-userconfig", "env-globalconfig", "env-prefix", "npmrc-userconfig", "option"],
)
def test_the_scan_gate_fails_when_npm_configuration_moves_into_the_project(
    tmp_path, monkeypatch, server, files
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    write_project(root, server, files)
    output = tmp_path / "bom.json"
    result = scan_cli(root, output)
    assert result.exit_code == 1, result.output
    assert "Scan gate failed" in result.output
    exported = output.read_text()
    assert "pkg:npm/safe-mcp" not in exported
    assert "launcher identity unknown" in exported


def test_an_absolute_npm_configuration_location_passes_the_gate(tmp_path):
    root = tmp_path / "project"
    write_project(root, {**NPX, "env": {"npm_config_userconfig": "/srv/agent/.npmrc"}}, {})
    output = tmp_path / "bom.json"
    result = scan_cli(root, output)
    assert result.exit_code == 0, result.output
    [server] = [c for c in json.loads(output.read_text())["components"] if c["name"] == "s"]
    assert server["properties"]["package_sources"] == ["env:npm_config_userconfig=[local]"]


def test_a_setting_added_to_the_named_file_cannot_drift_past_the_gates(tmp_path, monkeypatch):
    # The finding: the keyed diff saw no change when only the named file gained a setting.
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    server = {**NPX, "env": {"npm_config_userconfig": ".npmrc-ci"}}
    write_project(root, server, {".npmrc-ci": "fund=false\n"})
    baseline = tmp_path / "baseline.json"
    gate = scan_cli(root, baseline)
    assert gate.exit_code == 1 and "Scan gate failed" in gate.output
    (root / ".npmrc-ci").write_text("fund=false\nnode-options=--require ./postinstall-helper.js\n")
    candidate = tmp_path / "candidate.json"
    assert scan_cli(root, candidate, "--report-only").exit_code == 0
    validated = CliRunner().invoke(
        main, ["validate", "--no-project-policy", str(baseline), "--project", str(root)]
    )
    assert validated.exit_code == 1, validated.output
    assert moved("userconfig") in validated.output
    compared = CliRunner().invoke(main, ["diff", str(baseline), str(candidate), "--json-output"])
    notes = json.loads(compared.stdout)["notes"]
    assert any("baseline was already incomplete" in note["detail"] for note in notes)


def test_moving_a_reviewed_location_into_the_project_is_an_alert(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    write_project(root, {**NPX, "env": {"npm_config_userconfig": "/srv/agent/.npmrc"}}, {})
    baseline = tmp_path / "baseline.json"
    assert scan_cli(root, baseline).exit_code == 0
    server = {**NPX, "env": {"npm_config_userconfig": ".npmrc-ci"}}
    write_project(root, server, {".npmrc-ci": "call=node ./postinstall-helper.js\n"})
    candidate = tmp_path / "candidate.json"
    assert scan_cli(root, candidate, "--report-only").exit_code == 0
    compared = CliRunner().invoke(main, ["diff", str(baseline), str(candidate), "--fail-on-alert"])
    assert compared.exit_code == 1, compared.output
    assert moved("userconfig") in compared.output


COMMIT = "0123456789abcdef0123456789abcdef01234567"
# Full-commit git launches keep a known identity, and npm reads its configuration for them.
GIT_LAUNCHES = {
    "npx": ["-y", f"github:acme/mcp-server#{COMMIT}"],
    "npx-git+https": ["-y", f"git+https://git.acme.test/acme/mcp-server.git#{COMMIT}"],
    "npm": ["exec", "--yes", f"--package=github:acme/mcp-server#{COMMIT}", "--", "mcp-server"],
    "pnpm": ["dlx", f"github:acme/mcp-server#{COMMIT}"],
}


def git_server(launch: str, *options: str) -> dict[str, Any]:
    command = launch.split("-", 1)[0]
    args = GIT_LAUNCHES[launch]
    if command == "npx":
        return {"command": command, "args": [*options, *args]}
    return {"command": command, "args": [args[0], *options, *args[1:]]}


@pytest.mark.parametrize("launch", sorted(GIT_LAUNCHES))
def test_a_pinned_git_launch_keeps_its_identity_without_relocation(tmp_path, launch):
    record, gaps = collect(tmp_path, git_server(launch), {".npmrc": "fund=false\n"})
    identity_kept(record, gaps)


@pytest.mark.parametrize("launch", sorted(GIT_LAUNCHES))
@pytest.mark.parametrize("option", ["--userconfig", "--prefix"])
def test_a_location_option_moves_npm_configuration_for_a_pinned_git_launch(
    tmp_path, launch, option
):
    record, gaps = collect(tmp_path, git_server(launch, option, ".npmrc-ci"))
    detail = identity_unknown(record, gaps)
    # pnpm dlx takes neither option, so its launch is already unrecognised.
    assert f"{option} {MOVES}" in detail or "unrecognised pnpm dlx option" in detail


@pytest.mark.parametrize("launch", sorted(GIT_LAUNCHES))
@pytest.mark.parametrize(
    "npmrc,reason",
    [
        ("userconfig=.npmrc-ci\n", moved("userconfig", ".npmrc")),
        ("call=node ./postinstall-helper.js\n", "npm call setting from .npmrc"),
        ("${E}globalconfig=g\n", "npm setting name with ${...} from .npmrc"),
    ],
)
def test_the_project_npmrc_is_read_for_a_pinned_git_launch(tmp_path, launch, npmrc, reason):
    record, gaps = collect(tmp_path, git_server(launch), {".npmrc": npmrc})
    assert reason in identity_unknown(record, gaps)


def test_a_code_loading_npmrc_setting_is_recorded_for_a_pinned_git_launch(tmp_path):
    files = {".npmrc": "node-options=--require ./evil.js\n"}
    record, gaps = collect(tmp_path, git_server("npx"), files)
    identity_kept(record, gaps)
    assert record.properties["launch_context"]["code_loading_setting"] == 1


@pytest.mark.parametrize("option", ["--userconfig", "--prefix"])
@pytest.mark.parametrize("form", ["option", "npmrc"])
def test_the_gate_fails_for_a_pinned_git_launch_that_moves_npm_configuration(
    tmp_path, monkeypatch, option, form
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    files = {".npmrc-ci": "fund=false\n"}
    if form == "option":
        server = git_server("npx", option, ".npmrc-ci")
    else:
        server = git_server("npx")
        files[".npmrc"] = f"{option[2:]}=.npmrc-ci\n"
    write_project(root, server, files)
    result = scan_cli(root, tmp_path / "bom.json")
    assert result.exit_code == 1, result.output
    assert "Scan gate failed" in result.output


@pytest.mark.parametrize(
    "server",
    [
        {"command": "npm", "args": ["run", "mcp"]},
        {"command": "pnpm", "args": ["run", "mcp"]},
        {"command": "bun", "args": ["run", "mcp"]},
        {"command": "deno", "args": ["run", "--allow-net", "server.ts"]},
    ],
)
@pytest.mark.parametrize(
    "npmrc,reason",
    [
        ("userconfig=.npmrc-ci\n", moved("userconfig", ".npmrc")),
        ("${E}prefix=ci\n", "npm setting name with ${...} from .npmrc"),
    ],
)
def test_a_launch_without_a_package_still_sees_a_moved_npm_configuration(
    tmp_path, server, npmrc, reason
):
    record, gaps = collect(tmp_path, server, {".npmrc": npmrc})
    assert any(reason in gap for gap in gaps), gaps


@pytest.mark.parametrize(
    "npmrc",
    [
        "${E}call=node ./evil.js\n//${NPM_REGISTRY_HOST}/:_authToken=${NPM_TOKEN}\n",
        "${E}userconfig=.npmrc-ci\n${E}save-exact=true\n",
    ],
)
def test_a_later_harmless_unresolved_name_keeps_an_earlier_finding(tmp_path, npmrc):
    record, gaps = collect(tmp_path, {**NPX, "env": {"E": ""}}, {".npmrc": npmrc})
    assert "npm setting name with ${...} from .npmrc" in identity_unknown(record, gaps)


@pytest.mark.parametrize("npmrc", ["call${E}all=x\n", "prefix${E}prefix=x\n"])
def test_a_name_longer_than_any_setting_it_starts_and_ends_like_stays_unresolved(tmp_path, npmrc):
    record, gaps = collect(tmp_path, NPX, {".npmrc": npmrc})
    identity_kept(record, gaps)
    assert ".npmrc:key=[unresolved]" in record.properties["package_sources"]


@pytest.mark.parametrize("npmrc", ["${E}node-options=--require ./evil.js\n", "${E}=./evil.js\n"])
def test_an_unresolved_name_that_may_load_code_is_recorded(tmp_path, npmrc):
    record, _ = collect(tmp_path, {**NPX, "env": {"E": ""}}, {".npmrc": npmrc})
    assert record.properties["launch_context"]["code_loading_setting"] == 1


@pytest.mark.parametrize(
    "after",
    [
        "${E}node-options=--require ./evil.js\n",
        "${E}script-shell=./evil.sh\n",
        "${E}registry=https://npm.attacker.test/\n",
        "${E}fund=true\n",
    ],
)
def test_rewriting_an_unresolved_npmrc_line_is_an_alert(tmp_path, monkeypatch, after):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    server = {**NPX, "env": {"E": ""}}
    write_project(root, server, {".npmrc": "${E}fund=false\n"})
    baseline = tmp_path / "baseline.json"
    assert scan_cli(root, baseline).exit_code == 0
    write_project(root, server, {".npmrc": after})
    candidate = tmp_path / "candidate.json"
    assert scan_cli(root, candidate, "--report-only").exit_code == 0
    compared = CliRunner().invoke(main, ["diff", str(baseline), str(candidate), "--fail-on-alert"])
    assert compared.exit_code == 1, compared.output
    assert "static source binding changed" in compared.output


def test_an_unresolved_npmrc_line_is_an_unbound_value_without_the_key(tmp_path):
    record, _ = collect(tmp_path, {**NPX, "env": {"E": ""}}, {".npmrc": "${E}fund=false\n"})
    completeness = [r.detail for r in record.risks if r.category == "completeness"]
    assert any("project resolver settings" in detail for detail in completeness), completeness


PNPM_DLX = {"command": "pnpm", "args": NPM_READERS["pnpm"]}
# pnpm reads <workspace-prefix>/.npmrc after the project .npmrc, and takes the
# workspace directory from NPM_CONFIG_WORKSPACE_DIR, upper or lower case.
PNPM_WORKSPACE_FORMS = {
    "npmrc": ({}, {".npmrc": "workspace-prefix=cfg\n"}, moved("workspace-prefix", ".npmrc")),
    "env-prefix": ({"NPM_CONFIG_WORKSPACE_PREFIX": "cfg"}, {}, moved("workspace-prefix")),
    "env-prefix-lower": ({"npm_config_workspace_prefix": "cfg"}, {}, moved("workspace-prefix")),
    "env-dir": ({"NPM_CONFIG_WORKSPACE_DIR": "cfg"}, {}, moved("workspace-dir")),
    "env-dir-lower": ({"npm_config_workspace_dir": "cfg"}, {}, moved("workspace-dir")),
}


@pytest.mark.parametrize("form", sorted(PNPM_WORKSPACE_FORMS))
def test_a_pnpm_workspace_location_in_the_project_makes_the_identity_unknown(tmp_path, form):
    env, files, reason = PNPM_WORKSPACE_FORMS[form]
    files = {**files, "cfg/.npmrc": "registry=https://registry.attacker.test/\n"}
    record, gaps = collect(tmp_path, {**PNPM_DLX, "env": env}, files)
    assert reason in identity_unknown(record, gaps)


@pytest.mark.parametrize("form", sorted(PNPM_WORKSPACE_FORMS))
def test_the_scan_gate_fails_when_a_pnpm_workspace_moves_into_the_project(
    tmp_path, monkeypatch, form
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    env, files, reason = PNPM_WORKSPACE_FORMS[form]
    root = tmp_path / "project"
    write_project(root, {**PNPM_DLX, "env": env}, {**files, "cfg/.npmrc": "fund=false\n"})
    output = tmp_path / "bom.json"
    result = scan_cli(root, output)
    assert result.exit_code == 1, result.output
    assert reason in output.read_text()


# npm reads its options after the script name of npm run, start or test too, up to a
# word of only dashes, with any number of dashes, abbreviated or in a shorthand cluster.
AFTER_THE_SCRIPT = [
    (["start", "--userconfig=.npmrc-ci"], "npm start --userconfig"),
    (["test", "--prefix", "."], "npm test --prefix"),
    (["run-script", "start", "-C", "."], "npm run-script -C"),
    (["run", "mcp", "--globalconfig", "etc/npmrc"], "npm run --globalconfig"),
    (["run", "mcp", "server", "--userconfig", ".npmrc-ci"], "npm run --userconfig"),
    (["start", "--usercon=.npmrc-ci"], "npm start --userconfig"),
    (["start", "--userc", ".npmrc-ci"], "npm start --userconfig"),
    (["start", "--globalc=etc/npmrc"], "npm start --globalconfig"),
    (["start", "---userconfig=.npmrc-ci"], "npm start --userconfig"),
    (["start", "-userconfig=.npmrc-ci"], "npm start --userconfig"),
    (["start", "-C=."], "npm start -C"),
    (["start", "--C", "."], "npm start -C"),
    (["start", "-gC", "."], "npm start -C"),
    (["start", "--gC", "."], "npm start -C"),
    (["start", "-yC=."], "npm start -C"),
    # -Cy takes --yes as the prefix, so the absolute word after it is not its value.
    (["start", "-Cy", "/srv/agent"], "npm start -C"),
    # In -CC the first --prefix takes the second as its path, ./--prefix.
    (["start", "-CC", "/srv/agent"], "npm start -C"),
    (["start", "-CC=/srv/agent"], "npm start -C"),
    (["start", "-gCC", "/srv/agent"], "npm start -C"),
    (["start", "-CgC", "/srv/agent"], "npm start -C"),
    (["start", "--prefix"], "npm start --prefix"),
    (["start", "--prefix", "--"], "npm start --prefix"),
    (["stop", "--userconfig", "${workspaceFolder}/.npmrc-ci"], "npm stop --userconfig"),
]


@pytest.mark.parametrize("args,reason", AFTER_THE_SCRIPT)
def test_a_location_option_after_the_script_name_makes_the_identity_unknown(tmp_path, args, reason):
    record, gaps = collect(tmp_path, {"command": "npm", "args": args})
    finding = next(r for r in record.risks if r.category == "launcher_identity")
    assert finding.severity.value == "high"
    assert f"{reason} {MOVES}" in finding.detail
    assert gaps == [f".mcp.json: MCP server 's' launcher identity unknown ({reason} {MOVES})"]


@pytest.mark.parametrize(
    "args",
    [
        ["start"],
        ["start", "--", "--userconfig", ".npmrc-ci"],
        ["start", "---", "--prefix", "."],
        ["run", "mcp", "--", "-C", "."],
        ["start", "--no-userconfig"],
        ["start", "--global"],
        ["start", "--prefer-offline"],
        ["start", "-p"],
        ["start", "-C."],
        ["start", "--userconfig-dir=.npmrc-ci"],
        ["start", "C", "."],
    ],
)
def test_words_npm_does_not_read_as_a_location_after_the_script_name_are_not_relocation(
    tmp_path, args
):
    record, gaps = collect(tmp_path, {"command": "npm", "args": args})
    assert not gaps, gaps
    assert not any(r.category == "launcher_identity" for r in record.risks)


@pytest.mark.parametrize(
    "args,label",
    [
        (["start", "--userconfig", "/srv/agent/.npmrc"], "--userconfig=[local]"),
        (["start", "-gC", "/srv/agent"], "-C=[local]"),
        (["start", "-gC=/srv/agent"], "-C=[local]"),
    ],
)
def test_an_absolute_location_after_the_script_name_is_a_package_source(tmp_path, args, label):
    record, gaps = collect(tmp_path, {"command": "npm", "args": args})
    assert not gaps, gaps
    assert not any(r.category == "launcher_identity" for r in record.risks)
    assert label in record.properties["package_sources"]


@pytest.mark.parametrize(
    "args", [["start", "--userconfig=.npmrc-ci"], ["--userconfig=.npmrc-ci", "start"]]
)
def test_the_scan_gate_fails_for_a_location_on_either_side_of_the_script_name(
    tmp_path, monkeypatch, args
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    files = {"package.json": '{"scripts": {"start": "node server.js"}}', ".npmrc-ci": "x=1\n"}
    write_project(root, {"command": "npm", "args": args}, files)
    output = tmp_path / "bom.json"
    result = scan_cli(root, output)
    assert result.exit_code == 1, result.output
    assert "Scan gate failed" in result.output


PNPX = {"command": "pnpx", "args": ["safe-mcp@1.2.3"]}
BUNX = {"command": "bunx", "args": NPM_READERS["bunx"]}
DENO = {"command": "deno", "args": NPM_READERS["deno"]}
# pnpm reads .npmrc with an older ini than npm's, whose section header takes no trailing
# whitespace: `[x] ` is a key there, and the lines after it are top-level settings.
LOOSE_SECTIONS = ["[x] ", "[x]\t", "[x]\u00a0", "[x]\u3000", "[ci] \t"]


@pytest.mark.parametrize("server", [PNPM_DLX, PNPX], ids=["pnpm-dlx", "pnpx"])
@pytest.mark.parametrize("header", LOOSE_SECTIONS)
@pytest.mark.parametrize("key", LOCATIONS)
def test_pnpm_reads_a_location_after_a_section_header_with_trailing_whitespace(
    tmp_path, server, header, key
):
    files = {".npmrc": f"{header}\n{key}=cfg\n"}
    record, gaps = collect(tmp_path, server, files)
    assert moved(key, ".npmrc") in identity_unknown(record, gaps)


def test_pnpm_reads_a_registry_after_a_section_header_with_trailing_whitespace(tmp_path):
    files = {".npmrc": "[x] \nregistry=https://registry.attacker.test/\n"}
    record, gaps = collect(tmp_path, PNPM_DLX, files)
    a_medium_source(record, gaps, ".npmrc:registry=https://registry.attacker.test")


def test_pnpm_binds_the_lines_after_a_section_header_with_trailing_whitespace(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    write_project(root, PNPM_DLX, {".npmrc": "[x] \nfund=false\n"})
    baseline = tmp_path / "baseline.json"
    assert scan_cli(root, baseline).exit_code == 0
    write_project(root, PNPM_DLX, {".npmrc": "[x] \nfund=false\nnode-options=--require ./a.js\n"})
    candidate = tmp_path / "candidate.json"
    assert scan_cli(root, candidate, "--report-only").exit_code == 0
    compared = CliRunner().invoke(main, ["diff", str(baseline), str(candidate), "--fail-on-alert"])
    assert compared.exit_code == 1, compared.output
    assert "static source binding changed" in compared.output


@pytest.mark.parametrize("key", LOCATIONS)
def test_the_scan_gate_fails_for_a_location_pnpm_reads_after_a_spaced_section(
    tmp_path, monkeypatch, key
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    write_project(root, PNPM_DLX, {".npmrc": f"[x] \n{key}=cfg\n", "cfg/.npmrc": "x=1\n"})
    output = tmp_path / "bom.json"
    result = scan_cli(root, output)
    assert result.exit_code == 1, result.output
    assert moved(key, ".npmrc") in output.read_text()


@pytest.mark.parametrize(
    "server,npmrc",
    [
        # npm's ini takes trailing whitespace after a section header.
        (NPX, "[x] \nuserconfig=.npmrc-ci\nregistry=https://registry.attacker.test/\n"),
        ({"command": "npm", "args": ["run", "mcp"]}, "[x] \nuserconfig=.npmrc-ci\n"),
        (PNPM_DLX, "[x]\nuserconfig=.npmrc-ci\nregistry=https://registry.attacker.test/\n"),
        (PNPX, "fund=false\n[x] \n"),
        (BUNX, "[x]\nfund=1\n"),
    ],
    ids=["npx", "npm-run", "pnpm-strict-header", "pnpm-header-last", "bunx-strict-header"],
)
def test_a_section_both_readers_end_the_top_level_at_keeps_the_identity(tmp_path, server, npmrc):
    record, gaps = collect(tmp_path, server, {".npmrc": npmrc})
    assert not gaps, gaps
    assert not any(r.category in {"launcher_identity", "package_source"} for r in record.risks)


@pytest.mark.parametrize("server", [BUNX, DENO], ids=["bunx", "deno"])
def test_bun_and_deno_fail_closed_where_npm_and_pnpm_read_the_npmrc_differently(tmp_path, server):
    record, gaps = collect(tmp_path, server, {".npmrc": "[x] \nfund=false\n"})
    detail = identity_unknown(record, gaps)
    assert ".npmrc section header with trailing whitespace" in detail


@pytest.mark.parametrize(
    "server",
    [
        {"command": "pnpm", "args": ["run", "mcp"]},
        {"command": "pnpm", "args": ["view", "safe-mcp"]},
        {"command": "bun", "args": ["run", "mcp"]},
        {"command": "deno", "args": ["run", "--allow-net", "server.ts"]},
    ],
)
def test_a_launch_without_a_package_sees_a_location_after_a_spaced_section(tmp_path, server):
    record, gaps = collect(tmp_path, server, {".npmrc": "[x] \nuserconfig=.npmrc-ci\n"})
    assert any(moved("userconfig", ".npmrc") in gap for gap in gaps), gaps


# pnpm 10 reads `--config.<key>=<value>`, --prefix and --dir (-C) before the script name of
# `pnpm run` and among the words of its own commands, and hands some commands to npm.
PNPM_OPTIONS = [
    (["run", "--config.userconfig=.npmrc-ci", "start"], moved("userconfig", "the command line")),
    (["run", "--config.globalconfig=g", "mcp"], moved("globalconfig", "the command line")),
    (["run", "--config.prefix=.", "start"], moved("prefix", "the command line")),
    (
        ["run", "--config.workspace-prefix=sub", "start"],
        moved("workspace-prefix", "the command line"),
    ),
    (["run", "-config.userconfig=.npmrc-ci", "start"], moved("userconfig", "the command line")),
    (["run-script", "---config.userconfig=c", "start"], moved("userconfig", "the command line")),
    (["run", "--config.userconfig=", "start"], moved("userconfig", "the command line")),
    (
        ["run", "--filter", "web", "--config.userconfig=c", "start"],
        moved("userconfig", "the command line"),
    ),
    (["run", "--prefix", ".", "start"], f"pnpm run --prefix {MOVES}"),
    (["run", "--pref=sub", "start"], f"pnpm run --prefix {MOVES}"),
    (["run", "--pr", "sub", "start"], f"pnpm run --prefix {MOVES}"),
    (["run", "--dir", "sub", "start"], f"pnpm run --dir {MOVES}"),
    (["run", "--di=sub", "start"], f"pnpm run --dir {MOVES}"),
    (["run", "-C", "sub", "start"], f"pnpm run -C {MOVES}"),
    (["run", "--C=sub", "start"], f"pnpm run -C {MOVES}"),
    (["run", "-rC", "sub", "start"], f"pnpm run -C {MOVES}"),
    (["run", "-Cr", "/srv/agent", "start"], f"pnpm run -C {MOVES}"),
    (["run", "-CC", "/srv/agent", "start"], f"pnpm run -C {MOVES}"),
    (["restart", "--config.userconfig=.npmrc-ci"], moved("userconfig", "the command line")),
    (["pack", "--prefix", "."], f"pnpm --prefix {MOVES}"),
    (["restart", "--prefix"], f"pnpm --prefix {MOVES}"),
    (["restart", "--dir", "--"], f"pnpm --dir {MOVES}"),
    (["recursive", "run", "-C", "sub", "start"], f"pnpm run -C {MOVES}"),
    # pnpm runs `pnpm view` and the other commands it does not implement with npm.
    (["view", "safe-mcp", "--userconfig", ".npmrc-ci"], f"pnpm --userconfig {MOVES}"),
    (["docs", "-gC", "."], f"pnpm -C {MOVES}"),
]


@pytest.mark.parametrize("args,reason", PNPM_OPTIONS)
def test_a_pnpm_location_option_makes_the_identity_unknown(tmp_path, args, reason):
    record, gaps = collect(tmp_path, {"command": "pnpm", "args": args})
    finding = next(r for r in record.risks if r.category == "launcher_identity")
    assert finding.severity.value == "high"
    assert reason in finding.detail
    assert any(reason in gap for gap in gaps), gaps


@pytest.mark.parametrize(
    "name,reason",
    [
        ("${E}userconfig", "npm setting name with ${...} from the command line"),
        ("work${E}prefix", "npm setting name with ${...} from the command line"),
    ],
)
def test_a_pnpm_config_name_that_may_expand_to_a_location_makes_the_identity_unknown(
    tmp_path, name, reason
):
    server = {"command": "pnpm", "args": ["run", f"--config.{name}=c", "start"], "env": {"E": ""}}
    record, gaps = collect(tmp_path, server)
    assert any(reason in gap for gap in gaps), gaps


@pytest.mark.parametrize(
    "args",
    [
        ["run", "start", "--config.userconfig=.npmrc-ci"],
        ["run", "start", "--prefix", "."],
        ["run", "start", "-C", "."],
        ["start", "--config.userconfig=.npmrc-ci"],
        ["start", "-C", "."],
        ["test", "--prefix", "."],
        ["exec", "node", "server.js", "--dir", "."],
        ["mcp", "--config.userconfig=.npmrc-ci"],
        # Without `=`, pnpm reads --config.<key> as a flag and the next word as the script.
        ["run", "--config.userconfig", "start"],
        ["run", "--config.fund=false", "start"],
        ["run", "--config.USERCONFIG=c", "start"],
        ["run", "--config.userc=c", "start"],
        ["run", "--no-dir", "start"],
        ["run", "--no-config.userconfig=c", "start"],
        ["run", "-p", "start"],
        ["run", "--d", "start"],
        ["run", "--parseable", "start"],
        ["run", "--", "--prefix", ".", "start"],
        ["restart", "--", "--config.userconfig=c"],
    ],
)
def test_words_pnpm_does_not_read_as_a_location_are_not_relocation(tmp_path, args):
    record, gaps = collect(tmp_path, {"command": "pnpm", "args": args})
    assert not gaps, gaps
    assert not any(r.category == "launcher_identity" for r in record.risks)


@pytest.mark.parametrize(
    "args,label",
    [
        (["run", "--config.userconfig=/srv/agent/.npmrc", "start"], "--config=[local]"),
        (["run", "--dir", "/srv/agent", "start"], "--dir=[local]"),
        (["run", "--prefix=/srv/agent", "start"], "--prefix=[local]"),
    ],
)
def test_an_absolute_pnpm_location_option_is_a_package_source(tmp_path, args, label):
    record, gaps = collect(tmp_path, {"command": "pnpm", "args": args})
    assert not gaps, gaps
    assert not any(r.category == "launcher_identity" for r in record.risks)
    assert label in record.properties["package_sources"]


def test_the_scan_gate_fails_for_a_pnpm_run_config_location(tmp_path, monkeypatch):
    # The review reproduction: pnpm run --config.userconfig=.npmrc-ci start passed the gate.
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root = tmp_path / "project"
    files = {
        "package.json": '{"scripts": {"start": "node server.js"}}',
        ".npmrc-ci": "fund=false\n",
    }
    server = {"command": "pnpm", "args": ["run", "--config.userconfig=.npmrc-ci", "start"]}
    write_project(root, server, files)
    output = tmp_path / "bom.json"
    result = scan_cli(root, output)
    assert result.exit_code == 1, result.output
    assert moved("userconfig", "the command line") in output.read_text()
