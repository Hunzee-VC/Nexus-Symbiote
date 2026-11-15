"""npm configuration that may lie in the project makes the launcher identity unknown.

npm reads its user configuration from ``userconfig`` and its global configuration from
``globalconfig``, by default ``<prefix>/etc/npmrc``. The environment, the project
``.npmrc`` and the command line can each move them, and npm resolves a relative path
against the working directory. The collector reads no file there, so ``call``,
``package`` or ``registry`` added to one would change what runs with nothing in the
inventory changing; such a setting is treated like ``HOME`` or ``PREFIX`` in the project.
npm also expands ``${...}`` in setting names, so a name holding one may spell any of them.
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
}
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


@pytest.mark.parametrize("value", IN_PROJECT)
@pytest.mark.parametrize("key", ["userconfig", "globalconfig", "prefix"])
def test_any_location_npm_may_resolve_into_the_project_is_relocation(tmp_path, key, value):
    record, gaps = collect(tmp_path, {**NPX, "env": {f"npm_config_{key}": value}})
    assert moved(key) in identity_unknown(record, gaps)


@pytest.mark.parametrize("runner", sorted(NPM_READERS))
@pytest.mark.parametrize("key", ["userconfig", "globalconfig", "prefix"])
def test_every_runner_that_reads_npm_configuration_is_covered(tmp_path, runner, key):
    server = {"command": runner, "args": NPM_READERS[runner], "env": {f"npm_config_{key}": "c"}}
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
    ],
)
def test_an_absolute_npm_configuration_location_is_a_package_source(tmp_path, variable, value):
    record, gaps = collect(tmp_path, {**NPX, "env": {variable: value}})
    a_medium_source(record, gaps, f"env:{variable}=[local]")
    assert value not in record.model_dump_json()


@pytest.mark.parametrize("key", ["userconfig", "globalconfig", "prefix"])
def test_an_empty_variable_npm_ignores_keeps_the_identity(tmp_path, key):
    record, gaps = collect(tmp_path, {**NPX, "env": {f"npm_config_{key}": ""}})
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
