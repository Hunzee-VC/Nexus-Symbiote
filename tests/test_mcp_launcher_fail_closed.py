"""Launch text a shell or cmd re-reads is classified only when every word reads as written."""

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.mcp_launch import _yarn1_exec_words, analyze, npm_command

EVIL = "-y evil-mcp@latest"
GATEWAY = ["-y", "supergateway@3.4.0", "--stdio"]


def scan(project: Path, server: dict) -> tuple[MCPServerComponent, list[str]]:
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
    result = MCPScanner().scan(project)
    assert not result.scan_failures
    record = next(c for c in result.components if isinstance(c, MCPServerComponent))
    return record, [gap for gap in result.surfaces_excluded if "launcher identity unknown" in gap]


def unknown_reason(project: Path, server: dict) -> str:
    """The detail of the HIGH launcher_identity finding a server must get, with its gap."""
    record, gaps = scan(project, server)
    finding = next((r for r in record.risks if r.category == "launcher_identity"), None)
    assert finding is not None and gaps, (record.properties, [r.detail for r in record.risks])
    assert finding.severity.value == "high"
    assert record.version_pinned is False and record.package_url is None
    return finding.detail


def assert_no_gap(project: Path, server: dict) -> MCPServerComponent:
    record, gaps = scan(project, server)
    assert not gaps, gaps
    assert not any(r.category == "launcher_identity" for r in record.risks)
    return record


# Each script makes bash run `npx -y evil-mcp@latest`; dash runs the pattern,
# parameter and eval forms too (tests below run both against a printing npx).
EXPANDED = [
    "{npx,-y,evil-mcp@latest}",
    f"{{n..n}}px {EVIL}",
    f"np? {EVIL}",
    f"n*x {EVIL}",
    f"[n]px {EVIL}",
    f"/usr/bin/np[x] {EVIL}",
    f"${{X:-/usr/bin/npx}} {EVIL}",
    f"${{X-/usr/bin/npx}} {EVIL}",
    f"${{X:=/usr/bin/npx}} {EVIL}",
    f"${{X:-/usr/bin/np}}x {EVIL}",
    f"${{X#/}}npx {EVIL}",
    f"${{X:+/}}npx {EVIL}",
    f"${{PATH/*/npx}} {EVIL}",
    f"$'\\x6e'px {EVIL}",
    f"$'\\156'px {EVIL}",
    f'eval "n\\px {EVIL}"',
    f"eval n\\\\px {EVIL}",
    f"=npx {EVIL}",
]
# Quoting a shell removes: read exactly by a POSIX shell, so only a reader that
# does not remove it (wsl, env -S, an argument a gateway re-reads) must fail closed.
QUOTED = [f"n''px {EVIL}", f"n\\px {EVIL}", f'"npx" {EVIL}']


def carriers(script: str) -> dict[str, dict]:
    """The ways an MCP configuration hands a script to a shell."""
    found = {
        "sh -c": {"command": "sh", "args": ["-c", script]},
        "bash -c": {"command": "bash", "args": ["-c", script]},
        "zsh -c": {"command": "zsh", "args": ["-c", script]},
        "bash -lc": {"command": "/bin/bash", "args": ["-lc", script]},
        "wsl": {"command": "wsl", "args": script.split(" ")},
        "wsl --": {"command": "wsl", "args": ["--", *script.split(" ")]},
        "env -S": {"command": "env", "args": ["-S", script]},
        "gateway": {"command": "npx", "args": [*GATEWAY, script]},
        "gateway option": {"command": "npx", "args": [*GATEWAY[:2], f"--stdio={script}"]},
        "nested gateway": {"command": "node", "args": ["proxy.js", "--cmd", script, "--port=1"]},
    }
    if " " in script:
        found["command line"] = {"command": script}
    return found


@pytest.mark.parametrize(
    "script,carrier",
    [(script, carrier) for script in EXPANDED for carrier in carriers(script)],
)
def test_expanded_launch_text_is_unknown_behind_every_shell_reader(tmp_path, script, carrier):
    unknown_reason(tmp_path, carriers(script)[carrier])


@pytest.mark.parametrize(
    "script,carrier",
    [
        (script, carrier)
        for script in [*QUOTED, f"eval npx {EVIL}"]
        for carrier in ("wsl", "wsl --", "env -S", "gateway", "gateway option", "nested gateway")
    ],
)
def test_quoting_is_unknown_where_the_reader_does_not_remove_it(tmp_path, script, carrier):
    unknown_reason(tmp_path, carriers(script)[carrier])


@pytest.mark.parametrize(
    "script,carrier",
    [
        *[
            (script, carrier)
            for script in QUOTED
            for carrier in ("sh -c", "bash -c", "command line")
        ],
        (f"eval npx {EVIL}", "sh -c"),
        (f"eval exec eval npx {EVIL}", "bash -c"),
    ],
)
def test_quoting_a_shell_removes_is_read_as_the_shell_reads_it(tmp_path, script, carrier):
    record, gaps = scan(tmp_path, carriers(script)[carrier])
    assert not gaps
    assert record.properties["launcher"] == "npx"
    assert record.launcher_package == "npm:evil-mcp" and record.version_pinned is False
    assert any(r.category == "version_pinning" for r in record.risks)


@pytest.mark.parametrize(
    "server,reason",
    [
        ({"command": "sh", "args": ["-c", f"${{RUNNER}} {EVIL}"]}, "depends on the environment"),
        ({"command": "sh", "args": ["-c", f"exec ${{X:-/usr/bin/npx}} {EVIL}"]}, "environment"),
        ({"command": "sh", "args": ["-c", f"A=$X npx {EVIL}"]}, "inline shell script"),
        ({"command": "sh", "args": ["-c", f"npx {EVIL} ~/x"]}, "inline shell script"),
        ({"command": "sh", "args": ["-c", f"npx {EVIL} #x"]}, "inline shell script"),
        ({"command": "sh", "args": ["-c", f"npx {EVIL} !"]}, "inline shell script"),
        ({"command": "sh", "args": ["-c", "npx -y 'evil mcp@latest'"]}, "inline shell script"),
        ({"command": "sh", "args": ["-c", "npx -y évil-mcp@latest"]}, "inline shell script"),
        ({"command": "zsh", "args": ["-c", "npx -y evil-mcp@lates^t"]}, "inline shell script"),
        ({"command": "fish", "args": ["-c", f"\\x6epx {EVIL}"]}, "inline shell script"),
        ({"command": "fish", "args": ["-c", f"\\156px {EVIL}"]}, "inline shell script"),
        (
            {"command": "env", "args": ["-S", f"bash -c {{npx,{EVIL.replace(' ', ',')}}}"]},
            "env -S value is not a simple command",
        ),
        ({"command": "pwsh", "args": ["-Command", f"np? {EVIL}"]}, "PowerShell command"),
        ({"command": "pwsh", "args": ["-Command", f"npx {EVIL} #x"]}, "PowerShell command"),
        (
            {"command": "pipx", "args": ["run", "--pip-args=--index-url=~/w*", "p==1.2.3"]},
            "--pip-args value is not a simple option list",
        ),
        ({"command": f"np? {EVIL}"}, "command line is not a simple command"),
        ({"command": f'"/opt/my tools/npx" {EVIL} $X'}, "command line is not a simple command"),
        # A shell joins text after the closing quote to the quoted word: "np"x is npx.
        ({"command": f'"np"x {EVIL}'}, "command line is not a simple command"),
        ({"command": "'np'x", "args": EVIL.split()}, "command line is not a simple command"),
        ({"command": "${X:-/usr/bin/npx}", "args": ["-y", "e"]}, "depends on the environment"),
        ({"command": "${X#/}npx", "args": ["-y", "e"]}, "depends on the environment"),
        ({"command": "%PATH:~0,0%npx", "args": ["-y", "e"]}, "depends on the environment"),
    ],
)
def test_words_a_shell_would_rewrite_are_unknown(tmp_path, server, reason):
    assert reason in unknown_reason(tmp_path, server)


def test_an_expansion_cannot_hide_a_second_launch_behind_a_pinned_package(tmp_path):
    script = f"npx -y --package=safe-mcp@1.2.3 ${{X#/}}npx {EVIL}"
    for server in ({"command": "sh", "args": ["-c", script]}, {"command": script}):
        assert unknown_reason(tmp_path, server)
        record, _ = scan(tmp_path, server)
        assert record.launcher_package is None and "packages" not in record.properties
    # A runner starts its program through a shell, so the program word is re-read too.
    detail = unknown_reason(
        tmp_path,
        {"command": "npx", "args": ["-y", "--package=safe-mcp@1.2.3", "${X#/}npx", *EVIL.split()]},
    )
    assert "arguments start npx" in detail


CMD_FORMS = [
    ["/c", "@npx", "-y", "evil-mcp@latest"],
    ["/c", ";npx", "-y", "evil-mcp@latest"],
    ["/c", ",npx", "-y", "evil-mcp@latest"],
    ["/c", "=npx", "-y", "evil-mcp@latest"],
    ["/c", "@;,=npx", "-y", "evil-mcp@latest"],
    ["/c", "%PATH:~0,0%npx", "-y", "evil-mcp@latest"],
    ["/c", "%CD:~0,0%npx", "-y", "evil-mcp@latest"],
    ["/v:on", "/c", "!X!npx", "-y", "evil-mcp@latest"],
    ["/c", "@npx -y evil-mcp@latest"],
    ["/c", '""npx" -y evil-mcp@latest"'],
    ["/c", "npx\x0b-y\x0bevil-mcp@latest"],
    ["/c", "npx\x0c-y evil-mcp@latest"],
    ["/c@npx", "-y", "evil-mcp@latest"],
    ["/k", "@npx", "-y", "evil-mcp@latest"],
    ["/d", "/s", "/c", "@npx -y evil-mcp@latest"],
    ["/c", "@uvx", "evil-mcp"],
    ["/c", "@docker", "run", "-i", "attacker/mcp:latest"],
    ["/c", "npx", "-y", "good-mcp@1.2.3", "%MCP_OPTS%"],
    ["/c", "npx", "-y", "good-mcp@1.2.3", "!MCP_OPTS!"],
    ["/c", "npx", "-y", '"good-mcp@1.2.3"'],
    ["/c", "npx -y good-mcp@1.2.3 %MCP_OPTS%"],
    ["/c", "n\xa0px -y evil-mcp@latest"],
    # cmd keeps single quotes, so these command words are not npx.
    ["/c", "'npx' -y evil-mcp@latest"],
    ["/c", "np''x -y evil-mcp@latest"],
    ["/c", "'npx'", "-y", "evil-mcp@latest"],
]


@pytest.mark.parametrize("args", CMD_FORMS)
def test_cmd_line_that_cmd_rewrites_is_unknown(tmp_path, args):
    server = {"command": "cmd", "args": args, "env": {"MCP_OPTS": "& npx -y evil-mcp@latest"}}
    assert "cmd /c command line is not a simple command" in unknown_reason(tmp_path, server)


@pytest.mark.parametrize(
    "server",
    [
        {"command": "C:\\Windows\\System32\\cmd.exe", "args": ["/d", "/s", "/c", "@npx -y e@1"]},
        {"command": "cmd /c @npx -y evil-mcp@latest"},
        {"command": "env", "args": ["X=1", "cmd", "/c", "@npx", "-y", "evil-mcp@latest"]},
        {"command": "sh", "args": ["-c", "cmd /c @npx -y evil-mcp@latest"]},
    ],
)
def test_cmd_behind_other_wrappers_is_read_with_the_same_rule(tmp_path, server):
    unknown_reason(tmp_path, server)


@pytest.mark.parametrize(
    "args,pinned",
    [
        (["/c", "npx", "-y", "pkg@1.2.3"], True),
        (["/c", "npx -y pkg@1.2.3"], True),
        (["/C", "npx\t-y\tpkg@1.2.3"], True),
        (["/c", "C:\\nodejs\\npx.cmd", "-y", "pkg@1.2.3"], True),
        (["/d", "/s", "/c", "npx -y pkg@latest"], False),
        (["/c", "npx", "-y", "pkg@1.2.3", "--allow=a,b;c", "C:\\Users\\me\\My Docs"], True),
    ],
)
def test_ordinary_cmd_lines_stay_classified(tmp_path, args, pinned):
    record = assert_no_gap(tmp_path, {"command": "cmd", "args": args})
    assert record.launcher_package == "npm:pkg" and record.version_pinned is pinned


@pytest.mark.parametrize(
    "line", ["C:\\nodejs\\npx.cmd -y pkg@1.2.3", "node_modules\\.bin\\npx -y pkg@1.2.3"]
)
def test_cmd_keeps_backslashes_in_a_command_line(tmp_path, line):
    record = assert_no_gap(tmp_path, {"command": "cmd", "args": ["/c", line]})
    assert record.launcher_package == "npm:pkg" and record.version_pinned is True


def test_a_backslash_in_a_cmd_command_word_is_a_path_not_an_escape(tmp_path):
    record, _ = scan(tmp_path, {"command": "cmd", "args": ["/c", "n\\px -y evil-mcp@latest"]})
    assert record.properties.get("launcher") != "npx"
    assert record.launcher_package is None and record.version_pinned is not True


@pytest.mark.parametrize(
    "server,reason",
    [
        ({"command": "npx", "args": [*GATEWAY, f'npm "exec" {EVIL}']}, "arguments start npm"),
        ({"command": "npx", "args": [*GATEWAY, f"$(printf npx) {EVIL}"]}, "shell syntax"),
        ({"command": "npx", "args": [*GATEWAY, f"`printf npx` {EVIL}"]}, "shell syntax"),
        ({"command": "npx", "args": [*GATEWAY, f'$"npx" {EVIL}']}, "shell syntax"),
        ({"command": "npx", "args": [*GATEWAY, f"np$X {EVIL}"], "env": {"X": "x"}}, "start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"n${{X}}px {EVIL}"]}, "arguments start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"${{R:-npx}} {EVIL}"]}, "arguments start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"${{R:-${{S:-npx}}}} {EVIL}"]}, "start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"a${{R:-/n}}px {EVIL}"]}, "arguments start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"@npx {EVIL}"]}, "arguments start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"%PATH:~0,0%npx {EVIL}"]}, "start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"!P!npx {EVIL}"]}, "arguments start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"n^px {EVIL}"]}, "arguments start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"[^x]px {EVIL}"]}, "arguments start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"[[:alpha:]]px {EVIL}"]}, "start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"[]n]px {EVIL}"]}, "arguments start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"NP?.CMD {EVIL}"]}, "arguments start npx"),
        ({"command": "npx", "args": [*GATEWAY, f"np?@10 {EVIL}"]}, "arguments start npx"),
        ({"command": "npx", "args": [*GATEWAY, "{node,-e,require('x')}"]}, "inline node code"),
        ({"command": "npx", "args": [*GATEWAY, "pyth?n3 -c 'import os'"]}, "inline python"),
        ({"command": "npx", "args": [*GATEWAY, "{a,b}{c,d}x {n..n}px -y e"]}, "start npx"),
        ({"command": "nice", "args": ["n''px", *EVIL.split()]}, "arguments start npx"),
        ({"command": "nice", "args": ["{npx,-y}", "evil-mcp@latest"]}, "arguments start npx"),
        ({"command": "nice", "args": ["--", "u?x", "evil-mcp"]}, "arguments start uvx"),
    ],
)
def test_arguments_a_shell_or_cmd_may_rewrite_are_read_both_ways(tmp_path, server, reason):
    assert reason in unknown_reason(tmp_path, server)


@pytest.mark.parametrize(
    "server",
    [
        {
            "command": "npx",
            "args": [
                "-y",
                "mcp-remote@0.1.15",
                "https://x.test/sse",
                "--header",
                "Authorization: Bearer ${AUTH}",
            ],
            "env": {"AUTH": "token-value"},
        },
        {
            "command": "npx",
            "args": [
                "-y",
                "mcp-remote@0.1.15",
                "https://x.test/sse",
                "--header",
                "Authorization:${AUTH_HEADER}",
            ],
        },
        {
            "command": "node",
            "args": ["C:\\Users\\me\\My Docs\\server.js", "--data", "D:\\data\\*.csv"],
        },
        {"command": "node", "args": ["${workspaceFolder}/server.js", "--token", "${input:token}"]},
        {"command": "node", "args": ["${env:HOME}/server.js", "--config", "${userHome}/.cfg.json"]},
        {
            "command": "npx",
            "args": ["-y", "@playwright/mcp@0.0.40", "--allowed-hosts", "*", "--port", "1"],
        },
        {"command": "python", "args": ["-m", "s", "--dsn", "pg://${U:-u}:${P:-p}@${H:-h}:5432/db"]},
        {
            "command": "node",
            "args": ["s.js", "--glob", "**/*.{js,ts}", "--exclude", "node_modules/**"],
        },
        {
            "command": "node",
            "args": ["s.js", "--format", "%Y-%m-%d", "--greeting", "Hello, world!"],
        },
        {
            "command": "node",
            "args": ["s.js", "--config", '{"a": 1, "b": [1, 2]}', "--name", "Tom's"],
        },
        {
            "command": "node",
            "args": ["s.js", "--url", "https://x.test/sse?a=1&b=[2]", "--port", "1"],
        },
        {"command": "node", "args": ["s.js", "--range", "{1..3}", "--ids", "{a,b,c}", "--x", "1"]},
        {"command": "uvx", "args": ["mcp-server-time==1.2.3", "--local-timezone=${TZ:-UTC}"]},
        {"command": "sh", "args": ["-c", "npx -y pkg@1.2.3"]},
        {"command": "sh", "args": ["-c", "exec npx -y @scope/pkg@1.2.3 --dir=./data --port=8080"]},
        {"command": "sh", "args": ["-c", ".venv/bin/python server.py --log-level=INFO"]},
        {"command": "bash", "args": ["-c", "A=1 B=x,y uvx mcp-server-fetch==1.2.3"]},
        {"command": ".venv/bin/python", "args": ["server.py"]},
        {"command": "node", "args": ["server.js"]},
        {"command": "/opt/tools/my-server", "args": ["--port", "1"]},
        {"command": "${workspaceFolder}/.venv/bin/python", "args": ["server.py"]},
        {"command": "$HOME/bin/my-server", "args": []},
        {"command": "wsl", "args": ["--cd", "sub", "npx", "-y", "@acme/files-mcp@1.0.0"]},
        {"command": "pwsh", "args": ["-NoProfile", "-Command", "npx -y t@1.2.3"]},
        {"command": "env", "args": ["-S", "npx -y pkg@1.2.3 --dir=./data"]},
        {"command": "pipx", "args": ["run", "--pip-args=--no-cache-dir --pre", "pkg==1.2.3"]},
        {"command": "npx -y pkg@1.2.3 --port=8080"},
    ],
)
def test_ordinary_configurations_near_the_rules_get_no_gap(tmp_path, server):
    assert_no_gap(tmp_path, server)


# Bun 1.4.4 runs `bun exec SCRIPT` in Bun Shell: pipes, lists, redirections, subshells,
# expansions, `#` comments, `~`, quoting and escapes all work, and a tab does not
# separate words. Yarn 2+ runs `yarn exec SCRIPT ARGS...` in its portable shell and
# appends ARGS to the last command; Yarn 1 spawns SCRIPT as a program with ARGS.
INLINE_EXEC_SCRIPTS = [
    "echo marker | cat",
    "true; echo marker",
    "true && sh",
    "false || echo marker",
    "sh < payload.txt",
    "node server.js > server.log",
    "(sh)",
    "sh &",
    "echo $(sh)",
    "echo `sh`",
    "true\nsh",
    "true\rsh",
    "node\tserver.js",
    "node server.js $1",
    "node server.js ${PORT}",
    "node ~/server.js",
    "node server.js # comment",
    "node server.js !",
    "node server-*.js",
    "node server?.js",
    "node server.js {a,b}",
    "node 'server.js'",
    'node "server.js"',
    "node server\\.js",
    "node sérver.js",
    "node\u00a0server.js",
    "=node server.js",
    "A=1",
    "",
    " ",
]


def exec_carriers(script: str) -> dict[str, dict]:
    """The ways an MCP configuration hands a script to bun exec or yarn exec."""
    return {
        "bun exec": {"command": "bun", "args": ["exec", script]},
        "bun exec --": {"command": "bun", "args": ["exec", "--", script]},
        "bun --silent exec": {"command": "bun", "args": ["--silent", "exec", script]},
        "bun --bun exec": {"command": "/home/me/.bun/bin/bun", "args": ["--bun", "exec", script]},
        "bun.exe exec": {"command": "C:\\Tools\\BUN.EXE", "args": ["exec", script]},
        "bun exec command line": {"command": "bun exec", "args": [script]},
        "yarn exec": {"command": "yarn", "args": ["exec", script]},
        "yarn exec --": {"command": "yarn", "args": ["exec", "--", script]},
        "yarn exec with arguments": {"command": "yarn", "args": ["exec", script, "--port", "1"]},
        "yarnpkg exec": {"command": "yarnpkg", "args": ["exec", script]},
        "yarn.cmd exec": {"command": "yarn.cmd", "args": ["exec", script]},
        "yarn workspace exec": {"command": "yarn", "args": ["workspace", "app", "exec", script]},
    }


@pytest.mark.parametrize(
    "script,carrier",
    [(script, carrier) for script in INLINE_EXEC_SCRIPTS for carrier in exec_carriers("")],
)
def test_a_bun_or_yarn_exec_script_that_is_not_a_simple_command_is_unknown(
    tmp_path, script, carrier
):
    server = exec_carriers(script)[carrier]
    assert "exec script is not a simple command" in unknown_reason(tmp_path, server)
    launch = analyze(server["command"], server["args"])
    assert launch.context.get("inline_shell_code") == 1
    assert launch.launcher in {"bun exec", "yarn exec"}


@pytest.mark.parametrize(
    "script,carrier",
    [
        (script, carrier)
        for script in [*EXPANDED, *QUOTED]
        for carrier in ("bun exec", "bun exec --", "yarn exec", "yarn exec with arguments")
    ],
)
def test_expanded_or_quoted_launch_text_is_unknown_behind_bun_and_yarn_exec(
    tmp_path, script, carrier
):
    server = exec_carriers(script)[carrier]
    assert "exec script" in unknown_reason(tmp_path, server)
    assert analyze(server["command"], server["args"]).context.get("inline_shell_code") == 1


@pytest.mark.parametrize("carrier", ["bun exec", "yarn exec", "yarn workspace exec"])
@pytest.mark.parametrize(
    "script", ["${RUNNER} server.js", "$RUNNER server.js", "${X:-/usr/bin/npx} -y evil-mcp"]
)
def test_a_bun_or_yarn_exec_script_whose_program_depends_on_the_environment_is_unknown(
    tmp_path, script, carrier
):
    server = exec_carriers(script)[carrier]
    assert "exec script command depends on the environment" in unknown_reason(tmp_path, server)


@pytest.mark.parametrize("carrier", list(exec_carriers("")))
@pytest.mark.parametrize(
    "script,reason",
    [
        (f"npx {EVIL}", "arguments start npx"),
        ("bunx evil-mcp", "arguments start bunx"),
        ("bun x evil-mcp@latest", "arguments start bun"),
        ("bun exec sh", "arguments start bun"),
        ("yarn dlx evil-mcp", "arguments start yarn"),
        ("yarn exec sh", "arguments start yarn"),
        ("sh -c npx", "arguments start sh"),
        ("node -e require", "inline node code"),
        ("exec npx -y evil-mcp", "arguments start npx"),
        ("NODE_ENV=production npx -y evil-mcp", "arguments start npx"),
    ],
)
def test_a_simple_bun_or_yarn_exec_script_is_checked_like_its_words(
    tmp_path, carrier, script, reason
):
    assert reason in unknown_reason(tmp_path, exec_carriers(script)[carrier])


@pytest.mark.parametrize(
    "command,args,reason",
    [
        ("bun", ["exec"], "bun exec without a script"),
        ("bun", ["exec", "--"], "bun exec without a script"),
        # Bun reads its options anywhere among exec's words: --cwd moves the script.
        ("bun", ["exec", "--cwd", "../other", "node server.js"], "unrecognised bun exec option"),
        ("bun", ["exec", "node server.js", "--cwd", ".."], "unrecognised bun exec option"),
        ("bun", ["exec", "-e", "node server.js"], "unrecognised bun exec option"),
        ("bun", ["exec", "node server.js", "--"], "unrecognised bun exec option"),
        # Bun runs only the first word; the others are positional parameters.
        ("bun", ["exec", "node", "server.js"], "bun exec words after the script"),
        ("bun", ["exec", "--", "node server.js", "--cwd", ".."], "bun exec words after"),
        ("yarn", ["exec"], "yarn exec without a command"),
        ("yarn", ["exec", "--"], "yarn exec without a command"),
        ("yarn", ["exec", "--cwd", "..", "node server.js"], "unrecognised yarn exec option"),
        ("yarnpkg", ["exec", "-", "node server.js"], "unrecognised yarn exec option"),
        ("yarn", ["exec", "--silent", "--cwd", "..", "node"], "unrecognised yarn exec option"),
        ("bun", ["exec", "/"], "bun exec script command depends on the environment"),
        ("bun", ["exec", "./"], "bun exec script command depends on the environment"),
        ("yarn", ["exec", "/"], "yarn exec script command depends on the environment"),
    ],
)
def test_bun_and_yarn_exec_words_outside_the_documented_grammar_are_unknown(
    tmp_path, command, args, reason
):
    assert reason in unknown_reason(tmp_path, {"command": command, "args": args})


@pytest.mark.parametrize(
    "server",
    [
        {"command": "nice", "args": ["bun", "exec", "echo marker | cat"]},
        {"command": "nice", "args": ["bun", "--silent", "exec", "true; echo marker"]},
        {"command": "nice", "args": ["bun", "--cwd", "sub", "exec", "true; echo marker"]},
        {"command": "nice", "args": ["bun", "exec", "--cwd", "sub", "true; echo marker"]},
        {"command": "timeout", "args": ["60", "bun", "exec", "node server.js"]},
        {"command": "nice", "args": ["yarn", "exec", "echo marker | cat"]},
        {"command": "nice", "args": ["yarnpkg", "--silent", "exec", "true; echo marker"]},
        {"command": "nice", "args": ["yarn", "--cwd", "sub", "exec", "true; echo marker"]},
        {"command": "nice", "args": ["yarn", "workspace", "app", "exec", "true; echo marker"]},
        {
            "command": "node",
            "args": ["proxy.js", "--cmd", "bun exec 'true; echo marker'", "--port=1"],
        },
        {"command": "npx", "args": [*GATEWAY, "yarn exec 'true; echo marker'"]},
        {"command": "npx", "args": ["-y", "bun@1.2.0", "exec", "true; echo marker"]},
        {
            "command": "docker",
            "args": [
                "run",
                "--rm",
                "-i",
                "oven/bun@sha256:" + "0" * 64,
                "bun",
                "exec",
                "echo marker | cat",
            ],
        },
        {"command": "bun", "args": ["run", "start", "--", "yarn", "exec", "true; echo marker"]},
        {"command": "yarn", "args": ["exec", "nice", "bun", "exec", "true; echo marker"]},
    ],
)
def test_a_bun_or_yarn_exec_in_the_arguments_is_unknown(tmp_path, server):
    detail = unknown_reason(tmp_path, server)
    assert "arguments start bun" in detail or "arguments start yarn" in detail, detail


@pytest.mark.parametrize(
    "server,launcher",
    [
        ({"command": "bun", "args": ["exec", "node server.js"]}, "bun exec"),
        ({"command": "bun", "args": ["exec", "--", "bun run server.ts --port=8080"]}, "bun exec"),
        ({"command": "bun", "args": ["--silent", "exec", "./bin/server --stdio"]}, "bun exec"),
        ({"command": "bun", "args": ["exec", "A=1 B=x,y bun src/index.ts"]}, "bun exec"),
        ({"command": "bun", "args": ["exec", "pwd"]}, "bun exec"),
        ({"command": "yarn", "args": ["exec", "node", "server.js"]}, "yarn exec"),
        ({"command": "yarn", "args": ["exec", "--", "tsx", "src/server.ts"]}, "yarn exec"),
        # Yarn 1 reads its reporter options among exec's words; they change only output.
        ({"command": "yarn", "args": ["exec", "--silent", "node", "server.js"]}, "yarn exec"),
        ({"command": "yarn", "args": ["exec", "-s", "--", "node", "server.js"]}, "yarn exec"),
        ({"command": "yarn", "args": ["exec", "--verbose", "node server.js"]}, "yarn exec"),
        ({"command": "yarn", "args": ["exec", "tsx src/server.ts", "--port", "3000"]}, "yarn exec"),
        (
            {"command": "yarn", "args": ["exec", "node", "s.js", "--name", "My Server", "-x"]},
            "yarn exec",
        ),
        (
            {"command": "yarnpkg", "args": ["workspace", "app", "exec", "node", "dist/index.js"]},
            "yarn exec",
        ),
        ({"command": "bun", "args": ["run", "start"]}, "bun"),
        ({"command": "bun", "args": ["server.ts"]}, "bun"),
        ({"command": "yarn", "args": ["start"]}, "yarn"),
        ({"command": "nice", "args": ["bun", "run", "start"]}, "local"),
        ({"command": "nice", "args": ["yarn", "run", "start"]}, "local"),
    ],
)
def test_ordinary_bun_and_yarn_launches_near_exec_stay_classified(tmp_path, server, launcher):
    record = assert_no_gap(tmp_path, server)
    assert record.properties["launcher"] == launcher
    if launcher.endswith(" exec"):
        assert analyze(server["command"], server["args"]).context == {"shell_wrapper": 1}
        assert any(
            r.category == "launch_context" and r.severity.value == "low" for r in record.risks
        ), [r.detail for r in record.risks]


def test_a_bun_exec_script_records_the_environment_it_assigns(tmp_path):
    record, gaps = scan(
        tmp_path,
        {"command": "bun", "args": ["exec", "NODE_OPTIONS=--require=./hook.js bun server.ts"]},
    )
    assert not gaps
    assert any(
        r.category == "launch_context" and "environment that changes code loading" in r.detail
        for r in record.risks
    ), [r.detail for r in record.risks]


@pytest.mark.parametrize(
    "server",
    [
        {"command": "bun", "args": ["exec", "echo marker | cat"]},
        {"command": "yarn", "args": ["exec", "echo marker | cat"]},
        {"command": "nice", "args": ["bun", "exec", "echo marker | cat"]},
    ],
)
def test_the_scan_gate_fails_for_an_inline_bun_or_yarn_exec_script(tmp_path, server):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", "--no-project-policy", str(root), "-o", str(output)])
    assert run.exit_code == 1, run.output
    assert "Scan gate failed" in run.output
    assert "MCP server 's' launcher identity unknown" in run.output


# Bun 1.4.4 adds the words of BUN_OPTIONS, quotes removed, to the arguments of every
# bun, behind any wrapper: BUN_OPTIONS="exec 'SCRIPT'" makes `bun server.ts` run SCRIPT
# in Bun Shell, and BUN_OPTIONS=exec does so for `bun "SCRIPT"`.
@pytest.mark.parametrize(
    "server",
    [
        {
            "command": "bun",
            "args": ["server.ts"],
            "env": {"BUN_OPTIONS": "exec 'echo marker | cat'"},
        },
        {"command": "bun", "args": ["echo marker | cat"], "env": {"BUN_OPTIONS": "exec"}},
        {"command": "bun", "args": ["server.ts"], "env": {"bun_options": "-e 'x()'"}},
        {"command": "nice", "args": ["bun", "echo marker | cat"], "env": {"BUN_OPTIONS": "exec"}},
        {"command": "node", "args": ["server.js"], "env": {"BUN_OPTIONS": "exec"}},
        {"command": "npx", "args": ["-y", "pkg@1.2.3"], "env": {"BUN_OPTIONS": "exec"}},
        {"command": "env", "args": ["BUN_OPTIONS=exec", "bun", "echo marker | cat"]},
        {"command": "sh", "args": ["-c", "BUN_OPTIONS=exec bun server.ts"]},
        {"command": "bun", "args": ["exec", "BUN_OPTIONS=exec bun server.ts"]},
        {"command": "yarn", "args": ["exec", "BUN_OPTIONS=exec bun", "server.ts"]},
    ],
)
def test_bun_options_in_the_environment_make_any_launch_unknown(tmp_path, server):
    detail = unknown_reason(tmp_path, server)
    assert "environment adds arguments to every bun the launch starts" in detail


def test_an_empty_bun_options_adds_no_arguments(tmp_path):
    assert_no_gap(tmp_path, {"command": "bun", "args": ["server.ts"], "env": {"BUN_OPTIONS": " "}})


# npx, bunx and pnpm dlx run @yarnpkg/cli-dist, the npm package of Yarn 2+, as `yarn`:
# its bins `yarn` and `yarnpkg` name one file and npx takes the first.
@pytest.mark.parametrize(
    "server",
    [
        {"command": "npx", "args": ["-y", "@yarnpkg/cli-dist@4.18.1", "exec", "echo marker | cat"]},
        {"command": "npx", "args": ["-y", "@yarnpkg/cli-dist@4.18.1", "dlx", "evil-mcp"]},
        {"command": "npx", "args": ["-y", "@YarnPkg/Cli-Dist@4.18.1", "exec", "echo marker | cat"]},
        {"command": "bunx", "args": ["@yarnpkg/cli-dist@4.18.1", "exec", "echo marker | cat"]},
        {
            "command": "pnpm",
            "args": ["dlx", "@yarnpkg/cli-dist@4.18.1", "exec", "echo marker | cat"],
        },
    ],
)
def test_a_package_manager_package_is_read_as_its_program(tmp_path, server):
    assert "arguments start yarn" in unknown_reason(tmp_path, server)


def test_the_pnpm_exe_package_is_read_as_pnpm(tmp_path):
    server = {"command": "npx", "args": ["-y", "@pnpm/exe@10.28.0", "dlx", "evil-mcp"]}
    assert "arguments start pnpm" in unknown_reason(tmp_path, server)


# pnpm 10.28.0 runs `pnpm -c exec SCRIPT` (also --shell-mode, --config.shell-mode=true)
# through /bin/sh; it reads no option after exec.
@pytest.mark.parametrize(
    "server",
    [
        {"command": "nice", "args": ["pnpm", "-c", "exec", "echo marker | cat"]},
        {"command": "nice", "args": ["pnpm", "--shell-mode", "exec", "true; echo marker"]},
        {
            "command": "nice",
            "args": ["pnpm", "--config.shell-mode=true", "exec", "true; echo marker"],
        },
        {
            "command": "nice",
            "args": ["pnpm", "--config.shellMode=true", "exec", "true; echo marker"],
        },
        {"command": "nice", "args": ["pnpm", "-cr", "exec", "true; echo marker"]},
        {"command": "nice", "args": ["pnpm", "--silent", "-c", "exec", "true; echo marker"]},
        {"command": "npx", "args": ["-y", "pnpm@10.28.0", "-c", "exec", "true; echo marker"]},
        {
            "command": "npx",
            "args": ["-y", "pnpm@10.28.0", "--shell-mode", "exec", "true; echo marker"],
        },
        {"command": "pnpm", "args": ["exec", "pnpm", "-c", "exec", "true; echo marker"]},
    ],
)
def test_pnpm_shell_mode_in_the_arguments_is_unknown(tmp_path, server):
    assert "arguments start pnpm" in unknown_reason(tmp_path, server)


def test_pnpm_exec_without_shell_mode_in_the_arguments_stays_classified(tmp_path):
    assert_no_gap(tmp_path, {"command": "nice", "args": ["pnpm", "exec", "-c", "true"]})


# pnpm 10.28.0 ran `pnpm <option> exec 'echo M-$((1+1)) | cat'` through a shell for each
# of these: nopt strips every leading dash and each `no-`, takes any abbreviation of
# --shell-mode, leaves an option word after -C or --dir as an option, and camelCases
# a --config key, using any value as the shell.
PNPM_SHELL_MODE_SPELLINGS = [
    ["--shell"],
    ["--she"],
    ["--shell-m"],
    ["--shell=true"],
    ["--shell-mode=1"],
    ["-shell-mode"],
    ["-she"],
    ["---shell-mode"],
    ["--no-no-shell-mode"],
    ["--config.shell_mode=true"],
    ["--config.SHELL-MODE=true"],
    ["--config.Shell_Mode=1"],
    ["--config.shell.mode=true"],
    ["--config.shell--mode=true"],
    ["-config.shell-mode=true"],
    ["-C", "--shell-mode"],
    ["--dir", "--shell-mode"],
    ["-C", "-c"],
    ["--reporter", "--she"],
    ["-cs"],
]


@pytest.mark.parametrize("options", PNPM_SHELL_MODE_SPELLINGS)
def test_pnpm_shell_mode_in_any_spelling_pnpm_reads_is_unknown(tmp_path, options):
    server = {"command": "nice", "args": ["pnpm", *options, "exec", "echo marker | cat"]}
    assert "arguments start pnpm" in unknown_reason(tmp_path, server)


@pytest.mark.parametrize(
    "server",
    [
        {"command": "npx", "args": ["-y", "pnpm@10.28.0", "--shell", "exec", "echo marker"]},
        {"command": "yarn", "args": ["exec", "--", "pnpm", "--shell", "exec", "echo marker"]},
        {"command": "pnpm", "args": ["exec", "pnpm", "-she", "exec", "echo marker"]},
    ],
)
def test_pnpm_shell_mode_behind_another_runner_is_unknown(tmp_path, server):
    assert "arguments start pnpm" in unknown_reason(tmp_path, server)


# pnpm 10.28.0 ran none of these in a shell: -C takes `sub`, the others are not
# shell mode, and options after exec belong to the command.
@pytest.mark.parametrize(
    "options",
    [
        ["-C", "sub"],
        ["--silent"],
        ["--shamefully-hoist"],
        ["--config.shell-emulator=true"],
        ["--config.shellmodes=true"],
    ],
)
def test_pnpm_options_that_are_not_shell_mode_stay_classified(tmp_path, options):
    server = {"command": "nice", "args": ["pnpm", *options, "exec", "node", "server.js"]}
    assert_no_gap(tmp_path, server)


# What Yarn 1.22.22 spawned for `yarn exec WORDS`, read back from a printf program.
@pytest.mark.parametrize(
    "words,spawned",
    [
        (["sh", "--", "-c", "x"], ["sh", "-c", "x"]),
        (["node", "--foo", "srv", "--", "-e", "x"], ["node", "-e", "x"]),
        (["node", "--foo", "-e", "x"], ["node"]),
        (["node", "--foo=bar", "x"], ["node", "x"]),
        (["node", "-abc", "x", "y"], ["node", "y"]),
        (["node", "--cwd", ".", "x"], ["node", "x"]),
        (["node", "--registry", "-z", "x"], ["node", "x"]),
        (["node", "--emoji", "x"], ["node"]),
        (["node", "--emoji", "-q", "x"], ["node"]),
        (["node", "--prod", "false", "x"], ["node", "x"]),
        (["node", "--verbose", "x"], ["node", "x"]),
        (["node", "-s", "x"], ["node", "x"]),
        (["node", "--no-progress", "x"], ["node", "x"]),
        (["node", "--no-foo", "x"], ["node"]),
        (["node", "---x", "y", "z"], ["node", "z"]),
        (["node", "x", "--port", "1"], ["node", "x"]),
        (["node", "--help", "x"], ["node"]),
        (["node", "-", "x"], ["node", "-", "x"]),
        (["node", "a", "--", "b", "--", "c"], ["node", "a", "b", "--", "c"]),
        (["node", "--", "--help", "x"], ["node", "--help", "x"]),
        (["--silent", "node", "x"], ["node", "x"]),
        (["--", "sh", "-c", "x"], ["sh", "-c", "x"]),
        (["node", "--cwd"], None),
    ],
)
def test_yarn_exec_words_are_read_as_yarn_1_spawns_them(words, spawned):
    assert _yarn1_exec_words(words) == spawned


# Yarn 1.22.22 ran each as inline code: `yarn exec sh -- -c 'echo marker'` printed it.
@pytest.mark.parametrize(
    "args,reason",
    [
        (["exec", "sh", "--", "-c", "echo marker"], "arguments start sh"),
        (["exec", "node", "--", "-e", "console.log(1)"], "arguments run inline node code"),
        (["exec", "python3", "--", "-c", "print(1)"], "arguments run inline python code"),
        (
            ["exec", "node", "--foo", "server.js", "--", "-e", "console.log(1)"],
            "arguments run inline node code",
        ),
        (["exec", "-s", "node", "--cwd=.", "-x", "server.js", "--", "-p", "1"], "inline node"),
    ],
)
def test_yarn_exec_arguments_yarn_1_turns_into_inline_code_are_unknown(tmp_path, args, reason):
    assert reason in unknown_reason(tmp_path, {"command": "yarn", "args": args})


@pytest.mark.parametrize(
    "args",
    [
        ["exec", "node", "server.js", "--port", "1"],
        ["exec", "node", "server.js", "--", "--port", "1"],
        ["exec", "node", "--foo", "server.js", "--", "server.js"],
        ["exec", "-s", "node", "server.js"],
    ],
)
def test_yarn_exec_arguments_both_yarn_readings_leave_local_stay_classified(tmp_path, args):
    assert_no_gap(tmp_path, {"command": "yarn", "args": args})


# Each is the shebang entry point of a runner, run under a name the grammars miss:
# corepack's dist/yarn.js runs the Yarn the checkout names, pnpm.cjs reads
# --shell-mode, npx-cli.js fetches its package.
@pytest.mark.parametrize(
    "command,runner",
    [
        ("/usr/local/lib/node_modules/corepack/dist/yarn.js", "yarn"),
        ("/usr/local/lib/node_modules/corepack/dist/yarnpkg.js", "yarnpkg"),
        ("/usr/local/lib/node_modules/corepack/dist/corepack.js", "corepack"),
        ("/usr/local/lib/node_modules/pnpm/bin/pnpm.cjs", "pnpm"),
        ("/usr/local/lib/node_modules/pnpm/bin/pnpx.cjs", "pnpx"),
        ("/usr/local/lib/node_modules/npm/bin/npx-cli.js", "npx"),
        ("/usr/local/lib/node_modules/npm/bin/npm-cli.js", "npm"),
        ("C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\NPX-CLI.JS", "npx"),
    ],
)
def test_a_runner_script_entry_point_as_the_command_is_unknown(tmp_path, command, runner):
    server = {"command": command, "args": ["exec", "echo marker | cat"]}
    reason = unknown_reason(tmp_path, server)
    assert f"command is a script entry point of {runner}" in reason


@pytest.mark.parametrize("command", ["server.js", "bin/mcp-server.cjs", "yarn-helper.mjs"])
def test_a_script_named_after_no_runner_stays_a_local_launch(tmp_path, command):
    record = assert_no_gap(tmp_path, {"command": command, "args": ["--port", "1"]})
    assert record.properties["launcher"] == "local"


# pnpm 9.15.9 reads shell-mode from npm_config_* and the project .npmrc (rcOptionsTypes
# has "shell-mode": Boolean, getConfig calls conf.addEnv() and loads <prefix>/.npmrc),
# and pnpm exec spawns with `shell: opts.shellMode`. pnpm 10.28.0 reads neither.
@pytest.mark.parametrize(
    "server",
    [
        {
            "command": "pnpm",
            "args": ["exec", "echo marker | cat"],
            "env": {"npm_config_shell_mode": "true"},
        },
        {
            "command": "nice",
            "args": ["pnpm", "exec", "echo marker | cat"],
            "env": {"NPM_CONFIG_SHELL_MODE": "1"},
        },
        {
            "command": "node",
            "args": ["server.js"],
            "env": {"pnpm_config_shellMode": "true"},
        },
        {"command": "env", "args": ["npm_config_shell_mode=true", "pnpm", "exec", "echo marker"]},
    ],
)
def test_pnpm_shell_mode_from_the_environment_is_unknown(tmp_path, server):
    assert "environment turns on pnpm shell mode" in unknown_reason(tmp_path, server)


def test_an_empty_pnpm_shell_mode_variable_is_not_read(tmp_path):
    server = {
        "command": "pnpm",
        "args": ["exec", "node", "server.js"],
        "env": {"npm_config_shell_mode": ""},
    }
    assert_no_gap(tmp_path, server)


@pytest.mark.parametrize("key", ["shell-mode", "shell_mode", "shellMode"])
@pytest.mark.parametrize(
    "server",
    [
        {"command": "pnpm", "args": ["exec", "echo marker | cat"]},
        {"command": "nice", "args": ["pnpm", "exec", "echo marker | cat"]},
        {"command": "npx", "args": ["-y", "pnpm@9.15.9", "exec", "echo marker"]},
    ],
)
def test_a_root_npmrc_that_turns_on_pnpm_shell_mode_is_unknown(tmp_path, key, server):
    (tmp_path / ".npmrc").write_text(f"{key}=true\n")
    assert "a root .npmrc turns on pnpm shell mode" in unknown_reason(tmp_path, server)


def test_a_root_npmrc_shell_mode_leaves_launches_without_pnpm_alone(tmp_path):
    (tmp_path / ".npmrc").write_text("shell-mode=true\n")
    assert_no_gap(tmp_path, {"command": "node", "args": ["server.js"]})


# Yarn's shell reads a leading [A-Za-z0-9_]+=value as an assignment, digit first
# included; Bun Shell runs `1X=y` as a command.
@pytest.mark.parametrize(
    "script,reason",
    [
        ("1=1 PATH=. node server.js", "PATH may search the project for the runner"),
        ("1=1 HOME=. node server.js", "environment relocates resolver configuration"),
        ("_1=1 9x=2 BASH_ENV=./x.sh node server.js", "shell startup file"),
        ("1=$X node $Y", "yarn exec script is not a simple command"),
        ("1=1 npx -y evil-mcp", "arguments start npx"),
    ],
)
def test_yarn_exec_reads_digit_led_assignments(tmp_path, script, reason):
    server = {"command": "yarn", "args": ["exec", script]}
    assert reason in unknown_reason(tmp_path, server)


def test_yarn_exec_records_code_loading_set_behind_a_digit_led_assignment(tmp_path):
    script = "1=1 NODE_OPTIONS=--import=data:text/javascript,x node server.js"
    record, gaps = scan(tmp_path, {"command": "yarn", "args": ["exec", script]})
    assert not gaps
    assert any(
        r.category == "launch_context"
        and r.severity.value == "medium"
        and "environment that changes code loading" in r.detail
        for r in record.risks
    ), [r.detail for r in record.risks]


# A POSIX shell and Yarn's shell split an unquoted expansion into words, so with
# D="/usr/bin/npx -y evil-mcp@latest x" the word ${D}/server runs npx. Bun Shell runs
# such a word as written, a program that does not exist.
SPLITTING = {"D": "/usr/bin/npx -y evil-mcp@latest x"}


@pytest.mark.parametrize(
    "server",
    [
        {"command": "yarn", "args": ["exec", "${D}/server"], "env": SPLITTING},
        {"command": "yarn", "args": ["exec", "A=1 $D/server", "--stdio"], "env": SPLITTING},
        {"command": "sh", "args": ["-c", "${D}/server"], "env": SPLITTING},
        {"command": "sh", "args": ["-c", "exec ${D}/server"], "env": SPLITTING},
        {"command": "bash", "args": ["-c", "A=1 $D/server --stdio"], "env": SPLITTING},
        {"command": "${D}/server --stdio", "args": [], "env": SPLITTING},
        {"command": "bun", "args": ["exec", "${HOME}/bin/server --log-level=info"]},
        {"command": "bun", "args": ["exec", "${HOME}/bin/server ~/data * {a,b} # c"]},
        {"command": "yarn", "args": ["exec", "$HOME/bin/server ~/data é"]},
    ],
)
def test_a_script_program_that_expands_before_its_name_is_unknown(tmp_path, server):
    unknown_reason(tmp_path, server)
    assert analyze(server["command"], server["args"]).context.get("inline_shell_code") == 1


@pytest.mark.skipif(not shutil.which("sh"), reason="needs sh")
def test_a_real_shell_splits_an_expanding_program_word(tmp_path):
    fake = tmp_path / "npx"
    fake.write_text('#!/bin/sh\necho "FAKE-NPX $*"\n')
    fake.chmod(0o755)
    run = subprocess.run(  # noqa: S603
        [str(shutil.which("sh")), "-c", "${D}/server"],
        env={"PATH": "/usr/bin:/bin", "D": f"{fake} {EVIL} x"},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert run.stdout.strip() == f"FAKE-NPX {EVIL} x/server"
    assert analyze("sh", ["-c", "${D}/server"]).unknown == "inline shell script"


@pytest.mark.parametrize(
    "server",
    [
        {
            "command": "bun",
            "args": ["server.ts"],
            "env": {"BUN_OPTIONS": "exec 'echo marker | cat'"},
        },
        {"command": "npx", "args": ["-y", "@yarnpkg/cli-dist@4.18.1", "exec", "echo marker | cat"]},
        {"command": "nice", "args": ["pnpm", "-c", "exec", "echo marker | cat"]},
        {"command": "yarn", "args": ["exec", "${D}/server"], "env": SPLITTING},
        {"command": "yarn", "args": ["exec", "sh", "--", "-c", "echo marker | cat"]},
        {"command": "nice", "args": ["pnpm", "--shell", "exec", "echo marker | cat"]},
        {"command": "/usr/local/lib/node_modules/corepack/dist/yarn.js", "args": ["exec", "x"]},
        {
            "command": "pnpm",
            "args": ["exec", "echo marker | cat"],
            "env": {"npm_config_shell_mode": "true"},
        },
        {"command": "pnpm", "args": ["exec", "echo marker | cat"], "npmrc": "shell-mode=true\n"},
    ],
)
def test_the_scan_gate_fails_for_launches_that_reach_a_package_manager_shell(tmp_path, server):
    root = tmp_path / "project"
    root.mkdir()
    server = dict(server)
    if "npmrc" in server:
        (root / ".npmrc").write_text(server.pop("npmrc"))
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", "--no-project-policy", str(root), "-o", str(output)])
    assert run.exit_code == 1, run.output
    assert "MCP server 's' launcher identity unknown" in run.output


SHELLS = [name for name in ("bash", "dash") if shutil.which(name)]


def run_shell(shell: str, script: str, root: Path) -> str:
    """What ``shell -c script`` makes a printing npx receive, or None when it does not run."""
    fake = root / "bin"
    work = root / "work"
    (work / "usr" / "bin").mkdir(parents=True, exist_ok=True)
    fake.mkdir(exist_ok=True)
    for path in (fake / "npx", work / "usr" / "bin" / "npx"):
        path.write_text('#!/bin/sh\necho "FAKE-NPX $*"\n')
        path.chmod(0o755)
    # A file a pattern may match; it is never run, the npx found on PATH is.
    (work / "npx").write_text("")
    run = subprocess.run(  # noqa: S603
        [str(shutil.which(shell)), "-c", script],
        cwd=work,
        env={"PATH": str(fake)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return next((line for line in run.stdout.splitlines() if line.startswith("FAKE-NPX")), "")


@pytest.mark.skipif(not SHELLS, reason="needs bash or dash")
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("script", [f"npx {EVIL}", *EXPANDED, *QUOTED, f"eval npx {EVIL}"])
def test_every_script_a_real_shell_runs_npx_from_is_classified_or_unknown(tmp_path, shell, script):
    script = script.replace("/usr/bin/", f"{tmp_path}/work/usr/bin/")
    ran = run_shell(shell, script, tmp_path)
    if script == f"npx {EVIL}":
        assert ran == f"FAKE-NPX {EVIL}"
    if not ran:
        return
    readers = [
        (shell, ["-c", script]),
        (script, []),
        ("npx", [*GATEWAY, script]),
        ("bun", ["exec", script]),
        ("yarn", ["exec", script]),
    ]
    if shell == "bash":
        readers.append(("wsl", script.split(" ")))
    for command, args in readers:
        if command == script and " " not in script:
            continue
        launch = analyze(command, args)
        if launch.unknown is None:
            # Accepted: the reading must name what the shell ran.
            assert launch.launcher == "npx", (command, args, ran)
            assert [p.spec for p in launch.packages] == ["evil-mcp@latest"], (command, args)
            assert ran == f"FAKE-NPX {EVIL}"


def cpu(function, *args, loops: int = 1) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.process_time()
        for _ in range(loops):
            function(*args)
        best = min(best, time.process_time() - start)
    return best


@pytest.mark.no_cover
def test_npm_command_does_constant_work_on_long_words():
    short = cpu(npm_command, "AbCd" * 4, loops=2000) / 2000
    long = cpu(npm_command, "AbCd" * 250_000, loops=20) / 20
    assert long < 20 * short + 2e-5, (long, short)


@pytest.mark.no_cover
def test_runner_names_in_arguments_cost_about_what_other_words_cost(tmp_path):
    def project(word: str) -> Path:
        root = tmp_path / word
        root.mkdir()
        servers = {
            f"s{index}": {"command": "node", "args": [word, "-x"] * 500} for index in range(100)
        }
        (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
        return root

    hostile, control = project("npm"), project("abc")
    scanner = MCPScanner()
    result = scanner.scan(hostile)
    assert all("launcher identity unknown" in gap for gap in result.surfaces_excluded)
    assert len(result.surfaces_excluded) == 100
    # The scan may spend its whole budget (a few steps per word) before failing closed;
    # an uncharged forward scan cost five times the control and grew with word length.
    ratio = cpu(scanner.scan, hostile) / cpu(scanner.scan, control)
    assert ratio < 2.5, ratio


@pytest.mark.no_cover
def test_long_words_after_runner_names_cost_linear_time():
    def cost(length: int, count: int) -> float:
        args = ["npm@" + "A" * length, "-x"] * count
        assert analyze("node", args).unknown == "arguments exceed the launcher scan limit"
        return cpu(analyze, "node", args) / (length * count)

    # Input grows 16 times; the cost per character may not grow with it.
    assert cost(4096, 384) < 2.5 * cost(1024, 96)


@pytest.mark.no_cover
def test_one_long_word_after_many_runner_names_costs_linear_time():
    def cost(size: int) -> float:
        repeats = int((size / 16) ** 0.5)
        args = ["npm", "-x"] * repeats + ["-x", "A" * size]
        assert analyze("node", args).unknown == "arguments exceed the launcher scan limit"
        return cpu(analyze, "node", args, loops=20) / size

    assert cost(256_000) < 2.5 * cost(64_000)


@pytest.mark.no_cover
def test_brace_and_pattern_arguments_cost_is_bounded():
    def cost(count: int) -> float:
        args = ["--stdio", "{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}{o,p}" * 4, *["n?x[a]*"] * count]
        assert analyze("node", args).unknown is not None
        return cpu(analyze, "node", args) / count

    assert cost(16_000) < 2.5 * cost(1_000)
