"""Launch text a shell or cmd re-reads is classified only when every word reads as written."""

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.mcp_launch import analyze, npm_command

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
    readers = [(shell, ["-c", script]), (script, []), ("npx", [*GATEWAY, script])]
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
