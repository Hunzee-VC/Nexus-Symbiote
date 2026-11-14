"""Shell startup files, exported functions and expansion cost cannot keep a pinned identity.

bash sources --rcfile/--init-file (also spelled -rcfile) before its -c script when it is
interactive or its standard input is a socket, an interactive POSIX shell sources $ENV,
and bash imports exported functions from the environment; each replaces the npx the
script names. The brace, bracket, pattern and ${...} readers ran in time or memory far
beyond the scan budget they were charged, so a few kilobytes of launch text stalled a scan.
"""

import json
import os
import shutil
import socket
import subprocess
import time
import tracemalloc
from pathlib import Path

import pytest

from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners import mcp_launch
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.mcp_launch import analyze

PINNED = "npx -y pkg@1.2.3"


def scan(project: Path, server: dict) -> tuple[MCPServerComponent, list[str]]:
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
    result = MCPScanner().scan(project)
    assert not result.scan_failures, result.scan_failures
    record = next(c for c in result.components if isinstance(c, MCPServerComponent))
    return record, [gap for gap in result.surfaces_excluded if "launcher identity unknown" in gap]


def assert_unknown(project: Path, server: dict, reason: str) -> None:
    record, gaps = scan(project, server)
    finding = next((r for r in record.risks if r.category == "launcher_identity"), None)
    assert finding is not None and finding.severity.value == "high", record.risks
    assert reason in finding.detail and gaps, (finding.detail, gaps)
    assert record.package_url is None and record.version_pinned is False


@pytest.mark.parametrize(
    "args",
    [
        ["--rcfile", "./evil.sh", "-ic", PINNED],
        ["--rcfile", "./evil.sh", "-i", "-c", PINNED],
        ["--init-file", "./evil.sh", "-ci", PINNED],
        ["--init-file", "./evil.sh", "-xic", PINNED],
        # Not interactive: bash still sources the file when standard input is a socket.
        ["--rcfile", "./evil.sh", "-c", PINNED],
        ["--rcfile=./evil.sh", "-c", PINNED],
        # bash reads its long options after a single dash too.
        ["-rcfile", "-x", "-ic", PINNED],
        ["-init-file", "./evil.sh", "-c", PINNED],
    ],
)
def test_a_startup_file_leaves_the_identity_unknown(tmp_path, args):
    assert_unknown(tmp_path, {"command": "bash", "args": args}, "startup file")


@pytest.mark.parametrize("option", ["-login", "-norc", "-debug", "-restricted"])
def test_a_single_dash_long_option_is_ambiguous(tmp_path, option):
    assert_unknown(tmp_path, {"command": "bash", "args": [option, "-c", PINNED]}, "ambiguous")


def test_a_startup_file_before_a_script_file_is_unknown_too():
    assert analyze("bash", ["--rcfile", "./evil.sh", "-i", "run.sh"]).unknown is not None


@pytest.mark.parametrize(
    "variable", ["BASH_FUNC_npx%%", "BASH_FUNC_npx()", "bash_func_node%%", "__BASH_FUNC<npx>()"]
)
def test_an_exported_shell_function_leaves_the_identity_unknown(tmp_path, variable):
    server = {"command": "bash", "args": ["-c", PINNED], "env": {variable: "() { :; }"}}
    assert_unknown(tmp_path, server, "shell function")


def test_a_function_definition_in_any_variable_is_unknown(tmp_path):
    # bash before 2014 imported any variable whose value starts with "() {".
    server = {"command": "bash", "args": ["-c", PINNED], "env": {"npx": "() { :; }"}}
    assert_unknown(tmp_path, server, "shell function")


def test_trace_options_and_prompts_count_as_code_loading_environment(tmp_path):
    env = {"SHELLOPTS": "errexit", "PS4": "$(./evil.sh)", "BASHOPTS": "extdebug"}
    record, gaps = scan(tmp_path, {"command": "bash", "args": ["-c", PINNED], "env": env})
    # Without tracing the prompt is never expanded: the pin stays, with a finding.
    assert not gaps and record.package_url == "pkg:npm/pkg@1.2.3"
    assert record.properties["launch_context"]["code_loading_environment"] == 3


@pytest.mark.parametrize(
    "command,args,env",
    [
        ("sh", ["-xc", PINNED], {"PS4": "$((PATH=5))"}),
        ("sh", ["-o", "xtrace", "-c", PINNED], {"PS4": "$(./evil.sh)"}),
        ("bash", ["-c", PINNED], {"SHELLOPTS": "braceexpand:xtrace", "PS4": "`./evil.sh`"}),
        # zsh sets any option in GNU long form and ignores case and underscores in names.
        ("zsh", ["--xtrace", "-c", PINNED], {"PS4": "$(./evil.sh)"}),
        ("zsh", ["--X-Trace", "-c", PINNED], {"PS4": "$(./evil.sh)"}),
        ("zsh", ["-o", "x_trace", "-c", PINNED], {"PS4": "$(./evil.sh)"}),
    ],
)
def test_a_trace_prompt_with_tracing_on_is_unknown(tmp_path, command, args, env):
    assert_unknown(tmp_path, {"command": command, "args": args, "env": env}, "trace prompt")


def test_a_trace_prompt_without_an_expansion_keeps_the_pin(tmp_path):
    server = {"command": "sh", "args": ["-xc", PINNED], "env": {"PS4": "+ "}}
    record, gaps = scan(tmp_path, server)
    assert not gaps and record.package_url == "pkg:npm/pkg@1.2.3"


def test_a_name_that_only_mentions_bash_func_keeps_the_pin(tmp_path):
    server = {"command": "npx", "args": ["-y", "pkg@1.2.3"], "env": {"MY_BASH_FUNCTIONS": "/x"}}
    record, gaps = scan(tmp_path, server)
    assert not gaps and record.package_url == "pkg:npm/pkg@1.2.3"


def test_an_exported_function_beside_a_direct_runner_is_unknown(tmp_path):
    server = {"command": "npx", "args": ["-y", "pkg@1.2.3"], "env": {"BASH_FUNC_node%%": "() {"}}
    assert_unknown(tmp_path, server, "shell function")


def test_an_exported_function_counts_as_code_loading_environment(tmp_path):
    server = {"command": "bash", "args": ["-c", PINNED], "env": {"BASH_FUNC_npx%%": "() { :; }"}}
    record, _ = scan(tmp_path, server)
    assert record.properties["launch_context"]["code_loading_environment"] == 1


def _bash(
    tmp_path: Path,
    args: list[str],
    env: dict[str, str],
    *,
    interpreter: str = "bash",
    socket_stdin: bool = False,
) -> str:
    program = shutil.which(interpreter)
    if program is None:
        pytest.skip(f"{interpreter} is not installed")
    empty = tmp_path / "bin"
    empty.mkdir(exist_ok=True)
    # An empty PATH: an npx that is not replaced cannot be found, let alone run.
    environ = {"PATH": str(empty), "HOME": str(tmp_path), "TERM": "dumb", **env}
    ours, theirs = socket.socketpair() if socket_stdin else (None, None)
    try:
        done = subprocess.run(  # noqa: S603 - resolved shell and fixed arguments
            [program, *args],
            cwd=tmp_path,
            env=environ,
            stdin=theirs if theirs is not None else subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    finally:
        for end in (ours, theirs):
            if end is not None:
                end.close()
    return done.stdout


def test_bash_runs_what_the_startup_file_defines_instead_of_npx(tmp_path):
    (tmp_path / "evil.sh").write_text('npx() { echo "REPLACED $*"; }\n')
    ran = _bash(tmp_path, ["--rcfile", "./evil.sh", "-ic", PINNED], {})
    assert "REPLACED -y pkg@1.2.3" in ran
    assert analyze("bash", ["--rcfile", "./evil.sh", "-ic", PINNED]).unknown is not None


def test_bash_reads_a_startup_file_without_i_when_stdin_is_a_socket(tmp_path):
    # Node's child_process, which MCP clients use, gives a server a socketpair for stdin;
    # bash then reads the startup file as it would for rshd.
    (tmp_path / "evil.sh").write_text('npx() { echo "REPLACED $*"; }\n')
    args = ["--rcfile", "./evil.sh", "-c", PINNED]
    assert "REPLACED -y pkg@1.2.3" in _bash(tmp_path, args, {}, socket_stdin=True)
    assert analyze("bash", args).unknown is not None


def test_bash_reads_a_single_dash_long_option(tmp_path):
    (tmp_path / "evil.sh").write_text('npx() { echo "REPLACED $*"; }\n')
    args = ["-rcfile", "./evil.sh", "-ic", PINNED]
    assert "REPLACED -y pkg@1.2.3" in _bash(tmp_path, args, {})
    assert analyze("bash", args).unknown is not None


def test_bash_runs_an_exported_function_instead_of_npx(tmp_path):
    function = {"BASH_FUNC_npx%%": '() { echo "REPLACED $*"; }'}
    ran = _bash(tmp_path, ["-c", PINNED], function)
    assert "REPLACED -y pkg@1.2.3" in ran


def cpu(function, *args) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.process_time()
        function(*args)
        best = min(best, time.process_time() - start)
    return best


HOSTILE = {
    "unclosed braces after brace lists": lambda n: "{a,b}" * 6 + "{" * n,
    "single-item sequences": lambda n: "{a,b}" * 6 + "{1..1}" * 58 + "{" * n + "}",
    "unclosed brackets": lambda n: "[" * n,
    "unclosed braces": lambda n: "{" * n,
    "parameter expansions": lambda n: "${A:-x}" * (n // 7),
    "nested default operands": lambda n: "${A:-" * (n // 5) + "npx" + "}" * (n // 5),
}


@pytest.mark.no_cover
@pytest.mark.parametrize("shape", sorted(HOSTILE))
def test_expansion_readers_cost_linear_time(shape):
    def cost(length: int) -> float:
        args = ["-y", "some-mcp@1.2.3", HOSTILE[shape](length)]
        return cpu(analyze, "npx", args) / length

    small, large = cost(4_000), cost(256_000)
    # Quadratic readers cost 64 times more per character at the larger size, and took
    # tens of seconds on a few kilobytes; a linear reader costs about the same.
    assert large < 8 * small + 2e-6, (small, large)
    assert cpu(analyze, "npx", ["-y", "some-mcp@1.2.3", HOSTILE[shape](256_000)]) < 5


def test_hostile_expansions_fail_closed_instead_of_keeping_the_pin():
    launch = analyze(
        "npx", ["-y", "some-mcp@1.2.3", HOSTILE["unclosed braces after brace lists"](3000)]
    )
    assert launch.unknown == "arguments exceed the launcher scan limit"


def test_deeply_nested_default_operands_are_unreadable_not_a_crash(tmp_path):
    word = "${A:-" * 2000 + "npx" + "}" * 2000
    assert analyze("node", ["server.js", word]).unknown == (
        "arguments contain an expansion too large to read"
    )
    record, gaps = scan(tmp_path, {"command": "node", "args": ["server.js", word]})
    assert gaps and record.package_url is None


def test_many_parameter_expansions_are_read_without_recursion(tmp_path):
    word = "${A:-x}" * 2000
    record, gaps = scan(tmp_path, {"command": "npx", "args": ["-y", "pkg@1.2.3", word]})
    assert gaps and record.package_url is None


def test_shallow_default_operands_still_name_the_program():
    assert analyze("node", ["server.js", "${A:-${B:-npx}}", "-y", "x@1"]).unknown == (
        "arguments start npx"
    )


@pytest.mark.parametrize(
    "value",
    [
        "./evil.sh",
        "evil.sh",
        "${workspaceFolder}/evil.sh",
        "",
        "/proc/self/cwd/evil.sh",
        "//proc/thread-self/cwd/evil.sh",
        "/./proc/1/cwd/evil.sh",
        # /dev/fd links to /proc/self/fd, and a .. after any link can lead into /proc.
        "/dev/fd/../cwd/evil.sh",
        "/var/run/../proc/self/cwd/evil.sh",
        "/dev/fd/3",
    ],
)
def test_a_startup_file_from_the_environment_that_may_be_in_the_project_is_unknown(tmp_path, value):
    server = {"command": "bash", "args": ["-c", PINNED], "env": {"BASH_ENV": value}}
    assert_unknown(tmp_path, server, "startup file")


def test_an_absolute_startup_file_and_env_keep_the_pin_with_a_finding(tmp_path):
    for env in ({"BASH_ENV": "/etc/profile.d/tools.sh"}, {"ENV": "production"}):
        record, gaps = scan(tmp_path, {"command": "bash", "args": ["-c", PINNED], "env": env})
        assert not gaps and record.package_url == "pkg:npm/pkg@1.2.3", env
        assert record.properties["launch_context"]["code_loading_environment"] == 1


def test_bash_sources_bash_env_before_its_script(tmp_path):
    (tmp_path / "evil.sh").write_text('npx() { echo "REPLACED $*"; }\n')
    assert "REPLACED -y pkg@1.2.3" in _bash(tmp_path, ["-c", PINNED], {"BASH_ENV": "./evil.sh"})


def test_an_interactive_posix_shell_reads_env_from_the_project(tmp_path):
    server = {"command": "sh", "args": ["-ic", PINNED], "env": {"ENV": "./evil.sh"}}
    assert_unknown(tmp_path, server, "startup file")
    # Not interactive: ENV is never read, and production is not a file anyway.
    record, gaps = scan(tmp_path, {"command": "sh", "args": ["-c", PINNED], "env": server["env"]})
    assert not gaps and record.package_url == "pkg:npm/pkg@1.2.3"


def test_sh_sources_env_when_interactive(tmp_path):
    (tmp_path / "evil.sh").write_text('npx() { echo "REPLACED $*"; }\n')
    ran = _bash(tmp_path, ["-ic", PINNED], {"ENV": "./evil.sh"}, interpreter="sh")
    assert "REPLACED -y pkg@1.2.3" in ran


def test_a_path_through_proc_may_search_the_project(tmp_path):
    env = {"PATH": "/proc/self/cwd/bin:/usr/bin"}
    assert_unknown(tmp_path, {"command": "npx", "args": ["-y", "pkg@1.2.3"], "env": env}, "PATH")


@pytest.mark.skipif(not os.path.isdir("/proc/self/cwd"), reason="no /proc/self/cwd")
def test_bash_sources_bash_env_through_proc(tmp_path):
    (tmp_path / "evil.sh").write_text('npx() { echo "REPLACED $*"; }\n')
    env = {"BASH_ENV": "/proc/self/cwd/evil.sh"}
    assert "REPLACED -y pkg@1.2.3" in _bash(tmp_path, ["-c", PINNED], env)


def peak_bytes(function, *args) -> int:
    tracemalloc.start()
    try:
        function(*args)
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.no_cover
def test_a_long_brace_list_is_not_copied_once_per_item():
    # Each of 64,000 items copied the 64,000-character tail: 3.9 GB for a 128 KB word.
    word = "{" + "," * 64_000 + "}" + "x" * 64_000
    assert peak_bytes(analyze, "npx", ["-y", "pkg@1.2.3", word]) < 32 * 2**20
    assert cpu(analyze, "npx", ["-y", "pkg@1.2.3", word]) < 2


@pytest.mark.no_cover
def test_a_pattern_longer_than_any_program_is_not_compiled():
    # fnmatch compiled the whole word: 30 s and 1.9 GB for 4 MB of "*a".
    word = "*a" * 500_000
    assert peak_bytes(analyze, "npx", ["-y", "pkg@1.2.3", word]) < 32 * 2**20
    assert cpu(analyze, "npx", ["-y", "pkg@1.2.3", word]) < 2


def test_a_pattern_as_long_as_a_program_name_still_names_it():
    assert analyze("node", ["server.js", "n*p*x", "-y", "x@1"]).unknown == "arguments start npx"
    # A bracket reads as any one character, so ??x names npx, dnx and the like.
    reason = analyze("node", ["server.js", "[nN][!a]x", "-y", "x@1"]).unknown
    assert reason is not None and reason.startswith("arguments start ")


@pytest.mark.no_cover
def test_a_word_with_many_long_readings_is_charged_before_it_is_copied():
    # Six expansions make 64 readings, each a copy of a 4 MB word.
    word = "${A}" * 6 + "x" * 4_000_000
    assert peak_bytes(analyze, "npx", ["-y", "pkg@1.2.3", word]) < 160 * 2**20


FIXTURES = Path(__file__).parent / "fixtures"


def _config(servers: int, keys: int) -> dict:
    values = {f"key{index}": f"value-{index}" for index in range(keys)}
    return {"servers": {f"s{index}": dict(values) for index in range(servers)}}


def _inline_configs() -> list[str]:
    configs = json.loads((FIXTURES / "mcp-inline-json-arguments.json").read_text())
    # Both failed on the budget once each brace search cost a step: the spaced one as 120
    # words of a command line, the compact one as a brace expansion.
    found = [
        json.dumps(configs["spaced"]),
        json.dumps(configs["compact"], separators=(",", ":")),
    ]
    for servers, keys in [(1, 60), (20, 3), (8, 8), (30, 2)]:
        found.append(json.dumps(_config(servers, keys), separators=(",", ":")))
    return found


@pytest.mark.parametrize("config", _inline_configs())
def test_inline_json_arguments_keep_the_pin(config):
    argument = "--config=" + config
    launch = analyze("npx", ["-y", "@scope/server@1.2.3", argument])
    assert launch.unknown is None, (len(argument), launch.unknown)
    assert [package.spec for package in launch.packages] == ["@scope/server@1.2.3"]


@pytest.mark.parametrize(
    "args",
    [
        ["-o", "interactive", "-c", PINNED],
        ["-c", "-o", "interactive", PINNED],
        ["-xo", "interactive", "-c", PINNED],
        ["-o", "inter", "-c", PINNED],
    ],
)
def test_an_interactive_option_makes_the_shell_read_env(tmp_path, args):
    server = {"command": "sh", "args": args, "env": {"ENV": "./evil.sh"}}
    assert_unknown(tmp_path, server, "startup file")


def test_dash_reads_env_with_the_interactive_option(tmp_path):
    (tmp_path / "evil.sh").write_text('npx() { echo "REPLACED $*"; }\n')
    args = ["-o", "interactive", "-c", PINNED]
    assert "REPLACED -y pkg@1.2.3" in _bash(
        tmp_path, args, {"ENV": "./evil.sh"}, interpreter="dash"
    )


def test_dash_runs_the_project_runner_through_a_trace_prompt(tmp_path):
    runner = tmp_path / "5" / "npx"
    runner.parent.mkdir()
    runner.write_text('#!/bin/sh\necho "PROJECT $*"\n')
    runner.chmod(0o755)
    ran = _bash(tmp_path, ["-xc", PINNED], {"PS4": "$((PATH=5))"}, interpreter="dash")
    assert "PROJECT -y pkg@1.2.3" in ran


@pytest.mark.skipif(not os.path.isdir("/dev/fd/../cwd"), reason="no /dev/fd link into /proc")
def test_bash_sources_bash_env_through_dev_fd(tmp_path):
    (tmp_path / "evil.sh").write_text('npx() { echo "REPLACED $*"; }\n')
    env = {"BASH_ENV": "/dev/fd/../cwd/evil.sh"}
    assert "REPLACED -y pkg@1.2.3" in _bash(tmp_path, ["-c", PINNED], env)


def test_a_path_through_dev_fd_may_search_the_project(tmp_path):
    env = {"PATH": "/dev/fd/../cwd/bin:/usr/bin"}
    assert_unknown(tmp_path, {"command": "npx", "args": ["-y", "pkg@1.2.3"], "env": env}, "PATH")


def _pattern_words(count: int) -> list[str]:
    letters = "abcdefghijklmnopqrstuvwxyz"
    words = []
    for index in range(count):
        tag = "".join(letters[(index // 26**place) % 26] for place in range(4))
        words.append("".join(tag[step % 4] + "${A}" for step in range(6)) + "?*" * 14)
    return words


@pytest.mark.no_cover
def test_pattern_readings_are_charged_and_not_compiled_for_each():
    # 64 readings of each word, each a different pattern: compiling every one cost about
    # 40 seconds for 1,000 small servers.
    args = ["-y", "pkg@1.2.3", *_pattern_words(300)]
    assert cpu(analyze, "npx", args) < 1
    assert max(map(len, mcp_launch._PATTERNS), default=0) <= 2 * mcp_launch._LONGEST_PROGRAM + 2


def test_the_scan_budget_does_not_depend_on_patterns_earlier_scans_compiled():
    patterns = ["b*h", "b?sh", "ba*", "*ash", "d*h", "d?sh", "da*", "k*h", "k?h"]
    args = [word for pattern in patterns for word in (pattern, "x")]
    mcp_launch._PATTERNS.clear()
    first = analyze("server", args).unknown
    assert first == "arguments exceed the launcher scan limit"
    assert analyze("server", args).unknown == first


@pytest.mark.no_cover
def test_commas_in_one_word_do_not_pay_for_other_words():
    expensive = [word.replace("?*", "") for word in _pattern_words(750)]
    donors = ["{}" + "," * 65] * 248
    alone = cpu(analyze, "npx", ["-y", "pkg@1.2.3", *expensive])
    funded = cpu(analyze, "npx", ["-y", "pkg@1.2.3", *expensive, *donors])
    # Commas anywhere in a braced word once raised the whole budget: 113 s for 1 MB.
    assert funded < 4 * alone + 0.2, (alone, funded)
