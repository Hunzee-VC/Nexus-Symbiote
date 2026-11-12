"""Shell startup files, exported functions and expansion cost cannot keep a pinned identity.

An interactive bash sources --rcfile/--init-file before its -c script, and bash imports a
BASH_FUNC_<name>%% variable as a function; either replaces the npx the script names. The
brace, bracket and ${...} readers ran in time quadratic in a word's length while the scan
budget was charged linearly, so a few kilobytes of launch text stalled a scan.
"""

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from nexus_symbiote.core.models import MCPServerComponent
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
    ],
)
def test_an_interactive_shell_with_a_startup_file_leaves_the_identity_unknown(tmp_path, args):
    assert_unknown(tmp_path, {"command": "bash", "args": args}, "startup file")


def test_a_startup_file_of_a_non_interactive_shell_is_never_read(tmp_path):
    record, gaps = scan(tmp_path, {"command": "bash", "args": ["--rcfile", "x", "-c", PINNED]})
    assert not gaps and record.package_url == "pkg:npm/pkg@1.2.3"


def test_a_startup_file_before_a_script_file_is_unknown_too():
    assert analyze("bash", ["--rcfile", "./evil.sh", "-i", "run.sh"]).unknown is not None


@pytest.mark.parametrize("variable", ["BASH_FUNC_npx%%", "BASH_FUNC_npx()", "bash_func_node%%"])
def test_an_exported_shell_function_leaves_the_identity_unknown(tmp_path, variable):
    server = {"command": "bash", "args": ["-c", PINNED], "env": {variable: "() { :; }"}}
    assert_unknown(tmp_path, server, "shell function")


def test_an_exported_function_beside_a_direct_runner_is_unknown(tmp_path):
    server = {"command": "npx", "args": ["-y", "pkg@1.2.3"], "env": {"BASH_FUNC_node%%": "() {"}}
    assert_unknown(tmp_path, server, "shell function")


def test_an_exported_function_counts_as_code_loading_environment(tmp_path):
    server = {"command": "bash", "args": ["-c", PINNED], "env": {"BASH_FUNC_npx%%": "() { :; }"}}
    record, _ = scan(tmp_path, server)
    assert record.properties["launch_context"]["code_loading_environment"] == 1


def _bash(tmp_path: Path, args: list[str], env: dict[str, str]) -> str:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    empty = tmp_path / "bin"
    empty.mkdir()
    # An empty PATH: an npx that is not replaced cannot be found, let alone run.
    environ = {"PATH": str(empty), "HOME": str(tmp_path), "TERM": "dumb", **env}
    done = subprocess.run(  # noqa: S603 - resolved bash and fixed arguments
        [bash, *args],
        cwd=tmp_path,
        env=environ,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return done.stdout


def test_bash_runs_what_the_startup_file_defines_instead_of_npx(tmp_path):
    (tmp_path / "evil.sh").write_text('npx() { echo "REPLACED $*"; }\n')
    ran = _bash(tmp_path, ["--rcfile", "./evil.sh", "-ic", PINNED], {})
    assert "REPLACED -y pkg@1.2.3" in ran
    assert analyze("bash", ["--rcfile", "./evil.sh", "-ic", PINNED]).unknown is not None


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


@pytest.mark.parametrize("value", ["./evil.sh", "evil.sh", "${workspaceFolder}/evil.sh", ""])
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
