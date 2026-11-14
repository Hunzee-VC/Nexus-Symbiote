"""The suite's own isolation, time limit and skip accounting (tests/conftest.py)."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from tests.support import ROOT

CONFTEST = (Path(__file__).parent / "conftest.py").read_text(encoding="utf-8")


@pytest.fixture
def suite(pytester: pytest.Pytester) -> pytest.Pytester:
    pytester.makeconftest(CONFTEST)
    pytester.makeini("[pytest]\ntest_timeout = 30\n")
    return pytester


def test_ambient_tool_and_runner_variables_never_reach_a_test(suite, monkeypatch):
    for name in (
        "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY",
        "NEXUS_SYMBIOTE_MODE",
        "NEXUS_SYMBIOTE_LIMITS",
        "SYMBIOTE_SCAN_PATH",
        "GITHUB_OUTPUT",
        "GH_TOKEN",
        "FORCE_COLOR",
    ):
        monkeypatch.setenv(name, "ambient-value")
    monkeypatch.setenv("HOME", "/nonexistent-real-home")
    suite.makepyfile(
        """
        import os
        from pathlib import Path

        def test_isolated():
            leaked = [k for k, v in os.environ.items() if v == "ambient-value"]
            assert leaked == []
            home = Path(os.environ["HOME"])
            assert home.is_dir() and home != Path("/nonexistent-real-home")
            assert Path(os.environ["XDG_CACHE_HOME"]).parent == home
        """
    )
    suite.runpytest("-p", "no:cacheprovider").assert_outcomes(passed=1)


def test_a_hung_test_fails_with_its_traceback_instead_of_stalling_the_run(suite):
    suite.makepyfile(
        """
        import time
        import pytest

        @pytest.mark.timeout(0.5)
        def test_hangs():
            time.sleep(30)

        def test_next():
            pass
        """
    )
    result = suite.runpytest("-p", "no:cacheprovider")
    result.assert_outcomes(passed=1, failed=1)
    result.stdout.fnmatch_lines(["*time.sleep(30)*", "*0.5-second time limit*"])


@pytest.mark.parametrize(
    ("reason", "strict", "status"),
    [
        ("sigstore is not installed", True, pytest.ExitCode.TESTS_FAILED),
        ("sigstore is not installed", False, pytest.ExitCode.OK),
        ("the file system is case-sensitive", True, pytest.ExitCode.OK),
        ("file system rejects the name", True, pytest.ExitCode.OK),
        # The expected reasons are anchored: containing the words is not enough.
        ("quarantined for now; file system rejects nothing", True, pytest.ExitCode.TESTS_FAILED),
        ("flaky on case-sensitive hosts", True, pytest.ExitCode.TESTS_FAILED),
    ],
)
def test_only_host_file_system_skips_pass_a_strict_run(suite, reason, strict, status):
    suite.makepyfile(
        f"""
        import pytest

        def test_runs():
            pass

        def test_skips():
            pytest.skip({reason!r})
        """
    )
    result = suite.runpytest("-p", "no:cacheprovider", *(["--strict-skips"] if strict else []))
    assert result.ret == status
    result.stdout.fnmatch_lines(["*skip accounting*", f"*test_skips: {reason}*"])


def test_a_module_level_import_skip_is_accounted_for(suite):
    suite.makepyfile(
        test_runs="def test_runs():\n    pass\n",
        test_optional=(
            "import pytest\n"
            "pytest.importorskip('a_module_that_is_not_installed')\n"
            "def test_never_runs():\n    pass\n"
        ),
    )
    result = suite.runpytest("-p", "no:cacheprovider", "--strict-skips")
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(["UNEXPECTED: *a_module_that_is_not_installed*"])


def test_a_test_that_leaves_the_offline_guard_enforced_fails(suite):
    suite.makepyfile(
        """
        from nexus_symbiote import modes

        KEPT = []

        def test_leaks():
            KEPT.append(modes.enforce(modes.Mode.OFFLINE))
            KEPT[-1].__enter__()
        """
    )
    result = suite.runpytest_subprocess("-p", "no:cacheprovider")
    result.assert_outcomes(passed=1, errors=1)
    result.stdout.fnmatch_lines(["*left the offline mode enforced*"])


def test_a_test_that_leaves_collection_limits_fails_and_the_next_starts_at_the_defaults(suite):
    suite.makepyfile(
        """
        from nexus_symbiote import limits

        KEPT = []

        def test_leaks():
            KEPT.append(limits.applied(limits.resolve(["entries=3"], {})))
            KEPT[-1].__enter__()
            assert limits.current().entries == 3

        def test_next():
            assert limits.current() == limits.DEFAULTS
        """
    )
    result = suite.runpytest_subprocess("-p", "no:cacheprovider")
    result.assert_outcomes(passed=2, errors=1)
    result.stdout.fnmatch_lines(["*left collection limits other than the defaults*"])


@pytest.mark.parametrize(("ci", "status"), [(None, pytest.ExitCode.OK), ("true", 1)])
def test_a_missing_pip_is_an_expected_skip_only_outside_ci(suite, monkeypatch, ci, status):
    if ci is None:
        monkeypatch.delenv("CI", raising=False)
    else:
        monkeypatch.setenv("CI", ci)
    suite.makepyfile(
        """
        import pytest

        def test_skips():
            pytest.skip("pip is not importable here; CI, which installs with pip, runs this test")
        """
    )
    result = suite.runpytest("-p", "no:cacheprovider", "--strict-skips")
    assert result.ret == status
    result.stdout.fnmatch_lines([f"{'UNEXPECTED' if ci else 'expected'}: *pip is not importable*"])


def test_locked_only_tests_are_registered_and_left_out_only_at_the_floors(suite):
    suite.makepyfile(
        """
        import pytest

        @pytest.mark.locked_only
        def test_generated_schema_equals_the_committed_file():
            pass

        def test_behaviour():
            pass
        """
    )
    unknown_marks_fail = ("-W", "error::pytest.PytestUnknownMarkWarning")
    result = suite.runpytest("-p", "no:cacheprovider", *unknown_marks_fail, "-m", "not locked_only")
    result.assert_outcomes(passed=1, deselected=1)
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))

    def pytest_runs(job):
        steps = workflow["jobs"][job]["steps"]
        return [s["run"] for s in steps if "python -m pytest" in s.get("run", "")]

    assert pytest_runs("floor") and all('-m "not locked_only"' in r for r in pytest_runs("floor"))
    selects = re.compile(r"\s-[mk]\s+[\"']|locked_only")
    for job in ("test", "coverage"):
        assert pytest_runs(job) and not any(selects.search(run) for run in pytest_runs(job))


def test_every_subprocess_a_test_starts_has_its_own_timeout():
    """A hung child process must fail its test, not use up the CI job's time budget."""
    untimed = []
    for path in sorted(Path(__file__).parent.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr in {"run", "call", "check_call", "check_output"}
                and not any(k.arg in {"timeout", None} for k in node.keywords)
            ):
                untimed.append(f"{path.name}:{node.lineno}")
    assert untimed == []


def test_the_scaling_check_tells_linear_from_quadratic_work():
    from tests.support import scaling_ratio

    def linear(scale):
        sum(range(2_000_000 * scale))

    def quadratic(scale):
        n = 1_000 * scale
        for _ in range(n):
            for _ in range(n):
                pass

    assert scaling_ratio(linear) < 10
    assert scaling_ratio(quadratic) > 10


def test_a_ratio_skewed_by_a_burst_of_load_is_measured_once_more(monkeypatch):
    from tests import support

    def clock(durations):
        ticks, now = [], 0.0
        for duration in durations:
            ticks += [now, now + duration]
            now += duration
        return SimpleNamespace(process_time=iter(ticks).__next__)

    # Two runs at four times the size, then two at the size: the first pair of sizes
    # looks quadratic, the second is linear.
    monkeypatch.setattr(support, "time", clock([1.6, 1.6, 0.1, 0.1, 0.4, 0.4, 0.1, 0.1]))
    assert support.scaling_ratio(lambda scale: None) == pytest.approx(4)
    monkeypatch.setattr(support, "time", clock([1.6, 1.6, 0.1, 0.1] * 2))
    assert support.scaling_ratio(lambda scale: None) == pytest.approx(16)
    monkeypatch.setattr(support, "time", clock([0.5, 0.5, 0.1, 0.1]))
    assert support.scaling_ratio(lambda scale: None) == pytest.approx(5)
