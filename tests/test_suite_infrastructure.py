"""The suite's own isolation, time limit and skip accounting (tests/conftest.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

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
