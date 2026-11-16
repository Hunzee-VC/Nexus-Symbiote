"""Gate scripts refuse inputs a pull request controls that would hollow them out."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.support import load_script

locks = load_script("check_locks")
advisories = load_script("check_dependency_advisories")
wheel = load_script("check_wheel_security")


@pytest.mark.parametrize(
    "cutoff",
    [
        "2099-01-01T00:00:00Z",  # in the future: the next `make lock` reuses it
        (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z"),
        "2026-11-01",
        "2026-11-01T12:00:00Z",
        "2026-13-01T00:00:00Z",
        None,
    ],
)
def test_an_upload_cut_off_inside_the_cooldown_or_not_of_the_written_form_is_refused(cutoff):
    assert locks.cutoff_issue(cutoff) is not None


def test_an_upload_cut_off_past_the_cooldown_is_accepted() -> None:
    moment = (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00Z")
    assert locks.cutoff_issue(moment) is None


def test_installing_a_lock_never_follows_a_planted_staging_symlink(tmp_path: Path) -> None:
    # A branch can commit .requirements-ci.lock.new pointing at a file the maintainer
    # can write; installing the regenerated lock must not write through it.
    victim = tmp_path / "authorized_keys"
    victim.write_text("keep\n")
    target = tmp_path / "requirements-ci.lock"
    target.write_text("old\n")
    (tmp_path / ".requirements-ci.lock.new").symlink_to(victim)
    source = tmp_path / "resolved.lock"
    source.write_text("new\n")
    locks._install(source, target)
    assert victim.read_text() == "keep\n"
    assert target.read_text() == "new\n"
    assert not target.is_symlink()


def test_a_lock_that_is_a_symlink_is_not_replaced(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("old\n")
    target = tmp_path / "requirements-ci.lock"
    target.symlink_to(elsewhere)
    source = tmp_path / "resolved.lock"
    source.write_text("new\n")
    with pytest.raises(locks.LockError):
        locks._install(source, target)
    assert elsewhere.read_text() == "old\n"


def _waiver(**changes: str) -> dict[str, str]:
    waiver = {
        "advisory_id": "GHSA-aaaa-bbbb-cccc",
        "package": "requests",
        "version": "2.19.0",
        "reason": "Reviewed: the vulnerable code path is never reached here.",
        "expires": (date.today() + timedelta(days=10)).isoformat(),
    }
    return {**waiver, **changes}


@pytest.mark.parametrize(
    "changes",
    [
        {"advisory_id": "GHSA-x\n::error file=a::spoofed"},
        {"advisory_id": "::stop-commands::x"},
        {"package": "Requests"},
        {"package": "requests_oauth"},
        {"version": "2.19.0\n::warning::x"},
    ],
)
def test_a_waiver_field_that_could_reach_the_log_or_never_apply_is_refused(
    tmp_path: Path, changes: dict[str, str]
) -> None:
    path = tmp_path / "waivers.json"
    path.write_text(json.dumps({"waivers": [_waiver(**changes)]}))
    with pytest.raises(ValueError) as refused:
        advisories.load_waivers(path, date.today())
    assert "\n" not in str(refused.value)


def _report(nodeid: str, *, when: str = "call", outcome: str = "passed") -> SimpleNamespace:
    return SimpleNamespace(
        nodeid=nodeid,
        when=when,
        passed=outcome == "passed",
        skipped=outcome == "skipped",
    )


def test_a_case_module_skipped_at_collection_fails_the_wheel_check() -> None:
    required = wheel.RequireExecution()
    required.pytest_collectreport(_report("test_scoped_collection.py", outcome="skipped"))
    assert required.skipped == ["test_scoped_collection.py"]


def test_a_named_case_that_never_ran_is_reported() -> None:
    required = wheel.RequireExecution()
    first, second = wheel.CASES[0], wheel.CASES[1]
    required.pytest_runtest_logreport(_report(first))
    required.pytest_runtest_logreport(_report(f"{second}[param]"))
    missing = required.unexercised(wheel.CASES)
    assert first not in missing and second not in missing
    assert missing == list(wheel.CASES[2:])


def test_a_whole_module_case_is_exercised_by_any_of_its_tests() -> None:
    required = wheel.RequireExecution()
    module = next(case for case in wheel.CASES if "::" not in case)
    assert module in required.unexercised(wheel.CASES)
    required.pytest_runtest_logreport(_report(f"{module}::test_anything[param]"))
    assert module not in required.unexercised(wheel.CASES)
    required.pytest_runtest_logreport(_report(f"{module}x::test_other"))
    other = next(case for case in wheel.CASES if "::" not in case and case != module)
    assert other in required.unexercised(wheel.CASES)
