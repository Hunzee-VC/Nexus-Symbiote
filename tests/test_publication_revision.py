"""Publication requires successful CI for the exact source, not just configured checks."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "publication_controls", Path(__file__).parents[1] / "scripts/check_repository_controls.py"
)
assert SPEC and SPEC.loader
controls = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controls)


def test_settings_without_a_verified_source_cannot_approve_publication(monkeypatch):
    monkeypatch.setattr("sys.argv", ["check_repository_controls", "--repo", "owner/repo"])
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    monkeypatch.setenv("GH_TOKEN", "synthetic-test-token")
    monkeypatch.setattr(
        controls,
        "fetch_branch",
        lambda *_: {
            "protected": True,
            "protection": {
                "enabled": True,
                "required_status_checks": {
                    "enforcement_level": "everyone",
                    "contexts": ["Verified CI"],
                    "checks": [],
                },
            },
        },
    )
    assert controls.main() != 0


def branch(sha="a" * 40):
    return {
        "protected": True,
        "commit": {"sha": sha},
        "protection": {
            "enabled": True,
            "required_status_checks": {
                "enforcement_level": "everyone",
                "contexts": ["Verified CI"],
                "checks": [],
            },
        },
    }


def evidence():
    return (
        {
            "id": 123,
            "run_attempt": 2,
            "head_sha": "a" * 40,
            "head_branch": "main",
            "head_repository": {"full_name": "owner/repo"},
            "path": ".github/workflows/ci.yml",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
        },
        {
            "total_count": 1,
            "jobs": [
                {
                    "name": "Verified CI",
                    "run_id": 123,
                    "run_attempt": 2,
                    "status": "completed",
                    "conclusion": "success",
                }
            ],
        },
    )


def evaluate(run, jobs):
    return controls.evaluate_verification(run, jobs, repo="owner/repo", branch="main", sha="a" * 40)


def test_exact_source_and_latest_successful_workflow_attempt_pass():
    assert controls.evaluate_revision(branch(), "a" * 40) == []
    assert evaluate(*evidence()) == []


@pytest.mark.parametrize(
    "change",
    [
        {"head_sha": "b" * 40},
        {"head_branch": "other"},
        {"path": ".github/workflows/fake.yml"},
        {"event": "pull_request"},
        {"head_repository": {"full_name": "attacker/repo"}},
        {"head_repository": None},
        {"id": True},
        {"run_attempt": True},
    ],
)
def test_other_source_workflow_or_attempt_cannot_supply_verification(change):
    run, jobs = evidence()
    run.update(change)
    assert evaluate(run, jobs)


@pytest.mark.parametrize(
    "status,conclusion",
    [
        ("queued", None),
        ("in_progress", None),
        ("completed", "failure"),
        ("completed", "cancelled"),
        ("completed", "skipped"),
        ("completed", "neutral"),
    ],
)
def test_green_job_cannot_override_an_unsuccessful_latest_run(status, conclusion):
    run, jobs = evidence()
    run.update(status=status, conclusion=conclusion)
    assert evaluate(run, jobs)


@pytest.mark.parametrize(
    "change",
    [
        {"run_id": 124},
        {"run_attempt": 1},
        {"run_attempt": True},
        {"status": "in_progress"},
        {"conclusion": "failure"},
        {"conclusion": "skipped"},
        {"name": "other"},
    ],
)
def test_verified_job_must_belong_to_the_successful_current_attempt(change):
    run, jobs = evidence()
    jobs["jobs"][0].update(change)
    assert evaluate(run, jobs)


@pytest.mark.parametrize("change", ["missing", "duplicate", "partial", "invalid", "boolean-total"])
def test_missing_ambiguous_or_truncated_jobs_fail_closed(change):
    run, jobs = evidence()
    if change == "missing":
        jobs = {"jobs": [], "total_count": 0}
    elif change == "duplicate":
        jobs["jobs"] *= 2
        jobs["total_count"] = 2
    elif change == "partial":
        jobs["total_count"] = 101
    elif change == "invalid":
        jobs["jobs"] = [None]
    else:
        jobs["total_count"] = True
    assert evaluate(run, jobs)


@pytest.mark.parametrize("sha", ["", "main", "a" * 39, "g" * 40, "b" * 40])
def test_unknown_or_different_branch_revision_cannot_pass(sha):
    assert controls.evaluate_revision(branch(), sha)


def test_workflow_query_cannot_fall_back_to_an_older_green_run(monkeypatch):
    run, jobs = evidence()
    run["conclusion"] = "failure"
    calls = []

    def api(repo, path, token):
        calls.append((repo, path))
        if len(calls) == 1:
            return {"workflow_runs": [run], "total_count": 2}
        return jobs

    monkeypatch.setattr(controls, "_fetch", api)
    result = controls.fetch_verification("owner/repo", "a" * 40, "synthetic")
    assert evaluate(*result)
    assert calls == [
        ("owner/repo", "actions/workflows/ci.yml/runs?head_sha=" + "a" * 40 + "&per_page=1"),
        ("owner/repo", "actions/runs/123/jobs?filter=latest&per_page=100"),
    ]


@pytest.mark.parametrize("runs", [[], None, [None], [{"id": True}], [{"id": -1}]])
def test_missing_or_malformed_workflow_evidence_is_denied(monkeypatch, runs):
    monkeypatch.setattr(controls, "_fetch", lambda *_: {"workflow_runs": runs})
    assert evaluate(*controls.fetch_verification("owner/repo", "a" * 40, "synthetic"))


def test_cli_requires_both_protection_and_exact_revision_ci(monkeypatch):
    monkeypatch.setattr("sys.argv", ["check_repository_controls", "--repo", "owner/repo"])
    monkeypatch.setenv("GH_TOKEN", "synthetic-test-token")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setattr(controls, "fetch_branch", lambda *_: branch())
    monkeypatch.setattr(controls, "fetch_verification", lambda *_: evidence())
    assert controls.main() == 0
    monkeypatch.setattr(controls, "fetch_verification", lambda *_: (None, None))
    assert controls.main() == 1


def test_api_failure_blocks_publication_without_logging_credentials(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["check_repository_controls", "--repo", "owner/repo"])
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GH_TOKEN", "synthetic-secret-CANARY")
    monkeypatch.setattr(controls, "fetch_branch", lambda *_: branch())

    def unavailable(*_):
        raise OSError("synthetic-secret-CANARY")

    monkeypatch.setattr(controls, "fetch_verification", unavailable)
    assert controls.main() == 2
    assert "CANARY" not in capsys.readouterr().err
