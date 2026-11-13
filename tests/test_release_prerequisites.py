"""The publication preflight's soak period, tag ruleset, environment and release-tag checks."""

from __future__ import annotations

import http.client
import json
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError

import pytest

from tests.support import ROOT, load_script

controls = load_script("check_repository_controls")
SHA = "a" * 40
ARGV = ["check_repository_controls", "--repo", "owner/repo"]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


def branch(committed="2026-11-09T06:00:00Z"):
    return {
        "protected": True,
        "commit": {"sha": SHA, "commit": {"committer": {"date": committed}}},
        "protection": {
            "enabled": True,
            "required_status_checks": {
                "enforcement_level": "everyone",
                "contexts": ["Verified CI"],
                "checks": [{"context": "Verified CI", "app_id": 15368}],
            },
        },
    }


def run(**changes):
    return {
        "id": 123,
        "run_attempt": 1,
        "head_sha": SHA,
        "head_branch": "main",
        "head_repository": {"full_name": "owner/repo"},
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-11-09T06:01:00Z",
        **changes,
    }


def landed(metadata=None, runs=None):
    return controls.landed_at(
        metadata or branch(),
        [run()] if runs is None else runs,
        repo="owner/repo",
        branch="main",
        sha=SHA,
    )


def test_the_landing_time_is_the_later_of_commit_and_first_push_run():
    assert landed() == datetime(2026, 11, 9, 6, 1, tzinfo=UTC)
    # A commit dated long ago cannot shorten the soak once GitHub has seen it land.
    old = branch("2026-10-01T00:00:00Z")
    assert landed(old) == datetime(2026, 11, 9, 6, 1, tzinfo=UTC)
    # A later dispatch or an untrusted run does not move the landing time.
    runs = [run(), run(id=200, event="workflow_dispatch", created_at="2026-11-10T11:00:00Z")]
    runs.append(run(id=300, event="pull_request", created_at="2026-11-01T00:00:00Z"))
    assert landed(old, runs) == datetime(2026, 11, 9, 6, 1, tzinfo=UTC)
    # Without a trusted run, the commit date is only the committer's claim.
    assert landed(branch(), []) is None


DISPATCHED = "2026-11-10T11:50:00Z"


def test_a_commit_without_a_push_run_has_no_landing_time():
    # A "[skip ci]" push creates no push run; its commit date can say anything, and a
    # dispatch "on main" may have run on a tag named main, so neither shows the landing.
    backdated = branch("2026-11-07T12:00:00Z")
    only_dispatch = [run(event="workflow_dispatch", created_at=DISPATCHED)]
    assert landed(backdated, only_dispatch) is None
    assert controls.evaluate_soak(None, NOW + timedelta(days=30), "")
    # Runs elsewhere count for nothing either; only a push run on the branch does.
    early = "2026-11-01T00:00:00Z"
    elsewhere = [
        run(id=90, head_branch="release-prep", created_at=early),
        run(id=91, event="pull_request", created_at=early),
        run(id=92, head_repository={"full_name": "fork/repo"}, created_at=early),
        run(id=93, path=".github/workflows/other.yml", created_at=early),
    ]
    assert landed(backdated, [*only_dispatch, *elsewhere]) is None
    pushed = run(id=124, created_at="2026-11-10T11:55:00Z")
    assert landed(backdated, [*only_dispatch, *elsewhere, pushed]) == datetime(
        2026, 11, 10, 11, 55, tzinfo=UTC
    )


def test_a_push_run_marks_the_landing_even_after_an_earlier_dispatch():
    # A dispatch names its ref only by name, which a tag can share with the branch, so a
    # dispatch "on main" before the push run cannot pull the landing time back.
    early = run(id=50, event="workflow_dispatch", created_at="2026-11-01T00:00:00Z")
    assert landed(branch("2026-10-01T00:00:00Z"), [early, run()]) == datetime(
        2026, 11, 9, 6, 1, tzinfo=UTC
    )


@pytest.mark.parametrize(
    "metadata,runs",
    [
        (branch("yesterday"), None),
        (branch("2026-11-09T06:00:00"), None),
        ({"commit": {"sha": SHA}}, None),
        (branch(), [run(created_at=None)]),
        (branch(), [run(event="workflow_dispatch", created_at="yesterday")]),
        (branch(), [run(), run(id=124, event="workflow_dispatch", created_at=None)]),
    ],
)
def test_an_unreadable_landing_time_is_unknown(metadata, runs):
    assert landed(metadata, runs) is None


@pytest.mark.parametrize(
    "age,override,allowed",
    [
        (timedelta(hours=25), "", True),
        (timedelta(hours=24), "", True),
        (timedelta(hours=23, minutes=59), "", False),
        (timedelta(minutes=5), "", False),
        (timedelta(minutes=5), "urgent", False),
        (timedelta(minutes=5), "Fixes GHSA-xxxx-yyyy remote gate bypass", True),
        (timedelta(minutes=-30), "", False),
    ],
)
def test_pypi_publication_waits_for_the_soak_unless_a_reason_is_given(age, override, allowed):
    assert (controls.evaluate_soak(NOW - age, NOW, override) == []) is allowed


def test_an_unknown_landing_time_cannot_satisfy_the_soak():
    assert controls.evaluate_soak(None, NOW, "")


def test_the_override_reason_cannot_carry_runner_commands():
    reason = controls.override_reason("::warning::x ##[set-output name=a]%0Ab\n\x1b[31m")
    assert "#" not in reason and "[" not in reason and "%" not in reason
    assert "\n" not in reason and "\x1b" not in reason


def committed_ruleset(**changes):
    """The committed ruleset as GitHub returns it to an administrator, who cannot bypass it."""
    ruleset = json.loads((ROOT / "config/github-release-tag-ruleset.json").read_text())
    return {"id": 7, **ruleset, "current_user_can_bypass": "never", **changes}


def workflow_view(**changes):
    """The committed ruleset as GitHub returns it to a caller that cannot edit it."""
    ruleset = committed_ruleset(**changes)
    del ruleset["bypass_actors"]
    return ruleset


def test_the_committed_release_tag_ruleset_satisfies_the_administrator_check():
    for verify in (False, True):
        assert controls.evaluate_tag_rulesets(
            [committed_ruleset()], verify_bypass_actors=verify
        ) == ([], [])


@pytest.mark.parametrize(
    "changes",
    [
        {"enforcement": "evaluate"},
        {"enforcement": "disabled"},
        {"target": "branch"},
        {"rules": [{"type": "deletion"}]},
        {"rules": [{"type": "update"}]},
        {"conditions": {"ref_name": {"include": ["refs/tags/release-*"], "exclude": []}}},
        {"conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": ["refs/tags/v0*"]}}},
        {"bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole"}]},
        {"bypass_actors": "none"},
        {"current_user_can_bypass": "always"},
        {"current_user_can_bypass": "pull_requests_only"},
    ],
)
def test_a_ruleset_that_lets_release_tags_move_is_rejected(changes):
    errors, notices = controls.evaluate_tag_rulesets([committed_ruleset(**changes)])
    assert errors and not notices
    assert controls.evaluate_tag_rulesets([])[0]


@pytest.mark.parametrize("ruleset", [workflow_view(), committed_ruleset(bypass_actors=None)])
def test_an_unreadable_bypass_list_is_reported_never_taken_as_empty(ruleset):
    errors, notices = controls.evaluate_tag_rulesets([ruleset])
    assert errors == []
    assert len(notices) == 1 and "visible only to administrators" in notices[0]
    errors, notices = controls.evaluate_tag_rulesets([ruleset], verify_bypass_actors=True)
    assert len(errors) == 1 and "administrator's token" in errors[0]
    assert notices == []
    # Seeing that the caller itself may bypass is enough to reject, whoever else may.
    errors, _ = controls.evaluate_tag_rulesets([workflow_view(current_user_can_bypass="always")])
    assert errors and "no active ruleset" in errors[0]


def test_a_known_empty_bypass_list_outweighs_an_unreadable_one():
    rulesets = [workflow_view(), committed_ruleset(id=8)]
    assert controls.evaluate_tag_rulesets(rulesets, verify_bypass_actors=True) == ([], [])


def unreported_caller(view, value):
    ruleset = view()
    if value == "absent":
        del ruleset["current_user_can_bypass"]
    else:
        ruleset["current_user_can_bypass"] = value
    return ruleset


@pytest.mark.parametrize("value", ["absent", None])
@pytest.mark.parametrize("view", [committed_ruleset, workflow_view])
def test_an_unreported_caller_bypass_is_unknown_never_taken_as_never(view, value):
    # Whether the checking token itself may move a v* tag is unknown, not "never".
    ruleset = unreported_caller(view, value)
    errors, notices = controls.evaluate_tag_rulesets([ruleset])
    assert errors == []
    assert any("whether this token may bypass" in notice for notice in notices)
    assert len(notices) == (1 if view is committed_ruleset else 2)
    errors, notices = controls.evaluate_tag_rulesets([ruleset], verify_bypass_actors=True)
    assert any("whether this token may bypass" in error for error in errors)
    assert notices == []
    # A ruleset that reports both fields, in full, still settles it.
    assert controls.evaluate_tag_rulesets(
        [ruleset, committed_ruleset(id=8)], verify_bypass_actors=True
    ) == ([], [])


def test_the_workflow_token_reports_an_unreported_caller_bypass(live, capsys, tmp_path):
    summary = tmp_path / "summary.md"
    live.setenv("GITHUB_STEP_SUMMARY", str(summary))
    ruleset = unreported_caller(workflow_view, "absent")
    live.setattr(controls, "fetch_tag_rulesets", lambda *_: [ruleset])
    live.setattr("sys.argv", [*ARGV, "--publish", "pypi"])
    assert controls.main() == 0
    assert "whether this token may bypass" in capsys.readouterr().out
    assert "whether this token may bypass" in summary.read_text()
    live.setattr("sys.argv", [*ARGV, "--publish", "pypi", "--verify-bypass-actors"])
    assert controls.main() == 1
    assert "whether this token may bypass" in capsys.readouterr().err


def environment(**changes):
    return {
        "name": "pypi",
        "can_admins_bypass": False,
        "protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "User"}]}],
        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
        **changes,
    }


MAIN_ONLY = {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}


def test_a_reviewed_main_only_environment_without_bypass_passes():
    assert controls.evaluate_environment(environment(), MAIN_ONLY, name="pypi", branch="main") == []


def test_an_environment_open_to_every_protected_branch_is_not_limited_to_main():
    # Any branch given a protection rule, such as a release branch, could deploy.
    protected = environment(
        deployment_branch_policy={"protected_branches": True, "custom_branch_policies": False}
    )
    assert controls.evaluate_environment(protected, None, name="pypi", branch="main") == [
        "the pypi environment accepts deployments from refs other than main"
    ]


@pytest.mark.parametrize(
    "changes,policies",
    [
        ({"can_admins_bypass": True}, MAIN_ONLY),
        ({"can_admins_bypass": None}, MAIN_ONLY),
        ({"protection_rules": []}, MAIN_ONLY),
        ({"protection_rules": [{"type": "required_reviewers", "reviewers": []}]}, MAIN_ONLY),
        ({"deployment_branch_policy": None}, None),
        ({}, {"total_count": 1, "branch_policies": [{"name": "*", "type": "branch"}]}),
        ({}, {"total_count": 1, "branch_policies": [{"name": "main", "type": "tag"}]}),
        ({}, {"total_count": 2, "branch_policies": [{"name": "main", "type": "branch"}]}),
        ({"name": "testpypi"}, MAIN_ONLY),
    ],
)
def test_a_bypassable_unreviewed_or_unrestricted_environment_blocks(changes, policies):
    assert controls.evaluate_environment(
        environment(**changes), policies, name="pypi", branch="main"
    )


def tag_ref(kind="tag"):
    return {"ref": "refs/tags/v0.2.0", "object": {"type": kind, "sha": "b" * 40}}


def tag(**changes):
    return {
        "tag": "v0.2.0",
        "object": {"type": "commit", "sha": SHA},
        "verification": {"verified": True, "reason": "valid"},
        **changes,
    }


def test_a_verified_annotated_tag_on_the_commit_passes():
    assert controls.evaluate_release_tag(tag_ref(), tag(), version="0.2.0", sha=SHA) == []


@pytest.mark.parametrize(
    "ref,tag_object",
    [
        (None, None),
        (tag_ref("commit"), None),
        (tag_ref(), tag(object={"type": "commit", "sha": "c" * 40})),
        (tag_ref(), tag(tag="v0.1.0")),
        (tag_ref(), tag(verification={"verified": False, "reason": "unsigned"})),
        (tag_ref(), tag(verification=None)),
    ],
)
def test_a_missing_moved_lightweight_or_unverified_tag_blocks(ref, tag_object):
    assert controls.evaluate_release_tag(ref, tag_object, version="0.2.0", sha=SHA)


def test_a_missing_tag_is_reported_rather_than_an_api_failure(monkeypatch):
    def missing(*_):
        raise HTTPError("https://api.github.com", 404, "Not Found", {}, None)

    monkeypatch.setattr(controls, "_fetch", missing)
    assert controls.fetch_release_tag("owner/repo", "0.2.0", "synthetic") == (None, None)


@pytest.fixture
def live(monkeypatch):
    """A repository that meets every prerequisite, served without network access."""
    monkeypatch.setattr("sys.argv", ARGV)
    monkeypatch.setenv("GH_TOKEN", "synthetic-test-token")
    monkeypatch.setenv("GITHUB_SHA", SHA)
    monkeypatch.setattr(controls, "fetch_branch", lambda *_: branch())
    jobs = {
        "total_count": 3,
        "jobs": [
            {"name": name, "run_id": 123, "run_attempt": 1}
            | {"status": "completed", "conclusion": "success"}
            for name in ["Verified CI", "CodeQL policy", "Dependency advisories"]
        ],
    }
    monkeypatch.setattr(controls, "fetch_verification", lambda *_: (run(), jobs))
    monkeypatch.setattr(controls, "fetch_runs", lambda *_: [run()])
    monkeypatch.setattr(controls, "fetch_tag_rulesets", lambda *_: [committed_ruleset()])
    monkeypatch.setattr(
        controls,
        "fetch_environment",
        lambda _repo, name, _token: (environment(name=name), MAIN_ONLY),
    )
    monkeypatch.setattr(controls, "fetch_release_tag", lambda *_: (tag_ref(), tag()))
    monkeypatch.setattr(controls, "project_version", lambda: "0.2.0")
    return monkeypatch


@pytest.mark.parametrize("index", ["testpypi", "pypi"])
def test_the_preflight_passes_when_every_prerequisite_holds(live, index, capsys):
    live.setattr("sys.argv", [*ARGV, "--publish", index])
    assert controls.main() == 0
    assert "release-tag ruleset" in capsys.readouterr().out


def stamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_a_fresh_commit_blocks_pypi_but_not_the_testpypi_rehearsal(live, capsys):
    now = stamp(datetime.now(UTC))
    live.setattr(controls, "fetch_branch", lambda *_: branch(now))
    live.setattr(controls, "fetch_runs", lambda *_: [run(created_at=now)])
    live.setattr("sys.argv", [*ARGV, "--publish", "pypi"])
    assert controls.main() == 1
    assert "waits 24 hours" in capsys.readouterr().err
    live.setattr("sys.argv", [*ARGV, "--publish", "testpypi"])
    assert controls.main() == 0


def test_a_skip_ci_commit_dispatched_long_ago_still_needs_a_stated_override(live, capsys):
    # Pushed with "[skip ci]", so no push run; a dispatch "on main" two days ago may have
    # run on a tag named main and does not show when the commit reached the branch.
    now = datetime.now(UTC)
    live.setattr(controls, "fetch_branch", lambda *_: branch(stamp(now - timedelta(days=3))))
    dispatch = run(event="workflow_dispatch", created_at=stamp(now - timedelta(days=2)))
    live.setattr(controls, "fetch_runs", lambda *_: [dispatch])
    live.setattr("sys.argv", [*ARGV, "--publish", "pypi"])
    assert controls.main() == 1
    assert "reached the branch is unavailable" in capsys.readouterr().err
    live.setenv("SOAK_OVERRIDE", "Publishes the fix for an actively exploited gate bypass")
    assert controls.main() == 0


def test_without_a_trusted_run_the_soak_needs_a_stated_override(live, capsys):
    # The commit date is past the soak, but no run shows when the commit reached main.
    elsewhere = [run(head_branch="release-prep"), run(id=124, event="pull_request")]
    live.setattr(controls, "fetch_runs", lambda *_: elsewhere)
    live.setattr("sys.argv", [*ARGV, "--publish", "pypi"])
    assert controls.main() == 1
    assert "reached the branch is unavailable" in capsys.readouterr().err
    live.setenv("SOAK_OVERRIDE", "Publishes the fix for an actively exploited gate bypass")
    assert controls.main() == 0
    assert "Soak period waived by the publishing maintainer" in capsys.readouterr().out


@pytest.mark.parametrize(
    "error",
    [http.client.IncompleteRead(b"partial"), http.client.RemoteDisconnected("closed"), TypeError()],
)
def test_a_broken_github_response_blocks_publication_without_a_traceback(live, capsys, error):
    def broken(*_):
        raise error

    live.setattr(controls, "fetch_branch", broken)
    assert controls.main() == 2
    assert "could not be verified from GitHub" in capsys.readouterr().err


def test_a_stated_override_publishes_a_fresh_commit_and_is_logged(live, capsys, tmp_path):
    live.setattr(
        controls,
        "fetch_branch",
        lambda *_: branch(datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")),
    )
    live.setattr(controls, "fetch_runs", lambda *_: [])
    live.setenv("SOAK_OVERRIDE", "Publishes the fix for an actively exploited gate bypass")
    summary = tmp_path / "summary.md"
    live.setenv("GITHUB_STEP_SUMMARY", str(summary))
    live.setattr("sys.argv", [*ARGV, "--publish", "pypi"])
    assert controls.main() == 0
    out = capsys.readouterr().out
    assert "actively exploited gate bypass" in out
    assert "the stated soak waiver and the signed release tag" in out
    assert "the 24-hour soak and" not in out
    assert "the 24-hour soak was waived: Publishes the fix" in summary.read_text()


@pytest.mark.parametrize(
    "fetcher,value",
    [
        ("fetch_tag_rulesets", []),
        ("fetch_environment", (environment(can_admins_bypass=True), MAIN_ONLY)),
        ("fetch_release_tag", (None, None)),
        ("fetch_runs", None),
    ],
)
def test_each_unmet_prerequisite_blocks_pypi_publication(live, fetcher, value):
    live.setattr(controls, fetcher, lambda *_: value)
    live.setattr("sys.argv", [*ARGV, "--publish", "pypi"])
    assert controls.main() == 1


def test_an_unusable_run_listing_leaves_the_soak_unproven(live, capsys):
    # The commit date is well past the soak, but without the push runs it is only the
    # committer's claim.
    live.setattr(controls, "fetch_runs", lambda *_: None)
    live.setattr("sys.argv", [*ARGV, "--publish", "pypi"])
    assert controls.main() == 1
    assert "reached the branch is unavailable" in capsys.readouterr().err


def test_the_workflow_token_reports_what_it_cannot_see(live, capsys, tmp_path):
    summary = tmp_path / "summary.md"
    live.setenv("GITHUB_STEP_SUMMARY", str(summary))
    live.setattr(controls, "fetch_tag_rulesets", lambda *_: [workflow_view()])
    live.setattr("sys.argv", [*ARGV, "--publish", "pypi"])
    assert controls.main() == 0
    out = capsys.readouterr().out
    assert "Repository controls notice:" in out and "--verify-bypass-actors" in out
    # Shown on the run page as well, where the environment approval happens.
    assert "visible only to administrators" in summary.read_text()
    live.setattr("sys.argv", [*ARGV, "--publish", "pypi", "--verify-bypass-actors"])
    assert controls.main() == 1
    assert "administrator's token" in capsys.readouterr().err
    live.setattr(controls, "fetch_tag_rulesets", lambda *_: [committed_ruleset()])
    assert controls.main() == 0
    assert "notice" not in capsys.readouterr().out


def test_the_administrator_check_needs_a_publication_target(live):
    live.setattr("sys.argv", [*ARGV, "--verify-bypass-actors"])
    with pytest.raises(SystemExit) as raised:
        controls.main()
    assert raised.value.code == 2
