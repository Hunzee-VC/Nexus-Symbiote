"""scripts/check_workflows.py: pins, local actions, privilege and hollowed gates."""

from __future__ import annotations

import re
import shutil

import pytest
import yaml

from tests.support import ROOT, load_script

checker = load_script("check_workflows")
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
SAFE = f"""on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: {CHECKOUT}
        with:
          persist-credentials: false
      - run: echo safe
"""


@pytest.fixture
def repository(tmp_path, monkeypatch):
    (tmp_path / ".github/workflows").mkdir(parents=True)
    shutil.copyfile(ROOT / "action.yml", tmp_path / "action.yml")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run_checker(repository, workflow, capsys):
    (repository / ".github/workflows/untrusted.yml").write_text(workflow)
    status = checker.main()
    return status, capsys.readouterr().out


def test_the_repository_workflows_and_action_pass(monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    assert checker.main() == 0, capsys.readouterr().out


def test_a_reviewed_workflow_passes(repository, capsys):
    assert run_checker(repository, SAFE, capsys) == (0, "")


@pytest.mark.parametrize(
    "change,message",
    [
        (("on: pull_request", "on: pull_request_target"), "triggers must be among"),
        (("on: pull_request", "on: [workflow_run]"), "triggers must be among"),
        (("permissions:\n  contents: read\n", ""), "top-level permissions"),
        (("  contents: read", "  contents: write"), "top-level permissions"),
        (("    timeout-minutes: 5\n", ""), "timeout-minutes"),
        (
            ("          persist-credentials: false\n", "          fetch-depth: 0\n"),
            "persist-credentials",
        ),
        (("# v7.0.1", ""), "full version comment"),
        (("# v7.0.1", "# v6.0.0"), "older than its floor"),
        (("echo safe", "echo ${{ github.head_ref }}"), "never shell source"),
    ],
)
def test_privileged_triggers_write_tokens_and_unbounded_jobs_are_rejected(
    repository, capsys, change, message
):
    old, new = change
    assert old in SAFE
    status, output = run_checker(repository, SAFE.replace(old, new, 1), capsys)
    assert status == 1
    assert message in output


def test_one_commit_cannot_carry_two_version_labels(repository, capsys):
    workflow = SAFE + f"      - uses: {CHECKOUT.replace('v7.0.1', 'v7.0.9')}\n"
    status, output = run_checker(repository, workflow, capsys)
    assert status == 1 and "is labelled" in output


def test_a_local_action_is_checked_like_any_other(repository, capsys):
    action = repository / ".github/actions/setup"
    action.mkdir(parents=True)
    (action / "action.yml").write_text(
        "name: setup\nruns:\n  using: composite\n  steps:\n"
        "    - uses: some-org/some-action@main\n"
        "    - run: echo ${{ github.event.pull_request.title }}\n      shell: bash\n"
    )
    workflow = SAFE + "      - uses: ./.github/actions/setup\n"
    status, output = run_checker(repository, workflow, capsys)
    assert status == 1
    assert "pinned to a commit: some-org/some-action@main" in output
    assert "never shell source" in output


def test_a_missing_local_action_is_rejected(repository, capsys):
    status, output = run_checker(repository, SAFE + "      - uses: ./tools/absent\n", capsys)
    assert status == 1 and "does not exist" in output


def ci_workflow():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())


@pytest.mark.parametrize(
    "job,command",
    [
        ("dependency-audit", "scripts/check_dependency_advisories.py"),
        ("codeql", "scripts/check_codeql_sarif.py"),
        ("floor", "requirements-floor.lock"),
        ("test", "--strict-skips"),
        ("quality", "scripts/check_locks.py"),
        ("action", "sys.exit(bool(failures))"),
        ("action-annotations", "symbiote-injected-annotation"),
        ("action-annotations", "set-output"),
    ],
)
def test_a_gate_job_hollowed_out_under_its_name_is_rejected(tmp_path, job, command):
    workflow = ci_workflow()
    for step in workflow["jobs"][job]["steps"]:
        if command in step.get("run", ""):
            step["run"] = "true"
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any(f"{job} no longer runs {command}" in error for error in checker.check(path))


def workflow_errors(tmp_path, name, change):
    """The checker's errors for the repository's workflow `name` after `change` edits it."""
    workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
    change(workflow["jobs"])
    path = tmp_path / name
    path.write_text(yaml.safe_dump(workflow))
    return checker.check(path)


def step_running(job, command):
    return next(step for step in job["steps"] if command in step.get("run", step.get("uses", "")))


def condition(job, command, value):
    def change(jobs):
        step_running(jobs[job], command)["if"] = value

    return change


@pytest.mark.parametrize(
    "name,job,command,value",
    [
        ("ci.yml", "test", "python -m pytest", False),
        ("ci.yml", "quality", "mypy src/nexus_symbiote scripts", "false"),
        ("ci.yml", "quality", "scripts/check_workflows.py", "${{ false }}"),
        ("ci.yml", "coverage", "scripts/check_coverage.py", "github.event_name == 'never'"),
        ("ci.yml", "codeql", "github/codeql-action/init@", False),
        ("ci.yml", "action", "sys.exit(bool(failures))", False),
        ("ci.yml", "action-annotations", "symbiote-injected-annotation", "failure()"),
        (
            "release.yml",
            "build",
            "scripts/check_repository_controls.py",
            "inputs.publish == 'never'",
        ),
        # The preflight's reviewed condition does not carry over to another gate.
        ("release.yml", "build", "python -m pytest", "inputs.publish != 'none'"),
        ("release.yml", "compatibility", "scripts/check_installed_wheel.py", False),
    ],
)
def test_a_gate_step_that_a_condition_can_skip_is_rejected(tmp_path, name, job, command, value):
    errors = workflow_errors(tmp_path, name, condition(job, command, value))
    assert any(f"{job} may skip {command}" in error for error in errors), errors


@pytest.mark.parametrize(
    "name,job,value",
    [
        ("ci.yml", "quality", False),
        ("ci.yml", "test", "github.event_name == 'push'"),
        ("ci.yml", "action-annotations", "success() && false"),
        ("release.yml", "build", "github.ref == 'refs/heads/release'"),
        ("release.yml", "compatibility", "${{ false }}"),
    ],
)
def test_a_required_job_that_a_condition_can_skip_is_rejected(tmp_path, name, job, value):
    def change(jobs):
        jobs[job]["if"] = value

    errors = workflow_errors(tmp_path, name, change)
    assert any(f"required job {job} may be skipped" in error for error in errors), errors


@pytest.mark.parametrize("value", ["success()", "always()", "${{ always() }}", " ${{success()}} "])
def test_a_gate_may_run_on_success_or_always(tmp_path, value):
    def change(jobs):
        for job, command in (("test", "python -m pytest"), ("codeql", "init@")):
            step_running(jobs[job], command)["if"] = value
        jobs["quality"]["if"] = value

    assert workflow_errors(tmp_path, "ci.yml", change) == []


def edit_run(job, command, old, new):
    def change(jobs):
        step = step_running(jobs[job], command)
        assert old in step["run"]
        step["run"] = step["run"].replace(old, new, 1)

    return change


TEST_STEP = 'tee "$PYTEST_LOG"\n'
# A here-string is not a here-document: the next line still runs as a command.
HERE_STRING = "cat <<<EOF\nmypy src/nexus_symbiote scripts || true\nEOF"


@pytest.mark.parametrize(
    "name,job,command,old,new",
    [
        ("release.yml", "build", "python -m pytest", "--strict-skips", "--strict-skips || true"),
        ("release.yml", "build", "python -m pytest", "--strict-skips", "--strict-skips ||true"),
        ("release.yml", "build", "python -m pytest", "--strict-skips", "--strict-skips \\\n|| :"),
        ("release.yml", "build", "python -m pytest", "--strict-skips", "--strict-skips ||\n true"),
        ("ci.yml", "test", "python -m pytest", TEST_STEP, 'tee "$PYTEST_LOG" || true\n'),
        ("ci.yml", "test", "python -m pytest", TEST_STEP, 'tee "$PYTEST_LOG" &\n'),
        ("ci.yml", "quality", "mypy src", "mypy src/nexus_symbiote scripts", HERE_STRING),
        ("ci.yml", "test", "python -m pytest", "\n  '\n", "\n  ' || exit 0\n"),
        ("ci.yml", "quality", "mypy src/nexus_symbiote scripts", "scripts", "scripts || :"),
        ("ci.yml", "quality", "scripts/check_locks.py", ".py", ".py; true"),
        ("ci.yml", "quality", "scripts/check_workflows.py", ".py", ".py || /usr/bin/true"),
        ("ci.yml", "distribution", "python -m build --no-isolation", "isolation", "isolation &"),
        ("ci.yml", "action-annotations", "gh api --paginate", '/check-runs"\n', '/check-runs" &\n'),
        ("ci.yml", "action", "sys.exit(bool(failures))", "<<'PY'", "<<'PY' || true"),
        ("release.yml", "build", "check_repository_controls", '"$PUBLISH"', '"$PUBLISH" || echo'),
    ],
)
def test_a_gate_command_whose_status_is_discarded_is_rejected(
    tmp_path, name, job, command, old, new
):
    errors = workflow_errors(tmp_path, name, edit_run(job, command, old, new))
    assert any(f"{job} discards the exit status of" in error for error in errors), errors


@pytest.mark.parametrize(
    "job,command,old,new",
    [
        ("quality", "mypy src", "mypy", "pip cache purge || true\nmypy"),
        ("quality", "mypy src", "scripts", "scripts || exit 1"),
        ("quality", "mypy src", "scripts", "scripts || { echo 'mypy failed'; exit 1; }"),
        ("action", "$EVIDENCE/hostile.json", "set -euo", "echo 'a & b || true' >&2\nset -euo"),
        ("action-annotations", "gh api", '/jobs"', '/jobs?per_page=100&filter=latest"'),
        ("quality", "check_locks", ".py", '.py --title "Locks & pins"'),
    ],
)
def test_status_handling_that_keeps_the_gate_is_accepted(tmp_path, job, command, old, new):
    assert workflow_errors(tmp_path, "ci.yml", edit_run(job, command, old, new)) == []


@pytest.mark.parametrize(
    "old,new",
    [
        ("mypy src/nexus_symbiote scripts", "true # mypy src/nexus_symbiote scripts"),
        ("mypy src/nexus_symbiote scripts", "# mypy src/nexus_symbiote scripts\ntrue"),
        ("mypy src/nexus_symbiote scripts", "true;# mypy src/nexus_symbiote scripts"),
    ],
)
def test_a_gate_command_left_only_in_a_comment_is_rejected(tmp_path, old, new):
    errors = workflow_errors(tmp_path, "ci.yml", edit_run("quality", "mypy", old, new))
    assert any("quality no longer runs mypy src/nexus_symbiote scripts" in e for e in errors)


def test_the_annotation_check_fails_on_the_runners_legacy_command_warning(tmp_path):
    # The Action pre-seeds its outputs in GITHUB_OUTPUT, so a set-output that the runner
    # executed changes nothing; the deprecation warning it annotates is the only trace.
    step = step_running(ci_workflow()["jobs"]["action-annotations"], "gh api --paginate")
    pattern = re.compile(re.search(r"grep -Ei '([^']+)'", step["run"])[1], re.IGNORECASE)
    deprecated = (
        "The `{}` command is deprecated and will be disabled soon. Please upgrade to using"
        " Environment Files."
    )
    assert pattern.search(deprecated.format("set-output"))
    assert pattern.search(deprecated.format("save-state"))
    assert pattern.search("Warning ##[warning]symbiote-injected-annotation.pkl")
    assert not pattern.search(" Process completed with exit code 1.")
    reverted = edit_run(
        "action-annotations",
        "gh api --paginate",
        "grep -Ei 'symbiote-injected-annotation|set-output|save-state'",
        "grep -F 'symbiote-injected-annotation'",
    )
    errors = workflow_errors(tmp_path, "ci.yml", reverted)
    assert any("action-annotations no longer runs set-output" in error for error in errors)


def test_a_gating_job_cannot_continue_on_error(tmp_path):
    workflow = ci_workflow()
    workflow["jobs"]["codeql"]["steps"][-2]["continue-on-error"] = True
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any("continue on error" in error for error in checker.check(path))


def test_dropping_a_verification_job_from_verified_ci_is_rejected(tmp_path):
    workflow = ci_workflow()
    workflow["jobs"]["verified"]["needs"].remove("floor")
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any("Verified CI" in error for error in checker.check(path))


def test_removing_the_action_jobs_with_their_verified_ci_entries_is_rejected(tmp_path):
    workflow = ci_workflow()
    for job in ("action", "action-annotations"):
        del workflow["jobs"][job]
        workflow["jobs"]["verified"]["needs"].remove(job)
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    errors = checker.check(path)
    assert any("Verified CI must always aggregate" in error for error in errors)
    assert any("required job action is missing" in error for error in errors)


@pytest.mark.parametrize(
    "permissions",
    [
        "    permissions:\n      contents: write\n",
        "    permissions:\n      contents: read\n      pull-requests: write\n",
        "    permissions:\n      id-token: write\n",
        "    permissions: write-all\n",
        "    permissions:\n      contents: admin\n",
    ],
)
def test_a_job_cannot_grant_itself_a_write_token(repository, capsys, permissions):
    workflow = SAFE.replace("    timeout-minutes: 5\n", "    timeout-minutes: 5\n" + permissions)
    status, output = run_checker(repository, workflow, capsys)
    assert status == 1
    assert "test may hold write permissions only for nothing" in output


def test_a_write_scope_stays_with_the_job_reviewed_for_it(tmp_path):
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    path = tmp_path / "release.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert not any("write permissions" in error for error in checker.check(path))
    # The build job runs the test suite; it must never hold the publishing token.
    workflow["jobs"]["build"]["permissions"]["id-token"] = "write"
    path.write_text(yaml.safe_dump(workflow))
    assert any(
        "build may hold write permissions only for nothing" in error
        for error in checker.check(path)
    )


SCHEDULED = """on:
  schedule:
    - cron: "17 5 * * *"
    - cron: "43 4 * * 2"
permissions:
  contents: read
concurrency:
  group: {group}
  cancel-in-progress: {cancel}
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - run: echo safe
"""


@pytest.mark.parametrize(
    "group,cancel,rejected",
    [
        ("scheduled-${{ github.ref }}", "true", True),
        (
            "scheduled-${{ github.ref }}-${{ github.event.schedule || github.event_name }}",
            "true",
            False,
        ),
        ("scheduled-${{ github.ref }}", "false", False),
    ],
)
def test_one_schedule_cannot_cancel_another(repository, capsys, group, cancel, rejected):
    status, output = run_checker(repository, SCHEDULED.format(group=group, cancel=cancel), capsys)
    assert (status, "github.event.schedule" in output) == (int(rejected), rejected)
    single = SCHEDULED.replace('    - cron: "43 4 * * 2"\n', "")
    assert run_checker(repository, single.format(group=group, cancel=cancel), capsys)[0] == 0


def test_a_step_may_continue_on_error_only_when_its_outcome_is_checked(tmp_path):
    workflow = ci_workflow()
    steps = workflow["jobs"]["codeql"]["steps"]
    steps[-2].update({"id": "probe", "continue-on-error": True})
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any("continue on error" in error for error in checker.check(path))
    steps.append(
        {
            "name": "The probe must have failed",
            "env": {"OUTCOME": "${{ steps.probe.outcome }}"},
            "run": 'test "$OUTCOME" = failure',
        }
    )
    path.write_text(yaml.safe_dump(workflow))
    assert not any("continue on error" in error for error in checker.check(path))
    workflow["jobs"]["codeql"]["continue-on-error"] = True
    path.write_text(yaml.safe_dump(workflow))
    assert any("continue on error" in error for error in checker.check(path))


@pytest.mark.parametrize(
    "value,swallowed",
    [
        (False, True),
        ("failure()", True),
        ("always()", False),
        ("steps.probe.outcome != 'failure'", False),
    ],
)
def test_the_step_that_checks_an_outcome_must_run(tmp_path, value, swallowed):
    workflow = ci_workflow()
    steps = workflow["jobs"]["codeql"]["steps"]
    steps[-2].update({"id": "probe", "continue-on-error": True})
    steps.append(
        {
            "name": "The probe must have failed",
            "if": value,
            "env": {"OUTCOME": "${{ steps.probe.outcome }}"},
            "run": 'test "$OUTCOME" = failure',
        }
    )
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any("continue on error" in error for error in checker.check(path)) is swallowed


def test_the_action_jobs_outcome_assertions_must_run(tmp_path):
    errors = workflow_errors(
        tmp_path, "ci.yml", condition("action", "sys.exit(bool(failures))", False)
    )
    assert any("action must not continue on error" in error for error in errors), errors
