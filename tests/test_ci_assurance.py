"""Exercise regression gates and the Action's reviewed dependency boundary."""

from __future__ import annotations

import copy
import importlib.metadata
import json
import os
import re
import runpy
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def gate(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return runpy.run_path(str(ROOT / "scripts/check_security_regressions.py"))[
        "regression_failures"
    ]


def regression_inputs():
    cases = [
        {"id": "positive", "truth": True, "task": "detection"},
        {"id": "negative", "truth": False, "task": "detection"},
        {"id": "coverage", "truth": None, "task": "control"},
    ]
    rows = [{**case, "prediction": case["truth"], "passed": True, "error": None} for case in cases]
    rows[-1]["control_passed"] = True
    return {"cases": cases}, {"results": rows}


def test_unknown_prediction_for_passing_coverage_control_is_accepted(gate):
    manifest, report = regression_inputs()
    assert gate(report, manifest) == []


@pytest.mark.parametrize(
    "change", ["false-negative", "unknown", "control", "missing", "duplicate", "error", "label"]
)
def test_per_case_regressions_fail_even_without_aggregate_metrics(gate, change):
    manifest, report = regression_inputs()
    report = copy.deepcopy(report)
    if change == "false-negative":
        report["results"][0]["prediction"] = False
    elif change == "unknown":
        report["results"][0]["prediction"] = None
    elif change == "control":
        report["results"][-1]["control_passed"] = False
    elif change == "missing":
        report["results"].pop()
    elif change == "duplicate":
        report["results"].append(report["results"][0])
    elif change == "error":
        report["results"][0]["error"] = "ValueError"
    else:
        report["results"][0]["truth"] = False
    assert gate(report, manifest)


def lock_entries(path):
    entries = {}
    for match in re.finditer(r"^([a-zA-Z0-9][^\n]*)(?:\n(?:[ \t].*|$))*", path.read_text(), re.M):
        lines = [line for line in match.group().splitlines() if not line.lstrip().startswith("#")]
        requirement = Requirement(lines[0].removesuffix(" \\"))
        entries[canonicalize_name(requirement.name)] = (requirement, "\n".join(lines).rstrip())
    return entries


def test_action_lock_reuses_reviewed_hashes_and_closes_runtime_dependencies():
    action = lock_entries(ROOT / "requirements-action.lock")
    ci = lock_entries(ROOT / "requirements-ci.lock")
    assert not {"pytest", "ruff", "mypy"} & action.keys()
    for name, (_, block) in action.items():
        assert block == ci[name][1]
        assert "--hash=sha256:" in block
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    # The signature-policy input verifies Sigstore bundles inside the Action's
    # own venv, so its lock must close the signing extra as well as the core.
    roots = [*project["dependencies"], *project["optional-dependencies"]["sigstore"], "hatchling"]
    assert {"sigstore", "tuf"} <= action.keys()
    for python in ("3.11", "3.12", "3.13", "3.14"):
        env = default_environment()
        env.update(python_version=python, python_full_version=python + ".0", extra="")
        pending = [(root, "") for root in roots]
        seen = set()
        while pending:
            text, extra = pending.pop()
            requirement = Requirement(text)
            if requirement.marker and not requirement.marker.evaluate({**env, "extra": extra}):
                continue
            name = canonicalize_name(requirement.name)
            locked, _ = action[name]
            version = next(iter(locked.specifier)).version
            assert requirement.specifier.contains(version)
            assert not locked.marker or locked.marker.evaluate(env)
            for wanted in ("", *sorted(requirement.extras)):
                if (name, wanted) not in seen:
                    seen.add((name, wanted))
                    requires = importlib.metadata.distribution(name).requires or []
                    pending.extend((dependency, wanted) for dependency in requires)


def test_consumer_action_installs_only_locked_dependencies_before_source():
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    install = next(
        step for step in action["runs"]["steps"] if step["name"] == "Install reviewed Action source"
    )
    source = install["run"]
    assert '"$SYMBIOTE_BASE_PYTHON" -I -m venv "$action_venv"' in source
    assert (
        '--require-hashes --only-binary=:all: -r "$SYMBIOTE_ACTION_PATH/requirements-action.lock"'
        in source
    )
    assert '--no-deps --no-build-isolation -- "$SYMBIOTE_ACTION_PATH"' in source
    assert source.index("--require-hashes") < source.index("--no-deps")


def test_verified_ci_aggregates_all_verification_jobs_and_rejects_skips():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    jobs = workflow["jobs"]
    verified = jobs["verified"]
    assert verified["name"] == "Verified CI"
    assert verified["if"] == "always()"
    assert {
        "test",
        "coverage",
        "quality",
        "distribution",
        "security-regressions",
        "dependency-audit",
        "codeql",
    } <= jobs.keys()
    assert set(verified["needs"]) == jobs.keys() - {"verified"}


@pytest.mark.parametrize("change", ["none", "empty", "missing", "extra", "skipped", "malformed"])
def test_verified_ci_executes_fail_closed_on_incomplete_or_unsuccessful_metadata(change):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    verified = workflow["jobs"]["verified"]
    shell = verified["steps"][0]["run"]
    script = shell.split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    results = {name: {"result": "success"} for name in verified["needs"]}
    if change == "empty":
        results = {}
    elif change == "missing":
        results.pop("test")
    elif change == "extra":
        results["unexpected"] = {"result": "success"}
    elif change == "skipped":
        results["test"]["result"] = "skipped"
    elif change == "malformed":
        results["test"] = None
    process = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", script],
        env={**os.environ, "CI_RESULTS": json.dumps(results)},
        check=False,
        capture_output=True,
        text=True,
    )
    assert (process.returncode == 0) == (change == "none"), process.stdout + process.stderr


@pytest.mark.parametrize("change", ["statement", "branch", "unmeasured", "missing", "boolean"])
def test_coverage_gate_rejects_regressions_and_invalid_measurements(change):
    check = runpy.run_path(str(ROOT / "scripts/check_coverage.py"))["coverage_failures"]
    report = {
        "meta": {"branch_coverage": True},
        "totals": {
            "covered_lines": 900,
            "num_statements": 1000,
            "covered_branches": 750,
            "num_branches": 1000,
        },
    }
    assert check(report) == []
    if change == "statement":
        report["totals"]["covered_lines"] -= 1
    elif change == "branch":
        report["totals"]["covered_branches"] -= 1
    elif change == "unmeasured":
        report["meta"]["branch_coverage"] = False
    elif change == "missing":
        del report["totals"]["covered_branches"]
    else:
        report["totals"]["covered_lines"] = True
    assert check(report)
