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


@pytest.mark.locked_only
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
    assert 'python -I -m venv "$action_venv"' in source
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
        timeout=60,
    )
    assert (process.returncode == 0) == (change == "none"), process.stdout + process.stderr


def coverage_report(coverage):
    """A report exactly at every floor of scripts/check_coverage.py."""

    def summary(statements, branches):
        branches = 100 if branches is None else branches
        return {
            "covered_lines": statements * 10,
            "num_statements": 1000,
            "covered_branches": branches * 10,
            "num_branches": 1000,
        }

    files = {
        (f"src/{module}" if module.startswith("nexus_symbiote/") else module): {
            "summary": summary(*floors)
        }
        for module, floors in coverage["MODULE_FLOORS"].items()
    }
    # The rest of the package, sized so that the package total sits exactly at its floors.
    listed = [entry["summary"] for path, entry in files.items() if "nexus_symbiote" in path]
    rest = 100_000

    def filler(floor, covered_key, total_key):
        total = sum(s[total_key] for s in listed) + rest
        assert floor * total % 100 == 0
        return floor * total // 100 - sum(s[covered_key] for s in listed)

    files["src/nexus_symbiote/cli.py"] = {
        "summary": {
            "covered_lines": filler(
                coverage["MIN_STATEMENT_PERCENT"], "covered_lines", "num_statements"
            ),
            "num_statements": rest,
            "covered_branches": filler(
                coverage["MIN_BRANCH_PERCENT"], "covered_branches", "num_branches"
            ),
            "num_branches": rest,
        }
    }
    return {"meta": {"branch_coverage": True}, "files": files}


@pytest.mark.parametrize(
    "change",
    [
        "statement",
        "branch",
        "unmeasured",
        "missing",
        "boolean",
        "module-statement",
        "module-branch",
        "module-missing",
        "module-duplicated",
        "script-statement",
        "scripts-unmeasured",
    ],
)
def test_coverage_gate_rejects_regressions_and_invalid_measurements(change):
    coverage = runpy.run_path(str(ROOT / "scripts/check_coverage.py"))
    check = coverage["coverage_failures"]
    report = coverage_report(coverage)
    assert check(report) == []
    package = report["files"]["src/nexus_symbiote/cli.py"]["summary"]
    confined = report["files"]["src/nexus_symbiote/utils/confined.py"]["summary"]
    if change == "statement":
        package["covered_lines"] -= 1
    elif change == "branch":
        package["covered_branches"] -= 1
    elif change == "unmeasured":
        report["meta"]["branch_coverage"] = False
    elif change == "missing":
        del package["covered_branches"]
    elif change == "boolean":
        package["covered_lines"] = True
    elif change == "module-statement":
        # One untested security module fails even though the package total still passes.
        package["covered_lines"] += 100
        confined["covered_lines"] -= 1
    elif change == "module-branch":
        confined["covered_branches"] -= 1
    elif change == "module-missing":
        del report["files"]["src/nexus_symbiote/utils/confined.py"]
    elif change == "module-duplicated":
        report["files"]["build/lib/nexus_symbiote/utils/confined.py"] = {"summary": confined}
    elif change == "script-statement":
        report["files"]["scripts/run_action.py"]["summary"]["covered_lines"] -= 1
    else:
        report["files"] = {
            path: entry for path, entry in report["files"].items() if "nexus_symbiote" in path
        }
    assert check(report)


def test_measured_scripts_neither_dilute_nor_inflate_the_package_floor():
    coverage = runpy.run_path(str(ROOT / "scripts/check_coverage.py"))
    check = coverage["coverage_failures"]
    report = coverage_report(coverage)
    untested = {"covered_lines": 0, "num_statements": 10_000}
    untested |= {"covered_branches": 0, "num_branches": 10_000}
    report["files"]["scripts/check_wheel_security.py"] = {"summary": untested}
    assert check(report) == []
    report["files"]["src/nexus_symbiote/cli.py"]["summary"]["covered_lines"] -= 1
    untested["covered_lines"] = untested["num_statements"]
    failures = check(report)
    assert len(failures) == 1 and failures[0].startswith("package statement: ")
    rows = coverage["measured"](report)
    assert rows[2].startswith("| package |") and rows[3].startswith("| scripts |")


def test_coverage_floors_cover_the_security_critical_modules_and_exist():
    floors = runpy.run_path(str(ROOT / "scripts/check_coverage.py"))["MODULE_FLOORS"]
    for module in (
        "nexus_symbiote/utils/confined.py",
        "nexus_symbiote/core/hashing.py",
        "nexus_symbiote/utils/crypto.py",
        "nexus_symbiote/signature_policy.py",
        "nexus_symbiote/validators/completeness.py",
        "nexus_symbiote/validators/integrity.py",
        "nexus_symbiote/validators/risk.py",
        "nexus_symbiote/diff/differ.py",
        "nexus_symbiote/modes.py",
        "nexus_symbiote/runtime.py",
    ):
        assert module in floors
    assert "scripts/run_action.py" in floors
    assert all(
        (ROOT / ("src" if module.startswith("nexus_symbiote/") else "") / module).is_file()
        for module in floors
    )
