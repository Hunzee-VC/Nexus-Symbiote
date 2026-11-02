"""Repository tooling ported from ``main``: the workflow linter and the hygiene gate run clean on this tree."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


check_workflows = _load("check_workflows")
hygiene = _load("check_repository_hygiene")


# --- check_workflows --------------------------------------------------------------------------------------------


def test_repository_workflows_and_action_pass_the_linter() -> None:
    targets = check_workflows.targets(ROOT)
    assert ROOT / "action.yml" in targets and ROOT / ".github" / "workflows" / "ci.yml" in targets
    errors = [error for path in targets for error in check_workflows.check(path)]
    assert errors == []


def test_unpinned_action_is_rejected(tmp_path: Path) -> None:
    wf = tmp_path / "x.yml"
    wf.write_text("on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8")
    assert any("pinned to a commit" in e for e in check_workflows.check(wf))
    wf.write_text(
        "on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n",
        encoding="utf-8",
    )
    assert check_workflows.check(wf) == []


def test_expressions_in_run_blocks_are_rejected(tmp_path: Path) -> None:
    wf = tmp_path / "x.yml"
    wf.write_text("on: push\njobs:\n  a:\n    steps:\n      - run: echo ${{ inputs.x }}\n", encoding="utf-8")
    assert any("never shell source" in e for e in check_workflows.check(wf))


def test_unknown_needs_and_missing_verified_aggregate_are_rejected(tmp_path: Path) -> None:
    ci = tmp_path / "ci.yml"
    ci.write_text(
        "on: push\njobs:\n  test:\n    needs: [ghost]\n    steps: []\n  verified:\n    name: Verified CI\n    if: always()\n    needs: []\n    steps: []\n",
        encoding="utf-8",
    )
    errors = check_workflows.check(ci)
    assert any("unknown prerequisites" in e for e in errors)
    assert any("Verified CI" in e for e in errors)


def test_the_verified_job_covers_every_other_job() -> None:
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    jobs = ci["jobs"]
    assert jobs["verified"]["name"] == "Verified CI" and jobs["verified"]["if"] == "always()"
    assert set(jobs["verified"]["needs"]) == set(jobs) - {"verified"}
    protection = json.loads((ROOT / "config" / "github-main-protection.json").read_text(encoding="utf-8"))
    assert [c["context"] for c in protection["required_status_checks"]["checks"]] == ["Verified CI"]


# --- check_repository_hygiene ------------------------------------------------------------------------------------


def test_tracked_tree_passes_hygiene() -> None:
    files = hygiene.tracked_files(ROOT)
    assert files, "git ls-files returned nothing"
    assert hygiene.source_issues(ROOT, files) == []
    assert hygiene.version_issues(ROOT) == []
    assert hygiene.vendor_issues(ROOT) == []


def test_hygiene_detects_conflict_markers_and_dangling_links(tmp_path: Path) -> None:
    (tmp_path / "a.md").write_text(
        "<<<<<<< HEAD\nx\n=======\ny\n>>>>>>> theirs\n[gone](missing.md)\n", encoding="utf-8"
    )
    (tmp_path / "b.md").write_text(
        "```\n[ignored in fences](nope.md)\n```\n[ok](a.md) [ext](https://example.org/x)\n", encoding="utf-8"
    )
    errors = hygiene.source_issues(tmp_path, [Path("a.md"), Path("b.md")])
    assert any("conflict marker" in e for e in errors)
    assert any("missing.md" in e for e in errors)
    assert not any("b.md" in e for e in errors)


def test_hygiene_rejects_escaping_links(tmp_path: Path) -> None:
    (tmp_path / "a.md").write_text("[up](../outside.md)\n", encoding="utf-8")
    assert any("escaping" in e for e in hygiene.source_issues(tmp_path, [Path("a.md")]))


def test_vendor_provenance_covers_every_vendored_schema() -> None:
    manifest = json.loads((ROOT / hygiene.PROVENANCE).read_text(encoding="utf-8"))
    listed = {record["file"] for record in manifest["files"]}
    actual = {
        p.relative_to(ROOT / hygiene.VENDOR).as_posix() for p in (ROOT / hygiene.VENDOR).rglob("*.json*")
    }
    assert listed == actual


def test_vendor_digest_drift_is_detected(tmp_path: Path) -> None:
    vendor = tmp_path / hygiene.VENDOR
    vendor.mkdir(parents=True)
    (vendor / "x.schema.json").write_text("{}", encoding="utf-8")
    (tmp_path / hygiene.PROVENANCE).parent.mkdir(parents=True)
    (tmp_path / hygiene.PROVENANCE).write_text(
        json.dumps(
            {"directory": hygiene.VENDOR.as_posix(), "files": [{"file": "x.schema.json", "sha256": "0" * 64}]}
        ),
        encoding="utf-8",
    )
    assert any("differs from its reviewed provenance digest" in e for e in hygiene.vendor_issues(tmp_path))


@pytest.mark.parametrize("script", ["check_workflows.py", "check_repository_hygiene.py"])
def test_scripts_run_clean_as_processes(script: str) -> None:
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "scripts" / script)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
