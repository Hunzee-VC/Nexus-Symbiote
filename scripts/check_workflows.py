"""Reject mutable Action references and expressions embedded in shell source.

Checks ``action.yml`` (when present) and every workflow under ``.github/workflows``:

* every ``uses:`` outside the repository is pinned to a 40-hex commit (an explicit, reviewed exception list
  covers actions whose commit has not been verified yet; keep it empty when you can);
* no ``${{ }}`` expression appears inside a ``run:`` block (inputs travel through ``env``);
* workflows only use the supported top-level fields, every job defines steps and ``needs`` names real jobs;
* ``ci.yml`` has a ``verified`` job named ``Verified CI`` that always runs and needs every other job, so one
  status-check context can be required on the default branch (``config/github-main-protection.json``).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

#: Floating references that are tolerated until a commit has been verified. Each entry must name the exact
#: ``uses:`` string; anything else that is not a 40-hex pin is rejected.
UNPINNED_ALLOWLIST: frozenset[str] = frozenset({"open-policy-agent/setup-opa@v2"})

AGGREGATE_JOB = "verified"
AGGREGATE_NAME = "Verified CI"


def check(path: Path) -> list[str]:
    errors: list[str] = []
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        return [f"{path}: expected a mapping"]
    if path.name != "action.yml":
        # PyYAML's YAML 1.1 resolver interprets the GitHub key `on` as True.
        allowed = {"name", "run-name", "on", True, "permissions", "concurrency", "env", "defaults", "jobs"}
        if document.keys() - allowed:
            errors.append(f"{path}: unsupported workflow top-level fields")
        jobs = document.get("jobs", {})
        if not isinstance(jobs, dict) or not jobs:
            errors.append(f"{path}: workflow must define jobs")
        else:
            for name, job in jobs.items():
                if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
                    errors.append(f"{path}: {name} must define steps")
                    continue
                needs = job.get("needs", [])
                needs = [needs] if isinstance(needs, str) else needs
                if not isinstance(needs, list) or set(needs) - jobs.keys():
                    errors.append(f"{path}: {name} references unknown prerequisites")
            if path.name == "ci.yml":
                verified = jobs.get(AGGREGATE_JOB, {})
                if (
                    not isinstance(verified, dict)
                    or verified.get("name") != AGGREGATE_NAME
                    or verified.get("if") != "always()"
                    or not isinstance(verified.get("needs"), list)
                    or set(verified.get("needs", [])) != jobs.keys() - {AGGREGATE_JOB}
                ):
                    errors.append(f"{path}: {AGGREGATE_NAME} must always aggregate every verification job")

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if (
                    key == "uses"
                    and isinstance(child, str)
                    and not child.startswith("./")
                    and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", child)
                    and child not in UNPINNED_ALLOWLIST
                ):
                    errors.append(f"{path}: Action must be pinned to a commit: {child}")
                if key == "run" and isinstance(child, str) and "${{" in child:
                    errors.append(f"{path}: pass expressions through env, never shell source")
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(document)
    return errors


def targets(root: Path) -> list[Path]:
    action = root / "action.yml"
    return [*([action] if action.is_file() else []), *sorted((root / ".github" / "workflows").glob("*.yml"))]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = [error for path in targets(root) for error in check(path)]
    for error in errors:
        print(error)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
