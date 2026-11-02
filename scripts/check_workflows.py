"""Reject mutable Action references and expressions embedded in shell source."""

from __future__ import annotations

import re
from pathlib import Path

import yaml


def check(path: Path) -> list[str]:
    errors: list[str] = []
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        return [f"{path}: expected a mapping"]
    if path.name != "action.yml":
        # PyYAML's YAML 1.1 resolver interprets the GitHub key `on` as True.
        allowed = {
            "name",
            "run-name",
            "on",
            True,
            "permissions",
            "concurrency",
            "env",
            "defaults",
            "jobs",
        }
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
                verified = jobs.get("verified", {})
                required = {"test", "coverage", "quality", "distribution", "security-regressions"}
                if (
                    not isinstance(verified, dict)
                    or verified.get("name") != "Verified CI"
                    or verified.get("if") != "always()"
                    or not isinstance(verified.get("needs"), list)
                    or not required <= jobs.keys()
                    or set(verified.get("needs", [])) != jobs.keys() - {"verified"}
                ):
                    errors.append(
                        f"{path}: Verified CI must always aggregate every verification job"
                    )

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "uses" and isinstance(child, str) and not child.startswith("./"):
                    if not re.fullmatch(r"[^@]+@[0-9a-f]{40}", child):
                        errors.append(f"{path}: Action must be pinned to a commit: {child}")
                if key == "run" and isinstance(child, str) and "${{" in child:
                    errors.append(f"{path}: pass expressions through env, never shell source")
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(document)
    return errors


def main() -> int:
    errors = [
        error
        for path in [Path("action.yml"), *Path(".github/workflows").glob("*.yml")]
        for error in check(path)
    ]
    for error in errors:
        print(error)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
