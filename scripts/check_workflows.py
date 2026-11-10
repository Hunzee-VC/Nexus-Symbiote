"""Check workflows and actions for pinning, privilege and gate integrity.

Every remote action is pinned to a commit with a full-version comment that agrees wherever
the same commit is used, and is no older than its recorded floor. Local actions must exist
and are checked like any other. Expressions never reach shell source. Workflows use only
reviewed triggers, read-only top-level permissions, a job time limit and checkouts without
persisted credentials; the gating workflows never continue on error, and each of their
verification jobs still runs the command that makes it a gate.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

WORKFLOWS = Path(".github/workflows")
ALLOWED_TRIGGERS = frozenset(
    {"push", "pull_request", "workflow_dispatch", "schedule", "branch_protection_rule"}
)
READ_ONLY = frozenset({"read", "none"})
GATING = frozenset({"ci.yml", "release.yml"})
PIN = re.compile(r"[^@\s]+@[0-9a-f]{40}")
USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?([^\s'\"#]+)['\"]?(?:\s+#\s*(\S+))?")
VERSION = re.compile(r"v(\d+)\.(\d+)\.(\d+)")
# The oldest acceptable release of each pinned action. A squash merge from a stale
# branch that rewrites a workflow cannot silently move a pin back past these.
ACTION_FLOORS = {
    "actions/checkout": (7, 0, 1),
    "actions/setup-python": (7, 1, 0),
    "actions/upload-artifact": (7, 0, 2),
    "actions/download-artifact": (8, 0, 2),
    "actions/attest-build-provenance": (4, 2, 2),
    "github/codeql-action": (4, 39, 1),
    "ossf/scorecard-action": (2, 5, 0),
    "pypa/gh-action-pypi-publish": (1, 14, 3),
}
CI_JOBS = frozenset(
    {
        "test",
        "floor",
        "coverage",
        "quality",
        "distribution",
        "security-regressions",
        "dependency-audit",
        "codeql",
    }
)
# What makes each verification job a gate. A job that keeps its name but loses its
# command (hollowed out by mistake or by a stale squash merge) fails here.
REQUIRED_COMMANDS: dict[str, dict[str, tuple[str, ...]]] = {
    "ci.yml": {
        "test": ("requirements-ci.lock", "python -m pytest", "--strict-skips"),
        "floor": ("requirements-floor.lock", "python -m pytest", "--strict-skips"),
        "coverage": ("--cov=nexus_symbiote", "--cov-branch", "scripts/check_coverage.py"),
        "quality": (
            "ruff check src tests scripts",
            "ruff format --check src tests scripts",
            "mypy src/nexus_symbiote scripts",
            "scripts/check_workflows.py",
            "scripts/check_repository_hygiene.py",
            "scripts/check_locks.py",
        ),
        "distribution": (
            "python -m build --no-isolation",
            "twine check --strict",
            "scripts/check_wheel_security.py",
            "scripts/check_installed_wheel.py",
        ),
        "security-regressions": (
            "requirements-action.lock",
            "scripts/check_security_regressions.py",
        ),
        "dependency-audit": (
            "scripts/check_dependency_advisories.py",
            "--lock requirements-ci.lock",
            "--lock requirements-action.lock",
        ),
        "codeql": (
            "github/codeql-action/init@",
            "github/codeql-action/analyze@",
            "scripts/check_codeql_sarif.py",
        ),
    },
    "release.yml": {
        "build": (
            "scripts/check_repository_controls.py",
            "--publish",
            "scripts/check_dependency_advisories.py",
            "python -m pytest",
            "scripts/check_security_regressions.py",
            "scripts/check_wheel_security.py",
        ),
        "compatibility": ("scripts/check_installed_wheel.py",),
    },
}


def _triggers(document: dict[Any, Any]) -> set[str]:
    # PyYAML's YAML 1.1 resolver reads the GitHub key `on` as True.
    events = document.get("on", document.get(True))
    if isinstance(events, str):
        return {events}
    if isinstance(events, list):
        return {str(event) for event in events}
    if isinstance(events, dict):
        return {str(event) for event in events}
    return set()


def _read_only(permissions: Any) -> bool:
    if permissions in ("read-all", {}):
        return True
    return isinstance(permissions, dict) and all(
        value in READ_ONLY for value in permissions.values()
    )


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps")
    return [step for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []


def _job_text(job: dict[str, Any]) -> str:
    parts = []
    for step in _steps(job):
        for key in ("run", "uses"):
            if isinstance(step.get(key), str):
                parts.append(step[key])
    return "\n".join(" ".join(part.split()) for part in parts)


def _workflow_issues(path: Path, document: dict[Any, Any]) -> list[str]:
    errors: list[str] = []
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
    triggers = _triggers(document)
    if not triggers or triggers - ALLOWED_TRIGGERS:
        errors.append(f"{path}: triggers must be among {', '.join(sorted(ALLOWED_TRIGGERS))}")
    if "permissions" not in document or not _read_only(document["permissions"]):
        errors.append(f"{path}: top-level permissions must be present and read-only")
    jobs = document.get("jobs", {})
    if not isinstance(jobs, dict) or not jobs:
        return [*errors, f"{path}: workflow must define jobs"]
    for name, job in jobs.items():
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            errors.append(f"{path}: {name} must define steps")
            continue
        needs = job.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        if not isinstance(needs, list) or set(needs) - jobs.keys():
            errors.append(f"{path}: {name} references unknown prerequisites")
        timeout = job.get("timeout-minutes")
        if type(timeout) is not int or timeout <= 0:
            errors.append(f"{path}: {name} must set timeout-minutes")
        if path.name in GATING and (
            "continue-on-error" in job or any("continue-on-error" in s for s in _steps(job))
        ):
            errors.append(f"{path}: {name} must not continue on error in a gating workflow")
        for step in _steps(job):
            uses = step.get("uses")
            if isinstance(uses, str) and uses.startswith("actions/checkout@"):
                options = step.get("with")
                if not isinstance(options, dict) or options.get("persist-credentials") is not False:
                    errors.append(f"{path}: {name} must check out with persist-credentials: false")
        for command in REQUIRED_COMMANDS.get(path.name, {}).get(str(name), ()):
            if command not in _job_text(job):
                errors.append(f"{path}: {name} no longer runs {command}")
    for name in REQUIRED_COMMANDS.get(path.name, {}):
        if name not in jobs:
            errors.append(f"{path}: required job {name} is missing")
    if path.name == "ci.yml":
        verified = jobs.get("verified", {})
        if (
            not isinstance(verified, dict)
            or verified.get("name") != "Verified CI"
            or verified.get("if") != "always()"
            or not isinstance(verified.get("needs"), list)
            or not jobs.keys() >= CI_JOBS
            or set(verified.get("needs", [])) != jobs.keys() - {"verified"}
        ):
            errors.append(f"{path}: Verified CI must always aggregate every verification job")
    return errors


def local_actions(document: Any) -> Iterator[str]:
    """Every `uses: ./path` reference in a workflow or action."""
    if isinstance(document, dict):
        for key, child in document.items():
            if key == "uses" and isinstance(child, str) and child.startswith("./"):
                yield child
            yield from local_actions(child)
    elif isinstance(document, list):
        for child in document:
            yield from local_actions(child)


def check(path: Path) -> list[str]:
    errors: list[str] = []
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        return [f"{path}: expected a mapping"]
    if path.name not in {"action.yml", "action.yaml"}:
        errors.extend(_workflow_issues(path, document))

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "uses" and isinstance(child, str) and not child.startswith("./"):
                    if not PIN.fullmatch(child):
                        errors.append(f"{path}: Action must be pinned to a commit: {child}")
                if key == "run" and isinstance(child, str) and "${{" in child:
                    errors.append(f"{path}: pass expressions through env, never shell source")
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(document)
    return errors


def pin_comments(paths: list[Path]) -> list[str]:
    """Each pin names a full version, the same one wherever it appears, at or above its floor."""
    errors: list[str] = []
    seen: dict[str, tuple[str, Path]] = {}
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = USES_LINE.match(line)
            if match is None or match[1].startswith("./") or not PIN.fullmatch(match[1]):
                continue
            reference, comment = match[1], match[2] or ""
            version = VERSION.fullmatch(comment)
            if version is None:
                errors.append(f"{path}: {reference} needs a full version comment such as # v1.2.3")
                continue
            if reference in seen and seen[reference][0] != comment:
                errors.append(
                    f"{path}: {reference} is labelled {comment} here and"
                    f" {seen[reference][0]} in {seen[reference][1]}"
                )
            seen.setdefault(reference, (comment, path))
            action = "/".join(reference.split("@", 1)[0].split("/")[:2])
            floor = ACTION_FLOORS.get(action)
            if floor is None:
                errors.append(f"{path}: {action} has no recorded version floor")
            elif tuple(int(part) for part in version.groups()) < floor:
                errors.append(f"{path}: {action} {comment} is older than its floor")
    return errors


def targets(root: Path = Path()) -> list[Path]:
    """Workflows, the root action, local actions and every action they reference."""
    paths = [
        *(root / name for name in ("action.yml", "action.yaml") if (root / name).exists()),
        *sorted((root / WORKFLOWS).glob("*.yml")),
        *sorted((root / WORKFLOWS).glob("*.yaml")),
        *sorted((root / ".github/actions").glob("**/action.yml")),
        *sorted((root / ".github/actions").glob("**/action.yaml")),
    ]
    return list(dict.fromkeys(paths))


def main() -> int:
    paths = targets()
    errors: list[str] = []
    pending = list(paths)
    checked: set[Path] = set()
    while pending:
        # GitHub runs workflows with either extension; checking only one would let an
        # unpinned or shell-injecting workflow through under the other.
        path = pending.pop(0)
        if path in checked:
            continue
        checked.add(path)
        errors.extend(check(path))
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for reference in local_actions(document):
            directory = Path(reference[2:].split("@", 1)[0])
            found = [
                directory / n for n in ("action.yml", "action.yaml") if (directory / n).is_file()
            ]
            if not found or ".." in directory.parts or directory.is_absolute():
                errors.append(f"{path}: local action {reference} does not exist in the repository")
                continue
            pending.extend(found)
    errors.extend(pin_comments(sorted(checked)))
    for error in errors:
        print(error)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
