"""Check workflows and actions for pinning, privilege and gate integrity.

Every remote action is pinned to a commit with a full-version comment that agrees wherever
the same commit is used, and is no older than its recorded floor. Local actions must exist
and are checked like any other. Expressions never reach shell source. Workflows use only
reviewed triggers, read-only top-level permissions, write scopes only in the reviewed jobs
that need them, a job time limit and checkouts without persisted credentials; scheduled runs
cannot cancel each other. In the gating workflows no job continues on error, a step may only
when a later step that runs reads its outcome, and each verification job still runs the
command that makes it a gate: outside a shell comment, in a job and a step that only a
reviewed condition can skip, and without discarding the command's exit status.
"""

from __future__ import annotations

import json
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
# The only jobs that may hold a write scope, and which: uploading code-scanning results,
# signing attestations and trusted publishing. A token that could push, comment, approve or
# publish anywhere else fails the check.
JOB_WRITE_SCOPES: dict[str, dict[str, frozenset[str]]] = {
    "ci.yml": {"codeql": frozenset({"security-events"})},
    "codeql.yml": {"analyze": frozenset({"security-events"})},
    "release.yml": {
        "attest": frozenset({"id-token", "attestations"}),
        "publish": frozenset({"id-token"}),
    },
    "scorecard.yml": {"analysis": frozenset({"security-events", "id-token"})},
}
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
    "github/codeql-action": (4, 39, 3),
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
        "action",
        "action-annotations",
    }
)
# What makes each verification job a gate. A job that keeps its name but loses its
# command (hollowed out by mistake or by a stale squash merge) fails here.
REQUIRED_COMMANDS: dict[str, dict[str, tuple[str, ...]]] = {
    "ci.yml": {
        "test": ("requirements-ci.lock", "python -m pytest", "--strict-skips"),
        "floor": ("requirements-floor.lock", "python -m pytest", "--strict-skips"),
        "coverage": (
            "--cov=nexus_symbiote",
            "--cov=scripts",
            "--cov-branch",
            "scripts/check_coverage.py",
        ),
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
        # The composite Action from this checkout on passing, failing and hostile fixtures,
        # with each leg's outcome, outputs and evidence checked; then no annotation the
        # hostile fixture planted may exist on the run, nor the runner's warning that it
        # executed a set-output command, the only trace one leaves.
        "action": (
            "./",
            "symbiote-injected-annotation",
            "sys.exit(bool(failures))",
            "$EVIDENCE/hostile.json",
        ),
        "action-annotations": ("gh api --paginate", "symbiote-injected-annotation", "set-output"),
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
# A gate job or step runs by default, with success() or with always(). Besides those, the
# release build runs only from main, and its repository-controls preflight only for a run
# that publishes, as the publish job does; neither condition may skip any other gate.
ALWAYS_RUNS = frozenset({"success()", "always()"})
REVIEWED_JOB_CONDITIONS: dict[str, dict[str, str]] = {
    "release.yml": {"build": "github.ref == 'refs/heads/main'"},
}
REVIEWED_STEP_CONDITIONS: dict[str, dict[str, frozenset[str]]] = {
    "release.yml": {
        "inputs.publish != 'none'": frozenset({"scripts/check_repository_controls.py", "--publish"})
    },
}
# After a gate command on its line: "|| true", "|| :", "|| exit 0" or "|| echo" turn its
# failure into success, "; true" ends the line in success whatever it returned, and a
# trailing "&" runs it in the background.
DISCARDED = re.compile(
    r"\|\|\s*(?:true|:|exit\s+0|(?:/usr)?/bin/true|echo|printf)(?![\w./-])"
    r"|;\s*(?:true|:|exit\s+0|(?:/usr)?/bin/true)(?![\w./-])"
    r"|(?<![&|<>])&[\s'\")}]*$"
)
HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][\w.-]*)\2")


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


def _write_scopes(permissions: Any) -> set[str] | None:
    """The scopes a job's permissions grant write access to; None when unreadable."""
    if permissions is None or permissions in ("read-all", {}):
        return set()
    if not isinstance(permissions, dict) or any(
        value not in {"read", "write", "none"} for value in permissions.values()
    ):
        return None
    return {str(scope) for scope, value in permissions.items() if value == "write"}


def _schedules_cancel_each_other(document: dict[Any, Any]) -> bool:
    """Two schedules in one cancelling concurrency group: the later run cancels the earlier."""
    events = document.get("on", document.get(True))
    schedule = events.get("schedule") if isinstance(events, dict) else None
    concurrency = document.get("concurrency")
    if not isinstance(schedule, list) or len(schedule) < 2 or concurrency is None:
        return False
    cancels: Any = False
    if isinstance(concurrency, str):
        group = concurrency
    elif isinstance(concurrency, dict):
        group, cancels = str(concurrency.get("group", "")), concurrency.get("cancel-in-progress")
    else:
        return True
    return cancels not in (None, False) and "github.event.schedule" not in group


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps")
    return [step for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []


def _condition(entry: dict[str, Any]) -> str | None:
    """A job's or step's `if:` without the optional ${{ }} around it; None when it has none."""
    if "if" not in entry:
        return None
    value = entry["if"]
    text = value.strip() if isinstance(value, str) else json.dumps(value, default=str)
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    return text


def _continues_unchecked(job: dict[str, Any]) -> bool:
    """A job that continues on error, or a step that does with no step reading its outcome.

    Only a later step sure to run counts: one with no condition beyond success() or
    always(), or one whose condition reads that outcome.
    """
    if job.get("continue-on-error", False) is not False:
        return True
    steps = _steps(job)
    for index, step in enumerate(steps):
        if step.get("continue-on-error", False) is False:
            continue
        outcome = f"steps.{step.get('id')}.outcome"
        if not isinstance(step.get("id"), str) or not any(
            outcome in json.dumps(later, default=str)
            and (_condition(later) in (None, *ALWAYS_RUNS) or outcome in str(later["if"]))
            for later in steps[index + 1 :]
        ):
            return True
    return False


def _here_document(script: str, start: int, delimiter: str, tabs: bool) -> tuple[str, int]:
    """The here-document starting at ``start`` and the index after its delimiter line."""
    lines = []
    index = start
    while index < len(script):
        end = script.find("\n", index)
        end = len(script) if end < 0 else end
        line = script[index:end]
        index = end + 1
        if (line.lstrip("\t") if tabs else line) == delimiter:
            break
        lines.append(line)
    return " ".join(" ".join(lines).split()), index


def _logical_lines(script: str) -> list[tuple[str, str]]:
    """Each logical line of a shell script, with the here-documents it reads, without comments.

    A line break inside quotes, after a backslash or after "|", "||" or "&&" continues the
    line; a "#" that starts a word outside quotes starts a comment.
    """
    lines: list[tuple[str, str]] = []
    text: list[str] = []
    documents: list[str] = []
    pending: list[tuple[str, bool]] = []
    quote = ""
    index = 0
    while index < len(script):
        char = script[index]
        if quote == "'":
            quote = "" if char == "'" else quote
        elif char == "\\":
            pair = script[index : index + 2]
            if pair != "\\\n":
                text.append(pair)
            index += 2
            continue
        elif quote:
            quote = "" if char == '"' else quote
        elif char in "'\"":
            quote = char
        elif char == "#" and (not text or text[-1][-1] in " \t;&|()"):
            end = script.find("\n", index)
            index = len(script) if end < 0 else end
            continue
        elif script.startswith("<<<", index):
            text.append("<<<")
            index += 3
            continue
        elif char == "<" and (heredoc := HEREDOC.match(script, index)) is not None:
            pending.append((heredoc[3], bool(heredoc[1])))
            text.append(heredoc[0])
            index = heredoc.end()
            continue
        elif char == "\n":
            line = "".join(text).rstrip()
            index += 1
            if not pending and line.endswith(("|", "&&")):
                text.append(" ")
                continue
            for delimiter, tabs in pending:
                document, index = _here_document(script, index, delimiter, tabs)
                documents.append(document)
            lines.append((" ".join(line.split()), " ".join(documents)))
            text, documents, pending = [], [], []
            continue
        text.append(char)
        index += 1
    lines.append((" ".join("".join(text).split()), " ".join(documents)))
    return lines


def _step_lines(step: dict[str, Any]) -> list[tuple[str, str]]:
    """A step's action, or its script's logical lines with their here-documents."""
    lines = [(step["uses"], "")] if isinstance(step.get("uses"), str) else []
    if isinstance(step.get("run"), str):
        lines.extend(_logical_lines(step["run"]))
    return lines


def _discards_status(lines: list[tuple[str, str]], command: str) -> bool:
    """Whether a line that runs the command turns its failure into success."""
    for line, documents in lines:
        if command in line:
            after = line[line.index(command) + len(command) :]
        elif command in documents:
            after = line
        else:
            continue
        if DISCARDED.search(after):
            return True
    return False


def _gate_issues(path: Path, name: str, job: dict[str, Any]) -> list[str]:
    """A required job's gate commands must run, unskippable, and keep their exit status."""
    commands = REQUIRED_COMMANDS.get(path.name, {}).get(name, ())
    errors = []
    condition = _condition(job)
    reviewed_job = REVIEWED_JOB_CONDITIONS.get(path.name, {}).get(name)
    if commands and condition not in (None, *ALWAYS_RUNS, reviewed_job):
        errors.append(f"{path}: required job {name} may be skipped (if: {condition})")
    reviewed = REVIEWED_STEP_CONDITIONS.get(path.name, {})
    found: set[str] = set()
    for step in _steps(job):
        lines = _step_lines(step)
        text = "\n".join(f"{line}\n{documents}" for line, documents in lines)
        condition = _condition(step)
        skippable = (
            frozenset()
            if condition is None or condition in ALWAYS_RUNS
            else frozenset(commands) - reviewed.get(condition, frozenset())
        )
        for command in (command for command in commands if command in text):
            found.add(command)
            if command in skippable:
                errors.append(f"{path}: {name} may skip {command} (if: {condition})")
            if _discards_status(lines, command):
                errors.append(f"{path}: {name} discards the exit status of {command}")
    errors.extend(f"{path}: {name} no longer runs {c}" for c in commands if c not in found)
    return errors


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
    if _schedules_cancel_each_other(document):
        errors.append(
            f"{path}: key the concurrency group on github.event.schedule, so that one"
            " schedule's run cannot cancel another's"
        )
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
        granted = _write_scopes(job.get("permissions"))
        writable = JOB_WRITE_SCOPES.get(path.name, {}).get(str(name), frozenset())
        if granted is None or granted - writable:
            errors.append(
                f"{path}: {name} may hold write permissions only for"
                f" {', '.join(sorted(writable)) or 'nothing'}"
            )
        if path.name in GATING and _continues_unchecked(job):
            errors.append(
                f"{path}: {name} must not continue on error in a gating workflow, except in a"
                " step whose outcome a later step checks"
            )
        for step in _steps(job):
            uses = step.get("uses")
            if isinstance(uses, str) and uses.startswith("actions/checkout@"):
                options = step.get("with")
                if not isinstance(options, dict) or options.get("persist-credentials") is not False:
                    errors.append(f"{path}: {name} must check out with persist-credentials: false")
        errors.extend(_gate_issues(path, str(name), job))
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
