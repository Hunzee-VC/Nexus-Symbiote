"""Check workflows and actions for pinning, privilege and gate integrity.

Every remote action is pinned to a commit with a full-version comment that agrees wherever
the same commit is used, and is no older than its recorded floor. Local actions must exist
and are checked like any other. Expressions never reach shell source. Workflows use only
reviewed triggers, read-only top-level permissions, write scopes only in the reviewed jobs
that need them, a job time limit and checkouts without persisted credentials; scheduled runs
cannot cancel each other. In the gating workflows no job continues on error, a step may only
when a later step that runs reads its outcome, and each verification job still runs the
command that makes it a gate: outside a shell comment, in a job and a step that only a
reviewed condition can skip and that does not continue on error, and without discarding the
command's exit status. A gate command
must run as its own command line under errexit, in a reviewed shell and the checkout's root:
not quoted, in a condition, negated, chained with && or ||, in the background, after set +e,
set -n, cd, trap, exit, eval or hash (however invoked), nor in a step whose shell or working
directory is changed.
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
        # The one check branch protection requires: it must still fail on a prerequisite
        # that did not succeed.
        "verified": ("sys.exit(bool(failed))",),
    },
    "release.yml": {
        "build": (
            "scripts/check_repository_controls.py",
            "--publish",
            "scripts/check_dependency_advisories.py",
            "python -m pytest",
            "--strict-skips",
            "scripts/check_security_regressions.py",
            "scripts/check_wheel_security.py",
        ),
        "compatibility": ("scripts/check_installed_wheel.py",),
        "verify": ("gh attestation verify",),
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
HEREDOC_END = re.compile(r"[\s;&|()<>]|$")
# Required entries that are data the gate checks rather than a command it runs: they only
# have to appear, outside a comment, in a step whose shell and directory are reviewed.
REQUIRED_TEXT: dict[str, dict[str, frozenset[str]]] = {
    "ci.yml": {
        "action": frozenset({"symbiote-injected-annotation", "$EVIDENCE/hostile.json"}),
        "action-annotations": frozenset({"symbiote-injected-annotation", "set-output"}),
    },
    # Called once per distribution inside a loop, which the gate reader does not follow;
    # tests/test_release_provenance.py runs the loop.
    "release.yml": {"verify": frozenset({"gh attestation verify"})},
}
# The shells a gate step may run in, as (errexit, pipefail). GitHub runs a step without a
# shell as `bash -e {0}` and `shell: bash` as `bash --noprofile --norc -eo pipefail {0}`.
SHELLS: dict[str | None, tuple[bool, bool]] = {
    None: (True, False),
    "bash -e {0}": (True, False),
    "bash": (True, True),
    "bash --noprofile --norc -eo pipefail {0}": (True, True),
}
PYTHON = re.compile(r"python(?:\d+(?:\.\d+)?)?")
# Python options that print and exit before the script runs, or keep the process alive and
# discard its status.
PYTHON_EXITS = frozenset("h?Vi")
# The timeout options that leave the command's status intact, alone or with a value.
TIMEOUT_FLAGS = frozenset({"--foreground", "--preserve-status", "-v", "--verbose"})
TIMEOUT_VALUED = frozenset({"-k", "--kill-after", "-s", "--signal"})
# Bash long options that only change start-up; any other may print and exit.
BASH_LONG_OPTIONS = frozenset({"--noprofile", "--norc", "--posix"})
# Shell options after which a later command may not run: noexec reads without executing,
# onecmd exits after one command.
NOEXEC_NAMES = frozenset({"noexec", "onecmd"})
# NAME=value, and the forms that change a variable without giving it a known value:
# NAME+=value and NAME[index]=value.
ASSIGNMENT = re.compile(r"([A-Za-z_]\w*)(\[[^\]]*\])?(\+?)=")
REDIRECT = re.compile(r"&>>?|[<>]>?[&|]?")
# Builtins after which a later command is no longer a gate: they move the shell, replace or
# end it, install a trap that can rewrite its status, or define commands.
UNSAFE_BUILTINS = frozenset(
    {
        "cd",
        "pushd",
        "popd",
        "trap",
        "exec",
        "exit",
        "return",
        "eval",
        "source",
        ".",
        "alias",
        "hash",
        "enable",
    }
)
# Builtins that can rebind a variable other than by a plain NAME=value assignment.
BINDING_BUILTINS = frozenset(
    {"export", "declare", "typeset", "local", "readonly", "read", "mapfile", "readarray"}
    | {"unset", "getopts", "let"}
)
VARIABLE = re.compile(r"\$\{(\w+)\}|\$(\w+)")
DEFAULT_ASSIGNMENT = re.compile(r"\$\{(\w+):?=")
UNSUPPORTED = frozenset({"case", "select", "function", "coproc"})


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
    always(), or one whose condition reads that outcome. A step's name is not a read.
    """
    if job.get("continue-on-error", False) is not False:
        return True
    steps = _steps(job)
    for index, step in enumerate(steps):
        if step.get("continue-on-error", False) is False:
            continue
        outcome = f"steps.{step.get('id')}.outcome"
        if not isinstance(step.get("id"), str) or not any(
            outcome in json.dumps({k: v for k, v in later.items() if k != "name"}, default=str)
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


class _ShellSyntaxError(ValueError):
    """Shell source this checker does not read; a gate in it does not count."""


Token = tuple[str, Any]


def _lex(script: str) -> list[Token]:
    """Words, operators, redirections and here-documents of a shell script, without comments.

    A word's value drops its quotes and keeps expansions as written.
    """
    return _scan(script, 0, nested=False)[0]


def _scan(script: str, index: int, nested: bool) -> tuple[list[Token], int]:
    """Tokens from ``index`` to the end, or when nested, to the ")" that closes a substitution.

    Returns the tokens and the index after the last character read.
    """
    tokens: list[Token] = []
    pending: list[tuple[str, bool, list[str]]] = []
    word: list[str] | None = None
    depth = 0

    def finish() -> None:
        nonlocal word
        if word is not None:
            if nested and word == ["case"]:
                raise _ShellSyntaxError("case inside a substitution")
            tokens.append(("word", "".join(word)))
            word = None

    def substitution(start: int) -> int:
        end = _scan(script, start, nested=True)[1]
        if pending and "\n" in script[start:end]:
            raise _ShellSyntaxError("here-document around a multi-line substitution")
        return end

    while index < len(script):
        char = script[index]
        if char == "\\":
            if script[index + 1 : index + 2] != "\n":
                word = [*(word or []), script[index + 1 : index + 2]]
            index += 2
        elif char == "$" and script[index + 1 : index + 2] == "'":
            end = _ansi_c_quoted(script, index + 1)
            word = [*(word or []), script[index + 2 : end - 1]]
            index = end
        elif char == "'":
            end = script.find("'", index + 1)
            if end < 0:
                raise _ShellSyntaxError("unterminated quote")
            word = [*(word or []), script[index + 1 : end]]
            index = end + 1
        elif char == '"':
            end = _double_quoted(script, index)
            word = [*(word or []), script[index + 1 : end - 1]]
            index = end
        elif char == "$" and script[index + 1 : index + 2] == "(":
            end = substitution(index + 2)
            word = [*(word or []), script[index:end]]
            index = end
        elif char == "$" and script[index + 1 : index + 2] == "{":
            end = _balanced(script, index + 1)
            word = [*(word or []), script[index:end]]
            index = end
        elif char == "`":
            end = _backquoted(script, index)
            word = [*(word or []), script[index:end]]
            index = end
        elif char == "(" and word is not None and "".join(word).endswith("="):
            end = substitution(index + 1)
            word.append(script[index:end])
            index = end
        elif char in " \t":
            finish()
            index += 1
        elif char == "#" and word is None:
            end = script.find("\n", index)
            index = len(script) if end < 0 else end
        elif char == "\n":
            finish()
            tokens.append(("op", "\n"))
            index += 1
            for delimiter, tabs, document in pending:
                lines = []
                while index < len(script):
                    end = script.find("\n", index)
                    end = len(script) if end < 0 else end
                    line = script[index:end]
                    index = end + 1
                    if (line.lstrip("\t") if tabs else line) == delimiter:
                        break
                    lines.append(line)
                else:
                    raise _ShellSyntaxError("unterminated here-document")
                document.append("\n".join(lines))
            pending = []
        elif char in "<>" or script.startswith("&>", index):
            if word is not None and "".join(word).isdigit():
                word = None
            finish()
            if script.startswith("<<<", index):
                tokens.append(("redirect", "<<<"))
                index += 3
            elif script.startswith("<<", index):
                heredoc = HEREDOC.match(script, index)
                if heredoc is None or not HEREDOC_END.match(script, heredoc.end()):
                    raise _ShellSyntaxError("unreadable here-document")
                body: list[str] = []
                tokens.append(("heredoc", body))
                pending.append((heredoc[3], bool(heredoc[1]), body))
                index = heredoc.end()
            elif (redirect := REDIRECT.match(script, index)) is not None:
                tokens.append(("redirect", redirect[0]))
                index = redirect.end()
            else:
                raise _ShellSyntaxError("unreadable redirection")
        elif char in ";&|()":
            finish()
            if nested and char == ")" and depth == 0:
                if pending:
                    raise _ShellSyntaxError("unterminated here-document")
                return tokens, index + 1
            depth += {"(": 1, ")": -1}.get(char, 0)
            pair = script[index : index + 2]
            operator = pair if pair in ("&&", "||", ";;", "|&") else char
            tokens.append(("op", operator))
            index += len(operator)
        else:
            word = [*(word or []), char]
            index += 1
    if nested:
        raise _ShellSyntaxError("unbalanced expansion")
    finish()
    if pending:
        raise _ShellSyntaxError("unterminated here-document")
    return tokens, index


def _ansi_c_quoted(script: str, start: int) -> int:
    """The index after the $'...' string whose quote is at ``start``."""
    index = start + 1
    while index < len(script):
        if script[index] == "\\":
            index += 2
        elif script[index] == "'":
            return index + 1
        else:
            index += 1
    raise _ShellSyntaxError("unterminated quote")


def _double_quoted(script: str, start: int) -> int:
    """The index after the double-quoted string that starts at ``start``."""
    index = start + 1
    while index < len(script):
        char = script[index]
        if char == "\\":
            index += 2
        elif char == '"':
            return index + 1
        elif char == "$" and script[index + 1 : index + 2] == "(":
            index = _scan(script, index + 2, nested=True)[1]
        elif char == "$" and script[index + 1 : index + 2] == "{":
            index = _balanced(script, index + 1)
        elif char == "`":
            index = _backquoted(script, index)
        else:
            index += 1
    raise _ShellSyntaxError("unterminated quote")


def _backquoted(script: str, start: int) -> int:
    index = start + 1
    while index < len(script):
        if script[index] == "\\":
            index += 2
        elif script[index] == "`":
            return index + 1
        else:
            index += 1
    raise _ShellSyntaxError("unterminated command substitution")


def _balanced(script: str, start: int) -> int:
    """The index after the "{" at ``start`` and everything up to its partner."""
    depth = 0
    index = start
    while index < len(script):
        char = script[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            index = _double_quoted(script, index)
            continue
        if char == "$" and script[index + 1 : index + 2] == "(":
            index = _scan(script, index + 2, nested=True)[1]
            continue
        if char == "`":
            index = _backquoted(script, index)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    raise _ShellSyntaxError("unbalanced expansion")


class _Command:
    """A simple command's words and here-documents, or a compound command's body."""

    def __init__(
        self, body: list[_Item] | None = None, kind: str = "simple", binds: str = ""
    ) -> None:
        self.words: list[str] = []
        self.documents: list[str] = []
        self.body = body
        self.kind = kind
        self.binds = binds


class _Item:
    """An and-or list: pipelines (negated or not) joined by && or ||."""

    def __init__(self, pipeline: tuple[bool, list[_Command]]) -> None:
        self.pipelines = [pipeline]
        self.operators: list[str] = []
        self.background = False


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.index = 0

    def peek(self) -> Token | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def at(self, kind: str, *values: Any) -> bool:
        token = self.peek()
        return token is not None and token[0] == kind and (not values or token[1] in values)

    def skip_newlines(self) -> None:
        while self.at("op", "\n"):
            self.index += 1

    def script(self) -> list[_Item]:
        items, _ = self.items(frozenset())
        return items

    def items(self, ends: frozenset[str]) -> tuple[list[_Item], str]:
        items: list[_Item] = []
        while True:
            token = self.peek()
            if token is None:
                if ends:
                    raise _ShellSyntaxError("unterminated compound command")
                return items, ""
            if self.at("op", "\n", ";"):
                self.index += 1
                continue
            if (token[0] == "op" and token[1] == ")" and ")" in ends) or (
                token[0] == "word" and token[1] in ends
            ):
                self.index += 1
                return items, str(token[1])
            item = self.and_or()
            items.append(item)
            if self.at("op", "&"):
                item.background = True
                self.index += 1
            elif self.at("op", "\n", ";"):
                self.index += 1
            elif not (self.peek() is None or self.at("op", ")") or self.at("word", *ends)):
                raise _ShellSyntaxError("unexpected operator")

    def and_or(self) -> _Item:
        item = _Item(self.pipeline())
        while self.at("op", "&&", "||"):
            item.operators.append(str(self.tokens[self.index][1]))
            self.index += 1
            self.skip_newlines()
            item.pipelines.append(self.pipeline())
        return item

    def pipeline(self) -> tuple[bool, list[_Command]]:
        negated = False
        while self.at("word", "!"):
            negated = True
            self.index += 1
        commands = [self.command()]
        while self.at("op", "|", "|&"):
            self.index += 1
            self.skip_newlines()
            commands.append(self.command())
        return negated, commands

    def command(self) -> _Command:
        token = self.peek()
        if token is None:
            raise _ShellSyntaxError("missing command")
        body: list[_Item] = []
        kind = str(token[1])
        binds = ""
        if token == ("op", "("):
            self.index += 1
            body, _ = self.items(frozenset({")"}))
        elif token[0] == "op":
            raise _ShellSyntaxError("unexpected operator")
        elif token[0] != "word":
            return self.simple()
        elif token[1] in UNSUPPORTED:
            raise _ShellSyntaxError(f"unsupported {token[1]}")
        elif token[1] == "if":
            self.index += 1
            while True:
                body += self.items(frozenset({"then"}))[0]
                part, end = self.items(frozenset({"elif", "else", "fi"}))
                body += part
                if end == "else":
                    body += self.items(frozenset({"fi"}))[0]
                if end != "elif":
                    break
        elif token[1] in ("while", "until"):
            self.index += 1
            body = self.items(frozenset({"do"}))[0] + self.items(frozenset({"done"}))[0]
        elif token[1] == "for":
            self.index += 1
            if not self.at("word"):
                raise _ShellSyntaxError("unreadable for loop")
            binds = str(self.tokens[self.index][1])
            self.index += 1
            while self.at("word"):
                self.index += 1
            while self.at("op", "\n", ";"):
                self.index += 1
            if not self.at("word", "do"):
                raise _ShellSyntaxError("unreadable for loop")
            self.index += 1
            body = self.items(frozenset({"done"}))[0]
        elif token[1] == "{":
            self.index += 1
            body = self.items(frozenset({"}"}))[0]
        else:
            return self.simple()
        while self.redirections(_Command()):
            pass
        return _Command(body=body, kind=kind, binds=binds)

    def redirections(self, command: _Command) -> bool:
        token = self.peek()
        if token is None or token[0] not in ("redirect", "heredoc"):
            return False
        self.index += 1
        if token[0] == "heredoc":
            command.documents.append("".join(token[1]))
        elif self.at("word"):
            self.index += 1
        else:
            raise _ShellSyntaxError("redirection without a target")
        return True

    def simple(self) -> _Command:
        command = _Command()
        start = self.index
        while self.peek() is not None and not self.at("op"):
            if not self.redirections(command):
                command.words.append(str(self.tokens[self.index][1]))
                self.index += 1
        if self.index == start or (command.words and self.at("op", "(")):
            raise _ShellSyntaxError("unsupported command")
        return command


def _commands(items: list[_Item]) -> Iterator[tuple[_Command, bool]]:
    """Every simple command, and whether it stands alone at the top of the script."""
    for item in items:
        alone = len(item.pipelines) == 1 and len(item.pipelines[0][1]) == 1
        alone = alone and not item.pipelines[0][0] and not item.background
        for _, commands in item.pipelines:
            for command in commands:
                if command.body is None:
                    yield command, alone
                else:
                    yield from ((nested, False) for nested, _ in _commands(command.body))


def _loop_variables(items: list[_Item]) -> Iterator[str]:
    """The variables that for loops anywhere in these items assign."""
    for item in items:
        for _, commands in item.pipelines:
            for command in commands:
                if command.body is not None:
                    if command.binds:
                        yield command.binds
                    yield from _loop_variables(command.body)


def _options(args: list[str], errexit: bool, pipefail: bool) -> tuple[bool, bool, int, bool, bool]:
    """Apply set-style options; the new errexit and pipefail, the next index, -c and -n."""
    index = 0
    command = False
    noexec = False
    while index < len(args) and args[index][:1] in ("-", "+") and args[index] not in ("-", "--"):
        option = args[index]
        index += 1
        if option.startswith("--"):
            noexec = noexec or option not in BASH_LONG_OPTIONS
            continue
        for letter in option[1:]:
            if letter == "c":
                command = True
            elif letter in "ntD":
                noexec = noexec or option[0] == "-"
            elif letter == "e":
                errexit = option[0] == "-"
            elif letter == "o" and index < len(args):
                name = args[index]
                index += 1
                if name == "errexit":
                    errexit = option[0] == "-"
                elif name == "pipefail":
                    pipefail = option[0] == "-"
                elif name in NOEXEC_NAMES:
                    noexec = noexec or option[0] == "-"
    return errexit, pipefail, index, command, noexec


def _shopt(args: list[str], errexit: bool, pipefail: bool) -> tuple[bool, bool, bool]:
    """Apply `shopt -s -o` or `shopt -u -o`: the new errexit and pipefail, and noexec."""
    letters = ""
    index = 0
    noexec = False
    while index < len(args) and args[index].startswith("-") and args[index] != "--":
        letters += args[index][1:]
        index += 1
    index += index < len(args) and args[index] == "--"
    if "o" not in letters or not ({"s", "u"} & set(letters)):
        return errexit, pipefail, noexec
    enabled = "s" in letters
    for name in args[index:]:
        if name == "errexit":
            errexit = enabled
        elif name == "pipefail":
            pipefail = enabled
        elif name in NOEXEC_NAMES:
            noexec = noexec or enabled
    return errexit, pipefail, noexec


def _unwrapped(words: list[str]) -> list[str]:
    """A command's words without the `builtin`, `command` and `time` that only prefix it."""
    while words:
        if words[0] == "builtin":
            words = words[1:]
            if words and words[0] == "--":
                words = words[1:]
        elif words[0] in ("command", "time"):
            words = words[1:]
            while words and words[0].startswith("-"):
                if words[0] == "--":
                    words = words[1:]
                    break
                if {"v", "V"} & set(words[0]):
                    return []
                words = words[1:]
        else:
            break
    return words


def _resolve(word: str, variables: dict[str, str]) -> str:
    return VARIABLE.sub(lambda match: variables.get(match[1] or match[2], match[0]), word)


def _may_name_a_builtin(program: str) -> bool:
    """Whether a command name, as resolved, can still expand to the name of a builtin."""
    if "{" in VARIABLE.sub("", program):
        return True
    if "$" not in program and "`" not in program:
        return False
    literal = VARIABLE.sub("", program)
    return "$" in literal or "`" in literal or "/" not in literal


class _Gate:
    """A command whose failure fails the step: its program, arguments and here-documents."""

    def __init__(self, program: str, args: list[str], documents: list[str]) -> None:
        self.program = program
        self.args = args
        self.documents = documents

    def runs(self, required: str) -> bool:
        """Whether this command runs the required command, or passes it what it needs."""
        if " ".join([self.program, *self.args]).startswith(required):
            return True
        if PYTHON.fullmatch(self.program.rsplit("/", 1)[-1]) is None:
            return False
        script = None
        index = 0
        while index < len(self.args):
            arg = self.args[index]
            index += 1
            if not arg.startswith("-") or arg == "-":
                script = arg
                break
            if arg == "--":
                script = self.args[index] if index < len(self.args) else None
                break
            if arg.startswith("--"):
                if arg.partition("=")[0] != "--check-hash-based-pycs":
                    return False
                index += "=" not in arg
                continue
            letters = arg[1:]
            if PYTHON_EXITS & set(letters.split("W")[0].split("X")[0]):
                return False
            if "c" in letters.split("W")[0].split("X")[0]:
                return False
            if "m" in letters.split("W")[0].split("X")[0]:
                break
            value = re.search(r"[WX](.*)", letters)
            index += value is not None and not value[1]
        if required.endswith(".py"):
            return script is not None and (script == required or script.endswith("/" + required))
        return required in " ".join(self.args) or any(required in d for d in self.documents)


def _gates(script: str, errexit: bool, pipefail: bool) -> list[_Gate]:
    """The commands of a shell script whose failure fails it.

    Such a command stands alone on its line, at the top of the script and under errexit,
    unless it is a pipeline's last command or pipefail is on; a following "|| exit N" for a
    nonzero N keeps it. A script this checker cannot read has none.
    """
    try:
        items = _Parser(_lex(script)).script()
    except _ShellSyntaxError:
        return []
    gates: list[_Gate] = []
    variables: dict[str, str] = {}
    trusted = True
    for item in items:
        if trusted and errexit and not item.background:
            gates.extend(_item_gates(item, pipefail, variables))
        for name in _loop_variables([item]):
            variables.pop(name, None)
        for command, alone in _commands([item]):
            words = command.words
            for word in words:
                for match in DEFAULT_ASSIGNMENT.finditer(word):
                    variables.pop(match[1], None)
            start = next((i for i, w in enumerate(words) if not ASSIGNMENT.match(w)), len(words))
            for assignment in words[:start]:
                form = ASSIGNMENT.match(assignment)
                assert form is not None
                if alone and start == len(words) and not form[2] and not form[3]:
                    variables[form[1]] = assignment[form.end() :]
                else:
                    variables.pop(form[1], None)
            words = _unwrapped(words[start:])
            if not words:
                continue
            program, args = _resolve(words[0], variables), words[1:]
            # A set or shopt whose options come from an expansion cannot be read.
            expanded = program in ("set", "shopt") and any(
                mark in arg for arg in args for mark in ("$", "`", "{")
            )
            if _may_name_a_builtin(program) or expanded:
                trusted = False
            elif program == "set":
                enabled, piped, _, _, noexec = _options(args, errexit, pipefail)
                errexit = enabled if alone else errexit and enabled
                pipefail = piped if alone else pipefail and piped
                trusted = trusted and not noexec
            elif program == "shopt":
                enabled, piped, noexec = _shopt(args, errexit, pipefail)
                errexit = enabled if alone else errexit and enabled
                pipefail = piped if alone else pipefail and piped
                trusted = trusted and not noexec
            elif program in BINDING_BUILTINS or (program == "printf" and "-v" in args):
                variables.clear()
            elif program in UNSAFE_BUILTINS and not _fails(program, args):
                trusted = False
    return gates


def _fails(program: str, args: list[str]) -> bool:
    """`exit N` with a literal N that is nonzero modulo 256, or `exec` that only redirects."""
    if program == "exec":
        return not args
    return (
        program == "exit"
        and len(args) == 1
        and re.fullmatch(r"[0-9]+", args[0]) is not None
        and int(args[0]) % 256 != 0
    )


def _exits_with_failure(pipeline: tuple[bool, list[_Command]]) -> bool:
    negated, commands = pipeline
    if negated or len(commands) != 1:
        return False
    command = commands[0]
    if command.body is not None:
        if (
            command.kind not in ("{", "(")
            or not command.body
            or command.body[-1].background
            or command.body[-1].operators
        ):
            return False
        return _exits_with_failure(command.body[-1].pipelines[0])
    return command.words[:1] == ["exit"] and _fails("exit", command.words[1:])


def _after_timeout(words: list[str]) -> list[str]:
    """The command `timeout` runs, or none when an option may stop it from running."""
    while words and words[0].startswith("-"):
        option, equals, _ = words[0].partition("=")
        if words[0] == "--":
            words = words[1:]
            break
        if words[0] in TIMEOUT_FLAGS:
            words = words[1:]
        elif option in TIMEOUT_VALUED:
            words = words[1:] if equals else words[2:]
        elif option[:2] in ("-k", "-s") and not option.startswith("--"):
            words = words[1:]
        else:
            return []
    return words[1:]


def _item_gates(item: _Item, pipefail: bool, variables: dict[str, str]) -> list[_Gate]:
    if item.operators and not (item.operators == ["||"] and _exits_with_failure(item.pipelines[1])):
        return []
    negated, commands = item.pipelines[0]
    if negated:
        return []
    gates: list[_Gate] = []
    for index, command in enumerate(commands):
        if command.body is not None or (index < len(commands) - 1 and not pipefail):
            continue
        words = command.words
        while words and ASSIGNMENT.match(words[0]):
            words = words[1:]
        if words and words[0] == "timeout":
            words = _after_timeout(words[1:])
        if not words:
            continue
        program = _resolve(words[0], variables)
        gate = _Gate(program, words[1:], command.documents)
        gates.append(gate)
        if gate.program.rsplit("/", 1)[-1] in ("bash", "sh"):
            errexit, piped, script, inline, noexec = _options(gate.args, False, False)
            if inline and not noexec and script < len(gate.args):
                gates.extend(_gates(gate.args[script], errexit, piped))
    return gates


def _run_setting(
    key: str, step: dict[str, Any], job: dict[str, Any], defaults: Any
) -> tuple[Any, str]:
    """A step's shell or working directory, and where it was set; unreadable defaults fail."""
    if key in step:
        return step[key], "step"
    for source, value in (("job defaults", job.get("defaults")), ("workflow defaults", defaults)):
        if value is None:
            continue
        run = value.get("run", {}) if isinstance(value, dict) else None
        if not isinstance(run, dict):
            return "unreadable", source
        if key in run:
            return run[key], source
    return None, ""


def _gate_issues(path: Path, name: str, job: dict[str, Any], defaults: Any) -> list[str]:
    """A required job's gate commands must run, unskippable, and keep their exit status."""
    commands = REQUIRED_COMMANDS.get(path.name, {}).get(name, ())
    text_only = REQUIRED_TEXT.get(path.name, {}).get(name, frozenset())
    errors = []
    condition = _condition(job)
    reviewed_job = REVIEWED_JOB_CONDITIONS.get(path.name, {}).get(name)
    if commands and condition not in (None, *ALWAYS_RUNS, reviewed_job):
        errors.append(f"{path}: required job {name} may be skipped (if: {condition})")
    reviewed = REVIEWED_STEP_CONDITIONS.get(path.name, {})
    found: set[str] = set()
    unstructured: set[str] = set()
    continued: set[str] = set()
    for step in _steps(job):
        lines = _step_lines(step)
        text = "\n".join(f"{line}\n{documents}" for line, documents in lines)
        present = [command for command in commands if command in text]
        if not present:
            continue
        condition = _condition(step)
        skippable = (
            frozenset()
            if condition is None or condition in ALWAYS_RUNS
            else frozenset(commands) - reviewed.get(condition, frozenset())
        )
        uses: str = step["uses"] if isinstance(step.get("uses"), str) else ""
        run = step.get("run")
        gates: list[_Gate] = []
        if isinstance(run, str):
            shell, source = _run_setting("shell", step, job, defaults)
            directory, where = _run_setting("working-directory", step, job, defaults)
            flags = SHELLS.get(shell) if isinstance(shell, str) or shell is None else None
            if flags is None:
                errors.append(f"{path}: {name} runs its gate under the {source} shell {shell!r}")
            elif directory is not None:
                errors.append(
                    f"{path}: {name} runs its gate in the {where} directory {directory!r}"
                )
            else:
                gates = _gates(run, *flags)
        for command in present:
            if command in skippable:
                errors.append(f"{path}: {name} may skip {command} (if: {condition})")
            if _discards_status(lines, command):
                errors.append(f"{path}: {name} discards the exit status of {command}")
            if step.get("continue-on-error", False) is not False:
                continued.add(command)
            elif command in text_only or command in uses or any(g.runs(command) for g in gates):
                found.add(command)
            else:
                unstructured.add(command)
    for command in commands:
        if command in found:
            continue
        if command in unstructured:
            errors.append(
                f"{path}: {name} does not run {command} as a command of its own whose"
                " failure fails the step"
            )
        elif command in continued:
            errors.append(f"{path}: {name} runs {command} only in a step that continues on error")
        else:
            errors.append(f"{path}: {name} no longer runs {command}")
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
        errors.extend(_gate_issues(path, str(name), job, document.get("defaults")))
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


def _uses_values(document: Any) -> Iterator[str]:
    """Every string `uses` value in a workflow or action."""
    if isinstance(document, dict):
        for key, child in document.items():
            if key == "uses" and isinstance(child, str):
                yield child
            yield from _uses_values(child)
    elif isinstance(document, list):
        for child in document:
            yield from _uses_values(child)


def local_actions(document: Any) -> Iterator[str]:
    """Every `uses: ./path` reference in a workflow or action."""
    return (value for value in _uses_values(document) if value.startswith("./"))


def check(path: Path) -> list[str]:
    errors: list[str] = []
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        return [f"{path}: expected a mapping"]
    # GitHub runs every file in .github/workflows as a workflow, whatever it is called.
    is_action = path.name in {"action.yml", "action.yaml"} and tuple(path.parent.parts[-2:]) != (
        ".github",
        "workflows",
    )
    if not is_action:
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
        text = path.read_text(encoding="utf-8")
        # The comment is read line by line, so a pin in any other YAML spelling, such as a
        # flow mapping, would escape this check; the parsed file says how many there are.
        parsed = sum(
            1
            for value in _uses_values(yaml.safe_load(text))
            if not value.startswith("./") and PIN.fullmatch(value)
        )
        lines = [USES_LINE.match(line) for line in text.splitlines()]
        read = [m for m in lines if m and not m[1].startswith("./") and PIN.fullmatch(m[1])]
        if len(read) != parsed:
            errors.append(f"{path}: write each pinned uses on a line of its own, as uses: <pin>")
        for match in read:
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
    """Workflows, the root action, local actions and every action they reference.

    GitHub runs workflows with either extension; checking only one would let an unpinned
    or shell-injecting workflow through under the other.
    """
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
    if not any(path.parent == WORKFLOWS for path in paths):
        # Run from anywhere but the repository root, the checker would otherwise pass.
        errors.append(f"no workflow found in {WORKFLOWS}; run the check from the repository root")
    pending = list(paths)
    checked: set[Path] = set()
    while pending:
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
                errors.append(
                    f"{path}: local action {reference} does not exist in the repository"
                    " or points outside it"
                )
                continue
            pending.extend(found)
    errors.extend(pin_comments(sorted(checked)))
    for error in errors:
        print(error)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
