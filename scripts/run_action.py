"""GitHub Action driver for ``action.yml``: inputs are untrusted data, the ``symbiote`` CLI does the work.

The composite Action passes every input through environment variables (never through shell source). This
script validates each value, confines every path to ``GITHUB_WORKSPACE``, runs the real CLI as a subprocess
(``scan`` -> ``validate`` -> ``policy check`` -> optional ``conformance``) and maps the CLI's stable exit codes
(``src/symbiote/cli/exit_codes.py``) onto Action outputs and its own return code:

* 0  clean
* 1  findings at or above ``fail-on`` (or a failed conformance requirement)
* 3  an emitted document failed schema validation
* 5  conformance blocked by unknowns
* 6  the scan could not read or write

It imports nothing from ``symbiote`` so the driver stays independent of the package layout.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low", "info")
LEVELS = ("none", "minimal", "standard", "verified")

EXIT_FINDINGS = 1
EXIT_SCHEMA = 3
EXIT_COVERAGE = 5
EXIT_IO = 6

Command = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _boolean(value: str) -> bool:
    if value not in {"true", "false"}:
        raise ValueError("boolean inputs must be true or false")
    return value == "true"


_GLOB = re.compile(r"[A-Za-z0-9*?][A-Za-z0-9*?_-]*")


def _globs(value: str) -> tuple[str, ...]:
    """Comma- or space-separated check-id globs (``SYM-COV-*``); anything else is refused, not escaped."""
    items = tuple(v for v in re.split(r"[,\s]+", value) if v)
    if any(not _GLOB.fullmatch(v) for v in items):
        raise ValueError("exclude must list check-id globs such as SYM-COV-*")
    return items


def _within(workspace: Path, value: str) -> Path:
    if not value or any(c in value for c in "\r\n\x00"):
        raise ValueError("paths must be nonempty and contain no newline or NUL")
    path = (workspace / value).absolute()
    if (
        ".." in path.parts
        or not path.is_relative_to(workspace)
        or not path.resolve().is_relative_to(workspace)
    ):
        raise ValueError("Action paths must stay within GITHUB_WORKSPACE")
    return path


@dataclass(frozen=True)
class Config:
    workspace: Path
    project: Path
    output_dir: Path
    fail_on: str
    fail_on_indeterminate: bool
    conformance_level: str
    sarif: bool
    exclude: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Config:
        workspace = Path(env["GITHUB_WORKSPACE"]).resolve(strict=True)
        project = _within(workspace, env.get("SYMBIOTE_SCAN_PATH", "."))
        if not project.is_dir():
            raise ValueError("scan-path must be an existing directory")
        output_value = env.get("SYMBIOTE_OUTPUT_DIR", "agentbom")
        if any(c in output_value for c in "*?[]!"):
            raise ValueError("output-dir must be a literal path without glob syntax")
        output_dir = _within(workspace, output_value)
        if output_dir == workspace:
            raise ValueError("output-dir must be a subdirectory of the workspace")
        fail_on = env.get("SYMBIOTE_FAIL_ON", "high")
        if fail_on not in SEVERITIES:
            raise ValueError("fail-on must be one of " + ", ".join(SEVERITIES))
        level = env.get("SYMBIOTE_CONFORMANCE_LEVEL", "none")
        if level not in LEVELS:
            raise ValueError("conformance-level must be one of " + ", ".join(LEVELS))
        return cls(
            workspace,
            project,
            output_dir,
            fail_on,
            _boolean(env.get("SYMBIOTE_FAIL_ON_INDETERMINATE", "false")),
            level,
            _boolean(env.get("SYMBIOTE_SARIF", "false")),
            _globs(env.get("SYMBIOTE_EXCLUDE", "SYM-COV-001")),
        )


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    # The executable is this interpreter (the Action's isolated venv); arguments never pass through a shell.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", "import sys; from symbiote.cli import main; sys.exit(main())", *args],
        text=True,
        capture_output=True,
        check=False,
    )


def emit(outputs: Path | None, **values: str) -> None:
    """Append ``name=value`` lines to ``GITHUB_OUTPUT``; multiline values are refused, not escaped."""
    if outputs is None:
        return
    with outputs.open("a", encoding="utf-8") as stream:
        for name, value in values.items():
            if any(c in value for c in "\r\n"):
                raise ValueError("invalid multiline Action output")
            stream.write(f"{name}={value}\n")


def _write(path: Path, root: Path, content: str) -> None:
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError("refusing to write outside the output directory")
    path.write_text(content, encoding="utf-8")


def _fresh_output_dir(out: Path) -> None:
    """The output directory must be created by this run, or exist and be empty.

    The checked-out tree is untrusted (a pull request controls it). A planted symlink at
    ``agentbom.sarif`` would redirect the CLI's SARIF write outside GITHUB_WORKSPACE, and planted
    files (a forged ``conformance.json``, a link to ``.git/config``) would ship in the evidence
    artifact. Refuse to reuse anything that was already there.
    """
    if out.is_symlink():
        raise ValueError("output-dir must not be a symlink")
    out.mkdir(parents=True, exist_ok=True)
    if out.is_symlink() or any(out.iterdir()):
        raise ValueError(
            f"output-dir {out} already exists and is not empty; the Action only writes into a fresh directory"
        )


def run(config: Config, *, command: Command = _run, outputs: Path | None = None) -> int:
    out = config.output_dir
    _fresh_output_dir(out)
    companion = out / "agentbom.json"
    documents = [companion, out / "agentbom.cdx.json", out / "agentbom.spdx.json"]
    sarif = out / "agentbom.sarif"
    emit(
        outputs,
        output_dir=str(out),
        agentbom_path="",
        sarif_path="",
        policy_exit_code="",
        conformance_exit_code="",
    )

    scanned = command(["scan", str(config.project), "-o", str(out), "--format", "all"])
    if scanned.returncode != 0:
        print(scanned.stderr or scanned.stdout, file=sys.stderr)
        return scanned.returncode if scanned.returncode in {EXIT_SCHEMA, EXIT_IO} else EXIT_IO
    if not all(p.is_file() for p in documents):
        print("scan completed without writing the three AgentBOM documents", file=sys.stderr)
        return EXIT_IO
    emit(outputs, agentbom_path=str(companion))

    validated = command(["validate", *(str(p) for p in documents)])
    if validated.returncode != 0:
        print(validated.stderr or validated.stdout, file=sys.stderr)
        return EXIT_SCHEMA

    policy_args = [
        "policy",
        "check",
        str(companion),
        "--fail-on",
        config.fail_on,
        "--sarif",
        str(sarif),
        "--json",
    ]
    if config.fail_on_indeterminate:
        policy_args.append("--fail-on-indeterminate")
    for pattern in config.exclude:
        policy_args += ["--exclude", pattern]
    checked = command(policy_args)
    if checked.returncode not in {0, EXIT_FINDINGS}:
        print(checked.stderr or checked.stdout, file=sys.stderr)
        return checked.returncode or EXIT_IO
    _write(out / "findings.json", out, checked.stdout)
    emit(outputs, policy_exit_code=str(checked.returncode))
    if sarif.is_file():
        emit(outputs, sarif_path=str(sarif))

    conformance_rc = 0
    if config.conformance_level != "none":
        conformed = command(["conformance", str(companion), "--level", config.conformance_level, "--json"])
        if conformed.returncode not in {0, EXIT_FINDINGS, EXIT_COVERAGE}:
            print(conformed.stderr or conformed.stdout, file=sys.stderr)
            return conformed.returncode or EXIT_IO
        _write(out / "conformance.json", out, conformed.stdout)
        emit(outputs, conformance_exit_code=str(conformed.returncode))
        conformance_rc = conformed.returncode

    if checked.returncode != 0:
        print(f"policy findings at or above {config.fail_on}; see {out / 'findings.json'}", file=sys.stderr)
        return EXIT_FINDINGS
    return conformance_rc


def main() -> int:
    try:
        config = Config.from_env(os.environ)
        output_path = Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None
        return run(config, outputs=output_path)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Symbiote action failed: {exc}", file=sys.stderr)
        return EXIT_IO


if __name__ == "__main__":
    raise SystemExit(main())
