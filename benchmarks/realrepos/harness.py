#!/usr/bin/env python3
"""Real-repository precision harness: fetch, scan, report and label-template.

Standard library only. Nothing from a fetched tree is executed or imported: fetching uses
git with hooks, submodules, LFS and every non-HTTPS protocol disabled, and scanning runs the
installed Nexus SymBiote offline with the built-in policy in an isolated interpreter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SCHEMA_VERSION = 1
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
OBSERVATION_RE = re.compile(r"^[0-9a-f]{16}$")
SEVERITIES = ("critical", "high", "medium", "low", "info")
VERDICTS = ("true-positive", "false-positive", "out-of-scope")
STATUSES = ("proposed", "confirmed")
MANIFEST_KEYS = ("id", "url", "ref", "commit", "tree", "group", "license", "rationale")
FETCH_TIMEOUT = 900
SCAN_TIMEOUT = 1800
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
DROPPED_GATE_PREFIXES = ("finding:", "excluded:", "collection:", "score:", "not collected:")


class HarnessError(Exception):
    """A manifest, label, budget or output that the harness refuses."""


def is_credential_category(category: str) -> bool:
    """Categories whose published results carry counts only (no repository, path or detail)."""
    lowered = category.lower()
    return "credential" in lowered or "secret" in lowered


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def finding_id(repository: str, bom_ref: str, category: str, detail: str) -> str:
    payload = {"repo": repository, "bom_ref": bom_ref, "category": category, "detail": detail}
    return hashlib.sha256(_canonical(payload).encode()).hexdigest()[:16]


def component_id(repository: str, bom_ref: str, component_type: str) -> str:
    payload = {"repo": repository, "bom_ref": bom_ref, "component_type": component_type}
    return hashlib.sha256(_canonical(payload).encode()).hexdigest()[:16]


def gap_id(repository: str, gap: str) -> str:
    payload = {"repo": repository, "gap": gap}
    return hashlib.sha256(_canonical(payload).encode()).hexdigest()[:16]


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HarnessError(f"{path}: cannot read JSON ({exc.__class__.__name__})") from exc


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# Manifest


def parse_manifest(document: Any) -> list[dict[str, str]]:
    if not isinstance(document, dict):
        raise HarnessError("manifest: not an object")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError("manifest: schema_version must be 1")
    repositories = document.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise HarnessError("manifest: repositories must be a non-empty list")
    seen_ids: set[str] = set()
    seen_urls: set[str] = set()
    parsed: list[dict[str, str]] = []
    for index, entry in enumerate(repositories):
        where = f"manifest: repositories[{index}]"
        if not isinstance(entry, dict):
            raise HarnessError(f"{where}: not an object")
        if set(entry) != set(MANIFEST_KEYS):
            raise HarnessError(f"{where}: keys must be exactly {', '.join(MANIFEST_KEYS)}")
        if not all(isinstance(entry[key], str) for key in MANIFEST_KEYS):
            raise HarnessError(f"{where}: every value must be a string")
        repo_id = entry["id"]
        if not ID_RE.fullmatch(repo_id) or repo_id in {".", ".."}:
            raise HarnessError(f"{where}: invalid id")
        if not URL_RE.fullmatch(entry["url"]) or entry["url"].endswith((".", ".git")):
            raise HarnessError(f"{where}: url must be https://github.com/<owner>/<repo>")
        if not COMMIT_RE.fullmatch(entry["commit"]):
            raise HarnessError(f"{where}: commit must be 40 lowercase hexadecimal digits")
        if entry["tree"] and not COMMIT_RE.fullmatch(entry["tree"]):
            raise HarnessError(f"{where}: tree must be empty or 40 lowercase hexadecimal digits")
        if not entry["group"]:
            raise HarnessError(f"{where}: group is empty")
        if repo_id in seen_ids:
            raise HarnessError(f"{where}: duplicate id {repo_id}")
        url = entry["url"].lower()
        if url in seen_urls:
            raise HarnessError(f"{where}: duplicate url")
        seen_ids.add(repo_id)
        seen_urls.add(url)
        parsed.append({key: entry[key] for key in MANIFEST_KEYS})
    return parsed


def load_manifest(path: Path) -> list[dict[str, str]]:
    return parse_manifest(_read_json(path))


def _select(manifest: list[dict[str, str]], only: Sequence[str] | None) -> list[dict[str, str]]:
    if not only:
        return manifest
    known = {repo["id"] for repo in manifest}
    unknown = sorted(set(only) - known)
    if unknown:
        raise HarnessError(f"unknown repository id: {', '.join(unknown)}")
    return [repo for repo in manifest if repo["id"] in set(only)]


# Fetch

Runner = Callable[..., Any]

GIT_HARDENING = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "transfer.fsckObjects=true",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "advice.detachedHead=false",
)


def git_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    source = os.environ if base is None else base
    env = {key: value for key, value in source.items() if not key.startswith("GIT_")}
    env.update(
        {
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        }
    )
    return env


def fetch_commands(repo: Mapping[str, str], target: Path) -> list[list[str]]:
    git = ["git", "-C", str(target), *GIT_HARDENING]
    return [
        ["git", "init", "--quiet", str(target)],
        [
            *git,
            "fetch",
            "--quiet",
            "--depth",
            "1",
            "--no-tags",
            "--no-recurse-submodules",
            repo["url"],
            repo["commit"],
        ],
        [*git, "checkout", "--quiet", "--detach", "FETCH_HEAD"],
    ]


def read_head(tree: Path) -> str | None:
    """Resolve HEAD by reading files only, so no git configuration of the tree runs."""
    git_dir = tree / ".git"
    try:
        head = (git_dir / "HEAD").read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    if COMMIT_RE.fullmatch(head):
        return head
    if not head.startswith("ref: refs/"):
        return None
    ref = head[5:]
    if ".." in ref.split("/"):
        return None
    try:
        value = (git_dir / ref).read_text(encoding="ascii").strip()
        return value if COMMIT_RE.fullmatch(value) else None
    except (OSError, UnicodeDecodeError):
        pass
    try:
        packed = (git_dir / "packed-refs").read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        return None
    for line in packed.splitlines():
        parts = line.split(" ")
        if len(parts) == 2 and parts[1] == ref and COMMIT_RE.fullmatch(parts[0]):
            return parts[0]
    return None


def fetch(
    manifest: list[dict[str, str]], dest: Path, *, runner: Runner = subprocess.run
) -> list[str]:
    env = git_environment()
    problems: list[str] = []
    dest.mkdir(parents=True, exist_ok=True)
    for repo in manifest:
        target = dest / repo["id"]
        if target.exists():
            if read_head(target) == repo["commit"]:
                print(f"present {repo['id']}")
                continue
            problems.append(f"{repo['id']}: {target} exists at another commit")
            continue
        try:
            for argv in fetch_commands(repo, target):
                runner(argv, env=env, check=True, timeout=FETCH_TIMEOUT, stdin=subprocess.DEVNULL)
            tree = runner(
                ["git", "-C", str(target), *GIT_HARDENING, "rev-parse", "HEAD^{tree}"],
                env=env,
                check=True,
                timeout=60,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            ).stdout.strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            problems.append(f"{repo['id']}: fetch failed ({exc.__class__.__name__})")
            continue
        if read_head(target) != repo["commit"]:
            problems.append(f"{repo['id']}: HEAD is not the pinned commit")
        elif repo["tree"] and tree != repo["tree"]:
            problems.append(f"{repo['id']}: tree hash differs from the manifest")
        else:
            print(f"fetched {repo['id']} {repo['commit']}")
    return problems


# Scan


@dataclass(frozen=True)
class Measured:
    exit_code: int
    seconds: float
    max_rss_kib: int
    timed_out: bool


def run_measured(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    stdout: Path,
    stderr: Path,
    cwd: Path,
    timeout: float,
) -> Measured:
    """Run argv, recording wall time and the peak resident set of it and its waited children."""
    with stdout.open("wb") as out, stderr.open("wb") as err:
        started = time.monotonic()
        process = subprocess.Popen(  # noqa: S603 - the caller's interpreter, fixed arguments
            list(argv),
            env=dict(env),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            start_new_session=True,
        )
        timed_out = False
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                break
            if time.monotonic() - started > timeout:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                pid, status, usage = os.wait4(process.pid, 0)
                break
            time.sleep(0.05)
        seconds = time.monotonic() - started
        process.returncode = os.waitstatus_to_exitcode(status)
    return Measured(process.returncode, round(seconds, 3), int(usage.ru_maxrss), timed_out)


def scan_environment(home: Path, base: Mapping[str, str] | None = None) -> dict[str, str]:
    source = os.environ if base is None else base
    env = {
        key: value
        for key, value in source.items()
        if not key.startswith(("NEXUS_SYMBIOTE_", "PYTHON", "XDG_"))
    }
    env.update({"HOME": str(home), "SOURCE_DATE_EPOCH": "0", "NO_COLOR": "1"})
    return env


def scan_command(python: str, tree: Path, output: Path, output_format: str = "json") -> list[str]:
    return [
        python,
        "-I",
        "-m",
        "nexus_symbiote",
        "scan",
        str(tree),
        "--no-project-policy",
        "--report-only",
        "-f",
        output_format,
        "-o",
        str(output),
    ]


def risk_command(python: str, inventory: Path) -> list[str]:
    return [
        python,
        "-I",
        "-m",
        "nexus_symbiote",
        "risk",
        str(inventory),
        "--json-output",
        "--no-project-policy",
    ]


def parse_gate(text: str) -> tuple[str, list[str]]:
    """The scan gate verdict and its main reasons, without per-finding or per-path lines."""
    verdict = "unknown"
    reasons: list[str] = []
    in_gate = False
    for raw in text.splitlines():
        line = CONTROL_RE.sub("?", raw)
        if line.startswith("Scan gate passed"):
            verdict, in_gate = "passed", False
        elif line.startswith("Scan gate failed"):
            verdict, in_gate = "failed", True
        elif in_gate and line.startswith("  - "):
            reason = line[4:]
            if reason.startswith(DROPPED_GATE_PREFIXES):
                continue
            reasons.append("[credential finding]" if is_credential_category(reason) else reason)
        else:
            in_gate = False
    return verdict, reasons


def _source_revision() -> dict[str, Any]:
    root = HERE.parent.parent
    git = shutil.which("git")
    if git is None:
        return {"commit": "unknown", "dirty": None}
    try:
        commit = subprocess.run(  # noqa: S603 - resolved git, fixed arguments
            [git, "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(  # noqa: S603 - resolved git, fixed arguments
                [git, "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
                capture_output=True,
                text=True,
                check=True,
                timeout=60,
            ).stdout.strip()
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return {"commit": "unknown", "dirty": None}
    return {"commit": commit, "dirty": dirty}


def scan(
    manifest: list[dict[str, str]],
    trees: Path,
    out: Path,
    *,
    python: str = sys.executable,
    timeout: float = SCAN_TIMEOUT,
    sarif: bool = False,
    measure: Callable[..., Measured] = run_measured,
) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="realrepos-") as scratch:
        work = Path(scratch)
        version_env = scan_environment(work)
        version = measure(
            [python, "-I", "-m", "nexus_symbiote", "--version"],
            env=version_env,
            stdout=out / "version.txt",
            stderr=out / "version.log",
            cwd=work,
            timeout=120,
        )
        tool_version = (out / "version.txt").read_text(encoding="utf-8", errors="replace").strip()
        if version.exit_code != 0:
            tool_version = "unknown"
        for repo in manifest:
            repo_id = repo["id"]
            tree = trees / repo_id
            record: dict[str, Any] = {
                "id": repo_id,
                "commit": repo["commit"],
                "tree_prefix": str(tree.resolve()),
            }
            head = read_head(tree)
            record["tree_head"] = head
            if head != repo["commit"]:
                record["error"] = "tree missing or not at the pinned commit"
                records.append(record)
                print(f"skip {repo_id}: {record['error']}")
                continue
            home = work / f"home-{repo_id}"
            home.mkdir()
            env = scan_environment(home)
            inventory = out / f"{repo_id}.json"
            measured = measure(
                scan_command(python, tree, inventory),
                env=env,
                stdout=out / f"{repo_id}.stdout.txt",
                stderr=out / f"{repo_id}.log",
                cwd=home,
                timeout=timeout,
            )
            log = (out / f"{repo_id}.log").read_text(encoding="utf-8", errors="replace")
            verdict, reasons = parse_gate(log)
            record["scan"] = {
                "exit_code": measured.exit_code,
                "seconds": measured.seconds,
                "max_rss_kib": measured.max_rss_kib,
                "timed_out": measured.timed_out,
            }
            record["gate"] = verdict
            record["gate_reasons"] = reasons
            if inventory.exists():
                risk = measure(
                    risk_command(python, inventory),
                    env=env,
                    stdout=out / f"{repo_id}.risk.json",
                    stderr=out / f"{repo_id}.risk.log",
                    cwd=home,
                    timeout=timeout,
                )
                record["risk_exit_code"] = risk.exit_code
            if sarif:
                extra = measure(
                    scan_command(python, tree, out / f"{repo_id}.sarif", "sarif"),
                    env=env,
                    stdout=out / f"{repo_id}.sarif.stdout.txt",
                    stderr=out / f"{repo_id}.sarif.log",
                    cwd=home,
                    timeout=timeout,
                )
                record["sarif_exit_code"] = extra.exit_code
            records.append(record)
            print(
                f"{repo_id}: exit {measured.exit_code}, gate {verdict}, "
                f"{measured.seconds:.1f}s, {measured.max_rss_kib // 1024} MiB"
            )
    run = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": tool_version,
        "source": _source_revision(),
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "repositories": records,
    }
    _write_json(out / "run.json", run)
    return run


# Report


def _gaps(completeness: Mapping[str, Any]) -> list[str]:
    gaps = [f"failure: {item}" for item in completeness.get("scan_failures") or []]
    gaps += [f"excluded: {item}" for item in completeness.get("surfaces_excluded") or []]
    statuses = completeness.get("scanner_status") or {}
    gaps += [
        f"collector {name}: {status}"
        for name, status in sorted(statuses.items())
        if status != "complete"
    ]
    return sorted({str(gap) for gap in gaps})


def collect_observations(
    repo_id: str, inventory: Mapping[str, Any], tree_prefix: str = ""
) -> list[dict[str, Any]]:
    """Every finding, component and coverage gap of one inventory, each with a stable id."""

    def clean(text: Any) -> str:
        value = str(text)
        if tree_prefix:
            value = value.replace(tree_prefix, "<tree>")
        return CONTROL_RE.sub("?", value)

    observations: list[dict[str, Any]] = []
    for component in inventory.get("components") or []:
        bom_ref = clean(component.get("bom_ref", ""))
        component_type = clean(component.get("component_type", ""))
        observations.append(
            {
                "id": component_id(repo_id, bom_ref, component_type),
                "kind": "component",
                "repository": repo_id,
                "bom_ref": bom_ref,
                "component_type": component_type,
            }
        )
        for risk in component.get("risks") or []:
            category = clean(risk.get("category", ""))
            detail = clean(risk.get("detail", ""))
            observations.append(
                {
                    "id": finding_id(repo_id, bom_ref, category, detail),
                    "kind": "finding",
                    "repository": repo_id,
                    "bom_ref": bom_ref,
                    "component_type": component_type,
                    "category": category,
                    "severity": clean(risk.get("severity", "")),
                    "detail": detail,
                }
            )
    completeness = (inventory.get("metadata") or {}).get("completeness") or {}
    for gap in _gaps(completeness):
        text = clean(gap)
        observations.append(
            {"id": gap_id(repo_id, text), "kind": "gap", "repository": repo_id, "detail": text}
        )
    unique: dict[str, dict[str, Any]] = {}
    for observation in observations:
        unique.setdefault(observation["id"], observation)
    return sorted(unique.values(), key=lambda item: (item["kind"], item["id"]))


def is_private(observation: Mapping[str, Any]) -> bool:
    return observation.get("kind") == "finding" and is_credential_category(
        str(observation.get("category", ""))
    )


def _severity_table(observations: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    table: dict[str, Counter[str]] = defaultdict(Counter)
    for item in observations:
        if item["kind"] == "finding":
            table[item["category"]][item["severity"]] += 1
    return {category: dict(sorted(table[category].items())) for category in sorted(table)}


def parse_labels(document: Any, expected_repository: str | None = None) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError("labels: schema_version must be 1")
    repository = document.get("repository")
    if not isinstance(repository, str) or not ID_RE.fullmatch(repository):
        raise HarnessError("labels: invalid repository")
    if expected_repository is not None and repository != expected_repository:
        raise HarnessError(f"labels: file for {expected_repository} names {repository}")
    if not isinstance(document.get("commit"), str) or not COMMIT_RE.fullmatch(document["commit"]):
        raise HarnessError(f"labels {repository}: commit must be 40 hexadecimal digits")
    entries = document.get("labels")
    if not isinstance(entries, list):
        raise HarnessError(f"labels {repository}: labels must be a list")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise HarnessError(f"labels {repository}: entry is not an object")
        observation = entry.get("observation")
        if not isinstance(observation, str) or not OBSERVATION_RE.fullmatch(observation):
            raise HarnessError(f"labels {repository}: invalid observation id")
        if observation in seen:
            raise HarnessError(f"labels {repository}: duplicate observation {observation}")
        seen.add(observation)
        if entry.get("verdict") is not None and entry.get("verdict") not in VERDICTS:
            raise HarnessError(f"labels {repository}: invalid verdict for {observation}")
        if entry.get("status") not in STATUSES:
            raise HarnessError(f"labels {repository}: invalid status for {observation}")
        for key in ("reviewer", "date", "note"):
            if not isinstance(entry.get(key, ""), str):
                raise HarnessError(f"labels {repository}: {key} must be a string")
        if entry.get("status") == "confirmed" and entry.get("verdict") is None:
            raise HarnessError(f"labels {repository}: confirmed entry without a verdict")
    return document


def load_labels(directories: Sequence[Path]) -> dict[str, dict[str, Any]]:
    """Map each labelled observation id to its entry plus the repository and commit."""
    merged: dict[str, dict[str, Any]] = {}
    for directory in directories:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            document = parse_labels(_read_json(path), path.stem)
            for entry in document["labels"]:
                if entry.get("verdict") is None:
                    continue
                key = entry["observation"]
                if key in merged:
                    raise HarnessError(f"labels: observation {key} is labelled twice")
                merged[key] = {
                    **entry,
                    "repository": document["repository"],
                    "commit": document["commit"],
                }
    return merged


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def label_metrics(
    observations: Sequence[Mapping[str, Any]],
    labels: Mapping[str, Mapping[str, Any]],
    key: str,
    repository_count: int,
) -> dict[str, dict[str, Any]]:
    """Per value of `key`: count, labelled, TP, FP, out of scope, unlabeled and FP rate."""
    rows: dict[str, dict[str, Any]] = {}
    for item in observations:
        name = str(item.get(key, ""))
        row = rows.setdefault(
            name,
            {
                "observations": 0,
                "labelled": 0,
                "true_positive": 0,
                "false_positive": 0,
                "out_of_scope": 0,
                "unlabeled": 0,
                "confirmed": 0,
            },
        )
        row["observations"] += 1
        label = labels.get(item["id"])
        if label is None:
            row["unlabeled"] += 1
            continue
        row["labelled"] += 1
        row["confirmed"] += label.get("status") == "confirmed"
        verdict = label["verdict"]
        row[verdict.replace("-", "_")] += 1
    for row in rows.values():
        judged = row["true_positive"] + row["false_positive"]
        row["false_positive_rate"] = _rate(row["false_positive"], judged)
        row["precision"] = _rate(row["true_positive"], judged)
        row["false_positives_per_repository"] = (
            round(row["false_positive"] / repository_count, 4) if repository_count else None
        )
    return {name: rows[name] for name in sorted(rows)}


def build_summary(
    manifest: list[dict[str, str]], out: Path
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run = _read_json(out / "run.json")
    if not isinstance(run, dict) or run.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError("run.json: schema_version must be 1")
    by_id = {record["id"]: record for record in run.get("repositories") or []}
    repositories: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for repo in manifest:
        record = by_id.get(repo["id"])
        row: dict[str, Any] = {"id": repo["id"], "group": repo["group"], "commit": repo["commit"]}
        if record is None or "scan" not in record:
            row["error"] = (record or {}).get("error", "not scanned")
            repositories.append(row)
            continue
        inventory_path = out / f"{repo['id']}.json"
        inventory = _read_json(inventory_path) if inventory_path.exists() else {}
        found = collect_observations(repo["id"], inventory, record.get("tree_prefix", ""))
        observations.extend(found)
        public = [item for item in found if not is_private(item)]
        risk_path = out / f"{repo['id']}.risk.json"
        risk = _read_json(risk_path) if risk_path.exists() else {}
        metadata = inventory.get("metadata") or {}
        completeness = metadata.get("completeness") or {}
        row.update(
            {
                "exit_code": record["scan"]["exit_code"],
                "timed_out": record["scan"]["timed_out"],
                "seconds": record["scan"]["seconds"],
                "max_rss_kib": record["scan"]["max_rss_kib"],
                "gate": record.get("gate", "unknown"),
                "gate_reasons": record.get("gate_reasons", []),
                "score": risk.get("overall_score"),
                "risk_level": risk.get("risk_level"),
                "spec_version": metadata.get("spec_version"),
                "components": dict(
                    sorted(
                        Counter(
                            item["component_type"] for item in found if item["kind"] == "component"
                        ).items()
                    )
                ),
                "findings": _severity_table(public),
                "gaps": sum(item["kind"] == "gap" for item in found),
                "complete_coverage": all(
                    status == "complete"
                    for status in (completeness.get("scanner_status") or {"": ""}).values()
                )
                and not completeness.get("scan_failures")
                and not completeness.get("surfaces_excluded"),
            }
        )
        repositories.append(row)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": run.get("tool_version"),
        "source": run.get("source"),
        "repositories": repositories,
    }
    return summary, observations


def _gate_counts(repositories: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get("gate", "error")) for row in repositories).items()))


def compare(
    summary: Mapping[str, Any],
    observations: Sequence[Mapping[str, Any]],
    credential_counts: Mapping[str, Mapping[str, int]],
    baseline_dir: Path,
) -> dict[str, Any]:
    base_summary = _read_json(baseline_dir / "summary.json")
    base_observations = _read_json(baseline_dir / "observations.json")
    base_public = {item["id"]: item for item in base_observations.get("observations") or []}
    current_public = {item["id"]: item for item in observations if not is_private(item)}
    new = sorted(set(current_public) - set(base_public))
    removed = sorted(set(base_public) - set(current_public))

    def tally(ids: Iterable[str], source: Mapping[str, Mapping[str, Any]]) -> dict[str, int]:
        counter: Counter[str] = Counter()
        for key in ids:
            item = source[key]
            label = item.get("category") or item.get("component_type") or ""
            counter[f"{item['kind']}:{label}" if label else item["kind"]] += 1
        return dict(sorted(counter.items()))

    base_rows = {row["id"]: row for row in base_summary.get("repositories") or []}
    flips: list[dict[str, Any]] = []
    repositories: dict[str, dict[str, Any]] = {}
    for row in summary["repositories"]:
        before = base_rows.get(row["id"])
        if before is None or "error" in row or "error" in before:
            continue
        if before.get("gate") != row.get("gate"):
            flips.append(
                {
                    "repository": row["id"],
                    "before": before.get("gate"),
                    "after": row.get("gate"),
                    "reasons_before": before.get("gate_reasons", []),
                    "reasons_after": row.get("gate_reasons", []),
                }
            )
        score_delta = None
        if isinstance(row.get("score"), (int, float)) and isinstance(
            before.get("score"), (int, float)
        ):
            score_delta = round(row["score"] - before["score"], 3)
        repositories[row["id"]] = {
            "score_delta": score_delta,
            "time_ratio": _rate(int(row["seconds"] * 1000), int(before["seconds"] * 1000)),
            "rss_ratio": _rate(row["max_rss_kib"], before["max_rss_kib"]),
            "seconds_before": before["seconds"],
            "max_rss_kib_before": before["max_rss_kib"],
            "new_observations": sum(current_public[key]["repository"] == row["id"] for key in new),
            "new_gaps": sum(
                current_public[key]["repository"] == row["id"]
                and current_public[key]["kind"] == "gap"
                for key in new
            ),
            "complete_coverage_before": bool(before.get("complete_coverage")),
        }
    base_credentials = base_observations.get("credential_counts") or {}
    credential_delta: dict[str, dict[str, int]] = {}
    for category in sorted(set(base_credentials) | set(credential_counts)):
        severities = set(base_credentials.get(category, {})) | set(
            credential_counts.get(category, {})
        )
        credential_delta[category] = {
            severity: credential_counts.get(category, {}).get(severity, 0)
            - base_credentials.get(category, {}).get(severity, 0)
            for severity in sorted(severities)
        }
    return {
        "baseline_tool_version": base_summary.get("tool_version"),
        "baseline_source": base_summary.get("source"),
        "new_observations": tally(new, current_public),
        "removed_observations": tally(removed, base_public),
        "new_observation_ids": new,
        "removed_observation_ids": removed,
        "gate_flips": flips,
        "repositories": repositories,
        "credential_count_delta": credential_delta,
    }


DEFAULT_COST = {"max_time_ratio": 2.0, "max_rss_ratio": 2.0, "time_floor_seconds": 5.0}


def parse_budgets(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError("budgets: schema_version must be 1")
    categories = document.get("categories", {})
    if not isinstance(categories, dict):
        raise HarnessError("budgets: categories must be an object")
    for name, rule in categories.items():
        limit = rule.get("max_false_positives") if isinstance(rule, dict) else None
        if isinstance(limit, int) and limit >= 0:
            continue
        if isinstance(limit, dict) and all(
            key in SEVERITIES and isinstance(value, int) and value >= 0
            for key, value in limit.items()
        ):
            continue
        raise HarnessError(f"budgets: {name}: max_false_positives must be a count or by severity")
    precision = document.get("component_min_precision")
    if precision is not None and not (isinstance(precision, (int, float)) and 0 <= precision <= 1):
        raise HarnessError("budgets: component_min_precision must be between 0 and 1")
    return document


def check_budgets(
    budgets: Mapping[str, Any],
    summary: Mapping[str, Any],
    observations: Sequence[Mapping[str, Any]],
    labels: Mapping[str, Mapping[str, Any]],
    delta: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    """One result per budget: name, limit, actual, passed (None when it cannot be measured)."""
    results: list[dict[str, Any]] = []

    def add(name: str, limit: Any, actual: Any, passed: bool | None) -> None:
        results.append({"budget": name, "limit": limit, "actual": actual, "passed": passed})

    false_positives: dict[str, Counter[str]] = defaultdict(Counter)
    for item in observations:
        label = labels.get(item["id"])
        if item["kind"] == "finding" and label and label["verdict"] == "false-positive":
            false_positives[item["category"]][item["severity"]] += 1
    for category, rule in sorted((budgets.get("categories") or {}).items()):
        limit = rule["max_false_positives"]
        found = false_positives.get(category, Counter())
        if isinstance(limit, int):
            actual = sum(found.values())
            add(f"false positives: {category}", limit, actual, actual <= limit)
        else:
            for severity in SEVERITIES:
                if severity in limit:
                    actual = found.get(severity, 0)
                    add(
                        f"false positives: {category} {severity}",
                        limit[severity],
                        actual,
                        actual <= limit[severity],
                    )
    minimum = budgets.get("component_min_precision")
    if minimum is not None:
        components = [item for item in observations if item["kind"] == "component"]
        metrics = label_metrics(components, labels, "component_type", 1)
        for kind, row in metrics.items():
            if row["precision"] is not None:
                add(f"precision: {kind}", minimum, row["precision"], row["precision"] >= minimum)
    allowed_exits = budgets.get("exit_codes", [0])
    rows = summary["repositories"]
    bad = sorted(
        row["id"] for row in rows if "error" in row or row["exit_code"] not in allowed_exits
    )
    add("scan exit codes", allowed_exits, bad or "all allowed", not bad)
    negative_groups = set(budgets.get("negative_groups", ["negative"]))
    negatives = [row["id"] for row in rows if row["group"] in negative_groups]
    limit = budgets.get("negative_max_new_observations", 0)
    if delta is not None:
        actual = sum(
            delta["repositories"].get(repo, {}).get("new_observations", 0) for repo in negatives
        )
    else:
        actual = sum(
            item["kind"] == "finding" and item["repository"] in negatives for item in observations
        )
    add("negative repositories: new observations", limit, actual, actual <= limit)
    if delta is None:
        add("coverage: new gaps on complete-coverage repositories", 0, "no baseline", None)
        cost = {**DEFAULT_COST, **(budgets.get("cost") or {})}
        add("cost: wall time", cost["max_time_ratio"], "no baseline", None)
        add("cost: peak RSS", cost["max_rss_ratio"], "no baseline", None)
        return results
    gaps = sorted(
        repo
        for repo, row in delta["repositories"].items()
        if row["complete_coverage_before"] and row["new_gaps"]
    )
    add("coverage: new gaps on complete-coverage repositories", 0, gaps or 0, not gaps)
    cost = {**DEFAULT_COST, **(budgets.get("cost") or {})}
    slow: list[str] = []
    heavy: list[str] = []
    current = {row["id"]: row for row in rows if "error" not in row}
    for repo, row in delta["repositories"].items():
        seconds = current[repo]["seconds"]
        if (
            seconds > cost["time_floor_seconds"]
            and seconds > cost["max_time_ratio"] * row["seconds_before"]
        ):
            slow.append(repo)
        if current[repo]["max_rss_kib"] > cost["max_rss_ratio"] * row["max_rss_kib_before"]:
            heavy.append(repo)
    add("cost: wall time", cost["max_time_ratio"], slow or "within", not slow)
    add("cost: peak RSS", cost["max_rss_ratio"], heavy or "within", not heavy)
    return results


def _cell(value: Any) -> str:
    if value is None:
        return "–"
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, (list, dict)):
        value = json.dumps(value, sort_keys=True)
    return CONTROL_RE.sub("?", str(value)).replace("|", "\\|")


def _table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    body = ["| " + " | ".join(_cell(value) for value in row) + " |" for row in rows]
    if not body:
        return ["None."]
    return ["| " + " | ".join(headers) + " |", "|" + " --- |" * len(headers), *body]


METRIC_HEADERS = (
    "Observations",
    "Labelled",
    "TP",
    "FP",
    "Out of scope",
    "Unlabeled",
    "FP rate",
    "FP per repository",
    "Confirmed",
)
METRIC_KEYS = (
    "observations",
    "labelled",
    "true_positive",
    "false_positive",
    "out_of_scope",
    "unlabeled",
    "false_positive_rate",
    "false_positives_per_repository",
    "confirmed",
)


def render_results(summary: Mapping[str, Any]) -> str:
    """RESULTS.md from a summary.json document, so the committed pair can be checked."""
    report = summary
    lines = [
        "# Real-repository results",
        "",
        "Generated by `benchmarks/realrepos/harness.py report`; do not edit by hand. False-positive "
        "calibration on pinned public repositories, not a field efficacy estimate. Credential "
        "categories are reported as counts only.",
        "",
        f"- Nexus SymBiote: `{_cell(summary.get('tool_version'))}` at "
        f"`{_cell((summary.get('source') or {}).get('commit'))}`",
        f"- Repositories: {len(summary['repositories'])}; gates: "
        + ", ".join(f"{name} {count}" for name, count in summary["gates"].items()),
        "",
        "## Repositories",
        "",
    ]
    delta = report.get("delta")
    per_repo = (delta or {}).get("repositories", {})
    lines += _table(
        (
            "Repository",
            "Group",
            "Commit",
            "Exit",
            "Gate",
            "Score",
            "Components",
            "Findings",
            "Gaps",
            "Seconds",
            "Peak RSS MiB",
            "Score delta",
            "Time ratio",
            "RSS ratio",
        ),
        (
            (
                row["id"],
                row["group"],
                row["commit"][:8],
                row.get("exit_code", row.get("error")),
                row.get("gate"),
                row.get("score"),
                sum((row.get("components") or {}).values()),
                sum(sum(v.values()) for v in (row.get("findings") or {}).values()),
                row.get("gaps"),
                row.get("seconds"),
                (row["max_rss_kib"] // 1024) if "max_rss_kib" in row else None,
                per_repo.get(row["id"], {}).get("score_delta"),
                per_repo.get(row["id"], {}).get("time_ratio"),
                per_repo.get(row["id"], {}).get("rss_ratio"),
            )
            for row in summary["repositories"]
        ),
    )
    lines += ["", "## Findings by category and severity", ""]
    totals = report["finding_totals"]
    lines += _table(
        ("Category", *SEVERITIES, "Counts only"),
        (
            (
                category,
                *(totals[category].get(severity, 0) for severity in SEVERITIES),
                "yes" if is_credential_category(category) else "",
            )
            for category in totals
        ),
    )
    lines += ["", "## Labels by finding category", ""]
    lines += _table(
        ("Category", *METRIC_HEADERS),
        (
            (name, *(row[key] for key in METRIC_KEYS))
            for name, row in report["finding_metrics"].items()
        ),
    )
    lines += ["", "## Labels by component type", ""]
    lines += _table(
        ("Component type", *METRIC_HEADERS[:6], "Precision", "Confirmed"),
        (
            (name, *(row[key] for key in METRIC_KEYS[:6]), row["precision"], row["confirmed"])
            for name, row in report["component_metrics"].items()
        ),
    )
    lines += ["", "## Delta against the baseline", ""]
    if delta is None:
        lines.append("No baseline was given.")
    else:
        lines.append(
            f"Baseline: `{_cell(delta.get('baseline_tool_version'))}` at "
            f"`{_cell((delta.get('baseline_source') or {}).get('commit'))}`."
        )
        lines += ["", "New observations:", ""]
        lines += _table(("Kind", "Count"), delta["new_observations"].items())
        lines += ["", "Removed observations:", ""]
        lines += _table(("Kind", "Count"), delta["removed_observations"].items())
        lines += ["", "Gate flips:", ""]
        lines += _table(
            ("Repository", "Before", "After", "Reasons after"),
            (
                (flip["repository"], flip["before"], flip["after"], flip["reasons_after"])
                for flip in delta["gate_flips"]
            ),
        )
        lines += ["", "Credential count delta:", ""]
        lines += _table(("Category", "Delta by severity"), delta["credential_count_delta"].items())
    lines += ["", "## Budgets", ""]
    lines += _table(
        ("Budget", "Limit", "Actual", "Result"),
        (
            (
                item["budget"],
                item["limit"],
                item["actual"],
                {True: "pass", False: "FAIL", None: "not measured"}[item["passed"]],
            )
            for item in report["budgets"]
        ),
    )
    return "\n".join(lines) + "\n"


def report(
    manifest: list[dict[str, str]],
    out: Path,
    results: Path,
    *,
    labels: Sequence[Path] = (),
    private_labels: Sequence[Path] = (),
    baseline: Path | None = None,
    budgets: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    summary, observations = build_summary(manifest, out)
    public_labels = load_labels(labels)
    secret_labels = load_labels(private_labels)
    private_ids = {item["id"] for item in observations if is_private(item)}
    leaked = sorted(set(public_labels) & private_ids)
    if leaked:
        raise HarnessError(
            "labels: credential observations must be labelled under --private-labels"
        )
    overlap = set(public_labels) & set(secret_labels)
    if overlap:
        raise HarnessError("labels: an observation is labelled both publicly and privately")
    all_labels = {**public_labels, **secret_labels}
    repository_count = sum("error" not in row for row in summary["repositories"])
    findings = [item for item in observations if item["kind"] == "finding"]
    components = [item for item in observations if item["kind"] == "component"]
    public = [item for item in observations if not is_private(item)]
    private = [item for item in observations if is_private(item)]
    credential_counts = _severity_table(private)
    summary["gates"] = _gate_counts(summary["repositories"])
    summary["finding_totals"] = _severity_table(findings)
    summary["component_totals"] = dict(
        sorted(Counter(item["component_type"] for item in components).items())
    )
    delta = None
    if baseline is not None:
        delta = compare(summary, observations, credential_counts, baseline)
    budget_results = check_budgets(budgets or {}, summary, observations, all_labels, delta)
    summary_out = {
        **summary,
        "finding_metrics": label_metrics(findings, all_labels, "category", repository_count),
        "component_metrics": label_metrics(
            components, all_labels, "component_type", repository_count
        ),
        "budgets": budget_results,
        "delta": None
        if delta is None
        else {
            key: value
            for key, value in delta.items()
            if key not in {"new_observation_ids", "removed_observation_ids"}
        },
    }
    _write_json(results / "summary.json", summary_out)
    _write_json(
        results / "observations.json",
        {
            "schema_version": SCHEMA_VERSION,
            "observations": public,
            "credential_counts": credential_counts,
        },
    )
    (results / "RESULTS.md").write_text(render_results(summary_out), encoding="utf-8")
    _write_json(
        out / "private" / "credential-observations.json",
        {"schema_version": SCHEMA_VERSION, "observations": private},
    )
    if delta is not None:
        _write_json(
            out / "private" / "delta-ids.json",
            {
                "new": delta["new_observation_ids"],
                "removed": delta["removed_observation_ids"],
            },
        )
    return summary_out


def label_template(
    manifest: list[dict[str, str]],
    observations: Sequence[Mapping[str, Any]],
    labels_dir: Path,
) -> int:
    """Add an unlabeled entry for every observation that has none; returns how many it added."""
    commits = {repo["id"]: repo["commit"] for repo in manifest}
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in observations:
        grouped[item["repository"]].append(item)
    added = 0
    labels_dir.mkdir(parents=True, exist_ok=True)
    for repo_id in sorted(grouped):
        if repo_id not in commits:
            raise HarnessError(f"observations name an unknown repository {repo_id}")
        path = labels_dir / f"{repo_id}.json"
        if path.exists():
            document = parse_labels(_read_json(path), repo_id)
        else:
            document = {
                "schema_version": SCHEMA_VERSION,
                "repository": repo_id,
                "commit": commits[repo_id],
                "labels": [],
            }
        present = {entry["observation"] for entry in document["labels"]}
        for item in grouped[repo_id]:
            if item["id"] in present:
                continue
            context = {
                key: item[key]
                for key in ("kind", "bom_ref", "component_type", "category", "severity", "detail")
                if key in item
            }
            document["labels"].append(
                {
                    "observation": item["id"],
                    "verdict": None,
                    "status": "proposed",
                    "reviewer": "",
                    "date": "",
                    "note": "",
                    "context": context,
                }
            )
            added += 1
        _write_json(path, document)
    return added


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=HERE / "manifest.json")
    commands = parser.add_subparsers(dest="command", required=True)

    fetch_parser = commands.add_parser("fetch", help="shallow-fetch each pinned commit (network)")
    fetch_parser.add_argument("--dest", type=Path, required=True)
    fetch_parser.add_argument("--only", action="append")

    scan_parser = commands.add_parser("scan", help="scan fetched trees offline")
    scan_parser.add_argument("--trees", type=Path, required=True)
    scan_parser.add_argument("--out", type=Path, required=True)
    scan_parser.add_argument("--only", action="append")
    scan_parser.add_argument("--python", default=sys.executable)
    scan_parser.add_argument("--timeout", type=float, default=SCAN_TIMEOUT)
    scan_parser.add_argument("--sarif", action="store_true", help="also write SARIF per tree")

    report_parser = commands.add_parser("report", help="aggregate a scan into results")
    report_parser.add_argument("--out", type=Path, required=True, help="the scan directory")
    report_parser.add_argument("--results", type=Path, required=True)
    report_parser.add_argument("--labels", type=Path, action="append")
    report_parser.add_argument("--private-labels", type=Path, action="append", default=[])
    report_parser.add_argument("--baseline", type=Path)
    report_parser.add_argument("--budgets", type=Path, default=HERE / "budgets.json")
    report_parser.add_argument(
        "--enforce-budgets", action="store_true", help="exit 1 when a budget fails"
    )

    template_parser = commands.add_parser("label-template", help="add unlabeled label entries")
    template_parser.add_argument("--observations", type=Path, required=True)
    template_parser.add_argument("--labels", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        if args.command == "fetch":
            problems = fetch(_select(manifest, args.only), args.dest)
            for problem in problems:
                print(problem, file=sys.stderr)
            return 1 if problems else 0
        if args.command == "scan":
            run = scan(
                _select(manifest, args.only),
                args.trees,
                args.out,
                python=args.python,
                timeout=args.timeout,
                sarif=args.sarif,
            )
            return 1 if any("error" in record for record in run["repositories"]) else 0
        if args.command == "report":
            labels = args.labels if args.labels is not None else [HERE / "labels"]
            budgets = parse_budgets(_read_json(args.budgets)) if args.budgets else None
            document = report(
                manifest,
                args.out,
                args.results,
                labels=labels,
                private_labels=args.private_labels,
                baseline=args.baseline,
                budgets=budgets,
            )
            failed = [item["budget"] for item in document["budgets"] if item["passed"] is False]
            for name in failed:
                print(f"budget failed: {name}", file=sys.stderr)
            return 1 if failed and args.enforce_budgets else 0
        observations = _read_json(args.observations).get("observations") or []
        added = label_template(manifest, observations, args.labels)
        print(f"added {added} unlabeled entries")
        return 0
    except HarnessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
