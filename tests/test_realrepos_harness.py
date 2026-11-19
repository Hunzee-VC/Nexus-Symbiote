"""The real-repository precision harness, offline: manifest, ids, report, labels and budgets."""

from __future__ import annotations

import copy
import functools
import hashlib
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.support import ROOT

BENCH = ROOT / "benchmarks" / "realrepos"
COMMIT_A = "a" * 40
COMMIT_B = "b" * 40
COMMIT_C = "c" * 40
SENTINEL_DETAIL = "Literal credential sk-test-realrepos-sentinel in config/settings.py"


@functools.cache
def _harness() -> ModuleType:
    name = "realrepos_harness"
    spec = importlib.util.spec_from_file_location(name, BENCH / "harness.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _repo(repo_id: str, commit: str, group: str = "agents") -> dict[str, str]:
    return {
        "id": repo_id,
        "url": f"https://github.com/example/{repo_id}",
        "ref": "main",
        "commit": commit,
        "tree": "",
        "group": group,
        "license": "MIT",
        "rationale": "fixture",
    }


def _manifest(*repos: dict[str, str]) -> dict[str, Any]:
    return {"schema_version": 1, "name": "fixture", "repositories": list(repos)}


def _fixture_manifest() -> list[dict[str, str]]:
    document = _manifest(
        _repo("alpha", COMMIT_A),
        _repo("beta", COMMIT_B, "mcp-servers"),
        _repo("neg", COMMIT_C, "negative"),
    )
    parsed: list[dict[str, str]] = _harness().parse_manifest(document)
    return parsed


def _inventory(components: list[dict[str, Any]], gaps: list[str] | None = None) -> dict[str, Any]:
    return {
        "metadata": {
            "spec_version": "1.2.0",
            "completeness": {
                "scan_failures": [],
                "surfaces_excluded": gaps or [],
                "scanner_status": {"mcp": "complete", "model": "complete"},
            },
        },
        "components": components,
    }


def _component(bom_ref: str, kind: str, risks: list[tuple[str, str, str]]) -> dict[str, Any]:
    return {
        "bom_ref": bom_ref,
        "component_type": kind,
        "risks": [
            {"category": category, "severity": severity, "detail": detail}
            for category, severity, detail in risks
        ],
    }


def _write_scan(
    out: Path,
    inventories: dict[str, dict[str, Any]],
    *,
    gates: dict[str, str] | None = None,
    seconds: dict[str, float] | None = None,
    rss: dict[str, int] | None = None,
    exit_codes: dict[str, int] | None = None,
) -> None:
    out.mkdir(parents=True, exist_ok=True)
    records = []
    for repo_id, inventory in inventories.items():
        (out / f"{repo_id}.json").write_text(json.dumps(inventory), encoding="utf-8")
        (out / f"{repo_id}.risk.json").write_text(
            json.dumps({"overall_score": 12.0, "risk_level": "medium"}), encoding="utf-8"
        )
        records.append(
            {
                "id": repo_id,
                "commit": "0" * 40,
                "scan": {
                    "exit_code": (exit_codes or {}).get(repo_id, 0),
                    "seconds": (seconds or {}).get(repo_id, 1.0),
                    "max_rss_kib": (rss or {}).get(repo_id, 70000),
                    "timed_out": False,
                },
                "gate": (gates or {}).get(repo_id, "passed"),
                "gate_reasons": [],
            }
        )
    run = {"schema_version": 1, "tool_version": "fixture", "source": {}, "repositories": records}
    (out / "run.json").write_text(json.dumps(run), encoding="utf-8")


def _base_inventories() -> dict[str, dict[str, Any]]:
    return {
        "alpha": _inventory(
            [
                _component(
                    "mcp:alpha",
                    "mcp-server",
                    [
                        ("version_pinning", "high", "unpinned"),
                        ("hidden_markup", "low", "comment"),
                    ],
                ),
                _component(
                    "model:alpha", "model", [("credential_exposure", "high", SENTINEL_DETAIL)]
                ),
            ]
        ),
        "beta": _inventory([_component("mcp:beta", "mcp-server", [])], ["src/x.py: dynamic"]),
        "neg": _inventory([_component("agent:neg", "agent", [])]),
    }


def _budgets(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": 1,
        "categories": {
            "credential_exposure": {"max_false_positives": 0},
            "version_pinning": {"max_false_positives": {"high": 0, "medium": 2}},
        },
        "component_min_precision": 0.95,
        "exit_codes": [0],
        "negative_groups": ["negative"],
        "negative_max_new_observations": 0,
    }
    document.update(overrides)
    parsed: dict[str, Any] = _harness().parse_budgets(document)
    return parsed


def _budget(results: list[dict[str, Any]], name: str) -> dict[str, Any]:
    matches = [item for item in results if item["budget"] == name]
    assert len(matches) == 1, name
    return matches[0]


def _observation(observations: list[dict[str, Any]], **fields: Any) -> dict[str, Any]:
    matches = [item for item in observations if all(item.get(k) == v for k, v in fields.items())]
    assert len(matches) == 1, fields
    return matches[0]


def _labels(directory: Path, repo_id: str, commit: str, entries: list[dict[str, Any]]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    document = {"schema_version": 1, "repository": repo_id, "commit": commit, "labels": entries}
    (directory / f"{repo_id}.json").write_text(json.dumps(document), encoding="utf-8")


def _label(observation: str, verdict: str | None, status: str = "proposed") -> dict[str, Any]:
    return {
        "observation": observation,
        "verdict": verdict,
        "status": status,
        "reviewer": "fixture",
        "date": "2026-11-19",
        "note": "",
    }


# Manifest


def test_committed_manifest_pins_the_24_repositories() -> None:
    manifest = _harness().load_manifest(BENCH / "manifest.json")
    assert len(manifest) == 24
    assert {repo["group"] for repo in manifest} >= {"negative", "mcp-servers", "skills"}
    negatives = sorted(repo["id"] for repo in manifest if repo["group"] == "negative")
    assert negatives == ["pallets_flask", "psf_requests"]
    assert all(len(repo["tree"]) == 40 for repo in manifest)


@pytest.mark.parametrize("bad_id", [".", "..", "", "-x", "a/b", "a b", "x" * 101, "a\nb"])
def test_manifest_refuses_bad_ids(bad_id: str) -> None:
    with pytest.raises(_harness().HarnessError, match="invalid id"):
        _harness().parse_manifest(_manifest(_repo(bad_id, COMMIT_A)))


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/example/repo",
        "https://gitlab.com/example/repo",
        "https://github.com/example",
        "https://github.com/example/repo.git",
        "https://github.com/example/repo/tree/main",
        "ssh://git@github.com/example/repo",
        "https://github.com/example/..",
    ],
)
def test_manifest_refuses_urls_that_are_not_github_https(url: str) -> None:
    repo = _repo("repo", COMMIT_A)
    repo["url"] = url
    with pytest.raises(_harness().HarnessError, match="url"):
        _harness().parse_manifest(_manifest(repo))


@pytest.mark.parametrize("commit", ["abc1234", "A" * 40, "g" * 40, "a" * 41, ""])
def test_manifest_refuses_short_or_malformed_commits(commit: str) -> None:
    with pytest.raises(_harness().HarnessError, match="commit"):
        _harness().parse_manifest(_manifest(_repo("repo", commit)))


def test_manifest_refuses_duplicates_extra_keys_and_other_schemas() -> None:
    harness = _harness()
    with pytest.raises(harness.HarnessError, match="duplicate id"):
        harness.parse_manifest(_manifest(_repo("a", COMMIT_A), _repo("a", COMMIT_B)))
    twin = _repo("b", COMMIT_B)
    twin["url"] = "https://github.com/EXAMPLE/A"
    with pytest.raises(harness.HarnessError, match="duplicate url"):
        harness.parse_manifest(_manifest(_repo("a", COMMIT_A), twin))
    extra = {**_repo("a", COMMIT_A), "post_fetch": "make"}
    with pytest.raises(harness.HarnessError, match="keys"):
        harness.parse_manifest(_manifest(extra))
    with pytest.raises(harness.HarnessError, match="schema_version"):
        harness.parse_manifest({**_manifest(_repo("a", COMMIT_A)), "schema_version": 2})
    with pytest.raises(harness.HarnessError, match="non-empty"):
        harness.parse_manifest(_manifest())


# Fetch and scan command lines


def test_fetch_uses_the_hardened_git_command_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _harness()
    monkeypatch.setenv("GIT_DIR", "/elsewhere")
    monkeypatch.setenv("GIT_SSH_COMMAND", "evil")
    calls: list[tuple[list[str], dict[str, str]]] = []
    repo = {**_repo("alpha", COMMIT_A), "tree": COMMIT_B}

    def runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((argv, kwargs["env"]))
        assert kwargs.get("stdin") is subprocess.DEVNULL
        if "checkout" in argv:
            (tmp_path / "alpha" / ".git").mkdir(parents=True)
            (tmp_path / "alpha" / ".git" / "HEAD").write_text(COMMIT_A + "\n")
        return subprocess.CompletedProcess(argv, 0, stdout=COMMIT_B + "\n", stderr="")

    assert harness.fetch([repo], tmp_path, runner=runner) == []
    argvs = [argv for argv, _ in calls]
    assert argvs[0] == ["git", "init", "--quiet", str(tmp_path / "alpha")]
    fetch_argv = argvs[1]
    for flag in (
        "core.hooksPath=/dev/null",
        "protocol.allow=never",
        "protocol.https.allow=always",
        "transfer.fsckObjects=true",
        "core.fsmonitor=false",
    ):
        assert fetch_argv[fetch_argv.index(flag) - 1] == "-c"
    tail = fetch_argv[fetch_argv.index("fetch") :]
    assert tail == [
        "fetch",
        "--quiet",
        "--depth",
        "1",
        "--no-tags",
        "--no-recurse-submodules",
        repo["url"],
        COMMIT_A,
    ]
    assert argvs[2][-3:] == ["--quiet", "--detach", "FETCH_HEAD"]
    assert "core.hooksPath=/dev/null" in argvs[2]
    assert argvs[3][-2:] == ["rev-parse", "HEAD^{tree}"]
    for _, env in calls:
        assert env["GIT_LFS_SKIP_SMUDGE"] == "1"
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
        assert "GIT_DIR" not in env and "GIT_SSH_COMMAND" not in env


def test_fetch_reports_a_tree_or_commit_mismatch_and_a_foreign_checkout(tmp_path: Path) -> None:
    harness = _harness()
    repo = {**_repo("alpha", COMMIT_A), "tree": COMMIT_C}

    def runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "checkout" in argv:
            (tmp_path / "alpha" / ".git").mkdir(parents=True)
            (tmp_path / "alpha" / ".git" / "HEAD").write_text(COMMIT_A)
        return subprocess.CompletedProcess(argv, 0, stdout=COMMIT_B, stderr="")

    assert harness.fetch([repo], tmp_path, runner=runner) == [
        "alpha: tree hash differs from the manifest"
    ]
    other = {**_repo("alpha", COMMIT_B)}
    problems = harness.fetch([other], tmp_path, runner=runner)
    assert problems == [f"alpha: {tmp_path / 'alpha'} exists at another commit"]


def test_fetch_checks_the_tree_hash_of_a_present_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _harness()
    (tmp_path / "trees" / "alpha" / ".git").mkdir(parents=True)
    (tmp_path / "trees" / "alpha" / ".git" / "HEAD").write_text(COMMIT_A)
    calls: list[list[str]] = []

    def runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=COMMIT_B + "\n", stderr="")

    monkeypatch.chdir(tmp_path)
    present = {**_repo("alpha", COMMIT_A), "tree": COMMIT_B}
    assert harness.fetch([present], Path("trees"), runner=runner) == []
    assert calls[-1][:3] == ["git", "-C", str(tmp_path / "trees" / "alpha")]
    assert "core.hooksPath=/dev/null" in calls[-1] and calls[-1][-1] == "HEAD^{tree}"
    assert not [argv for argv in calls if "fetch" in argv or "checkout" in argv]
    swapped = {**present, "tree": COMMIT_C}
    assert harness.fetch([swapped], Path("trees"), runner=runner) == [
        "alpha: tree hash differs from the manifest"
    ]


def test_read_head_reads_refs_and_packed_refs_without_git(tmp_path: Path) -> None:
    harness = _harness()
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (git / "packed-refs").write_text(f"# pack-refs\n{COMMIT_B} refs/heads/main\n")
    assert harness.read_head(tmp_path) == COMMIT_B
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "refs" / "heads" / "main").write_text(COMMIT_A + "\n")
    assert harness.read_head(tmp_path) == COMMIT_A
    (tmp_path / "outside").write_text(COMMIT_C + "\n")
    assert (git / "refs" / ".." / ".." / "outside").read_text().strip() == COMMIT_C
    (git / "HEAD").write_text("ref: refs/../../outside\n")
    assert harness.read_head(tmp_path) is None
    assert harness.read_head(tmp_path / "missing") is None


def test_scan_runs_offline_in_an_isolated_interpreter_with_a_fresh_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _harness()
    monkeypatch.setenv("NEXUS_SYMBIOTE_MODE", "live")
    monkeypatch.setenv("PYTHONPATH", "/planted")
    trees = tmp_path / "trees"
    for repo_id, commit in (("alpha", COMMIT_A), ("beta", COMMIT_C)):
        (trees / repo_id / ".git").mkdir(parents=True)
        (trees / repo_id / ".git" / "HEAD").write_text(commit)
    calls: list[tuple[list[str], dict[str, str], Path]] = []

    def measure(argv: list[str], *, env: dict[str, str], stdout: Path, stderr: Path, **kw: Any):
        calls.append((argv, env, kw["cwd"]))
        if "--version" in argv:
            stdout.write_text("nexus-symbiote, version 9")
        elif "scan" in argv:
            Path(argv[argv.index("-o") + 1]).write_text(json.dumps(_inventory([])))
            stderr.write_text("Scanning\nScan gate failed (report only: exit status 0)\n  - x\n")
        else:
            stdout.write_text("{}")
        stderr.touch()
        return harness.Measured(0, 1.5, 70000, False)

    run = harness.scan(
        [_repo("alpha", COMMIT_A), _repo("beta", COMMIT_B)],
        trees,
        tmp_path / "out",
        python="/py",
        measure=measure,
    )
    alpha, beta = run["repositories"]
    assert alpha["gate"] == "failed" and alpha["gate_reasons"] == ["x"]
    assert beta["error"] == "tree missing or not at the pinned commit"
    assert run["tool_version"] == "nexus-symbiote, version 9"
    scan_argv = next(argv for argv, _, _ in calls if "scan" in argv)
    assert scan_argv[:5] == ["/py", "-I", "-m", "nexus_symbiote", "scan"]
    assert "--no-project-policy" in scan_argv and "--report-only" in scan_argv
    assert scan_argv[scan_argv.index("-f") + 1] == "json"
    assert "--check" not in scan_argv
    for argv, env, cwd in calls:
        assert "NEXUS_SYMBIOTE_MODE" not in env and "PYTHONPATH" not in env
        assert env["SOURCE_DATE_EPOCH"] == "0"
        assert Path(env["HOME"]) == cwd and not cwd.is_relative_to(trees)
        assert "beta" not in " ".join(argv)


def test_scan_resolves_relative_trees_and_output_before_changing_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _harness()
    (tmp_path / "trees" / "alpha" / ".git").mkdir(parents=True)
    (tmp_path / "trees" / "alpha" / ".git" / "HEAD").write_text(COMMIT_A)
    scans: list[tuple[list[str], Path]] = []

    def measure(argv: list[str], *, env: dict[str, str], stdout: Path, stderr: Path, **kw: Any):
        if "scan" in argv:
            scans.append((argv, kw["cwd"]))
            Path(argv[argv.index("-o") + 1]).write_text(json.dumps(_inventory([])))
        stdout.touch()
        stderr.touch()
        return harness.Measured(0, 1.0, 1, False)

    monkeypatch.chdir(tmp_path)
    run = harness.scan([_repo("alpha", COMMIT_A)], Path("trees"), Path("scan"), measure=measure)
    [(argv, cwd)] = scans
    assert cwd != tmp_path
    assert argv[argv.index("scan") + 1] == str(tmp_path / "trees" / "alpha")
    assert argv[argv.index("-o") + 1] == str(tmp_path / "scan" / "alpha.json")
    assert (tmp_path / "scan" / "alpha.json").is_file()
    assert harness.scan_succeeded(run["repositories"][0])


@pytest.mark.parametrize(
    ("record", "succeeded"),
    [
        ({"scan": {"exit_code": 0, "timed_out": False}}, True),
        ({"scan": {"exit_code": 2, "timed_out": False}}, False),
        ({"scan": {"exit_code": -9, "timed_out": True}}, False),
        ({"error": "tree missing or not at the pinned commit"}, False),
    ],
)
def test_main_scan_fails_on_a_failed_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, record: dict[str, Any], succeeded: bool
) -> None:
    harness = _harness()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_manifest(_repo("alpha", COMMIT_A))))
    run = {"repositories": [{"id": "alpha", **record}]}
    monkeypatch.setattr(harness, "scan", lambda *args, **kwargs: run)
    argv = ["--manifest", str(manifest), "scan", "--trees", "t", "--out", "o"]
    assert harness.main(argv) == (0 if succeeded else 1)


def test_run_measured_kills_the_process_group_on_timeout(tmp_path: Path) -> None:
    harness = _harness()
    marker = tmp_path / "survived"
    child = f"import time; time.sleep(1.5); open({str(marker)!r}, 'w').close()"
    script = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-I', '-c', {child!r}]); time.sleep(30)"
    )
    measured = harness.run_measured(
        [sys.executable, "-I", "-c", script],
        env={},
        stdout=tmp_path / "out.txt",
        stderr=tmp_path / "err.txt",
        cwd=tmp_path,
        timeout=0.3,
    )
    assert measured.timed_out and measured.exit_code < 0
    assert measured.seconds < 10
    time.sleep(3)
    assert not marker.exists()


def test_run_measured_records_exit_time_and_peak_rss(tmp_path: Path) -> None:
    harness = _harness()
    measured = harness.run_measured(
        [sys.executable, "-I", "-c", "import sys; print('ok'); sys.exit(3)"],
        env={},
        stdout=tmp_path / "out.txt",
        stderr=tmp_path / "err.txt",
        cwd=tmp_path,
        timeout=60,
    )
    assert measured.exit_code == 3 and not measured.timed_out
    assert measured.max_rss_kib > 0 and measured.seconds > 0
    assert (tmp_path / "out.txt").read_text().strip() == "ok"


def test_parse_gate_keeps_main_reasons_and_hides_credential_and_path_lines() -> None:
    text = "\n".join(
        [
            "Scanning /tmp/x",
            "Risk warning: score 60.0",
            "Scan gate failed (report only: exit status 0)",
            "  - collection coverage is unknown or incomplete",
            "  - finding at or above high: credential_exposure",
            "  - finding: [high] model:x credential_exposure: sk-...",
            "  - score: 60.0 (fail threshold 50)",
            "  - excluded: src/a.py:3 (unresolved receiver) (from mcp)",
            "  - collection: unreadable",
            "  - bad \x1b[31mescape",
        ]
    )
    verdict, reasons = _harness().parse_gate(text)
    assert verdict == "failed"
    assert reasons == [
        "collection coverage is unknown or incomplete",
        "[credential finding]",
        "bad ?[31mescape",
    ]
    assert _harness().parse_gate("Scan gate passed\n") == ("passed", [])
    assert _harness().parse_gate("Traceback") == ("unknown", [])


# Observations and ids


def test_observation_ids_are_stable_hashes_of_the_documented_fields() -> None:
    harness = _harness()
    payload = {"bom_ref": "mcp:a", "category": "c", "detail": "d", "repo": "alpha"}
    expected = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    assert harness.finding_id("alpha", "mcp:a", "c", "d") == expected
    assert harness.finding_id("beta", "mcp:a", "c", "d") != expected
    assert harness.component_id("alpha", "mcp:a", "tool") != harness.component_id(
        "alpha", "mcp:a", "model"
    )


def test_collect_observations_covers_findings_components_and_gaps() -> None:
    harness = _harness()
    inventory = _inventory(
        [
            _component(
                "mcp:x",
                "mcp-server",
                [
                    ("version_pinning", "high", "/scan/root/a.json \x1b[2J"),
                    ("version_pinning", "high", "/scan/root/a.json \x1b[2J"),
                ],
            )
        ],
        ["src/a.py: dynamic"],
    )
    inventory["metadata"]["completeness"]["scanner_status"]["rag"] = "partial"
    found = harness.collect_observations("alpha", inventory, "/scan/root")
    assert [item["kind"] for item in found] == ["component", "finding", "gap", "gap"]
    finding = _observation(found, kind="finding")
    assert finding["detail"] == "<tree>/a.json ?[2J"
    assert {item["detail"] for item in found if item["kind"] == "gap"} == {
        "collector rag: partial",
        "excluded: src/a.py: dynamic",
    }
    assert found == harness.collect_observations("alpha", copy.deepcopy(inventory), "/scan/root")


# Report


def test_report_publishes_counts_only_for_credential_categories(tmp_path: Path) -> None:
    harness = _harness()
    out, results = tmp_path / "out", tmp_path / "results"
    _write_scan(out, _base_inventories(), gates={"alpha": "failed"})
    summary = harness.report(_fixture_manifest(), out, results, budgets=_budgets())
    public_text = "".join(path.read_text() for path in results.iterdir())
    assert "sk-test-realrepos-sentinel" not in public_text
    observations = json.loads((results / "observations.json").read_text())
    assert observations["credential_counts"] == {"credential_exposure": {"high": 1}}
    assert not [
        item
        for item in observations["observations"]
        if "credential" in str(item.get("category", ""))
    ]
    alpha = next(row for row in summary["repositories"] if row["id"] == "alpha")
    assert alpha["findings"] == {"hidden_markup": {"low": 1}, "version_pinning": {"high": 1}}
    assert summary["finding_totals"]["credential_exposure"] == {"high": 1}
    private = json.loads((out / "private" / "credential-observations.json").read_text())
    assert [item["detail"] for item in private["observations"]] == [SENTINEL_DETAIL]
    assert summary["gates"] == {"failed": 1, "passed": 2}
    rendered = (results / "RESULTS.md").read_text()
    assert rendered == harness.render_results(json.loads((results / "summary.json").read_text()))
    assert "| credential_exposure | 0 | 1 | 0 | 0 | 0 | yes |" in rendered


def test_label_metrics_compute_the_false_positive_rate(tmp_path: Path) -> None:
    harness = _harness()
    out, results, labels = tmp_path / "out", tmp_path / "results", tmp_path / "labels"
    inventories = _base_inventories()
    inventories["alpha"]["components"][0]["risks"] += [
        {"category": "version_pinning", "severity": "high", "detail": f"second {n}"}
        for n in range(3)
    ]
    _write_scan(out, inventories)
    found = harness.collect_observations("alpha", inventories["alpha"])
    pinning = sorted(item["id"] for item in found if item.get("category") == "version_pinning")
    component = _observation(found, kind="component", bom_ref="mcp:alpha")["id"]
    _labels(
        labels,
        "alpha",
        COMMIT_A,
        [
            _label(pinning[0], "false-positive", "confirmed"),
            _label(pinning[1], "true-positive"),
            _label(pinning[2], "true-positive"),
            _label(pinning[3], "out-of-scope"),
            _label(component, "false-positive"),
        ],
    )
    summary = harness.report(_fixture_manifest(), out, results, labels=[labels], budgets=_budgets())
    row = summary["finding_metrics"]["version_pinning"]
    assert row["observations"] == 4 and row["labelled"] == 4 and row["unlabeled"] == 0
    assert (row["true_positive"], row["false_positive"], row["out_of_scope"]) == (2, 1, 1)
    assert row["false_positive_rate"] == pytest.approx(1 / 3, abs=1e-4)
    assert row["false_positives_per_repository"] == pytest.approx(1 / 3, abs=1e-4)
    assert row["confirmed"] == 1
    assert summary["component_metrics"]["mcp-server"]["precision"] == 0.0
    budgets = summary["budgets"]
    assert _budget(budgets, "false positives: version_pinning high")["passed"] is False
    assert _budget(budgets, "false positives: version_pinning medium")["passed"] is True
    assert _budget(budgets, "precision: mcp-server")["passed"] is False
    assert _budget(budgets, "false positives: credential_exposure")["passed"] is True
    assert _budget(budgets, "cost: wall time")["passed"] is None


def test_credential_observations_cannot_be_labelled_publicly(tmp_path: Path) -> None:
    harness = _harness()
    out, results = tmp_path / "out", tmp_path / "results"
    _write_scan(out, _base_inventories())
    found = harness.collect_observations("alpha", _base_inventories()["alpha"])
    secret = _observation(found, category="credential_exposure")["id"]
    public, private = tmp_path / "labels", tmp_path / "private-labels"
    _labels(public, "alpha", COMMIT_A, [_label(secret, "false-positive")])
    with pytest.raises(harness.HarnessError, match="private-labels"):
        harness.report(_fixture_manifest(), out, results, labels=[public])
    _labels(private, "alpha", COMMIT_A, [_label(secret, "false-positive")])
    summary = harness.report(
        _fixture_manifest(), out, results, private_labels=[private], budgets=_budgets()
    )
    result = _budget(summary["budgets"], "false positives: credential_exposure")
    assert result["actual"] == 1 and result["passed"] is False
    assert "alpha" not in json.dumps(summary["finding_metrics"])


@pytest.mark.parametrize(
    ("entry", "match"),
    [
        ({"verdict": "maybe"}, "verdict"),
        ({"status": "accepted"}, "status"),
        ({"status": "confirmed", "verdict": None}, "confirmed entry"),
        ({"observation": "XYZ"}, "observation id"),
        ({"note": 3}, "note"),
    ],
)
def test_labels_are_validated(entry: dict[str, Any], match: str) -> None:
    label = {**_label("0123456789abcdef", "true-positive"), **entry}
    document = {"schema_version": 1, "repository": "a", "commit": COMMIT_A, "labels": [label]}
    with pytest.raises(_harness().HarnessError, match=match):
        _harness().parse_labels(document)


def test_public_labels_refuse_credential_context_and_unlabelled_credential_entries(
    tmp_path: Path,
) -> None:
    harness = _harness()
    entry = {**_label("0123456789abcdef", None), "context": {"category": "credential_exposure"}}
    document = {"schema_version": 1, "repository": "a", "commit": COMMIT_A, "labels": [entry]}
    with pytest.raises(harness.HarnessError, match="private-labels"):
        harness.parse_labels(document)
    assert harness.parse_labels(document, private=True) is document

    out, results = tmp_path / "out", tmp_path / "results"
    _write_scan(out, _base_inventories())
    found = harness.collect_observations("alpha", _base_inventories()["alpha"])
    secret = _observation(found, category="credential_exposure")["id"]
    _labels(tmp_path / "labels", "alpha", COMMIT_A, [_label(secret, None)])
    with pytest.raises(harness.HarnessError, match="private-labels"):
        harness.report(_fixture_manifest(), out, results, labels=[tmp_path / "labels"])


def test_report_refuses_labels_for_another_commit_or_repository(tmp_path: Path) -> None:
    harness = _harness()
    out, results = tmp_path / "out", tmp_path / "results"
    _write_scan(out, _base_inventories())
    _labels(tmp_path / "stale", "alpha", COMMIT_B, [])
    with pytest.raises(harness.HarnessError, match="manifest commit"):
        harness.report(_fixture_manifest(), out, results, labels=[tmp_path / "stale"])
    _labels(tmp_path / "private", "gamma", COMMIT_A, [])
    with pytest.raises(harness.HarnessError, match="manifest commit"):
        harness.report(_fixture_manifest(), out, results, private_labels=[tmp_path / "private"])


def test_an_observation_cannot_be_labelled_publicly_and_privately(tmp_path: Path) -> None:
    harness = _harness()
    out, results = tmp_path / "out", tmp_path / "results"
    _write_scan(out, _base_inventories())
    found = harness.collect_observations("alpha", _base_inventories()["alpha"])
    pinning = _observation(found, category="version_pinning")["id"]
    _labels(tmp_path / "public", "alpha", COMMIT_A, [_label(pinning, "true-positive")])
    _labels(tmp_path / "private", "alpha", COMMIT_A, [_label(pinning, "false-positive")])
    with pytest.raises(harness.HarnessError, match="both publicly and privately"):
        harness.report(
            _fixture_manifest(),
            out,
            results,
            labels=[tmp_path / "public"],
            private_labels=[tmp_path / "private"],
        )


def test_labels_refuse_duplicates_and_a_file_for_another_repository(tmp_path: Path) -> None:
    harness = _harness()
    entry = _label("0123456789abcdef", "true-positive")
    _labels(tmp_path / "one", "alpha", COMMIT_A, [entry, entry])
    with pytest.raises(harness.HarnessError, match="duplicate"):
        harness.load_labels([tmp_path / "one"])
    _labels(tmp_path / "two", "alpha", COMMIT_A, [entry])
    _labels(tmp_path / "three", "beta", COMMIT_B, [entry])
    with pytest.raises(harness.HarnessError, match="labelled twice"):
        harness.load_labels([tmp_path / "two", tmp_path / "three"])
    (tmp_path / "two" / "alpha.json").rename(tmp_path / "two" / "gamma.json")
    with pytest.raises(harness.HarnessError, match="file for gamma"):
        harness.load_labels([tmp_path / "two"])


def test_label_template_adds_only_missing_entries(tmp_path: Path) -> None:
    harness = _harness()
    found = harness.collect_observations("alpha", _base_inventories()["alpha"])
    public = [item for item in found if not harness.is_private(item)]
    labels = tmp_path / "labels"
    _labels(labels, "alpha", COMMIT_A, [_label(public[0]["id"], "true-positive")])
    assert harness.label_template(_fixture_manifest(), public, labels) == len(public) - 1
    assert harness.label_template(_fixture_manifest(), public, labels) == 0
    document = json.loads((labels / "alpha.json").read_text())
    assert document["labels"][0]["verdict"] == "true-positive"
    assert {entry["verdict"] for entry in document["labels"][1:]} == {None}
    assert harness.load_labels([labels]).keys() == {public[0]["id"]}
    with pytest.raises(harness.HarnessError, match="unknown repository"):
        harness.label_template(_fixture_manifest(), [{**public[0], "repository": "z"}], labels)


def test_label_template_writes_credential_observations_only_privately(tmp_path: Path) -> None:
    harness = _harness()
    found = harness.collect_observations("alpha", _base_inventories()["alpha"])
    labels = tmp_path / "labels"
    with pytest.raises(harness.HarnessError, match="--private"):
        harness.label_template(_fixture_manifest(), found, labels)
    assert not labels.exists()
    with pytest.raises(harness.HarnessError, match="outside the repository"):
        harness.label_template(_fixture_manifest(), found, BENCH / "labels", private=True)
    assert harness.label_template(_fixture_manifest(), found, labels, private=True) == len(found)
    assert SENTINEL_DETAIL in (labels / "alpha.json").read_text()
    assert harness.load_labels([labels], private=True) == {}
    with pytest.raises(harness.HarnessError, match="private-labels"):
        harness.load_labels([labels])


def test_delta_against_a_baseline_reports_flips_new_observations_and_budgets(
    tmp_path: Path,
) -> None:
    harness = _harness()
    manifest = _fixture_manifest()
    base_out, base_results = tmp_path / "base-out", tmp_path / "baseline"
    _write_scan(base_out, _base_inventories(), seconds={"beta": 5.0})
    harness.report(manifest, base_out, base_results, budgets=_budgets())

    changed = _base_inventories()
    changed["neg"]["components"][0]["risks"] = [
        {"category": "rag_discovery", "severity": "info", "detail": "chroma import"}
    ]
    changed["alpha"]["components"][1]["risks"].append(
        {"category": "credential_exposure", "severity": "high", "detail": "another"}
    )
    changed["alpha"]["metadata"]["completeness"]["surfaces_excluded"] = ["new.py: dynamic"]
    changed["beta"]["components"] = []
    out, results = tmp_path / "out", tmp_path / "results"
    _write_scan(out, changed, gates={"neg": "failed"}, seconds={"alpha": 9.0, "beta": 9.0})
    summary = harness.report(manifest, out, results, baseline=base_results, budgets=_budgets())
    delta = summary["delta"]
    assert delta["new_observations"] == {"finding:rag_discovery": 1, "gap": 1}
    assert delta["removed_observations"] == {"component:mcp-server": 1}
    assert delta["credential_count_delta"] == {"credential_exposure": {"high": 1}}
    assert [(f["repository"], f["before"], f["after"]) for f in delta["gate_flips"]] == [
        ("neg", "passed", "failed")
    ]
    assert delta["repositories"]["alpha"]["time_ratio"] == 9.0
    budgets = summary["budgets"]
    assert _budget(budgets, "negative repositories: new observations")["actual"] == 1
    coverage = _budget(budgets, "coverage: new gaps on complete-coverage repositories")
    assert coverage["actual"] == ["alpha"] and coverage["passed"] is False
    assert _budget(budgets, "cost: wall time")["actual"] == ["alpha"]
    assert _budget(budgets, "cost: peak RSS")["passed"] is True
    ids = json.loads((out / "private" / "delta-ids.json").read_text())
    assert len(ids["new"]) == 2 and len(ids["removed"]) == 1
    assert "another" not in "".join(path.read_text() for path in results.iterdir())


def test_a_new_credential_finding_on_a_negative_repository_fails_with_a_baseline(
    tmp_path: Path,
) -> None:
    harness = _harness()
    manifest = _fixture_manifest()
    base_out, base_results = tmp_path / "base-out", tmp_path / "baseline"
    _write_scan(base_out, _base_inventories())
    harness.report(manifest, base_out, base_results, budgets=_budgets())

    changed = _base_inventories()
    changed["neg"]["components"][0]["risks"] = [
        {"category": "credential_exposure", "severity": "critical", "detail": "sk-live-neg"}
    ]
    out, results = tmp_path / "out", tmp_path / "results"
    _write_scan(out, changed)
    summary = harness.report(manifest, out, results, baseline=base_results, budgets=_budgets())
    negative = _budget(summary["budgets"], "negative repositories: new observations")
    assert negative["actual"] == 1 and negative["passed"] is False
    assert summary["delta"]["repositories"]["neg"]["new_observations"] == 0
    published = "".join(path.read_text() for path in results.iterdir())
    assert "sk-live-neg" not in published and "new_private" not in published

    private = out / "private" / "credential-observations.json"
    summary = harness.report(
        manifest,
        out,
        tmp_path / "again",
        baseline=base_results,
        baseline_private=private,
        budgets=_budgets(),
    )
    negative = _budget(summary["budgets"], "negative repositories: new observations")
    assert negative["actual"] == 0 and negative["passed"] is True


def test_scan_exit_code_and_cost_budgets_fail(tmp_path: Path) -> None:
    harness = _harness()
    manifest = _fixture_manifest()
    base_out, base_results = tmp_path / "base-out", tmp_path / "baseline"
    _write_scan(base_out, _base_inventories(), seconds={"alpha": 2.0, "beta": 6.0})
    harness.report(manifest, base_out, base_results, budgets=_budgets())

    out, results = tmp_path / "out", tmp_path / "results"
    _write_scan(
        out,
        {key: value for key, value in _base_inventories().items() if key != "neg"},
        seconds={"alpha": 4.5, "beta": 13.0},
        rss={"alpha": 140001},
        exit_codes={"beta": 1},
    )
    summary = harness.report(manifest, out, results, baseline=base_results, budgets=_budgets())
    budgets = summary["budgets"]
    exits = _budget(budgets, "scan exit codes")
    assert exits["actual"] == ["beta", "neg"] and exits["passed"] is False
    assert _budget(budgets, "cost: wall time")["actual"] == ["beta"]
    rss = _budget(budgets, "cost: peak RSS")
    assert rss["actual"] == ["alpha"] and rss["passed"] is False

    _write_scan(out, _base_inventories(), seconds={"alpha": 4.5, "beta": 12.0}, rss={"alpha": 1})
    summary = harness.report(manifest, out, results, baseline=base_results, budgets=_budgets())
    assert _budget(summary["budgets"], "scan exit codes")["passed"] is True
    assert _budget(summary["budgets"], "cost: wall time")["passed"] is True
    assert _budget(summary["budgets"], "cost: peak RSS")["passed"] is True


def test_main_enforces_budgets_only_when_asked(tmp_path: Path) -> None:
    harness = _harness()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            _manifest(
                _repo("alpha", COMMIT_A),
                _repo("beta", COMMIT_B, "mcp-servers"),
                _repo("neg", COMMIT_C, "negative"),
            )
        )
    )
    inventories = _base_inventories()
    inventories["neg"]["components"][0]["risks"] = [
        {"category": "rag_discovery", "severity": "info", "detail": "x"}
    ]
    _write_scan(tmp_path / "out", inventories)
    budgets = tmp_path / "budgets.json"
    budgets.write_text(json.dumps(_budgets()))
    common = [
        "--manifest",
        str(manifest),
        "report",
        "--out",
        str(tmp_path / "out"),
        "--results",
        str(tmp_path / "results"),
        "--labels",
        str(tmp_path / "none"),
        "--budgets",
        str(budgets),
    ]
    assert harness.main(common) == 0
    assert harness.main([*common, "--enforce-budgets"]) == 1
    bad = _manifest(_repo("..", COMMIT_A))
    manifest.write_text(json.dumps(bad))
    assert harness.main(common) == 2


@pytest.mark.parametrize(
    "budgets",
    [
        {"schema_version": 2},
        {"schema_version": 1, "categories": {"x": {"max_false_positives": -1}}},
        {"schema_version": 1, "categories": {"x": {"max_false_positives": {"severe": 1}}}},
        {"schema_version": 1, "component_min_precision": 1.5},
    ],
)
def test_budgets_are_validated(budgets: dict[str, Any]) -> None:
    with pytest.raises(_harness().HarnessError, match="budgets"):
        _harness().parse_budgets(budgets)


# Committed baseline


def test_committed_baseline_is_consistent_with_the_manifest_labels_and_budgets() -> None:
    harness = _harness()
    manifest = harness.load_manifest(BENCH / "manifest.json")
    harness.parse_budgets(json.loads((BENCH / "budgets.json").read_text()))
    baseline = BENCH / "results" / "baseline"
    summary = json.loads((baseline / "summary.json").read_text())
    assert [row["id"] for row in summary["repositories"]] == [repo["id"] for repo in manifest]
    assert all(row["exit_code"] == 0 for row in summary["repositories"])
    assert (baseline / "RESULTS.md").read_text() == harness.render_results(summary)
    observations = json.loads((baseline / "observations.json").read_text())
    published = observations["observations"]
    assert not [item for item in published if harness.is_private(item)]
    for row in summary["repositories"]:
        assert not [name for name in row["findings"] if harness.is_credential_category(name)]
    findings: dict[str, dict[str, int]] = {}
    for category, severities in observations["credential_counts"].items():
        findings[category] = dict(severities)
    for item in published:
        if item["kind"] == "finding":
            row = findings.setdefault(item["category"], {})
            row[item["severity"]] = row.get(item["severity"], 0) + 1
    assert findings == summary["finding_totals"]
    components: dict[str, int] = {}
    for item in published:
        if item["kind"] == "component":
            components[item["component_type"]] = components.get(item["component_type"], 0) + 1
    assert components == summary["component_totals"]
    for row in summary["repositories"]:
        mine = [item for item in published if item["repository"] == row["id"]]
        assert sum(item["kind"] == "gap" for item in mine) == row["gaps"]
        assert sum(item["kind"] == "component" for item in mine) == sum(row["components"].values())
    ids = {item["id"] for item in published}
    commits = {repo["id"]: repo["commit"] for repo in manifest}
    for path in sorted((BENCH / "labels").glob("*.json")):
        document = harness.parse_labels(json.loads(path.read_text()), path.stem)
        assert document["commit"] == commits[path.stem]
        for entry in document["labels"]:
            assert entry["observation"] in ids
            assert entry["status"] == "proposed"
