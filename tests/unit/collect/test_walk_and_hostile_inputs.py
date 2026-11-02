"""Shared collector plumbing under hostile repositories: walk reporting, non-regular files, odd names, linear scans."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from symbiote.collect.base import CollectContext, CollectionResult, WalkReport
from symbiote.collect.identity import expression_spans, reference_hits, secret_names
from symbiote.model.common import looks_like_secret
from symbiote.model.entities import Collector as CollectorRecord
from symbiote.model.enums import CoverageStatus, Surface


def _ctx(root: Path, **kw: object) -> CollectContext:
    return CollectContext(root=root, platform="linux", **kw)  # type: ignore[arg-type]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_walk_never_yields_non_regular_files_and_reports_them(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    os.mkfifo(tmp_path / "pkg" / "agent-card.json")
    (tmp_path / "pkg" / "ok.json").write_text("{}")
    report = WalkReport()
    files = list(_ctx(tmp_path).walk(report=report))
    assert [p.name for p in files] == ["ok.json"]
    assert report.non_regular == 1 and report.non_regular_paths == ["pkg/agent-card.json"]


@pytest.mark.skipif(sys.platform == "darwin", reason="APFS rejects non-UTF-8 names")
def test_walk_skips_and_counts_non_utf8_names(tmp_path: Path) -> None:
    os.mkdir(os.fsencode(tmp_path) + b"/bad-\xff")
    (Path(os.fsdecode(os.fsencode(tmp_path) + b"/bad-\xff")) / "AGENTS.md").write_text("x")
    (tmp_path / "AGENTS.md").write_text("y")
    report = WalkReport()
    names = [p.relative_to(tmp_path).as_posix() for p in _ctx(tmp_path).walk(report=report)]
    assert names == ["AGENTS.md"] and report.non_utf8 == 1


def test_depth_and_vendor_pruning_are_reported_and_client_trees_exempt(tmp_path: Path) -> None:
    deep = tmp_path.joinpath(*[f"d{i}" for i in range(14)])
    deep.mkdir(parents=True)
    (deep / "AGENTS.md").write_text("deep")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "SKILL.md").write_text("vendored")
    (tmp_path / ".claude" / "skills" / "build").mkdir(parents=True)
    (tmp_path / ".claude" / "skills" / "build" / "SKILL.md").write_text("a skill named build")
    report = WalkReport()
    names = {
        p.relative_to(tmp_path).as_posix()
        for p in _ctx(tmp_path).walk(report=report, keep_within=(".claude",))
    }
    assert "node_modules/x/SKILL.md" not in names and report.excluded >= 1
    assert report.too_deep and report.too_deep[0].startswith("d0/")
    vendored = tmp_path / ".claude" / "skills" / "node_modules"
    vendored.mkdir()
    (vendored / "SKILL.md").write_text("named like a vendor dir")
    names = {p.relative_to(tmp_path).as_posix() for p in _ctx(tmp_path).walk(keep_within=(".claude",))}
    assert ".claude/skills/node_modules/SKILL.md" in names
    assert "node_modules/x/SKILL.md" not in names


def test_record_walk_makes_skips_visible(tmp_path: Path) -> None:
    result = CollectionResult(collector=CollectorRecord(name="t", version="0"))
    report = WalkReport(unreadable=["locked"], too_deep=["d0/d1"], non_utf8=2, non_regular_paths=["fifo"])
    result.record_walk(Surface.INSTRUCTIONS, report)
    result.finalize_coverage([Surface.INSTRUCTIONS])
    cov = result.coverage[Surface.INSTRUCTIONS]
    classes = {(s.locator, s.error_class) for s in cov.sources if not s.ok}
    assert {("locked", "permission-denied"), ("d0/d1", "too-deep"), ("fifo", "not-a-regular-file")} <= classes
    assert cov.status is CoverageStatus.PARTIAL


def test_missing_root_is_empty_not_an_error(tmp_path: Path) -> None:
    report = WalkReport()
    assert list(_ctx(tmp_path / "absent").walk(report=report)) == []
    assert not report.unreadable


@pytest.mark.parametrize(
    "text",
    ["eyJ-" * 160_000, "${{" * 300_000, "spiffe://a\n" * 60_000],
    ids=["jwt-run", "unclosed-expression", "many-references"],
)
def test_shared_scanners_are_linear(text: str) -> None:
    start = time.perf_counter()
    looks_like_secret(text)
    secret_names(text, expression=False)
    expression_spans(text)
    reference_hits(text)
    assert time.perf_counter() - start < 2.0


def test_scanners_still_find_real_things() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    assert looks_like_secret("Authorization: Bearer " + jwt)
    assert secret_names(
        "run: echo ${{ secrets.NPM_TOKEN }} and ${{ secrets['PYPI'] }}", expression=False
    ) == [
        "NPM_TOKEN",
        "PYPI",
    ]
    assert [h.line for h in reference_hits("x\nspiffe://a/b\ny\nspiffe://c/d\n")] == [2, 4]


def test_url_facts_never_keeps_credentials() -> None:
    from symbiote.collect._common import url_facts

    slash = url_facts("https://deployer:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY@rules.example.com/team.md")
    assert slash.display == "https://rules.example.com/team.md" and slash.had_userinfo
    assert (
        url_facts("https://registry.npmjs.org/@anthropic-ai/sdk").display
        == "https://registry.npmjs.org/@anthropic-ai/sdk"
    )
    assert url_facts("https://host:8080/@scope/pkg").display == "https://host:8080/@scope/pkg"
    secret_path = url_facts("https://agent.example.com/a2a/sk-ant-api03-" + "A" * 40)
    assert secret_path.display == "https://agent.example.com/<redacted>" and secret_path.secret_in_path
    assert url_facts("https://ghp_" + "Z" * 36 + ".example.com/x").display == "https://<redacted>"


def test_symlinked_rule_files_are_considered_or_reported(tmp_path: Path) -> None:
    from symbiote.collect.base import run_collectors
    from symbiote.collect.instructions import InstructionsCollector

    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "rule.txt").write_text("always do x\n")
    rules = tmp_path / ".cursor" / "rules"
    rules.mkdir(parents=True)
    os.symlink("../../docs/rule.txt", rules / "linked.mdc")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.md"
    outside.write_text("outside\n")
    os.symlink(outside, rules / "escape.mdc")
    result = run_collectors(_ctx(tmp_path), [InstructionsCollector()])[0]
    paths = {getattr(e, "path", None) for e in result.entities}
    assert ".cursor/rules/linked.mdc" in paths and ".cursor/rules/escape.mdc" not in paths
    failed = {(s.locator, s.error_class) for c in result.coverage.values() for s in c.sources if not s.ok}
    assert (".cursor/rules/escape.mdc", "symlink-escape") in failed


def test_yaml_amplification_is_refused_everywhere() -> None:
    import yaml as _yaml

    from symbiote.collect._common import load_yaml
    from symbiote.collect.identity import _yaml_documents

    merge_bomb = "a0: &a0 {x: 1}\n" + "".join(
        f"a{i}: &a{i} {{<<: [*a{i - 1}, *a{i - 1}]}}\n" for i in range(1, 40)
    )
    alias_bomb = "x: &r " + "y" * 100_000 + "\nl:\n" + "".join("  - *r\n" for _ in range(2000))
    start = time.perf_counter()
    assert _yaml_documents(merge_bomb)[1] and _yaml_documents(alias_bomb)[1]
    with pytest.raises(_yaml.YAMLError):
        load_yaml(merge_bomb)
    with pytest.raises(_yaml.YAMLError):
        load_yaml("a: !!bool maybe\n")
    assert time.perf_counter() - start < 2.0
    assert load_yaml("a: &x 1\nb: *x\n") == {"a": 1, "b": 1}
