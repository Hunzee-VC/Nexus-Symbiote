"""Collector runner: budgets, failures as coverage facts, coverage merge, registry."""

from __future__ import annotations

import time
from pathlib import Path

from symbiote.collect.base import (
    BaseCollector,
    CollectContext,
    CollectionResult,
    load_collectors,
    merge_coverage,
    merge_surface,
    run_collectors,
)
from symbiote.model.entities import SourceRun, SurfaceCoverage
from symbiote.model.enums import CollectorStatus, Completeness, CoverageStatus, Surface


class _Ok(BaseCollector):
    name = "ok"
    surfaces = (Surface.TOOLS,)

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        result.add_source(Surface.TOOLS, "x", ok=True, items=2)
        return result


class _Slow(BaseCollector):
    name = "slow"
    surfaces = (Surface.DATA,)

    def collect(self, ctx: CollectContext) -> CollectionResult:
        time.sleep(1.0)
        return self.new_result()


class _Boom(BaseCollector):
    name = "boom"
    surfaces = (Surface.CODE,)

    def collect(self, ctx: CollectContext) -> CollectionResult:
        raise RuntimeError("kaput")


class _NotHere(BaseCollector):
    name = "absent"
    surfaces = (Surface.NETWORK,)

    def detect(self, ctx: CollectContext) -> bool:
        return False


def test_runner_turns_failures_into_coverage(tmp_path: Path) -> None:
    ctx = CollectContext(root=tmp_path, budget_seconds=0.2)
    results = {r.collector.name: r for r in run_collectors(ctx, [_Ok(), _Slow(), _Boom(), _NotHere()])}
    assert results["ok"].coverage[Surface.TOOLS].status is CoverageStatus.QUERIED
    assert results["ok"].elapsed_ms is not None
    assert results["slow"].status is CollectorStatus.FAILED
    assert results["slow"].coverage[Surface.DATA].status is CoverageStatus.PARTIAL
    assert results["boom"].status is CollectorStatus.FAILED
    assert results["boom"].reason is not None and "kaput" in results["boom"].reason
    assert results["absent"].status is CollectorStatus.SKIPPED
    assert results["absent"].coverage[Surface.NETWORK].status is CoverageStatus.NOT_ATTEMPTED
    coverage = merge_coverage(results.values())
    assert set(coverage.surfaces) == set(Surface)
    assert coverage.completeness is Completeness.INCOMPLETE
    assert [c.name for c in coverage.collectors] == ["absent", "boom", "ok", "slow"]


def test_finalize_coverage_statuses() -> None:
    result = _Ok().new_result()
    result.add_source(Surface.TOOLS, "a", ok=True)
    result.add_source(Surface.TOOLS, "b", ok=False, error_class="parse-error")
    result.add_source(Surface.DATA, "c", ok=False, error_class="permission-denied")
    result.add_source(Surface.REGISTRY, "d", ok=False, error_class="unreachable")
    result.finalize_coverage([Surface.TOOLS, Surface.DATA, Surface.REGISTRY, Surface.RUNTIME])
    assert result.coverage[Surface.TOOLS].status is CoverageStatus.PARTIAL
    assert result.coverage[Surface.DATA].status is CoverageStatus.PERMISSION_DENIED
    assert result.coverage[Surface.REGISTRY].status is CoverageStatus.UNREACHABLE
    assert result.coverage[Surface.RUNTIME].status is CoverageStatus.NOT_ATTEMPTED


def test_merge_surface_rules() -> None:
    queried = SurfaceCoverage(
        status=CoverageStatus.QUERIED, sources=[SourceRun(source="a", ok=True)], items_seen=1
    )
    failed = SurfaceCoverage(status=CoverageStatus.UNREACHABLE, sources=[SourceRun(source="b", ok=False)])
    empty = SurfaceCoverage()
    assert merge_surface(empty, queried) == queried
    assert merge_surface(queried, empty) == queried
    merged = merge_surface(queried, failed)
    assert merged.status is CoverageStatus.PARTIAL
    assert merged.items_seen == 1 and len(merged.sources) == 2
    both = merge_surface(queried, queried)
    assert both.status is CoverageStatus.QUERIED


def test_context_display_and_user_dirs(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ctx = CollectContext(root=tmp_path / "repo", home=home, platform="macos")
    assert ctx.display(tmp_path / "repo" / ".mcp.json") == ".mcp.json"
    assert ctx.display(home / ".claude.json") == "~/.claude.json"
    assert ctx.user_config_dir() == home / "Library" / "Application Support"
    assert (
        CollectContext(root=tmp_path, home=home, platform="windows").user_config_dir()
        == home / "AppData" / "Roaming"
    )
    assert CollectContext(root=tmp_path, home=home, platform="linux").user_config_dir() == home / ".config"
    assert CollectContext(root=tmp_path).user_config_dir() is None


def test_walk_prunes_excludes(tmp_path: Path) -> None:
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "AGENTS.md").write_text("vendored")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "AGENTS.md").write_text("ours")
    files = [p.relative_to(tmp_path).as_posix() for p in CollectContext(root=tmp_path).walk()]
    assert files == ["src/AGENTS.md"]


def test_load_collectors_skips_missing_modules() -> None:
    warnings: list[str] = []
    collectors = load_collectors(include_plugins=False, warnings=warnings)
    names = [c.name for c in collectors]
    assert "mcp-config" in names
    assert names == sorted(names)
    only = load_collectors(["mcp-config"], include_plugins=False)
    assert [c.name for c in only] == ["mcp-config"]


def test_failed_source_never_merges_into_queried() -> None:
    """I2: a fragment carrying a failed source run (e.g. a crashed collector
    recorded as not-attempted) must degrade the merged surface to partial,
    not disappear behind another collector's clean 'queried'."""
    queried = SurfaceCoverage(status=CoverageStatus.QUERIED, sources=[SourceRun(source="ok", ok=True)])
    crashed = SurfaceCoverage(
        status=CoverageStatus.NOT_ATTEMPTED,
        sources=[SourceRun(source="boom", ok=False, error_class="error")],
    )
    for first, second in ((queried, crashed), (crashed, queried)):
        merged = merge_surface(first, second)
        assert merged.status is CoverageStatus.PARTIAL
        assert len(merged.sources) == 2


def test_crashing_collector_degrades_shared_surface(tmp_path: Path) -> None:
    class _Crash(BaseCollector):
        name = "zz-crash"  # sorts after 'ok' so the clean run merges first
        surfaces = (Surface.TOOLS,)

        def collect(self, ctx: CollectContext) -> CollectionResult:
            raise RuntimeError("live query exploded")

    ctx = CollectContext(root=tmp_path, budget_seconds=5.0)
    results = run_collectors(ctx, [_Ok(), _Crash()], only_detected=False)
    coverage = merge_coverage(results)
    assert coverage.surfaces[Surface.TOOLS].status is CoverageStatus.PARTIAL
    assert any(not s.ok for s in coverage.surfaces[Surface.TOOLS].sources)
