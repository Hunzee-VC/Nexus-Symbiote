"""The collector contract, plugin registry and runner (``spec/collectors.md``).

A collector turns one family of artefacts (MCP client configs, instruction files, skills, model directories,
traces, ...) into AgentBOM entities, edges and evidence, plus a **coverage fragment** for every surface it is
responsible for. Two rules are enforced here rather than left to each collector:

* **I2 — unknown is not absence.** A collector that is skipped, times out or crashes still contributes a
  coverage fragment (``not-attempted`` / ``partial`` with the error class), never an empty "nothing found".
* **No execution of scanned content.** Collectors receive paths and a context, never an import hook; the
  runner gives each one a wall-clock budget so a hostile input cannot stall a scan.

Third-party collectors register under the ``symbiote.collectors`` entry-point group with an object that
satisfies :class:`Collector`.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Literal, Protocol, runtime_checkable

from symbiote.collect._common import ReadOutcome, read_bounded
from symbiote.model.common import Party
from symbiote.model.edges import Edge
from symbiote.model.entities import Collector as CollectorRecord
from symbiote.model.entities import (
    CollectorRun,
    Coverage,
    Entity,
    Evidence,
    Redaction,
    SourceRun,
    SurfaceCoverage,
)
from symbiote.model.enums import CollectorMode, CollectorStatus, CoverageStatus, Surface

__all__ = [
    "BUILTIN_COLLECTORS",
    "ENTRY_POINT_GROUP",
    "BaseCollector",
    "CollectContext",
    "CollectionResult",
    "Collector",
    "Platform",
    "load_collectors",
    "merge_coverage",
    "merge_surface",
    "run_collectors",
]

Platform = Literal["linux", "macos", "windows"]

ENTRY_POINT_GROUP = "symbiote.collectors"

#: Built-in collectors as ``module:attribute``. Modules that are not installed yet are skipped with a
#: warning, so packages can land independently (``docs/development/work-packages.md``).
BUILTIN_COLLECTORS: tuple[str, ...] = (
    "symbiote.collect.mcp_config:McpConfigCollector",
    "symbiote.collect.instructions:InstructionsCollector",
    "symbiote.collect.skills:SkillsCollector",
    "symbiote.collect.models_local:ModelsLocalCollector",
    "symbiote.collect.models_hosted:ModelsHostedCollector",
    "symbiote.collect.frameworks:FrameworksCollector",
    "symbiote.collect.a2a:A2ACardsCollector",
    "symbiote.collect.identity:IdentityConfigCollector",
    "symbiote.collect.sbom_merge:SbomMergeCollector",
    "symbiote.collect.mcp_live:McpLiveCollector",
    "symbiote.collect.otel:OtelTracesCollector",
    "symbiote.collect.registry:McpRegistryCollector",
    "symbiote.collect.shadowscan:ShadowScanReportCollector",
)

#: Default directory exclusions for repository walks (vendored code, environments, VCS metadata).
DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".tox",
    "dist",
    "build",
    "site-packages",
)


def _detect_platform() -> Platform:
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("win"):
        return "windows"
    return "linux"


@dataclass(frozen=True, slots=True)
class CollectContext:
    """Everything a collector may read. Collectors must not consult the process environment directly.

    ``home`` is ``None`` for a repository-only scan (the default in CI): user-scope configuration such as
    ``~/.claude.json`` is then reported as ``not-attempted`` instead of being read from the runner's home.
    """

    root: Path
    agent_id: str = "agent:unnamed"
    home: Path | None = None
    platform: Platform = field(default_factory=_detect_platform)
    appdata: Path | None = None
    xdg_config_home: Path | None = None
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    deterministic: bool = False
    budget_seconds: float = 20.0
    max_file_bytes: int = 16 * 1024 * 1024
    max_files: int = 50_000
    exclude_dirs: tuple[str, ...] = DEFAULT_EXCLUDES
    include_text: bool = False
    options: Mapping[str, Any] = field(default_factory=dict)

    @property
    def user_scope(self) -> bool:
        return self.home is not None

    def user_config_dir(self) -> Path | None:
        """Per-OS application configuration directory (``~/Library/Application Support``, ``%APPDATA%``, XDG)."""
        if self.home is None:
            return None
        if self.platform == "macos":
            return self.home / "Library" / "Application Support"
        if self.platform == "windows":
            return self.appdata or self.home / "AppData" / "Roaming"
        return self.xdg_config_home or self.home / ".config"

    def read_config(self, path: Path) -> ReadOutcome:
        """Read only beneath a root enabled for this collection context."""
        for root in (self.root, self.home, self.user_config_dir()):
            if root is not None and path.is_relative_to(root):
                return read_bounded(path, self.max_file_bytes, root=root)
        return ReadOutcome(None, "permission-denied", "outside collection scope")

    def display(self, path: Path) -> str:
        """Stable, privacy-preserving display path: repo-relative, ``~/``-relative, or absolute as a last resort."""
        try:
            return path.relative_to(self.root).as_posix() or "."
        except ValueError:
            pass
        if self.home is not None:
            try:
                return "~/" + path.relative_to(self.home).as_posix()
            except ValueError:
                pass
        return path.as_posix()

    def walk(self, *, max_depth: int = 12) -> Iterable[Path]:
        """Yield files under ``root`` in sorted order, pruning excluded directories and never following symlinks."""
        count = 0
        stack: list[tuple[Path, int]] = [(self.root, 0)]
        while stack:
            directory, depth = stack.pop()
            try:
                entries = sorted(directory.iterdir(), key=lambda p: p.name, reverse=True)
            except OSError:
                continue
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    if entry.name not in self.exclude_dirs and depth < max_depth:
                        stack.append((entry, depth + 1))
                    continue
                count += 1
                if count > self.max_files:
                    return
                yield entry


@dataclass(slots=True)
class CollectionResult:
    """What one collector run contributes to a snapshot."""

    collector: CollectorRecord
    entities: list[Entity] = field(default_factory=list)
    parties: list[Party] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    coverage: dict[Surface, SurfaceCoverage] = field(default_factory=dict)
    redactions: list[Redaction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    status: CollectorStatus = CollectorStatus.OK
    reason: str | None = None
    elapsed_ms: int | None = None
    #: Computed flags a collector can assert directly (merged with the policy engine's flags by the runner).
    flags: list[Any] = field(default_factory=list)
    #: Document-level foreign properties (importer passthrough of observation-only records).
    foreign_properties: list[Any] = field(default_factory=list)
    #: Field updates for the **root agent** (``autonomy_assessment``, ``tags``, ``foreign`` …): a collector
    #: cannot replace the root entity the scan created, so it hands facts about it back to the runner.
    root_updates: dict[str, Any] = field(default_factory=dict)

    def add_source(
        self,
        surface: Surface,
        source: str,
        *,
        locator: str | None = None,
        ok: bool = True,
        error_class: str | None = None,
        items: int = 0,
    ) -> None:
        """Record that ``source`` was examined for ``surface`` (coverage is derived from these records)."""
        current = self.coverage.get(surface, SurfaceCoverage())
        run = SourceRun(source=source, locator=locator, ok=ok, error_class=error_class, items=items)
        self.coverage[surface] = current.model_copy(
            update={"sources": [*current.sources, run], "items_seen": current.items_seen + items}
        )

    def set_status(
        self, surface: Surface, status: CoverageStatus, *, truncated_at: int | None = None
    ) -> None:
        current = self.coverage.get(surface, SurfaceCoverage())
        self.coverage[surface] = current.model_copy(update={"status": status, "truncated_at": truncated_at})

    def finalize_coverage(self, surfaces: Iterable[Surface]) -> None:
        """Derive each owned surface's status from its source records when the collector did not set one."""
        for surface in surfaces:
            cov = self.coverage.get(surface)
            if cov is None:
                self.coverage[surface] = SurfaceCoverage(status=CoverageStatus.NOT_ATTEMPTED)
                continue
            if cov.status is not CoverageStatus.NOT_ATTEMPTED or not cov.sources:
                continue
            oks = [s.ok for s in cov.sources]
            if all(oks):
                status = CoverageStatus.QUERIED
            elif any(oks):
                status = CoverageStatus.PARTIAL
            else:
                classes = {s.error_class for s in cov.sources}
                status = (
                    CoverageStatus.PERMISSION_DENIED
                    if classes == {"permission-denied"}
                    else CoverageStatus.UNREACHABLE
                    if classes == {"unreachable"}
                    else CoverageStatus.PARTIAL
                )
            self.coverage[surface] = cov.model_copy(update={"status": status})

    def run_record(self) -> CollectorRun:
        return CollectorRun(
            name=self.collector.name, version=self.collector.version, status=self.status, reason=self.reason
        )


@runtime_checkable
class Collector(Protocol):
    """A collector plugin. Implementations should subclass :class:`BaseCollector`."""

    name: str
    version: str
    surfaces: tuple[Surface, ...]
    mode: CollectorMode

    def detect(self, ctx: CollectContext) -> bool: ...

    def collect(self, ctx: CollectContext) -> CollectionResult: ...


class BaseCollector:
    """Convenience base: identity, record and result factory. Subclasses implement ``detect``/``collect``."""

    name: ClassVar[str] = "base"
    version: ClassVar[str] = "0.1.0"
    surfaces: ClassVar[tuple[Surface, ...]] = ()
    mode: ClassVar[CollectorMode] = CollectorMode.DECLARED

    @property
    def ref(self) -> str:
        return f"collector:{self.name}@{self.version}"

    def record(self) -> CollectorRecord:
        return CollectorRecord(
            name=self.name, version=self.version, mode=self.mode, surfaces=list(self.surfaces)
        )

    def new_result(self) -> CollectionResult:
        return CollectionResult(collector=self.record())

    def detect(self, ctx: CollectContext) -> bool:
        del ctx
        return True

    def collect(self, ctx: CollectContext) -> CollectionResult:  # pragma: no cover - abstract
        raise NotImplementedError


# --------------------------------------------------------------------------------------------- registry


def _load_target(target: str) -> Collector:
    module_name, _, attr = target.partition(":")
    module = importlib.import_module(module_name)
    obj = getattr(module, attr)
    instance = obj() if isinstance(obj, type) else obj
    if not isinstance(instance, Collector):
        raise TypeError(f"{target} does not implement the Collector protocol")
    return instance


def load_collectors(
    names: Iterable[str] | None = None,
    *,
    include_plugins: bool = True,
    warnings: list[str] | None = None,
) -> list[Collector]:
    """Instantiate built-in collectors (and entry-point plugins), optionally filtered by ``names``.

    Built-ins whose module is not present are skipped with a warning rather than failing the scan.
    """
    wanted = set(names) if names is not None else None
    found: dict[str, Collector] = {}
    targets: list[str] = list(BUILTIN_COLLECTORS)
    if include_plugins:
        for ep in importlib.metadata.entry_points(group=ENTRY_POINT_GROUP):
            targets.append(ep.value)
    for target in targets:
        try:
            collector = _load_target(target)
        except ModuleNotFoundError as exc:
            if warnings is not None and exc.name and exc.name.startswith("symbiote."):
                warnings.append(f"collector {target} unavailable: {exc.name} not installed")
            continue
        except (AttributeError, TypeError, ImportError) as exc:
            if warnings is not None:
                warnings.append(f"collector {target} failed to load: {type(exc).__name__}: {exc}")
            continue
        if wanted is not None and collector.name not in wanted:
            continue
        found.setdefault(collector.name, collector)
    return sorted(found.values(), key=lambda c: c.name)


# --------------------------------------------------------------------------------------------- runner


def _skipped(collector: Collector, reason: str) -> CollectionResult:
    record = CollectorRecord(
        name=collector.name, version=collector.version, mode=collector.mode, surfaces=list(collector.surfaces)
    )
    result = CollectionResult(collector=record, status=CollectorStatus.SKIPPED, reason=reason)
    for surface in collector.surfaces:
        result.coverage[surface] = SurfaceCoverage(status=CoverageStatus.NOT_ATTEMPTED)
    return result


def _failed(collector: Collector, reason: str, status: CoverageStatus) -> CollectionResult:
    result = _skipped(collector, reason)
    result.status = CollectorStatus.FAILED
    for surface in collector.surfaces:
        result.coverage[surface] = SurfaceCoverage(
            status=status,
            sources=[SourceRun(source=collector.name, ok=False, error_class=reason.split(":", 1)[0])],
        )
    return result


def run_collectors(
    ctx: CollectContext,
    collectors: Sequence[Collector],
    *,
    only_detected: bool = True,
) -> list[CollectionResult]:
    """Run each collector under ``ctx.budget_seconds``; failures become coverage facts, never exceptions."""
    results: list[CollectionResult] = []
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="symbiote-collector")
    try:
        for collector in collectors:
            try:
                applicable = collector.detect(ctx)
            except Exception as exc:  # a broken detect() must not abort the scan
                results.append(
                    _failed(collector, f"detect-error: {type(exc).__name__}", CoverageStatus.NOT_ATTEMPTED)
                )
                continue
            if only_detected and not applicable:
                results.append(_skipped(collector, "not-detected"))
                continue
            started = time.monotonic()
            future = executor.submit(collector.collect, ctx)
            try:
                result = future.result(timeout=ctx.budget_seconds)
            except FutureTimeout:
                results.append(_failed(collector, "timeout", CoverageStatus.PARTIAL))
                executor.shutdown(wait=False, cancel_futures=True)
                executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="symbiote-collector")
                continue
            except Exception as exc:
                results.append(
                    _failed(collector, f"error: {type(exc).__name__}: {exc}", CoverageStatus.NOT_ATTEMPTED)
                )
                continue
            result.elapsed_ms = int((time.monotonic() - started) * 1000)
            result.finalize_coverage(collector.surfaces)
            results.append(result)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return results


# --------------------------------------------------------------------------------------------- coverage merge

#: When two collectors report on one surface, the more informative status wins in this order.
_STATUS_RANK: dict[CoverageStatus, int] = {
    CoverageStatus.NOT_ATTEMPTED: 0,
    CoverageStatus.QUERIED: 1,
    CoverageStatus.TRUNCATED: 2,
    CoverageStatus.PARTIAL: 3,
    CoverageStatus.UNREACHABLE: 4,
    CoverageStatus.PERMISSION_DENIED: 5,
}


def merge_surface(a: SurfaceCoverage, b: SurfaceCoverage) -> SurfaceCoverage:
    """Combine two fragments for one surface.

    ``queried`` + ``queried`` stays ``queried``; any failure or truncation in either fragment degrades the
    merged status (a surface is only complete when every contributor completed); ``not-attempted`` never
    masks a fragment that did run.
    """
    if a.status is CoverageStatus.NOT_ATTEMPTED and not a.sources:
        return b
    if b.status is CoverageStatus.NOT_ATTEMPTED and not b.sources:
        return a
    ran = [s for s in (a.status, b.status) if s is not CoverageStatus.NOT_ATTEMPTED]
    status = max(ran, key=_STATUS_RANK.__getitem__) if ran else CoverageStatus.NOT_ATTEMPTED
    if (
        status in (CoverageStatus.UNREACHABLE, CoverageStatus.PERMISSION_DENIED)
        and CoverageStatus.QUERIED in ran
    ):
        status = CoverageStatus.PARTIAL
    truncated = [t for t in (a.truncated_at, b.truncated_at) if t is not None]
    return SurfaceCoverage(
        status=status,
        sources=[*a.sources, *b.sources],
        items_seen=a.items_seen + b.items_seen,
        truncated_at=min(truncated) if truncated else None,
    )


def merge_coverage(results: Iterable[CollectionResult], *, text_included: bool = False) -> Coverage:
    """Fold every result's fragments into one document-level :class:`Coverage` (all ten surfaces present)."""
    surfaces: dict[Surface, SurfaceCoverage] = {s: SurfaceCoverage() for s in Surface}
    runs: list[CollectorRun] = []
    for result in results:
        for surface, fragment in result.coverage.items():
            surfaces[surface] = merge_surface(surfaces[surface], fragment)
        runs.append(result.run_record())
    runs.sort(key=lambda r: r.name)
    return Coverage(surfaces=surfaces, collectors=runs, text_included=text_included)


def env_flag(name: str) -> bool:
    """Read a boolean feature flag from the environment (CLI layer only; collectors use ``ctx.options``)."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}
