"""``shadowscan-report`` collector: fold a ShadowScan report into a ``symbiote scan`` run (``spec/collectors.md``).

The collector never runs ShadowScan. It reads a report the operator produced (``shadowscan code . --format json``
or ``--format cyclonedx``) when one is named — ``symbiote scan --shadowscan-report FILE``, the
``shadowscan.report`` key of ``symbiote.yaml``, or a ``shadowscan.json`` / ``shadowscan.report.json`` file at the
repository root — and contributes:

* the tool servers, credentials, identities and discovered agents ShadowScan found (``scope=root`` by default:
  only findings about the scanned repository; ``shadowscan.scope: estate`` keeps everything);
* the agent's autonomy interval (``autonomy_assessment``) and harness facts, applied to the root agent;
* one ``scan-report`` evidence record per finding plus one for the report file;
* coverage for the surfaces ShadowScan's connectors queried, honest about incomplete connectors.

A report that does not parse yields a ``partial`` coverage fragment with the error class — never a silent skip.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, ClassVar

from symbiote.collect._common import read_bounded
from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult
from symbiote.model.enums import CollectorMode, CollectorStatus, CoverageStatus, Surface
from symbiote.shadowscan.mapping import map_report
from symbiote.shadowscan.report import ReportError, read_report

DEFAULT_REPORT_NAMES = ("shadowscan.report.json", "shadowscan.json", "shadowscan.cdx.json")
OPTION_KEY = "shadowscan_report"
SCOPE_KEY = "shadowscan_scope"


class _Declared:
    """Where the report comes from: the operator (any location) or the scanned repository (root-confined)."""

    __slots__ = ("operator", "path", "scope")

    def __init__(self, path: Path, scope: str, *, operator: bool) -> None:
        self.path, self.scope, self.operator = path, scope, operator


def _declared_report(ctx: CollectContext) -> tuple[Path | None, str]:
    """``(path, scope)`` of the report to read (compatibility wrapper around :func:`_declared`)."""
    declared = _declared(ctx)
    return (declared.path, declared.scope) if declared else (None, str(ctx.options.get(SCOPE_KEY) or "root"))


def _declared(ctx: CollectContext) -> _Declared | None:
    """The report named by the operator, by ``symbiote.yaml`` in the scanned repository, or by convention.

    A path the **operator** passes (``--shadowscan-report``) may live anywhere. A path taken from the scanned
    repository is attacker-controlled: it must resolve inside the scan root (``..`` and absolute paths are
    refused) and it is later read through :meth:`CollectContext.read_config`, which refuses symlinks and
    non-regular files and bounds the read.
    """
    scope = str(ctx.options.get(SCOPE_KEY) or "root")
    explicit = ctx.options.get(OPTION_KEY)
    if explicit:
        path = Path(str(explicit))
        return _Declared(path if path.is_absolute() else Path.cwd() / path, scope, operator=True)
    declaration = ctx.options.get("declaration")
    if isinstance(declaration, dict) and isinstance(declaration.get("shadowscan"), dict):
        block: dict[str, Any] = declaration["shadowscan"]
        scope = str(block.get("scope") or scope)
        report = block.get("report")
        if isinstance(report, str) and report:
            return _Declared(ctx.root / report, scope, operator=False)
    for name in DEFAULT_REPORT_NAMES:
        candidate = ctx.root / name
        if candidate.is_file() and not candidate.is_symlink():
            return _Declared(candidate, scope, operator=False)
    return None


def _confined(ctx: CollectContext, path: Path) -> Path | None:
    """``path`` if it stays inside the scan root after resolving ``..`` (symlinks are refused at open time)."""
    root = ctx.root.resolve()
    candidate = Path(os.path.normpath(root / path if not path.is_absolute() else path))
    return candidate if candidate.is_relative_to(root) else None


def _read(ctx: CollectContext, declared: _Declared) -> bytes:
    """Bounded, regular-file-only read; never follows a final symlink; repository paths stay inside the root."""
    if declared.operator:
        outcome = read_bounded(declared.path, ctx.max_file_bytes, root=declared.path.parent)
    else:
        confined = _confined(ctx, declared.path)
        if confined is None:
            raise ReportError("report path declared by the scanned repository leaves the scan root")
        outcome = ctx.read_config(confined)
    if outcome.data is None:
        raise ReportError(f"report not read ({outcome.error_class}): {outcome.detail}")
    return outcome.data


class ShadowScanReportCollector(BaseCollector):
    name: ClassVar[str] = "shadowscan-report"
    version: ClassVar[str] = "0.1.0"
    surfaces: ClassVar[tuple[Surface, ...]] = (
        Surface.CODE,
        Surface.TOOLS,
        Surface.INSTRUCTIONS,
        Surface.IDENTITY,
        Surface.MODEL_GATEWAY,
        Surface.RUNTIME,
        Surface.NETWORK,
    )
    mode: ClassVar[CollectorMode] = CollectorMode.OBSERVED

    def detect(self, ctx: CollectContext) -> bool:
        return _declared(ctx) is not None

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        declared = _declared(ctx)
        if declared is None:  # pragma: no cover - detect() gates this
            result.status = CollectorStatus.SKIPPED
            result.reason = "no report"
            return result
        scope = declared.scope
        display = ctx.display(declared.path)
        try:
            report = read_report(_read(ctx, declared))
        except (OSError, ReportError) as exc:
            result.status = CollectorStatus.FAILED
            result.reason = f"{type(exc).__name__}: {exc}"
            for surface in self.surfaces:
                result.add_source(
                    surface, "shadowscan-report", locator=display, ok=False, error_class=type(exc).__name__
                )
                result.set_status(surface, CoverageStatus.PARTIAL)
            result.warnings.append(f"{display}: {exc}")
            return result
        root_hint = ctx.options.get("shadowscan_scan_root")
        mapped = map_report(
            report,
            root=None,
            agent_name=ctx.agent_id.split(":", 1)[1],
            now=ctx.now,
            scope=scope if scope in ("estate", "root") else "root",
            scan_root=str(root_hint) if root_hint else None,
        )
        if mapped.root.id != ctx.agent_id:
            # the mapper derived its own root from the agent name; re-key to the scan's root agent
            result.warnings.append(
                f"{display}: ShadowScan findings bound to {mapped.root.id}, re-attached to {ctx.agent_id}"
            )
        result.entities.extend(e for e in mapped.entities if e.id != mapped.root.id)
        result.entities.extend(a for a in mapped.agents if a.id != mapped.root.id)
        result.parties.extend(mapped.parties)
        result.evidence.extend(mapped.evidence)
        for edge in mapped.edges:
            if mapped.root.id in (edge.from_ref, edge.to_ref):
                data = edge.model_dump(mode="python", by_alias=True)
                data["from"] = ctx.agent_id if data["from"] == mapped.root.id else data["from"]
                data["to"] = ctx.agent_id if data["to"] == mapped.root.id else data["to"]
                result.edges.append(type(edge).model_validate(data))
            else:
                result.edges.append(edge)
        result.flags.extend(
            fl.replace(
                subject_ref=ctx.agent_id,
                inputs=[ctx.agent_id if i == mapped.root.id else i for i in fl.inputs],
            )
            if fl.subject_ref == mapped.root.id
            else fl
            for fl in mapped.flags
        )
        result.foreign_properties.extend(mapped.foreign_properties)
        result.warnings.extend(mapped.warnings)
        for surface, fragment in mapped.coverage.items():
            if fragment.status is CoverageStatus.NOT_ATTEMPTED:
                continue
            result.coverage[surface] = fragment
        result.add_source(
            Surface.CODE, "shadowscan-report", locator=display, ok=True, items=len(report.findings)
        )
        root = mapped.root
        updates: dict[str, Any] = {}
        if root.autonomy_assessment is not None:
            updates["autonomy_assessment"] = root.autonomy_assessment
        if root.automation_level is not None:
            updates["automation_level"] = root.automation_level
        if root.tags:
            updates["tags"] = list(root.tags)
        if root.foreign:
            updates["foreign"] = dict(root.foreign)
        if root.autonomy_profile:
            updates["autonomy_profile"] = list(root.autonomy_profile)
        if root.framework is not None:
            updates["framework"] = root.framework
        result.root_updates = updates
        result.status = CollectorStatus.OK if report.complete else CollectorStatus.PARTIAL
        result.reason = None if report.complete else "shadowscan report incomplete"
        return result


__all__ = ["DEFAULT_REPORT_NAMES", "OPTION_KEY", "SCOPE_KEY", "ShadowScanReportCollector"]
