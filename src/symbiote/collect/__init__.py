"""Collectors: the self-writing layer that turns agent artefacts into AgentBOM facts (``spec/collectors.md``).

Public contract: :class:`~symbiote.collect.base.Collector`, :class:`~symbiote.collect.base.CollectContext`,
:class:`~symbiote.collect.base.CollectionResult`, :func:`~symbiote.collect.base.run_collectors` and
:func:`~symbiote.collect.base.merge_coverage`. Third-party collectors register under the
``symbiote.collectors`` entry-point group.
"""

from __future__ import annotations

from symbiote.collect.base import (
    BUILTIN_COLLECTORS,
    ENTRY_POINT_GROUP,
    BaseCollector,
    CollectContext,
    CollectionResult,
    Collector,
    load_collectors,
    merge_coverage,
    merge_surface,
    run_collectors,
)

__all__ = [
    "BUILTIN_COLLECTORS",
    "ENTRY_POINT_GROUP",
    "BaseCollector",
    "CollectContext",
    "CollectionResult",
    "Collector",
    "load_collectors",
    "merge_coverage",
    "merge_surface",
    "run_collectors",
]
