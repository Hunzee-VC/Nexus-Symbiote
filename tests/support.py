"""Helpers shared by test modules; fixtures that wrap them live in conftest.py."""

from __future__ import annotations

import importlib.util
import sys
import time
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def load_script(name: str) -> ModuleType:
    """Import scripts/<name>.py once, by its own name, with its sibling scripts importable."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve string annotations through sys.modules.
    sys.modules[name] = module
    added = str(SCRIPTS) not in sys.path
    if added:
        sys.path.insert(0, str(SCRIPTS))
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    finally:
        if added:
            sys.path.remove(str(SCRIPTS))
    return module


def scaling_ratio(run: Callable[[int], object], factor: int = 4, repeats: int = 2) -> float:
    """CPU time of run(factor) over run(1), each the best of ``repeats`` runs.

    Linear work grows about ``factor`` times, quadratic work about ``factor`` squared. Two
    sizes measured on the same machine cancel what an absolute bound cannot: a slow or busy
    runner and coverage tracing.
    """

    def best(scale: int) -> float:
        timings = []
        for _ in range(repeats):
            iterations = 1
            started = time.process_time()
            run(scale)
            elapsed = time.process_time() - started
            while elapsed < 2e-3 and iterations < 32:
                iterations *= 2
                started = time.process_time()
                for _ in range(iterations):
                    run(scale)
                elapsed = time.process_time() - started
            timings.append(elapsed / iterations)
        return max(min(timings), 1e-5)

    return best(factor) / best(1)


def otlp_attribute(key: str, value: object) -> dict[str, object]:
    """One OTLP/JSON attribute: a string as stringValue, an int as intValue, a dict as is."""
    if isinstance(value, dict):
        return {"key": key, "value": value}
    if isinstance(value, int) and not isinstance(value, bool):
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": value}}


def otlp_span(
    attributes: dict[str, object], *, kind: int = 1, start: int | None = 1_700_000_000_000_000_000
) -> dict[str, object]:
    """An OTLP/JSON span with these attributes, in the order given."""
    span: dict[str, object] = {
        "traceId": "5b8efff798038103d269b633813fc60c",
        "spanId": "eee19b7ec3c1b174",
        "name": "span",
        "kind": kind,
        "attributes": [otlp_attribute(key, value) for key, value in attributes.items()],
    }
    if start is not None:
        span["startTimeUnixNano"] = str(start)
    return span


def otlp_export(
    *spans: dict[str, object], resource: dict[str, object] | None = None
) -> dict[str, object]:
    """One ExportTraceServiceRequest holding ``spans`` under one resource and scope."""
    attributes = [otlp_attribute(key, value) for key, value in (resource or {}).items()]
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": attributes},
                "scopeSpans": [{"scope": {"name": "tests"}, "spans": list(spans)}],
            }
        ]
    }
