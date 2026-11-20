#!/usr/bin/env python3
"""Run Cisco AI BOM's deterministic Tier-1 scanners without the LLM stage.

``cisco-aibom analyze`` always requires an LLM provider (Tier 3). This driver
calls the same scanner entry point the tool's own agent wrapper uses
(``aibom.agentic.tools``: ``ScanContext(paths=[path])`` then
``run_scanners``) so that the benchmark can record Tier-1 candidates offline.
The result is NOT the shipped CLI's output: Tier 2 cross-referencing and the
Tier 3 LLM classification that the vendor says removes false positives are
not applied. The report labels it accordingly.

    cisco-venv/bin/python cisco_tier1.py CORPUS OUT.json
"""

from __future__ import annotations

import dataclasses
import json
import sys


def to_jsonable(obj):
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if hasattr(obj, "__dict__"):
        return {k: to_jsonable(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return obj if isinstance(obj, (str, int, float, bool)) or obj is None else str(obj)


def main() -> None:
    corpus, out = sys.argv[1], sys.argv[2]
    from aibom.models.scan import ScanContext
    from aibom.scanners.base import run_scanners

    ctx = ScanContext(paths=[corpus])
    components, relationships = run_scanners(ctx)
    doc = {
        "note": "Cisco AI BOM Tier-1 scanner candidates only; Tier 2/3 not applied",
        "components": to_jsonable(components),
        "relationships": to_jsonable(relationships),
    }
    with open(out, "w") as fh:
        json.dump(doc, fh, indent=2, default=str)
    print(f"{len(components)} candidates, {len(relationships)} relationships")


if __name__ == "__main__":
    main()
