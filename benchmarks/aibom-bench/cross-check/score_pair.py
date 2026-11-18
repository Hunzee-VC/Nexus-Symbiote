"""Per-class detection for the runs of run_pair.sh, by the other tree's own match rules.

    python3 -I score_pair.py BENCH OUT

BENCH is the other tree's benchmarks/aibom-bench directory and OUT the output directory
of run_pair.sh. A component counts when ``detect`` of that tree's score.py matches it in
the tool's outputs after ``strip_coverage`` (its strict mode). Matching is textual, so
every item the pair gains over SymBiote alone is then located in the native inventory:
a match in a component name is an identification, a match in an evidence locator is the
path of a file where something else was cited and is listed as incidental.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

BENCH, OUT = Path(sys.argv[1]), Path(sys.argv[2])
TOOLS = ("sym-main", "shadowscan", "pair-main", "pair-change")
SKIPPED = {"stdout", "stderr", "exit"}

spec = importlib.util.spec_from_file_location("other_score", BENCH / "score.py")
assert spec is not None and spec.loader is not None
other = importlib.util.module_from_spec(spec)
spec.loader.exec_module(other)


def text_of(tool: Path) -> str:
    parts = []
    for mode in sorted(p for p in tool.iterdir() if p.is_dir()):
        for file in sorted(mode.iterdir()):
            if file.name not in SKIPPED and file.is_file():
                parts.append(other.strip_coverage(file.read_bytes()).decode("utf-8", "replace"))
    return "\n".join(parts)


def strings(node: object, path: str = ""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from strings(value, f"{path}.{key}")
    elif isinstance(node, list):
        for value in node:
            yield from strings(value, path)
    elif isinstance(node, str):
        yield path, node


record: dict[str, object] = {}
for corpus, truth in (("A", "ground_truth.json"), ("B", "ground_truth_b.json")):
    ground = json.loads((BENCH / truth).read_text())
    components = ground["components"]
    hits = {}
    for tool in TOOLS:
        blob = text_of(OUT / "results" / corpus / tool)
        lower = blob.lower()
        hits[tool] = {item["id"]: other.detect(blob, lower, item) for item in components}
        hits[tool + ":decoys"] = [
            item["id"] for item in ground["decoys"] if other.detect(blob, lower, item) is not None
        ]

    inventory = json.loads(
        (OUT / "results" / corpus / "pair-change" / "json" / "bom.json.json").read_text()
    )
    located = list(strings(inventory))
    incidental = []
    for item in components:
        matched = hits["pair-change"][item["id"]]
        if matched is None or hits["sym-main"][item["id"]] is not None:
            continue
        literal = matched in item.get("match_any", [])
        pattern = re.compile(re.escape(matched), re.IGNORECASE) if literal else re.compile(matched)
        places = {path for path, text in located if pattern.search(text)}
        if places and not any(path.endswith((".name", ".bom_ref")) for path in places):
            incidental.append(item["id"])

    classes: dict[str, list[str]] = {}
    for item in components:
        classes.setdefault(item["class"], []).append(item["id"])
    print(f"\ncorpus {corpus}: {len(components)} components")
    print(
        f"{'class':14} {'n':>3} "
        + " ".join(f"{tool:>11}" for tool in TOOLS)
        + "  pair-change, reviewed"
    )
    totals = dict.fromkeys((*TOOLS, "reviewed"), 0)
    for name, ids in classes.items():
        counts = [sum(hits[tool][i] is not None for i in ids) for tool in TOOLS]
        reviewed = sum(hits["pair-change"][i] is not None and i not in incidental for i in ids)
        for tool, count in zip(TOOLS, counts, strict=True):
            totals[tool] += count
        totals["reviewed"] += reviewed
        print(
            f"{name:14} {len(ids):>3} " + " ".join(f"{c:>11}" for c in counts) + f"  {reviewed:>10}"
        )
    print(
        f"{'all':14} {len(components):>3} "
        + " ".join(f"{totals[tool]:>11}" for tool in TOOLS)
        + f"  {totals['reviewed']:>10}"
    )
    print("incidental (a path in an evidence locator, no component of that kind):", incidental)
    for tool in TOOLS:
        print(f"decoys matched, {tool}:", hits[tool + ":decoys"])
    record[corpus] = {"hits": hits, "incidental": incidental}

(OUT / "hits.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
