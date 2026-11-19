"""Triage of the planted-value hits: which needle matched, and whether main has the same hit.

    python leak_triage.py <corpus dir> <results dir>
"""
import json, sys
from collections import Counter, defaultdict
from pathlib import Path
corpus, results = Path(sys.argv[1]), Path(sys.argv[2])
manifest = {c["id"]: c for c in json.loads((corpus / "manifest.json").read_text())}
data = {}
for tree in ("main", "pr255", "pr259"):
    rows = [json.loads(line) for line in (results / f"{tree}.jsonl").read_text().splitlines()[1:]]
    data[tree] = {r["id"]: r for r in rows}
def needle(case, kind):
    source = case["secret"] if kind.startswith("secret") else case["value"]
    part = kind.split(":")[1]
    return source[:6] if part == "prefix6" else source[-6:] if part == "suffix6" else source
for label in ("credential", "benign"):
    print(f"\n=== {label} cases ===")
    for tree in ("main", "pr255", "pr259"):
        groups = Counter(); examples = {}
        new_cases = set()
        for cid, row in data[tree].items():
            case = manifest[cid]
            if case["label"] != label: continue
            base = {(h["kind"], h["output"]) for h in data["main"][cid]["leaks"]}
            for h in row["leaks"]:
                kind = h["kind"].split(":")[1]
                text = needle(case, h["kind"])
                is_new = (h["kind"], h["output"]) not in base
                groups[(kind, text if kind != "whole" else "<whole value>", is_new)] += 1
                examples.setdefault((kind, text if kind != "whole" else "<whole value>", is_new), (cid, h["output"], h.get("extent"), h["context"].replace("\n", " ")[:150], case["value"][:50]))
                if is_new: new_cases.add(cid)
        print(f"\n--- {tree}: {sum(groups.values())} hits; cases with a hit that main does not have in the same output: {len(new_cases)}")
        for (kind, text, is_new), count in sorted(groups.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1])):
            if tree == "main" and count < 6 and label == "benign": continue
            if tree != "main" and not is_new: continue
            cid, output, extent, context, value = examples[(kind, text, is_new)]
            print(f"  {count:4d} x {kind:8s} {text!r:22s} new={is_new} e.g. {cid} in {output} extent={extent} value={value!r}\n         context: {context!r}")
