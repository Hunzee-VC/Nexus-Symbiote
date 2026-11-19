"""Compact view of one tree's false positives or clean benign cases, by shape.

    python fp_summary.py <corpus dir> <results dir> pr255|pr259 flagged|clean [shape ...]
"""
import json, sys
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import corpus as C
corpus_dir, results, tree, want = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
shapes = set(sys.argv[5:])
rows = {r["id"]: r for r in map(json.loads, (results / f"{tree}.jsonl").read_text().splitlines()[1:])}
groups = defaultdict(list)
for case in C.CASES:
    if case["label"] != "benign" or (shapes and case["shape"] not in shapes): continue
    hit = bool(rows[case["id"]]["findings"])
    if hit != (want == "flagged"): continue
    server = case["server"] or {}
    where = case["position"]
    name = case["name"]
    if case["server"] is not None:
        for field in ("env", "headers", "http_headers"):
            m = server.get(field)
            if isinstance(m, dict) and len(m) == 1 and case["position"] in ("env", "header", "url_userinfo_env", "url_query_env"):
                name = next(iter(m))
    value = case["value"].replace("\n", "\\n")
    detail = "; ".join(f["detail"].split("in its launch: ")[-1].split(" at ", 1)[-1].rstrip(".") for f in rows[case["id"]]["findings"])
    groups[case["shape"]].append(f"{case['id']} [{where}] {name}={value[:70]}" + (f"  -> {detail[:70]}" if detail else ""))
for shape in sorted(groups):
    print(f"\n## {shape}: {len(groups[shape])}")
    for line in groups[shape]: print("  ", line)
