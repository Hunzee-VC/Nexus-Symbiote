"""Compare result files of several trees over the corpus.

    python compare.py <corpus dir> <results dir> <tree> [<tree> ...] [--lost BASE NEW] [--by-shape]

Prints, per tree, how many labelled credentials and how many benign values raise a
credential finding. --lost lists credentials BASE reports and NEW does not, and benign
values NEW reports and BASE does not. --by-shape adds one row per shape.
"""
import json, sys
from collections import Counter, defaultdict
from pathlib import Path
args = sys.argv[1:]
corpus, results = Path(args[0]), Path(args[1])
rest = args[2:]
lost = None
by_shape = "--by-shape" in rest
if by_shape: rest.remove("--by-shape")
if "--lost" in rest:
    i = rest.index("--lost"); lost = (rest[i + 1], rest[i + 2]); rest = rest[:i] + rest[i + 3:]
trees = rest
manifest = json.loads((corpus / "manifest.json").read_text())
data = {}
for tree in sorted(set(trees) | set(lost or ())):
    rows = [json.loads(line) for line in (results / f"{tree}.jsonl").read_text().splitlines()[1:]]
    data[tree] = {r["id"]: r for r in rows}
    assert len(data[tree]) == len(manifest), (tree, len(data[tree]))
n = Counter(c["label"] for c in manifest)
print(f"| tree | credentials reported (of {n['credential']}) | benign values reported (of {n['benign']}) | cases with a hit of the planted value that main lacks |")
print("| --- | --- | --- | --- |")
for tree in trees:
    cred = sum(bool(data[tree][c["id"]]["findings"]) for c in manifest if c["label"] == "credential")
    ben = sum(bool(data[tree][c["id"]]["findings"]) for c in manifest if c["label"] == "benign")
    whole = sum(any(h["kind"].split(":")[1] in ("whole", "percent-encoded", "sha256", "sha1", "md5") for h in data[tree][c["id"]]["leaks"]) for c in manifest if c["label"] == "credential")
    print(f"| {tree} | {cred} ({100 * cred / n['credential']:.1f}%) | {ben} ({100 * ben / n['benign']:.1f}%) | whole value or digest of a credential: {whole} |")
if by_shape:
    for label in ("credential", "benign"):
        shapes = defaultdict(list)
        for c in manifest:
            if c["label"] == label: shapes[c["shape"]].append(c["id"])
        print(f"\n| {label} shape | cases | " + " | ".join(trees) + " |")
        print("| --- | --- | " + " | ".join("---" for _ in trees) + " |")
        for shape in sorted(shapes):
            print(f"| {shape} | {len(shapes[shape])} | " + " | ".join(str(sum(bool(data[t][i]["findings"]) for i in shapes[shape])) for t in trees) + " |")
if lost:
    base, new = lost
    print(f"\ncredentials {base} reports and {new} does not:")
    for c in manifest:
        if c["label"] == "credential" and data[base][c["id"]]["findings"] and not data[new][c["id"]]["findings"]:
            print(f"  {c['id']} {c['origin']} {c['shape']} [{c['position']}] {c['name']}={c['value'][:60]!r}")
    print(f"\ncredentials {new} reports and {base} does not:")
    for c in manifest:
        if c["label"] == "credential" and not data[base][c["id"]]["findings"] and data[new][c["id"]]["findings"]:
            print(f"  {c['id']} {c['origin']} {c['shape']} [{c['position']}] {c['name']}={c['value'][:60]!r}")
    print(f"\nbenign values {new} reports and {base} does not:")
    for c in manifest:
        if c["label"] == "benign" and not data[base][c["id"]]["findings"] and data[new][c["id"]]["findings"]:
            print(f"  {c['id']} {c['origin']} {c['shape']} [{c['position']}] {c['name']}={c['value'][:60]!r}")
