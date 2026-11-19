"""Replace or append rows of a results file by case id.

    python merge_rows.py <results.jsonl> <rows.jsonl> [<rows.jsonl> ...]
"""
import json, sys
from pathlib import Path
base = Path(sys.argv[1])
lines = base.read_text().splitlines()
head = json.loads(lines[0])
rows = {json.loads(line)["id"]: line for line in lines[1:]}
for extra in sys.argv[2:]:
    more = Path(extra).read_text().splitlines()
    assert json.loads(more[0])["source"] == head["source"], (more[0], head)
    for line in more[1:]:
        rows[json.loads(line)["id"]] = line
head["cases"] = len(rows)
base.write_text("\n".join([json.dumps(head), *(rows[i] for i in sorted(rows))]) + "\n")
print(base.name, head["cases"], "cases")
