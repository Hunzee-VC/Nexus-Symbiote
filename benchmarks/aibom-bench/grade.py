#!/usr/bin/env python3
"""Compute totals and grades from grades.json so the arithmetic is checkable.

    python grade.py [grades.json]

Rules (SPEC.md): dimension points = mean(criterion scores)/4 * weight; D1 and
D5 are single scores (D1 is the mean of corpus A and corpus B when D1_B is present); a criterion labeled D or A scores at most 2; N excludes
the dimension; total is normalized to the assessed weight; hard-gate caps apply.
"""

from __future__ import annotations

import json
import sys

GRADES = [(90, "A+"), (80, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]
CAP_SCORE = {"C": 69.9}


def grade(total: float) -> str:
    return next(g for floor, g in GRADES if total >= floor)


def main() -> None:
    with open(sys.argv[1] if len(sys.argv) > 1 else "grades.json") as fh:
        data = json.load(fh)
    weights = data["weights"]
    rows = []
    for tool, t in data["tools"].items():
        earned = 0.0
        assessed = 0.0
        per_dim = {}
        for dim, w in weights.items():
            v = t[dim]
            if v == "N":
                per_dim[dim] = "N"
                continue
            if dim == "D1" and "D1_B" in t:
                v = (t["D1"] + t["D1_B"]) / 2
            if isinstance(v, (int, float)):
                score = v / 4 * w
            else:
                vals = []
                for s, label in v.values():
                    vals.append(min(s, 2) if label in ("D", "A") else s)
                score = sum(vals) / len(vals) / 4 * w
            per_dim[dim] = round(score, 1)
            earned += score
            assessed += w
        total = earned / assessed * 100
        g = grade(total)
        capped = t.get("cap")
        if capped and total > CAP_SCORE[capped]:
            g = capped + " (capped)"
        flags = ", ".join(k for k in ("provisional", "not_run") if t.get(k))
        rows.append((total, tool, per_dim, g, flags, assessed))
    rows.sort(reverse=True)
    print(
        f"{'tool':24}{'total':>7}  grade        D1   D2   D3   D4   D5   D6   D7   D8   D9  flags"
    )
    for total, tool, pd, g, flags, assessed in rows:
        dims = "".join(f"{str(pd[d]):>5}" for d in weights)
        norm = "" if assessed == 100 else f" (of {int(assessed)})"
        print(f"{tool:24}{total:7.1f}  {g:12}{dims}  {flags}{norm}")


if __name__ == "__main__":
    main()
