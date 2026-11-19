#!/bin/sh
# Build the corpus, run each named source tree over it and print the comparison.
#   sh run_all.sh PYTHON OUT label=TREE [label=TREE ...]
#   sh run_all.sh .venv/bin/python /tmp/cred main=/checkouts/main fix=/checkouts/fix
# PYTHON needs the project's dependencies; each TREE is a checkout root with src/ in it.
# About six minutes per tree on an idle core.
set -e
S=$(cd "$(dirname "$0")" && pwd); PY=$1; OUT=$2; shift 2
export PYTHONDONTWRITEBYTECODE=1
"$PY" -I "$S/corpus.py" build "$OUT/corpus"
mkdir -p "$OUT/results" "$OUT/home"
labels=""
for pair in "$@"; do
  label=${pair%%=*}; tree=${pair#*=}
  (cd "$tree" && HOME="$OUT/home" PYTHONPATH=src "$PY" -B "$S/run_tree.py" "$label" "$OUT/corpus" "$OUT/results/$label.jsonl")
  labels="$labels $label"
done
"$PY" -I "$S/compare.py" "$OUT/corpus" "$OUT/results" $labels --by-shape
