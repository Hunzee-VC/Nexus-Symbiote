#!/usr/bin/env bash
# Run SymBiote alone, ShadowScan alone and the ShadowScan-into-SymBiote pair on the two
# corpora of another AIBOM-Bench tree (build_corpus.py and build_corpus_b.py), offline.
#
#   BENCH=/path/to/other/benchmarks/aibom-bench  SHADOWSCAN=/venv/bin/shadowscan \
#   PYTHON=/venv/bin/python  MAIN_SRC=/checkout-of-main/src  PR_SRC=/checkout-of-the-change/src \
#   OUT=/path/to/output  ./run_pair.sh
#
# Needs an unprivileged user namespace (`unshare -rn true`). Every tool runs without a
# network and with an isolated HOME. Exit codes are recorded, not acted on: the scan gate
# fails on these corpora by design.
set -u
: "${BENCH:?}" "${SHADOWSCAN:?}" "${PYTHON:?}" "${MAIN_SRC:?}" "${PR_SRC:?}" "${OUT:?}"
export SOURCE_DATE_EPOCH=1700000000
declare -A SRC=( [main]=$MAIN_SRC [change]=$PR_SRC )
mkdir -p "$OUT/home"

run() { # outdir cmd...
  local out=$1; shift
  mkdir -p "$out"
  ( HOME=$OUT/home XDG_CACHE_HOME=$OUT/home/.cache XDG_CONFIG_HOME=$OUT/home/.config \
      timeout 900 unshare -rn "$@" > "$out/stdout" 2> "$out/stderr"; echo $? > "$out/exit" )
}

for corpus in A B; do
  build=build_corpus.py; [ "$corpus" = B ] && build=build_corpus_b.py
  work=$OUT/work/$corpus; results=$OUT/results/$corpus
  rm -rf "$work" "$results"; mkdir -p "$work" "$results"
  python3 -I "$BENCH/$build" --out "$work/corpus" --manifest "$work/manifest.json" > /dev/null || exit 1
  cp -a "$work/corpus" "$work/corpus-pair"

  for format in json cyclonedx sarif; do
    run "$results/shadowscan/$format" "$SHADOWSCAN" code "$work/corpus" --format "$format" \
      -o "$results/shadowscan/$format/report.$format.json"
  done
  for tree in main change; do
    for format in json cyclonedx spdx sarif; do
      run "$results/sym-$tree/$format" env PYTHONPATH="${SRC[$tree]}" "$PYTHON" -m nexus_symbiote.cli \
        scan "$work/corpus" -f "$format" -o "$results/sym-$tree/$format/bom.$format.json"
    done
  done

  # The documented merged workflow: ShadowScan writes its report into the project,
  # then SymBiote scans the project and reads it.
  run "$results/pair-discover" "$SHADOWSCAN" code "$work/corpus-pair" --format json \
    -o "$work/corpus-pair/shadowscan.json"
  for tree in main change; do
    for format in json cyclonedx spdx sarif; do
      run "$results/pair-$tree/$format" env PYTHONPATH="${SRC[$tree]}" "$PYTHON" -m nexus_symbiote.cli \
        scan "$work/corpus-pair" -f "$format" -o "$results/pair-$tree/$format/bom.$format.json"
    done
  done
done
