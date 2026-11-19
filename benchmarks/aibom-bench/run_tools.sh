#!/usr/bin/env bash
# AIBOM-Bench runner.
#
# For every tool and mode it materializes a fresh corpus at the same path,
# runs the tool with an isolated HOME and a fixed SOURCE_DATE_EPOCH, and records
# the exit status, wall-clock seconds, stdout, stderr, the files the tool wrote
# into the corpus, and (in "network" mode) an strace of connect/execve/openat
# calls. Modes other than "network" run inside an unprivileged network
# namespace with no interfaces, so a tool that needs the network fails there.
# "airgap" and "repeat" are identical runs used for the determinism check.
#
#   RESULTS=/path/results WORK=/path/work \
#   NEXUS=/venv/bin/nexus-symbiote CDXGEN=/node_modules/.bin/cdxgen \
#   AIBOM_CLI=/node_modules/.bin/aibom AGENT_BOM=/venv/bin/agent-bom \
#   AI_BOM=/venv/bin/ai-bom AGENTBOM=/venv/bin/agentbom AI_FINDER=/venv/bin/ai-finder \
#   ./run_tools.sh [tool ...]
set -u
BENCH_DIR=$(cd "$(dirname "$0")" && pwd)
: "${RESULTS:?set RESULTS}" "${WORK:?set WORK}"
TIMEOUT=${TIMEOUT:-900}
export SOURCE_DATE_EPOCH=1700000000

run_case() { # tool mode -- cmd...   placeholders: {CORPUS} {OUT}
  local tool=$1 mode=$2; shift 2; [ "$1" = "--" ] && shift
  local out=$RESULTS/$tool/$mode base=$WORK/$tool corpus=$WORK/$tool/corpus home=$WORK/$tool/home
  rm -rf "$out" "$base"; mkdir -p "$out" "$base" "$home"
  python3 "$BENCH_DIR/${BUILD:-build_corpus.py}" --out "$corpus" --manifest "$base/manifest.json" >/dev/null
  local -a cmd=()
  for a in "$@"; do a=${a//\{CORPUS\}/$corpus}; a=${a//\{OUT\}/$out}; cmd+=("$a"); done
  printf '%q ' "${cmd[@]}" > "$out/command"; echo >> "$out/command"
  local -a wrapper=()
  case $mode in
    network*) wrapper=(strace -f -qq -s 200 -o "$out/strace.log" -e trace=connect,execve,openat,readlink) ;;
    *) wrapper=(unshare -rn) ;;
  esac
  local start end
  start=$(date +%s.%N)
  ( cd "$base" && HOME=$home XDG_CACHE_HOME=$home/.cache XDG_CONFIG_HOME=$home/.config \
      timeout "$TIMEOUT" "${wrapper[@]}" "${cmd[@]}" > "$out/stdout" 2> "$out/stderr"; echo $? > "$out/exit" )
  end=$(date +%s.%N)
  awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f\n", e-s}' > "$out/seconds"
  python3 "$BENCH_DIR/corpus_delta.py" "$corpus" "$base/manifest.json" > "$out/corpus-delta.json"
  # files the tool wrote outside the corpus and the output dir (isolated HOME)
  ( cd "$home" && find . -type f | sort ) > "$out/home-writes.txt"
  echo "[$tool/$mode] exit=$(cat "$out/exit") seconds=$(cat "$out/seconds")"
}

want() { [ $# -eq 0 ] && return 0; for t in "$@"; do [ "$t" = "$TOOL" ] && return 0; done; return 1; }
ARGS=("$@")

TOOL=nexus-symbiote
if want "${ARGS[@]}" && [ -n "${NEXUS:-}" ]; then
  for m in network airgap repeat; do
    run_case $TOOL $m -- "$NEXUS" scan "{CORPUS}" -f json -o "{OUT}/bom.json"
  done
  run_case $TOOL cyclonedx -- "$NEXUS" scan "{CORPUS}" -f cyclonedx -o "{OUT}/bom.cdx.json"
  run_case $TOOL spdx      -- "$NEXUS" scan "{CORPUS}" -f spdx -o "{OUT}/bom.spdx.json"
  run_case $TOOL sarif     -- "$NEXUS" scan "{CORPUS}" -f sarif -o "{OUT}/bom.sarif.json"
fi

TOOL=cdxgen
if want "${ARGS[@]}" && [ -n "${CDXGEN:-}" ]; then
  for m in network airgap repeat; do
    run_case $TOOL $m -- "$CDXGEN" -t ai -r --include-formulation --no-install-deps --spec-version 1.7 \
      --json-pretty --bom-audit --bom-audit-categories ai-bom -o "{OUT}/bom.json" "{CORPUS}"
  done
  run_case $TOOL aibom-cli -- "$AIBOM_CLI" --no-install-deps --json-pretty -o "{OUT}/bom.json" "{CORPUS}"
  run_case $TOOL python-js -- "$CDXGEN" -t python -t js -r --no-install-deps --spec-version 1.7 --json-pretty -o "{OUT}/bom.json" "{CORPUS}"
fi

TOOL=agent-bom
if want "${ARGS[@]}" && [ -n "${AGENT_BOM:-}" ]; then
  COMMON=(scan -p "{CORPUS}" --no-discover --no-scan --scan-prompts --model-files "{CORPUS}" --model-provenance
          --ai-inventory "{CORPUS}" --dataset-cards "{CORPUS}" --enforce --full-analysis)
  run_case $TOOL network -- "$AGENT_BOM" "${COMMON[@]}" -f json -o "{OUT}/report.json"
  for m in airgap repeat; do
    run_case $TOOL $m -- "$AGENT_BOM" "${COMMON[@]}" --offline -f json -o "{OUT}/report.json"
  done
  run_case $TOOL cyclonedx -- "$AGENT_BOM" "${COMMON[@]}" --offline -f cyclonedx -o "{OUT}/bom.cdx.json"
  run_case $TOOL spdx      -- "$AGENT_BOM" "${COMMON[@]}" --offline -f spdx -o "{OUT}/bom.spdx.json"
  run_case $TOOL sarif     -- "$AGENT_BOM" "${COMMON[@]}" --offline -f sarif -o "{OUT}/bom.sarif.json"
  run_case $TOOL skills    -- "$AGENT_BOM" --agent-mode skills scan "{CORPUS}"
fi

TOOL=trusera-ai-bom
if want "${ARGS[@]}" && [ -n "${AI_BOM:-}" ]; then
  for m in network airgap repeat; do
    run_case $TOOL $m -- "$AI_BOM" scan "{CORPUS}" --deep --quiet --no-telemetry -f json -o "{OUT}/report.json"
  done
  run_case $TOOL cyclonedx -- "$AI_BOM" scan "{CORPUS}" --deep --quiet --no-telemetry -f cyclonedx -o "{OUT}/bom.cdx.json"
  run_case $TOOL spdx      -- "$AI_BOM" scan "{CORPUS}" --deep --quiet --no-telemetry -f spdx3 -o "{OUT}/bom.spdx.json"
  run_case $TOOL sarif     -- "$AI_BOM" scan "{CORPUS}" --deep --quiet --no-telemetry -f sarif -o "{OUT}/bom.sarif.json"
fi

TOOL=ai-agentbom
if want "${ARGS[@]}" && [ -n "${AGENTBOM:-}" ]; then
  for m in network airgap repeat; do
    run_case $TOOL $m -- "$AGENTBOM" scan "{CORPUS}" --output-dir "{OUT}" --pretty --cyclonedx --sarif --mermaid
  done
fi

TOOL=ai-finder
if want "${ARGS[@]}" && [ -n "${AI_FINDER:-}" ]; then
  for m in network airgap repeat; do
    run_case $TOOL $m -- "$AI_FINDER" scan "{CORPUS}" -r -f json -o "{OUT}/report.json"
  done
  run_case $TOOL cyclonedx -- "$AI_FINDER" scan "{CORPUS}" -r -f cyclonedx -o "{OUT}/bom.cdx.json"
  run_case $TOOL spdx      -- "$AI_FINDER" scan "{CORPUS}" -r -f spdx --spdx-v3 -o "{OUT}/bom.spdx.json"
fi

TOOL=cisco-aibom
if want "${ARGS[@]}" && [ -n "${CISCO_PY:-}" ]; then
  for m in network airgap repeat; do
    run_case $TOOL $m -- "$CISCO_PY" -I "$BENCH_DIR/cisco_tier1.py" "{CORPUS}" "{OUT}/tier1.json"
  done
fi

# Alternative invocations added for the fairness re-run: each competitor gets
# the broadest documented invocation, and D1 takes the best of its runs.
TOOL=cdxgen-alt
if want "${ARGS[@]}" && [ -n "${CDXGEN:-}" ]; then
  run_case $TOOL ai-ml-profile -- "$CDXGEN" -t ai -t python -t js -r --profile ml --include-formulation --no-install-deps --spec-version 1.7 --json-pretty --evidence -o "{OUT}/bom.json" "{CORPUS}"
  run_case $TOOL deep-noignore -- "$CDXGEN" -t ai -r --deep --no-ignore --no-install-deps --spec-version 1.7 --json-pretty -o "{OUT}/bom.json" "{CORPUS}"
  run_case $TOOL mcp-only -- "$CDXGEN" -t mcp -r --no-install-deps --spec-version 1.7 --json-pretty -o "{OUT}/bom.json" "{CORPUS}"
fi
TOOL=agent-bom-alt
if want "${ARGS[@]}" && [ -n "${AGENT_BOM:-}" ]; then
  run_case $TOOL enterprise-offline -- "$AGENT_BOM" scan -p "{CORPUS}" --preset enterprise --offline --no-scan --scan-prompts --model-files "{CORPUS}" --ai-inventory "{CORPUS}" --dataset-cards "{CORPUS}" --enforce --full-analysis -f json -o "{OUT}/report.json"
  run_case $TOOL ambient-cwd -- sh -c 'cd "$1" && exec "$0" scan -p . --offline --no-scan --scan-prompts --enforce --full-analysis -f json -o "$2/report.json"' "$AGENT_BOM" "{CORPUS}" "{OUT}"
fi
TOOL=trusera-alt
if want "${ARGS[@]}" && [ -n "${AI_BOM:-}" ]; then
  run_case $TOOL nodeep -- "$AI_BOM" scan "{CORPUS}" --quiet --no-telemetry --max-file-size 64 -f json -o "{OUT}/report.json"
fi
TOOL=ai-finder-alt
if want "${ARGS[@]}" && [ -n "${AI_FINDER:-}" ]; then
  run_case $TOOL noenrich -- "$AI_FINDER" scan "{CORPUS}" -f json --no-enrich -o "{OUT}/report.json"
fi
TOOL=nexus-alt
if want "${ARGS[@]}" && [ -n "${NEXUS:-}" ]; then
  run_case $TOOL depth64 -- "$NEXUS" --limit depth=64 scan "{CORPUS}" -f json -o "{OUT}/bom.json"
fi
TOOL=cdxgen-trace
if want "${ARGS[@]}" && [ -n "${CDXGEN:-}" ]; then
  run_case $TOOL network-python -- "$CDXGEN" -t ai -t python -t js -r --profile ml --no-install-deps --spec-version 1.7 --json-pretty -o "{OUT}/bom.json" "{CORPUS}"
fi
# cdxgen with the MCP project type added, for the corpus B run and best-of
TOOL=cdxgen-mcp
if want "${ARGS[@]}" && [ -n "${CDXGEN:-}" ]; then
  for m in network airgap repeat; do
    run_case $TOOL $m -- "$CDXGEN" -t ai -t mcp -r --include-formulation --no-install-deps --spec-version 1.7 --json-pretty -o "{OUT}/bom.json" "{CORPUS}"
  done
fi
