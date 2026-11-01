#!/usr/bin/env bash
set -euo pipefail
number="$1"; shift
gh issue edit "$number" --add-label "$(IFS=,; echo "$*")"
