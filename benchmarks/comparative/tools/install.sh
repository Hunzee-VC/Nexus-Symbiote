#!/usr/bin/env bash
# Install every measured tool at its pinned version under one directory.
#
#   benchmarks/comparative/tools/install.sh /path/to/tools
#
# Needs uv, Python 3.13, Node.js 22 with npm, and Go 1.24 or newer. Python tools
# install from hash-locked requirements; cdxgen from the committed lockfile, without
# running package scripts; the Go tools at exact module versions.
set -euo pipefail

root="${1:?usage: install.sh TOOLS_DIRECTORY}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository="$(cd "$here/../../.." && pwd)"
mkdir -p "$root"
root="$(cd "$root" && pwd)"

python_tool() {
  local name="$1"
  uv venv --quiet --python 3.13 "$root/$name"
  uv pip install --quiet --python "$root/$name/bin/python" --require-hashes -r "$here/locks/$name.txt"
}

python_tool symbiote-0.1.0
python_tool agent-bom
python_tool trusera
python_tool aisbom

uv venv --quiet --python 3.13 "$root/symbiote-tree"
uv pip install --quiet --python "$root/symbiote-tree/bin/python" \
  --require-hashes --only-binary=:all: -r "$repository/requirements-ci.lock"
uv pip install --quiet --python "$root/symbiote-tree/bin/python" \
  --no-deps --no-build-isolation -e "$repository"

mkdir -p "$root/cdxgen"
cp "$here/cdxgen/package.json" "$here/cdxgen/package-lock.json" "$root/cdxgen/"
(cd "$root/cdxgen" && npm ci --ignore-scripts --no-audit --no-fund)

export GOBIN="$root/gobin" GOFLAGS=-mod=mod
go install github.com/anchore/syft/cmd/syft@v1.57.2
go install github.com/safedep/xbom@v0.0.3

echo "Tools installed under $root"
