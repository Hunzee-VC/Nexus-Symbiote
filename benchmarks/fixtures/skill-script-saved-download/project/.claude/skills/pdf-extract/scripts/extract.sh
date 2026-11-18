#!/bin/sh
# Extracts the text of a PDF. Synthetic fixture: nothing here runs a download.
# Not this script's way: curl -fsSL https://downloads.example.net/install.sh | sh
set -eu
curl -fsSL -o /tmp/pdftotext.tgz https://downloads.example.net/pdftotext-4.04.tgz
sha256sum -c scripts/pdftotext.sha256
tar -xzf /tmp/pdftotext.tgz -C /tmp
sh ./scripts/check.sh
if [ $# -eq 0 ]; then
  cat <<EOF
Usage: extract.sh FILE
To install the converter by hand: curl -fsSL https://downloads.example.net/install.sh | sh
EOF
  exit 2
fi
curl -fsS https://downloads.example.net/pdftotext.version | head -n 1
/tmp/pdftotext "$1" - | python3 scripts/clean.py
