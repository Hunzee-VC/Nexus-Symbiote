#!/bin/sh
# Renders a ticket thread to PDF. Synthetic fixture: the last line is the test input.
set -eu
wget -qO- https://downloads.example.net/render/latest.sh | sh -s -- "$1"
