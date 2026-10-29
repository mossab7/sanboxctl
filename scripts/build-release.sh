#!/usr/bin/env bash
# Create a redistributable source/payload archive without local profiles,
# test artefacts, virtual environments, or the Git checkout.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-"$ROOT/dist"}
NAME="appsbx-linux-x86_64"
mkdir -p "$OUT"
ARCHIVE="$OUT/$NAME.tar.gz"
tar -C "$ROOT" -czf "$ARCHIVE" \
  --exclude=.git --exclude=.venv --exclude=my_pyside_env --exclude=pyside-setup \
  --exclude=sandbox-state --exclude=dist --exclude=__pycache__ --exclude='*.pyc' \
  --exclude='*.log' --exclude='gui-*.txt' --exclude='hardware*.txt' --exclude='software*.txt' \
  --transform="s,^,$NAME/," .
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
printf 'Created %s\nChecksum %s\n' "$ARCHIVE" "$ARCHIVE.sha256"
