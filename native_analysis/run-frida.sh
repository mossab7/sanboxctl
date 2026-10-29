#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
FRIDA_BIN="${FRIDA_BIN:-$(command -v frida || true)}"
if [[ -z "$FRIDA_BIN" ]]; then echo "error: Frida CLI is not installed" >&2; exit 127; fi
FRIDA_PYTHON="${FRIDA_PYTHON:-$(dirname "$(readlink -f "$FRIDA_BIN")")/python}"
if [[ ! -x "$FRIDA_PYTHON" ]]; then echo "error: Frida Python runtime was not found; set FRIDA_PYTHON" >&2; exit 127; fi
exec "$FRIDA_PYTHON" "$ROOT/collector.py" "$@"
