#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT="${1:-$PWD/native-analysis-output/fixture-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"
BIN="$OUT/host-info-fixture"
cc -O2 -Wall -Wextra "$ROOT/fixture/host_info_fixture.c" -o "$BIN"
"$ROOT/run-frida.sh" --duration 3 --output "$OUT/frida.ndjson" --spawn "$BIN"
python3 "$ROOT/analyze.py" --frida "$OUT/frida.ndjson" --out-dir "$OUT"
printf 'Fixture report: %s\n' "$OUT/native-host-analysis.html"
