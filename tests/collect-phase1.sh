#!/usr/bin/env bash
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=${APPSBX_LOG_DIR:-"$ROOT/test-logs/phase1-$STAMP"}
mkdir -p "$OUT"

run_capture() {
    name=$1
    shift
    "$@" >"$OUT/$name.stdout" 2>"$OUT/$name.stderr"
    status=$?
    printf '%s\n' "$status" >"$OUT/$name.status"
}

printf 'appsbx phase1 collection\n' >"$OUT/manifest.txt"
printf 'collection format: stdout/stderr/status per command\n' >>"$OUT/manifest.txt"

run_capture unit-tests env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT" \
    python3 -m unittest discover -s "$ROOT/tests" -p 'test_*.py' -v
run_capture profile-list "$ROOT/sandboxctl" profile list
run_capture profile-validate "$ROOT/sandboxctl" profile validate example
run_capture capabilities "$ROOT/sandboxctl" capabilities
run_capture probe "$ROOT/sandboxctl" probe
run_capture network-status "$ROOT/sandboxctl" net status 1

if [[ -n "${APPSBX_APPIMAGE:-}" ]]; then
    run_capture rootfs-inspect "$ROOT/sandboxctl" rootfs inspect "$APPSBX_APPIMAGE"
fi

if [[ -n "${APPSBX_APP_ROOT:-}" ]]; then
    run_capture run-plan "$ROOT/sandboxctl" run --profile example --mode stub \
        --app-root "$APPSBX_APP_ROOT" -- /opt/app/zaap
else
    run_capture run-plan "$ROOT/sandboxctl" run --profile example --mode stub \
        -- /opt/app/zaap
fi

printf '%s\n' "$OUT"
