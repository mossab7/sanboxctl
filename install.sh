#!/usr/bin/env bash
# Per-user bootstrap.  It never changes system packages or privileged helper
# state unless --yes is explicitly passed through to the Python installer.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
case "${1:-}" in
  check|plan|uninstall) exec python3 -m appsbx.install "$@" ;;
  *) exec python3 -m appsbx.install install "$@" ;;
esac
