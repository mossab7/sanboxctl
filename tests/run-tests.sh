#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT" python3 -m unittest discover -s tests -p 'test_*.py' -v
