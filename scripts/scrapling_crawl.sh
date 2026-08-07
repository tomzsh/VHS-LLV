#!/bin/bash
# Launcher for scrapling_crawl.py — clears PYTHONPATH, then runs under the
# scrapling venv (same pattern as crawl4ai_crawl.sh).
# Override with VHS_SCRAPLING_HOME (dir containing bin/python) or
# VHS_SCRAPLING_PYTHON (explicit interpreter path).
set -euo pipefail
S="${VHS_SCRAPLING_HOME:-${HOME}/tools/scrapling/venv}"
PY="${VHS_SCRAPLING_PYTHON:-$S/bin/python}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -x "$PY" ]; then
    echo "FATAL: scrapling venv python not found: $PY" >&2
    exit 2
fi

env -u PYTHONPATH NO_COLOR=1 "$PY" "$SCRIPT_DIR/scrapling_crawl.py" "$@"
