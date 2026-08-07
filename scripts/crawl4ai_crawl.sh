#!/bin/bash
# Launcher for crawl4ai_crawl.py — clears PYTHONPATH, then runs under a
# crawl4ai venv. Override the legacy default with VHS_CRAWL4AI_PYTHON or
# VHS_CRAWL4AI_HOME.
set -euo pipefail
C4="${VHS_CRAWL4AI_HOME:-${HOME}/tools/crawl4ai}"
PY="${VHS_CRAWL4AI_PYTHON:-$C4/bin/python}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -x "$PY" ]; then
    echo "FATAL: crawl4ai venv python not found: $PY" >&2
    exit 2
fi

env -u PYTHONPATH NO_COLOR=1 "$PY" "$SCRIPT_DIR/crawl4ai_crawl.py" "$@"
