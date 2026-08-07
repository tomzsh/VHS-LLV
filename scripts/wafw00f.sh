#!/bin/bash
# Launcher for wafw00f — runs under the wafw00f venv (PEP 668 safe).
# Override with VHS_WAFW00F_HOME (dir containing bin/wafw00f).
set -euo pipefail
W="${VHS_WAFW00F_HOME:-/home/tomz/tools/wafw00f}"
BIN="${W}/bin/wafw00f"
if [ ! -x "$BIN" ]; then
    echo "FATAL: wafw00f venv binary not found: $BIN" >&2
    exit 2
fi
exec env -u PYTHONPATH "$BIN" "$@"
