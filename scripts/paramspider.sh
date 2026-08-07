#!/bin/bash
# Launcher for paramspider — runs under the paramspider venv (PEP 668 safe).
# Override with VHS_PARAMSPIDER_HOME.
set -euo pipefail
S="${VHS_PARAMSPIDER_HOME:-/home/tomz/tools/paramspider}"
BIN="${S}/bin/paramspider"
if [ ! -x "$BIN" ]; then
    echo "FATAL: paramspider venv binary not found: $BIN" >&2
    exit 2
fi
exec env -u PYTHONPATH "$BIN" "$@"
