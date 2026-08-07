#!/bin/bash
# Launcher for sqlmap — runs under the sqlmap venv (PEP 668 safe).
# Override with VHS_SQLMAP_HOME.
set -euo pipefail
S="${VHS_SQLMAP_HOME:-${HOME}/tools/sqlmap}"
BIN="${S}/bin/sqlmap"
if [ ! -x "$BIN" ]; then
    echo "FATAL: sqlmap venv binary not found: $BIN" >&2
    exit 2
fi
exec env -u PYTHONPATH "$BIN" "$@"
