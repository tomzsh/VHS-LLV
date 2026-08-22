#!/bin/bash
# Launcher for sqlmap — runs under the sqlmap venv (PEP 668 safe).
# Override with VHS_SQLMAP_HOME.
#
# Optional bounded preset for blind/OOB detection workflows:
#   VHS_SQLMAP_PRESET=blind  prepends --batch --level=3 --risk=2 --technique=BT
#                            (boolean + time-based only; no stacked/file writes)
# Add --dns-domain=<your-collaborator-domain> for OOB confirmation when the
# engagement explicitly allows OAST (allowed_methods includes 'oast').
#
# Controlled-impact takeover flags (--os-shell, --os-pwn, --os-cmd, --privileged,
# --msf-path) are refused: interactive post-exploitation stays manual by design.
set -euo pipefail
S="${VHS_SQLMAP_HOME:-${HOME}/tools/sqlmap}"
BIN="${S}/bin/sqlmap"
if [ ! -x "$BIN" ]; then
    echo "FATAL: sqlmap venv binary not found: $BIN" >&2
    exit 2
fi

for arg in "$@"; do
    case "$arg" in
        --os-shell|--os-pwn|--os-cmd|--privileged|--msf-path*)
            echo "FATAL: $arg is controlled-impact and not automated by VHS; run it manually under a separately approved test plan." >&2
            exit 2
            ;;
    esac
done

PRESET_ARGS=()
if [ "${VHS_SQLMAP_PRESET:-}" = "blind" ]; then
    PRESET_ARGS=(--batch --level=3 --risk=2 --technique=BT)
fi

exec env -u PYTHONPATH "$BIN" "${PRESET_ARGS[@]}" "$@"
