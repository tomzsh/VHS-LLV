#!/usr/bin/env bash
# Thin compatibility wrapper. All argument parsing belongs to Python.
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/vulnhunter_orchestrator.py" "$@"
