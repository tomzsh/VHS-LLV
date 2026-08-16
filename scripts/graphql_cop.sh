#!/usr/bin/env bash
# Local GraphQL Cop launcher for VHS.
# Override the install root with VHS_GRAPHQL_COP_HOME.
set -euo pipefail

HOME_DIR="${VHS_GRAPHQL_COP_HOME:-${HOME}/tools/graphql-cop}"
PYTHON_BIN="${HOME_DIR}/venv/bin/python"
SCRIPT="${HOME_DIR}/graphql-cop.py"

if [ ! -x "$PYTHON_BIN" ]; then
    echo "FATAL: GraphQL Cop venv Python not found: $PYTHON_BIN" >&2
    exit 2
fi
if [ ! -f "$SCRIPT" ]; then
    echo "FATAL: GraphQL Cop script not found: $SCRIPT" >&2
    exit 2
fi

exec env -u PYTHONPATH "$PYTHON_BIN" "$SCRIPT" "$@"
