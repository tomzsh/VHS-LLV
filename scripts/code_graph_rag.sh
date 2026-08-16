#!/usr/bin/env bash
# Local Code-Graph-RAG launcher for VHS.
# Override the binary with VHS_CODE_GRAPH_RAG_BIN.
set -euo pipefail

if [ -n "${VHS_CODE_GRAPH_RAG_BIN:-}" ]; then
    BIN="$VHS_CODE_GRAPH_RAG_BIN"
else
    BIN="$(command -v cgr 2>/dev/null || true)"
    if [ -z "$BIN" ] && [ -x "${HOME}/.local/bin/cgr" ]; then
        BIN="${HOME}/.local/bin/cgr"
    fi
    if [ -z "$BIN" ]; then
        BIN="$(command -v code-graph-rag 2>/dev/null || true)"
    fi
fi

if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    echo "FATAL: Code-Graph-RAG CLI not found; install cgr or set VHS_CODE_GRAPH_RAG_BIN" >&2
    exit 2
fi

exec env -u PYTHONPATH "$BIN" "$@"
