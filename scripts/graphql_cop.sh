#!/usr/bin/env bash
# Local GraphQL Cop launcher for VHS.
# Override the install root with VHS_GRAPHQL_COP_HOME.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOME_DIR="${VHS_GRAPHQL_COP_HOME:-${HOME}/tools/graphql-cop}"
PYTHON_BIN="${HOME_DIR}/venv/bin/python"
SCRIPT="${HOME_DIR}/graphql-cop.py"
ENGAGEMENT=""
TARGET=""
TOOL_ARGS=()

fatal() {
    echo "FATAL: $*" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --engagement)
            [ "$#" -ge 2 ] || fatal "--engagement requires a directory"
            ENGAGEMENT="$2"
            shift 2
            ;;
        --engagement=*)
            ENGAGEMENT="${1#*=}"
            shift
            ;;
        -t|--target)
            [ "$#" -ge 2 ] || fatal "$1 requires a URL"
            [ -z "$TARGET" ] || fatal "target may be specified only once"
            TARGET="$2"
            TOOL_ARGS+=("$1" "$2")
            shift 2
            ;;
        -t=*|--target=*)
            [ -z "$TARGET" ] || fatal "target may be specified only once"
            TARGET="${1#*=}"
            TOOL_ARGS+=("$1")
            shift
            ;;
        *)
            TOOL_ARGS+=("$1")
            shift
            ;;
    esac
done

[ -n "$ENGAGEMENT" ] || fatal "--engagement is required"
[ -n "$TARGET" ] || fatal "-t/--target is required"

if ! python3 - "$SCRIPT_DIR" "$ENGAGEMENT" "$TARGET" <<'PY'
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, sys.argv[1])
from policy import PolicyError, authorize_run

try:
    target = sys.argv[3]
    parsed = urlsplit(target)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise PolicyError("target must be an HTTP(S) URL without credentials")
    _, _, policy = authorize_run(
        Path(sys.argv[2]).expanduser().resolve(),
        parsed.hostname,
        "active-safe",
    )
    if not policy.url_allowed(target):
        raise PolicyError("target URL is not permitted by the engagement scope")
except (PolicyError, ValueError) as exc:
    print(f"[!] authorization refused: {exc}", file=sys.stderr)
    raise SystemExit(2)
PY
then
    exit 2
fi

if [ ! -x "$PYTHON_BIN" ]; then
    echo "FATAL: GraphQL Cop venv Python not found: $PYTHON_BIN" >&2
    exit 2
fi
if [ ! -f "$SCRIPT" ]; then
    echo "FATAL: GraphQL Cop script not found: $SCRIPT" >&2
    exit 2
fi

exec env -u PYTHONPATH "$PYTHON_BIN" "$SCRIPT" "${TOOL_ARGS[@]}"
