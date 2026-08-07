#!/bin/bash
# apk_recon.sh — one-shot Android APK static recon for vhs (P2 mobile surface).
#
# Decompiles an APK with jadx (Java sources) and apktool (manifest/resources),
# then extracts the high-signal static findings: exported components, deep links,
# hard-coded secrets, and API endpoints. Read-only static analysis — it never
# installs, runs, or contacts the app.
#
# Usage:
#   apk_recon.sh <target.apk> [-o OUTDIR]
#
# Output (default ./apk-recon-<basename>/):
#   jadx/            full jadx decompile (sources + resources)
#   apktool/         decoded manifest + smali + res
#   AndroidManifest.xml         copied decoded manifest
#   report/exported.txt         exported activities/services/receivers/providers
#   report/deeplinks.txt        intent-filter data schemes/hosts
#   report/secrets.txt          hard-coded key/secret/token candidates
#   report/endpoints.txt        unique http(s) URLs / hosts
#   report/summary.txt          counts + next-step hints
#
# Env overrides: VHS_JADX (jadx binary), VHS_APKTOOL (apktool binary),
#                VHS_JADX_ARGS (extra jadx flags, e.g. "--deobf").
set -euo pipefail

JADX="${VHS_JADX:-jadx}"
APKTOOL="${VHS_APKTOOL:-apktool}"
JADX_ARGS="${VHS_JADX_ARGS:-}"

die() { echo "FATAL: $*" >&2; exit 2; }

APK=""
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o|--out) OUT="$2"; shift 2 ;;
        -h|--help) grep '^#' "$0" | grep -v '^#!' | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) die "unknown option: $1" ;;
        *) APK="$1"; shift ;;
    esac
done

[ -n "$APK" ] || die "no APK given (usage: apk_recon.sh <target.apk> [-o OUTDIR])"
[ -f "$APK" ] || die "APK not found: $APK"
command -v "$JADX" >/dev/null 2>&1 || die "jadx not found (set VHS_JADX)"
command -v "$APKTOOL" >/dev/null 2>&1 || die "apktool not found (set VHS_APKTOOL)"

APK_ABS="$(cd "$(dirname "$APK")" && pwd)/$(basename "$APK")"
BASE="$(basename "$APK" | sed 's/\.[^.]*$//')"
OUT="${OUT:-./apk-recon-${BASE}}"
mkdir -p "$OUT/report"
OUT_ABS="$(cd "$OUT" && pwd)"

echo "[*] APK      : $APK_ABS"
echo "[*] Output   : $OUT_ABS"

# --- 1. decompile ---------------------------------------------------------
echo "[*] jadx decompile (this can take a while for large APKs)..."
# shellcheck disable=SC2086
"$JADX" $JADX_ARGS -d "$OUT_ABS/jadx" "$APK_ABS" >"$OUT_ABS/report/jadx.log" 2>&1 || \
    echo "[!] jadx exited non-zero (partial decompile possible) — see report/jadx.log" >&2

echo "[*] apktool decode (manifest + resources)..."
"$APKTOOL" d -f -o "$OUT_ABS/apktool" "$APK_ABS" >"$OUT_ABS/report/apktool.log" 2>&1 || \
    echo "[!] apktool exited non-zero — see report/apktool.log" >&2

MANIFEST="$OUT_ABS/apktool/AndroidManifest.xml"
[ -f "$MANIFEST" ] && cp "$MANIFEST" "$OUT_ABS/AndroidManifest.xml"

SRC="$OUT_ABS/jadx/sources"
RES="$OUT_ABS/apktool/res"

# --- 2. manifest: exported components + deep links ------------------------
if [ -f "$MANIFEST" ]; then
    echo "[*] extracting exported components + deep links..."
    grep -nE 'android:exported="true"' "$MANIFEST" > "$OUT_ABS/report/exported.txt" 2>/dev/null || true
    grep -nE '<data ' "$MANIFEST" > "$OUT_ABS/report/deeplinks.txt" 2>/dev/null || true
    grep -nE 'android:(debuggable|allowBackup|usesCleartextTraffic)="true"' "$MANIFEST" \
        >> "$OUT_ABS/report/exported.txt" 2>/dev/null || true
else
    echo "[!] no decoded manifest — skipping manifest extraction" >&2
fi

# --- 3. secrets + endpoints (jadx sources + apktool res) ------------------
GREP_TARGETS=()
[ -d "$SRC" ] && GREP_TARGETS+=("$SRC")
[ -d "$RES" ] && GREP_TARGETS+=("$RES")

if [ "${#GREP_TARGETS[@]}" -gt 0 ]; then
    echo "[*] hunting hard-coded secrets..."
    grep -rniE '(api[_-]?key|secret|passwd|password|token|app[_-]?id|app[_-]?key|tenant|sign[_-]?authcode|client[_-]?secret|private[_-]?key)\s*=\s*"[^"]+"' \
        "${GREP_TARGETS[@]}" 2>/dev/null | grep -viE '=\s*""' | sort -u > "$OUT_ABS/report/secrets.txt" || true

    echo "[*] extracting endpoints..."
    grep -rhoE 'https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=%-]+' "${GREP_TARGETS[@]}" 2>/dev/null \
        | grep -viE 'schemas\.android\.com|w3\.org|apache\.org|xmlpull\.org|json-schema\.org|example\.(com|org)|localhost|127\.0\.0\.1' \
        | sed -E 's#(https?://[a-zA-Z0-9._-]+).*#\1#' | sort -u > "$OUT_ABS/report/endpoints.txt" || true
else
    echo "[!] no sources/resources to grep" >&2
fi

# --- 4. summary -----------------------------------------------------------
count() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
{
    echo "APK static recon summary"
    echo "  apk        : $APK_ABS"
    echo "  exported   : $(count "$OUT_ABS/report/exported.txt") line(s) (report/exported.txt)"
    echo "  deep links : $(count "$OUT_ABS/report/deeplinks.txt") line(s) (report/deeplinks.txt)"
    echo "  secrets    : $(count "$OUT_ABS/report/secrets.txt") candidate(s) (report/secrets.txt)"
    echo "  endpoints  : $(count "$OUT_ABS/report/endpoints.txt") unique host(s) (report/endpoints.txt)"
    echo
    echo "Next steps:"
    echo "  - Review report/exported.txt → craft adb 'am start' PoCs (see module-android-apk.md §3)."
    echo "  - Confirm secrets: does the key work against an in-scope endpoint? public client id = not a finding."
    echo "  - Feed report/endpoints.txt hosts through scope check, then P2→P4 (api_auth_probe.py)."
    echo "  - Capture evidence with evidence_capture.py; triage in P5."
} > "$OUT_ABS/report/summary.txt"

cat "$OUT_ABS/report/summary.txt"
echo "[*] done → $OUT_ABS"
