#!/usr/bin/env bash
# make_deliverables.sh — P6 report generation from engagement ledgers via officecli.
#
# Produces, inside <engagement-dir>/deliverables/:
#   final-report.docx   executive report (title + headings + findings table)
#   findings.xlsx       findings-index.csv imported with header/filter
#   evidence.xlsx       evidence-ledger.csv imported with header/filter
#   assets.xlsx         asset-inventory.csv imported with header/filter
#
# Usage:
#   bash make_deliverables.sh <engagement-dir>
#
# Requires: officecli (https://officecli.ai), standard vhs ledger CSVs.
# Sources: redacted ledgers only — never evidence/raw.

set -euo pipefail
umask 077

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi
if [ "$#" -ne 1 ]; then
  usage >&2
  exit 2
fi

ENG="$1"
ENG="$(cd "$ENG" && pwd)"

if ! command -v officecli >/dev/null 2>&1; then
  echo "[!] officecli not found — install: curl -fsSL https://d.officecli.ai/install.sh | bash" >&2
  exit 1
fi

OUT="$ENG/deliverables"
mkdir -p "$OUT"
cd "$OUT"

# Title from engagement.json if present
TITLE="Security Assessment"
if [ -f "$ENG/engagement.json" ]; then
  TITLE=$(python3 - "$ENG/engagement.json" <<'PY' 2>/dev/null || echo "Security Assessment"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle).get("title", "Security Assessment"))
PY
  )
fi

echo "[*] building deliverables in $OUT"

# ---- final-report.docx ----
DOCX="$OUT/final-report.docx"
officecli create "$DOCX" >/dev/null 2>&1
officecli set "$DOCX" / --prop docDefaults.font=Arial --prop docDefaults.fontSize=11pt >/dev/null 2>&1
officecli add "$DOCX" /body --type paragraph --prop text="$TITLE" --prop style=Title >/dev/null 2>&1
officecli add "$DOCX" /body --type paragraph --prop text="Generated $(date -u '+%Y-%m-%d %H:%M UTC')" --prop style=Normal >/dev/null 2>&1

# Findings summary table from findings-index.csv (if any)
if [ -s "$ENG/findings-index.csv" ]; then
  # count data rows
  N=$(($(wc -l < "$ENG/findings-index.csv") - 1))
  if [ "$N" -gt 0 ]; then
    officecli add "$DOCX" /body --type paragraph --prop text="Findings Summary" --prop style=Heading1 >/dev/null 2>&1
    officecli add "$DOCX" /body --type paragraph --prop text="$(python3 - "$ENG/findings-index.csv" <<'PY'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1], encoding='utf-8')))
from collections import Counter
c = Counter((r.get('severity') or 'n/a').strip() for r in rows)
print(f"{len(rows)} findings: " + ", ".join(f"{k}={v}" for k, v in sorted(c.items())))
PY
)" --prop style=Normal >/dev/null 2>&1
  fi
fi
if ! officecli close "$DOCX" >/dev/null 2>&1; then
  echo "[!] close failed for $DOCX" >&2
  exit 1
fi
echo "[+] $DOCX"

# ---- xlsx exports (import ledger CSVs) ----
import_csv() { # $1 source csv  $2 target xlsx  $3 sheet
  local src="$1" tgt="$2" sheet="$3"
  if [ ! -s "$src" ]; then
    echo "[.] skip $src (empty/missing)"
    return
  fi
  if ! officecli create "$tgt" >/dev/null 2>&1; then
    echo "[!] create failed for $tgt" >&2
    return 1
  fi
  # drop pre-existing default sheet if the file was just created fresh
  if ! officecli import "$tgt" "$sheet" --file "$src" --header >/dev/null 2>&1 \
    && ! officecli import "$tgt" "$sheet" --stdin --format csv --header < "$src" >/dev/null 2>&1; then
    echo "[!] import failed for $src" >&2
    officecli close "$tgt" >/dev/null 2>&1 || true
    return 1
  fi
  if ! officecli close "$tgt" >/dev/null 2>&1; then
    echo "[!] close failed for $tgt" >&2
    return 1
  fi
  echo "[+] $tgt"
}

import_csv "$ENG/findings-index.csv"  "$OUT/findings.xlsx"  /Sheet1
import_csv "$ENG/evidence-ledger.csv" "$OUT/evidence.xlsx"  /Sheet1
import_csv "$ENG/asset-inventory.csv" "$OUT/assets.xlsx"    /Sheet1

echo "[*] done — deliverables in $OUT"
ls -la "$OUT"
