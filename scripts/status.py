#!/usr/bin/env python3
"""Engagement status summary.

Prints current phase, gate history, and per-ledger counts (open hypotheses,
test states, evidence, findings) in one compact view. Useful when resuming an
engagement or before a gate review.

Usage:
  python3 status.py <engagement-dir> [--json]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path


def read_csv_counts(root: Path, name: str) -> Counter:
    path = root / name
    counts: Counter = Counter()
    if not path.is_file():
        return counts
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            # status column names vary per ledger
            for col in ("status", "scope_status", "redaction_status", "disclosure_status", "retest_status"):
                if row.get(col):
                    counts[f"{col}={row[col].strip()}"] += 1
                    break
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("engagement_dir")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    root = Path(args.engagement_dir).expanduser().resolve()
    state_path = root / "state.json"
    if not state_path.is_file():
        print(f"[!] no state.json in {root} — not an engagement dir?", file=sys.stderr)
        return 1

    state = json.loads(state_path.read_text(encoding="utf-8"))
    phases = state.get("phases", {})
    current = state.get("current_phase", "?")

    summary = {
        "engagement_dir": str(root),
        "current_phase": current,
        "phase_status": {p: (ph.get("status") if isinstance(ph, dict) else "?") for p, ph in sorted(phases.items())},
        "ledgers": {},
    }
    for name in ("asset-inventory.csv", "surface-inventory.csv", "hypothesis-ledger.csv",
                 "test-matrix.csv", "evidence-ledger.csv", "findings-index.csv"):
        summary["ledgers"][name] = dict(read_csv_counts(root, name))

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    print(f"=== {root.name} — phase {current} ===")
    order = ["P0", "P1", "P2", "P3", "P4", "P5", "P6"]
    line = []
    for p in order:
        st = (phases.get(p, {}).get("status") if isinstance(phases.get(p), dict) else "?") or "?"
        mark = {"completed": "✅", "in_progress": "🔄", "pending": "⬜"}.get(st, "❓")
        line.append(f"{p}:{mark}")
    print(" ".join(line))
    print()
    for name, counts in summary["ledgers"].items():
        if not counts:
            continue
        short = name.replace("-inventory.csv", "").replace("-ledger.csv", "").replace("-matrix.csv", "").replace("-index.csv", "")
        parts = [f"{v} {k.split('=', 1)[-1]}" for k, v in sorted(counts.items())]
        print(f"{short:16s} {', '.join(parts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
