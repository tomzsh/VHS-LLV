#!/usr/bin/env python3
"""Capture evidence and append it to the engagement evidence-ledger.csv.

Atomic-ish helper: writes a raw evidence file under evidence/raw/, computes its
SHA-256, write a matching redacted copy under evidence/redacted/, and appends a
row to evidence-ledger.csv.

Usage:
  python3 evidence_capture.py <engagement-dir> [...options]

Examples:
  # capture from an existing file that is already redacted
  python3 evidence_capture.py ./engagement \
      --evidence-id EV-004 --asset AST-004 --hypothesis HYP-001 --test TST-002 \
      --observation "cross-account portfoio returned 200" \
      --file response.json --sensitivity confidential --redacted

  # capture from stdin (e.g. a curl body piped in), auto-hash
  curl -s ... | python3 evidence_capture.py ./engagement --evidence-id EV-005 \
      --asset AST-004 --observation "401 on /bank-details" --stdin ev005.txt

Options:
  --evidence-id ID      required EV-### (unique)
  --asset AST-###       asset id (required by ledger schema)
  --hypothesis HYP-###  optional hypothesis id
  --test TST-###        optional test id
  --finding F-###       optional finding id
  --observation TEXT    captured observation (required)
  --file PATH           copy an existing file into evidence/  (raw unless --redacted)
  --stdin NAME          read content from stdin into a file named NAME
  --sensitivity TEXT    confidential | internal | public (default confidential)
  --redacted            mark the captured file as already redacted (skip redact copy)
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def existing_evidence_ids(root: Path) -> set[str]:
    path = root / "evidence-ledger.csv"
    if not path.exists():
        return set()
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.reader(fh))
    return {r[0] for r in rows[1:] if r}


def append_ledger(root: Path, row: list[str]) -> None:
    path = root / "evidence-ledger.csv"
    header = ["evidence_id", "captured_at_utc", "hypothesis_id", "test_id",
              "finding_id", "asset_id", "path", "sha256", "sensitivity",
              "redaction_status", "observation", "cleanup_status"]
    rows: list[list[str]] = []
    if path.exists():
        with path.open(encoding="utf-8", newline="") as fh:
            rows = list(csv.reader(fh))
        if rows and rows[0] != header:
            # tolerate pre-existing header variants only if first row = header
            print(f"[!] evidence-ledger.csv header mismatch; not appending", file=sys.stderr)
            shutil.copy(path, root / "evidence-ledger.csv.bak")
            print(f"[!] backed up to evidence-ledger.csv.bak", file=sys.stderr)
            rows = [header]
    else:
        rows = [header]
    rows.append(row)
    with path.open("w", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerows(rows)
    print(f"[+] appended {row[0]} to evidence-ledger.csv")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("engagement_dir")
    ap.add_argument("--evidence-id", required=True)
    ap.add_argument("--asset", required=True)
    ap.add_argument("--hypothesis", default="")
    ap.add_argument("--test", default="")
    ap.add_argument("--finding", default="")
    ap.add_argument("--observation", required=True)
    ap.add_argument("--file", default="", help="existing file to capture")
    ap.add_argument("--stdin", default="", help="read stdin into file with this name")
    ap.add_argument("--sensitivity", default="confidential")
    ap.add_argument("--redacted", action="store_true", help="file is already redacted")
    args = ap.parse_args()

    root = Path(args.engagement_dir).expanduser().resolve()
    raw_dir = root / "evidence" / "raw"
    red_dir = root / "evidence" / "redacted"
    raw_dir.mkdir(parents=True, exist_ok=True)
    red_dir.mkdir(parents=True, exist_ok=True)

    if bool(args.file) == bool(args.stdin):
        print("[!] provide exactly one of --file or --stdin", file=sys.stderr)
        return 1

    # Reject duplicate evidence ids BEFORE writing any file, so a rejected
    # capture never leaves an orphan raw artifact behind.
    if args.evidence_id in existing_evidence_ids(root):
        print(f"[!] evidence id {args.evidence_id} already present in "
              f"evidence-ledger.csv; choose a unique --evidence-id", file=sys.stderr)
        return 2

    if args.file:
        src = Path(args.file).expanduser().resolve()
        if not src.is_file():
            print(f"[!] source file not found: {src}", file=sys.stderr)
            return 1
        name = src.name
        dst_raw = raw_dir / name
        shutil.copy2(src, dst_raw)
    else:
        name = args.stdin
        dst_raw = raw_dir / name
        dst_raw.write_bytes(sys.stdin.buffer.read())

    # Raw evidence may contain unredacted PII / secrets — lock it down to the
    # owner only (SKILL.md: "Preserve raw evidence ... with restrictive
    # permissions"). Best-effort: chmod is a no-op on filesystems without it.
    try:
        dst_raw.chmod(0o600)
    except OSError:
        pass

    digest = sha256_of(dst_raw)

    # redacted copy
    if args.redacted:
        red_status = "already_redacted"
    else:
        red_copy = red_dir / name
        shutil.copy2(dst_raw, red_copy)
        try:
            red_copy.chmod(0o600)
        except OSError:
            pass
        red_status = "redacted_copy_created"

    rel = dst_raw.relative_to(root)
    row = [args.evidence_id, utc_now(), args.hypothesis, args.test, args.finding,
           args.asset, str(rel), digest, args.sensitivity, red_status,
           args.observation, "keep"]
    append_ledger(root, row)
    print(f"[+] raw:     {dst_raw}")
    print(f"[+] sha256:  {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())