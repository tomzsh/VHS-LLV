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
import fcntl
import hashlib
import os
import re
import shutil
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from schemas import LEDGER_SCHEMAS


EVIDENCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_filename(value: str) -> str:
    """Allow only a plain filename for stdin evidence output."""
    candidate = Path(value)
    if (
        not value
        or candidate.is_absolute()
        or candidate.name != value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
    ):
        raise ValueError("--stdin must be a plain filename, not a path")
    return value


def safe_artifact_name(evidence_id: str, source_name: str) -> str:
    if not EVIDENCE_ID_RE.fullmatch(evidence_id):
        raise ValueError("--evidence-id must be a single safe identifier")
    name = Path(source_name).name
    if not name or name in {".", ".."}:
        raise ValueError("evidence source must have a filename")
    return f"{evidence_id}-{name}"


def owner_only(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        pass


@contextmanager
def ledger_lock(root: Path):
    lock_path = root / ".evidence-ledger.lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        owner_only(lock_path, 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def existing_evidence_ids(root: Path) -> set[str]:
    path = root / "evidence-ledger.csv"
    if not path.exists():
        return set()
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.reader(fh))
    return {r[0] for r in rows[1:] if r}


def append_ledger_locked(root: Path, row: list[str]) -> None:
    path = root / "evidence-ledger.csv"
    header = LEDGER_SCHEMAS["evidence-ledger.csv"]
    rows: list[list[str]] = []
    if path.exists():
        with path.open(encoding="utf-8", newline="") as fh:
            rows = list(csv.reader(fh))
        if not rows or rows[0] != header:
            raise ValueError("evidence-ledger.csv header mismatch; not appending")
    else:
        rows = [header]
    rows.append(row)
    fd, temp_name = tempfile.mkstemp(
        prefix=".evidence-ledger.", suffix=".tmp", dir=root, text=True,
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            csv.writer(fh).writerows(rows)
            fh.flush()
            os.fsync(fh.fileno())
        owner_only(temp_path, 0o600)
        os.replace(temp_path, path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise
    print(f"[+] appended {row[0]} to evidence-ledger.csv")


def append_ledger(root: Path, row: list[str]) -> None:
    with ledger_lock(root):
        append_ledger_locked(root, row)


def copy_exclusive(source: Path, destination: Path) -> None:
    created = False
    try:
        with source.open("rb") as src, destination.open("xb") as dst:
            created = True
            shutil.copyfileobj(src, dst)
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def write_stdin_exclusive(destination: Path) -> None:
    created = False
    try:
        with destination.open("xb") as dst:
            created = True
            shutil.copyfileobj(sys.stdin.buffer, dst)
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


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
    evidence_dir = root / "evidence"
    raw_dir = root / "evidence" / "raw"
    red_dir = root / "evidence" / "redacted"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    red_dir.mkdir(parents=True, exist_ok=True)
    for directory in (evidence_dir, raw_dir, red_dir):
        owner_only(directory, 0o700)

    if bool(args.file) == bool(args.stdin):
        print("[!] provide exactly one of --file or --stdin", file=sys.stderr)
        return 1

    stdin_name = ""
    if args.stdin:
        try:
            stdin_name = safe_filename(args.stdin)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2

    if args.file:
        src = Path(args.file).expanduser().resolve()
        if not src.is_file():
            print(f"[!] source file not found: {src}", file=sys.stderr)
            return 1
        source_name = src.name
    else:
        src = None
        source_name = stdin_name

    try:
        name = safe_artifact_name(args.evidence_id, source_name)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    dst_raw = raw_dir / name
    red_copy = red_dir / name
    raw_created = False
    redacted_created = False
    try:
        with ledger_lock(root):
            # The lock covers duplicate validation, artifact creation, and
            # ledger replacement, so competing captures cannot share an ID.
            if args.evidence_id in existing_evidence_ids(root):
                raise ValueError(
                    f"evidence id {args.evidence_id} already present in "
                    "evidence-ledger.csv; choose a unique --evidence-id"
                )
            if src is not None:
                copy_exclusive(src, dst_raw)
            else:
                write_stdin_exclusive(dst_raw)
            raw_created = True
            owner_only(dst_raw, 0o600)
            digest = sha256_of(dst_raw)

            if args.redacted:
                red_status = "already_redacted"
            else:
                copy_exclusive(dst_raw, red_copy)
                redacted_created = True
                owner_only(red_copy, 0o600)
                red_status = "redacted_copy_created"

            rel = dst_raw.relative_to(root)
            row = [args.evidence_id, utc_now(), args.hypothesis, args.test, args.finding,
                   args.asset, str(rel), digest, args.sensitivity, red_status,
                   args.observation, "keep"]
            append_ledger_locked(root, row)
    except (OSError, ValueError) as exc:
        if redacted_created:
            red_copy.unlink(missing_ok=True)
        if raw_created:
            dst_raw.unlink(missing_ok=True)
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    print(f"[+] raw:     {dst_raw}")
    print(f"[+] sha256:  {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
