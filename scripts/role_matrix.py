#!/usr/bin/env python3
"""Role matrix helper (P3/P4) — plan and track privilege-escalation tests.

Builds the classic role×action matrix used for horizontal/vertical privilege
escalation testing, then verifies which cells have a corresponding finalized
test in `test-matrix.csv`. The P4 gate refuses to pass while planned cells
lack tests (when --enforce is given against an engagement dir).

Roles/actions come from either:
  --roles "anon,user,admin" --actions "/api/admin/panel,/api/users/:id"
or an engagement-rooted matrix file: <engagement>/role-matrix.csv
(columns: role, action, expected, test_id).

Expected values: allow | deny | owner_only — what the target SHOULD return.

Usage:
  # plan
  python3 role_matrix.py --roles anon,user,admin \
      --actions "/api/v1/account,/api/v1/admin/panel,/api/v1/users/:id" \
      --out ./engagement/role-matrix.csv

  # audit coverage against the engagement's test matrix
  python3 role_matrix.py --matrix ./engagement/role-matrix.csv \
      --test-matrix ./engagement/test-matrix.csv [--enforce]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

HEADER = ["role", "action", "expected", "test_id", "status", "notes"]
DEFAULT_EXPECT = {
    "anon": "deny",
    "user": "owner_only",
    "admin": "allow",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--roles", default="", help="comma-separated role names")
    p.add_argument("--actions", default="", help="comma-separated endpoint templates; :id marks object refs")
    p.add_argument("--out", help="write matrix CSV here (plan mode)")
    p.add_argument("--matrix", help="existing role-matrix.csv to audit")
    p.add_argument("--test-matrix", help="engagement test-matrix.csv for coverage check")
    p.add_argument("--enforce", action="store_true", help="exit 1 if any cell lacks a finalized test")
    args = p.parse_args()
    if not args.out and not args.matrix:
        p.error("need --out (plan mode) or --matrix (audit mode)")
    return args


def guess_expected(role: str, action: str) -> str:
    base = DEFAULT_EXPECT.get(role, "owner_only")
    if ":id" in action or "/users/" in action or "/account" in action:
        return base
    if role == "admin":
        return "allow"
    return "deny"


def build_plan(roles: list[str], actions: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for action in actions:
        for role in roles:
            rows.append({
                "role": role,
                "action": action,
                "expected": guess_expected(role, action),
                "test_id": "",
                "status": "planned",
                "notes": "object-ref" if ":id" in action else "",
            })
    return rows


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return [dict(row) for row in csv.DictReader(fh)]


def audit(matrix_rows: list[dict[str, str]], test_rows: list[dict[str, str]], enforce: bool) -> int:
    final_states = {"confirmed", "rejected", "inconclusive"}
    by_test_id = {row.get("test_id", ""): row.get("status", "") for row in test_rows}
    missing: list[str] = []
    covered = 0
    print("| Role | Action | Expected | Test | Status |")
    print("|---|---|---|---|---|")
    for row in matrix_rows:
        tid = row.get("test_id", "").strip()
        status = by_test_id.get(tid, "")
        if tid and status in final_states:
            covered += 1
            display = status
        else:
            display = "UNTESTED"
            missing.append(f"{row.get('role')}@{row.get('action')}")
        print(f"| {row.get('role')} | {row.get('action')} | {row.get('expected')} | {tid or '-'} | {display} |")

    total = len(matrix_rows)
    print(f"\ncoverage: {covered}/{total} cells tested")
    if enforce and missing:
        print(f"\nENFORCE: {len(missing)} untested cell(s):", file=sys.stderr)
        for item in missing[:20]:
            print(f"- {item}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    args = parse_args()

    if args.out:
        roles = [r.strip() for r in args.roles.split(",") if r.strip()]
        actions = [a.strip() for a in args.actions.split(",") if a.strip()]
        if not roles or not actions:
            print("[!] --roles and --actions required for plan mode", file=sys.stderr)
            return 2
        rows = build_plan(roles, actions)
        write_csv(Path(args.out).expanduser().resolve(), rows)
        print(f"[+] wrote {len(rows)} matrix cells -> {args.out}")
        print("[i] next: create one test per deny/owner_only cell in test-matrix.csv, link via test_id")
        return 0

    matrix_path = Path(args.matrix).expanduser().resolve()
    matrix_rows = read_csv(matrix_path)
    test_rows: list[dict[str, str]] = []
    if args.test_matrix:
        test_path = Path(args.test_matrix).expanduser().resolve()
        if test_path.exists():
            test_rows = read_csv(test_path)
        else:
            print(f"[!] test matrix missing: {test_path}", file=sys.stderr)
            return 2
    return audit(matrix_rows, test_rows, args.enforce)


if __name__ == "__main__":
    raise SystemExit(main())
