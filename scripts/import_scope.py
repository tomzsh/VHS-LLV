#!/usr/bin/env python3
"""Import a program scope CSV (HackerOne/Bugcrowd export) into asset-inventory.csv.

Maps standard scope columns (identifier, asset_type, instruction,
eligible_for_bounty, ...) to the vhs asset-inventory schema. Rows that are
eligible for bounty/bounty submission become in_scope; others are recorded
with scope_status=out_of_scope. Unknown asset types (API, wildcard domains)
are normalized to URL where safe.

Usage:
  python3 import_scope.py <engagement-dir> --scope <program-scope.csv> [--dry-run]

Compatible with the standard H1/Bugcrowd program scope export columns:
  identifier, asset_type, instruction, eligible_for_bounty,
  eligible_for_submission, availability/confidentiality/integrity_requirement,
  max_severity, system_tags, created_at, updated_at
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

# asset-inventory.csv columns (vhs schema)
HEADER = ["asset_id", "asset", "type", "environment", "owner", "scope_status", "source", "notes"]

# normalize program asset types -> vhs types
TYPE_MAP = {
    "URL": "URL",
    "DOMAIN": "URL",
    "WILDCARD": "URL",
    "API": "URL",
    "GOOGLE_PLAY_APP_ID": "GOOGLE_PLAY_APP_ID",
    "APPLE_STORE_APP_ID": "APPLE_STORE_APP_ID",
    "WINDOWS_PHONE_APP_ID": "APPLE_STORE_APP_ID",
    "ANDROID": "GOOGLE_PLAY_APP_ID",
    "IOS": "APPLE_STORE_APP_ID",
    "OTHER": "URL",
}


def read_program_scope(path: Path) -> list[dict[str, str]]:
    """Read the program scope CSV, preserving header case variations."""
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
    if not rows:
        sys.exit(f"[!] no rows in {path}")
    # normalize keys to lowercase
    return [{k.strip().lower(): (v or "").strip() for k, v in row.items()} for row in rows]


def infer_env(identifier: str, notes: str) -> str:
    low = identifier.lower()
    if "uat" in low or "stg" in low or "stage" in low or "nonprod" in low or "test" in low:
        return "UAT"
    if "sandbox" in low or "dev" in low:
        return "sandbox"
    return "production"


def asset_id(identifier: str, index: int) -> str:
    return f"AST-{index:03d}"


def build_rows(program_rows: list[dict], source: str) -> list[list[str]]:
    out: list[list[str]] = []
    index = 0
    for row in program_rows:
        identifier = row.get("identifier") or row.get("asset_identifier") or row.get("asset")
        if not identifier:
            continue
        index += 1
        asset_type = (row.get("asset_type") or "").upper()
        vtype = TYPE_MAP.get(asset_type, "URL")
        eligible = (row.get("eligible_for_bounty") or "").lower()
        eligible_sub = (row.get("eligible_for_submission") or "").lower()
        # presence in the program scope export implies in-scope; only an
        # explicit false/none marks the asset out_of_scope (some exports leave
        # the eligibility column blank for in-scope assets)
        is_scope = eligible not in {"false", "no", "0", "n", "none"}
        is_sub = eligible_sub not in {"false", "no", "0", "n", "none"}
        # wildcard domains keep the *. prefix
        asset = identifier
        env = infer_env(identifier, row.get("instruction") or "")
        notes = (row.get("instruction") or "")[:200]
        if notes:
            notes = notes.replace("\n", " | ")[:200]
        scope = "in_scope" if (is_scope or is_sub) else "out_of_scope"
        out.append([asset_id(identifier, index), asset, vtype, env, "program", scope, source, notes])
    return out


def write_inventory(root: Path, rows: list[list[str]], dry_run: bool, force: bool = False) -> None:
    path = root / "asset-inventory.csv"
    if dry_run:
        print(f"[dry-run] would write {len(rows)} rows to {path}")
        for r in rows[:10]:
            print("  ", " | ".join(r[:5]))
        return
    # Guard against silent data loss: asset-inventory.csv may already hold
    # manually-added assets or a prior import. mode="w" would clobber them.
    if path.exists() and not force:
        with path.open(encoding="utf-8", newline="") as fh:
            existing = [r for r in csv.reader(fh) if any((c or "").strip() for c in r)]
        # more than the header row means real data is present
        if len(existing) > 1:
            raise SystemExit(
                f"[!] {path} already has {len(existing) - 1} asset row(s). "
                "Refusing to overwrite. Re-run with --force to replace it, or "
                "merge manually."
            )
    with path.open("w", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerows([HEADER] + rows)
    print(f"[+] wrote {len(rows)} asset rows to {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engagement_dir", help="engagement directory (with asset-inventory.csv)")
    parser.add_argument("--scope", required=True, help="program scope CSV (H1/BC export)")
    parser.add_argument("--dry-run", action="store_true", help="preview rows without writing")
    parser.add_argument("--force", action="store_true", help="overwrite an existing non-empty asset-inventory.csv")
    args = parser.parse_args()

    root = Path(args.engagement_dir).expanduser().resolve()
    if not root.is_dir():
        sys.exit(f"[!] engagement dir not found: {root}")
    scope_path = Path(args.scope).expanduser().resolve()
    if not scope_path.is_file():
        sys.exit(f"[!] scope CSV not found: {scope_path}")

    program_rows = read_program_scope(scope_path)
    rows = build_rows(program_rows, f"import_scope.py:{scope_path.name}")
    write_inventory(root, rows, args.dry_run, args.force)
    in_scope = sum(1 for r in rows if r[5] == "in_scope")
    print(f"[+] {len(rows)} assets imported ({in_scope} in_scope)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
