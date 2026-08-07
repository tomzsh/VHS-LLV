#!/usr/bin/env python3
"""Per-surface P1/P2 hunting checklist generator.

Reads the engagement surface-inventory.csv and the bundled taxonomy JSON, then
prints (or writes) a per-surface checklist of priority-1/2 variants reachable
from that surface's asset type + protocol + auth requirement.

The checklist is advisory — it maps taxonomy variants to surfaces so P2/P3 can
prioritize hypotheses. It does NOT authorize anything on its own; the P0 gate
and engagement.json remain the source of truth.

Usage:
  python3 surface_checklist.py <engagement-dir> [--out checklist.md] [--json]

Output:
  For each in_scope surface: surface id, asset, and a list of
  <priority> <taxonomy variant> <why-relevant> lines.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# default taxonomy path relative to this script
TAXONOMY = Path(__file__).resolve().parents[1] / "vulnerability-rating-taxonomy.json"

# variant relevance heuristics: surface asset-type / protocol keyword -> variant
# keywords looked up inside the taxonomy variant names/descriptions.
SURFACE_RULES = {
    "web": [
        ("bac", "idor"),
        ("bac", "admin"),
        ("ssrf", "ssrf"),
        ("xss", "stored"),
        ("oauth", "oauth"),
        ("reset", "password reset"),
        ("secret", "publicly accessible"),
    ],
    "api": [
        ("bac", "idor"),
        ("bac", "broken access"),
        ("mass", "mass assignment"),
        ("idempotency", "idempotency"),
        ("rate", "rate limit"),
        ("jwt", "jwt"),
        ("secret", "secret"),
        ("ssrf", "ssrf"),
    ],
    "mobile": [
        ("secret", "hardcoded"),
        ("exported", "exported"),
        ("storage", "storage"),
        ("pin", "ssl pinning"),
        ("root", "root detection"),
    ],
    "cloud": [
        ("iam", "iam"),
        ("bucket", "bucket"),
        ("storage", "storage"),
    ],
    "fintech": [
        ("price", "price"),
        ("order", "order"),
        ("withdraw", "withdrawal"),
        ("ledger", "ledger"),
        ("balance", "balance"),
    ],
}


def load_taxonomy(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def iter_variants(tax: dict):
    """Yield (category, subcategory, variant_name, priority) tuples.

    Taxonomy layout: content[] = categories {id,name,type,children},
    children = subcategories, their children = variants {id,name,priority}.
    """
    for cat in tax.get("content", []):
        cname = cat.get("name") or cat.get("id") or ""
        for sub in cat.get("children", []):
            sname = sub.get("name") or sub.get("id") or ""
            for var in sub.get("children", []):
                vname = var.get("name") or var.get("id") or ""
                prio = var.get("priority")
                yield cname, sname, vname, prio


def classify_surface(surface_row: dict) -> str:
    """Pick the rule bucket from surface text/asset type."""
    blob = " ".join([
        surface_row.get("surface", ""),
        surface_row.get("asset_id", ""),
        surface_row.get("protocol", ""),
        surface_row.get("notes", ""),
    ]).lower()
    # "marketing"/"marketplace" must not trigger the fintech bucket
    blob = blob.replace("marketing", " ").replace("marketplace", " marketplace ")
    # fintech surfaces first so trading/wallet/portfolio get price+order vars
    if any(k in blob for k in ("trading", "trade", "wallet", "ledger", "fintech", "withdraw", "portfolio", "order book", "orderbook", "payout", "payment", "auction", "bid")):
        return "fintech"
    # service/API surfaces before mobile: live-service, auction-service, api, graphql
    if any(k in blob for k in ("service", "api", "rest", "graphql", "ws", "websocket", "json", "scim", "bridge", "backend")):
        return "api"
    # mobile only when explicitly a mobile asset (app store id / com.* bundle / android / ios)
    if any(k in blob for k in ("android", "ios", "google_play", "apple_store", "com.whatnot", "mobile app", "bundle")):
        return "mobile"
    if any(k in blob for k in ("s3", "bucket", "cloud", "lambda", "serverless", "storage")):
        return "cloud"
    return "web"


def build_checklist(tax: dict, surfaces: list[dict]) -> list[dict]:
    variants = list(iter_variants(tax))
    p1p2 = [v for v in variants if v[3] in (1, 2)]
    out = []
    for row in surfaces:
        if row.get("scope_status") != "in_scope":
            continue
        bucket = classify_surface(row)
        hits = []
        for cat, sub, vname, prio in p1p2:
            hay = f"{cat} {sub} {vname}".lower()
            for _, needle in SURFACE_RULES.get(bucket, []):
                if needle in hay:
                    hits.append({"priority": prio, "category": cat,
                                 "subcategory": sub, "variant": vname})
                    break
        out.append({"surface_id": row.get("surface_id"), "asset_id": row.get("asset_id"),
                    "surface": row.get("surface"), "bucket": bucket, "variants": hits})
    return out


def render_md(checklist: list[dict]) -> str:
    lines = ["# Per-surface P1/P2 hunting checklist", ""]
    for item in checklist:
        lines.append(f"## {item['surface_id']} — {item['surface']}")
        lines.append(f"- Asset: `{item['asset_id']}` · bucket: {item['bucket']}")
        if not item["variants"]:
            lines.append("- No priority-1/2 variants matched (review manually)")
        else:
            for v in item["variants"]:
                lines.append(f"- [ ] P{v['priority']} — {v['category']} > {v['subcategory']} > {v['variant']}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("engagement_dir")
    ap.add_argument("--out", default="", help="write markdown checklist to this path")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--taxonomy", default=str(TAXONOMY), help="taxonomy JSON path")
    args = ap.parse_args()

    root = Path(args.engagement_dir).expanduser().resolve()
    surf_path = root / "surface-inventory.csv"
    if not surf_path.is_file():
        print(f"[!] surface-inventory.csv not found in {root}", file=sys.stderr)
        return 1
    tax_path = Path(args.taxonomy).expanduser().resolve()
    if not tax_path.is_file():
        print(f"[!] taxonomy not found: {tax_path}", file=sys.stderr)
        return 1

    with surf_path.open(encoding="utf-8", newline="") as fh:
        surfaces = list(csv.DictReader(fh))
    tax = load_taxonomy(tax_path)
    checklist = build_checklist(tax, surfaces)

    if args.json:
        print(json.dumps(checklist, indent=2))
        return 0
    md = render_md(checklist)
    if args.out:
        Path(args.out).expanduser().resolve().write_text(md, encoding="utf-8")
        print(f"[+] wrote checklist to {args.out}")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
