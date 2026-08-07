#!/usr/bin/env python3
"""vhs P1/P2 research stage: pull disclosed hacktivity / writeups for a target.

Uses research_sources.py (ported from BountySkiller) to fetch public
disclosed bug-bounty reports and writeups, filter by relevance query +
minimum severity / bounty, and write a compact research digest under the
engagement dir. Use it BEFORE drafting hypotheses in P1/P2 so hunt classes
track what actually gets rewarded on similar programs.

Usage:
  python3 research_hacktivity.py <engagement-dir> \
      --sources hackerone,pentesterland,portswigger \
      --months 6 \
      --query "vue wallet card idor api js" \
      --min-bounty 500 \
      --limit 25

Sources (id -> availability):
  hackerone, pentesterland, medium, infosecwriteups, portswigger,
  intigriti, research_blogs, google (needs GOOGLE_API_KEY/GOOGLE_CSE_ID),
  all (try every source, skip failures).

Output:
  <engagement>/research/hacktivity-research.md
  <engagement>/research/research-ledger.csv   (append rows)
"""

import argparse
import csv
import json
import os
import re
import sys
import datetime
import itertools
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

try:
    from research_sources import source_list, fetch_source
except ImportError as exc:  # pragma: no cover
    sys.exit(f"[!] research_sources.py not found next to this script: {exc}")


def score(query_terms: list[str], item: dict) -> int:
    """Relevance score: +1 per query term found in title/tags/url/program."""
    blurbs = " ".join(
        str(item.get(k) or "") for k in ("title", "url", "program", "tags", "extra")
    ).lower()
    return sum(1 for t in query_terms if t and t.lower() in blurbs)


def sev_rank(item: dict) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sev = str(item.get("severity") or "").lower()
    return order.get(sev, 4)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("engagement_dir", help="path to engagement/ dir")
    ap.add_argument("--sources", default="hackerone,pentesterland,portswigger",
                    help="comma-separated sources or 'all'")
    ap.add_argument("--months", type=int, default=6)
    ap.add_argument("--query", default="", help="space-separated relevance terms")
    ap.add_argument("--min-bounty", type=int, default=0)
    ap.add_argument("--min-severity", default="low",
                    choices=["critical", "high", "medium", "low"])
    ap.add_argument("--limit", type=int, default=10, help="max digest rows")
    ap.add_argument("--dry-run", action="store_true",
                    help="print fetch counts without writing files")
    args = ap.parse_args()

    root = Path(args.engagement_dir)
    if not (root / "engagement.json").exists():
        sys.exit(f"[!] {root} is not an engagement dir (no engagement.json)")

    src_names = [s.strip() for s in args.sources.split(",") if s.strip()]
    query_terms = [t.strip() for t in args.query.lower().split() if t.strip()]
    sev_cut = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.min_severity.lower()]

    print(f"[research] fetching from {src_names}, months={args.months}")
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    cutoff = _dt.now(_tz.utc) - _td(days=args.months * 30.44)
    rows, errors = [], {}
    for name in src_names:
        try:
            got = fetch_source(name, args.months, cutoff, {}, progress=None)
            print(f"  {name}: {len(got)} rows")
            rows += got
        except Exception as exc:  # noqa: BLE001
            errors[name] = str(exc)[:160]
            print(f"  {name}: ERROR {str(exc)[:120]}")

    if args.dry_run:
        print(f"[dry-run] {len(rows)} raw rows from "
              f"{len([n for n in src_names if n not in errors])} sources "
              f"(errors: {errors or 'none'})")
        return

    # filter: bounty + severity, then rank by relevance
    kept = []
    for it in rows:
        if args.min_bounty and (it.get("bounty") or 0) < args.min_bounty:
            continue
        if (sev_rank(it) > sev_cut):
            continue
        kept.append(it)
    kept.sort(key=lambda it: (sev_rank(it), -(it.get("bounty") or 0)))
    kept = kept[: args.limit]

    # relevance ordering applied to the pre-limited set for display
    kept.sort(key=lambda it: -sum(
        1 for t in query_terms if t and t in " ".join(
            str(it.get(k) or "") for k in ("title", "url", "program", "tags")
        ).lower()
    ))

    research_dir = root / "research"
    research_dir.mkdir(exist_ok=True)

    # markdown digest
    md_lines = [
        "# Hacktivity / writeup research digest",
        "",
        f"- Engagement: {root.name}",
        f"- Sources: {', '.join(src_names)} | months: {args.months}",
        f"- Query terms: {args.query.strip() or '(none)'}",
        f"- Min bounty: ${args.min_bounty} | Min severity: {args.min_severity}",
        f"- Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}",
        "",
        f"Rows fetched: **{len(rows)}** | kept in digest: **{len(kept)}**",
    ]
    for s, e in errors.items():
        md_lines.append(f"- Source error `{s}`: {e}")
    md_lines.append("")
    md_lines.append("## Ranked items")
    for it in kept:
        md_lines.append("")
        md_lines.append(f"### [{it.get('title') or 'Untitled'}]({it.get('url') or '#'})")
        md_lines.append(f"`{it.get('source')}` · `{it.get('severity') or 'n/a'}` · "
                        f"bounty `${it.get('bounty') or 0}` · {it.get('program') or 'n/a'}")
        md_lines.append(f"tags: {', '.join(it.get('tags') or []) or 'n/a'}")
    md_lines.append("")
    md_lines.append("> Research is secondary intel. It is a hypothesis input, not a finding.")
    md_path = research_dir / "hacktivity-results.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    # append journal jsonl
    journal = research_dir / "research-ledger.jsonl"
    with journal.open("a", encoding="utf-8") as f:
        for it in kept:
            f.write(json.dumps({
                "source": it.get("source"),
                "kind": it.get("kind"),
                "title": it.get("title"),
                "url": it.get("url"),
                "published_at": it.get("published_at"),
                "author": it.get("author"),
                "program": it.get("program"),
                "severity": it.get("severity"),
                "bounty": it.get("bounty"),
                "tags": it.get("tags"),
                "engagement": root.name,
            }, ensure_ascii=False) + "\n")

    print(f"[+] wrote {research_dir.relative_to(root)}/research.md "
          f"({len(kept)} kept / {len(rows)} fetched)")
    if errors:
        print(f"[!] source errors: {errors}")


if __name__ == "__main__":
    main()