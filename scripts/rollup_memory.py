#!/usr/bin/env python3
"""Per-target isolated memory rollup for vhs engagements.

Engagement state ALREADY lives on disk (engagement.json + ledgers + evidence).
This script compacts it into ONE self-contained per-target memory file so you
never need to push engagement facts into the agent's global memory / mem0.

Output: <engagement>/memory-rollup.md  (single source of truth for resume)

Resume workflow:
  read memory-rollup.md -> reload phase, assets, surfaces, hypotheses,
  test status, evidence, findings. Do NOT rely on chat history or global
  memory for engagement facts.

Usage:
  python3 rollup_memory.py <engagement-dir> [--json] [--write]
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8-sig", newline="") as f:
        return [row for row in csv.DictReader(f) if any((v or "").strip() for v in row.values())]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("engagement_dir")
    ap.add_argument("--json", action="store_true", help="print JSON instead of markdown")
    ap.add_argument("--write", action="store_true", help="write memory-rollup.md")
    args = ap.parse_args()

    root = Path(args.engagement_dir)
    if not (root / "engagement.json").exists():
        sys.exit(f"[!] {root} is not an engagement dir (no engagement.json)")

    eng = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
    state = {}
    if (root / "state.json").exists():
        state = json.loads((root / "state.json").read_text(encoding="utf-8"))

    assets = read_csv(root / "asset-inventory.csv")
    surfaces = read_csv(root / "surface-inventory.csv")
    hyps = read_csv(root / "hypothesis-ledger.csv")
    tests = read_csv(root / "test-matrix.csv")
    evidence = read_csv(root / "evidence-ledger.csv")
    reviews = read_csv(root / "critical-review.csv")
    dig_deeper_chains = read_csv(root / "dig-deeper-chain.csv")
    pivot_ladders = read_csv(root / "pivot-ladder.csv")
    findings = read_csv(root / "findings-index.csv")

    rollup = {
        "engagement": eng.get("engagement_id"),
        "target": eng.get("primary_target"),
        "phase": state.get("current_phase"),
        "assets": assets,
        "surfaces": surfaces,
        "hypotheses": hyps,
        "tests": tests,
        "evidence": evidence,
        "critical_reviews": reviews,
        "dig_deeper_chains": dig_deeper_chains,
        "pivot_ladders": pivot_ladders,
        "findings": findings,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    if args.json:
        print(json.dumps(rollup, indent=2, ensure_ascii=False))
        return

    L = []
    L.append(f"# Engagement memory rollup — {eng.get('primary_target')}")
    L.append("")
    L.append(f"- engagement_id: `{eng.get('engagement_id')}`")
    L.append(f"- phase: **{state.get('current_phase')}**")
    L.append(f"- authorization: {eng.get('authorization_status')} | mode: {eng.get('permission_mode')}")
    L.append(f"- window: {eng.get('testing_window')}")
    L.append(f"- generated: {rollup['generated_at']}")
    L.append("")

    L.append(f"## Assets ({len(assets)})")
    for a in assets:
        L.append(f"- `{a.get('asset_id')}` {a.get('asset')} [{a.get('environment')}] {a.get('scope_status')}")
    L.append("")

    L.append(f"## Surfaces ({len(surfaces)})")
    for s in surfaces:
        L.append(f"- `{s.get('surface_id')}` {s.get('surface')} auth={s.get('auth_requirement')} cov={s.get('coverage_status')} {s.get('notes','')}")
    L.append("")

    L.append(f"## Hypotheses ({len(hyps)})")
    for h in hyps:
        L.append(f"- `{h.get('hypothesis_id')}` P{h.get('priority')} [{h.get('status')}] {h.get('invariant')} — mutation: {h.get('mutation')}")
    L.append("")

    L.append(f"## Tests ({len(tests)})")
    for t in tests:
        L.append(f"- `{t.get('test_id')}` [{t.get('status')}] {t.get('baseline')} -> {t.get('mutation')} (ev: {t.get('evidence_ids','')})")
    L.append("")

    L.append(f"## Evidence ({len(evidence)})")
    for e in evidence:
        L.append(f"- `{e.get('evidence_id')}` {e.get('observation')} [{e.get('redaction_status')}] {e.get('path')}")
    L.append("")

    L.append(f"## Critical reviews ({len(reviews)})")
    for review in reviews:
        L.append(
            f"- `{review.get('review_id')}` test={review.get('test_id')} finding={review.get('finding_id','')} "
            f"[{review.get('decision')}] uncertainty={review.get('uncertainty')}"
        )
    L.append("")

    L.append(f"## Dig-deeper chains ({len(dig_deeper_chains)})")
    for hop in dig_deeper_chains:
        L.append(
            f"- `{hop.get('chain_id')}` hop={hop.get('step_no')} test={hop.get('test_id')} "
            f"[{hop.get('status')}] uncertainty={hop.get('uncertainty')}"
        )
    L.append("")

    L.append(f"## Pivot ladders ({len(pivot_ladders)})")
    for hop in pivot_ladders:
        L.append(
            f"- `{hop.get('ladder_id')}` hop={hop.get('step_no')} "
            f"{hop.get('from_asset_id')} -> {hop.get('to_asset_id')} [{hop.get('status')}]"
        )
    L.append("")

    L.append(f"## Findings ({len(findings)})")
    for f_ in findings:
        L.append(f"- `{f_.get('finding_id')}` [{f_.get('status')}/{f_.get('severity')}] {f_.get('title')}")
    L.append("")
    L.append("> This file is the per-target memory. Do NOT copy its contents into the")
    L.append("> agent's global memory or mem0 — read it from disk on resume.")

    md = "\n".join(L)
    if args.write:
        out = root / "memory-rollup.md"
        out.write_text(md, encoding="utf-8")
        print(f"[+] wrote {out.relative_to(root)} ({len(md)} bytes)")
    else:
        print(md)


if __name__ == "__main__":
    main()
