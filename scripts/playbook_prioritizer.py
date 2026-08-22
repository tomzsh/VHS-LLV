#!/usr/bin/env python3
"""Stack-aware playbook prioritizer (P3 helper).

Reads the orchestrator's recon artifacts (httpx.jsonl tech fingerprints,
response headers, JS hints) and ranks the 19 attack playbooks by expected
yield for THIS target's stack — so P3 test design starts with the highest
probability classes instead of a flat list.

Inputs (any subset; missing files are skipped):
  <run>/agents/recon/httpx.jsonl   httpx -tech-detect output
  <run>/agents/crawl/urls_all.txt  discovered URLs (framework path hints)

Output: ranked playbook list (stdout + optional --out JSON) mapping each
playbook to concrete evidence ("spring boot detected via tech field",
"/wp-admin seen in urls"), plus the priority tier from attack-playbooks index.

Usage:
  python3 playbook_prioritizer.py --run-dir ./run-output [--out ranking.json]
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

# Playbook -> detection signals. Each signal is (artifact_kind, regex).
# artifact kinds: tech (httpx technologies), url (discovered URL), header.
PLAYBOOK_SIGNALS: dict[str, list[tuple[str, str]]] = {
    "unauth-access": [
        ("url", r"(?i)(swagger|api-docs|actuator|\.git/|\.env|kibana|grafana|jenkins)"),
        ("tech", r"(?i)(tomcat|jenkins|kibana|grafana)"),
    ],
    "rce": [
        ("tech", r"(?i)(spring|struts|jboss|weblogic|tomcat|fastjson|log4j)"),
        ("url", r"(?i)(struts|action=|\.do\b|\.action)"),
    ],
    "file-upload": [
        ("url", r"(?i)(upload|attachment|editor|ueditor|kindeditor|ckeditor|fckeditor)"),
    ],
    "path-traversal": [
        ("url", r"(?i)(download|file=|path=|\.jsp|WEB-INF)"),
        ("tech", r"(?i)(tomcat|jboss|weblogic|iis|asp)"),
    ],
    "info-disclosure": [
        ("url", r"(?i)(\.bak$|\.sql$|\.zip$|\.tar|phpinfo|debug|backup|\.svn|\.DS_Store)"),
        ("tech", r"(?i)(php|apache)"),
    ],
    "logic-flaws": [
        ("url", r"(?i)(reset|password|verify|otp|coupon|pay|order|checkout|invite)"),
    ],
    "arbitrary-x-authz": [
        ("url", r"(?i)(admin|manage|console|user/|account/)"),
    ],
    "oauth-saml-jwt": [
        ("url", r"(?i)(oauth|saml|jwt|token|authorize|callback|sso|openid)"),
        ("header", r"(?i)bearer"),
    ],
    "sqli": [
        ("url", r"(\?.*(id|uid|pid|cat|page|no|num|q|search|sort)=)"),
        ("tech", r"(?i)(mysql|mssql|postgres|oracle|php)"),
    ],
    "ssrf-cache-host": [
        ("url", r"(?i)(fetch|proxy|render|image=|url=|import|webhook|callback)"),
        ("tech", r"(?i)(cloudflare|varnish|squid|nginx|akamai)"),
    ],
    "api-rest": [
        ("url", r"(?i)(/api/|/v[0-9]/|rest|jsonrpc)"),
        ("header", r"(?i)application/json"),
    ],
    "graphql": [
        ("url", r"(?i)(graphql|graphiql)"),
    ],
    "race-conditions": [
        ("url", r"(?i)(redeem|withdraw|transfer|vote|coupon|claim|like|follow)"),
    ],
    "xss": [
        ("url", r"(\?.*(q|search|keyword|name|message|comment|redirect|next|return)=)"),
    ],
    "http-smuggling": [
        ("tech", r"(?i)(nginx|apache|haproxy|envoy|cloudflare|aws)"),
    ],
    "mobile": [],
    "llm-prompt-injection": [
        ("url", r"(?i)(ai|chat|gpt|llm|assistant|copilot|bot)"),
    ],
    "dos": [],          # excluded from default ranking (compliance red line)
    "intranet-postexp": [],  # excluded from default ranking (post-exploitation)
}

# Priority tiers from references/attack-playbooks/00-index.md
TIER = {
    "unauth-access": "P0", "rce": "P0", "file-upload": "P0", "path-traversal": "P0",
    "info-disclosure": "P1", "logic-flaws": "P1", "arbitrary-x-authz": "P1",
    "oauth-saml-jwt": "P1", "sqli": "P1", "ssrf-cache-host": "P1",
    "api-rest": "P1/P2", "graphql": "P1/P2", "race-conditions": "P2", "xss": "P2",
    "http-smuggling": "P2", "mobile": "P2", "llm-prompt-injection": "P2", "dos": "-",
    "intranet-postexp": "-",
}
TIER_WEIGHT = {"P0": 3, "P1": 2, "P1/P2": 1.5, "P2": 1, "-": 0}

EXCLUDED = {"dos", "intranet-postexp", "mobile"}  # mobile needs APK; dos/postexp gated


def load_tech(run_dir: Path) -> dict[str, list[str]]:
    """host -> technology list from httpx.jsonl."""
    out: dict[str, list[str]] = {}
    path = run_dir / "agents" / "recon" / "httpx.jsonl"
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(item.get("host") or item.get("input") or "")
        techs = item.get("technologies") or item.get("tech") or []
        if isinstance(techs, list):
            out.setdefault(host, []).extend(str(t) for t in techs)
        store = item.get("store") or {}
        if isinstance(store, dict):
            out[host].extend(str(t) for t in store.get("technologies", []))
    return out


def load_urls(run_dir: Path) -> list[str]:
    path = run_dir / "agents" / "crawl" / "urls_all.txt"
    if not path.exists():
        return []
    return [u.strip() for u in path.read_text(encoding="utf-8", errors="ignore").splitlines() if u.strip()]


def rank(run_dir: Path) -> tuple[list[dict], list[str]]:
    tech_map = load_tech(run_dir)
    all_tech = [t for techs in tech_map.values() for t in techs]
    urls = load_urls(run_dir)
    evidence_pool = [(t, "tech") for t in set(all_tech)] + [(u, "url") for u in urls]

    ranked: list[dict] = []
    unmatched_evidence = set(evidence_pool)
    for playbook, signals in PLAYBOOK_SIGNALS.items():
        hits: list[str] = []
        score = TIER_WEIGHT.get(TIER.get(playbook, "P2"), 1)
        for kind, pattern in signals:
            rx = re.compile(pattern)
            for value, actual_kind in evidence_pool:
                if actual_kind == kind and rx.search(value):
                    hits.append(f"{value[:80]}")
                    unmatched_evidence.discard((value, actual_kind))
        score += len(hits) * 2
        if hits or playbook in {"unauth-access", "logic-flaws", "arbitrary-x-authz", "api-rest"}:
            # baseline playbooks always listed; others need at least one hit
            ranked.append({
                "playbook": playbook,
                "tier": TIER.get(playbook, "?"),
                "score": round(score, 1),
                "signals": sorted(set(hits))[:6],
            })
    ranked.sort(key=lambda item: (-item["score"], item["tier"]))
    leftover = sorted({v for v, _ in unmatched_evidence})
    return ranked, leftover


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-dir", required=True, help="orchestrator output directory")
    p.add_argument("--out", help="optional JSON output path")
    args = p.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    if not run_dir.is_dir():
        p.error(f"run dir not found: {run_dir}")

    ranked, leftover = rank(run_dir)
    print(f"# Playbook priority ranking — {run_dir.name}\n")
    print("| Rank | Playbook | Tier | Score | Signals |")
    print("|---|---|---|---|---|")
    for i, item in enumerate(ranked, 1):
        sig = "; ".join(item["signals"][:3]) or "-"
        print(f"| {i} | {item['playbook']} | {item['tier']} | {item['score']} | {sig} |")
    excluded_note = ", ".join(sorted(EXCLUDED))
    print(f"\nExcluded from auto-ranking (manual/gated): {excluded_note}")
    if leftover:
        print(f"\nUnmatched evidence (check manually): {leftover[:10]}")

    if args.out:
        Path(args.out).write_text(
            json.dumps({"ranking": ranked, "unmatched": leftover}, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"[i] JSON: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
