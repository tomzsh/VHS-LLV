#!/usr/bin/env python3
"""Probe CORS reflection and missing security headers on live in-scope URLs.

GET-only, rate-limited. For each URL it issues up to three requests
(baseline, arbitrary-origin, null-origin) and records:

- whether Access-Control-Allow-Origin reflects an attacker-chosen origin
  (and whether credentials are allowed alongside - the dangerous pair);
- whether ACAO is ``null`` with credentials;
- absence of CSP / X-Frame-Options / HSTS (informational only).

Matches are hypotheses; validate at P4. Output: header-probe.csv and optional
hypothesis-ledger rows (--append-hypotheses).
"""
from __future__ import annotations

import argparse
import csv
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import PolicyError, authorize_run  # noqa: E402
from schemas import LEDGER_SCHEMAS, validate_ledger_header  # noqa: E402

TEST_ORIGIN = "https://cors-probe-origin.example.net"
CONTEXT = ssl.create_default_context()
CONTEXT.check_hostname = False
CONTEXT.verify_mode = ssl.CERT_NONE


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def fetch_headers(url: str, origin: str | None, timeout: int) -> dict[str, str] | None:
    headers = {"User-Agent": "security-research (authorized)", "Accept": "*/*"}
    if origin:
        headers["Origin"] = origin
    request = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=CONTEXT) as response:
            return {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        return {k.lower(): v for k, v in exc.headers.items()} if exc.headers else None
    except (urllib.error.URLError, OSError, ValueError):
        return None


def probe_url(url: str, timeout: int) -> dict:
    base = fetch_headers(url, None, timeout) or {}
    arbitrary = fetch_headers(url, TEST_ORIGIN, timeout) or {}
    null = fetch_headers(url, "null", timeout) or {}

    acao = arbitrary.get("access-control-allow-origin", "")
    acac = arbitrary.get("access-control-allow-credentials", "")
    null_acao = null.get("access-control-allow-origin", "")
    null_acac = null.get("access-control-allow-credentials", "")

    if acao and acao.strip() == TEST_ORIGIN:
        verdict = "acao_reflect_credentials" if acac.lower() == "true" else "acao_reflect"
    elif acao == "*":
        verdict = "acao_wildcard_credentials" if acac.lower() == "true" else "acao_wildcard"
    elif null_acao.lower() == "null":
        verdict = "acao_null_credentials" if null_acac.lower() == "true" else "acao_null"
    else:
        verdict = "no_cors_signal"

    return {
        "url": url,
        "acao_arbitrary": acao,
        "acac": acac,
        "acao_null": null_acao,
        "csp": base.get("content-security-policy", ""),
        "xfo": base.get("x-frame-options", "") or base.get("content-security-policy", ""),
        "hsts": base.get("strict-transport-security", ""),
        "verdict": verdict,
        "missing_headers": ",".join(
            name for name, value in (
                ("csp", base.get("content-security-policy", "")),
                ("xfo", base.get("x-frame-options", "")),
                ("hsts", base.get("strict-transport-security", "")),
            ) if not value
        ),
    }


FIELDS = [
    "url", "acao_arbitrary", "acac", "acao_null", "csp", "xfo", "hsts",
    "missing_headers", "verdict",
]
HIGH_VALUE = {"acao_reflect_credentials", "acao_wildcard_credentials", "acao_null_credentials", "acao_reflect"}


def next_id(existing: set[str], prefix: str) -> str:
    number = 1
    while f"{prefix}-{number:03d}" in existing:
        number += 1
    return f"{prefix}-{number:03d}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engagement_dir")
    parser.add_argument("--run-dir", required=True, help="orchestrator run directory (agents/recon/live_urls.txt)")
    parser.add_argument("--max-hosts", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--rate", type=float, default=0.2, help="seconds between requests")
    parser.add_argument("--append-hypotheses", action="store_true")
    parser.add_argument("--asset-id", default="")
    args = parser.parse_args()

    engagement_root = Path(args.engagement_dir).expanduser().resolve()
    run_root = Path(args.run_dir).expanduser().resolve()
    live = run_root / "agents" / "recon" / "live_urls.txt"
    if not live.exists():
        print(f"ERROR: {live} not found; run the orchestrator active-safe stage first", file=sys.stderr)
        return 2
    urls = [u.strip() for u in live.read_text(encoding="utf-8", errors="ignore").splitlines() if u.strip()]
    urls = urls[: max(1, args.max_hosts)]
    if not urls:
        print("No live URLs to probe.")
        return 0

    from policy import normalize_host
    host = normalize_host(urls[0])
    try:
        _, _, policy = authorize_run(engagement_root, host, "active-safe")
    except PolicyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    rows: list[dict] = []
    for index, url in enumerate(urls, 1):
        if not policy.url_allowed(url):
            continue
        row = probe_url(url, args.timeout)
        rows.append(row)
        print(f"[{index}/{len(urls)}] {row['verdict']:28s} {url}")
        time.sleep(args.rate)

    out_path = run_root / "header-probe.csv"
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    high = sum(1 for r in rows if r["verdict"] in HIGH_VALUE)
    print(f"\nprobed: {len(rows)}; cors signals: {high} high-value")
    print(f"report: {out_path}")

    if args.append_hypotheses and high:
        ledger_path = engagement_root / "hypothesis-ledger.csv"
        error = validate_ledger_header(ledger_path, LEDGER_SCHEMAS[ledger_path.name])
        if error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 2
        with ledger_path.open(encoding="utf-8", newline="") as handle:
            existing_rows = list(csv.DictReader(handle))
        existing_ids = {row.get("hypothesis_id", "") for row in existing_rows}
        with ledger_path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=LEDGER_SCHEMAS[ledger_path.name])
            for row in rows:
                if row["verdict"] not in HIGH_VALUE:
                    continue
                hypothesis_id = next_id(existing_ids, "HYP-HDR")
                existing_ids.add(hypothesis_id)
                credentials = "with credentials" if "credentials" in row["verdict"] else "without credentials flag"
                writer.writerow({
                    "hypothesis_id": hypothesis_id,
                    "asset_id": args.asset_id,
                    "surface_id": "",
                    "actor": "unauthenticated external attacker origin",
                    "invariant": "arbitrary origins cannot read authenticated cross-origin responses",
                    "mutation": f"Origin reflection probe on {row['url']} ({credentials})",
                    "safe_validation": "P4: fetch the URL cross-origin with a test account session and a researcher-controlled page; no real-user data",
                    "priority": "P0" if "credentials" in row["verdict"] else "P1",
                    "status": "pending",
                    "notes": f"CORS {row['verdict']} at {row['url']}; imported at {utc_now()}; not confirmed.",
                })
        print(f"appended {high} hypothesis row(s) to {ledger_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
