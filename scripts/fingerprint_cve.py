#!/usr/bin/env python3
"""Correlate recon fingerprints (httpx tech-detect, exposed ports) with known CVEs.

Purely local analysis of artifacts already collected by an orchestrator run:

- parses agents/recon/httpx.jsonl (tech, webserver, title) and agents/recon/ports.txt;
- matches fingerprints against references/kev-snapshot.json (offline seed of
  CISA-KEV-style product/CVE data);
- optionally enriches with local searchsploit results (--searchsploit);
- writes cve-hypotheses.csv into the run directory and can append prioritized
  hypothesis rows to the engagement's hypothesis-ledger.csv (--append-hypotheses).

Every match is a hypothesis that needs manual version verification at P3/P4.
This script never sends traffic to the target.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import PolicyError, authorize_run, normalize_host  # noqa: E402
from schemas import LEDGER_SCHEMAS, validate_ledger_header  # noqa: E402

DEFAULT_SNAPSHOT = Path(__file__).resolve().parents[1] / "references" / "kev-snapshot.json"
VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)")

SEVERITY_PRIORITY = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_snapshot(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    products = data.get("products")
    if not isinstance(products, list):
        raise ValueError(f"invalid snapshot at {path}: missing products list")
    return products


def load_httpx(path: Path) -> list[dict]:
    """Return [{host, url, tech, webserver, title}] rows from httpx JSONL."""
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        tech = item.get("tech")
        if isinstance(tech, str):
            tech = [tech]
        rows.append({
            "host": str(item.get("host") or item.get("input") or ""),
            "url": str(item.get("url") or item.get("input") or ""),
            "tech": [str(t) for t in tech] if isinstance(tech, list) else [],
            "webserver": str(item.get("webserver") or ""),
            "title": str(item.get("title") or ""),
        })
    return rows


def load_ports(path: Path) -> dict[str, list[str]]:
    """Return host -> open ports from naabu-style host:port lines."""
    result: dict[str, list[str]] = {}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        host, _, port = line.rpartition(":")
        host = normalize_host(host)
        if host and port.isdigit():
            result.setdefault(host, []).append(port)
    return result


def product_tokens(product: dict) -> list[str]:
    values = [product.get("product", "")] + list(product.get("aliases") or [])
    return [re.sub(r"[^a-z0-9]+", " ", str(v).lower()).strip() for v in values if str(v).strip()]


def match_products(fingerprints: list[str], products: list[dict]) -> list[tuple[dict, str, str]]:
    """Return (product, matched_token, version) for fingerprints that mention a product."""
    matches: list[tuple[dict, str, str]] = []
    for fingerprint in fingerprints:
        haystack = re.sub(r"[^a-z0-9.]+", " ", fingerprint.lower())
        for product in products:
            for token in product_tokens(product):
                if not token:
                    continue
                pattern = r"(?<![a-z0-9])" + re.escape(token).replace(r"\ ", r"[ ]") + r"(?![a-z0-9])"
                found = re.search(pattern, haystack)
                if not found:
                    continue
                tail = haystack[found.end(): found.end() + 24]
                version_match = VERSION_RE.search(tail)
                version = version_match.group(1) if version_match else ""
                matches.append((product, fingerprint, version))
                break
    return matches


def searchsploit_lines(query: str, limit: int = 10) -> list[str]:
    binary = shutil.which("searchsploit")
    if not binary:
        return []
    try:
        proc = subprocess.run(
            [binary, query], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    return lines[:limit]


def next_id(existing: set[str], prefix: str) -> str:
    number = 1
    while f"{prefix}-{number:03d}" in existing:
        number += 1
    return f"{prefix}-{number:03d}"


def build_hypotheses(
    httpx_rows: list[dict],
    ports: dict[str, list[str]],
    products: list[dict],
    host_allowed,
) -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for item in httpx_rows:
        host = normalize_host(item["host"] or item["url"])
        if not host or not host_allowed(host):
            continue
        fingerprints = item["tech"] + ([item["webserver"]] if item["webserver"] else [])
        for product, fingerprint, version in match_products(fingerprints, products):
            exposed = ",".join(sorted(ports.get(host, [])))
            for cve in product.get("cves") or []:
                cve_id = str(cve.get("id") or "")
                if not cve_id or cve_id == "CORE":
                    continue
                key = (host, product["product"], cve_id)
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "host": host,
                    "url": item["url"],
                    "product": product["product"],
                    "version": version,
                    "cve": cve_id,
                    "known_exploited": bool(cve.get("known_exploited")),
                    "cvss": cve.get("cvss"),
                    "summary": str(cve.get("summary") or ""),
                    "affected_hint": str(cve.get("affected_hint") or ""),
                    "fingerprint_source": fingerprint,
                    "exposed_ports": exposed,
                    "version_verified": "no",
                })
    # KEV-first ordering, then CVSS descending.
    rows.sort(key=lambda r: (not r["known_exploited"], -float(r["cvss"] or 0), r["host"], r["cve"]))
    return rows


FIELDS = [
    "host", "url", "product", "version", "cve", "known_exploited", "cvss",
    "summary", "affected_hint", "fingerprint_source", "exposed_ports", "version_verified",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engagement_dir", help="authorized engagement directory")
    parser.add_argument("--run-dir", required=True, help="orchestrator run directory (manifest.json / agents/)")
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--append-hypotheses", action="store_true")
    parser.add_argument("--asset-id", default="")
    parser.add_argument("--searchsploit", action="store_true", help="enrich with local searchsploit titles (offline db)")
    args = parser.parse_args()

    engagement_root = Path(args.engagement_dir).expanduser().resolve()
    run_root = Path(args.run_dir).expanduser().resolve()

    manifest = run_root / "manifest.json"
    target = ""
    if manifest.exists():
        try:
            target = str(json.loads(manifest.read_text(encoding="utf-8")).get("target") or "")
        except json.JSONDecodeError:
            target = ""
    if not target:
        # Fall back to the first httpx row so authorize_run has a host to check.
        first = load_httpx(run_root / "agents" / "recon" / "httpx.jsonl")
        target = first[0]["host"] if first else ""

    try:
        products = load_snapshot(args.snapshot)
        _, _, policy = authorize_run(engagement_root, target, "passive-osint")
    except (PolicyError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    httpx_rows = load_httpx(run_root / "agents" / "recon" / "httpx.jsonl")
    ports = load_ports(run_root / "agents" / "recon" / "ports.txt")
    rows = build_hypotheses(httpx_rows, ports, products, policy.host_allowed)

    if args.searchsploit:
        for row in rows:
            query = " ".join(part for part in (row["product"], row["version"]) if part)
            extra = searchsploit_lines(query)
            if extra:
                row["summary"] += " | searchsploit: " + extra[0]

    report_path = run_root / "cve-hypotheses.csv"
    with report_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    exploited = sum(1 for row in rows if row["known_exploited"])
    print(f"fingerprints analyzed : {len(httpx_rows)} httpx row(s)")
    print(f"cve hypotheses       : {len(rows)} ({exploited} known-exploited)")
    print(f"report               : {report_path}")

    if not rows:
        return 0

    if args.append_hypotheses:
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
                hypothesis_id = next_id(existing_ids, "HYP-CVE")
                existing_ids.add(hypothesis_id)
                kev = "KEV-listed " if row["known_exploited"] else ""
                writer.writerow({
                    "hypothesis_id": hypothesis_id,
                    "asset_id": args.asset_id,
                    "surface_id": "",
                    "actor": "unauthenticated external actor",
                    "invariant": f"Running {row['product']} is not affected by {row['cve']}",
                    "mutation": f"fingerprinted {row['fingerprint_source']!r} at {row['host']}",
                    "safe_validation": "verify exact installed version against advisory; no exploit traffic before P4 approval",
                    "priority": "P0" if row["known_exploited"] else "P1",
                    "status": "pending",
                    "notes": (
                        f"{kev}{row['cve']} (cvss {row['cvss']}) match on {row['host']}; "
                        f"affected hint: {row['affected_hint'] or 'unspecified'}; imported at {utc_now()}; not confirmed."
                    ),
                })
        print(f"appended {len(rows)} hypothesis row(s) to {ledger_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
