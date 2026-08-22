#!/usr/bin/env python3
"""Detect dangling-CNAME subdomain takeover candidates (DNS-only, never claims).

For each in-scope host: resolve its CNAME chain, match the target against the
bundled takeover fingerprint database (references/takeover-fingerprints.json),
and check whether the CNAME target still resolves. A fingerprint match whose
target is dangling (NXDOMAIN / no A record) is a takeover candidate hypothesis.

This script only issues DNS queries - it never claims, registers, or modifies
any third-party resource. Claiming is a controlled-impact action that stays a
separate, manual, program-approved decision.
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import PolicyError, authorize_run, normalize_host  # noqa: E402
from schemas import LEDGER_SCHEMAS, validate_ledger_header  # noqa: E402

DEFAULT_FINGERPRINTS = Path(__file__).resolve().parents[1] / "references" / "takeover-fingerprints.json"
FALLBACK_HOSTS = [
    Path("agents/recon/hosts_scoped.txt"),
    Path("agents/recon/hosts_resolved.txt"),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_fingerprints(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("fingerprints")
    if not isinstance(entries, list):
        raise ValueError(f"invalid fingerprint database at {path}")
    return entries


def resolve_cname(host: str, timeout: int) -> list[str]:
    """Return the CNAME chain for host using dig, host, or dnsx if available."""
    if shutil.which("dig"):
        proc = subprocess.run(
            ["dig", "+short", "+time=" + str(timeout), "CNAME", host],
            capture_output=True, text=True, timeout=timeout + 5, check=False,
        )
        return [line.strip().rstrip(".") for line in proc.stdout.splitlines() if line.strip()]
    if shutil.which("host"):
        proc = subprocess.run(
            ["host", "-W", str(timeout), "-t", "CNAME", host],
            capture_output=True, text=True, timeout=timeout + 5, check=False,
        )
        targets: list[str] = []
        for line in proc.stdout.splitlines():
            if "is an alias for" in line:
                target = line.rpartition("is an alias for")[2].strip().rstrip(".")
                if target:
                    targets.append(target)
        return targets
    if shutil.which("dnsx"):
        proc = subprocess.run(
            ["dnsx", "-silent", "-cname", "-t", "CNAME", host],
            capture_output=True, text=True, timeout=timeout + 5, check=False,
        )
        targets = []
        for line in proc.stdout.splitlines():
            for part in line.split():
                candidate = normalize_host(part)
                if candidate and candidate != normalize_host(host):
                    targets.append(part.strip().rstrip("."))
        return targets
    return []


def resolves(host: str, timeout: int) -> bool:
    """Return True when host has any A/AAAA record."""
    if shutil.which("dig"):
        proc = subprocess.run(
            ["dig", "+short", "+time=" + str(timeout), host],
            capture_output=True, text=True, timeout=timeout + 5, check=False,
        )
        return bool(proc.stdout.strip())
    if shutil.which("host"):
        proc = subprocess.run(
            ["host", "-W", str(timeout), host],
            capture_output=True, text=True, timeout=timeout + 5, check=False,
        )
        return "has address" in proc.stdout or "has IPv6 address" in proc.stdout
    if shutil.which("dnsx"):
        proc = subprocess.run(
            ["dnsx", "-silent", host], capture_output=True, text=True,
            timeout=timeout + 5, check=False,
        )
        return bool(proc.stdout.strip())
    return True  # no resolver available: do not flag as dangling


def match_fingerprint(cname: str, fingerprints: list[dict]) -> dict | None:
    normalized = cname.strip().rstrip(".").lower()
    for entry in fingerprints:
        for domain in entry.get("domains") or []:
            if normalized == domain.lower() or normalized.endswith("." + domain.lower()):
                return entry
    return None


def next_id(existing: set[str], prefix: str) -> str:
    number = 1
    while f"{prefix}-{number:03d}" in existing:
        number += 1
    return f"{prefix}-{number:03d}"


FIELDS = ["host", "cname", "service", "status", "fingerprint", "target_resolves", "verdict", "reference"]


def check_hosts(
    hosts: list[str], fingerprints: list[dict], *, timeout: int, rate: float, host_allowed
) -> list[dict]:
    rows: list[dict] = []
    for host in hosts:
        if not host_allowed(host):
            continue
        cnames = resolve_cname(host, timeout)
        time.sleep(rate)
        for cname in cnames:
            entry = match_fingerprint(cname, fingerprints)
            if not entry:
                continue
            live = resolves(cname, timeout)
            time.sleep(rate)
            if live:
                verdict = "uses_service_normally"
            elif entry.get("status") == "claimable":
                verdict = "takeover_candidate"
            elif entry.get("status") == "partial":
                verdict = "takeover_candidate_conditions"
            else:
                verdict = "fingerprint_discontinued"
            rows.append({
                "host": host,
                "cname": cname,
                "service": entry.get("service", "?"),
                "status": entry.get("status", "?"),
                "fingerprint": ",".join(entry.get("domains") or []),
                "target_resolves": "yes" if live else "no",
                "verdict": verdict,
                "reference": str(entry.get("reference") or ""),
            })
    order = {"takeover_candidate": 0, "takeover_candidate_conditions": 1, "fingerprint_discontinued": 2, "uses_service_normally": 3}
    rows.sort(key=lambda r: (order.get(r["verdict"], 9), r["host"]))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engagement_dir", help="authorized engagement directory")
    parser.add_argument("--hosts", type=Path, help="host list file (one per line); default: run-dir agents/recon/hosts_scoped.txt")
    parser.add_argument("--run-dir", type=Path, help="orchestrator run directory used to locate hosts when --hosts is absent")
    parser.add_argument("--out", type=Path, help="output CSV path (default: <run-dir|cwd>/takeover-candidates.csv)")
    parser.add_argument("--fingerprints", type=Path, default=DEFAULT_FINGERPRINTS)
    parser.add_argument("--max-hosts", type=int, default=500)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--rate", type=float, default=0.05, help="seconds between DNS queries")
    parser.add_argument("--append-hypotheses", action="store_true")
    parser.add_argument("--asset-id", default="")
    args = parser.parse_args()

    if not any((args.hosts, args.run_dir)):
        parser.error("provide --hosts or --run-dir")

    engagement_root = Path(args.engagement_dir).expanduser().resolve()
    hosts_file = args.hosts
    if hosts_file is None:
        for candidate in FALLBACK_HOSTS:
            merged = (args.run_dir / candidate) if args.run_dir else None
            if merged and merged.exists():
                hosts_file = merged
                break
    if hosts_file is None or not hosts_file.exists():
        print("ERROR: host list not found; pass --hosts explicitly", file=sys.stderr)
        return 2

    hosts: list[str] = []
    for line in hosts_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        host = normalize_host(line)
        if host and host not in hosts:
            hosts.append(host)
    hosts = hosts[: max(1, args.max_hosts)]
    if not hosts:
        print("No hosts to check.")
        return 0

    probe = hosts[0]
    try:
        fingerprints = load_fingerprints(args.fingerprints)
        _, _, policy = authorize_run(engagement_root, probe, "active-safe")
    except (PolicyError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    rows = check_hosts(hosts, fingerprints, timeout=args.timeout, rate=args.rate, host_allowed=policy.host_allowed)

    out_path = args.out or ((args.run_dir or Path.cwd()) / "takeover-candidates.csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    candidates = sum(1 for r in rows if r["verdict"].startswith("takeover_candidate"))
    print(f"hosts checked        : {len(hosts)}")
    print(f"fingerprint matches  : {len(rows)} ({candidates} takeover candidate(s))")
    print(f"report               : {out_path}")

    if rows and args.append_hypotheses:
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
                if not row["verdict"].startswith("takeover_candidate"):
                    continue
                hypothesis_id = next_id(existing_ids, "HYP-TKO")
                existing_ids.add(hypothesis_id)
                writer.writerow({
                    "hypothesis_id": hypothesis_id,
                    "asset_id": args.asset_id,
                    "surface_id": "",
                    "actor": "unauthenticated external actor",
                    "invariant": f"{row['host']} cannot be claimed via {row['service']} takeover",
                    "mutation": f"dangling CNAME {row['cname']} ({row['status']}); target does not resolve",
                    "safe_validation": "verify dangling state again, then request program approval BEFORE claiming; claiming is controlled-impact",
                    "priority": "P0" if row["verdict"] == "takeover_candidate" else "P1",
                    "status": "pending",
                    "notes": f"takeover fingerprint {row['service']} at {row['host']}; imported at {utc_now()}; not confirmed.",
                })
        print(f"appended {candidates} hypothesis row(s) to {ledger_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
