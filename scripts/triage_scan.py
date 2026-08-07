#!/usr/bin/env python3
"""Triage Nuclei matches from an orchestrator run without confirming findings.

The script reads output locations from manifest.json, verifies the engagement's
current authorization and scope, performs one low-impact re-request per match,
and optionally appends needs-review items to hypothesis-ledger.csv.
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from policy import PolicyError, authorize_run
from schemas import LEDGER_SCHEMAS, validate_ledger_header

SEVERITY_PRIORITY = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}
SIZE_TOLERANCE = 0.05


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def origin(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def load_manifest(root: Path) -> dict:
    path = root / "manifest.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"missing {path}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid manifest.json: {exc}") from None
    if not isinstance(value, dict):
        raise ValueError("manifest.json must contain an object")
    return value


def output_path(root: Path, manifest: dict, key: str, legacy: str) -> Path:
    outputs = manifest.get("outputs") if isinstance(manifest.get("outputs"), dict) else {}
    relative = outputs.get(key) or legacy
    path = (root / str(relative)).resolve()
    if root not in path.parents and path != root:
        raise ValueError(f"manifest output path escapes run directory: {relative!r}")
    return path


def load_baselines(path: Path) -> dict[str, tuple[str, int]]:
    if not path.exists():
        return {}
    if path.suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        result: dict[str, tuple[str, int]] = {}
        if isinstance(data, dict):
            for host, item in data.items():
                if not isinstance(item, dict):
                    continue
                try:
                    result[str(host)] = (str(item["status"]), int(item["size"]))
                except (KeyError, TypeError, ValueError):
                    continue
        return result
    result = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.strip().split()
        if len(parts) != 3:
            continue
        url, status, size = parts
        try:
            result[origin(url)] = (status, int(size))
        except ValueError:
            continue
    return result


def load_nuclei(path: Path) -> list[dict]:
    findings: list[dict] = []
    if not path.exists():
        return findings
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            findings.append(item)
    return findings


def live_probe(url: str, timeout: int) -> tuple[str, int] | None:
    try:
        process = subprocess.run(
            [
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{size_download}",
                "--max-time", str(timeout), "--max-redirs", "0", url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
            check=False,
        )
        if process.returncode != 0:
            return None
        status, size = process.stdout.strip().split()
        if status == "000":
            return None
        return status, int(float(size))
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def verdict(baseline: tuple[str, int] | None, live: tuple[str, int] | None) -> str:
    if live is None:
        return "unreachable"
    if baseline is None:
        return "needs_review"
    baseline_status, baseline_size = baseline
    live_status, live_size = live
    if live_status != baseline_status:
        return "needs_review"
    if baseline_size == 0:
        return "likely_fp" if live_size == 0 else "needs_review"
    return "likely_fp" if abs(live_size - baseline_size) / baseline_size <= SIZE_TOLERANCE else "needs_review"


def next_id(existing: set[str], prefix: str) -> str:
    number = 1
    while f"{prefix}-{number:03d}" in existing:
        number += 1
    return f"{prefix}-{number:03d}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engagement_dir")
    parser.add_argument("--recon-dir", required=True, help="Directory containing manifest.json")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--append-hypotheses", action="store_true")
    parser.add_argument("--asset-id", default="")
    args = parser.parse_args()

    engagement_root = Path(args.engagement_dir).expanduser().resolve()
    run_root = Path(args.recon_dir).expanduser().resolve()
    try:
        manifest = load_manifest(run_root)
        target = str(manifest.get("target") or "")
        _, _, policy = authorize_run(engagement_root, target, "active-safe")
        nuclei_path = output_path(run_root, manifest, "nuclei", "nuclei_critical.jsonl")
        baseline_path = output_path(run_root, manifest, "baselines", "baselines.txt")
        if not nuclei_path.exists():
            print(
                "WARNING: nuclei output not found at "
                f"{nuclei_path.relative_to(run_root) if nuclei_path.is_relative_to(run_root) else nuclei_path}. "
                "This run's manifest may be from an older schema (v1) without an 'outputs' "
                "map; current runs write agents/scan/nuclei.jsonl. Point --recon-dir at a "
                "v2 manifest run directory to triage real findings.",
                file=sys.stderr,
            )
    except (ValueError, PolicyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    baselines = load_baselines(baseline_path)
    nuclei = load_nuclei(nuclei_path)
    if not nuclei:
        print(f"No findings in {nuclei_path} — nothing to triage.")
        return 0

    rows: list[dict] = []
    counts = {"likely_fp": 0, "needs_review": 0, "unreachable": 0, "out_of_scope": 0}
    print(f"Triaging {len(nuclei)} match(es) against {len(baselines)} baseline(s)...\n")
    for index, finding in enumerate(nuclei, 1):
        matched_at = str(finding.get("matched-at") or finding.get("host") or "")
        template_id = str(finding.get("template-id") or "?")
        info = finding.get("info") if isinstance(finding.get("info"), dict) else {}
        severity = str(info.get("severity") or "unknown")
        name = str(info.get("name") or template_id)
        if not policy.url_allowed(matched_at):
            result = "out_of_scope"
            baseline = live = None
        else:
            baseline = baselines.get(origin(matched_at))
            live = live_probe(matched_at, args.timeout)
            result = verdict(baseline, live)
        counts[result] = counts.get(result, 0) + 1
        rows.append({
            "template_id": template_id,
            "name": name,
            "severity": severity,
            "matched_at": matched_at,
            "verdict": result,
            "baseline": baseline,
            "live": live,
        })
        print(f"[{index}/{len(nuclei)}] {result:13s} {severity:8s} {template_id:35s} {matched_at}")

    report_path = run_root / "triage_report.csv"
    with report_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "template_id", "name", "severity", "matched_at", "verdict",
            "baseline_status", "baseline_size", "live_status", "live_size",
        ])
        for row in rows:
            baseline = row["baseline"] or ("", "")
            live = row["live"] or ("", "")
            writer.writerow([
                row["template_id"], row["name"], row["severity"], row["matched_at"], row["verdict"],
                baseline[0], baseline[1], live[0], live[1],
            ])

    print(
        f"\nSummary: {counts['likely_fp']} likely_fp | {counts['needs_review']} needs_review | "
        f"{counts['unreachable']} unreachable | {counts['out_of_scope']} blocked_by_scope"
    )
    print(f"Full report: {report_path}")

    if args.append_hypotheses:
        ledger_path = engagement_root / "hypothesis-ledger.csv"
        header_error = validate_ledger_header(ledger_path, LEDGER_SCHEMAS[ledger_path.name])
        if header_error:
            print(f"ERROR: {header_error}", file=sys.stderr)
            return 2
        with ledger_path.open(encoding="utf-8", newline="") as handle:
            existing_rows = list(csv.DictReader(handle))
        existing_ids = {row.get("hypothesis_id", "") for row in existing_rows}
        candidates = [row for row in rows if row["verdict"] == "needs_review"]
        if not candidates:
            print("\nNo needs_review items to append.")
            return 0
        with ledger_path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=LEDGER_SCHEMAS[ledger_path.name])
            for row in candidates:
                hypothesis_id = next_id(existing_ids, "HYP-SCAN")
                existing_ids.add(hypothesis_id)
                writer.writerow({
                    "hypothesis_id": hypothesis_id,
                    "asset_id": args.asset_id,
                    "surface_id": "",
                    "actor": "unauthenticated external actor",
                    "invariant": f"No unauthorized {row['name']} exposure",
                    "mutation": row["matched_at"],
                    "safe_validation": "manual baseline, controlled mutation, and negative-control comparison",
                    "priority": SEVERITY_PRIORITY.get(row["severity"], "P3"),
                    "status": "pending",
                    "notes": (
                        f"Imported from Nuclei template {row['template_id']} at {utc_now()}; "
                        "triage=needs_review; not confirmed."
                    ),
                })
        print(f"\nAppended {len(candidates)} hypothesis row(s) to {ledger_path}.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
