#!/usr/bin/env python3
"""Create a non-destructive workspace for an authorized security assessment."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from schemas import create_missing_ledgers


PHASES = ["P0", "P1", "P2", "P3", "P4", "P5", "P6"]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def write_private_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def write_json(path: Path, value: object) -> None:
    write_private_text(path, json.dumps(value, indent=2) + "\n")



def safe_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:80] or "assessment"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Initialize a CyberSec Superworkflow engagement directory."
    )
    parser.add_argument("directory", help="New or empty engagement directory")
    parser.add_argument("--title", required=True, help="Human-facing assessment title")
    parser.add_argument("--target", required=True, help="Primary target label")
    parser.add_argument("--owner", default="TO_BE_CONFIRMED", help="Target owner/program")
    parser.add_argument("--operator", default="TO_BE_CONFIRMED", help="Researcher/operator")
    parser.add_argument("--scope-source", default="TO_BE_CONFIRMED", help="URL/doc that defines the authorized scope (RoE, program page)")
    parser.add_argument("--testing-window", default="TO_BE_CONFIRMED", help="Authorized testing window, e.g. '2026-08-01T00:00Z..2026-08-15T00:00Z'")
    parser.add_argument("--emergency-contact", default="TO_BE_CONFIRMED", help="Who to notify on a hard-stop event")
    parser.add_argument("--disclosure-channel", default="TO_BE_CONFIRMED", help="Approved channel for reporting findings")
    parser.add_argument("--rate-limit", default="TO_BE_CONFIRMED", help="Agreed max request rate, e.g. '50 req/s, burst 100'")
    parser.add_argument("--allowed-asset", action="append", default=[], help="Explicit in-scope asset; repeatable")
    parser.add_argument("--excluded-asset", action="append", default=[], help="Explicit out-of-scope asset; repeatable")
    parser.add_argument("--allowed-method", action="append", default=[], help="Explicitly permitted test method; repeatable")
    parser.add_argument("--prohibited-method", action="append", default=[], help="Explicitly prohibited test method; repeatable")
    parser.add_argument("--test-identity", action="append", default=[], help="Approved researcher-owned test identity; repeatable")
    parser.add_argument("--data-retention", default="TO_BE_CONFIRMED", help="Evidence retention rule from the engagement")
    parser.add_argument(
        "--authorization-status",
        default="unconfirmed",
        choices=["unconfirmed", "confirmed"],
        help="Use 'confirmed' only after independently verifying the current authorization and scope",
    )
    parser.add_argument(
        "--permission-mode",
        default="PLAN_ONLY",
        choices=["PLAN_ONLY", "PASSIVE", "ACTIVE_SAFE", "CONTROLLED_IMPACT"],
        help="Starting permission mode — default is the safest and should only be raised once authorization is confirmed",
    )
    args = parser.parse_args()

    root = Path(args.directory).expanduser().resolve()
    if root.exists() and any(root.iterdir()):
        raise SystemExit(f"Refusing to overwrite non-empty directory: {root}")

    root.mkdir(parents=True, exist_ok=True)
    for relative in ("evidence/raw", "evidence/redacted", "findings"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
        for relative in ("evidence", "evidence/raw", "evidence/redacted", "findings"):
            (root / relative).chmod(0o700)
    except OSError:
        pass

    # evidence/raw holds UNREDACTED material (may contain tokens, cookies,
    # PII, credentials). If this engagement dir ever lives inside a git repo,
    # it must never be committed. Belt-and-suspenders: ignore it at both the
    # engagement root and inside the folder itself.
    write_private_text(root / ".gitignore", "evidence/raw/\n")
    write_private_text(root / "evidence" / "raw" / ".gitignore", "*\n!.gitignore\n")

    engagement_id = f"{safe_slug(args.title)}-{datetime.now(timezone.utc):%Y%m%d}"
    engagement = {
        "schema_version": 2,
        "engagement_id": engagement_id,
        "title": args.title,
        "primary_target": args.target,
        "owner": args.owner,
        "operator": args.operator,
        "authorization_status": args.authorization_status,
        "scope_source": args.scope_source,
        "allowed_assets": args.allowed_asset,
        "excluded_assets": args.excluded_asset,
        "testing_window": args.testing_window,
        "timezone": "UTC",
        "permission_mode": args.permission_mode,
        "allowed_methods": args.allowed_method,
        "prohibited_methods": args.prohibited_method,
        "rate_limits": args.rate_limit,
        "test_identities": args.test_identity,
        "emergency_contact": args.emergency_contact,
        "disclosure_channel": args.disclosure_channel,
        "data_handling": {
            "classification": "confidential",
            "minimize_collection": True,
            "redact_before_sharing": True,
            "retention": args.data_retention,
        },
        "stop_conditions": [
            "scope uncertainty",
            "production instability",
            "real-user or third-party impact",
            "sensitive credential or regulated-data exposure",
            "real-fund risk",
        ],
        "created_at": utc_now(),
    }
    state = {
        "schema_version": 2,
        "current_phase": "P0",
        "phases": {
            phase: {
                "status": "in_progress" if phase == "P0" else "pending",
                "completed_at": None,
                "gate_notes": "",
            }
            for phase in PHASES
        },
        "redaction_reviewed": False,
        "disclosure_status": "draft",
        "retest_status": "not_started",
        "updated_at": utc_now(),
    }
    write_json(root / "engagement.json", engagement)
    write_json(root / "state.json", state)

    create_missing_ledgers(root)

    write_private_text(root / "threat-model.md",
        "# Threat Model\n\n"
        "## Architecture and data flows\n\n"
        "<Document the authorized system.>\n\n"
        "## Actors and roles\n\n"
        "<Document user, service, admin, support, partner, wallet, and automation roles.>\n\n"
        "## Trust boundaries\n\n"
        "<Document tenant, identity, service, client/server, and off-chain/on-chain boundaries.>\n\n"
        "## Sensitive assets and authoritative state\n\n"
        "<Document secrets, data, funds, permissions, and systems of record.>\n\n"
        "## Security invariants\n\n"
        "<Write falsifiable invariant statements.>\n\n"
        "## Limitations\n\n"
        "<Document unavailable roles, excluded systems, and prohibited actions.>\n"
    )
    write_private_text(root / "session-log.md",
        f"# Session Log\n\n"
        f"## {utc_now()} — Workspace initialized\n\n"
        f"- Engagement: {args.title}\n"
        f"- Primary target: {args.target}\n"
        "- Phase: P0\n"
        f"- Permission mode: {args.permission_mode}\n"
        "- Action: Created assessment ledgers; no target interaction performed.\n"
    )
    write_private_text(root / "report-draft.md",
        f"# Security Assessment — {args.target}\n\n"
        "Status: Draft; not cleared for disclosure.\n\n"
        "## Executive Summary\n\n<Complete after triage.>\n\n"
        "## Engagement and Scope\n\n<Complete from engagement.json.>\n\n"
        "## Methodology and Coverage\n\n<Complete from P0–P6 ledgers.>\n\n"
        "## Findings Summary\n\n<Complete from findings-index.csv.>\n\n"
        "## Findings\n\n<Insert evidence-backed findings.>\n\n"
        "## Limitations\n\n<Complete from the threat model and blocked tests.>\n"
    )

    write_private_text(root / "README.md",
        "# Engagement workspace\n\n"
        "| File | Purpose | Phase |\n"
        "|---|---|---|\n"
        "| `engagement.json` | Authorization, scope, RoE, rate limits | P0 |\n"
        "| `state.json` | Current phase + gate history — do not hand-edit `current_phase` | all |\n"
        "| `threat-model.md` | Architecture, actors, trust boundaries, invariants | P1 |\n"
        "| `asset-inventory.csv` | Authorized/discovered assets + scope status | P1-P2 |\n"
        "| `surface-inventory.csv` | Mapped interfaces with provenance | P2 |\n"
        "| `hypothesis-ledger.csv` | Falsifiable hypotheses tied to an asset/actor/invariant | P1-P3 |\n"
        "| `test-matrix.csv` | Planned tests: baseline, mutation, negative control, cleanup | P3-P4 |\n"
        "| `evidence-ledger.csv` | Provenance + SHA-256 + redaction status per evidence item | P4 |\n"
        "| `critical-review.csv` | Claim, alternative, disconfirming test, controls, uncertainty, decision | P4-P5 |\n"
        "| `findings-index.csv` | Root-caused, evidence-backed findings | P5 |\n"
        "| `evidence/raw/` | **Unredacted** evidence — never commit, never share directly | P4 |\n"
        "| `evidence/redacted/` | Sanitized copies safe for the report/disclosure | P6 |\n"
        "| `session-log.md` | Chronological method/timing/stop-event log | all |\n"
        "| `report-draft.md` → `final-report.md` | The deliverable | P6 |\n\n"
        "Run `python3 scripts/gate_check.py <this-dir> --phase P0` after filling in `engagement.json` "
        "before doing anything beyond passive/plan-only work.\n"
    )

    print(f"Created engagement workspace: {root}")
    print(f"Current phase: P0 (authorization {args.authorization_status}; {args.permission_mode})")
    print("Next: complete engagement.json, then run gate_check.py --phase P0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
