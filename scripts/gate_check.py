#!/usr/bin/env python3
"""Validate and optionally advance CyberSec Superworkflow phase gates."""

from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from schemas import LEDGER_SCHEMAS, create_missing_ledgers, validate_ledger_header


PHASES = ["P0", "P1", "P2", "P3", "P4", "P5", "P6"]
PLACEHOLDERS = {"", "TO_BE_CONFIRMED", "<todo>", "todo", "unknown"}
FINAL_TEST_STATES = {"confirmed", "rejected", "blocked", "inconclusive", "not_applicable"}
REVIEW_DECISIONS = {"retain", "reject", "blocked", "inconclusive", "not_applicable"}
REVIEW_DECISION_BY_STATUS = {
    "confirmed": "retain",
    "rejected": "reject",
    "blocked": "blocked",
    "inconclusive": "inconclusive",
    "not_applicable": "not_applicable",
}
REVIEW_REQUIRED_FIELDS = (
    "review_id",
    "hypothesis_id",
    "test_id",
    "claim",
    "alternative_explanation",
    "disconfirming_test",
    "negative_control",
    "scope_impact",
    "uncertainty",
    "decision",
    "reviewer",
    "reviewed_at_utc",
)
PLAYBOOK_CITATION_RE = re.compile(
    r"(?:attack[-_ ]?playbooks?/|(?:playbook|pb)\s*[:=]\s*)"
    r"([A-Za-z0-9][A-Za-z0-9_-]*)(?:\.md)?",
    re.IGNORECASE,
)

CSV_TEMPLATES = LEDGER_SCHEMAS


def init_ledgers(root: Path) -> list[str]:
    return create_missing_ledgers(root)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"Missing required file: {path.name}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path.name}: {exc}") from None


def read_csv(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))
    except FileNotFoundError:
        raise ValueError(f"Missing required file: {path.name}") from None


def meaningful(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip() not in PLACEHOLDERS
    return value is not None


def split_ids(value: str) -> set[str]:
    return {part.strip() for part in value.replace(";", ",").split(",") if part.strip()}


def p0(root: Path, errors: list[str]) -> None:
    engagement = read_json(root / "engagement.json")
    required = (
        "owner",
        "operator",
        "scope_source",
        "testing_window",
        "emergency_contact",
        "disclosure_channel",
        "rate_limits",
    )
    if engagement.get("authorization_status") != "confirmed":
        errors.append("authorization_status must be 'confirmed'")
    for key in required:
        if not meaningful(engagement.get(key)):
            errors.append(f"engagement.json field '{key}' is incomplete")
    if not engagement.get("allowed_assets"):
        errors.append("allowed_assets must contain at least one explicit asset")
    if engagement.get("permission_mode") not in {
        "PASSIVE",
        "ACTIVE_SAFE",
        "CONTROLLED_IMPACT",
    }:
        errors.append("permission_mode must reflect confirmed permission")
    if not engagement.get("stop_conditions"):
        errors.append("at least one target-specific stop condition is required")
    if not isinstance(engagement.get("data_handling"), dict):
        errors.append("data_handling must be a structured object")


def p1(root: Path, errors: list[str]) -> None:
    assets = read_csv(root / "asset-inventory.csv")
    hypotheses = read_csv(root / "hypothesis-ledger.csv")
    in_scope = [row for row in assets if row.get("scope_status") == "in_scope"]
    if not in_scope:
        errors.append("asset-inventory.csv needs at least one in_scope asset")
    if not hypotheses:
        errors.append("hypothesis-ledger.csv needs at least one hypothesis")
    else:
        asset_ids = {row.get("asset_id", "") for row in assets}
        for index, row in enumerate(hypotheses, 2):
            for field in ("hypothesis_id", "asset_id", "actor", "invariant", "mutation", "status"):
                if not meaningful(row.get(field)):
                    errors.append(f"hypothesis-ledger.csv line {index}: missing {field}")
            if meaningful(row.get("asset_id")) and asset_ids and row.get("asset_id") not in asset_ids:
                errors.append(
                    f"hypothesis-ledger.csv line {index}: asset_id '{row.get('asset_id')}' not found in asset-inventory.csv"
                )
    model = root / "threat-model.md"
    if not model.exists():
        errors.append("threat-model.md is missing")
    else:
        model_text = model.read_text(encoding="utf-8")
        if "<Document" in model_text or len(model_text.strip()) < 600:
            errors.append("threat-model.md is still substantially incomplete")


def p2(root: Path, errors: list[str]) -> None:
    surfaces = read_csv(root / "surface-inventory.csv")
    assets = read_csv(root / "asset-inventory.csv")
    asset_ids = {row.get("asset_id", "") for row in assets}
    if not surfaces:
        errors.append("surface-inventory.csv needs at least one mapped surface")
    for index, row in enumerate(surfaces, 2):
        # scope_status is a controlled vocabulary where "unknown" is a valid,
        # deliberate value (quarantined pending clarification) — it must NOT
        # be treated as a placeholder/incompleteness marker like elsewhere.
        for field in ("surface_id", "asset_id", "surface", "source", "confidence"):
            if not meaningful(row.get(field)):
                errors.append(f"surface-inventory.csv line {index}: missing {field}")
        if row.get("scope_status") not in {"in_scope", "out_of_scope", "unknown"}:
            errors.append(f"surface-inventory.csv line {index}: invalid or missing scope_status")
        if meaningful(row.get("asset_id")) and asset_ids and row.get("asset_id") not in asset_ids:
            errors.append(
                f"surface-inventory.csv line {index}: asset_id '{row.get('asset_id')}' not found in asset-inventory.csv"
            )


def p3(root: Path, errors: list[str]) -> None:
    surfaces = read_csv(root / "surface-inventory.csv")
    tests = read_csv(root / "test-matrix.csv")
    hypotheses = read_csv(root / "hypothesis-ledger.csv")
    assets = read_csv(root / "asset-inventory.csv")
    hypothesis_ids = {row.get("hypothesis_id", "") for row in hypotheses}
    asset_ids = {row.get("asset_id", "") for row in assets}
    surface_ids = {row.get("surface_id", "") for row in surfaces}
    state = read_json(root / "state.json")
    if state.get("playbooks_loaded") is not True:
        errors.append(
            "playbooks not loaded: run gate_check.py --phase P3 --mark-playbooks after reading references/attack-playbooks/00-index.md"
        )
    playbook_dir = Path(__file__).resolve().parents[1] / "references" / "attack-playbooks"
    if not tests:
        errors.append("test-matrix.csv needs at least one planned test")
    covered_surfaces = {row.get("surface_id", "") for row in tests}
    for row in surfaces:
        if row.get("scope_status") != "in_scope":
            continue
        coverage = row.get("coverage_status", "")
        if row.get("surface_id") not in covered_surfaces and coverage not in {
            "blocked",
            "not_applicable",
        }:
            errors.append(
                f"in-scope surface {row.get('surface_id') or '<missing>'} lacks a test or justified coverage status"
            )
    for index, row in enumerate(tests, 2):
        notes = row.get("notes", "")
        citation = PLAYBOOK_CITATION_RE.search(notes)
        if not citation:
            errors.append(
                f"test-matrix.csv line {index} ({row.get('test_id') or '?'}): notes must cite a playbook "
                f"(e.g. notes='playbook: sqli' or 'attack-playbooks/sqli.md') — see references/attack-playbooks/00-index.md"
            )
        elif not (playbook_dir / f"{citation.group(1).lower()}.md").is_file():
            errors.append(
                f"test-matrix.csv line {index} ({row.get('test_id') or '?'}): "
                f"playbook '{citation.group(1)}' does not exist under references/attack-playbooks/"
            )
        for field in (
            "test_id",
            "hypothesis_id",
            "asset_id",
            "surface_id",
            "baseline",
            "mutation",
            "expected_result",
            "negative_control",
            "cleanup",
            "risk",
            "permission_mode",
            "status",
        ):
            if not meaningful(row.get(field)):
                errors.append(f"test-matrix.csv line {index}: missing {field}")
        if meaningful(row.get("hypothesis_id")) and hypothesis_ids and row.get("hypothesis_id") not in hypothesis_ids:
            errors.append(f"test-matrix.csv line {index}: hypothesis_id '{row.get('hypothesis_id')}' not found in hypothesis-ledger.csv")
        if meaningful(row.get("asset_id")) and asset_ids and row.get("asset_id") not in asset_ids:
            errors.append(f"test-matrix.csv line {index}: asset_id '{row.get('asset_id')}' not found in asset-inventory.csv")
        if meaningful(row.get("surface_id")) and surface_ids and row.get("surface_id") not in surface_ids:
            errors.append(f"test-matrix.csv line {index}: surface_id '{row.get('surface_id')}' not found in surface-inventory.csv")


def p4(root: Path, errors: list[str]) -> None:
    tests = read_csv(root / "test-matrix.csv")
    evidence = read_csv(root / "evidence-ledger.csv")
    evidence_ids = {row.get("evidence_id", "") for row in evidence}
    if not tests:
        errors.append("no tests exist")
    for index, row in enumerate(tests, 2):
        status = row.get("status", "")
        if status not in FINAL_TEST_STATES:
            errors.append(f"test-matrix.csv line {index}: status '{status}' is not final")
        if status == "confirmed":
            linked = split_ids(row.get("evidence_ids", ""))
            if not linked:
                errors.append(f"confirmed test {row.get('test_id')} has no evidence_ids")
            for evidence_id in linked:
                if evidence_id not in evidence_ids:
                    errors.append(f"confirmed test {row.get('test_id')} references unknown {evidence_id}")
    for index, row in enumerate(evidence, 2):
        for field in ("evidence_id", "captured_at_utc", "path", "sha256", "redaction_status", "observation"):
            if not meaningful(row.get(field)):
                errors.append(f"evidence-ledger.csv line {index}: missing {field}")
    reviews = read_critical_reviews(root, errors)
    validate_critical_reviews(reviews, tests, evidence_ids, errors)


def p5(root: Path, errors: list[str]) -> None:
    tests = read_csv(root / "test-matrix.csv")
    findings = read_csv(root / "findings-index.csv")
    evidence = read_csv(root / "evidence-ledger.csv")
    evidence_ids = {row.get("evidence_id", "") for row in evidence}
    confirmed_tests = [row for row in tests if row.get("status") == "confirmed"]
    if confirmed_tests and not findings:
        errors.append("confirmed tests exist but findings-index.csv is empty")
    for index, row in enumerate(findings, 2):
        for field in (
            "finding_id",
            "title",
            "root_cause",
            "affected_assets",
            "status",
            "severity",
            "severity_rationale",
            "confidence",
            "prerequisite",
            "demonstrated_impact",
            "evidence_ids",
        ):
            if not meaningful(row.get(field)):
                errors.append(f"findings-index.csv line {index}: missing {field}")
        for evidence_id in split_ids(row.get("evidence_ids", "")):
            if evidence_id not in evidence_ids:
                errors.append(f"finding {row.get('finding_id')} references unknown {evidence_id}")
    reviews = read_critical_reviews(root, errors)
    validate_critical_reviews(reviews, tests, evidence_ids, errors, findings=findings)


def read_critical_reviews(root: Path, errors: list[str]) -> list[dict[str, str]]:
    header_error = validate_ledger_header(root / "critical-review.csv", CSV_TEMPLATES["critical-review.csv"])
    if header_error:
        errors.append(header_error)
        return []
    try:
        return read_csv(root / "critical-review.csv")
    except ValueError as exc:
        errors.append(str(exc))
        return []


def validate_critical_reviews(
    reviews: list[dict[str, str]],
    tests: list[dict[str, str]],
    evidence_ids: set[str],
    errors: list[str],
    *,
    findings: list[dict[str, str]] | None = None,
) -> None:
    """Enforce one bounded adversarial review per finalized test and finding."""
    test_by_id = {row.get("test_id", ""): row for row in tests if row.get("test_id")}
    reviews_by_test: dict[str, dict[str, str]] = {}
    for index, row in enumerate(reviews, 2):
        for field in REVIEW_REQUIRED_FIELDS:
            if not meaningful(row.get(field)):
                errors.append(f"critical-review.csv line {index}: missing {field}")
        test_id = row.get("test_id", "")
        if test_id not in test_by_id:
            errors.append(f"critical-review.csv line {index}: test_id '{test_id}' not found in test-matrix.csv")
        elif test_id in reviews_by_test:
            errors.append(f"critical-review.csv line {index}: duplicate review for test_id '{test_id}'")
        else:
            reviews_by_test[test_id] = row
            expected_hypothesis = test_by_id[test_id].get("hypothesis_id", "")
            if row.get("hypothesis_id") != expected_hypothesis:
                errors.append(
                    f"critical-review.csv line {index}: hypothesis_id does not match test {test_id}"
                )
            for evidence_id in split_ids(row.get("evidence_ids", "")):
                if evidence_id not in evidence_ids:
                    errors.append(f"critical-review.csv line {index}: unknown evidence_id '{evidence_id}'")
            decision = row.get("decision", "")
            if decision not in REVIEW_DECISIONS:
                errors.append(f"critical-review.csv line {index}: invalid decision '{decision}'")
            expected_decision = REVIEW_DECISION_BY_STATUS.get(test_by_id[test_id].get("status", ""))
            if expected_decision and decision and decision != expected_decision:
                errors.append(
                    f"critical-review.csv line {index}: decision '{decision}' does not match test status "
                    f"'{test_by_id[test_id].get('status')}'"
                )
            if test_by_id[test_id].get("status") == "confirmed":
                test_evidence = split_ids(test_by_id[test_id].get("evidence_ids", ""))
                review_evidence = split_ids(row.get("evidence_ids", ""))
                if not test_evidence.issubset(review_evidence):
                    errors.append(
                        f"critical-review.csv line {index}: confirmed test {test_id} review must include its evidence_ids"
                    )

    for test in tests:
        if test.get("status") in FINAL_TEST_STATES and test.get("test_id") not in reviews_by_test:
            errors.append(
                f"critical-review.csv needs one review for finalized test {test.get('test_id') or '<missing>'}"
            )

    if findings is None:
        return

    finding_ids = {row.get("finding_id", "") for row in findings if row.get("finding_id")}
    for index, row in enumerate(reviews, 2):
        finding_id = row.get("finding_id", "")
        if finding_id and finding_id not in finding_ids:
            errors.append(f"critical-review.csv line {index}: finding_id '{finding_id}' not found in findings-index.csv")
    for finding in findings:
        finding_id = finding.get("finding_id", "")
        linked = [row for row in reviews if row.get("finding_id") == finding_id]
        if not linked:
            errors.append(f"critical-review.csv needs a linked review for finding {finding_id or '<missing>'}")
        elif not any(row.get("decision") == "retain" for row in linked):
            errors.append(f"critical-review.csv finding {finding_id} needs a review with decision 'retain'")


def p6(root: Path, errors: list[str]) -> None:
    state = read_json(root / "state.json")
    report = root / "final-report.md"
    if not report.exists() or report.stat().st_size < 500:
        errors.append("final-report.md is missing or too incomplete")
    if state.get("redaction_reviewed") is not True:
        errors.append("state.json redaction_reviewed must be true after automated and manual review")
    if state.get("disclosure_status") not in {"ready", "submitted", "acknowledged"}:
        errors.append("disclosure_status must be ready, submitted, or acknowledged")


CHECKS = {"P0": p0, "P1": p1, "P2": p2, "P3": p3, "P4": p4, "P5": p5, "P6": p6}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a CyberSec Superworkflow phase gate.")
    parser.add_argument("directory", help="Engagement directory")
    parser.add_argument("--phase", choices=PHASES, help="Phase to check (not needed with --init)")
    parser.add_argument("--advance", action="store_true", help="Advance state after a passing gate")
    parser.add_argument("--init", action="store_true", help="Create missing ledger CSVs with correct headers")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text")
    parser.add_argument(
        "--mark-playbooks",
        action="store_true",
        help="Mark state.json playbooks_loaded=true after reading references/attack-playbooks/00-index.md (required before P3 advance)",
    )
    args = parser.parse_args()

    root = Path(args.directory).expanduser().resolve()
    if not args.init and not args.phase and not args.mark_playbooks:
        parser.error("--phase is required unless --init or --mark-playbooks is used")
    if args.mark_playbooks:
        state = read_json(root / "state.json")
        state["playbooks_loaded"] = True
        state["updated_at"] = utc_now()
        (root / "state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        msg = "Playbooks marked as loaded. P3 advance will now accept playbook-grounded tests."
        print(json.dumps({"phase": args.phase, "pass": True, "playbooks_loaded": True}) if args.json else msg)
        return 0
    if args.init:
        created = init_ledgers(root)
        msg = f"INIT: created {len(created)} ledger(s): {', '.join(created)}" if created else "INIT: all ledgers already exist"
        print(json.dumps({"init": True, "created": created}) if args.json else msg)
        return 0
    errors: list[str] = []
    try:
        state = read_json(root / "state.json")
        for name, headers in CSV_TEMPLATES.items():
            if name == "critical-review.csv":
                continue
            header_error = validate_ledger_header(root / name, headers)
            if header_error:
                errors.append(header_error)
        if not errors:
            CHECKS[args.phase](root, errors)
    except ValueError as exc:
        errors.append(str(exc))

    if errors:
        if args.json:
            print(json.dumps({"phase": args.phase, "pass": False, "errors": errors}, indent=2))
        else:
            print(f"FAIL {args.phase}: {len(errors)} gate issue(s)")
            for item in errors:
                print(f"- {item}")
        return 1

    if not args.json:
        print(f"PASS {args.phase}: automated checks satisfied")
        print("Confirm the phase reference's human-judgment requirements before advancing.")

    if args.advance:
        current = state.get("current_phase")
        if current != args.phase:
            msg = f"REFUSED: state current_phase is {current!r}, not {args.phase!r}"
            print(json.dumps({"phase": args.phase, "pass": True, "advanced": False, "reason": msg}) if args.json else msg)
            return 2
        phase_index = PHASES.index(args.phase)
        state["phases"][args.phase]["status"] = "completed"
        state["phases"][args.phase]["completed_at"] = utc_now()
        if phase_index + 1 < len(PHASES):
            next_phase = PHASES[phase_index + 1]
            state["current_phase"] = next_phase
            state["phases"][next_phase]["status"] = "in_progress"
        else:
            state["current_phase"] = "COMPLETE"
        state["updated_at"] = utc_now()
        (root / "state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        if args.json:
            print(json.dumps({"phase": args.phase, "pass": True, "advanced": True, "current_phase": state["current_phase"]}))
        else:
            print(f"ADVANCED: {args.phase} -> {state['current_phase']}")
    elif args.json:
        print(json.dumps({"phase": args.phase, "pass": True, "advanced": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
