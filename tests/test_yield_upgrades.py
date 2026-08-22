"""Tests for the 2.8.0 critical-yield upgrades (tracks A, B, C)."""
from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))

from policy import PolicyError, ScopePolicy, authorize_run  # noqa: E402
from schemas import LEDGER_SCHEMAS, create_missing_ledgers  # noqa: E402
from gate_check import p3, p4  # noqa: E402


class AuthProfileTests(unittest.TestCase):
    def test_load_auth_profile_reads_env_and_masks(self) -> None:
        from vulnhunter_orchestrator import load_auth_profile, redact_command

        with mock.patch.dict(
            os.environ,
            {"VHS_AUTH_RESEARCHER_COOKIE": "session=abc123", "VHS_AUTH_RESEARCHER_BEARER": "tok456"},
        ):
            headers, secrets = load_auth_profile("researcher")
        self.assertEqual(headers, [("Cookie", "session=abc123"), ("Authorization", "Bearer tok456")])
        redacted = redact_command(["curl", "-H", "Cookie: session=abc123", "https://x.example"], secrets)
        self.assertNotIn("abc123", " ".join(redacted))
        self.assertIn("<redacted>", " ".join(redacted))

    def test_load_auth_profile_requires_env(self) -> None:
        from vulnhunter_orchestrator import load_auth_profile

        env = {k: v for k, v in os.environ.items() if not k.startswith("VHS_AUTH_")}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(PolicyError):
                load_auth_profile("missing")


class FingerprintCveTests(unittest.TestCase):
    def test_match_products_finds_token_and_version(self) -> None:
        from fingerprint_cve import match_products

        products = [{"product": "grafana", "aliases": [], "cves": []}]
        matches = match_products(["Grafana 9.4.1", "nginx"], products)
        self.assertEqual(len(matches), 1)
        _product, fingerprint, version = matches[0]
        self.assertEqual(fingerprint, "Grafana 9.4.1")
        self.assertEqual(version, "9.4.1")

    def test_build_hypotheses_ranks_known_exploited_first(self) -> None:
        from fingerprint_cve import build_hypotheses

        products = [
            {"product": "tomcat", "aliases": [], "cves": [
                {"id": "CVE-2017-12617", "summary": "put rce", "known_exploited": True, "cvss": 8.1},
            ]},
            {"product": "nginx", "aliases": [], "cves": [
                {"id": "CVE-2021-23017", "summary": "resolver", "known_exploited": False, "cvss": 7.7},
            ]},
        ]
        httpx_rows = [
            {"host": "a.example", "url": "https://a.example", "tech": ["Tomcat 8.5.0"], "webserver": "", "title": ""},
            {"host": "b.example", "url": "https://b.example", "tech": ["nginx"], "webserver": "", "title": ""},
        ]
        rows = build_hypotheses(httpx_rows, {}, products, lambda host: True)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["cve"], "CVE-2017-12617")  # KEV first despite lower CVSS
        self.assertEqual(rows[0]["known_exploited"], True)

    def test_build_hypotheses_respects_scope(self) -> None:
        from fingerprint_cve import build_hypotheses

        products = [{"product": "nginx", "aliases": [], "cves": [{"id": "CVE-1", "summary": "x", "known_exploited": False, "cvss": 5}]}]
        rows = build_hypotheses(
            [{"host": "evil.example", "url": "https://evil.example", "tech": ["nginx"], "webserver": "", "title": ""}],
            {}, products, lambda host: False,
        )
        self.assertEqual(rows, [])


class TakeoverCheckTests(unittest.TestCase):
    FINGERPRINTS = [
        {"service": "Heroku", "domains": ["herokudns.com"], "status": "claimable", "reference": "r"},
        {"service": "Fastly", "domains": ["fastly.net"], "status": "discontinued", "reference": "r"},
    ]

    def test_match_fingerprint_exact_and_subdomain(self) -> None:
        from takeover_check import match_fingerprint

        self.assertEqual(match_fingerprint("stellar-unicorn-42.herokudns.com", self.FINGERPRINTS)["service"], "Heroku")
        self.assertEqual(match_fingerprint("edge.fastly.net", self.FINGERPRINTS)["service"], "Fastly")
        self.assertIsNone(match_fingerprint("api.example.com", self.FINGERPRINTS))

    def test_verdict_uses_fingerprint_status_and_resolution(self) -> None:
        from takeover_check import check_hosts

        def fake_cname(host, timeout):
            return {"a.example": ["gone.herokudns.com"], "b.example": ["live.fastly.net"]}[host]

        def fake_resolves(host, timeout):
            return host != "gone.herokudns.com"

        with mock.patch("takeover_check.resolve_cname", fake_cname), \
                mock.patch("takeover_check.resolves", fake_resolves), \
                mock.patch("takeover_check.time.sleep"):
            rows = check_hosts(["a.example", "b.example"], self.FINGERPRINTS, timeout=5, rate=0, host_allowed=lambda h: True)
        verdicts = {row["host"]: row["verdict"] for row in rows}
        self.assertEqual(verdicts["a.example"], "takeover_candidate")
        self.assertEqual(verdicts["b.example"], "uses_service_normally")


class RaceProbeTests(unittest.TestCase):
    def test_build_request_includes_headers_and_body(self) -> None:
        from race_probe import build_request

        request = build_request("https://x.example/api/coupon?src=1", "POST", "code=X", ["Cookie: s=1"])
        text = request.decode()
        self.assertIn("POST /api/coupon?src=1 HTTP/1.1", text)
        self.assertIn("Host: x.example", text)
        self.assertIn("Cookie: s=1", text)
        self.assertIn("Content-Length: 6", text)

    def test_summarize_flags_mixed_outcomes(self) -> None:
        from race_probe import summarize

        results = [
            {"status_line": "HTTP/1.1 200 OK", "body_sha256_12": "aaa", "latency_ms": 10},
            {"status_line": "HTTP/1.1 200 OK", "body_sha256_12": "aaa", "latency_ms": 11},
            {"status_line": "HTTP/1.1 409 Conflict", "body_sha256_12": "bbb", "latency_ms": 12},
        ]
        summary = summarize(results)
        self.assertTrue(summary["mixed_outcome_signal"])
        self.assertEqual(summary["verdict_hint"], "race_window_candidate")

    def test_method_allowed_requires_race_permission(self) -> None:
        from race_probe import method_allowed

        self.assertIsNotNone(method_allowed({"allowed_methods": []}, "GET", state_change_flag=False))
        self.assertIsNone(method_allowed({"allowed_methods": ["race_testing"]}, "GET", state_change_flag=False))
        # POST without state-change opt-in is refused even with race_testing.
        self.assertIsNotNone(
            method_allowed({"allowed_methods": ["race_testing"]}, "POST", state_change_flag=False)
        )
        self.assertIsNone(
            method_allowed({"allowed_methods": ["race_testing", "state_change"]}, "POST", state_change_flag=True)
        )


def write_csv(root: Path, name: str, rows: list[dict[str, str]]) -> None:
    with (root / name).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEDGER_SCHEMAS[name])
        writer.writeheader()
        writer.writerows(rows)


def engagement_root(root: Path) -> None:
    now = datetime.now(timezone.utc)
    (root / "engagement.json").write_text(
        json.dumps({
            "engagement_id": "t-001", "authorization_status": "confirmed",
            "permission_mode": "ACTIVE_SAFE",
            "testing_window": {"start": (now - timedelta(days=1)).isoformat(), "end": (now + timedelta(days=1)).isoformat()},
            "allowed_assets": ["example.com"], "excluded_assets": [],
            "allowed_methods": ["automated_scanning"], "prohibited_methods": [],
        }), encoding="utf-8")
    (root / "state.json").write_text(json.dumps({"phases": {"P0": {"status": "completed"}}}), encoding="utf-8")


class TieredGateTests(unittest.TestCase):
    def _matrix_row(self, **overrides: str) -> dict[str, str]:
        row = {
            "test_id": "TST-001", "hypothesis_id": "HYP-001", "asset_id": "AST-001",
            "surface_id": "SUR-001", "baseline": "b", "mutation": "m",
            "expected_result": "r", "negative_control": "c", "evidence_plan": "p",
            "cleanup": "cl", "risk": "low", "permission_mode": "ACTIVE_SAFE",
            "status": "planned", "evidence_ids": "", "notes": "playbook: sqli",
        }
        row.update(overrides)
        return row

    def _fixture(self, root: Path, rows: list[dict[str, str]], *, mark_playbooks: bool = True) -> None:
        root.mkdir()
        engagement_root(root)
        state = json.loads((root / "state.json").read_text(encoding="utf-8"))
        if mark_playbooks:
            state["playbooks_loaded"] = True
        (root / "state.json").write_text(json.dumps(state), encoding="utf-8")
        write_csv(root, "asset-inventory.csv", [{"asset_id": "AST-001", "asset": "example.com", "type": "web", "environment": "prod", "owner": "o", "scope_status": "in_scope", "source": "manual", "notes": ""}])
        write_csv(root, "surface-inventory.csv", [{"surface_id": "SUR-001", "asset_id": "AST-001", "surface": "web", "protocol": "https", "auth_requirement": "none", "state_change_risk": "low", "third_party": "no", "scope_status": "in_scope", "source": "manual", "confidence": "high", "coverage_status": "planned", "notes": ""}])
        write_csv(root, "hypothesis-ledger.csv", [{"hypothesis_id": "HYP-001", "asset_id": "AST-001", "surface_id": "SUR-001", "actor": "external", "invariant": "i", "mutation": "m", "safe_validation": "s", "priority": "P2", "status": "pending", "notes": ""}])
        write_csv(root, "test-matrix.csv", rows)

    def test_read_only_row_skips_derivable_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "eng"
            row = self._matrix_row(
                negative_control="", cleanup="", risk="",
                notes="playbook: sqli; read-only GET probe",
            )
            self._fixture(root, [row])
            errors: list[str] = []
            p3(root, errors)
            self.assertEqual([e for e in errors if "missing" in e], [], errors)

    def test_state_changing_row_requires_full_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "eng"
            row = self._matrix_row(negative_control="", cleanup="", risk="")
            self._fixture(root, [row])
            errors: list[str] = []
            p3(root, errors)
            self.assertTrue(any("missing negative_control" in e for e in errors), errors)

    def test_playbooks_loaded_auto_satisfied_by_citations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "eng"
            self._fixture(root, [self._matrix_row()], mark_playbooks=False)
            errors: list[str] = []
            p3(root, errors)
            self.assertFalse(any("playbooks not loaded" in e for e in errors), errors)

    def test_playbooks_flag_still_required_without_citations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "eng"
            self._fixture(root, [self._matrix_row(notes="no citation")], mark_playbooks=False)
            errors: list[str] = []
            p3(root, errors)
            self.assertTrue(any("playbooks not loaded" in e for e in errors), errors)

    def test_lightweight_review_for_rejected_test(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "eng"
            row = self._matrix_row(status="rejected", evidence_ids="")
            self._fixture(root, [row])
            write_csv(root, "evidence-ledger.csv", [])
            review = {
                "review_id": "REV-001", "hypothesis_id": "HYP-001", "test_id": "TST-001",
                "finding_id": "", "claim": "", "evidence_ids": "",
                "alternative_explanation": "", "disconfirming_test": "",
                "negative_control": "", "scope_impact": "", "uncertainty": "",
                "decision": "reject", "reviewer": "operator",
                "reviewed_at_utc": "2026-08-22T00:00:00+00:00",
            }
            with (root / "critical-review.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=LEDGER_SCHEMAS["critical-review.csv"])
                writer.writeheader()
                writer.writerow(review)
            errors: list[str] = []
            p4(root, errors)
            self.assertEqual(errors, [], errors)

    def test_confirmed_test_still_requires_full_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "eng"
            row = self._matrix_row(status="confirmed", evidence_ids="EV-001")
            self._fixture(root, [row])
            write_csv(root, "evidence-ledger.csv", [{
                "evidence_id": "EV-001", "captured_at_utc": "2026-08-22T00:00:00+00:00",
                "hypothesis_id": "HYP-001", "test_id": "TST-001", "finding_id": "",
                "asset_id": "AST-001", "path": "evidence/redacted/EV-001.txt",
                "sha256": "a" * 64, "sensitivity": "low", "redaction_status": "reviewed",
                "observation": "observed", "cleanup_status": "complete",
            }])
            review = {
                "review_id": "REV-001", "hypothesis_id": "HYP-001", "test_id": "TST-001",
                "finding_id": "", "claim": "claim", "evidence_ids": "EV-001",
                "alternative_explanation": "", "disconfirming_test": "d",
                "negative_control": "c", "scope_impact": "s", "uncertainty": "low",
                "decision": "retain", "reviewer": "operator",
                "reviewed_at_utc": "2026-08-22T00:00:00+00:00",
            }
            with (root / "critical-review.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=LEDGER_SCHEMAS["critical-review.csv"])
                writer.writeheader()
                writer.writerow(review)
            errors: list[str] = []
            p4(root, errors)
            self.assertTrue(any("missing alternative_explanation" in e for e in errors), errors)


class TriageVerdictTests(unittest.TestCase):
    def test_same_status_different_head_is_never_likely_fp(self) -> None:
        from triage_scan import verdict

        baseline = ("404", 512, "aaaa1111bbbb")
        live = ("404", 520, "cccc2222dddd", False)
        self.assertEqual(verdict(baseline, live), "needs_review")

    def test_soft404_marker_and_similar_size_is_likely_fp(self) -> None:
        from triage_scan import verdict

        baseline = ("404", 512, "")
        live = ("404", 500, "", True)  # body head contains "not found"
        self.assertEqual(verdict(baseline, live), "likely_fp")

    def test_size_similarity_alone_still_flags_likely_fp(self) -> None:
        from triage_scan import verdict

        baseline = ("200", 1000, "")
        live = ("200", 1010, "", False)
        self.assertEqual(verdict(baseline, live), "likely_fp")


if __name__ == "__main__":
    unittest.main()
