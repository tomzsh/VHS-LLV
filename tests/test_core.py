from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))

from policy import PolicyError, ScopePolicy, authorize_run  # noqa: E402
from api_auth_probe import resolve_endpoint, state_change_allowed  # noqa: E402
from schemas import LEDGER_SCHEMAS, create_missing_ledgers  # noqa: E402
from vulnhunter_orchestrator import Step, authorization_fingerprint, stage  # noqa: E402


class SchemaTests(unittest.TestCase):
    def test_shared_schema_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            created = create_missing_ledgers(root)
            self.assertEqual(set(created), set(LEDGER_SCHEMAS))
            for name, expected in LEDGER_SCHEMAS.items():
                with (root / name).open(newline="", encoding="utf-8") as handle:
                    actual = next(csv.reader(handle))
                self.assertEqual(actual, expected)


class ToolCheckTests(unittest.TestCase):
    def test_naabu_initialization_error_is_not_reported_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fakebin = Path(temp) / "bin"
            fakebin.mkdir()
            naabu = fakebin / "naabu"
            naabu.write_text(
                "#!/usr/bin/env bash\necho 'could not initialize router' >&2\nexit 1\n",
                encoding="utf-8",
            )
            naabu.chmod(0o755)
            env = {**os.environ, "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", "")}
            process = subprocess.run(
                [sys.executable, str(SCRIPTS / "check_tools.py"), "--profile", "active-safe", "--verify", "--json"],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env=env,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            self.assertFalse(result["verification"]["naabu"]["ok"])

    def test_crawl4ai_launcher_honors_python_override(self) -> None:
        process = subprocess.run(
            ["bash", str(SCRIPTS / "crawl4ai_crawl.sh"), "--help"],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
            env={**os.environ, "VHS_CRAWL4AI_PYTHON": "/bin/true"},
        )
        self.assertEqual(process.returncode, 0, process.stderr)


class ScopeTests(unittest.TestCase):
    def test_deny_precedence_and_url_filter(self) -> None:
        policy = ScopePolicy(["example.com", "*.example.com"], ["admin.example.com"])
        self.assertTrue(policy.host_allowed("api.example.com"))
        self.assertTrue(policy.host_allowed("deep.api.example.com"))
        self.assertTrue(policy.url_allowed("https://api.example.com/v1?q=1"))
        self.assertFalse(policy.host_allowed("admin.example.com"))
        self.assertFalse(policy.url_allowed("https://evil.example.net/"))
        self.assertFalse(policy.url_allowed("file:///etc/passwd"))

    def test_scope_file_cannot_expand_engagement(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            scope = Path(temp) / "scope.txt"
            scope.write_text("example.com\nevil.test\n", encoding="utf-8")
            engagement = {"allowed_assets": ["example.com"], "excluded_assets": []}
            policy = ScopePolicy.from_engagement(engagement, scope)
            self.assertTrue(policy.host_allowed("example.com"))
            self.assertFalse(policy.host_allowed("evil.test"))


class ApiProbeTests(unittest.TestCase):
    def test_resolve_endpoint_rejects_absolute_out_of_scope_url(self) -> None:
        policy = ScopePolicy(["api.example.com"])
        with self.assertRaises(PolicyError):
            resolve_endpoint("https://api.example.com", "https://evil.test/x", policy)

    def test_resolve_endpoint_accepts_relative_path(self) -> None:
        policy = ScopePolicy(["api.example.com"])
        self.assertEqual(
            resolve_endpoint("https://api.example.com", "/v1/items", policy),
            "https://api.example.com/v1/items",
        )

    def test_resolve_endpoint_rejects_url_credentials(self) -> None:
        policy = ScopePolicy(["api.example.com"])
        with self.assertRaises(PolicyError):
            resolve_endpoint("https://api.example.com", "https://user:pass@api.example.com/v1", policy)

    def test_state_change_requires_flag_and_method_permission(self) -> None:
        engagement = {"allowed_methods": ["post"]}
        self.assertFalse(state_change_allowed(engagement, "POST", False))
        self.assertTrue(state_change_allowed(engagement, "POST", True))
        self.assertFalse(state_change_allowed(engagement, "DELETE", True))


class DeliverableTests(unittest.TestCase):
    def test_import_failure_returns_nonzero_and_reports_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "engagement"
            root.mkdir()
            (root / "findings-index.csv").write_text("finding_id\nF-001\n", encoding="utf-8")
            fakebin = Path(temp) / "bin"
            fakebin.mkdir()
            officecli = fakebin / "officecli"
            officecli.write_text(
                "#!/usr/bin/env bash\n"
                "if [ \"$1\" = \"import\" ]; then exit 1; fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            officecli.chmod(0o700)
            process = subprocess.run(
                ["bash", str(SCRIPTS / "make_deliverables.sh"), str(root)],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", "")},
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("import failed", process.stdout + process.stderr)


class AuthorizationTests(unittest.TestCase):
    def make_engagement(self, root: Path) -> None:
        root.mkdir()
        (root / "engagement.json").write_text(
            json.dumps(
                {
                    "engagement_id": "test-001",
                    "authorization_status": "confirmed",
                    "permission_mode": "ACTIVE_SAFE",
                    "testing_window": "2026-01-01T00:00:00Z..2026-12-31T23:59:59Z",
                    "allowed_assets": ["example.com", "*.example.com"],
                    "excluded_assets": ["admin.example.com"],
                    "allowed_methods": ["automated_scanning"],
                    "prohibited_methods": [],
                }
            ),
            encoding="utf-8",
        )
        (root / "state.json").write_text(
            json.dumps({"phases": {"P0": {"status": "completed"}}}),
            encoding="utf-8",
        )

    def test_authorized_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "engagement"
            self.make_engagement(root)
            engagement, _, policy = authorize_run(
                root,
                "example.com",
                "scanner-safe",
                at=datetime(2026, 7, 31, 12, tzinfo=timezone.utc),
            )
            self.assertEqual(engagement["authorization_status"], "confirmed")
            self.assertTrue(policy.host_allowed("api.example.com"))

    def test_refuses_outside_window(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "engagement"
            self.make_engagement(root)
            with self.assertRaises(PolicyError):
                authorize_run(
                    root,
                    "example.com",
                    "active-safe",
                    at=datetime(2027, 1, 1, tzinfo=timezone.utc),
                )


class EngagementCliTests(unittest.TestCase):
    def test_new_engagement_and_p0_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "engagement"
            create = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "new_engagement.py"), str(root),
                    "--title", "Test", "--target", "example.com",
                    "--owner", "Owner", "--operator", "Operator",
                    "--scope-source", "https://example.com/rules",
                    "--testing-window", "2026-01-01T00:00:00Z..2026-12-31T23:59:59Z",
                    "--emergency-contact", "security@example.com",
                    "--disclosure-channel", "security@example.com",
                    "--rate-limit", "10 req/s",
                    "--allowed-asset", "example.com",
                    "--permission-mode", "ACTIVE_SAFE",
                    "--authorization-status", "confirmed",
                    "--allowed-method", "http_probe",
                    "--prohibited-method", "port_scan",
                    "--test-identity", "researcher@example.com",
                    "--data-retention", "Delete raw evidence after triage.",
                ],
                text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(create.returncode, 0, create.stderr)
            engagement = json.loads((root / "engagement.json").read_text(encoding="utf-8"))
            self.assertEqual(engagement["authorization_status"], "confirmed")
            self.assertEqual(engagement["allowed_methods"], ["http_probe"])
            self.assertEqual(engagement["prohibited_methods"], ["port_scan"])
            self.assertEqual(engagement["test_identities"], ["researcher@example.com"])
            self.assertEqual(engagement["data_handling"]["retention"], "Delete raw evidence after triage.")
            gate = subprocess.run(
                [sys.executable, str(SCRIPTS / "gate_check.py"), str(root), "--phase", "P0"],
                text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(gate.returncode, 0, gate.stdout + gate.stderr)


class EvidenceCaptureTests(unittest.TestCase):
    def create_evidence_ledger(self, root: Path) -> None:
        (root / "evidence" / "raw").mkdir(parents=True)
        (root / "evidence" / "redacted").mkdir()
        with (root / "evidence-ledger.csv").open("w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow(LEDGER_SCHEMAS["evidence-ledger.csv"])

    def test_capture_names_are_unique_and_hashes_remain_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.create_evidence_ledger(root)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            (first / "response.json").write_text("first", encoding="utf-8")
            (second / "response.json").write_text("second", encoding="utf-8")
            for evidence_id, source in (("EV-001", first / "response.json"), ("EV-002", second / "response.json")):
                result = subprocess.run(
                    [
                        sys.executable, str(SCRIPTS / "evidence_capture.py"), str(root),
                        "--evidence-id", evidence_id, "--asset", "AST-001",
                        "--observation", evidence_id, "--file", str(source),
                    ],
                    text=True, capture_output=True, check=False, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            with (root / "evidence-ledger.csv").open(encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len({row["path"] for row in rows}), 2)
            for row in rows:
                artifact = root / row["path"]
                self.assertEqual(hashlib.sha256(artifact.read_bytes()).hexdigest(), row["sha256"])

    def test_header_mismatch_fails_without_replacing_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "evidence" / "raw").mkdir(parents=True)
            (root / "evidence" / "redacted").mkdir()
            ledger = root / "evidence-ledger.csv"
            ledger.write_text("wrong,header\nkeep,this\n", encoding="utf-8")
            source = root / "response.txt"
            source.write_text("payload", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "evidence_capture.py"), str(root),
                    "--evidence-id", "EV-001", "--asset", "AST-001",
                    "--observation", "test", "--file", str(source),
                ],
                text=True, capture_output=True, check=False, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(ledger.read_text(encoding="utf-8"), "wrong,header\nkeep,this\n")

    def test_raw_collision_preserves_preexisting_artifact_and_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.create_evidence_ledger(root)
            ledger = root / "evidence-ledger.csv"
            ledger_before = ledger.read_bytes()
            source = root / "source" / "response.txt"
            source.parent.mkdir()
            source.write_bytes(b"new raw evidence")
            collision = root / "evidence" / "raw" / "EV-001-response.txt"
            collision.write_bytes(b"preserve raw artifact")

            result = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "evidence_capture.py"), str(root),
                    "--evidence-id", "EV-001", "--asset", "AST-001",
                    "--observation", "test", "--file", str(source),
                ],
                text=True, capture_output=True, check=False, timeout=30,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(collision.read_bytes(), b"preserve raw artifact")
            self.assertEqual(ledger.read_bytes(), ledger_before)

    def test_redacted_collision_preserves_preexisting_artifact_and_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.create_evidence_ledger(root)
            ledger = root / "evidence-ledger.csv"
            ledger_before = ledger.read_bytes()
            source = root / "source" / "response.txt"
            source.parent.mkdir()
            source.write_bytes(b"new raw evidence")
            collision = root / "evidence" / "redacted" / "EV-001-response.txt"
            collision.write_bytes(b"preserve redacted artifact")

            result = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "evidence_capture.py"), str(root),
                    "--evidence-id", "EV-001", "--asset", "AST-001",
                    "--observation", "test", "--file", str(source),
                ],
                text=True, capture_output=True, check=False, timeout=30,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(collision.read_bytes(), b"preserve redacted artifact")
            self.assertFalse((root / "evidence" / "raw" / "EV-001-response.txt").exists())
            self.assertEqual(ledger.read_bytes(), ledger_before)


class OrchestratorTests(unittest.TestCase):
    def run_orchestrator(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "vulnhunter_orchestrator.py"), *args],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def test_plan_only_executes_without_engagement(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "run"
            process = self.run_orchestrator("example.com", "--profile", "plan-only", "--out", str(out))
            self.assertEqual(process.returncode, 0, process.stderr)
            plan = json.loads((out / "EXECUTION_PLAN.json").read_text(encoding="utf-8"))
            manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            self.assertFalse(plan["target_traffic"])
            self.assertFalse(manifest["authorization"]["verified"])
            self.assertEqual(manifest["steps"][0]["tool"], "plan-only")

    def test_non_plan_requires_engagement(self) -> None:
        process = self.run_orchestrator("example.com", "--profile", "active-safe")
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("--engagement is required", process.stderr)

    def test_resume_uses_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "run"
            first = self.run_orchestrator("example.com", "--profile", "plan-only", "--out", str(out))
            second = self.run_orchestrator(
                "example.com", "--profile", "plan-only", "--out", str(out), "--resume"
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertTrue((out / "stages" / "00-plan.json").exists())

    def test_authorization_fingerprint_changes_with_scope_and_scope_file(self) -> None:
        engagement = {
            "authorization_status": "confirmed",
            "permission_mode": "ACTIVE_SAFE",
            "allowed_assets": ["example.com"],
            "excluded_assets": [],
            "allowed_methods": ["http_probe"],
            "prohibited_methods": [],
            "testing_window": "2026-01-01T00:00:00Z..2026-12-31T23:59:59Z",
            "rate_limits": "10 req/s",
            "stop_conditions": ["instability"],
        }
        state = {"phases": {"P0": {"status": "completed"}}}
        with tempfile.TemporaryDirectory() as temp:
            scope = Path(temp) / "scope.txt"
            scope.write_text("example.com\n", encoding="utf-8")
            first = authorization_fingerprint(engagement, state, scope)
            engagement["allowed_assets"] = ["api.example.com"]
            second = authorization_fingerprint(engagement, state, scope)
            self.assertNotEqual(first, second)
            engagement["allowed_assets"] = ["example.com"]
            scope.write_text("api.example.com\n", encoding="utf-8")
            third = authorization_fingerprint(engagement, state, scope)
            self.assertNotEqual(first, third)

    def test_resume_retries_checkpoint_with_tool_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "stages").mkdir()
            (root / "stages" / "x.json").write_text(json.dumps([{
                "agent": "scan", "tool": "fake", "status": "error",
                "seconds": 1.0, "output": "", "note": "failed", "command": [],
            }]), encoding="utf-8")
            calls = []
            result = stage(
                {"out": root, "resume": True},
                "x",
                lambda ctx: (calls.append(True) or [Step("scan", "fake", "ok", 0.0)]),
            )
            self.assertEqual(len(calls), 1)
            self.assertEqual(result[0].status, "ok")

    def test_wrapper_forwards_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "run"
            process = subprocess.run(
                [
                    "bash", str(SCRIPTS / "vulnhunter-tools.sh"), "example.com",
                    "--profile", "plan-only", "--out", str(out),
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertTrue((out / "EXECUTION_PLAN.json").exists())

    def test_atomic_write_is_safe_across_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "shared.json"
            payloads = [json.dumps({"writer": index, "body": "x" * 32768}) + "\n" for index in range(8)]
            workers: list[subprocess.Popen[str]] = []
            for payload in payloads:
                code = (
                    "import sys; from pathlib import Path; "
                    f"sys.path.insert(0, {str(SCRIPTS)!r}); "
                    "from vulnhunter_orchestrator import atomic_write; "
                    f"p=Path({str(target)!r}); data={payload!r}; "
                    "[atomic_write(p, data) for _ in range(40)]"
                )
                workers.append(
                    subprocess.Popen(
                        [sys.executable, "-c", code],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                )
            failures = []
            for worker in workers:
                stdout, stderr = worker.communicate(timeout=30)
                if worker.returncode != 0:
                    failures.append(stdout + stderr)
            self.assertFalse(failures, "\n".join(failures))
            self.assertIn(target.read_text(encoding="utf-8"), payloads)
            self.assertFalse(list(target.parent.glob(".shared.json.*.tmp")))

    def test_live_lock_blocks_before_config_and_recovers_after_sigkill(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "run"
            out.mkdir()
            ready = Path(temp) / "ready"
            holder_code = (
                "import sys,time; from pathlib import Path; "
                f"sys.path.insert(0, {str(SCRIPTS)!r}); "
                "from vulnhunter_orchestrator import run_lock; "
                f"out=Path({str(out)!r}); ready=Path({str(ready)!r}); "
                "ctx=run_lock(out); ctx.__enter__(); "
                "ready.write_text('ready'); time.sleep(60)"
            )
            holder = subprocess.Popen(
                [sys.executable, "-c", holder_code],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                for _ in range(100):
                    if ready.exists():
                        break
                    if holder.poll() is not None:
                        stdout, stderr = holder.communicate()
                        self.fail(f"lock holder exited early: {stdout}{stderr}")
                    import time
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), "lock holder did not become ready")

                blocked = self.run_orchestrator(
                    "example.com", "--profile", "plan-only", "--out", str(out)
                )
                self.assertEqual(blocked.returncode, 2, blocked.stderr)
                self.assertIn("run directory is locked", blocked.stderr)
                self.assertNotIn("FileNotFoundError", blocked.stderr)
                self.assertFalse((out / "run-config.json").exists())

                holder.kill()
                holder.communicate(timeout=10)
                self.assertTrue((out / ".run.lock").exists())

                recovered = self.run_orchestrator(
                    "example.com", "--profile", "plan-only", "--out", str(out)
                )
                self.assertEqual(recovered.returncode, 0, recovered.stderr)
                self.assertTrue((out / "run-config.json").exists())
            finally:
                if holder.poll() is None:
                    holder.kill()
                holder.communicate(timeout=10)


class KillChainTests(unittest.TestCase):
    """Regression tests for the P5 kill-chain adapter + scoring engine.

    The vhs findings schema has no bug_class/endpoint columns, so the adapter
    must derive them or the BountyForge scoring engine matches nothing (silent
    dead feature). These lock in that behaviour.
    """

    FINDINGS_HEADER = [
        "finding_id", "title", "root_cause", "affected_assets", "status",
        "severity", "severity_rationale", "confidence", "prerequisite",
        "demonstrated_impact", "evidence_ids", "relationships",
        "remediation_owner", "disclosure_status", "retest_status",
    ]

    def _write_findings(self, root: Path, rows: list[dict]) -> None:
        (root / "engagement.json").write_text(
            json.dumps({"primary_target": "example.com"}), encoding="utf-8")
        p = root / "findings-index.csv"
        with p.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=self.FINDINGS_HEADER)
            w.writeheader()
            for r in rows:
                w.writerow({k: r.get(k, "") for k in self.FINDINGS_HEADER})

    def _run(self, root: Path, *extra):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "kill_chain_vhs.py"), str(root),
             "--output-format", "markdown", *extra],
            capture_output=True, text=True)

    def test_adapter_derives_bug_class_and_matches_chain(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_findings(root, [
                {"finding_id": "F-001", "title": "IDOR on /account",
                 "root_cause": "missing authz", "affected_assets": "api.example.com",
                 "status": "open", "severity": "medium", "confidence": "high",
                 "demonstrated_impact": "read other user via GET /account/123"},
            ])
            res = self._run(root, "--novel")
            self.assertEqual(res.returncode, 0, res.stderr)
            report = (root / "kill-chains.md").read_text()
            # bug_class derived -> CHAIN-001 (IDOR) matched (regression: was 0)
            self.assertIn("CHAIN-001", report)
            # target header populated from engagement.json (regression: was empty)
            self.assertIn("example.com", report)

    def test_single_finding_never_downgraded_below_its_severity(self):
        # A lone MEDIUM IDOR must not be reported as LOW (severity invariant).
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_findings(root, [
                {"finding_id": "F-001", "title": "IDOR on /orders",
                 "root_cause": "rc", "affected_assets": "example.com",
                 "status": "open", "severity": "medium", "confidence": "high",
                 "demonstrated_impact": "GET /orders/1 leaks other order"},
            ])
            res = self._run(root)
            self.assertEqual(res.returncode, 0, res.stderr)
            report = (root / "kill-chains.md").read_text()
            self.assertIn("Combined Severity: MEDIUM", report)
            self.assertNotIn("Combined Severity: LOW", report)

    def test_non_open_findings_are_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_findings(root, [
                {"finding_id": "F-001", "title": "IDOR on /account",
                 "root_cause": "rc", "affected_assets": "example.com",
                 "status": "rejected", "severity": "high", "confidence": "high",
                 "demonstrated_impact": "GET /account/1"},
            ])
            res = self._run(root)
            # only finding was rejected -> nothing to chain -> exit 1
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
