from __future__ import annotations

import csv
import hashlib
import json
import os
import re
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


class ReferenceIntegrityTests(unittest.TestCase):
    def test_web2_2026_reference_is_routed_and_cited(self) -> None:
        doc = (SKILL / "references" / "web2-2026-references.md").read_text(encoding="utf-8")
        router = (SKILL / "references" / "context-router.md").read_text(encoding="utf-8")
        index = (SKILL / "references" / "index.md").read_text(encoding="utf-8")
        skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("version: 2.6.0", skill)
        self.assertIn("web2-2026-references.md", router)
        self.assertIn("web2-2026-references.md", index)
        for term in (
            "ATO", "IDOR", "business logic", "SQL injection", "NoSQL injection",
            "SSTI", "CSRF", "deserialization", "TOCTOU", "privilege escalation",
            "fail-open", "canonicalization", "configuration",
        ):
            self.assertIn(term, doc)
        for cve in (
            "CVE-2026-33385", "CVE-2026-3021", "CVE-2026-22265",
            "CVE-2026-15734", "CVE-2026-26718", "CVE-2026-43633",
            "CVE-2026-25728", "CVE-2026-19598", "CVE-2026-72856",
            "CVE-2026-49819", "CVE-2026-73421", "CVE-2026-37525",
            "CVE-2026-28498", "CVE-2026-53976", "CVE-2026-2311",
        ):
            self.assertIn(cve, doc)
        citations = {int(value) for value in re.findall(r"\[(\d+)\]", doc)}
        self.assertGreaterEqual(len(citations), 40)
        self.assertIn("## Sources", doc)

    def test_web2_reference_has_no_patch_artifact(self) -> None:
        for name in ("references/web2-2026-references.md", "references/index.md"):
            text = (SKILL / name).read_text(encoding="utf-8")
            self.assertNotRegex(text, r"^\+", msg=name)


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

    def test_graphql_cop_launcher_honors_home_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "graphql-cop"
            python_bin = home / "venv" / "bin" / "python"
            python_bin.parent.mkdir(parents=True)
            log = Path(temp) / "args.log"
            python_bin.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' \"$@\" > {str(log)!r}\n",
                encoding="utf-8",
            )
            python_bin.chmod(0o700)
            (home / "graphql-cop.py").write_text("# fake\n", encoding="utf-8")
            process = subprocess.run(
                [
                    "bash", str(SCRIPTS / "graphql_cop.sh"),
                    "-t", "https://example.com/graphql", "-o", "json",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "VHS_GRAPHQL_COP_HOME": str(home)},
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            args = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(args[0], str(home / "graphql-cop.py"))
            self.assertIn("https://example.com/graphql", args)
            self.assertIn("json", args)

    def test_check_tools_reports_graphql_cop_from_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "graphql-cop"
            python_bin = home / "venv" / "bin" / "python"
            python_bin.parent.mkdir(parents=True)
            python_bin.write_text(
                "#!/usr/bin/env bash\n"
                "if [ \"$2\" = \"--version\" ]; then printf 'version: 1.15\\n'; fi\n",
                encoding="utf-8",
            )
            python_bin.chmod(0o700)
            (home / "graphql-cop.py").write_text("# fake\n", encoding="utf-8")
            process = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "check_tools.py"),
                    "--profile", "active-safe", "--verify", "--json",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "VHS_GRAPHQL_COP_HOME": str(home)},
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            self.assertTrue(result["agents"]["graphql"]["optional"]["graphql-cop"])
            self.assertTrue(result["verification"]["graphql-cop"]["ok"])

    def test_check_tools_reports_missing_graphql_cop_as_not_present(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            process = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "check_tools.py"),
                    "--profile", "active-safe", "--verify", "--json",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "VHS_GRAPHQL_COP_HOME": str(Path(temp) / "missing")},
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            self.assertFalse(result["verification"]["graphql-cop"]["present"])
            self.assertFalse(result["verification"]["graphql-cop"]["ok"])

    def test_detect_cache_calls_special_probe_once(self) -> None:
        import check_tools

        calls = []
        original = check_tools.SPECIAL_DETECT.get("cache-test")
        check_tools.SPECIAL_DETECT["cache-test"] = lambda: (calls.append(True) or (True, "ok"))
        check_tools.detect.cache_clear()
        try:
            self.assertEqual(check_tools.detect("cache-test"), (True, "ok"))
            self.assertEqual(check_tools.detect("cache-test"), (True, "ok"))
            self.assertEqual(len(calls), 1)
        finally:
            if original is None:
                check_tools.SPECIAL_DETECT.pop("cache-test", None)
            else:
                check_tools.SPECIAL_DETECT["cache-test"] = original
            check_tools.detect.cache_clear()

    def test_code_graph_launcher_honors_binary_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "args.log"
            binary = Path(temp) / "cgr"
            binary.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' \"$@\" > {str(log)!r}\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            process = subprocess.run(
                [
                    "bash", str(SCRIPTS / "code_graph_rag.sh"),
                    "start", "--repo-path", "/tmp/repo", "--update-graph",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "VHS_CODE_GRAPH_RAG_BIN": str(binary)},
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            args = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(args, ["start", "--repo-path", "/tmp/repo", "--update-graph"])

    def test_check_tools_reports_code_graph_from_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "cgr"
            binary.write_text(
                "#!/usr/bin/env bash\n"
                "if [ \"$1\" = \"--version\" ]; then printf 'cgr 0.0.658\\n'; else printf 'help\\n'; fi\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            process = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "check_tools.py"),
                    "--profile", "active-safe", "--verify", "--json",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "VHS_CODE_GRAPH_RAG_BIN": str(binary)},
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            self.assertTrue(result["agents"]["sast"]["optional"]["code-graph-rag"])
            self.assertTrue(result["verification"]["code-graph-rag"]["ok"])

    def test_code_graph_grounding_rejects_unknown_nodes_and_edges(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            graph = root / "graph.json"
            claims = root / "claims.json"
            graph.write_text(json.dumps({
                "metadata": {"project": "fixture"},
                "nodes": [
                    {"node_id": 1, "labels": ["Function"], "properties": {
                        "qualified_name": "app.auth.login", "path": "app.py",
                        "start_line": 1, "end_line": 4,
                    }},
                    {"node_id": 2, "labels": ["Resource"], "properties": {
                        "qualified_name": "resource::DATABASE::users", "kind": "DATABASE",
                    }},
                ],
                "relationships": [{"from_id": 1, "to_id": 2, "type": "READS_FROM", "properties": {}}],
            }), encoding="utf-8")
            claims.write_text(json.dumps({
                "answer": "login reads users",
                "citations": [
                    {"node_id": 1, "qualified_name": "app.auth.login"},
                    {"from_node_id": 1, "to_node_id": 2, "type": "READS_FROM"},
                    {"node_id": 999, "qualified_name": "hallucinated.node"},
                ],
            }), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "code_graph_grounding.py"), "verify",
                 "--graph", str(graph), "--claims", str(claims)],
                text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertFalse(payload["grounded"])
            self.assertIn("node_id 999", " ".join(payload["errors"]))

    def test_code_graph_grounding_accepts_valid_citations_and_source_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "app.py"
            source.write_text("def login():\n    return True\n", encoding="utf-8")
            graph = root / "graph.json"
            claims = root / "claims.json"
            graph.write_text(json.dumps({
                "metadata": {"project": "fixture"},
                "nodes": [
                    {"node_id": 1, "labels": ["Function"], "properties": {
                        "qualified_name": "app.login", "path": "app.py",
                        "start_line": 1, "end_line": 2,
                    }},
                ],
                "relationships": [],
            }), encoding="utf-8")
            claims.write_text(json.dumps({
                "answer": "login is defined in app.py",
                "citations": [{
                    "node_id": 1, "qualified_name": "app.login", "path": "app.py",
                    "start_line": 1, "end_line": 2,
                }],
            }), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "code_graph_grounding.py"), "verify",
                 "--graph", str(graph), "--claims", str(claims), "--repo", str(root)],
                text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["grounded"])
            self.assertEqual(payload["status"], "SUPPORTED")
            self.assertRegex(payload["validated_citations"][0]["source_sha256"], r"^[0-9a-f]{64}$")


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

    def test_new_engagement_files_are_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "engagement"
            create = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "new_engagement.py"), str(root),
                    "--title", "Private test", "--target", "example.com",
                ],
                text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(create.returncode, 0, create.stderr)
            files = [path for path in root.rglob("*") if path.is_file()]
            self.assertTrue(files)
            for path in files:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600, path)

    def test_p3_rejects_unknown_playbook_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "engagement"
            create = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "new_engagement.py"), str(root),
                    "--title", "P3 test", "--target", "example.com",
                ],
                text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(create.returncode, 0, create.stderr)
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            state["playbooks_loaded"] = True
            (root / "state.json").write_text(json.dumps(state), encoding="utf-8")
            rows = {
                "asset-inventory.csv": {"asset_id": "AST-001", "asset": "example.com", "type": "web", "environment": "prod", "owner": "owner", "scope_status": "in_scope", "source": "manual", "notes": ""},
                "surface-inventory.csv": {"surface_id": "SUR-001", "asset_id": "AST-001", "surface": "web", "protocol": "https", "auth_requirement": "none", "state_change_risk": "low", "third_party": "no", "scope_status": "in_scope", "source": "manual", "confidence": "high", "coverage_status": "planned", "notes": ""},
                "hypothesis-ledger.csv": {"hypothesis_id": "HYP-001", "asset_id": "AST-001", "surface_id": "SUR-001", "actor": "external", "invariant": "authz holds", "mutation": "probe", "safe_validation": "manual", "priority": "P2", "status": "pending", "notes": ""},
                "test-matrix.csv": {"test_id": "TST-001", "hypothesis_id": "HYP-001", "asset_id": "AST-001", "surface_id": "SUR-001", "baseline": "baseline", "mutation": "mutation", "expected_result": "deny", "negative_control": "control", "evidence_plan": "none", "cleanup": "none", "risk": "low", "permission_mode": "ACTIVE_SAFE", "status": "planned", "evidence_ids": "", "notes": "playbook: does-not-exist"},
            }
            for filename, row in rows.items():
                with (root / filename).open("w", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=LEDGER_SCHEMAS[filename])
                    writer.writeheader()
                    writer.writerow(row)
            gate = subprocess.run(
                [sys.executable, str(SCRIPTS / "gate_check.py"), str(root), "--phase", "P3", "--json"],
                text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertNotEqual(gate.returncode, 0)
            self.assertIn("does-not-exist", gate.stdout)

    def test_make_deliverables_help_and_apostrophe_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "engagement's"
            root.mkdir()
            (root / "engagement.json").write_text(
                json.dumps({"title": "Title survives apostrophe path"}), encoding="utf-8"
            )
            fakebin = Path(temp) / "bin"
            fakebin.mkdir()
            log = Path(temp) / "officecli.log"
            officecli = fakebin / "officecli"
            officecli.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' \"$*\" >> {str(log)!r}\n"
                "exit 0\n",
                encoding="utf-8",
            )
            officecli.chmod(0o700)
            env = {**os.environ, "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", "")}
            help_run = subprocess.run(
                ["bash", str(SCRIPTS / "make_deliverables.sh"), "--help"],
                text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(help_run.returncode, 0, help_run.stderr)
            run = subprocess.run(
                ["bash", str(SCRIPTS / "make_deliverables.sh"), str(root)],
                text=True, capture_output=True, timeout=30, check=False, env=env,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("Title survives apostrophe path", log.read_text(encoding="utf-8"))

    def test_evidence_capture_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "engagement"
            root.mkdir()
            (root / "evidence-ledger.csv").write_text(
                "evidence_id,captured_at_utc,hypothesis_id,test_id,finding_id,asset_id,path,sha256,sensitivity,redaction_status,observation,cleanup_status\n",
                encoding="utf-8",
            )
            outside = root / "escape.txt"
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "evidence_capture.py"), str(root),
                    "--evidence-id", "EV-001", "--asset", "AST-001",
                    "--observation", "test", "--stdin", "../../escape.txt",
                ],
                input="secret\n", text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(outside.exists())


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
