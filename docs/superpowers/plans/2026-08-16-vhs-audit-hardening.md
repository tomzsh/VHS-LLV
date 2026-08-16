# VHS Audit Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the confirmed VHS integrity, scope, resume, reporting, and discovery bugs while adding deterministic section-level reference loading that reduces context without removing full playbook coverage.

**Architecture:** Keep the existing standard-library Python/Bash workflow and CSV ledgers. Add narrow helpers at existing boundaries: authorization digests at run startup, replay validation at stage checkpoints, locked atomic writes at evidence capture, scope filtering at API/discovery inputs, and a read-only Markdown section slicer for context routing. Preserve full references and make section slicing reversible with `--full`.

**Tech Stack:** Python 3.10+ standard library, Bash, `fcntl`, `hashlib`, `json`, `csv`, `urllib`, `unittest`, existing `ScopePolicy`, existing orchestrator `Step`/stage model.

## Global Constraints

- Do not rewrite or translate the imported attack playbooks.
- Do not change authorization policy to permit broader target traffic.
- Do not automatically enable OAST, destructive tests, race amplification, or state-changing API methods.
- Do not migrate engagement ledgers to a new database or format.
- Do not reset, rebase, or overwrite unrelated existing working-tree changes.
- Do not remove the full playbook or reference files; context slicing is an additional access path, not a content reduction.
- All active inputs must continue to pass the existing `ScopePolicy` before reaching a tool.
- All scanner matches remain hypotheses and must not be promoted to confirmed findings.
- Every task ends with its focused test command and a scoped commit; never stage unrelated existing changes.

## File Map

| File | Responsibility in this plan |
|---|---|
| `scripts/vulnhunter_orchestrator.py` | Authorization-aware resume fingerprint, failed-stage replay, discovery URL aggregation, Dalfox input merge |
| `scripts/evidence_capture.py` | Unique evidence artifacts, engagement-local locking, atomic ledger append, shared schema |
| `scripts/check_tools.py` | Cached tool detection and accurate `present`/`ok` verification fields |
| `scripts/make_deliverables.sh` | Fail-closed Office import behavior and private output umask |
| `scripts/api_auth_probe.py` | Engagement scope validation, safe endpoint joining, explicit state-change authorization, controlled network errors |
| `scripts/context_slice.py` | New no-network Markdown outline and section extraction CLI |
| `tests/test_core.py` | Regression tests for runtime behavior, scope, cache, and context loading |
| `tests/test_fake_tools.py` | End-to-end fake-tool assertion that discovery URLs reach the Dalfox candidate file only after scope filtering |
| `SKILL.md` | Versioned concise loading contract and context-slice commands |
| `references/context-router.md` | Single source for progressive reference loading |
| `references/index.md` | Remove contradictory full-file loading instruction and point to the slicer |
| `README.md` | Document the context helper and current offline verification command |
| `CHANGELOG.md` | Record the hardening and token-efficiency release |

---

### Task 1: Harden authorization-aware resume and failed-stage replay

**Files:**
- Modify: `scripts/vulnhunter_orchestrator.py:594-654, 749-779`
- Test: `tests/test_core.py` in `OrchestratorTests`

**Interfaces:**
- Produces `authorization_fingerprint(engagement: dict, state: dict, scope_file: Path | None) -> str`.
- Produces `checkpoint_rows_reusable(rows: object) -> list[Step] | None`.
- `config_fingerprint(ctx: dict)` includes the authorization digest but never serializes raw engagement content.

- [ ] **Step 1: Add failing tests for authorization changes and failed checkpoint retry**

Add these imports to the existing orchestrator test section:

```python
from vulnhunter_orchestrator import Step, authorization_fingerprint, stage  # noqa: E402
```

Add the following tests:

```python
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
```

- [ ] **Step 2: Run the focused tests and verify they fail for the current implementation**

Run:

```bash
python3 -m unittest tests.test_core.OrchestratorTests -v
```

Expected: the new fingerprint test reports equal digests after scope changes and the retry test reports zero function calls.

- [ ] **Step 3: Implement canonical authorization hashing**

Add a helper that hashes only stable authorization material:

```python
def authorization_fingerprint(
    engagement: dict, state: dict, scope_file: Path | None
) -> str:
    projection = {
        "engagement": {
            key: engagement.get(key)
            for key in (
                "authorization_status", "permission_mode", "allowed_assets",
                "excluded_assets", "allowed_methods", "prohibited_methods",
                "testing_window", "rate_limits", "stop_conditions",
            )
        },
        "p0_status": ((state.get("phases") or {}).get("P0") or {}).get("status"),
        "scope_file_sha256": (
            hashlib.sha256(scope_file.read_bytes()).hexdigest()
            if scope_file and scope_file.is_file() else None
        ),
    }
    encoded = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
```

After building `ctx` in `main()`, assign:

```python
ctx["authorization_fingerprint"] = authorization_fingerprint(
    engagement or {}, state or {}, args.scope
)
```

`config_fingerprint()` must retain its current exclusion of `engagement`, `state`, and `policy`, while including the new digest through the normal context projection.

- [ ] **Step 4: Implement checkpoint reuse validation**

Add:

```python
def checkpoint_rows_reusable(rows: object) -> list[Step] | None:
    if not isinstance(rows, list):
        return None
    try:
        parsed = [Step(**row) for row in rows]
    except (TypeError, ValueError):
        return None
    if any(item.status in {"error", "timeout"} for item in parsed):
        return None
    return parsed
```

Update `stage()` to call this helper and execute the stage function when it returns `None`. Keep `skipped` checkpoints reusable so unavailable optional tools are not repeatedly probed during a normal resume.

- [ ] **Step 5: Run the focused tests and the existing resume tests**

Run:

```bash
python3 -m unittest tests.test_core.OrchestratorTests -v
```

Expected: all orchestrator tests pass, including the new authorization and retry regressions.

- [ ] **Step 6: Commit only the orchestrator and test changes**

```bash
git add scripts/vulnhunter_orchestrator.py tests/test_core.py
git commit -m "fix: invalidate unsafe orchestrator resumes"
```

### Task 2: Preserve evidence integrity under collisions and concurrent capture

**Files:**
- Modify: `scripts/evidence_capture.py:34-182`
- Test: `tests/test_core.py` in a new `EvidenceCaptureTests` class

**Interfaces:**
- Consumes `LEDGER_SCHEMAS["evidence-ledger.csv"]` from `scripts/schemas.py`.
- Produces `safe_artifact_name(evidence_id: str, source_name: str) -> str`.
- Produces `ledger_lock(root: Path)`, an exclusive context manager for `.evidence-ledger.lock`.
- `append_ledger(root: Path, row: list[str])` either appends atomically or raises without replacing the active ledger.

- [ ] **Step 1: Add a failing collision and header-mismatch regression test**

Add a helper fixture that creates the canonical evidence ledger header from `LEDGER_SCHEMAS`. Add:

```python
def test_capture_names_are_unique_and_hashes_remain_valid(self) -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "evidence" / "raw").mkdir(parents=True)
        (root / "evidence" / "redacted").mkdir()
        with (root / "evidence-ledger.csv").open("w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow(LEDGER_SCHEMAS["evidence-ledger.csv"])
        first = root / "first"; second = root / "second"
        first.mkdir(); second.mkdir()
        (first / "response.json").write_text("first", encoding="utf-8")
        (second / "response.json").write_text("second", encoding="utf-8")
        for evidence_id, source in (("EV-001", first / "response.json"), ("EV-002", second / "response.json")):
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "evidence_capture.py"), str(root),
                 "--evidence-id", evidence_id, "--asset", "AST-001",
                 "--observation", evidence_id, "--file", str(source)],
                text=True, capture_output=True, check=False, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        rows = list(csv.DictReader((root / "evidence-ledger.csv").open(encoding="utf-8", newline="")))
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
            [sys.executable, str(SCRIPTS / "evidence_capture.py"), str(root),
             "--evidence-id", "EV-001", "--asset", "AST-001",
             "--observation", "test", "--file", str(source)],
            text=True, capture_output=True, check=False, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(ledger.read_text(encoding="utf-8"), "wrong,header\nkeep,this\n")
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
python3 -m unittest tests.test_core.EvidenceCaptureTests -v
```

Expected: the collision test observes one shared path/hash mismatch and the header test observes the current backup-and-replace behavior.

- [ ] **Step 3: Implement shared schema, ID validation, and unique artifact names**

Import `LEDGER_SCHEMAS` and use its evidence header in `append_ledger()`. Add:

```python
EVIDENCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

def safe_artifact_name(evidence_id: str, source_name: str) -> str:
    if not EVIDENCE_ID_RE.fullmatch(evidence_id):
        raise ValueError("--evidence-id must be a single safe identifier")
    name = Path(source_name).name
    if not name or name in {".", ".."}:
        raise ValueError("evidence source must have a filename")
    return f"{evidence_id}-{name}"
```

Call `safe_artifact_name()` before writing either raw or redacted output. Set `evidence`, `evidence/raw`, and `evidence/redacted` to `0700` where supported.

- [ ] **Step 4: Implement lock-protected atomic ledger append**

Add an `@contextmanager` using `fcntl.flock()` on `root / ".evidence-ledger.lock"`. Move duplicate-ID validation inside that lock. Make `append_ledger()` reject any header other than `LEDGER_SCHEMAS["evidence-ledger.csv"]`, write the complete row set to a temporary file in the engagement root, flush/fsync it, chmod it `0600`, and replace the ledger with `os.replace()`.

Wrap artifact creation and append in a `try/except` that unlinks only the newly created raw/redacted artifacts when append fails. Do not delete or rewrite pre-existing evidence.

- [ ] **Step 5: Run focused evidence tests and the existing path-traversal tests**

Run:

```bash
python3 -m unittest tests.test_core.EvidenceCaptureTests tests.test_core.EngagementCliTests.test_evidence_capture_rejects_path_traversal -v
```

Expected: all tests pass and every ledger path resolves to a distinct artifact with a matching SHA-256.

- [ ] **Step 6: Commit only evidence code and tests**

```bash
git add scripts/evidence_capture.py tests/test_core.py
git commit -m "fix: preserve evidence artifact integrity"
```

### Task 3: Feed scoped discovery output into XSS scanning

**Files:**
- Modify: `scripts/vulnhunter_orchestrator.py:418-444, 504-522`
- Modify: `tests/test_fake_tools.py:57-72, 125-141`
- Test: `tests/test_core.py` in a focused discovery helper test if needed

**Interfaces:**
- Produces `extract_json_urls(value: object) -> set[str]`.
- Produces `collect_discovery_urls(directory: Path, policy: ScopePolicy, output: Path) -> int`.
- `dalfox_scan(ctx)` consumes `agents/discovery/urls_normalized.txt` and `agents/discovery/urls_discovered.txt`, then writes the existing `agents/scan/xss_candidates.txt`.

- [ ] **Step 1: Add failing fake-tool assertions**

Change the fake `arjun` tool to emit both an in-scope and out-of-scope URL:

```python
open(path, "w", encoding="utf-8").write(json.dumps({
    "results": [
        {"url": "https://api.example.com/discovered?x=1"},
        {"url": "https://evil.test/discovered?x=1"},
    ]
}))
```

Change the fake `dalfox` tool to copy the candidate file into `dalfox-input.txt` instead of writing only `fake-poc`. Add assertions:

```python
discovered = (out / "agents" / "discovery" / "urls_discovered.txt").read_text(encoding="utf-8")
self.assertIn("https://api.example.com/discovered?x=1", discovered)
self.assertNotIn("evil.test", discovered)
xss_input = (out / "agents" / "scan" / "dalfox-input.txt").read_text(encoding="utf-8")
self.assertIn("https://api.example.com/discovered?x=1", xss_input)
self.assertNotIn("evil.test", xss_input)
```

- [ ] **Step 2: Run the fake integration test and verify it fails**

Run:

```bash
python3 -m unittest tests.test_fake_tools.FakeToolIntegrationTests.test_scanner_dag_and_scope_filters -v
```

Expected: `urls_discovered.txt` is absent and the Dalfox input does not contain the discovered in-scope URL.

- [ ] **Step 3: Implement recursive URL extraction and final scope filtering**

Implement `extract_json_urls()` recursively for dictionaries, lists, and strings. A string is accepted only when `urlsplit()` yields `http` or `https` and a hostname. In `collect_discovery_urls()`, read `arjun.json` and every `ffuf_*.json`, call the extractor, apply `policy.url_allowed()`, normalize with the existing `filter_urls()` behavior, and atomically write sorted unique URLs to the output.

Call `collect_discovery_urls()` as the final action of `active_discovery()`, after all tool commands finish. Add a `Step("discovery", "scope-guard-discovered-urls", "ok", 0, ...)` with the count.

- [ ] **Step 4: Merge discovery URLs into Dalfox candidates**

Read both normalized and discovered files, keep lines containing `=`, deduplicate them, reapply `ctx["policy"].url_allowed()`, and atomically write `xss_candidates.txt`. Keep the existing `80-dalfox` stage after `60-active-discovery`; no scanner starts before the discovery artifact is complete.

- [ ] **Step 5: Run the fake integration and full orchestrator tests**

Run:

```bash
python3 -m unittest tests.test_fake_tools.FakeToolIntegrationTests tests.test_core.OrchestratorTests -v
```

Expected: fake discovery reaches Dalfox only through a scope-filtered artifact and all orchestrator DAG tests pass.

- [ ] **Step 6: Commit only discovery code and fake-tool tests**

```bash
git add scripts/vulnhunter_orchestrator.py tests/test_fake_tools.py tests/test_core.py
git commit -m "fix: connect scoped discovery to xss scan"
```

### Task 4: Make API probing scope-safe and deliverable imports fail closed

**Files:**
- Modify: `scripts/api_auth_probe.py:29-146`
- Modify: `scripts/make_deliverables.sh:16-104`
- Modify: `references/operator-commands.md:41-52`
- Test: `tests/test_core.py` in new `ApiProbeTests` and `DeliverableTests`

**Interfaces:**
- Produces `resolve_endpoint(base_url: str, endpoint: str, policy: ScopePolicy) -> str`.
- Produces `state_change_allowed(engagement: dict, method: str, explicit_flag: bool) -> bool`.
- Email/password login requires an engagement `allowed_methods` entry of `login` or `authentication`; direct `API_AUTH_TOKEN` use skips the login POST.
- `req()` returns `(status: int | None, body: object)` for HTTP, URL, and timeout failures without raising network errors to `main()`.

- [ ] **Step 1: Add failing pure-helper tests**

Add:

```python
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

def test_state_change_requires_flag_and_method_permission(self) -> None:
    engagement = {"allowed_methods": ["post"]}
    self.assertFalse(state_change_allowed(engagement, "POST", False))
    self.assertTrue(state_change_allowed(engagement, "POST", True))
    self.assertFalse(state_change_allowed(engagement, "DELETE", True))
```

Add a subprocess test with a fake `officecli` whose `import` command exits 1; assert `make_deliverables.sh` returns non-zero and prints `import failed`.

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
python3 -m unittest tests.test_core.ApiProbeTests tests.test_core.DeliverableTests -v
```

Expected: the imports fail until the new helper functions and strict shell status are implemented.

- [ ] **Step 3: Implement endpoint resolution and engagement authorization**

Add `--engagement` as a required option. In `main()`, call `authorize_run(Path(args.engagement).expanduser().resolve(), parsed_base.hostname, "active-safe")` before login. Resolve `--login-path` and every endpoint using `urllib.parse.urljoin`; reject absolute or network-path endpoints whose host is not permitted. Pass the authorized `ScopePolicy` to `resolve_endpoint()` for every request, including mutation URLs.

Keep credentials environment-only. Do not add token or password values to command output.

- [ ] **Step 4: Implement explicit state-change controls and controlled network errors**

Keep `GET` and `HEAD` allowed by default for target endpoint requests. If credentials are used instead of `API_AUTH_TOKEN`, allow the login POST only when `allowed_methods` contains `login` or `authentication`. Add `--allow-state-change`; for any other target endpoint method require that flag and an `allowed_methods` value equal to the lowercase HTTP method or one of `state_change`/`api_state_change`. Reject the invocation before login when authorization is absent.

Catch `urllib.error.URLError` and `TimeoutError` in `req()` and return `(None, {"error": "unreachable"})`. Keep HTTP errors as their status/body observation. Validate `--rate >= 0` and `--timeout >= 1` in `parse_args()`.

- [ ] **Step 5: Make Office imports strict and private**

Add `umask 077` after `set -euo pipefail`. In `import_csv()`, fail if `officecli create` fails, try the file import then stdin fallback, return 1 if both fail, and fail if `officecli close` fails. Preserve the existing skip behavior for missing/empty source ledgers.

- [ ] **Step 6: Update the operator command reference and run focused tests**

Document:

```bash
python3 <skill-dir>/scripts/api_auth_probe.py https://api-uat.target.com \
  --engagement ./engagement --endpoints /account/info --token-path access_token
```

Run:

```bash
python3 -m unittest tests.test_core.ApiProbeTests tests.test_core.DeliverableTests -v
bash -n scripts/make_deliverables.sh
```

Expected: out-of-scope endpoints and unauthorized methods fail before traffic, network failures are represented as observations, and Office import failure returns non-zero.

- [ ] **Step 7: Commit only API, deliverable, reference, and tests**

```bash
git add scripts/api_auth_probe.py scripts/make_deliverables.sh references/operator-commands.md tests/test_core.py
git commit -m "fix: fail closed on api and deliverable helpers"
```

### Task 5: Cache tool probes and correct special-tool presence reporting

**Files:**
- Modify: `scripts/check_tools.py:5-13, 286-339`
- Test: `tests/test_core.py` in `ToolCheckTests`

**Interfaces:**
- `detect(name: str) -> tuple[bool, str]` remains the readiness API used by agent summaries.
- Produces `detect_present(name: str) -> bool` for the verification JSON `present` field.

- [ ] **Step 1: Add failing tests for missing special tools and cache behavior**

Add a test that sets `VHS_GRAPHQL_COP_HOME` to a missing temporary path, runs `check_tools.py --profile active-safe --verify --json`, and asserts:

```python
self.assertFalse(result["verification"]["graphql-cop"]["present"])
self.assertFalse(result["verification"]["graphql-cop"]["ok"])
```

Add a direct cache test:

```python
def test_detect_cache_calls_special_probe_once(self) -> None:
    import check_tools
    calls = []
    check_tools.SPECIAL_DETECT["cache-test"] = lambda: (calls.append(True) or (True, "ok"))
    check_tools.detect.cache_clear()
    self.assertEqual(check_tools.detect("cache-test"), (True, "ok"))
    self.assertEqual(check_tools.detect("cache-test"), (True, "ok"))
    self.assertEqual(len(calls), 1)
```

Restore the temporary mapping and clear the cache in a `finally` block.

- [ ] **Step 2: Run focused tests and verify the presence test fails**

Run:

```bash
python3 -m unittest tests.test_core.ToolCheckTests -v
```

Expected: the current implementation reports missing GraphQL Cop as `present=true` and has no cache API.

- [ ] **Step 3: Add cached detection and a separate presence helper**

Import `functools` and decorate `detect()` with `@functools.lru_cache(maxsize=None)`. Implement `detect_present()` so regular tools use `shutil.which()` and special tools check their configured launcher/interpreter/binary/script paths without executing them. For `graphql-cop`, presence requires the launcher, `venv/bin/python`, and `graphql-cop.py`; readiness still comes from `graphql_cop_ok()`.

Use `detect_present()` in `results["verification"][name]["present"]` and keep `detect()` for `ok` and agent optional readiness. Ensure tests can call `detect.cache_clear()`.

- [ ] **Step 4: Run tool-check tests and inspect JSON output**

Run:

```bash
python3 -m unittest tests.test_core.ToolCheckTests -v
python3 scripts/check_tools.py --profile plan-only --verify --json
```

Expected: special-tool presence is truthful, repeated probes are cached, and the plan-only JSON remains valid.

- [ ] **Step 5: Commit only tool-check code and tests**

```bash
git add scripts/check_tools.py tests/test_core.py
git commit -m "perf: cache optional tool readiness probes"
```

### Task 6: Add deterministic context slicing and update lazy-loading documentation

**Files:**
- Create: `scripts/context_slice.py`
- Modify: `SKILL.md:1-384`
- Modify: `references/context-router.md:1-60`
- Modify: `references/index.md:1-65`
- Modify: `README.md:35-110, 285-300`
- Modify: `CHANGELOG.md:1-18`
- Test: `tests/test_core.py` in `ReferenceIntegrityTests` and new `ContextSliceTests`

**Interfaces:**
- Produces `parse_headings(text: str) -> list[tuple[int, str, int, int]]` where each tuple is `(level, title, start_line, end_line)`.
- Produces `slice_sections(text: str, terms: list[str]) -> str`.
- CLI supports `--file PATH`, `--outline`, repeated `--section TERM`, and `--full`.

- [ ] **Step 1: Add failing context-slice tests**

Add:

```python
def test_context_slice_keeps_selected_section_and_nested_children(self) -> None:
    from context_slice import slice_sections
    source = "# Root\nintro\n## Entry\nentry\n### Detail\ndetail\n## Evidence\nevidence\n"
    sliced = slice_sections(source, ["entry"])
    self.assertIn("entry", sliced)
    self.assertIn("detail", sliced)
    self.assertNotIn("evidence", sliced)

def test_context_slice_falls_back_to_full_text_without_match(self) -> None:
    from context_slice import slice_sections
    source = "# Root\n## Probe\nprobe\n"
    self.assertEqual(slice_sections(source, ["missing"]), source)

def test_context_slice_ignores_heading_like_comments_inside_fences(self) -> None:
    from context_slice import slice_sections
    source = "## Probe\n```bash\n# not a heading\n```\nbody\n## Evidence\nevidence\n"
    sliced = slice_sections(source, ["probe"])
    self.assertIn("body", sliced)
    self.assertNotIn("evidence", sliced)

def test_context_slice_cli_outline_and_full(self) -> None:
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "ref.md"
        path.write_text("# Root\n## Probe\nbody\n", encoding="utf-8")
        outline = subprocess.run(
            [sys.executable, str(SCRIPTS / "context_slice.py"), "--file", str(path), "--outline"],
            text=True, capture_output=True, check=False,
        )
        full = subprocess.run(
            [sys.executable, str(SCRIPTS / "context_slice.py"), "--file", str(path), "--full"],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(outline.returncode, 0)
        self.assertIn("Probe", outline.stdout)
        self.assertEqual(full.stdout, path.read_text(encoding="utf-8"))
```

- [ ] **Step 2: Run context tests and verify they fail**

Run:

```bash
python3 -m unittest tests.test_core.ContextSliceTests -v
```

Expected: import fails because `scripts/context_slice.py` does not yet exist.

- [ ] **Step 3: Implement the read-only Markdown parser and CLI**

Parse only ATX headings matching `^(#{1,6})[ \t]+(.+?)\s*$` outside fenced code blocks delimited by triple backticks or tildes. A section starts at its heading and ends immediately before the next heading with level less than or equal to the selected heading level. Include nested child headings. Match section terms case-insensitively against heading titles. If no term matches, return the original text exactly. `--outline` prints `level`, `title`, and line number without body text. `--full` prints the original file exactly and takes precedence over section filters.

Do not import third-party packages, perform network access, or write files.

- [ ] **Step 4: Update the routing contract to use one progressive-loading policy**

Update `context-router.md` and `SKILL.md` to prescribe:

```bash
python3 <skill-dir>/scripts/context_slice.py \
  --file <skill-dir>/references/attack-playbooks/<type>.md --outline
python3 <skill-dir>/scripts/context_slice.py \
  --file <skill-dir>/references/attack-playbooks/<type>.md \
  --section "高频入口" --section "探测手法" --section Bypass \
  --section "复现" --section "证据" --section "不要做" \
  --section Entry --section Probe --section Evidence --section Compliance
```

Use `--full` for P4 exact validation or when the selected slice has no matching heading. Remove duplicate statements that require both router and index to load the same routing policy, and replace the `references/index.md` instruction to read every selected file completely with the progressive-loading rule. Keep the attack index, full playbooks, evidence rules, and compliance red lines intact.

Update `SKILL.md` version to `2.7.0`, update the existing reference-integrity test assertion, document the helper in `README.md`, and add a `2.7.0` changelog entry describing hardening and section-level loading.

- [ ] **Step 5: Run reference and context tests**

Run:

```bash
python3 -m unittest tests.test_core.ReferenceIntegrityTests tests.test_core.ContextSliceTests -v
python3 scripts/context_slice.py --file references/attack-playbooks/rce.md --outline | head -20
```

Expected: all selected sections are bounded correctly, full mode preserves exact content, and routing documentation contains no contradictory full-file loading rule.

- [ ] **Step 6: Commit only context helper, docs, changelog, and tests**

```bash
git add scripts/context_slice.py SKILL.md references/context-router.md references/index.md README.md CHANGELOG.md tests/test_core.py
git commit -m "feat: add progressive reference context loading"
```

### Task 7: Run complete verification and hand off the branch

**Files:**
- Modify: none unless a verification-discovered regression requires a focused fix in the task that introduced it
- Test: `tests/test_core.py`, `tests/test_fake_tools.py`, all Python and shell scripts

**Interfaces:**
- No new runtime interface.
- Completion requires fresh evidence from every verification command below.

- [ ] **Step 1: Run the complete offline unit suite**

Run:

```bash
python3 -m unittest discover -s tests -v
```

Expected: every test passes with zero failures and zero errors.

- [ ] **Step 2: Compile all Python scripts**

Run:

```bash
python3 -m py_compile scripts/*.py
```

Expected: exit code 0.

- [ ] **Step 3: Check every shell script**

Run:

```bash
for f in scripts/*.sh; do bash -n "$f" || exit 1; done
```

Expected: exit code 0.

- [ ] **Step 4: Check the final diff and working-tree scope**

Run:

```bash
git diff --check
git status --short
git log --oneline -8
```

Expected: no whitespace errors; only the intended task commits are new, while unrelated pre-existing user changes remain preserved and un-staged.

- [ ] **Step 5: Commit any focused verification fix and report evidence**

If a focused regression appears, return to the task that owns the failing behavior, add its regression test first, rerun that task's command, then commit only its files. Do not claim completion until Task 7 Steps 1–4 have fresh successful output.
