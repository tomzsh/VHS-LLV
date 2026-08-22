# Changelog

## 2.8.0 — critical-yield upgrade: detection engine, playbooks, proportional gates

Track A — detection engine:
- Authenticated scanning: `--auth-profile NAME` injects a session (env-only
  `VHS_AUTH_<NAME>_COOKIE` / `VHS_AUTH_<NAME>_BEARER`) into katana, arjun,
  ffuf, nuclei, and dalfox. Credentials never enter argv, run configs,
  manifests, or logs (`redact_command` masks them and resume fingerprints
  exclude them), unlocking authenticated IDOR/authz/logic coverage.
- Added `scripts/fingerprint_cve.py` + `references/kev-snapshot.json`: offline
  fingerprint→CVE/KEV correlation over httpx tech-detect and naabu banners,
  ranked known-exploited-first, `--append-hypotheses` imports leads as
  HYP-CVE rows. Wired as orchestrator stage `35-fingerprint-cve` (local-only).
- Added `scripts/takeover_check.py` + `references/takeover-fingerprints.json`:
  DNS-only dangling-CNAME subdomain-takeover screening (26 services,
  claimable/partial/discontinued statuses). Never claims resources — claiming
  stays a manual, program-approved controlled-impact action. Stage
  `38-takeover-check`.
- Added `scripts/header_probe.py` + stage `45-header-probe`: GET-only CORS
  reflection (arbitrary/null origin × credentials) and missing-header
  inventory; high-value signals import as HYP-HDR rows.
- Added `scripts/race_probe.py`: bounded race harness (barrier-parallel and
  HTTP/1.1 last-byte-sync pipeline modes, hard cap 50, single burst). Requires
  explicit `race_testing` in allowed_methods; state-changing methods also need
  `--allow-state-change` plus method permission (api_auth_probe semantics).
- Discovery depth: ffuf gains `-recursion -recursion-depth 2`, `--extensions`,
  `--vhost` Host-header enumeration, and a merged wordlist including paths
  extracted from JS bundles; `--port-set top1000` widens naabu when port
  scanning is authorized; defaults raised (`--max-hosts` 30, `--max-js-files`
  150).
- Blind/OOB workflow: `sqlmap.sh` gains `VHS_SQLMAP_PRESET=blind`
  (boolean+time, level 3 risk 2) and refuses controlled-impact flags
  (`--os-shell/--os-pwn/--os-cmd/--privileged`); new `sqli-oob` payload
  section (MSSQL xp_dirtree/OPENROWSET UNC, MySQL LOAD_FILE UNC, Oracle
  UTL_HTTP/UTL_INADDR, PostgreSQL dblink, sqlmap `--dns-domain`).
- Triage `verdict()` is now multi-signal: status-code delta, body-head hash
  comparison against the soft-404 baseline (baselines now record
  `head_sha256_12`), and soft-404 content markers — same-size clones are no
  longer mislabelled likely_fp and content-differing responses surface for
  review.

Track B — playbooks and finding policy:
- New playbook `attack-playbooks/subdomain-takeover.md` (registered in
  00-index.md): leak surfaces, dangling verification, fingerprint table,
  value-escalation paths, evidence/CVSS guidance, and red lines (claim =
  controlled impact; program policy governs eligibility).
- P3 unblinding: per-vuln-class "Bypass 矩阵" sections are now routable through
  `context_slice.py --safe-playbook` with the compliance section still
  attached; detection-evasion, exploitation/privesc/lateral movement,
  persistence, DoS, and post-exploitation categories remain refused and
  whole-playbook blocks (dos.md, intranet-postexp.md) are unchanged.
- Playbook additions: UUID/GUID leak-then-reuse + org/tenant-switch
  (arbitrary-x-authz 6.5), PKCE bypass & code-handling attacks
  (oauth-saml-jwt 3.2b), field suggestions / persisted queries / alias races /
  subscriptions (graphql 3.6b–3.6e), modern single-packet racing
  (race-conditions 3.2).
- `non-qualifying.md` is now explicitly a default template overridden by the
  target program's policy: subdomain takeover is no longer globally excluded,
  and blind SSRF qualifies when internal reachability is proven.
- `p4-validation.md` SSRF proof pattern: authorized escalation ladder
  (researcher-controlled callback → non-sensitive internal reachability proof
  → metadata/credential proof only with explicit program approval, canary
  identity where possible, immediate disclosure).
- Taxonomy: added priority-1 anchors for SQLi (auth-bypass admin access, OOB
  exfil), RCE (unauthenticated, deserialization chain), XXE (file disclosure
  to credential theft); SSRF Internal Secrets Exposure raised P2→P1 to match
  the documented critical hunt list.
- Fixed `http-smuggling.md` binary detection (embedded literal NUL byte
  escaped) so grep/context tooling can slice it.

Track C — proportional throughput (authorization model unchanged):
- P4 critical review is proportional: full 12-field adversarial review only
  for confirmed tests; rejected/blocked/inconclusive/not_applicable tests need
  a bounded decision record (id/hypothesis/test/decision/reviewer/timestamp).
- P3 test matrix is tiered: read-only probes (permission_mode PASSIVE or a
  `read-only` tag in notes) skip auto-derivable fields
  (negative_control/cleanup/risk); state-changing tests keep the full set.
- `playbooks_loaded` is satisfied automatically when every test row cites a
  playbook; `--mark-playbooks` remains available.
- Authorization/scope invariants untouched: P0 gate, deny-override scope,
  scope-narrowing-only, method/login gating, redirect containment, evidence
  integrity, testing window, and the tests locking them all stay green.

## 2.7.4 — stack-aware prioritization and role matrix

- Added `scripts/playbook_prioritizer.py`: ranks the 19 attack playbooks by
  expected yield from recon evidence (httpx technology fingerprints, discovered
  URL patterns). Baseline playbooks always listed; others need a stack/URL
  signal. Excludes dos/intranet-postexp/mobile (gated surfaces). Output feeds
  P3 test-design ordering.
- Added `scripts/role_matrix.py`: privilege-escalation role×action matrix.
  Plan mode generates cells with expected outcomes (allow/deny/owner_only);
  audit mode cross-checks every cell against test-matrix.csv and `--enforce`
  exits 1 while untested cells remain.
- Registered both in SKILL.md (P3/P4 sections).

## 2.7.3 — critical-finding yield and throughput upgrades

- Added `scripts/identity_diff.py`: identity differential engine for P4. Probes
  the same endpoints under two identities (env-based tokens or per-identity
  login) and classifies each response pair (identical / data_diff /
  access_diff / shape_diff), flagging value diffs on sensitive fields
  (balance, email, role, owner...) as strong IDOR/BOLA candidates. Supports
  `--swap-param/--swap-values` object mutation per endpoint.
- Added `scripts/js_deep_parse.py` + wired a `jsluice-deep-parse` step into the
  orchestrator's active-crawl stage: downloads discovered JS bundles
  (scope-checked, rate-limited, GET-only), extracts hidden API endpoints and
  embedded secrets via jsluice, writes scoped URL list + secrets JSON.
- ffuf discovery now runs as a parallel worker pool across targets
  (`--discovery-workers`, default 4) instead of sequential per-target loops.
- Added `--include-medium` to add medium-severity nuclei results (chaining
  material for composite criticals).
- Registered `identity_diff.py` usage in SKILL.md P4 section.
- Regression tests: ZeroFindingGateTests (3 cases) cover the persistence gate;
  full suite green.

## 2.7.2 — zero-finding persistence protocol

- Added `references/persistence-protocol.md`: hard requirements before any
  engagement may conclude 0 findings (executed surface coverage, playbook
  rotation, identity matrix, multi-source discovery, second-pass mutations,
  signal accounting, profile escalation) plus a 10-rung escalation ladder and
  anti-pattern list.
- Added `check_zero_finding_exhaustion()` to `scripts/gate_check.py`, enforced
  at both P5 and P6: a zero-finding advance now requires ≥10 finalized tests,
  ≥2 distinct executed playbooks, and a `coverage-exhaustion.md` document.
  Engagements with findings are unaffected.
- Registered the protocol in SKILL.md so it loads when an engagement trends
  toward a zero-finding conclusion.
- Verified: gate refuses premature zero-finding conclusion; passes once
  exhaustion requirements are met; negative control with findings skips the
  check.

## 2.7.1 — GraphQL launcher help contract

- Fixed `scripts/graphql_cop.sh --help` to return success and show usage before
  requiring an engagement or target.
- Added an offline regression test for the side-effect-free help path.
- No target behavior, authorization policy, or GraphQL execution contract changed.

## 2.7.0 — progressive context loading and final audit hardening

- Added the deterministic, no-network `scripts/context_slice.py` helper for
  Markdown outlines and selected heading sections, with fenced-code handling
  and nested-child preservation.
- Hardened playbook routing with exact outline-derived terms, mandatory safety
  context, and refusal of evasion/post-exploitation categories while retaining
  every imported playbook byte and P4 `--full` access.
- Added redirect-time scope/origin enforcement to authenticated API probing;
  authorization headers and login credentials cannot cross origins.
- Made prohibited API/login methods override normalized allow aliases, kept
  evidence artifacts consistent after post-commit output failures, and put the
  GraphQL Cop launcher behind engagement/P0/ScopePolicy validation.
- Made DOCX close failures fail closed and expanded the offline regression suite
  for the final audit findings.

## 2.6.0 — cited 2026 Web2 vulnerability references

- Added `references/web2-2026-references.md` covering ATO, IDOR/BOLA,
  business logic, SQLi, NoSQLi, SSTI, command injection, CSRF,
  deserialization, race/TOCTOU, privilege escalation, fail-open,
  authorization, canonicalization, and configuration/exception handling.
- Added a 2026 CVE anchor matrix using canonical CVE Services records, plus
  OWASP 2025, CWE, and PortSwigger methodology sources.
- Explicitly separates IDOR evidence (CWE-639/object ownership proof) from
  adjacent 2026 authorization-bypass and privilege-transition cases.
- Routed the reference through `context-router.md` and `references/index.md` so
  only the matching subsection is loaded; core token footprint is unchanged.
- Bumped the local skill version from 2.5.0 to 2.6.0; no GitHub commit/push.

## 2.5.0 — lazy context routing and token-footprint reduction

- Added `references/context-router.md` with phase/surface routing, fallback
  rules, and a no-unrelated-playbooks loading invariant.
- Moved account/OTP, research, operator commands, tool quirks/catalog, and
  crawler extras into conditional references instead of the core `SKILL.md`.
- Reduced duplicate GraphQL and Code Graph prose in `SKILL.md` to routing
  pointers while preserving their full integration references and commands.
- Kept authorization, P0-P6 gates, evidence, state/resume, scope, and
  verification rules in the core prompt so capability is not reduced.
- Bumped the local skill version from 2.4.0 to 2.5.0; no GitHub commit/push.

## 2.4.0 — Code Graph SAST and grounded RAG integration

- Added local Code-Graph-RAG integration as the static-analysis counterpart to
  GraphQL Cop DAST: Tree-sitter code graphs and typed nodes/edges are kept
  behind `scripts/code_graph_rag.sh`; optional embedding search is documented
  separately because it pulls a large ML runtime.
- Added `scripts/code_graph_grounding.py` with deterministic `context` and
  `verify` commands. Node/edge citations must exist in the graph export;
  unsupported or fabricated citations return `UNKNOWN` and a non-zero exit.
- Added the `sast` tool agent and Code-Graph-RAG readiness probe to
  `check_tools.py`, with `VHS_CODE_GRAPH_RAG_BIN` override support.
- Added `references/code-graph-rag-integration.md`, covering SAST workflow,
  RAG retrieval contract, provenance, source/line checks, prompt-injection
  boundaries, and evidence handling.
- Added regression tests for launcher forwarding, tool detection, and rejection
  of hallucinated graph nodes/edges.

## 2.3.0 — local GraphQL Cop integration

- Installed GraphQL Cop `1.15` locally at `~/tools/graphql-cop` in an isolated
  virtual environment; no global Python package or GitHub push was used.
- Added `scripts/graphql_cop.sh`, with `VHS_GRAPHQL_COP_HOME` override and
  `PYTHONPATH` isolation.
- Added GraphQL-specific readiness detection to `check_tools.py` and the
  `graphql` tool agent in `config/tools.json`.
- Added `references/graphql-integration.md` and connected the GraphQL playbook
  to the local launcher. GraphQL Cop remains explicit/manual rather than an
  automatic orchestrator stage because its checks generate active requests.
- Added regression tests for launcher argument forwarding and isolated tool
  detection.

## 2.2.2 — engagement and gate hardening

Fixed four reproducible defects found during the script audit:

- `new_engagement.py` and `schemas.py` now create engagement documents and
  ledgers with owner-only mode `0600`; confidential scope, RoE, evidence
  metadata, and findings notes no longer inherit a world-readable `0644` mode
  under a typical `umask 022`.
- `evidence_capture.py --stdin` now accepts only a plain filename. Absolute and
  traversal paths such as `../../escape.txt` are rejected before capture, so a
  capture cannot write outside `evidence/raw/`.
- P3 gate playbook citations are now checked against the installed
  `references/attack-playbooks/` directory. A typo or nonexistent playbook no
  longer satisfies the grounding requirement.
- `make_deliverables.sh` now supports `--help` and reads `engagement.json` via
  an argv path instead of interpolating the path into Python source; engagement
  directories containing apostrophes or other shell-significant characters now
  preserve the report title.
- Added four regression tests; offline suite is now 22/22.

## 2.2.1 — kill_chain.py no longer writes into the skill folder

Fixed a cleanup bug: `kill_chain.py` defaulted `CHAIN_DIR` to
`<skill>/state/chains` and created `state/chains/<target>/` on **every**
`KillChainBuilder()` instantiation (the adapter always instantiates), leaving an
empty `state/` folder inside the installed skill / repo — runtime data leaking
into the skill tree.

- `CHAIN_DIR` now defaults to a temp dir (`$TMPDIR/vhs-kill-chains`), overridable
  with `VHS_CHAIN_DIR`; it is never placed inside the skill folder.
- Directory creation moved from `__init__` (eager, every instance) to
  `save_chains()` (lazy, only when chains are actually persisted). Instantiating
  a builder no longer creates any folder.
- `save_chains()` / `load_chains()` still work unchanged when called.
- Removed the stray `state/` artifact; added `state/` + `vhs-kill-chains/` to
  `.gitignore`.
- Note: the per-target *engagement* memory system (`<engagement>/state.json` +
  ledgers + `memory-rollup.md`) is unrelated and was already correct — verified
  isolation across two separate engagements.

## 2.2.0 — Android APK static-analysis module

Added a first-class Android mobile surface. Previously the skill recognized a
`mobile` surface only as a generic 5-item checklist with no tooling — despite
APK review being a routine, high-yield source of endpoints, secrets, and
exported-component bugs. Added:

- **`references/module-android-apk.md`** — full static-analysis playbook:
  acquire (apkeep/adb), decompile (jadx + apktool), AndroidManifest review
  (exported components, deep links, debuggable/allowBackup, cleartext,
  network-security-config), exported-component adb PoCs (`am start` /
  `content query`), secret + endpoint hunting, WebView/TLS pitfalls, local
  storage/logging, a severity/FP findings checklist, and P2→P4→P5 feedback.
- **`scripts/apk_recon.sh`** — one-shot launcher: jadx + apktool decompile, then
  extracts exported components, deep links, secret candidates, and endpoints
  into a `report/` folder. Read-only (never installs/runs the app). Env
  overrides `VHS_JADX` / `VHS_APKTOOL` / `VHS_JADX_ARGS`. Tested end-to-end on a
  real 60MB+ Flutter APK (14 exported, 21 deep links, 31 secret candidates, 62
  endpoints extracted; jadx partial-decompile on obfuscated code handled).
- **`config/tools.json`** — new `mobile` tool profile (jadx, apktool, apkeep,
  adb, aapt); wired into the `active-safe` and `scanner-safe` profiles.
- **`check_tools.py`** — detects the mobile toolchain (version probes added).
- **`surface_checklist.py`** — expanded the `mobile` checklist (deep link,
  debuggable/backup, cleartext, WebView, insecure storage) from 5 to 9 items.
- Documented in SKILL.md (Phase router P2-mobile, Bundled scripts, quick
  commands, quirks table) and `references/index.md` (target modules).

## 2.1.3 — P5 kill-chain + evidence-capture bug fixes

Bug audit found the P5 kill-chain feature was silently dead and evidence
capture had a permission/dedup gap. Fixed:

- **kill_chain_vhs.py — chain matching was always empty (critical).** The
  scoring engine (`kill_chain.py`) matches on `finding["bug_class"]` and
  `finding["endpoint"]`, but the vhs findings schema has neither column, so the
  adapter never populated them → `class_score`/`endpoint_score` always 0 → no
  chain pattern could ever match. Added a keyword→bug_class classifier plus
  endpoint/method extraction from the finding's title/root_cause/impact text.
  The advertised "P5 chaining (composite A→B→C severity)" now actually works.
- **kill_chain.py — single-finding severity downgrade.** `_escalate_severity`
  returned `low` for a lone `medium`/`high` matched finding (e.g. `["medium"]`
  → `low`), violating the documented invariant "a chain is always >= max
  individual severity." Now floored at the strongest component.
- **kill_chain_vhs.py — empty report target.** Header read `root.parent.name`,
  which is empty for `./engagement`; now resolves `primary_target` from
  engagement.json with a resolved-dir-name fallback.
- **kill_chain_vhs.py — non-open findings chained.** Now only
  open/confirmed/triaged/validated findings feed the chain builder.
- **evidence_capture.py — world-readable raw evidence.** Raw + redacted files
  inherited umask (0644) despite SKILL.md promising "restrictive permissions";
  now chmod 0600 (best-effort). Matters for unredacted PII/secret captures.
- **evidence_capture.py — silent duplicate evidence ids.** `--evidence-id` is
  documented unique but dups appended silently; now rejected before any file is
  written (no orphan raw artifact).
- Added `tests/test_core.py::KillChainTests` (3 regression tests) locking in
  chain matching, the severity invariant, and non-open exclusion. Suite: 18/18.
- **import_scope.py — silent asset-inventory overwrite.** `write_inventory`
  used mode="w", clobbering an existing non-empty asset-inventory.csv (manual
  assets or a prior import) with no warning. Now refuses to overwrite a
  populated inventory unless `--force` is given.

Full 20-script audit: policy, gate_check, schemas, new_engagement, status,
surface_checklist, rollup_memory, triage_scan, api_auth_probe, redact_scan, and
vulnhunter_orchestrator reviewed with no logic bugs found (orchestrator's
flock lifecycle, atomic_write+fsync, and per-stage scope guards verified sound).

## 2.1.1 — OIDC session auto-refresh reference

- Added `references/oidc-session-refresh.md`: reusable Keycloak/OIDC flow to obtain
  a self-refreshing access token (auth-code + PKCE S256) from session cookies.
  Covers cookie `Path=/auth/realms/<realm>/` requirement, 43-char PKCE verifier,
  and the "never re-type long JWTs by hand" pitfall.
- Wired into `references/index.md` (load during P3/P4 for Keycloak targets).

## 2.1.0 — Toolchain optimization + crawler extras

- Added `scrapling_crawl.py` (stealth fetch, anti-bot pages) and
  `crawl4ai_crawl.py` + `crawl4ai_crawl.sh` (headless-Chromium JS crawl) to the
  active-crawl stage; outputs merge into `urls_all.txt` through the same scope guard.
- `check_tools.py` now detects non-binary tools: scrapling (python module) and
  crawl4ai (venv launcher with `env -u PYTHONPATH` probe).
- Bumped `--max-hosts` default from 5 to 15 for wider scan coverage.
- Expanded `gau` providers to `wayback,otx,commoncrawl,urlscan`.
- Added `-fc 404` to httpx so soft-404s are not marked live.
- Installed katana, assetfinder, and amass into the recon toolchain.

## 2.0.1 — Concurrency hardening

- Replaced fixed `.tmp` names with unique same-directory temporary files.
- Added flush and `fsync()` before atomic replacement.
- Replaced existence-based run locks with Linux kernel `flock` locking.
- Lock files now retain PID and creation metadata for diagnostics.
- Crash, SIGKILL, and power-loss scenarios no longer leave a permanently blocking lock.
- Moved lock acquisition before `run-config.json` and every other mutable run artifact.
- Added cross-process atomic-write and SIGKILL recovery regression tests.

## 2.0.0 — Fixed and hardened

- Replaced positional Bash parsing with exact argument forwarding.
- Removed hard-coded `/home/tomz` paths.
- Added shared ledger schemas used by initialization and gate validation.
- Added fail-closed authorization, P0, testing-window, permission, and scope checks.
- Added execution profiles: plan-only, passive-osint, active-safe, scanner-safe.
- Changed `--manual-only` into a true no-direct-target-traffic passive alias.
- Added deny-first host and URL scope guards before active tools.
- Scope files now restrict but cannot expand engagement scope.
- Restricted HTTP redirects to the same host.
- Fixed the parallel dependency: Dalfox waits for discovery output.
- Implemented resumable stage checkpoints with configuration fingerprint checks.
- Wired `--rate-scan` into Nuclei and removed the hard-coded 20-host limit.
- Added explicit OAST opt-in with `--enable-oast`.
- Added scoped soft-404 baseline capture for scanner triage.
- Made triage read output paths from `manifest.json`.
- Added JSON output counting and truthful authorization metadata.
- Added secure default file permissions and run-directory locking.
- Reduced `SKILL.md` from 826 lines to a progressive-disclosure core.
- Added offline regression tests.

## 2.0.2 — Test isolation hardening

- Added fake stubs for `waymore`, `hakrawler`, `naabu`, `ffuf`, `amass`,
  `assetfinder` in `test_fake_tools.py` so PATH never falls through to real
  binaries on fully-provisioned hosts.
- Full suite (13 tests) now completes in ~2s instead of hanging 30s+ on
  real-network tool invocations.
