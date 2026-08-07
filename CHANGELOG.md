# Changelog

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
