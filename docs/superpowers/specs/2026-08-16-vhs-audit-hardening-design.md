# VHS Audit Hardening and Context Efficiency Design

## Goal

Harden the existing VHS pentest workflow against confirmed integrity, scope,
resume, and reporting bugs while reducing repeated context/tool work without
removing vulnerability classes, playbooks, or evidence requirements.

The implementation targets the current working tree and must preserve unrelated
local changes already present in the repository.

## Current evidence

The current baseline has 30 passing offline tests, Python compilation success,
shell syntax success, and clean whitespace checks. Additional minimal
reproductions confirmed:

1. `evidence_capture.py` lets two evidence IDs with the same basename overwrite
   the same raw file, invalidating the first row's recorded hash.
2. `vulnhunter_orchestrator.py` produces the same resume fingerprint after the
   engagement's `allowed_assets` changes because authorization and policy are
   excluded from the fingerprint.
3. A cached stage containing an `error` step is reused on resume, so a failed
   tool is not retried.
4. `check_tools.py --verify` can report a special tool as `present=true` when
   its configured executable or virtual environment is missing.

Static review also found that failed spreadsheet imports are made non-fatal,
the authenticated API helper has no engagement scope guard, and active
`arjun`/`ffuf` output is not consumed by the Dalfox input builder.

## Non-goals

- Do not rewrite or translate the imported attack playbooks.
- Do not change authorization policy to permit broader target traffic.
- Do not automatically enable OAST, destructive tests, race amplification, or
  state-changing API methods.
- Do not migrate engagement ledgers to a new database or format.
- Do not reset, rebase, or overwrite unrelated existing working-tree changes.
- Do not remove the full playbook or reference files; context slicing is an
  additional access path, not a content reduction.

## Design

### 1. Resume safety and stage replay

Add a canonical authorization fingerprint to the orchestrator run fingerprint.
It will hash a stable JSON projection of the current engagement authorization
record, including:

- authorization status and permission mode;
- allowed and excluded assets;
- allowed and prohibited methods;
- testing window and rate limits;
- stop conditions and scope-file content when a scope file is used;
- the P0 phase status from `state.json`.

The projection is hashed and stored only as a digest in `run-config.json`; raw
engagement data is not copied into the run configuration. A resume with changed
authorization, scope, exclusions, testing window, methods, or P0 status fails
before any cached stage is reused.

Stage checkpoints remain JSON arrays of `Step` objects. A checkpoint is reusable
only when it is valid JSON, has valid `Step` fields, and contains no `error` or
`timeout` step. Failed stages are re-executed on resume, while successful and
explicitly skipped stages retain their existing behavior.

### 2. Evidence artifact and ledger integrity

`evidence_capture.py` will use the shared ledger schema from `schemas.py`,
validate evidence IDs as safe single-component identifiers, and prefix every
raw/redacted filename with the evidence ID. This prevents two captures with the
same source basename from aliasing the same ledger path.

The capture path will:

1. create and chmod evidence directories owner-only;
2. acquire an exclusive engagement-local ledger lock;
3. re-check evidence ID uniqueness while holding the lock;
4. copy/read the source into a unique raw artifact;
5. create the redacted working copy when requested;
6. append the ledger atomically through a temporary file and `os.replace`;
7. remove newly created artifacts if the ledger append fails.

Existing header mismatches fail closed and leave the original ledger untouched;
they no longer replace the active ledger with a shortened backup-derived file.

### 3. Discovery-to-scan data flow

`active_discovery()` will produce a scope-filtered
`agents/discovery/urls_discovered.txt` artifact in addition to the raw tool
outputs. URL extraction will accept common URL-bearing fields from JSON output
and preserve only `http`/`https` URLs accepted by the existing `ScopePolicy`.

`dalfox_scan()` will merge the normalized crawl URLs with the discovered URL
artifact, deduplicate them, and apply the scope guard again before writing
`xss_candidates.txt`. This preserves the existing scan order and does not add a
new target request beyond the already authorized discovery stage.

### 4. Tool-check and deliverable failure semantics

Cache `detect()` results for one `check_tools.py` process so special venv/module
probes are not repeated for the same tool. Verification output will distinguish
availability from readiness consistently: a missing special executable or venv
will not be reported as present.

`make_deliverables.sh` will keep the current fallback import command, but return
non-zero when both import paths fail. It will also use a private umask for
generated deliverables. A successful command must mean that every requested
non-empty ledger was either imported or explicitly skipped because it is
missing/empty.

### 5. Scope-safe authenticated API helper

Extend `api_auth_probe.py` with a required `--engagement` argument. It will load
the current engagement through `authorize_run()` and reject a base URL or any
resolved endpoint whose host is outside the engagement scope. Endpoint joining
will use URL parsing rather than unchecked string concatenation.

GET remains the default for target endpoint requests. Direct token use skips
the login request; email/password login is treated as an authentication bootstrap
and requires an engagement `allowed_methods` entry of `login` or
`authentication`. Other non-GET methods require an explicit
`--allow-state-change` flag and an engagement `allowed_methods` entry matching
the requested method/action class. Network and timeout errors will be rendered
as controlled observations instead of terminating the helper with an unhandled
exception.

### 6. Token-efficient reference loading

Add `scripts/context_slice.py`, a deterministic read-only helper that can list
Markdown headings and emit selected heading sections. It will support:

- outline-only output;
- case-insensitive heading-term selection;
- extraction through the next heading of equal or higher level;
- ignoring ATX-looking lines inside fenced code blocks;
- a `--full` escape hatch for exact full-reference review;
- safe fallback to the complete file when no requested section matches.

Update `references/context-router.md`, `references/index.md`, and `SKILL.md` so
the router is the single loading policy:

- load the compact contract and current phase guidance once;
- use the attack-playbook index to select classes;
- use section slices for P3 planning (bilingual terms covering entry, probe,
  bypass, evidence, and compliance/stop sections, including the imported
  headings `高频入口`, `探测手法`, `复现`, `证据`, and `不要做`);
- load the full selected playbook for P4 exact validation or when a slice does
  not contain the required procedure;
- do not load unrelated playbooks, duplicate routing tables, or full catalogs.

All original references remain available, and the full-load path ensures that
the optimization cannot make a required procedure unreachable.

## Files and responsibilities

Modify:

- `scripts/vulnhunter_orchestrator.py` — authorization digest, failed-stage
  replay policy, and discovery URL aggregation.
- `scripts/evidence_capture.py` — unique artifact naming, locking, atomic ledger
  writes, and shared schema use.
- `scripts/check_tools.py` — cached detection and accurate verification state.
- `scripts/make_deliverables.sh` — strict import failure propagation and private
  output defaults.
- `scripts/api_auth_probe.py` — engagement-aware scope and controlled method
  handling.
- `SKILL.md`, `references/context-router.md`, and `references/index.md` —
  concise context-loading rules and exact slicing workflow.
- `tests/test_core.py` and/or a focused test module — regression coverage for
  every confirmed bug and the new context helper.
- `CHANGELOG.md` — concise release note for the hardening and context changes.

Create:

- `scripts/context_slice.py` — no-network, read-only Markdown outline/section
  selector.
- `docs/superpowers/specs/2026-08-16-vhs-audit-hardening-design.md` — this
  design record.

## Verification strategy

The implementation is complete only when all of the following are verified:

- the regression suite passes, including red-green tests for stale resume,
  failed-stage retry, evidence collision, scope enforcement, and discovery
  aggregation;
- `python3 -m py_compile scripts/*.py` succeeds;
- every `scripts/*.sh` passes `bash -n`;
- `git diff --check` succeeds;
- focused offline fixtures prove no out-of-scope URL reaches the API helper or
  Dalfox candidate file;
- an import-failure fixture proves `make_deliverables.sh` exits non-zero;
- context slicing preserves the selected section boundaries and `--full`
  returns the complete source;
- the full test command is rerun immediately before completion claims.

## Rollout order

1. Add regression tests for confirmed defects.
2. Implement resume and evidence integrity fixes.
3. Implement discovery aggregation and helper failure/scope hardening.
4. Implement tool-check caching and context slicing.
5. Update routing documentation and changelog.
6. Run focused tests, then the complete verification suite.
