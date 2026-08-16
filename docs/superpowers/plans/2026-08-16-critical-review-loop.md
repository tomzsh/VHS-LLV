# VHS Critical Review Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce a bounded, evidence-backed critical review at P4/P5 while keeping lazy-load and per-engagement memory isolation intact.

**Architecture:** Add one engagement ledger and validate it in `gate_check.py`; route a compact reference only for P3–P5. Bootstrap and rollup persist the ledger, while tests cover missing, malformed, and valid review paths.

**Tech Stack:** Python `unittest`, CSV schemas, Markdown references, existing VHS phase gates.

## Global Constraints

- P0–P3 remain usable without a critical-review ledger; P4/P5 fail closed when required reviews are absent or invalid.
- Each finalized test needs a review; each finding needs a linked `retain` review.
- No target traffic, global memory, third-party dependency, or unbounded reasoning loop is added.
- VHS authorization, scope, evidence, and stop conditions remain authoritative.

---

### Task 1: Add failing critical-review tests

**Files:**
- Modify: `tests/test_core.py`

**Interfaces:**
- Consumes: existing `gate_check` phase functions and engagement bootstrap
- Produces: regression tests for routing, bootstrap, P4/P5 enforcement, and valid review acceptance

- [ ] **Step 1: Write failing tests**

Add tests that assert the new reference is routed for P3/P4/P5, new engagements
create `critical-review.csv`, P4 rejects a final test without a review, P4
rejects a missing disconfirming field, P5 rejects an unreviewed finding, and a
complete linked review passes both gates.

- [ ] **Step 2: Run focused tests**

Run: `python3 -m unittest tests.test_core.CriticalReviewLoopTests -v`

Expected: FAIL because the reference, schema, bootstrap, and gate checks do not
exist yet.

### Task 2: Add the ledger and gate enforcement

**Files:**
- Modify: `config/ledger_schemas.json`
- Modify: `scripts/gate_check.py`
- Modify: `scripts/new_engagement.py`
- Modify: `scripts/status.py`

**Interfaces:**
- Consumes: test/evidence/finding ledgers
- Produces: `critical-review.csv` and fail-closed P4/P5 structural validation

- [ ] **Step 1: Add the exact CSV schema**

Use columns: `review_id`, `hypothesis_id`, `test_id`, `finding_id`, `claim`,
`evidence_ids`, `alternative_explanation`, `disconfirming_test`,
`negative_control`, `scope_impact`, `uncertainty`, `decision`, `reviewer`,
`reviewed_at_utc`.

- [ ] **Step 2: Implement P4 validation**

Require at least one review for every finalized test. Validate required fields,
known test/hypothesis/evidence IDs, and map `confirmed/rejected/blocked/`
`inconclusive/not_applicable` to `retain/reject/blocked/inconclusive/`
`not_applicable` decisions.

- [ ] **Step 3: Implement P5 validation**

Require every finding to have a known `finding_id` in a review with decision
`retain`; reject unknown links and missing required review fields.

- [ ] **Step 4: Bootstrap and status integration**

Let `create_missing_ledgers` create the new file for new engagements, include
it in status output, and preserve P0–P3 compatibility for older engagements.

- [ ] **Step 5: Run focused tests**

Run: `python3 -m unittest tests.test_core.CriticalReviewLoopTests -v`

Expected: PASS with zero failures.

### Task 3: Add lazy reference and memory/docs routing

**Files:**
- Create: `references/critical-review-loop.md`
- Modify: `SKILL.md`
- Modify: `references/context-router.md`
- Modify: `scripts/rollup_memory.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: ledger fields and P3–P5 gate behavior
- Produces: bounded loop guidance, phase routing, isolated resume memory, and user documentation

- [ ] **Step 1: Write the reference**

Document the seven-field loop, trigger conditions, one-pass default, second pass
only for high/critical or conflicting evidence, and explicit non-goals.

- [ ] **Step 2: Route it lazily**

Add P3/P4/P5 routing and a compact SKILL entry; do not add it to always-loaded
references or P0–P2 startup.

- [ ] **Step 3: Include reviews in rollup and README**

Persist review rows in JSON/Markdown rollups and document the ledger, commands,
and token-saving bounded behavior.

- [ ] **Step 4: Run focused tests**

Run: `python3 -m unittest tests.test_core.CriticalReviewLoopTests -v`

Expected: PASS with zero failures.

### Task 4: Verify and commit

**Files:**
- Verify: all changed files and repository test commands

- [ ] **Step 1: Run the complete suite**

Run: `python3 -m unittest discover -s tests -q`

Expected: zero failures.

- [ ] **Step 2: Run static checks**

Run: `python3 -m py_compile scripts/*.py`

Run: `for f in scripts/*.sh; do bash -n "$f" || exit 1; done`

Run: `git diff --check`

Expected: all commands exit 0.

- [ ] **Step 3: Review and commit**

Confirm that no target data or network behavior was added, then commit with:

```bash
git add config/ledger_schemas.json scripts/gate_check.py scripts/new_engagement.py scripts/status.py scripts/rollup_memory.py SKILL.md references/context-router.md references/critical-review-loop.md README.md tests/test_core.py docs/superpowers/specs/2026-08-16-critical-review-loop-design.md docs/superpowers/plans/2026-08-16-critical-review-loop.md
git commit -m "feat: add critical review gates"
```
