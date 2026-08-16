# Bounded Chain Ladders Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add lazy, scope-gated `dig-deeper-chain.csv` and `pivot-ladder.csv` workflows with a default three-hop bound.

**Architecture:** Keep both modes as optional per-engagement ledgers. Centralize structural validation in `scripts/gate_check.py`, reuse `critical-review.csv` and existing evidence/test ledgers, and expose only conditional references in the router. Preserve `kill-chain` as the P5 composite-finding adapter.

**Tech Stack:** Python 3 standard library, CSV ledgers, Markdown skill references, `unittest`.

## Global Constraints

- Do not send target traffic from tests or helper validation.
- A hop never expands authorization or scope; both pivot assets must be `in_scope`.
- Default maximum depth is exactly 3 per chain or ladder.
- Missing optional ledgers remain compatible with existing engagements; new engagements bootstrap empty ledgers.
- P3 permits planned rows; P4/P5 require final status, evidence for confirmed rows, and critical-review links.

---

### Task 1: Add failing regression tests

**Files:**
- Modify: `tests/test_core.py` near `CriticalReviewLoopTests`
- Test: `tests/test_core.py`

**Interfaces:**
- Tests import `p3`, `p4`, and `p5` from `gate_check`.
- Fixtures use `LEDGER_SCHEMAS["dig-deeper-chain.csv"]` and
  `LEDGER_SCHEMAS["pivot-ladder.csv"]`.

- [ ] **Step 1: Write the failing tests**

Add tests for: both ledgers bootstrapping; conditional reference routing; P4
rejecting a fourth hop; a broken `next_test_id`; chain reuse across chain IDs;
a pivot destination that is not `in_scope`; a pivot asset outside
`engagement.json allowed_assets`; a pivot test/destination mismatch; a
confirmed hop without linked review/evidence; and one complete three-hop-safe
fixture accepted by P4. Keep all fixture actions offline.

- [ ] **Step 2: Run the focused tests to verify RED**

Run:

```bash
python3 -m unittest tests.test_core.DigDeeperAndPivotLadderTests -v
```

Expected: failures because the new schemas, bootstrap entries, and gate
validators do not exist yet.

### Task 2: Add schemas, bootstrap, status, and rollup support

**Files:**
- Modify: `config/ledger_schemas.json`
- Modify: `scripts/new_engagement.py`
- Modify: `scripts/status.py`
- Modify: `scripts/rollup_memory.py`
- Modify: `tests/test_core.py`

**Interfaces:**
- `create_missing_ledgers()` creates the two schema-defined CSV files.
- Rollup JSON keys are `dig_deeper_chains` and `pivot_ladders`.

- [ ] **Step 1: Add exact CSV headers**

Add `dig-deeper-chain.csv` with fields
`chain_id,step_no,test_id,hypothesis_id,question,alternative_explanation,disconfirming_test,negative_control,scope_impact,evidence_ids,next_test_id,status,stop_reason,uncertainty,review_id`.
Add `pivot-ladder.csv` with fields
`ladder_id,step_no,test_id,from_asset_id,to_asset_id,actor_or_identity,authorization_basis,precondition,action,expected_control,evidence_ids,status,rollback,impact,stop_reason,review_id`.

- [ ] **Step 2: Document and expose the ledgers**

Add both files to the engagement README table, status ledger listing, and
per-engagement rollup without adding global memory writes.

- [ ] **Step 3: Run focused bootstrap and rollup tests**

Run:

```bash
python3 -m unittest tests.test_core.DigDeeperAndPivotLadderTests.test_new_engagement_bootstraps_chain_ledgers -v
```

Expected: PASS.

### Task 3: Implement fail-closed chain and ladder gates

**Files:**
- Modify: `scripts/gate_check.py`
- Modify: `tests/test_core.py`

**Interfaces:**
- Add `validate_optional_ladders(root, tests, evidence_ids, reviews, errors, phase)`.
- `p3`, `p4`, and `p5` call it after their existing checks.

- [ ] **Step 1: Implement shared validation**

Read optional ledgers only when present. Validate exact headers, non-empty IDs,
positive contiguous step numbers starting at one, maximum depth three, linked
next hops and terminal rows, no test/hypothesis reuse across chain IDs, known
test and hypothesis links, and status/test-status consistency. For confirmed
rows require evidence IDs and a `critical-review.csv` review whose `test_id`
matches. Validate `next_test_id` when present.

- [ ] **Step 2: Implement pivot-specific scope checks**

Load `asset-inventory.csv` and `engagement.json` through `ScopePolicy`; require
both asset IDs to exist, have `scope_status == in_scope`, and match the
engagement allowlist. Require distinct assets, require the linked test's
`asset_id` to equal `to_asset_id`, and require a meaningful authorization basis
and rollback plan for every row. Do not parse or persist credential material.

- [ ] **Step 3: Run focused tests to verify GREEN**

Run:

```bash
python3 -m unittest tests.test_core.DigDeeperAndPivotLadderTests -v
```

Expected: all focused tests pass.

### Task 4: Add lazy-load references and workflow routing

**Files:**
- Create: `references/dig-deeper-chain.md`
- Create: `references/pivot-ladder.md`
- Modify: `references/index.md`
- Modify: `references/context-router.md`
- Modify: `SKILL.md`
- Modify: `README.md`
- Modify: `tests/test_core.py`

**Interfaces:**
- References are loaded conditionally in P3–P5 and never for passive discovery.
- `kill-chain` documentation remains explicitly P5 post-triage.

- [ ] **Step 1: Write concise references**

Document triggers, hop contract, stop conditions, token bounds, and the
distinction between the two modes. Include no target-specific facts or raw
credentials.

- [ ] **Step 2: Wire phase routing and user-facing docs**

Route only the selected reference from the context router and update the phase
table, lazy-load section, and feature summary.

- [ ] **Step 3: Run reference integrity tests**

Run:

```bash
python3 -m unittest tests.test_core.DigDeeperAndPivotLadderTests.test_chain_references_are_conditionally_routed -v
```

Expected: PASS.

### Task 5: Verify, review, and commit

**Files:**
- All files from Tasks 1–4

- [ ] **Step 1: Run the full offline suite**

Run `python3 -m unittest discover -s tests -q`; expect 88 tests and zero
failures after the six new tests are added.

- [ ] **Step 2: Run static checks**

Run `python3 -m py_compile scripts/*.py`, `bash -n` for every shell script,
and `git diff --cached --check`.

- [ ] **Step 3: Inspect the staged diff**

Confirm optional ledgers are not mandatory for old engagements, pivot scope is
fail-closed, maximum depth is enforced, references are conditional, and no
global-memory path is added.

- [ ] **Step 4: Commit the implementation**

```bash
git add config/ledger_schemas.json scripts/gate_check.py scripts/new_engagement.py scripts/status.py scripts/rollup_memory.py references/dig-deeper-chain.md references/pivot-ladder.md references/context-router.md SKILL.md README.md tests/test_core.py
git commit -m "feat: add bounded exploration ladders"
```
