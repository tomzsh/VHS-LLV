# Race Conditions & Dedup-Reentrancy Flaws (2026)

> Concurrency bugs where the system processes the **same resource more than
> once** because a check-then-set or a duplicate-suppression guard is missing
> or non-atomic — money, state, or a proof gets created/inflated more times
> than intended. 2026 emphasis is **non-networked dedup/accounting races**:
> the "verify once, accept many" pattern found by logical reasoning, not just
> multi-thread HTTP races. Use at P3/P4.
> Taxonomy: CWE-362 (Race Condition), CWE-367 (TOCTOU), CWE-799 (concurrent
> execution), CWE-770 (duplicate suppression absent).
> Pair with the black-box **`attack-playbooks/race-conditions.md`** (Turbo
> Intruder / concurrency harness) and `module-business-logic-flaws.md`.

---

## 1. Three race shapes to hunt in 2026

1. **Check-then-set (TOCTOU)** — read value → decide → write, with no
   atomicity. Two concurrent requests both pass the check before either
   writes → double-spend / double-withdraw / double-approve / double-coupon.
   *Classic HTTP race.*
2. **Non-atomic dedup / duplicate-identity** — the system *allows* the same
   logical item to enter N times because there is **no uniqueness guard** on
   the identity (key_image, txid, request id, order id, email, job id).
   Seen at the **accounting/math** layer, not the HTTP layer:
   #3699522 (`check_reserve_proof` tallies duplicate rows → inflated total).
   This is the 2026 pay pattern — it does **not** need parallel HTTP; a single
   crafted request repeating an identity is enough.
3. **Two-phase state** — an operation that must transition atomically
   (create→approve→settle) is split; a concurrent path can settle before
   validation writes, or re-enter a transition.

**Why #1 the hard cases are gone but #2 remains:** WAFs/rate-limit catch
parallel-request races, but **identity-dedup gaps** are logic bugs invisible
to traffic analysis.

---

## 2. Proven case study (real, disclosed 2026)

### #3699522 — Monero · duplicate entries inflate `check_reserve_proof` `total` (High)
- **When:** 2026-04-27 · program **Monero** · `src/wallet/wallet2.cpp`
- **Dedup/identity flaw (verbatim):** the verifier iterates `reserve_proof_entry`
  rows and `total += amount` per row, **without requiring each `key_image` or
  `(txid, index_in_tx)` to appear only once**. Repeat the same output N times →
  N copies in the prefix → all per-row signatures valid → **total scales with
  occurrence count, not distinct outputs**. A custom (malicious) prover can
  inflate a reserve proof → falsified proof-of-funds.
- **Why it's a race/dedup bug:** acceptance is *not idempotent by identity*;
  the guard that should prevent the same logical entry counting twice is
  missing. You don't need concurrent network calls — one crafted request
  repeats the row.
- **Link:** `https://hackerone.com/reports/3699522`
- Also verify **#3700036** Monero txid-substitution (proof not bound to the
  returned tx) — a single-request *binding* flaw in the same family.

---

## 3. Detection checklist (P2/P3)

- [ ] **Parallel race surfaces:** endpoints that credit/debit/approve/coupon/
      withdraw/redeem — send **2x+ concurrent identical requests** and diff the
      outcome (balance, credit, count, order) vs 1x.
      → Playbook `race-conditions.md` (Turbo Intruder / async harness).
- [ ] **Check-then-set:** identify read→decide→write flows with no lock/
      transaction isolation / idempotency key. Grep for
      `SELECT ... WHERE` then `UPDATE/INSERT`, `if (user.balance >= x) { debit }`.
- [ ] **Identity-dedup (2026 focus):** does any consumer of untrusted data
      (proof, receipt, import, webhook, order) **dedup by a unique identity**
      or does it **count every occurrence**? Grep `total +=`, `sum +=`, loops
      over vectors/arrays with no set/HashSet/`DISTINCT`/unique-constraint.
      (#3699522 pattern — verify once, accept many.)
- [ ] **Idempotency key:** does the app accept an `Idempotency-Key` or request
      id — and does it actually dedup on it? Test same key 2x.
- [ ] **Re-entrancy/fallback:** after a failed/settled transition, can the same
      logical unit be re-submitted as if new?

---

## 4. PoC harness (read-only / controlled, authorized target only)

```bash
# A) parallel race (needs 2+ requests near-simultaneous)
cat <<'EOF' | xargs -P8 -I{} curl -s -X POST "https://TARGET/api/withdraw" -d '{}' 
{"amount":100,"account":"ME"}   # send 8x concurrently
EOF

# B) single-request dedup flaw (#3699522 pattern) — repeat the SAME entry in one payload
curl -s -X POST "https://TARGET/api/reserve" \
  -d '{"rows":[{"id":"A","amt":100},{"id":"A","amt":100},{"id":"A","amt":100}]}'
#   ^ if total=300 (not 100), identity-dedup is broken

# C) idempotency-key reuse
curl -s -X POST -H "Idempotency-Key: k1" "https://TARGET/api/order" -d '{"sku":"X"}'
curl -s -X POST -H "Idempotency-Key: k1" "https://TARGET/api/order" -d '{"sku":"X"}'
```

**RoE:** test accounts / minimal amounts; never double-spend real funds or
trigger real payments; abort at first confirmed double-count; record baseline
vs concurrent/dedup-normal outcome + negative control.

---

## 5. Severity

- **Double-spend / double-withdraw / double-credit, financial** → **Critical**.
- **Proof/reserve inflation** (falsified solvency, #3699522 class) → High; in
  fintech/CEX often Critical.
- **Duplicate row without financial impact** → Medium.
- **Parallel race causing unauthorized state** → High; blind (logic-only,
  dedup) races → Medium-High depending on the state affected.
- Cite: CWE-362/367/366/770; case #3699522, #3700036; pair with the
  race-conditions playbook for the transport-level harness.