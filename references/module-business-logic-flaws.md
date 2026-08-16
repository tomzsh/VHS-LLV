# Business Logic Flaws — Accounting, Integrity, and State-Transition Errors

> Bugs where the **logic** is wrong, not the access control: duplicate entries
> counted twice, proof/token not bound to its object, state transitions that
> skip validation, idempotency violations, negative/overflow amounts, and
> "trust the blob" hand-offs. These are the highest-ROI class for 2026: they
> survive auth checks because **the check is fine — the math/state is not.**
> Use at P3/P4. Taxonomy: CWE-840 (Business Logic), CWE-20/697 (improper
> validation), CWE-345 (insufficient verification of data authenticity).

---

## 1. The four logic-flaw patterns that pay

1. **Accounting / counting** — totals derived by summing rows without dedup
   or bounds. Duplicate/negative/overflow rows inflate or deflate state
   (#3699522: reserve proof inflated by repeating rows).
2. **Binding / integrity** — a proof, receipt, token, or signature is created
   against identifier A, but the object it proves is B — because the code
   uses a *caller-supplied* id instead of the *derived* one (#3700036:
   spend proof signs txid but rings/inputs come from a different tx).
3. **State-transition** — a workflow (order → pay → fulfill; verify → approve;
   import → reconcile) allows skipping an intermediate authorized step, or
   re-entering one, or finishing in an inconsistent state.
4. **Idempotency / uniqueness** — the same operation performed twice creates
   double funds, double approval, or duplicated entries (often combines with
   race; see `module-race-condition.md`).

---

## 2. Proven case studies (real, disclosed 2026)

### 2.1 Monero — #3699522 · `check_reserve_proof` counts duplicate entries: one output inflates `total` (High)
- **When:** submitted 2026-04-27 · program **Monero** · verifier flaw in
  `src/wallet/wallet2.cpp` / `wallet_rpc_server.cpp`
- **Flaw (verbatim):** reserve proofs are **untrusted blobs**. The verifier
  walks `reserve_proof_entry` rows, checks each signature, then adds the row's
  amount to `total` — **nothing requires each key_image / (txid,index) to
  appear only once**. Repeating the same output N times repeats the key image
  in the prefix, recomputes the prefix hash, and each per-row signature is
  valid (owner has the keys). Result: `total += amount` per *occurrence*, so
  **the reported reserve scales with how many times the row is repeated**, not
  with distinct on-chain outputs.
- **Impact:** a malicious prover can inflate a reserve proof → **accounting
  manipulation / forged proof of funds**.
- **Root cause:** flat `for` loop with no dedup / set check; per-row checks do
  not see "this key image was already used."
- **Link:** `https://hackerone.com/reports/3699522`

### 2.2 Monero — #3700036 · SpendProofV1 txid-substitution: proof not bound to returned tx
- **When:** submitted 2026-04-28 · program **Monero**
- **Flaw:** `get_spend_proof` fetches a pruned tx, builds the challenge from
  the **txid argument**, but **never compares the parsed tx_hash to txid**
  before signing/verifying (the sibling `check_tx_proof` does
  `THROW_WALLET_EXCEPTION_IF(tx_hash != txid, ...)`). A malicious/fake daemon
  or on-path MITM answers a request for txid B with a valid body for a
  **different tx A**; the wallet signs `H(B || message)` while using A's
  inputs/rings.
- **Impact:** spend-proof **integrity/binding** broken — a verifier against
  the same bad endpoint sees `good: true` for B even though nothing
  authenticates B. (Requires broken/attacker-controlled daemon channel; no
  key exfiltration.)
- **Root cause:** caller-supplied id (txid) used as the binding identity
  instead of the **derived hash from the retrieved blob**.
- **Link:** `https://hackerone.com/reports/3700036`

> **Both share the same mental model:** "the value an untrusted party sends
> determines what the system believes is true" — count, proof, id, total.
> Grep for `total +=`, `for(...) { sum += }`, `id` args used to build
> signatures/keys, and "trusted blob" verifiers.

---

## 3. Detection checklist (P2/P3)

- [ ] **Money/state math:** totals, balances, fees, refunds, point balances,
      coupon codes, referral counts — trace how `total` is computed. Can a
      row be **duplicated / negative / zero / overflowing**? Is there a **set/
      dedup** guard? (#3699522)
- [ ] **Proof/receipt binding:** signatures, tokens, proofs, receipts — is the
      binding identity the **derived** object hash, or a **caller-supplied**
      id? Does verification recompute & compare? (#3700036)
- [ ] **State machine:** order/payment/fulfillment, KYC verification, OTP
      flows, subscription state — enumerate allowed transitions. Can you
      **skip / repeat / reorder** a step, or reach a "done" state without the
      prerequisite?
- [ ] **Idempotency:** repeat the same request 2x — double charge/double
      approval/duplicate row? (usually = logic flaw, sometimes = race)
- [ ] **Trust-the-blob:** anywhere an untrusted payload (proof, receipt,
      webhook, import, export) drives sums/state/signatures.
- [ ] Compare **browse vs export/render** paths for the same object (see
      `module-export-auth-bypass.md`) — the export path often skips the
      accounting/visibility checks.

---

## 4. PoC harness (read-only / controlled, authorized target only)

```bash
# 1. duplicate-row inflation (#3699522 pattern)
#    submit the same line item twice and observe the total vs distinct total
curl -s -X POST "https://TARGET/api/reserve" -d '{"rows":[{"id":"A","amt":100},{"id":"A","amt":100}]}'

# 2. binding test (#3700036 pattern)
#    obtain proof for object A, then ask to verify it against object B
#    -> if verifier returns ok/true using caller-supplied id, binding broken

# 3. state-transition skip
#    call the "finalize/approve" endpoint directly without the prerequisite step

# 4. idempotency
#    same purchase/create request sent twice -> 2 objects / 2 charges?
for i in 1 2; do curl -s -X POST "https://TARGET/api/order" -d '{"sku":"X","qty":1}' ; echo; done
```

**RoE:** use test accounts/own data only; controlled amounts; never
double-spend real funds or trigger real payments. Record baseline / expected
vs actual totals / negative control (a unique-only request should not
inflate).

---

## 5. Severity

- Proof-of-funds / accounting inflation (can falsify solvency or balances) →
  **High–Critical** (Monero rated High class; fintech contexts higher).
- Broken proof/receipt binding enabling forgery → **High**.
- Idempotency/duplicate that double-charges or double-credits → **High**
  (financial); duplicate row only → Medium.
- State-skip causing unauthorized state change → Medium–High.
- Cite: CWE-840, CWE-345, CWE-20; case studies #3699522, #3700036.