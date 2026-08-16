# Bounded Dig-Deeper Chains and Pivot Ladders

## Goal

Add two evidence-driven exploration modes to Vulnhunter Superworkflow: Lazy
Load Version without turning normal reconnaissance into an unbounded loop or
silently expanding scope.

## Design

`dig-deeper-chain.csv` records a bounded investigation chain from an existing
test. Each row is one hop and must identify the test, hypothesis, question,
alternative explanation, disconfirming test, negative control, scope/impact,
uncertainty, evidence, status, and critical review. The default maximum depth
is three hops per `chain_id`. Each `next_test_id` must point to the following
row and the terminal row must be empty. Tests and initial hypotheses cannot be
reused in another chain ID to reset the bound; a new chain requires a
separately reviewed hypothesis.

`pivot-ladder.csv` records an authorized movement between two known assets.
Each hop identifies the source and destination asset, actor/identity alias,
authorization basis, precondition, action, expected control, evidence, status,
rollback, impact, and critical review. Both assets must be explicitly
`in_scope` and allowed by `engagement.json`; the linked test must target the
destination asset, and the source and destination must differ. Raw credentials
never belong in this ledger. The default maximum depth is three hops per
`ladder_id`.

Both ledgers are created for new engagements but are optional in execution.
P3 validates planned rows; P4 and P5 require finalized statuses, evidence for
confirmed hops, and review links. Empty ledgers add no work. Missing ledgers
remain compatible with old engagements until `gate_check.py --init` is run.

References are lazy: load the dig-deeper reference only when a credible signal
needs another controlled test; load the pivot reference only when an authorized
cross-asset path is being considered. A ledger is active only when it has at
least one validated row; at P4 load neither by default and load exactly one
ladder reference for the active ledger. `kill-chain` remains a P5 post-triage
composite-finding analysis and is not replaced by either ledger.

## Safety and token controls

- No hop authorizes traffic, privilege use, credential collection, or scope expansion.
- A missing control, evidence, review, or scope proof fails closed at P4/P5.
- A chain stops at the depth limit, on scope uncertainty, on instability, or
  when the next hop would only restate existing evidence.
- A chain cannot continue through a new chain ID or a cycle using the same test
  or initial hypothesis.
- Rollups include only populated rows and preserve per-engagement isolation.

## Acceptance criteria

- New engagement bootstrap creates both ledgers and documents them.
- P3 accepts a well-formed planned chain/ladder and rejects invalid references.
- P4 rejects over-depth, reset/cyclic, cross-scope, target-mismatched,
  incomplete, or unreviewed finalized hops.
- P5 applies the same controls without requiring unused ledgers.
- Router and skill docs describe conditional loading and distinguish both modes
  from `kill-chain`.
- Existing suite remains green plus focused regression coverage for both modes.
