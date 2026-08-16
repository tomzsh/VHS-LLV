# Critical review loop

Load this reference only during P3–P5 when a hypothesis is being promoted to a
controlled test, a test result is being interpreted, or a finding is being
triaged. Do not run this loop for every passive observation or tool invocation.

## One bounded pass

Record these fields in `critical-review.csv`:

1. **Claim** — what the result appears to demonstrate.
2. **Evidence** — exact evidence IDs and provenance.
3. **Alternative explanation** — the strongest benign or unrelated cause.
4. **Disconfirming test** — the smallest safe test that could refute the claim.
5. **Negative/expected control** — what the control did and why it matters.
6. **Scope and impact** — authorized asset, actor, prerequisite, and demonstrated
   consequence.
7. **Uncertainty and decision** — what remains unknown and whether to retain,
   reject, block, mark inconclusive, or mark not applicable.

P3 uses the loop to sharpen hypotheses and test design. P4 requires one review
for every finalized test. P5 requires every finding to link to a `retain`
review. The gate checks structure and links; human judgment must still decide
whether the alternative and disconfirming test are credible.

Use a second pass only when evidence conflicts, the result is high/critical
impact, or the first pass leaves material uncertainty. Update the same review
row; the active ledger keeps one review per test. Never repeat the loop merely
to produce more prose.

## Anti-skip rules

- A scanner result remains a hypothesis until P4 controls and evidence support
  it.
- Missing review fields fail the relevant gate; they do not authorize extra
  target traffic or stronger claims.
- A weak alternative, absent negative control, or speculative impact belongs in
  `inconclusive` or `blocked` until resolved.
- Target facts stay in the engagement directory and its rollup, never global
  memory or chat-only state.
