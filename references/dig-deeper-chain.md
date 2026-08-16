# Dig-deeper chain

Load this reference only in P3–P4 when a credible signal needs one or more
controlled follow-up tests. Do not use it for every passive observation,
scanner alert, or tool output.

## Trigger

Start a chain when the signal suggests a violated invariant, an authorization
boundary, a meaningful data flow, or a repeated mismatch that one safe test
cannot explain. The first row must point to an existing `test-matrix.csv` test.

## Hop contract

For every hop in `dig-deeper-chain.csv`, write:

- the question and hypothesis being tested;
- the strongest benign alternative;
- the smallest disconfirming test and negative control;
- authorized scope/impact and uncertainty;
- the evidence IDs, test status, and critical-review ID.

Create the next test in `test-matrix.csv` before naming it in `next_test_id`.
Keep one new question per hop. The default maximum is three hops per
`chain_id`; each `next_test_id` must name the following row, and the terminal
row must be empty. A fourth hop is a gate failure, not an invitation to
continue. Do not reuse a test or initial hypothesis in another `chain_id` to
reset the bound; create a separately reviewed hypothesis instead.

## Stop conditions

Stop when the next hop repeats existing evidence, scope is unclear, the target
becomes unstable, the control is unavailable, or the depth limit is reached.
Use `blocked` or `inconclusive` with a concrete `stop_reason` when uncertainty
remains. A chain proposes controlled work; it never authorizes traffic or
stronger impact.

At P4, every finalized hop needs evidence when confirmed and a linked critical
review. Keep facts in the engagement rollup, not global memory or chat-only
state.
