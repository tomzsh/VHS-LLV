# VHS Critical Review Loop

## Goal

Add an evidence-backed anti-skip and anti-complacency checkpoint for P4/P5
without forcing repetitive reasoning into every reconnaissance step.

## Design

Create `critical-review.csv` as a per-engagement ledger. New engagements get
the ledger automatically; older engagements remain usable through P0–P3 and
receive an actionable P4 error until `gate_check.py --init` creates the new
header. The ledger records one bounded review per finalized test and a linked
review for each P5 finding.

Each review captures the claim, evidence references, alternative explanation,
disconfirming test, control result, scope/impact, uncertainty, decision,
reviewer, and timestamp. P4 validates required fields, test linkage, evidence
IDs, and decision/status consistency. P5 validates that every finding has a
`retain` review linked to a known finding. These are structural checks; human
judgment still determines whether the alternative and disconfirming test are
credible.

The lazy-loaded `references/critical-review-loop.md` explains the loop and its
bounded triggers. It is routed for P3–P5, but only P4/P5 enforce the ledger.
P0–P2 and ordinary tool output do not load or invoke it. The per-target rollup
includes reviews so resume never depends on global memory or chat history.

## Safety and compatibility

VHS authorization, scope, stop conditions, evidence rules, and phase authority
remain higher priority. A missing or malformed review fails closed at the
relevant gate; it never authorizes additional target traffic. No external
dependency or network access is introduced.
