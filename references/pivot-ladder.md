# Pivot ladder

Load this reference only in P4–P5 when a confirmed or high-confidence path
could cross from one authorized asset to another. Do not load it for ordinary
reconnaissance or treat it as permission to discover new scope.

## Authorization before movement

Both `from_asset_id` and `to_asset_id` must already exist in
`asset-inventory.csv` with `scope_status=in_scope`. Record the authorization
basis, approved test identity alias, precondition, expected control, rollback,
and bounded impact in `pivot-ladder.csv`. The inventory hostnames must also
match `engagement.json` `allowed_assets`, and the linked test's `asset_id` must
equal `to_asset_id`. Never store raw cookies, tokens, passwords, private keys,
or other credentials in the ledger.

## Hop contract

Each hop points to one `test-matrix.csv` test and one `critical-review.csv`
review. Use the smallest safe action that can distinguish “the boundary holds”
from “the boundary failed.” Capture only necessary redacted evidence. The
default maximum is three hops per `ladder_id`; every hop must move between
distinct known assets.

## Stop conditions

Stop immediately on scope ambiguity, unexpected privilege, sensitive data,
third-party impact, instability, missing rollback, or a failed control that
already answers the question. Mark the hop `blocked` or `inconclusive` and
write a concrete `stop_reason`. A pivot ladder is a planning and evidence
structure, not an autonomous pivot engine.

P4/P5 gates fail closed when a hop lacks scope proof, evidence, rollback, or a
critical review. `kill-chain` remains the separate P5 analysis of composite
findings after triage.
