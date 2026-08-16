# P4 — Controlled Validation

## Objective

Safely confirm or reject hypotheses with minimal, reproducible evidence.

> **Playbook re-check:** before each validation round, re-open the relevant
> `attack-playbooks/<class>.md` for the exact probe/bypass variant and the
> evidence/CVSS notes it lists. A playbook match is still a hypothesis — only
> the captured `EV-###` evidence confirms it.

## Validation sequence

For each `TST-###`:

1. Reconfirm scope, permission mode, account ownership, and current system health.
2. Capture a clean baseline.
3. Execute one planned mutation.
4. Capture the observable result.
5. Run the planned negative control.
6. Reproduce once more when safe and necessary.
7. Clean up created state.
8. Save redacted evidence, hash it, and add `EV-###`.
9. Update the hypothesis and test statuses.
10. Stop; do not expand beyond the evidence threshold.

## Evidence thresholds

Use the lowest tier sufficient for the claim:

| Tier | Proof | Typical use |
| --- | --- | --- |
| E0 | Static observation only | Exposed version, suspicious client code, theoretical concern |
| E1 | Behavioral difference without protected impact | Control mismatch, unexpected response, safe reflection |
| E2 | Researcher-owned cross-role or cross-account proof | Authorization, workflow, replay, tenant-isolation validation |
| E3 | Minimal protected-state proof under explicit permission | Canary read/write, controlled transaction, privileged action |
| E4 | Destructive, large-scale, real-user, real-fund, persistence, or service-impact proof | Do not perform unless separately and specifically authorized |

E0 is usually a lead, not a confirmed high-impact finding. E2 using two owned accounts is preferred for access-control claims. Stop before E4 by default.

## Safe proof patterns

- For unauthorized read: use a record created by a second researcher-owned account.
- For unauthorized write: modify a reversible canary field on an owned test record and restore it.
- For enumeration: show a small bounded sequence and response difference; do not harvest.
- For data exposure: record schema, count estimate, and one synthetic row where possible; do not bulk retrieve.
- For token issues: prove acceptance only against an owned identity and record exact validation failure.
- For code or command execution: use a harmless marker and environment-isolated proof; do not establish a shell, persistence, or lateral movement.
- For SSRF-like behavior: use a researcher-controlled callback and stop before internal metadata or credential access.
- For financial logic: use testnet, sandbox, fork, or minimal owned test funds and pre-agreed limits.
- For contract behavior: reproduce on a fork with pinned block and state before considering a live-chain proof.

## Contradictory results

When a reproduction fails:

1. Preserve both results.
2. Check actor, session, cache, race, region, build, state, and cleanup differences.
3. Reduce the claim to what remains observed.
4. Mark `inconclusive` if the causal condition is unknown.

Do not discard negative evidence.

## Required artifacts

- Every executed test has status and timestamp.
- Every confirmed test has at least one linked evidence ID.
- Evidence ledger contains provenance, path, SHA-256, sensitivity, and redaction status.
- Cleanup is documented.
- Candidate findings identify the broken invariant and exact demonstrated capability.

## Gate

Pass when every executed hypothesis is confirmed, rejected, blocked, or inconclusive with evidence and limitations. A screenshot without baseline, context, and provenance does not pass.
