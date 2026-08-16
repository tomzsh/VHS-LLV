# P3 — Systematic Test Design

## Objective

Turn the attack-surface map into a risk-prioritized test matrix that is complete, safe, and traceable.

> **Playbook input:** before drafting mutations, open `attack-playbooks/00-index.md`
> and read the matching `attack-playbooks/<class>.md` for each surface. They supply
> the high-frequency entry points, probe payloads, and bypass matrices per
> vuln-class — turn those into concrete `TST-###` rows. Playbook content is a
> hypothesis source, never a confirmed finding.

## Build tests from invariants

For every in-scope surface:

1. Select the actor and prerequisite state.
2. Identify the intended invariant and enforcement point.
3. Establish the known-good baseline.
4. Choose one mutation:
   - identity or role;
   - tenant or owner;
   - object or action;
   - method or content type;
   - sequence, state, replay, or timing;
   - amount, asset, recipient, expiry, or network;
   - audience, issuer, redirect, or token binding;
   - trusted source versus client-controlled value.
5. Define expected secure behavior.
6. Define the smallest observable that would disprove it.
7. Define negative control, cleanup, request limit, and stop condition.
8. Link a `TST-###` row to `HYP-###`.

## Prioritization

Score qualitatively:

- reachability;
- privilege delta;
- sensitive asset value;
- cross-tenant or cross-account boundary;
- financial or irreversible effect;
- exploit prerequisites;
- production risk of the test;
- remediation leverage;
- evidence cost.

Run high-signal, low-impact tests first. Do not front-load dangerous tests merely because their hypothetical severity is high.

## State-machine coverage

For workflows such as recovery, invitation, checkout, withdrawal, bridging, approval, upload processing, or agent actions, cover:

- valid transition;
- skipped step;
- repeated step;
- reordered step;
- stale state;
- parallel requests;
- cancellation and rollback;
- cross-account continuation;
- server/client disagreement;
- retry and idempotency.

Design concurrency tests locally or in staging first. Production race amplification needs explicit authorization.

## Differential testing

Prefer comparisons that isolate policy failures:

- same request, different owned account;
- same account, different role;
- same object, different tenant;
- same token, changed audience;
- same quote, changed recipient or amount;
- same prompt, different tool permission;
- same transaction, changed network or nonce.

## Required artifacts

`test-matrix.csv` must include:

- unique test ID;
- linked hypothesis ID;
- asset and surface ID;
- baseline;
- single mutation;
- expected result;
- evidence plan;
- negative control;
- cleanup;
- risk level;
- permission mode;
- status.

Every in-scope surface must map to a test or explicit not-applicable/blocked reason.

## Gate

Pass when the matrix can be executed without improvising scope, identity, impact proof, cleanup, or stop conditions.
