# Zero-Finding Persistence Protocol

Load this reference whenever an engagement is heading toward a **zero-finding
conclusion** — an empty `findings-index.csv` at P5, or the urge to declare
"nothing found" after a single automated pass. A clean scanner run is a data
point, never a conclusion.

## Hard requirements before declaring 0 findings

All of the following must be true and documented before a zero-finding report
is acceptable:

1. **Executed surface coverage** — every in-scope surface has at least one
   test row with status `confirmed`, `rejected`, or `inconclusive` (a
   `planned` row is not coverage).
2. **Playbook rotation** — for each surface class, at least **two different**
   attack playbooks were *executed* (tests actually run), not merely cited.
3. **Identity matrix** — where the target has authentication, hypotheses were
   tested from at least two contexts: unauthenticated and lowest-privilege
   authenticated user. Object-access classes additionally need a second
   tenant/account where the program allows test accounts.
4. **Content-discovery depth** — directory/endpoint discovery used more than
   one wordlist source, plus at least one non-bruteforce source (JS bundle
   parsing, archive/wayback URLs, param mining output).
5. **Re-entry second pass** — after the first full pass yields nothing
   confirmed, run a second pass with *different* mutation angles: state-machine
   sequences, parameter pollution, encoding/canonicalization variants, and
   race/timing windows on sensitive actions.
6. **Signal accounting** — every credible signal observed during recon
   (anomalous response, inconsistent error, unusual header, debug artifact)
   either has a dig-deeper chain hop or an explicit rejection reason in the
   hypothesis ledger. Silent drops are gate failures.
7. **Profile escalation** — passive → active-safe → scanner-safe were all
   exercised as far as the engagement's permission mode allows.

Document the outcome in `coverage-exhaustion.md` (engagement root): what was
tested, which avenues were blocked and why, and why each remaining hypothesis
closed. P5/P6 gates refuse a zero-finding advance without this file.

## Escalation ladder when stuck

Work down the ladder; each rung is a legitimate next move before concluding
anything:

1. Rotate wordlists (different sizes/sources) and re-run content discovery.
2. Change identity context — register a fresh account, use a different role,
   compare responses between two accounts.
3. Deep-parse JavaScript bundles (`jsluice`, linkfinder-style regexes) for
   hidden endpoints, API routes, and config artifacts.
4. Archive-based URL discovery (gau, wayback CDX) for endpoints live search
   misses.
5. Parameter mining (arjun, paramspider) on high-value endpoints.
6. State-machine testing — replay workflow steps out of order, skip steps,
   resubmit completed steps.
7. Race/timing probes on actions with side effects (redeem, transfer, vote,
   invite) within program rules.
8. Alternate surfaces — mobile APK endpoints, GraphQL introspection, staging
   hosts listed in scope, versioned API paths (`/api/v2`, `/api/internal`).
9. Business-logic review of money/quota/permission flows against the threat
   model's invariants.
10. Re-read the attack-playbook index and pick the highest-frequency entry
    point not yet executed for this stack.

## Anti-patterns that do NOT count as exhaustion

- "Nuclei found nothing" with no manual hypothesis testing behind it.
- One ffuf run with one small wordlist.
- Only unauthenticated testing on an application that has a login.
- Skipping GraphQL/API/mobile discovery because the main site looked simple.
- Concluding from a single nuclei pass on default templates only.
- Treating `blocked` statuses as done without trying the alternate route.
- Stopping at the first 403/401 instead of probing header/path/auth variants.

## Reporting a genuine zero

If all requirements above are met and the target is genuinely clean, say so
with the evidence: list executed tests, coverage percentages, blocked avenues,
and the exhaustion document. A defensible "we tried X, Y, Z across N surfaces
and M identities" is a valid result; "scanner came back empty" is not.
