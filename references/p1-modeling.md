# P1 — Scope & Threat Model

## Objective

Translate the authorized target into assets, actors, trust boundaries, data flows, invariants, and testable hypotheses.

## Model the system

Capture:

- asset, environment, owner, technology, exposure, and scope status;
- user, support, admin, service, partner, vendor, wallet, contract, and automation actors;
- authentication, authorization, session, signing, payment, deployment, and recovery flows;
- sensitive data, secrets, tokens, funds, permissions, and business-critical state;
- browser/server, tenant/tenant, service/service, off-chain/on-chain, and human/automation trust boundaries;
- authoritative source of truth and reconciliation paths;
- privileged operations and irreversible actions.

## Define security invariants

Write each invariant as a falsifiable statement, for example:

- A user can read only records belonging to an authorized tenant.
- A password reset token is single-use, short-lived, and bound to one account.
- A quote cannot be executed after its asset, amount, recipient, or expiry changes.
- An agent tool call cannot exceed the requesting user's permissions.
- A ledger mutation preserves double-entry balance and idempotency.

Avoid generic labels such as “test IDOR.” State actor, object, action, expected policy, and boundary.

## Map invariants to the rating taxonomy

Load `taxonomy-rating.md` (source: `vulnerability-rating-taxonomy.json`) and map
the target's architecture to the applicable taxonomy **categories** and
**subcategories** before writing invariants. The taxonomy's priority-1/2
variants are the highest-value invariants to hunt (see the priority hunting
checklist in `taxonomy-rating.md`). Each invariant should name the taxonomy
category/subcategory it protects so the eventual severity rating has a baseline.

## Build hypotheses

For each high-value invariant, create `HYP-###` with:

- asset and surface;
- actor and prerequisite;
- expected control;
- one-variable mutation;
- observable success/failure signal;
- safest validation method;
- likely impact if confirmed;
- current state and priority.

Prioritize by reachable trust boundary, asset value, privilege delta, irreversibility, and evidence cost.

## Coverage model

Create at least these matrices where relevant:

- actor × action;
- role × object owner;
- endpoint × HTTP method;
- state × transition;
- token × audience/issuer/tenant;
- client input × server-side authoritative value;
- off-chain event × on-chain effect;
- agent/tool × permission/context source.

## Required artifacts

- At least one in-scope row in `asset-inventory.csv`.
- At least one meaningful row in `hypothesis-ledger.csv`.
- Trust-boundary and data-flow notes in `threat-model.md`.
- Scope limitations and excluded dependencies recorded explicitly.

## Gate

Pass when the agent can answer:

1. What are the highest-value invariants?
2. Which actors and trust boundaries can reach them?
3. What evidence would confirm or reject each hypothesis?
4. Which actions remain prohibited?

Do not advance with only a tool list or vulnerability taxonomy.
