# P2 — Attack-Surface Mapping

## Objective

Map reachable surfaces with provenance and scope status while minimizing traffic and avoiding accidental expansion.

## Order of work

1. Review provided architecture, API specifications, repositories, SBOMs, and deployment notes.
2. Use public and passive sources permitted by the RoE.
3. Resolve every discovered asset against scope before interacting with it.
4. Perform low-noise active identification only in `ACTIVE_SAFE` or stronger mode.
5. Enrich each surface with protocol, authentication, actor, data class, state-change risk, and source.

## Map surfaces

Where relevant, inventory:

- DNS, certificates, hosts, ports, virtual hosts, redirects;
- browser routes, JavaScript chunks, source maps, manifests, service workers;
- REST, GraphQL, WebSocket, webhook, file, import/export, and callback surfaces;
- login, registration, recovery, invitation, SSO, linking, and session flows;
- admin, support, analytics, observability, health, and debug surfaces;
- mobile deep links, custom schemes, embedded endpoints, update channels;
- buckets, object URLs, queues, serverless functions, CI/CD artifacts;
- AI prompts, models, retrieval stores, tools, connectors, memory, and output sinks;
- wallet connections, signing messages, RPCs, indexers, relayers, paymasters, contracts, oracles, bridges;
- payment providers, ledgers, settlement, refunds, disputes, and reconciliation.

## Priority hunting

Cross-reference discovered surfaces against the **priority-1/2 checklist** in
`taxonomy-rating.md` (source: `vulnerability-rating-taxonomy.json`). Ensure each
high-value surface is assessed against at least the applicable critical/high
variants before the recon gate passes — e.g. IDOR (iterable IDs), exposed admin
portal, SSRF→internal secrets, secret on public asset, LFI, OAuth ATO, stored
XSS, password-reset token via host-header, marketplace price/fee manipulation.
Record which P1-P2 variants are reachable per surface in `surface-inventory.csv`.

## Provenance

Every row in `surface-inventory.csv` must record:

- source method and timestamp;
- parent asset;
- exact scope status;
- confidence;
- authentication requirement;
- state-changing capability;
- third-party ownership;
- next safe hypothesis.

Do not interact with `unknown` or `out_of_scope` surfaces. Keep them as leads for scope clarification.

## Secrets and sensitive discoveries

If exposed material appears:

1. Do not use it.
2. Capture only enough metadata to identify the issue.
3. Redact the value and hash it locally if a correlation marker is required.
4. Determine whether it is synthetic, public, revoked, or active only through approved non-use methods.
5. Trigger the stop and disclosure path for signing keys, production credentials, private data, or session material.

## Required artifacts

- `asset-inventory.csv` contains every authorized and discovered asset with scope status.
- `surface-inventory.csv` contains mapped interfaces and provenance.
- `session-log.md` records methods, versions, timing, rate limits, errors, and stop events.
- Every in-scope surface has at least one hypothesis or a reason it is not applicable.

## Gate

Pass when the surface inventory is sufficient to design systematic tests and unresolved assets are quarantined from interaction. Recon volume alone does not satisfy the gate.
