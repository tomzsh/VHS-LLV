# Module — Web, API & Identity

Convert relevant checks into hypotheses tied to the target's actual actors, objects, and invariants.

## Identity lifecycle

Map and test:

- registration, verification, invitation, account linking, merge, and deletion;
- login identifiers, normalization, aliasing, and tenant discovery;
- password reset, magic link, OTP, MFA enrollment/recovery, passkeys;
- lockout, rate control, device trust, remembered sessions;
- email/phone change and recovery-channel replacement;
- support and admin impersonation or recovery flows.

Look for inconsistent enforcement across web, mobile, legacy, partner, and direct API clients.

## Sessions and tokens

Model:

- issuance, rotation, expiry, revocation, logout, and concurrent sessions;
- cookie flags, origin boundaries, CSRF, CORS, and browser storage;
- JWT/JWE algorithm, issuer, audience, subject, tenant, time, nonce, and key selection;
- refresh-token families, device binding, replay, and session fixation;
- service tokens versus user tokens;
- WebSocket or stream authorization after session changes.

Do not treat a decodable token or public signing key as a vulnerability.

## OAuth, OIDC, SAML, and federation

Verify:

- redirect URI matching and canonicalization;
- state, nonce, PKCE, response mode, and code binding;
- client, issuer, audience, tenant, and identity-provider binding;
- account linking and email-domain assumptions;
- relay state and destination handling;
- logout and token revocation;
- JWK/key rotation and trust-source selection.

Use researcher-owned identity providers or approved tenants. Do not target third-party users.

## Authorization and multi-tenancy

Build actor × action × object-owner tests for:

- direct object references;
- nested and bulk objects;
- exports, imports, reports, search, and analytics;
- comments, attachments, jobs, notifications, and audit logs;
- role changes, invitations, ownership transfer, and admin actions;
- soft-deleted, archived, shared, or moved resources;
- alternate IDs, filters, field selection, and method variants.

Confirm server-side policy using two owned accounts or tenants.

## API behavior

For REST, GraphQL, RPC, WebSocket, and webhooks, cover:

- method/content-type differences;
- schema validation and unknown fields;
- object and field-level authorization;
- pagination, filtering, sorting, and count leaks;
- batching, aliases, persisted queries, subscriptions;
- idempotency, retries, replay, and duplicate delivery;
- webhook authenticity, timestamp, replay, destination, and event ownership;
- versioned, legacy, mobile, internal, and partner routes.

Avoid broad introspection or enumeration when prohibited.

## Input and output boundaries

Where a real sink exists, test safely for:

- context-specific output encoding and stored rendering;
- structured query and command parameterization;
- template, expression, path, and filename handling;
- URL fetching and redirect validation;
- file type, parser, archive, metadata, and post-processing boundaries;
- request desynchronization or cache-key disagreement;
- cross-origin and cross-site browser behavior.

Use harmless canaries. Do not read system files, cloud metadata, credentials, or establish command shells.

## Business logic

Map:

- price, quantity, coupon, entitlement, limit, quota, and eligibility sources;
- approval, invitation, purchase, refund, cancellation, and settlement state;
- server-side recalculation versus client-supplied totals;
- stale quotes, replay, idempotency, race, and partial failure;
- admin/support actions and auditability.

Prefer sequential tests. Race amplification in production requires explicit authorization.

## Modern frontend

Inspect:

- route guards versus server authorization;
- source maps, build manifests, exposed configuration, and environment labels;
- service workers, caches, offline queues, and deep links;
- postMessage origin and message validation;
- DOM sinks and trusted-types boundaries;
- feature flags and alternate backends.

Public configuration values are not automatically secrets. Validate sensitivity and server-side effect.
