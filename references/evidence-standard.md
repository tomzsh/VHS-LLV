# Evidence & PoC Standard

## Evidence record

Assign `EV-###` and record:

- UTC capture time;
- linked hypothesis, test, and finding IDs;
- asset, endpoint/component, environment, build/version;
- actor, role, and account alias;
- collection method and tool version;
- relative file path;
- SHA-256;
- sensitivity;
- redaction status;
- short observation;
- cleanup or revocation state.

## Good evidence set

A compact evidence set normally contains:

1. baseline;
2. mutated request or action;
3. actual result;
4. negative control;
5. second reproduction when safe;
6. cleanup confirmation.

Use structured text over screenshots when it preserves meaning. Use screenshots for visual state, not as a substitute for raw metadata.

## PoC construction

Write PoCs for reproducibility and safety:

- list prerequisites and owned test identities;
- pin host, route, method, protocol, network, and version;
- use placeholders for secrets;
- use synthetic identifiers and canary data;
- show only necessary headers and fields;
- include expected secure behavior;
- include actual behavior;
- include cleanup;
- state limits and prohibited expansion.

Do not embed:

- live bearer tokens, cookies, API keys, wallet keys, seed phrases;
- reusable signed URLs;
- real-user IDs, PII, or unrelated response data;
- bulk export logic;
- persistence, stealth, evasion, or destructive follow-up.

## Evidence hashing

Hash local files without printing their content:

```bash
sha256sum <evidence-file>
```

Preserve originals and create redacted copies for sharing. Do not overwrite raw evidence with the redacted version.

Each `EV-###` id must be **unique** within the engagement. `evidence_capture.py`
rejects a duplicate id before writing, so a ledger row is never silently
overwritten and no orphan raw file is left behind. Raw and redacted files are
written with `0600` permissions inside the `0700`, git-ignored `evidence/`
tree — never relax these on shared hosts.

## Claim calibration

Use these labels:

- `confirmed`: repeated or logically complete evidence supports the exact claim;
- `likely`: strong evidence but one condition remains unverified;
- `inconclusive`: behavior observed but cause or impact is not established;
- `rejected`: secure behavior or a false assumption was demonstrated;
- `blocked`: scope, access, instability, or safety prevented validation.

Examples:

- An exposed identifier is not automatically sensitive data.
- A client-side admin route is not authorization bypass without server acceptance.
- A token decoded locally is not a token-validation flaw.
- A callback is not internal network access unless destination control is proven.
- A simulated transaction is not fund movement.
- A public key or OAuth client ID is not a secret by itself.

## Chain evidence

Number chain links and attach evidence per link:

```text
L1 observation -> EV-001
L2 privilege primitive -> EV-004
L3 protected action -> EV-007
```

If L2 is only assumed, the chain's demonstrated impact stops at L1.

## Redaction review

Use consistent aliases:

- `USER_A`, `USER_B`;
- `TENANT_A`, `TENANT_B`;
- `WALLET_TEST_A`;
- `TOKEN_REDACTED`;
- `OBJECT_CANARY_001`.

Preserve enough stable structure for reviewers to correlate requests without revealing values.
