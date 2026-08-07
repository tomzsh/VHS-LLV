# P0 — Authorization & Safety

## Objective

Establish what may be tested, by whom, when, how, and with what stop conditions. Do not send active traffic before this gate passes.

## Checklist

1. Identify the owner, program, or contracting party.
2. Capture the authoritative scope URL, statement of work, or written approval.
3. Normalize explicit inclusions and exclusions:
   - domains, subdomains, IP ranges;
   - apps, APIs, repositories, packages;
   - cloud accounts and regions;
   - mobile bundle IDs;
   - contracts, chains, testnets, addresses;
   - vendors and third-party services.
4. Record the test window, timezone, maintenance windows, and emergency contact.
5. Record allowed and prohibited techniques, including automation, concurrency, account creation, state changes, uploads, transactions, and disclosure.
6. Record provided test identities and prove they belong to the researcher or engagement.
7. Define data minimization, storage, encryption, sharing, and retention.
8. Convert restrictions into machine-checkable notes in `engagement.json`.
9. Select permission mode: `PLAN_ONLY`, `PASSIVE`, `ACTIVE_SAFE`, or `CONTROLLED_IMPACT`.
10. Write stop conditions specific to the target.

## Ambiguity resolution

Use the narrower interpretation when:

- a wildcard could include acquired, parked, vendor, or customer-controlled assets;
- a mobile application uses third-party APIs;
- a contract is in scope but the frontend or oracle is not;
- a repository is public but deployment infrastructure is not;
- a program lists a domain but excludes disruption or automated testing.

Ask one focused question that names the action blocked by the ambiguity.

## Required artifacts

- `engagement.json` with:
  - `authorization_status` set to `confirmed`;
  - non-placeholder `owner`, `scope_source`, `testing_window`, `emergency_contact`;
  - at least one `allowed_asset`;
  - `permission_mode`;
  - `data_handling`;
  - target-specific `stop_conditions`.
- Initial `session-log.md` entry.

## Gate

Pass only when the authorization record supports the next phase. P0 does not establish vulnerability impact; it establishes safe operating boundaries.

Remain in P0 or `PLAN_ONLY` if authorization is missing, expired, conflicting, or only implied by public accessibility.
