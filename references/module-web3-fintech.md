# Module — Web3 & Fintech

Prioritize fund safety, signing intent, ledger integrity, reconciliation, and irreversible state. Default to testnet, sandbox, local fork, or minimal pre-approved owned funds.

## Wallet authentication and signing

Map:

- wallet connection and account/network changes;
- challenge creation, domain, URI, chain, nonce, issue/expiry time;
- signature verification, replay, and session binding;
- wallet-to-profile linking, unlinking, recovery, and merge;
- human-readable intent versus encoded payload;
- typed-data domain separator and verifying contract;
- transaction simulation and final submitted transaction.

Verify that a signature for one domain, chain, wallet, nonce, action, or session cannot authorize another. Do not request or store seed phrases or private keys.

## Relayers, paymasters, and gasless flows

Model:

- user operation or meta-transaction construction;
- signer, nonce, deadline, chain, target, selector, value, and calldata binding;
- sponsorship policy and quotas;
- replay and idempotency;
- bundler/relayer trust and failure handling;
- simulation versus execution;
- webhook/indexer confirmation.

Use bounded test operations. Do not consume material sponsor funds or relay harmful calls.

## Smart contracts and protocols

For in-scope code and deployed addresses, model:

- roles, ownership, upgradeability, initialization, pausing, and emergency controls;
- external calls, callbacks, reentrancy boundaries, and state ordering;
- accounting, shares, rounding, decimals, fees, and invariant preservation;
- approvals, permits, signatures, nonces, and replay;
- oracle source, freshness, decimals, manipulation resistance, and fallback;
- liquidation, collateral, slippage, deadlines, and minimum outputs;
- bridge message origin, destination, replay, finality, and failure recovery;
- governance proposal, voting, quorum, execution, and timelock;
- token behavior differences and integration assumptions.

Reproduce suspicious state transitions on a fork pinned to a block. Never deploy an exploit or move third-party funds to prove impact.

## Off-chain/on-chain consistency

Trace:

```text
request -> quote -> authorization -> submission -> chain event -> indexer -> ledger/UI -> settlement
```

Create hypotheses around:

- stale or reused quote;
- client-modified amount, asset, recipient, route, or fee;
- chain/network mismatch;
- event spoofing or insufficient confirmation;
- reorg and duplicate processing;
- indexer lag or missed event;
- off-chain credit before finality;
- refund, cancellation, and partial failure.

## Fintech ledger and payments

Map:

- available, pending, held, settled, and reversed balances;
- double-entry postings and authoritative balance;
- deposit, withdrawal, transfer, card, refund, dispute, and fee state machines;
- idempotency keys, retry, webhook, settlement, and reconciliation;
- currency, decimals, rounding, exchange rate, and limit enforcement;
- beneficiary, bank account, address, and device changes;
- KYC/KYB, sanctions, risk, support, and manual review controls.

Use synthetic accounts and sandbox providers. Never induce real chargebacks, launder value, bypass compliance on real identities, or test stolen payment instruments.

## Admin, support, and operational risk

Review:

- manual balance adjustments;
- withdrawal holds and overrides;
- KYC decisions and document access;
- wallet/address allowlists;
- treasury and signer permissions;
- audit logs and dual control;
- webhook replay and operational tooling.

Prove privilege boundaries with owned test users and approved roles.

## Severity discipline

Separate:

- simulated from executed transactions;
- testnet from mainnet;
- displayed balance from authoritative ledger;
- approval from transfer;
- public address from private credential;
- theoretical contract path from reachable state;
- recoverable accounting mismatch from irreversible loss.

Fund-loss claims require a complete, evidenced path with all prerequisites. Stop before real-user or real-fund harm.
