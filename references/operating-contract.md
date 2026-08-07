# Operating Contract

This contract applies in every phase.

## 1. Authorization is a technical prerequisite

Treat authorization as data, not an assumption. Record:

- owner or program;
- authoritative scope source;
- allowed and excluded assets;
- allowed test classes;
- prohibited actions;
- approved accounts, identities, wallets, and funding;
- test window and timezone;
- rate or concurrency limits;
- data handling and retention rules;
- emergency contact and disclosure channel.

If any item materially changes what may be tested, remain in `PLAN_ONLY` until it is resolved.

## 2. Evidence before conclusions

Keep three layers distinct:

1. **Observation:** directly captured behavior.
2. **Inference:** interpretation supported by observations.
3. **Assumption:** plausible but unverified condition.

Never write an assumption as observed fact. Confidence does not replace evidence.

## 3. Minimal impact

Use the smallest action that answers the security question:

- synthetic data instead of real records;
- two researcher-owned accounts instead of another person's account;
- metadata and counts instead of bulk downloads;
- read-only queries before writes;
- reversible writes with canary values and cleanup;
- testnet, staging, fork, or local reproduction before production;
- one controlled request before concurrency.

Do not improve a proof by increasing harm.

## 4. No hidden expansion

Do not silently:

- follow redirects or discovered hosts outside scope;
- test vendors merely because they are integrated;
- reuse leaked credentials;
- access unrelated tenants or users;
- pivot from an application finding into infrastructure;
- turn a read proof into a write proof;
- turn a write proof into persistence or destructive impact.

Create a new authorization question whenever the action class changes.

## 5. Reproducible state

Record before each meaningful action:

- time in UTC;
- phase;
- asset and endpoint/component;
- actor and account role;
- environment/build/version when known;
- hypothesis ID and test ID;
- expected behavior;
- allowed action class.

Record after:

- actual behavior;
- response or transaction identifier;
- evidence ID and hash;
- cleanup;
- uncertainty and next safe step.

## 6. Safe handling

- Store secrets only in an approved secret manager or ephemeral environment variable, never in prompts, reports, source files, or command history.
- Redact authorization headers, cookies, API keys, wallet secrets, seed phrases, PII, financial records, and private communications.
- Keep raw evidence access-controlled and retain it only as long as permitted.
- Do not submit real secrets to third-party scanners, paste sites, or public malware services.
- Avoid terminal commands that print entire environments, credential files, keychains, or browser profiles.

## 7. Tool discipline

- Prefer primary documentation and directly observed behavior.
- Pin the target and protocol explicitly; avoid broad wildcards.
- Start passive and low-noise.
- Rate-limit and serialize state-changing tests unless RoE says otherwise.
- Treat automated scanner output as hypotheses.
- Log tool version and configuration relevant to reproducibility.
- Do not use stealth, evasion, persistence, or anti-forensics.

## 8. Honest stopping

Mark a test `blocked` or `inconclusive` when evidence is insufficient. Do not compensate with stronger claims.

Stop on scope doubt, instability, third-party impact, sensitive data exposure, real-fund risk, or any hard-stop condition from `SKILL.md`. Preserve minimum evidence and use the approved contact.

## 9. Human control points

Obtain explicit approval before:

- any production state change not already covered by RoE;
- testing denial of service, race amplification, resource exhaustion, or mass enumeration;
- interacting with real funds, real users, regulated data, or external providers;
- social engineering, physical testing, credential attacks, or phishing;
- publishing details or sharing evidence outside the approved recipients.

## 10. Output integrity

The final assessment must be auditable:

```text
scope -> asset -> surface -> invariant -> hypothesis -> test -> evidence -> finding -> remediation -> retest
```

Every broken link is either fixed or documented as a limitation.

## 11. Real-account and secondary-surface discipline (hard rule)

- **Primary product endpoints** may use the operator's real account only after the operator explicitly approves that exact auth flow.
- **Secondary / auxiliary surfaces** — MCP servers, support/internal dashboards, staging/uat, third-party auth providers, sandboxes where the operator has no account — MUST use a **disposable identity** (AgentMail inbox, dedicated throwaway account, or a researcher-created test account). NEVER the operator's real verified account.
- Triggering an OTP / login / verification email to the operator's real inbox for such a surface is prohibited without prior explicit confirmation. A "spare" event like an OTP is still a real event on a real account and is not how we test.
- Before any auth-triggering request, ask: "does this use the operator's real identity, where, and did they approve it?" If not explicitly approved, use disposable.
