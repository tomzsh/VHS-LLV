# P6 — Report, Disclosure & Retest

## Objective

Deliver a concise, reproducible, safely redacted report and maintain a verifiable remediation/retest record.

## Report assembly

Use `reporting-templates.md`. Include:

- executive summary;
- authorization, scope, dates, environment, accounts/roles, and limitations;
- methodology mapped to P0–P6;
- attack-surface coverage and exclusions;
- finding summary table;
- one section per finding;
- positive security observations when useful;
- systemic remediation priorities;
- disclosure timeline;
- evidence inventory;
- retest criteria and status.

## Office deliverables (officecli)

When the program or reviewer wants Office-format files (`.docx` final report,
`.xlsx` findings/evidence summary, `.pptx` briefing), generate them from the
**redacted** ledgers with `officecli` — see `officecli-reporting.md` for the
exact commands (create, headings, tables, CSV→xlsx, batch, pitfalls). Keep the
markdown `final-report.md` as the canonical report; Office files are derived
deliverables. Never build Office files from `evidence/raw/`.

## Finding QA

For each finding, verify:

- title describes the broken control and impact;
- prerequisites appear before steps;
- steps use owned/synthetic data;
- expected and actual behavior are distinct;
- IDs, roles, tenants, timestamps, and versions are internally consistent;
- the PoC stops at minimum proof;
- impact matches evidence;
- remediation covers the root cause;
- logs/screenshots are redacted and linked by evidence ID;
- cleanup and residual risk are documented.

## Redaction

Run:

```bash
python3 <skill-dir>/scripts/redact_scan.py <engagement-dir>/final-report.md
```

Manually inspect for:

- credentials, tokens, cookies, private keys, seed phrases;
- PII, financial data, private messages, and customer identifiers;
- internal hostnames, source paths, or employee details not needed for remediation;
- unredacted request/response bodies;
- signed URLs and reusable links.

Treat the scanner as a warning system, not proof of safety.

## Disclosure

- Use the approved channel and recipients.
- Send only the detail needed for triage.
- Keep raw evidence private unless requested through an approved secure channel.
- Respect embargo, coordinated disclosure, and program rules.
- Record acknowledgments, status changes, requests, and dates.
- Do not publicly disclose without authorization or an agreed policy basis.

## Retest

For each fix:

1. Record the version, deployment, date, and remediation claim.
2. Re-run the original baseline and minimal PoC.
3. Run the negative control.
4. Test closely related variants sharing the root cause.
5. Verify server-side enforcement, not only UI changes.
6. Check for bypass through alternate methods, encodings, clients, or state transitions when safely in scope.
7. Mark `fixed`, `partially_fixed`, `not_fixed`, `regressed`, or `unable_to_verify`.
8. Record new evidence IDs and residual risk.

Do not expand retest into a new assessment without authorization.

## Gate

Pass when the report is consistent, reproducible, redacted, delivered through the approved channel, and disclosure/retest state is recorded. If the engagement ends before remediation, mark retest as pending rather than complete.
