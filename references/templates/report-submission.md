# Report Submission Template — HackerOne / Bugcrowd (三段式提交模板)

> The file `00-index.md` (line 64) references this path as the three-part
> submission template. It is the **platform submission** format (title /
> summary / reproduction), distinct from the internal `../reporting-templates.md`
> (full assessment + evidence ledger). Keep the submission tight: triagers read
> the first screen. Pair with `../non-qualifying.md` before submitting.
>
> Reference: `00-index.md — templates/report-submission.md → H1/Bugcrowd 三段式提交模板`

---

## Part 1 — Title (one line, <100 chars)

Format: `[<Impact verb>] <control gap> on <surface> <conditions>`.

Examples:
- `[IDOR] Unauthenticated file download of any user's invoice on /api/files/{id}`
- `[LFI] Unauthenticated path traversal reads arbitrary files via /custom-sounds/`

Rule: name the **broken invariant**, not the payload. Avoid vendor jargon; use
the program's severity vocabulary if defined.

---

## Part 2 — Summary (2–4 sentences)

```
An <actor> can <capability> on <asset> because <root-cause one-liner>.
No <prerequisite> is required / Requires <minimal prerequisite>.
The demonstrated impact is <exact impact>.
```

Keep it gated: who (actor + auth state) → what (exact capability) → why
(root cause) → so-what (impact, unchanged). No inference inflation.

---

## Part 3 — Steps to reproduce (numbered, minimal, negative control)

```markdown
### Steps to reproduce
1. <Create/identify owned canary state> (e.g. your own file id F-123).
2. <Capture baseline> — GET /api/v1/files/OWN returns 200.
3. <Perform one mutation> — GET /api/v1/files/<OTHER_USER_ID> without a session.
4. <Observe> — returns 200 and the object's bytes/blob.
5. <Negative control> — a valid scope-negative id returns 403/404 (proves the
   endpoint exists but the owner check is missing, not a generic 200).

### Impact
<Exact evidenced impact> — describe the minimal proof you demonstrated.
<Assumptions / conditional impact> — clearly labeled, not asserted.

### Notes
- Severity: <rating> (see vulnerability-rating-taxonomy.json / CVSS 3.1).
- CWE: <e.g. CWE-639>.
- Remediation: <one-line root-cause fix>.
```

**Submission rules (authorized testing only):**
- Use only **owned/canary** data; never include other users' real PII.
- One issue per submission; no wall of text.
- Include the negative control — it distinguishes a missing check from an
  arbitrary 200.
- Reference evidence ids from the engagement ledger (`evidence-ledger.csv`)
  so you can attach full evidence asynchronously.