# Object-Level Authorization Bypass on Export / File-Materialization Paths

> Export, download, and report-render endpoints that **materialize an object
> (PDF, CSV, ZIP, attachment, transcript) into a file** frequently skip the
> per-object authorization check that the *view* path applies. The object is
> the same, but the code path is different — and authorization was bolted onto
> the view, not onto the object. Use at **P3/P4**. Taxonomy: CWE-639 /
> CWE-284 / OWASP API1:2023 (BOLA). Companion: `module-unauth-idor-file-access.md`.

---

## 1. Why this class exists

Normal browse path: `GET /reports/{id}` → middleware checks "can this actor
read this object?" → renders view.

Export path: `POST /reports/{id}/export` (or `exportReportPdf`) → template
assembles **the same timeline/fields** from the underlying data **without
re-running the per-activity visibility check** → PDF/CSV/ZIP generated.

Because the check lives in the view layer, every **second materializer** that
skips it is a fresh bug — even when the primary view is solid. This is the
classic "authorization on the object, not the path" failure.

Detection keywords: `export`, `download`, `render`, `generate`, `pdf`, `csv`,
`zip`, `print`, `report`, `statement`, `invoice`, `transcript`, `receipt`,
`backup`, `archive`, `bundle`.

---

## 2. Proven case studies (real, disclosed 2026)

### 2.1 HackerOne — #3577216 · `exportReportPdf` shows internal Activity (bounty paid)
- **When:** submitted 2026-02-27 · disclosed 2026-03 · severity **High (8.2)**
  (downgraded from Critical 9.3) · **bounty rewarded**
- **Root cause (verbatim summary):** the PDF export pipeline "did not apply
  the same visibility and authorization scoping that governs the normal report
  view… generated PDF could include timeline content beyond what the requester
  was authorized to see, such as **internal team activity, triage guidance,
  and internal fields**, and reports at a limited disclosure level could be
  rendered as if fully disclosed."
- **Fix:** enforce the same per-activity visibility checks and disclosure-level
  scoping **along the export path**.
- **Lesson:** even the platform's own report-export endpoint had this bug —
  *any* object with a render/export path is in scope.
- **Link:** `https://hackerone.com/reports/3577216`

### 2.2 Liberapay — #3878586 · unauthenticated export leaks donor privacy (see IDOR ref §3.2)
- The `income/payments.spt` **export/listing path** applied only a frozen
  `visibility` flag, omitting the live permission gates used everywhere else.
- Pattern identical: **materializer path ≠ view path** → leak.
- **Link:** `https://hackerone.com/reports/3878586`

---

## 3. Detection checklist (P2/P3)

- [ ] Enumerate every endpoint that **produces a file**: grep routes for
      `export|download|pdf|csv|zip|report|invoice|statement|transcript`
      (REST) and mutations `*Pdf*|*Export*|*Download*` (GraphQL).
- [ ] For each, compare the authorization applied vs the **view** endpoint of
      the same object:
      - same actor → same object → same fields? (should be identical)
      - does the export re-check **per-field / per-activity** visibility, or
        only a coarse "can view at all"?
- [ ] Test **limited-disclosure objects**: an object the caller may see *in
      part* — does export render the *full* object (internal fields, triage
      notes, hidden donors, internal activity)?
- [ ] Test **no-auth**: is the export reachable without a session at all?
- [ ] Test **cross-object**: swap the id — does export honor the same 404/403
      as view, or materialize a file for an object you shouldn't read?
- [ ] Test **stale flag**: does export read a **snapshot permission flag**
      (e.g. `visibility` stored at creation) instead of the **current**
      permission? (#3878586 pattern)

---

## 4. PoC harness (read-only, authorized target only)

```bash
# 1) baseline — view path (expected: scoped)
curl -s -o view.json -w "%{http_code}\n" "https://TARGET/api/reports/OWN_ID"

# 2) export path — same object
curl -s -o export.pdf -w "%{http_code}\n" \
  -X POST "https://TARGET/api/reports/OWN_ID/export"
#   ^ compare content vs view.json: fields present in export but not in view?

# 3) limited-disclosure object (if applicable) — does export show more than view?
curl -s -o lim.pdf -w "%{http_code}\n" \
  -X POST "https://TARGET/api/reports/PARTIALLY_VISIBLE_ID/export"

# 4) cross-object / unauth — object you may not read
curl -s -o other.pdf -w "%{http_code}\n" \
  -X POST "https://TARGET/api/reports/OTHER_USER_ID/export"
```

Evidence to capture: side-by-side **view vs export** content diff, the object
id used, session state (auth/unauth), and which internal fields leaked.

---

## 5. Severity

- Internal/triage/internal-activity leak via export → **Medium–High** (info
  disclosure through authorization gap; H1 rated #3577216 High 8.2).
- Export materializes **another user's** object (cross-object) → **High**.
- Unauthenticated export of PII/payment data → **High–Critical**.
- Report with `export` + `pdf` + visibility-scope mismatch, cite #3577216.
