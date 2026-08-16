# Unauthenticated IDOR — Access to Arbitrary User Files

> Object-level access control flaw where an **unauthenticated** (or cross-user)
> request reaches a file/object it must not read, because the authorization gate
> is missing, bypassed, or replaced by a frozen/legacy permission check. Use at
> **P3 (test design)** to build the matrix and **P4 (validation)** to prove it.
> Severity baseline: see `taxonomy-rating.md` (Access Control / IDOR family).

---

## 1. Taxonomy & canonical references (accurate, proven)

| Source | What it establishes |
|---|---|
| **CWE-639 — Authorization Bypass Through User-Controlled Key** | *"The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data."* Base weakness; root mapping for the class. |
| **PortSwigger — Insecure Direct Object References (IDOR)** | Official definition + two canonical examples: **direct reference to DB objects** (`/customer_account?customer_number=132355`) and **direct reference to static files** (`/static/12144.txt` — attacker mutates filename to read another user's file/credentials). |
| **OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization (BOLA)** | Object-level authorization must be enforced per-user on every object access, not only on the "main" resource. |
| **OWASP API Security — API5:2023** | Broken Function Level Authorization (adjacent: missing auth on the endpoint itself). |
| **CWE-284** Improper Access Control | Parent class for object/function-level gaps. |

The CWE-639 extended description is the precise capture of an unauth-IDOR:
**the key is user-controlled, the data-access is keyed on it, and the only
authorization in the path is the lookup key itself** — hence *nothing else*
stops a request that does not carry a valid session for the owning user.

---

## 2. Detection — when to suspect it (P2/P3 checklist)

Approach each **file/object read endpoint** (document, export, transcript,
attachment, report PDF, uploaded asset, static served file) with:

- [ ] Is the endpoint reachable **without any session/cookie** (unauth) but
      still returns 200+object content?
- [ ] Is the **object id / file path / filename** in a GET/POST parameter,
      route segment, or static path?
  - `GET /api/files/{id}` · `GET /download?doc=...` · `/static/12145.txt`
- [ ] Is enforcement **only** the id/path itself (no per-object owner check)?
- [ ] Is a surrogate/permission flag used instead of the real owner check?
      (e.g. only `visibility = 3` frozen flag, ignoring the user's live
      `hide_*` / opt-out gates → **the #3878586 pattern**)
- [ ] Is the redirect/export**PDF extended .spt / export / /income endpoint unauthenticated
      and keyed only by a public username/team path?
- [ ] Does the request work with **one object id from your account**, and still
      return a valid object when swapped to **another user's id**?

Highest-value: endpoints that materialize a real file (PDF export, attachment,
transcript, report) — impact = disclosure of PII, documents, credentials, or
payment records.

---

## 3. Proven case studies (real, disclosed 2026)

### 3.1 Rocket.Chat — #3514640 · Unauthenticated Path Traversal (LFI) reading arbitrary files
- **When:** reported 2026-01-17 · disclosed 2026-08-03 · status **Resolved**
- **Severity:** High (CVSS 7.5) · CVE-2026-56845
- **Class:** IDOR-in-the-path / object-level LFI
- **Vector:** `GET /custom-sounds/{name}` when CustomSounds storage is
  `FileSystem` — including `../` sequences reads files **outside** the base dir,
  **unauthenticated**. Arbitrary file disclosure from user-controlled path.
- **Remediation:** canonicalize the path and confine reads to the storage dir;
  never trust the filename segment as a real path.
- **Link:** `https://hackerone.com/reports/3514640`

### 3.2 Liberapay — #3878586 — Unauthenticated data export leaks donor privacy
- **When:** submitted 2026-07-21 · disclosed 2026-07 (recent)
- **Key:** Object-level authorization replaced by a **frozen visibility flag**.
  `income/payments.spt` is reachable **without auth** (`get_participant(..., restrict=False)`),
  and the SQL gate only checks `pt.visibility = 3` — **omitting** the live
  `hide_giving`, `hide_from_lists`, and the recipient opt-in check that every
  other public surface honors. The per-payment visibility is never updated
  after payment.
- **Consequence:** an unauthenticated visitor reads donor identity + exact
  per-payment amount + date for donations the donor explicitly opted out of.
- **Root-cause rule:** a gate that reads a **snapshot flag** instead of the
  **current owner permission** is the hidden IDOR on object metadata read.
- **Link (public):** `https://hackerone.com/reports/3878586`

> **How to use:** at P4, reproduce the minimal pattern: find an object whose
> access check is "does the flag/visibility allow me" rather than "am I the
> owner / is this allowed for this actor". Prove it with two requests (other
> user's id / unauth) → same object returned.

---

## 4. PoC harness (read-only, authorized target only)

```bash
# 1) baseline: your own object (proves endpoint + format)
curl -s -o baseline.bin \
  "https://TARGET/api/files/$(curl -s ... /api/me | jq -r .file_id)"

# 2) mutate — other user's id, or no auth at all
curl -s -o victim.bin -w "%{http_code}\n" \
  "https://TARGET/api/files/<OTHER_USER_FILE_ID>"
cmp baseline.bin victim.bin && echo "same object leaked: IDOR confirmed"

# 3) unauth flush (no cookie / no session header) — key test for this class
curl -s -o unauth.bin -w "%{http_code}\n" \
  -H "Cookie: " "https://TARGET/static/12145.txt"
```

**Rules (vhs RoE):** read-only GET only; smallest proof (object type, size,
a reversible marker); never exfiltrate real PII. Document baseline / expected
control / negative control (an authorized id must 200, a definitive-to-ignore id
must 404/403) in the evidence ledger.

---

## 5. Severity & reporting

- **Unauth disclosure of PII / documents / credentials** → High–Critical
  (CWE-639 + impact). File containing credentials or payment data → uplift.
- **Authenticated cross-user object read (IDOR, no data leak beyond object
  scope)** brightly → Medium–High depending on asset.
- **Metadata-only / low-sensitivity** → Medium.
- Cite: CWE-639, OWASP API1/BOLA, and the matching case study ID for the
  reporter's edge cases (e.g. "frozen visibility flag" = the #3878586 pattern).