# Web2 vulnerability references — 2026 snapshot

**Checked:** 2026-08-16 UTC  
**Use:** P1/P2 modeling and P3/P4 test-design reference.  
**Scope:** authorized Web2/API/application assessments only.

This is a compact, cited routing reference—not a claim that a target is
vulnerable. A CVE is a pattern anchor: reproduce the relevant precondition,
server-side state transition, principal boundary, and impact in the authorized
engagement before opening a hypothesis or finding. A search result, version
match, or client-side symptom is not proof.

## Loading policy

1. At P1/P2, load only the taxonomy row matching the target architecture.
2. At P3, load the matching class subsection and its selected playbook.
3. At P4, re-check the cited case and use baseline → mutation → control →
   negative control. Record principal, object, state transition, response,
   timestamp, request/response digests, and limitations.
4. Do not turn a CVE's exploit precondition into a generic payload. For example,
   an authenticated NoSQLi case is not evidence of unauthenticated NoSQLi.
5. If a citation or case detail cannot be verified from the linked source, mark
   the statement `UNKNOWN` and do not promote it to a finding.

## Class routing matrix

| Target concern | Load first | 2026 anchor set | Core test lens |
|---|---|---|---|
| ATO / IDOR / business logic | [1][4][5][8][9][17][18][19][20] | [37][38][39] | Bind identity, object ownership, role, workflow state, recovery state, and side effects server-side. |
| SQLi / NoSQLi / SSTI / CMDi / CSRF | [3][12][13][14][15][16] | [30][31][32][33][34] | Identify parser/context boundaries; preserve controls and use non-destructive proof. |
| Deserialization / race / privilege escalation | [6][10][11][26][27] | [35][36][37] | Validate trust boundary, atomicity, TOCTOU window, capability transition, and blast radius. |
| Fail-open / authorization | [1][5][7][18][19][28][29] | [38][39][40][41][42][44] | Force invalid/error/unknown states and verify deny-by-default plus least privilege. |
| Canonicalization / path boundary | [22][23][24][25] | [43] | Decode and normalize exactly once, then enforce the final canonical resource boundary. |
| Configuration / exceptional conditions | [2][7][21][28] | [40][41] | Compare valid, missing, malformed, and unavailable configuration; errors must not grant access. |

## ATO, IDOR, and business logic

### ATO and account-ownership transitions

- **CVE-2026-72856** (published 2026-08-13) describes a Budibase tenant-owner email reassignment path
  where deployment conditions reduce protection to a general authentication
  check and a lowest-privilege authenticated user can reach an ownership-change
  operation. It is an ATO-adjacent/account-ownership transition anchor, not a
  blanket claim that every Budibase deployment is exploitable.[38]
- **CVE-2026-49819** (published 2026-08-12) describes an UpSnap initialization path reachable without
  authentication and protected only by a superuser-count condition, chaining
  missing authentication with privilege escalation. Treat setup/bootstrap
  endpoints as a separate ATO and takeover surface.[39]
- Map account takeover separately from ordinary authentication failure: prove
  the attacker can change a recovery factor, password, session, owner, or
  equivalent durable account-control state. Do not rate email enumeration or a
  reflected identifier as ATO without that transition.

### IDOR / BOLA / object-level authorization

- CWE-639 defines the core condition: user-controlled keys identify records but
  authorization does not verify that the requesting user is entitled to the
  selected record.[17]
- PortSwigger's IDOR reference covers database-object and static-file forms,
  horizontal access, and possible vertical privilege escalation.[8]
- **2026 evidence boundary:** the selected official 2026 anchors below are
  authorization-bypass, missing-authentication, and privilege-transition cases;
  they are useful adjacent cases but are not relabeled as IDOR. Use [17] and
  [8] when the actual proof is cross-principal object access.
- Test with two principals and a role matrix: read, update, delete, export,
  share, download, webhook, invoice, payment, file, and tenant identifiers.
  A valid `200` alone is insufficient; compare object ownership, response body,
  side effect, and durable state.

### Business logic / workflow invariants

- OWASP 2025 places business-logic design failures under Insecure Design and
  emphasizes that controls must be modeled at the system/workflow level rather
  than inferred from one endpoint.[4]
- PortSwigger's business-logic material is the procedure reference for
  unintended but technically valid workflow sequences.[9]
- Model invariants before testing: one-time use, monotonic status, amount and
  currency conservation, approval separation, tenant ownership, replay
  resistance, and allowed state transitions. A race or IDOR is a chain
  component only after the invariant violation is demonstrated.

## Injection family

### SQL injection

- **CVE-2026-33385** (published 2026-07-29) records blind SQL injection in Quick.CMS administration
  fields, attributed to improper neutralization of SQL-command elements (CWE-89)
  and requiring a high-privilege administrator context.[30]
- Test the actual query context and privilege precondition. Prefer harmless
  differential/time-bounded indicators and a read-only proof; do not infer
  database destruction from a scanner flag or a front-end validation bypass.
- Use the SQLi methodology and labs in PortSwigger's current reference.[13]

### NoSQL injection

- **CVE-2026-3021** (published 2026-03-16) records NoSQL injection in a Wakyma employee endpoint where
  an authenticated user can alter a GET request to enumerate sensitive employee
  data; the record maps it to CWE-943.[31]
- Preserve JSON types and parser context in the matrix: string, array, object,
  operator-like keys, duplicate keys, and content-type changes. Record whether
  the server coerces types before authorization and whether the query is
  actually reached.
- Use PortSwigger's NoSQL injection material for query-logic-specific cases.[14]

### Server-side template injection (SSTI)

- **CVE-2026-15734** (published 2026-08-06) records SSTI in WGDashboard 4.3.2 and earlier, allowing an
  authenticated attacker to execute code as root.[33]
- Separate template evaluation from ordinary reflected text: identify the
  template engine, context, rendering boundary, and execution identity. Use a
  non-destructive expression/canary in an authorized environment and stop
  before arbitrary command execution unless explicitly approved by the RoE.
- Load PortSwigger's SSTI reference for engine/context identification.[12]

### OS command injection (CMDi)

- **CVE-2026-22265** (published 2026-01-15) records authenticated command injection in Roxy-WI's log
  viewing functionality, where a parameter was sanitized on one use but passed
  raw on another; the CVE maps it to CWE-78.[32]
- Trace every use of the value, not just the first sanitizer. Test shell,
  argument, option, and logging contexts independently; use a benign canary and
  verify the process boundary rather than destructive command output.
- Use PortSwigger's OS-command-injection material for context-specific testing.
  [15]

### CSRF

- **CVE-2026-26718** (published 2026-07-15) records CSRF in xxl-job-admin where Glue IDE shell-script
  modifications lacked proper token validation and accepted arbitrary methods
  through permissive request mapping.[34]
- Test authenticated state-changing requests with origin/site context, token
  presence, token binding, method/content-type changes, SameSite behavior, and
  re-authentication requirements. A missing token on a read-only request is not
  automatically a finding.
- Use the PortSwigger CSRF reference for proof structure and browser-context
  constraints.[16]

## Deserialization, race, and privilege escalation

### Insecure deserialization

- **CVE-2026-43633** (published 2026-05-19) records unauthenticated root-level code execution in HestiaCP
  through a PHP/Node.js session-format mismatch in the web terminal; it maps to
  CWE-502.[35]
- Identify the serialization format, trust boundary, producer/consumer mismatch,
  integrity protection, class/type allowlist, and execution identity. Prefer
  parser-level or harmless object-type proof; do not generate a gadget chain for
  an external target.
- Use PortSwigger's deserialization reference for identification and impact
  analysis.[11]

### Race / TOCTOU

- **CVE-2026-25728** (published 2026-02-10) records a ClipBucket upload TOCTOU flaw: the file became
  web-accessible before validation and deletion, leaving a window for code
  execution; it maps to CWE-367.[36]
- Test the invariant and timing window, not request volume alone. Record the
  exact sequence, concurrency level, server responses, resulting state, and
  whether the operation is atomic. Stop when the smallest safe proof is reached.
- Use PortSwigger's race-condition reference for synchronization and state
  validation.[10]

### Privilege escalation / authorization transition

- **CVE-2026-19598** (published 2026-08-15) records WordPress Pods privilege escalation through an
  authorization bypass in an AJAX router and maps to CWE-863.[37]
- **CVE-2026-2311** (published 2026-04-30) records an invalid authorization check in IBM i Web
  Administration GUI that can result in user-controlled code running with
  administrator privilege; it maps to CWE-284.[44]
- Model the capability transition explicitly: principal before, requested
  operation, enforcement point, principal/capability after, and durable impact.
  Do not call a hidden admin route a privilege escalation until the lower
  principal crosses a protected capability boundary.

## Fail-open, authorization, canonicalization, and configuration

### Fail-open / exceptional conditions

- **CVE-2026-73421** (published 2026-08-13) records a NextAuth.js failure mode where a server
  configuration error produces a truthy auth object; checks such as `!!auth` can
  grant routes to unauthenticated visitors. NVD maps the case to CWE-285 and
  CWE-636.[40]
- **CVE-2026-37525** (published 2026-05-01) records authorization decisions receiving NULL credentials
  and APIs that fail open in that state, enabling privilege escalation.[41]
- **CVE-2026-28498** (published 2026-03-16) records a fail-open behavior in Authlib OIDC hash
  validation when an unsupported/unknown cryptographic algorithm is encountered;
  the record maps it to integrity-validation weaknesses.[42]
- Test missing, malformed, expired, unsupported, unavailable, and error-state
  credentials/configuration. The expected result is deny-by-default with an
  auditable error—not a truthy object, NULL principal, fallback role, or skipped
  check.

### Authorization taxonomy

- CWE-284 is the broad improper-access-control class; CWE-285 covers improper
  authorization decisions; CWE-862 covers missing authorization; CWE-863 covers
  incorrect authorization.[18][19][29]
- Use the narrowest proven label. `401`/`403` behavior, a hidden route, or a
  client-side role flag is not enough to establish a bypass; prove the protected
  action or data boundary with the smallest authorized mutation/read.

### Canonicalization and path boundaries

- CWE-174 covers double decoding; CWE-180 covers validating before
  canonicalization; CWE-181 covers validating before filtering.[22][23][24]
- **CVE-2026-53976** (published 2026-08-06) records unauthenticated arbitrary-file reads in OpenChamber
  after a workspace boundary check was bypassed through an outside-workspace
  flag and absolute path; it maps to CWE-22.[43]
- Verify decode count, separator normalization, Unicode/alternate separator
  handling, symlink resolution, absolute-path handling, archive extraction, and
  the final resolved path. Authorization must apply after canonicalization and
  before file access.

### Configuration and exceptional-condition failures

- OWASP 2025 A02 covers security misconfiguration; A10 covers mishandling
  exceptional conditions. Treat defaults, missing secrets, debug/admin routes,
  permissive CORS, exposed management interfaces, verbose errors, and fallback
  providers as configuration/state hypotheses—not automatic findings.[2][7]
- **CVE-2026-73421** is a concrete configuration-induced fail-open anchor: the
  security outcome changes only after the deployment becomes misconfigured.[40]
- **CVE-2026-49819** is a bootstrap/configuration-boundary anchor: a superuser
  initialization endpoint lacks authentication and relies on a count condition.
  [39]
- Compare secure baseline, missing configuration, malformed configuration,
  startup failure, dependency timeout, and partial initialization. Each state
  must fail closed and must not silently fall back to an administrative or
  anonymous identity.

## Evidence and reporting contract

For every hypothesis, capture:

- source class and selected reference IDs;
- target surface, endpoint, method, content type, and parser/context;
- principal, role, tenant, object/resource ID, and ownership expectation;
- baseline, mutation, control, negative control, and exact state transition;
- timestamp with timezone, request/response digests, status/body delta, and
  cleanup result;
- precondition from the cited 2026 case and whether the target actually meets
  it; and
- limitations, including authentication requirement, deployment mode, version,
  feature flag, race window, or unverified impact.

A citation supports methodology or a case pattern. It never substitutes for
engagement evidence. Unsupported node, edge, source, sink, or citation claims
remain `UNKNOWN` under the Code Graph grounding contract.

## Sources

[1] https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A01_2025-Broken_Access_Control.md — OWASP Top 10 2025 A01 Broken Access Control
[2] https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A02_2025-Security_Misconfiguration.md — OWASP Top 10 2025 A02 Security Misconfiguration
[3] https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A05_2025-Injection.md — OWASP Top 10 2025 A05 Injection
[4] https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A06_2025-Insecure_Design.md — OWASP Top 10 2025 A06 Insecure Design
[5] https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A07_2025-Authentication_Failures.md — OWASP Top 10 2025 A07 Authentication Failures
[6] https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A08_2025-Software_or_Data_Integrity_Failures.md — OWASP Top 10 2025 A08 Software or Data Integrity Failures
[7] https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A10_2025-Mishandling_of_Exceptional_Conditions.md — OWASP Top 10 2025 A10 Mishandling of Exceptional Conditions
[8] https://portswigger.net/web-security/access-control/idor — PortSwigger IDOR
[9] https://portswigger.net/web-security/logic-flaws — PortSwigger business logic vulnerabilities
[10] https://portswigger.net/web-security/race-conditions — PortSwigger race conditions
[11] https://portswigger.net/web-security/deserialization — PortSwigger insecure deserialization
[12] https://portswigger.net/web-security/server-side-template-injection — PortSwigger SSTI
[13] https://portswigger.net/web-security/sql-injection — PortSwigger SQL injection
[14] https://portswigger.net/web-security/nosql-injection — PortSwigger NoSQL injection
[15] https://portswigger.net/web-security/os-command-injection — PortSwigger OS command injection
[16] https://portswigger.net/web-security/csrf — PortSwigger CSRF
[17] https://cwe.mitre.org/data/definitions/639.html — CWE-639 Authorization Bypass Through User-Controlled Key
[18] https://cwe.mitre.org/data/definitions/862.html — CWE-862 Missing Authorization
[19] https://cwe.mitre.org/data/definitions/863.html — CWE-863 Incorrect Authorization
[20] https://cwe.mitre.org/data/definitions/640.html — CWE-640 Weak Password Recovery Mechanism
[21] https://cwe.mitre.org/data/definitions/16.html — CWE-16 Configuration
[22] https://cwe.mitre.org/data/definitions/174.html — CWE-174 Double Decoding
[23] https://cwe.mitre.org/data/definitions/180.html — CWE-180 Validate Before Canonicalize
[24] https://cwe.mitre.org/data/definitions/181.html — CWE-181 Validate Before Filter
[25] https://cwe.mitre.org/data/definitions/22.html — CWE-22 Path Traversal
[26] https://cwe.mitre.org/data/definitions/502.html — CWE-502 Deserialization of Untrusted Data
[27] https://cwe.mitre.org/data/definitions/367.html — CWE-367 TOCTOU
[28] https://cwe.mitre.org/data/definitions/636.html — CWE-636 Not Failing Securely
[29] https://cwe.mitre.org/data/definitions/285.html — CWE-285 Improper Authorization
[30] https://cveawg.mitre.org/api/cve/CVE-2026-33385 — CVE-2026-33385
[31] https://cveawg.mitre.org/api/cve/CVE-2026-3021 — CVE-2026-3021
[32] https://cveawg.mitre.org/api/cve/CVE-2026-22265 — CVE-2026-22265
[33] https://cveawg.mitre.org/api/cve/CVE-2026-15734 — CVE-2026-15734
[34] https://cveawg.mitre.org/api/cve/CVE-2026-26718 — CVE-2026-26718
[35] https://cveawg.mitre.org/api/cve/CVE-2026-43633 — CVE-2026-43633
[36] https://cveawg.mitre.org/api/cve/CVE-2026-25728 — CVE-2026-25728
[37] https://cveawg.mitre.org/api/cve/CVE-2026-19598 — CVE-2026-19598
[38] https://cveawg.mitre.org/api/cve/CVE-2026-72856 — CVE-2026-72856
[39] https://cveawg.mitre.org/api/cve/CVE-2026-49819 — CVE-2026-49819
[40] https://cveawg.mitre.org/api/cve/CVE-2026-73421 — CVE-2026-73421
[41] https://cveawg.mitre.org/api/cve/CVE-2026-37525 — CVE-2026-37525
[42] https://cveawg.mitre.org/api/cve/CVE-2026-28498 — CVE-2026-28498
[43] https://cveawg.mitre.org/api/cve/CVE-2026-53976 — CVE-2026-53976
[44] https://cveawg.mitre.org/api/cve/CVE-2026-2311 — CVE-2026-2311
