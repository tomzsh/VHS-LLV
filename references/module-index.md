# VHS Module Index — pick the module that matches the in-scope surface

> Quick-pick table for P3/P4. Load `references/<file>` **only** when the
> target's surface matches. Each module: detection checklist, verified 2026
> case study(ies), read-only PoC harness, severity. Hypothesis still requires
> evidence-ledger validation at P4. See `attack-playbooks/00-index.md` for the
> black-box per-class playbooks.

## Object / file / authz

| Surface | Module |
|---|---|
| File/object reads (documents, attachments, static files) | `module-unauth-idor-file-access.md` |
| Export/render/materialization to PDF/CSV/ZIP | `module-export-auth-bypass.md` |
| File upload (filter bypass, stored XSS, traversal) | `module-file-upload.md` |
| OAuth/SSO/scoped or service tokens | `module-oauth-token-scope.md` |
| Web API identity (OIDC/JWT/tokens) | `module-web-api-identity.md` |
| Keycloak/OIDC authenticated probing | `oidc-session-refresh.md` |

## Injection / logic / concurrency

| Surface | Module |
|---|---|
| Server code forwards input into a trusted library | `module-injection-rce.md` |
| User-influenced URLs/hosts fetched server-side | `module-ssrf.md` |
| Accounting / integrity / state-transition bugs | `module-business-logic-flaws.md` (+ `module-business-logic.md` tables) |
| Race / dedup / idempotency | `module-race-condition.md` (+ playbook `attack-playbooks/race-conditions.md`) |

## Platform / stack

| Surface | Module |
|---|---|
| AI / MCP / agent attack surface | `module-ai-mcp.md` |
| Android APK static analysis | `module-android-apk.md` |
| Cloud / AI supply chain | `module-cloud-ai-supply-chain.md` |
| Web3 / fintech / smart-contract | `module-web3-fintech.md` |

## Evidence & reporting (P4/P5/P6)

| Stage | Module |
|---|---|
| Evidence standard & PoC review | `evidence-standard.md` |
| Severity taxonomy (P1→P5, mandatory at P5) | `taxonomy-rating.md` + `vulnerability-rating-taxonomy.json` |
| CVSS 3.1 vector scoring | `bountyforge-cvss.md` |
| Finding gate evaluation (refutation→impact) | `bountyforge-judging.md` |
| Reporting templates | `reporting-templates.md` |
| Platform submission (H1/Bugcrowd 3-part) | `templates/report-submission.md` |
| Office deliverables (.docx/.xlsx) | `officecli-reporting.md` |

## Attack playbooks — title mapping (Chinese → English)

> `attack-playbooks/` are ported verbatim (Mandarin). Use this mapping to pick
> a playbook by English keyword; search also works via `hermes-find --reference`.

| English keyword | Playbook file |
|---|---|
| unauthenticated access / default creds / actuator / swagger / .git | `attack-playbooks/unauth-access.md` |
| RCE / log4shell / fastjson / struts | `attack-playbooks/rce.md` |
| file upload / webshell / parser bypass | `attack-playbooks/file-upload.md` |
| path traversal / LFI / encoding | `attack-playbooks/path-traversal.md` |
| info disclosure / .git / backup / OSS bucket | `attack-playbooks/info-disclosure.md` |
| business logic / password reset / captcha / payment | `attack-playbooks/logic-flaws.md` |
| arbitrary X authorization / account takeover | `attack-playbooks/arbitrary-x-authz.md` |
| OAuth / SAML / JWT / redirect_uri / state | `attack-playbooks/oauth-saml-jwt.md` |
| SQL injection | `attack-playbooks/sqli.md` |
| SSRF / host header / cache poisoning | `attack-playbooks/ssrf-cache-host.md` |
| REST API / BOLA / mass assignment / CORS | `attack-playbooks/api-rest.md` |
| GraphQL / introspection / nested IDOR | `attack-playbooks/graphql.md` |
| race condition / double-spend / coupon | `attack-playbooks/race-conditions.md` |
| XSS / context bypass | `attack-playbooks/xss.md` |
| HTTP request smuggling / desync | `attack-playbooks/http-smuggling.md` |
| mobile / Android exported components / WebView | `attack-playbooks/mobile.md` |
| LLM prompt injection / RAG poisoning / agent | `attack-playbooks/llm-prompt-injection.md` |
| DoS / regex disaster / resource exhaustion | `attack-playbooks/dos.md` |
| intranet / post-exploitation / privesc | `attack-playbooks/intranet-postexp.md` |
