# Vulnerability Rating Taxonomy — Integration Guide

Source: `vulnerability-rating-taxonomy.json` (bundled in this skill).

## What it is

A 37-category / 229-subcategory / 315-variant severity taxonomy used for rating
findings. Every `variant` node carries a `priority`:

| Priority | Meaning | Mapping |
| --- | --- | --- |
| 1 | Critical | P0/P1 — immediate reporting, highest impact |
| 2 | High | P1/P2 — report promptly, strong evidence required |
| 3 | Medium | P2/P3 |
| 4 | Low | P4 — usually needs extra impact to qualify |
| 5 | Informational / NQ | usually non-qualifying on its own |
| null | Unrated | rate by demonstrated impact, not class |

## How to use in each phase

### P1 (modeling) — build invariants from categories

Map the target's architecture to taxonomy **categories** and **subcategories**,
then write invariants for the applicable ones:

- Web/API app: Broken Access Control (BAC), Broken Authentication & Session
  Management, Cross-Site Scripting (XSS), Server-Side Injection, Sensitive Data
  Exposure, Cryptographic Weakness, Unvalidated Redirects.
- Fintech/ledger: Decentralized Application Misconfiguration (Marketplace
  Security: Orderbook Manipulation, Price/Fee Manipulation, Unauthorized Asset
  Transfer, Signer Account Takeover), Application-Level DoS.
- Cloud: Cloud Security (IAM, Storage, Network misconfig).
- AI/LLM surface: AI Application Security (Prompt Injection, Model Extraction,
  System Prompt Leakage, PII Leakage).
- AD/infra: Active Directory (Kerberos), Insecure OS/Firmware (hardcoded creds).

Each invariant should cite the taxonomy subcategory it protects.

### P2 (recon) — priority hunting checklist

Prioritize hunting for **priority 1-2 variants** reachable from the target:

**CRITICAL (priority 1) — hunt first:**
- BAC > IDOR > *Modify/View Sensitive Information (Iterable Object Identifiers)*
- Server-Side Injection > File Inclusion > Local (LFI)
- Sensitive Data Exposure > Disclosure of Secrets > *For Publicly Accessible Asset*
- Server Security Misconfiguration > Exposed Portal > *Admin Portal*
- Server Security Misconfiguration > SSRF > *Internal Secrets Exposure*
- Cloud > IAM > *Publicly Accessible IAM Credentials*
- Decentralized App > Marketplace > Orderbook Manipulation / Signer ATO /
  Unauthorized Asset Transfer
- AI App > Key Leak / Cross-Tenant PII Leakage / Full System Compromise

**HIGH (priority 2) — hunt next:**
- BAC > IDOR > *Modify Sensitive Information (Iterable IDs)*
- Server Security > OAuth Misconfiguration > *Account Takeover*
- XSS > Stored > Non-Privileged User to Anyone
- Sensitive Data Exposure > Weak Password Reset > *Token Leakage via Host Header
  Poisoning*
- Cryptographic Weakness > Key Reuse > Inter-Environment
- Decentralized App > Marketplace > Price/Fee Manipulation, Malicious Order Offer
- AI App > Prompt Injection > System Prompt Leakage; DoS Application-Wide
- Cloud > IAM Overly Permissive Roles; Storage Unencrypted at Rest

### P5 (triage) — rate by taxonomy + demonstrated impact

Rating order:
1. Match the finding to its taxonomy category/subcategory/variant.
2. Read the variant's `priority` as the baseline severity.
3. Adjust using vhs severity rules: prerequisites, user interaction, tenant
   delta, demonstrated vs hypothetical, compensating controls, program rules.
4. Never assign severity from class alone — an IDOR can be P1 (iterable,
   sensitive, modify) or P5 (view non-sensitive, GUID).
5. Record the taxonomy variant ID in the finding's severity rationale.

## Web/API P1-P2 quick map (most common on bug bounty targets)

| Priority | Variant | Typical proof |
| --- | --- | --- |
| 1 | IDOR modify/view sensitive (iterable id) | swap sequential object id → other user's data |
| 1 | Exposed admin portal | unauthenticated admin/login reachable |
| 1 | SSRF → internal secrets | server fetches internal URL → secret returned |
| 1 | Secret on publicly accessible asset | key/credential in public file/JS/bucket |
| 1 | Local file inclusion | path traversal → /etc/passwd or app source |
| 2 | OAuth misconfig → account takeover | token/code reuse, redirect_uri tamper |
| 2 | Stored XSS (non-priv → anyone) | persist payload, triggers for other users |
| 2 | Password reset token leak (host header) | host-header poison → token in attacker URL |
| 2 | Key reuse across environments | staging key works on prod |
| 3 | Reflected XSS | payload echoed unencoded (needs impact) |
| 3 | CSRF application-wide | state-changing request without token |
| 4 | User enumeration | different error/response for valid user |
| 5 | Missing security headers | header absence only |

## Updating the taxonomy

The JSON is the source of truth. If a program's RoE defines its own severity
table, use the program table first, then the taxonomy for gaps. Do not edit the
JSON for program-specific preferences — keep it program-agnostic.
