# Non-Qualifying Vulnerabilities

> **This file is a DEFAULT exclusion list, not the authority.** The authoritative
> policy is the target program's own rules (recorded in `engagement.json`
> `scope_source` at P0). Before classifying any finding as non-qualifying, check
> the program's published policy — many programs explicitly reward classes that
> appear below (notably subdomain takeover, rate-limit, and session-invalidation
> issues). When the program policy conflicts with this list, the program wins.
> Copy this template into `<engagement>/program-policy.md` and strike/add rows to
> mirror the real program before P5 triage.

The following issues are **generally not eligible** for rewards under the bug bounty program. Reports containing only these findings will typically be closed as **Informative** or **Not Applicable** unless a demonstrable security impact can be shown.

---

# Web Security

| Vulnerability | Eligible |
|---------------|:-------:|
| Tabnabbing | ❌ |
| Missing Cookie Flags | ❌ |
| Content / Text Injection | ❌ |
| Mixed Content Warnings | ❌ |
| Clickjacking / UI Redressing | ❌ |
| CSV Injection | ❌ |
| HTTP Strict Transport Security (HSTS) Header | ❌ |
| Missing Security-Related HTTP Headers | ❌ |
| HTTP Host Header based XSS / Open Redirect (unexploitable) | ❌ |
| Blind SSRF with external-callback evidence only and no demonstrable internal reachability | ❌ |
| Blind SSRF **with** proven internal network reachability (or an authorized program-approved canary hit) | ✅ |
| Self-XSS or XSS without impact on other users | ❌ |
| User Enumeration (email, phone number, GUID, alias) | ❌ |
| Lack of Rate Limiting / Brute Force / CAPTCHA | ❌ |
| Ability to Spam Users (Email, SMS, Direct Messages) | ❌ |
| Low-Severity CSRF (Login, Logout, Unauthenticated) | ❌ |
| CORS Wildcard (`Access-Control-Allow-Origin: *`) without `Access-Control-Allow-Credentials: true` | ❌ |
| CORS Origin Reflection without `Access-Control-Allow-Credentials: true` | ❌ |

---

# Authentication & Session Management

The following authentication-related findings are not considered valid security vulnerabilities on their own:

- Session expiration policies.
- Missing automatic logout.
- Session not invalidated after password changes.
- Password complexity or length requirements.
- Password reuse policies.

---

# Information Disclosure

The following disclosures are not rewarded unless they directly enable a security compromise.

- Stack traces.
- Path disclosure.
- Directory listings.
- Software version disclosure.
- Internal IP address disclosure.
- Third-party secrets without security impact.
- Open ports without demonstrable security impact.

---

# TLS / SSL

The following TLS-related issues are out of scope.

- Expired TLS/SSL certificates.
- TLS best-practice recommendations.
- SSL configuration improvements.
- HSTS header recommendations.

---

# Mobile Application Findings

The following mobile-specific issues are not eligible.

| Finding | Eligible |
|---------|:-------:|
| Missing SSL Pinning | ❌ |
| Missing Binary Protection | ❌ |
| Missing Code Obfuscation | ❌ |
| Missing Jailbreak Detection | ❌ |
| Missing Root Detection | ❌ |
| Missing Anti-Debugging Controls | ❌ |
| Lack of Encryption on Local Databases or Preference Files | ❌ |
| Generic Android Vulnerabilities | ❌ |
| Generic iOS Vulnerabilities | ❌ |

---

# Unsupported Platforms

Reports are not accepted if exploitation is only possible on unsupported environments.

- Android 7 or below.
- iOS 10 or below.
- Jailbroken iOS devices.
- Outdated browsers.
- Outdated operating systems.
- Outdated application versions not available in the latest official app stores.

---

# Third-Party & Public Issues

The following report types are outside the scope of the program.

- Known CVEs without a working Proof of Concept (PoC).
- Recently disclosed public 0-day vulnerabilities (less than **90 days** after the official patch release).
- Outdated libraries without demonstrated exploitability.
- Google API Keys (including Google Maps) that are publicly disclosed or misconfigured.
- Password reset token leaks via trusted third-party Referer headers (e.g., Google Analytics, Facebook).
- Exposed secrets or credentials on organization-controlled assets that are unrelated to the program's scope.
- Subdomain takeover findings **only when the program excludes them**; takeovers with a verified claimable dangling resource are rewarded by many programs — check the program policy before discarding.
- Hypothetical vulnerabilities without a working exploit or demonstrable impact.

---

# Social Engineering & Physical Attacks

The following attack vectors are not accepted.

- Social engineering of employees or contractors.
- Phishing attacks.
- Attacks requiring Man-in-the-Middle (MITM).
- Attacks requiring physical access to the victim's device.

---

# General Exclusions

The following findings are considered informational only.

- Security best-practice recommendations without real-world impact.
- Missing security hardening controls.
- Configuration improvements without exploitability.
- Findings that cannot be reproduced.
- Vulnerabilities without a working Proof of Concept.
- Findings without measurable security impact.

---

# Summary

A report is generally **not eligible** if it:

- Depends on outdated software or unsupported platforms.
- Requires physical access, MITM, or social engineering.
- Is based solely on best-practice recommendations.
- Lacks a working Proof of Concept (PoC).
- Has no demonstrable security or business impact.
- Targets assets or information outside the official program scope.
