# OIDC Session Auto-Refresh (Keycloak pattern)

For targets using Keycloak/OIDC (Bitso, nvio, many fintech), obtain a **self-refreshing
access token** without asking the operator to re-paste JWT every ~5 minutes.

## When to use

- Target authenticates via Keycloak (realm + `protocol/openid-connect/*`).
- Operator can provide a **valid Keycloak session cookie set** (`AUTH_SESSION_ID`,
  `KEYCLOAK_SESSION`, `KEYCLOAK_IDENTITY`) from their logged-in browser.
- Access tokens expire in minutes; refresh token not available/not shared.

## Prerequisites (from JS bundle / OIDC discovery)

- realm (e.g. `web`)
- client_id (e.g. `bitso-web-client`)
- redirect_uri registered by the client (e.g. `https://<host>/wallet`)
- auth/token endpoints: `<origin>/auth/realms/<realm>/protocol/openid-connect/{auth,token}`

## Steps

1. **Cookie jar (Netscape format) — CRITICAL PATH**: Keycloak session cookies live
   at `Path=/auth/realms/<realm>/`, NOT `/`. A jar with the wrong path makes
   Keycloak reset the session (`KEYCLOAK_SESSION=;Max-Age=0` → 200 login page).
   ```
   .bitso.com TRUE /auth/realms/web/ TRUE 1848764026 AUTH_SESSION_ID <value>
   .bitso.com TRUE /auth/realms/web/ TRUE 0 KEYCLOAK_SESSION <value>
   .bitso.com TRUE /auth/realms/web/ TRUE 1848764026 KEYCLOAK_IDENTITY <jwt>
   ```

2. **PKCE S256** — Keycloak requires `code_challenge_method=S256`; missing → 302
   `error=invalid_request Missing parameter: code_challenge_method`.
   - verifier: `bso-pkce-$(head -c40 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')`
     — MUST be ≥43 chars (prefix + 40-byte base64). A 41-char verifier is rejected:
     `PKCE verification failed: Invalid code verifier`.
   - challenge: `printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='`

3. **Authorize** (GET, with jar, follow 302):
   `auth?client_id=..&redirect_uri=..&response_type=code&scope=openid&state=..&nonce=..&code_challenge=..&code_challenge_method=S256`
   - Success: 302 with `code=...` in Location.
   - Session invalid: 200 login page + reset cookies → ask operator for fresh cookies.

4. **Exchange** (POST token endpoint, form-urlencoded):
   `grant_type=authorization_code&code=..&redirect_uri=..&client_id=..&code_verifier=..`
   → JSON `access_token` (+ `refresh_token`).

5. **Save + use**: write `access_token` to a file (e.g. `runs/auto-token.txt`),
   `Authorization: Bearer $(cat file)` on API calls.

## Pitfalls

- **Never re-type long JWTs by hand** — the agent corrupts them. Always have the
  operator save to a file, or obtain via the OIDC flow above.
- ISP DNS-poisoned host (block.myrepublic.co.id): add `--resolve host:443:<real-ip>`
  (real IP via `dig @1.1.1.1 A host`).
- Cookies set by Keycloak include `__cf_bm`/CF challenge — if the jar lacks them,
  Cloudflare may block; the authorize step usually re-sets what's needed.
- `session_state` in the redirect URL is normal; not a token.

## Reference implementation

`/home/tomz/Documents/Bug Bounty/Bitso/runs/bitso-token.sh` — full working script
(OIDC auth-code + PKCE, saves auto-token.txt, `--probe` flag for quick PII probes).
