# Module — AI / MCP / Agent Attack Surface 🤖

Trigger: the target has an MCP server, AI plugin, CLI installer, agent
integration, ChatGPT/Claude connector, or other LLM tooling.

> Field note: a fintech MCP endpoint (`mcp.<target>`) exposed dynamic client
> registration without authentication — a High-severity finding sourced from
> exactly this surface. Treat MCP/OAuth surfaces as high-value.

---

## 1. MCP Discovery (passive first)

| Endpoint | Information obtained |
|----------|----------------------|
| `/.well-known/oauth-authorization-server` | issuer, authorization/token/register/revoke endpoints, PKCE support, scopes, grant types |
| `/.well-known/oauth-protected-resource` | resource metadata |
| `/sse`, `/messages`, `/mcp`, `/setup` | transport + session management |
| Root `/` | sometimes reveals the framework (Railway/Express/Next) |

**Required checks:**
```bash
curl -sk https://<mcp-host>/.well-known/oauth-authorization-server
curl -sk https://<mcp-host>/setup -H "Authorization: Bearer ***"   # error shape reveal
```

## 2. OAuth Attack Patterns (high priority)

### 2.1 Dynamic Client Registration — `POST /register`
```bash
curl -sk -X POST https://<mcp-host>/register -H "Content-Type: application/json" \
  -d '{"redirect_uris":["https://evil.com/cb"],"client_name":"t","token_endpoint_auth_method":"none"}'
```
- ✅ If 200 + `client_id` → **FINDING**: registration without auth + arbitrary redirect_uri
- Chain: register evil client → `/authorize?client_id=<reg>&redirect_uri=evil.com` → victim logs in (OTP/Google) → code sent to evil.com → `POST /token` → access token
- Impact: MCP token (usually read-only wallet/card/data) — but check scope; sometimes the same token is valid on the main API
- **FP check**: if registration needs approval/is manual, or redirect_uri is whitelisted → not a finding

### 2.2 redirect_uri Validation
- Try: `https://evil.com`, `https://host.evil.com`, `https://***@evil.com/`, path traversal, case, port, double-encode
- Distinguish `invalid_client` vs `invalid_grant`: a valid client_id with a wrong redirect_uri = whitelist is active

### 2.3 PKCE Downgrade
- Remove `code_challenge` from /authorize → if the server still issues a code → PKCE not enforced
- Client `token_endpoint_auth_method: none` = public client → code_verifier is REQUIRED; if not, any attacker who obtains the code can use it

### 2.4 Token Scope Confusion
- Metadata `scopes_supported` — only 1 scope? request a different scope (if the server ignores it = scope confusion)
- Refresh token lifetime — `grant_types_supported: refresh_token` → long-lived refresh token? check expiry in the token claims

## 3. MCP Tool Enumeration (after obtaining a token)

```bash
# MCP JSON-RPC
curl -sk -X POST https://<mcp-host>/setup -H "Authorization: Bearer ***" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```
- Record tool names + input schema → look for IDOR-prone params (userId, accountId, cardId)
- Test tools cross-account: call a tool with a resource ID belonging to another account (if you control 2 accounts)

## 4. CLI / Installer Supply Chain 🔥 (often leaks endpoints)

`install.sh` / `install.ps1` / an npm package = a **documented API client**:
```bash
curl -sk https://<host>/install.sh | grep -E 'API_URL|BASE_URL|api/v[0-9]|/auth|/wallet|/card'
```
- A `<APP>_API_URL`-style env default → API base URL
- Embedded public keys (RSA for a "reveal" crypto flow) — a public key is not a secret, but the reveal flow itself = sensitive data
- lib scripts (auth.sh, wallet.sh, cards.sh) = a complete endpoint list
- **Supply chain check**: does the installer use a checksum? (sha256 verify) — if not, a MITM install = RCE on the user's machine

## 5. AI Plugin Manifests

| Path | Contents |
|------|----------|
| `/.well-known/ai-plugin.json` | plugin manifest: API endpoints, auth type, logo (SSRF via logo URL?) |
| `/llms.txt` | full docs content (GitBook-style) — endpoint list, flow detail |
| `/openapi.json`, `/swagger.json` | API spec |
| `sitemap.xml` | docs structure |

## 6. Tool-Specific Checks

- **MCP setup/login page**: email OTP form → rate limit? user enum? (POST /oauth/login/email)
- **WebSocket**: MCP transport can be WS — auth via session cookie? header?
- **QR login** (mobile CLI pattern): `/qr-login/create` unauthenticated? does the status endpoint leak encryptedPayload? is the code space large enough?
- **Agent skills** (`.claude/skills/`, `.codex/skills/`): SKILL.md + reference.md sometimes expose endpoints + example commands

## Findings Checklist

| Finding | Typical severity | FP check |
|---------|:----------------:|----------|
| Dynamic client reg without auth + arbitrary redirect_uri | High (needs user interaction) | reg needs approval? redirect whitelist? |
| PKCE downgrade | Medium | server accepts code without verifier? |
| Token scope confusion | Medium | non-default scope accepted? |
| Installer without checksum | Medium (supply chain) | official binary? |
| OTP no rate limit (MCP login) | Low-Med | valid email getting spammed? |
| QR login phishing | Medium | needs scan+approve (user interaction) |
| llms.txt/docs expose internal endpoints | Info | internal = not public? |
