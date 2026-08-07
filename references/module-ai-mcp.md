# Module — AI / MCP / Agent Attack Surface 🤖

Trigger: target punya MCP server, AI plugin, CLI installer, agent integration, ChatGPT/Claude connector, atau LLM tooling.

> Referensi lapangan: Avici.money MCP (mcp.avici.money) — F-001 dynamic client registration tanpa auth = temuan High dari surface ini.

---

## 1. MCP Discovery (passive dulu)

| Endpoint | Info yang didapat |
|----------|-------------------|
| `/.well-known/oauth-authorization-server` | issuer, authorization/token/register/revoke endpoints, PKCE support, scopes, grant types |
| `/.well-known/oauth-protected-resource` | resource metadata |
| `/sse`, `/messages`, `/mcp`, `/setup` | transport + session management |
| Root `/` | kadang nampilin framework (Railway/Express/Next) |

**Cek wajib:**
```bash
curl -sk https://<mcp-host>/.well-known/oauth-authorization-server
curl -sk https://<mcp-host>/setup -H "Authorization: Bearer x"   # error shape reveal
```

## 2. OAuth Attack Patterns (prioritas tinggi)

### 2.1 Dynamic Client Registration — `POST /register`
```bash
curl -sk -X POST https://<mcp-host>/register -H "Content-Type: application/json" \
  -d '{"redirect_uris":["https://evil.com/cb"],"client_name":"t","token_endpoint_auth_method":"none"}'
```
- ✅ Kalau 200 + `client_id` → **FINDING**: registration tanpa auth + redirect_uri bebas
- Chain: register evil client → `/authorize?client_id=<reg>&redirect_uri=evil.com` → korban login (OTP/Google) → code ke evil.com → `POST /token` → access token
- Impact: token MCP (biasanya read-only wallet/card/data) — tapi cek scope; kadang token sama berlaku di API utama
- **FP check**: kalau registration butuh approval/manual, atau redirect_uri di-whitelist → bukan temuan

### 2.2 redirect_uri Validation
- Coba: `https://evil.com`, `https://host.evil.com`, `https://host.com@evil.com/`, path traversal, case, port, double-encode
- Error `invalid_client` vs `invalid_grant` bedain: client_id valid tapi redirect_uri salah = whitelist aktif

### 2.3 PKCE Downgrade
- Hapus `code_challenge` dari /authorize → kalau server tetap kasih code → PKCE tidak enforced
- Client `token_endpoint_auth_method: none` = public client → code_verifier WAJIB; kalau gak, code bisa dipake attacker yang dapet code

### 2.4 Token Scope Confusion
- Metadata `scopes_supported` — cuma 1 scope? coba minta scope lain (kalau server ignore = scope confusion)
- Refresh token lifetime — `grant_types_supported: refresh_token` → refresh token umur panjang? cek expiry di token claims

## 3. MCP Tool Enumeration (setelah dapat token)

```bash
# MCP JSON-RPC
curl -sk -X POST https://<mcp-host>/setup -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```
- Catat tool names + input schema → cari IDOR-prone params (userId, accountId, cardId)
- Tes tool cross-account: panggil tool dengan resource ID milik akun lain (kalau ada 2 akun)

## 4. CLI / Installer Supply Chain 🔥 (sering bocor endpoints)

`install.sh` / `install.ps1` / npm package = **documented API client**:
```bash
curl -sk https://<host>/install.sh | grep -E 'API_URL|BASE_URL|api/v[0-9]|/auth|/wallet|/card'
```
- `AVICI_API_URL` style env default → API base URL
- Embedded public keys (RSA untuk "reveal" crypto) — public key bukan secret, tapi reveal flow = data sensitif
- lib scripts (auth.sh, wallet.sh, cards.sh) = endpoint list lengkap
- **Supply chain check**: installer pakai checksum? (sha256 verify) — kalau gak, MITM install = RCE di mesin user

## 5. AI Plugin Manifests

| Path | Isi |
|------|-----|
| `/.well-known/ai-plugin.json` | plugin manifest: API endpoints, auth type, logo (bisa SSRF via logo URL?) |
| `/llms.txt` | full docs content (GitBook-style) — endpoint list, flow detail |
| `/openapi.json`, `/swagger.json` | API spec |
| `sitemap.xml` | struktur docs |

## 6. Tool-Specific Checks

- **MCP setup/login page**: form email OTP → rate limit? user enum? (POST /oauth/login/email)
- **WebSocket**: transport MCP bisa WS — auth via session cookie? header?
- **QR login** (mobile CLI pattern): `/qr-login/create` unauthenticated? status endpoint bocor encryptedPayload? code space cukup besar?
- **Agent skills** (`.claude/skills/`, `.codex/skills/`): SKILL.md + reference.md kadang expose endpoint + contoh perintah

## Checklist Temuan

| Temuan | Severity khas | FP check |
|--------|:-------------:|----------|
| Dynamic client reg tanpa auth + redirect_uri bebas | High (butuh user interaction) | reg butuh approval? redirect whitelist? |
| PKCE downgrade | Medium | server accept code tanpa verifier? |
| Token scope confusion | Medium | scope non-default diterima? |
| Installer tanpa checksum | Medium (supply chain) | binary official? |
| OTP no rate limit (MCP login) | Low-Med | email valid di-spam? |
| QR login phishing | Medium | butuh scan+approve (user interaction) |
| llms.txt/docs expose internal endpoints | Info | internal = bukan public? |
