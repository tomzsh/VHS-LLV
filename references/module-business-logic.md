# Module — Business Logic Attack Patterns 💰

Focus: critical bugs in logic flows that often yield high payouts. Test with 2
accounts, synthetic data, and minimal impact.

---

## Payment & Transactions

### Price Manipulation
| Attack | How to Test | Expected |
|--------|-------------|----------|
| Negative price | Send `price=-10000` | Reject / server-side validation |
| Zero price | Send `price=0` checkout | Must not succeed |
| Fractional cent | Send `price=0.001` | Reject or rounding |
| Integer overflow | Send `price=9999999999999` | Validate max value |
| Quantity negative | Send `quantity=-1` → negative total | Reject |
| Currency mismatch | Change `currency=USD` to `IDR` at the same amount | Rate conversion must be server-side |
| Coupon stacking | Apply multiple coupons that should not stack | Check each combination |
| Coupon percentage | Change `discount=10%` to `100%` via intercept | Validate on the server |

Test pattern:
```http
POST /api/checkout
Content-Type: application/json

{"item_id": 123, "quantity": -1, "price": 0}  ← ❌
```

### Race Condition
| Attack | How to Test |
|--------|-------------|
| Checkout race | Send 10 concurrent POST /checkout with a just-enough balance |
| Refund race | Refund the same transaction twice simultaneously |
| Withdrawal race | Withdraw the same balance from 2 different sessions |
| Coupon usage | Redeem the same coupon twice concurrently |
| Stock depletion | Buy a limited-stock item concurrently |

Test pattern:
```bash
# Race: send 10 concurrent requests
for i in {1..10}; do curl -X POST https://target/api/checkout \
  -H "Cookie: session=xxx" \
  -d '{"item_id":1,"quantity":1}' &
done
wait
```

### Idempotency Bypass
Check: if there is an `idempotency_key` or `nonce` — try:
1. Submit request with key A → success
2. Submit request again with key A → should reject (duplicate)
3. Submit with key B (variant) → if it succeeds, idempotency works
4. Change another parameter (amount, recipient) but keep the same key → should still reject

### Refund / Reversal
| Scenario | Critical? |
|----------|:---------:|
| Refund full amount but item not returned | ⭐ Yes |
| Refund to an account different from the original buyer | ⭐ Yes |
| Refund exceeding the payment amount | ⭐ Yes |
| Cancel order after the refund is processed | 🟡 Maybe |

---

## Authentication & Session

### JWT Attacks
| Attack | How to Test |
|--------|-------------|
| None algorithm | Change `alg: "RS256"` → `alg: "none"`, remove signature |
| Weak key | Try to crack an HS256 JWT with rockyou.txt |
| Kid injection | Inject `kid: "../../../etc/passwd"` or SQLi |
| Jku/x5u SSRF | Inject a URL into `jku` → server fetches from the attacker server |
| Expired token | Submit a JWT after it has expired |
| Token reuse across tenants | Test a token from tenant A user → access tenant B resource |

Test:
```bash
# JWT none algorithm
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).rstrip(b'=')
print(f'{header.decode()}.{payload.decode()}.')
"
```

### OIDC / OAuth
| Attack | How to Test |
|--------|-------------|
| CSRF on OIDC callback | State parameter missing / guessable |
| PKCE downgrade | Remove `code_challenge` → server accepts without PKCE |
| redirect_uri validation | Try `redirect_uri=https://evil.com` |
| Token interception | Token sent via URL fragment → readable by third-party JS |
| OpenID scope leaking | Request `openid profile email phone address` → check whether all are granted |

### Session Attacks
| Attack | How to Test |
|--------|-------------|
| Session fixation | Set a session cookie before login, check whether it is used after login |
| Session not invalidated after logout | Logout → use the old cookie → still valid? |
| Concurrent session limit | Login from 50 different browsers → not limited? |
| Weak session token | Token predictable (integer increment, timestamp) |
| Session in URL | Token present in URL → can leak via referer header |

---

## Registration & Invitation

### Account Takeover (ATO)
| Attack | How to Test |
|--------|-------------|
| Password reset token bruteforce | 4-digit token → bruteforce 9999 possibilities |
| Email change without confirmation | Change email in profile → login with the new email |
| Account linking takeover | OAuth connect a Google account → take over the target account |
| Invitation token predict | Invite your own email → try to guess the invitation token for another org |
| Mass account creation | Register 1000+ accounts → rate limit check |

### Email/Phone Verification
| Attack | How to Test |
|--------|-------------|
| Verification link predictable | Check the `/verify?token=xxx` pattern → guessable? |
| Skip verification | Login directly without verifying email |
| Re-verify with different email | Input email A → intercept → change to email B → verify |
| Expired verify link still valid | Use a verify link from 7 days ago |

---

## Upload & File Handling

### SSRF via Upload
| Attack | How to Test |
|--------|-------------|
| Upload URL fetch | Upload URL `http://169.254.169.254/latest/meta-data/` |
| Webhook callback | Point the webhook to an internal service |
| SVG with XInclude | Upload an SVG that fetches an internal resource |
| Image processing SSRF | Upload a crafted image → server processes → callback |

### Path Traversal
| Attack | How to Test |
|--------|-------------|
| Filename traversal | `../../../etc/passwd` in the filename |
| Zip slip | Upload a ZIP with a symlink to /etc/shadow |
| CloudFront traversal | Path like `/..%2f..%2f..%2fadmin` |
| Static file serving | Check `/static/..%2f..%2f..%2f.env` |

---

## API & Rate Limit

### API Abuse
| Attack | How to Test |
|--------|-------------|
| Pagination without bound | `?page=1&limit=1000000` → dump all data |
| GraphQL introspection | `{__schema{types{name}}}` → leak all models |
| GraphQL batching | Batch queries to bypass rate limits |
| Mass assignment | Inject field `role:admin` in the request body |
| REST parameter pollution | `?user_id=123&user_id=456` → multiple interpretation |

### Rate Limit Bypass
| Attack | How to Test |
|--------|-------------|
| IP rotation | Via Tor / rotating proxy |
| Header spoof | `X-Forwarded-For: 1.2.3.4` and IP variants |
| Cookie-based limit | Remove cookie → server issues a fresh rate limit |
| Method variant | Swap POST for PUT / PATCH / DELETE |
| Parameter difference | Add a random parameter to the URL → bypass |
