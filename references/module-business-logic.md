# Module — Business Logic Attack Patterns 💰

Fokus: critical bugs di logic flow yang sering menghasilkan payout tinggi. Test dengan 2 akun, synthetic data, dan minimal impact.

---

## Payment & Transaksi

### Price Manipulation
| Attack | Cara Test | Expected |
|--------|-----------|----------|
| Negative price | Kirim `price=-10000` | Reject / validasi server-side |
| Zero price | Kirim `price=0` checkout | Jangan sampai success |
| Fractional cent | Kirim `price=0.001` | Reject atau rounding |
| Integer overflow | Kirim `price=9999999999999` | Validasi max value |
| Quantity negative | Kirim `quantity=-1` → total harga minus | Reject |
| Currency mismatch | Ganti `currency=USD` jadi `IDR` dengan harga sama | Rate conversion harus server-side |
| Coupon stacking | Apply multiple coupon yang seharusnya gak bisa stack | Cek tiap kombinasi |
| Coupon percentage | Ubah `discount=10%` jadi `100%` via intercept | Validasi di server |

Test pattern:
```http
POST /api/checkout
Content-Type: application/json

{"item_id": 123, "quantity": -1, "price": 0}  ← ❌
```

### Race Condition
| Attack | Cara Test |
|--------|-----------|
| Checkout race | Kirim 10 concurrent POST /checkout dengan balance pas-pasan |
| Refund race | Refund transaksi yang sama 2x bersamaan |
| Withdrawal race | Withdraw saldo yang sama dari 2 session berbeda |
| Coupon usage | Redeem coupon yang sama 2x concurrent |
| Stock depletion | Beli item limited stock concurrent |

Test pattern:
```bash
# Race: kirim 10 request concurrent
for i in {1..10}; do curl -X POST https://target/api/checkout \
  -H "Cookie: session=xxx" \
  -d '{"item_id":1,"quantity":1}' &
done
wait
```

### Idempotency Bypass
Check: kalau ada `idempotency_key` atau `nonce` — coba:
1. Submit request dengan key A → success
2. Submit request lagi dengan key A → harusnya reject (duplicate)
3. Submit dengan key B (variant) → kalau success, idempotency works
4. Ganti parameter lain (amount, recipient) tapi key sama → harusnya masih reject

### Refund / Reversal
| Scenario | Critical? |
|----------|:---------:|
| Refund full amount tapi item gak dikembalikan | ⭐ Ya |
| Refund ke akun berbeda dari pembeli asli | ⭐ Ya |
| Refund melebihi amount pembayaran | ⭐ Ya |
| Cancel order setelah refund diproses | 🟡 Maybe |

---

## Authentication & Session

### JWT Attacks
| Attack | Cara Test |
|--------|-----------|
| None algorithm | Ubah `alg: "RS256"` → `alg: "none"`, hapus signature |
| Weak key | Coba crack HS256 JWT dengan rockyou.txt |
| Kid injection | Inject `kid: "../../../etc/passwd"` atau SQLi |
| Jku/x5u SSRF | Inject URL ke `jku` → server fetch dari attacker server |
| Expired token | Submit JWT setelah expired |
| Token reuse across tenants | Test token dari user tenant A → akses resource tenant B |

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
| Attack | Cara Test |
|--------|-----------|
| CSRF on OIDC callback | State parameter tidak ada / bisa ditebak |
| PKCE downgrade | Hapus `code_challenge` → server terima tanpa PKCE |
| redirect_uri validation | Coba `redirect_uri=https://evil.com` |
| Token interception | Token dikirim via URL fragment → bisa di-read oleh JS pihak lain |
| OpenID scope leaking | Request `openid profile email phone address` → cek apa semua dikasih |

### Session Attacks
| Attack | Cara Test |
|--------|-----------|
| Session fixation | Set session cookie sebelum login, lihat apakah dipake setelah login |
| Session not invalidated after logout | Logout → pakai cookie lama → masih valid? |
| Concurrent session limit | Login dari 50 browser berbeda → gak dibatasin? |
| Weak session token | Token predictable (integer increment, timestamp) |
| Session in URL | Token ada di URL → bisa leak via referer header |

---

## Registration & Invitation

### Account Takeover (ATO)
| Attack | Cara Test |
|--------|-----------|
| Password reset token bruteforce | Token 4 digit → bruteforce 9999 possibilities |
| Email change tanpa konfirmasi | Ubah email di profile → login dengan email baru |
| Account linking takeover | OAuth connect akun Google → ambil alih akun tujuan |
| Invitation token predict | Invite ke email sendiri → coba tebak token undangan untuk org lain |
| Mass account creation | Register 1000+ akun → rate limit check |

### Email/Phone Verification
| Attack | Cara Test |
|--------|-----------|
| Verification link predictable | Cek pola /verify?token=xxx → bisa ditebak? |
| Skip verification | Langsung login tanpa verify email |
| Re-verify with different email | Input email A → intercept → ganti jadi email B → verify |
| Expired verify link masih valid | Pakai verify link dari 7 hari lalu |

---

## Upload & File Handling

### SSRF via Upload
| Attack | Cara Test |
|--------|-----------|
| Upload URL fetch | Upload URL `http://169.254.169.254/latest/meta-data/` |
| Webhook callback | Point webhook ke internal service |
| SVG with XInclude | Upload SVG yang fetch internal resource |
| Image processing SSRF | Upload crafted image → server proses → callback |

### Path Traversal
| Attack | Cara Test |
|--------|-----------|
| Filename traversal | `../../../etc/passwd` di filename |
| Zip slip | Upload ZIP dengan symlink ke /etc/shadow |
| CloudFront traversal | Path seperti `/..%2f..%2f..%2fadmin` |
| Static file serving | Cek `/static/..%2f..%2f..%2f.env`

---

## API & Rate Limit

### API Abuse
| Attack | Cara Test |
|--------|-----------|
| Pagination without bound | `?page=1&limit=1000000` → dump semua data |
| GraphQL introspection | `{__schema{types{name}}}` → leak semua model |
| GraphQL batching | Batch query untuk bypass rate limit |
| Mass assignment | Inject field `role:admin` di request body |
| REST parameter pollution | `?user_id=123&user_id=456` → multiple interpretation |

### Rate Limit Bypass
| Attack | Cara Test |
|--------|-----------|
| IP rotation | Via Tor / rotating proxy |
| Header spoof | `X-Forwarded-For: 1.2.3.4` dan variasi IP |
| Cookie-based limit | Hapus cookie → server kasih rate limit baru |
| Method variant | Ganti POST dengan PUT / PATCH / DELETE |
| Parameter difference | Tambah parameter random ke URL → bypass |
