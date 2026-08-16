# File Upload — Filter Bypass, Content-Disposition, and Stored-Content Attacks (2026)

> Upload endpoints are a dense bug surface: the file passes *some* filter, then
> gets stored and re-served. Every gap between **what the filter allows**,
> **what the storage accepts**, and **how the file is served** is a finding:
> XSS via SVG/HTML, path traversal via filename, malware hosting, stored
> content served inline, MIME confusion, decompression bombs. Use at P3/P4.
> Taxonomy: CWE-434 (unrestricted upload), CWE-79 (XSS), CWE-22 (path
> traversal), CWE-436 (interpretation conflict).

---

## 1. The three-layer mental model

A safe upload needs: (1) **type validation** (extension+content sniffing),
(2) **neutral storage** (outside webroot / random name / non-executable),
(3) **safe serving** (`Content-Disposition: attachment`, `X-Content-Type-Options:
nosniff`, sandboxed CSP). Most real bugs are layer-3 or layer-1 gaps:

- **Layer 1 gap — filter bypass:** blocklist of extensions/content signatures
  that misses a variant (SVG with embedded script, polyglot, double extension,
  trailing dot/space, case tricks, `%00`, mime sniffing mismatch).
- **Layer 2 gap — storage/execution:** file lands where it can be executed
  (webroot, served dir), filename kept attacker-controlled → path traversal.
- **Layer 3 gap — serving:** stored user content served with
  `Content-Disposition: inline` or without nosniff → **stored XSS on the
  upload domain**, self-propagating when the upload renders user content.

---

## 2. Proven case study (real, disclosed 2026)

### #3606773 — phpBB · Stored XSS via SVG Upload — blocklist bypass & 256-byte scan limit
- **When:** submitted 2026-03 · disclosed **2026-07-30** · program **phpBB**
- **Severity:** Medium (6.7)
- **Class:** layer-1 (filter bypass) + layer-3 (inline serving)
- **Vector (verbatim):** XSS in 4.0.0-a2-dev when an admin configures **SVG
  image uploads as a non-image upload type**. The `check_content()` blocklist
  is bypassable and the content scan has a **256-byte limit** — payload beyond
  the first 256 bytes is not inspected. Additionally, **non-inline served
  files must never receive `Content-Disposition: inline`**; serving the stored
  SVG inline enables script execution in the user's origin. Self-propagating
  worm class (the SVG is re-served to other users).
- **Not exploitable on 3.3.15** (other protections) — but hardening gap
  remains.
- **Lesson:** (a) 256-byte scan limits are trivially bypassed by padding the
  payload past the window; (b) blocklist ≠ allowlist; (c) `inline` serving of
  any user file = stored XSS surface.
- **Link:** `https://hackerone.com/reports/3606773`

---

## 3. Detection checklist (P2/P3)

- [ ] Find every upload endpoint (avatar, attachment, image, doc, sound,
      theme, import, profile, export-then-upload). Grep
      `multipart`, `upload`, `file`, `attachment`, `Content-Type`.
- [ ] **Type validation:** is it an allowlist of extensions+magic bytes, or a
      blocklist? Try: `.svg`, `.svgz`, `.html`, `.htm`, `.xhtml`, `.xml`,
      `.webp` (polyglot), `.jpg` with embedded HTML, double extension
      `x.php.jpg`, trailing `x.php.`, case `x.PhP`, `%00`/null byte, Unicode
      homoglyph.
- [ ] **Scan window:** does content sniffing scan the whole file or first N
      bytes? (256-byte limit = bypass by padding — #3606773)
- [ ] **Storage:** random filename? outside webroot? non-executable dir?
      Is the file served from a static/CDN path under the app origin?
- [ ] **Serving:** check response headers of the *stored* file:
      `Content-Disposition` (inline vs attachment), `X-Content-Type-Options:
      nosniff`, CSP on that route. Inline + no nosniff = XSS candidate.
- [ ] **Re-upload of stored file:** does the platform re-render user content
      (avatar in admin, preview, image proxy)? Self-XSS → stored.
- [ ] **Path traversal in filename:** `../../etc/passwd` or `..%2f` in the
      filename/relative path param.

---

## 4. PoC harness (read-only / controlled, authorized target only)

```bash
# 1) filter bypass probe — SVG XSS (classic; only against authorized test targets)
cat > poc.svg <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>
EOF
curl -s -F "file=@poc.svg;type=image/svg+xml" "https://TARGET/api/upload" -o /data/up.json

# 2) scan-window bypass (#3606773): pad 300 bytes before payload
python3 - <<'PY'
open('/tmp/pad.svg','w').write('A'*300 + '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
PY
curl -s -F "file=@/tmp/pad.svg;type=image/svg+xml" "https://TARGET/api/upload" -o /data/up2.json

# 3) serving check — GET the stored file and inspect headers (never trigger XSS)
curl -s -D - -o /dev/null "https://TARGET/uploads/<stored-name>.svg"
#   look for: Content-Disposition: inline / missing nosniff / no CSP
```

**RoE:** upload only to test account; never actually execute stored XSS
against other users; proof = file accepted + served inline + (if needed) a
benign `<script>` that does nothing; never use real malware payloads. Record
baseline (reject case), bypass case, and serving-header evidence.

---

## 5. Severity

- Stored XSS via upload, **self-propagating / admin context** → High
  (phpBB rated Medium 6.7 for a dev-version gap; production admin-context
  upload XSS usually High).
- Filter bypass allowing **executable** content (PHP/webshell) in webroot →
  **Critical** (RCE).
- Path traversal in filename → file write → High–Critical depending on target.
- Serving header gap (inline without nosniff) alone → Medium (hardening).
- Cite: CWE-434/79/22/436; case #3606773 (SVG + 256-byte scan limit +
  inline-serving).