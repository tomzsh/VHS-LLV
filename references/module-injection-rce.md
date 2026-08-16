# Server-Side Injection → RCE via Trusted Library Input

> When an **unauthenticated** (or low-priv) input reaches a server-side
> library that **compiles or interprets** its input (regex, filter, template,
> expression, query builder, deserializer), the "data" becomes code. Modern
> RCE bugs hide inside trusted dependencies that happily turn strings into
> `new Function` / `eval` / compiled regex / template render. Use at P3/P4.
> Taxonomy: CWE-94 / CWE-95 / CWE-1336 (template injection), CWE-917.

---

## 1. The pattern

```
User JSON/param ──► server passes it *unvalidated* ──► library
                        (sift, validator, jq, handlebars, lodash._template,
                         Python eval-ish helpers, deserializers)
                        ──► library compiles string as code ──► RCE
```

The vulnerability is not in your target's own code — it's in the **trusted
hand-off**: the app forwards attacker-controlled structure into a library
that has a code-execution mode. Grep for the *library calls*, then check
whether input reaches them unfiltered.

Keywords: `filter` (sift/jq), `$where`, `new Function`, `eval`, `template`,
`render`, `compile`, `match` with user regex, `deserialize`, `pickle`,
`yaml.load`, `Object.assign`, `merge` (prototype pollution), `gm`/`sharp`
(options object).

---

## 2. Proven case study (real, disclosed 2026)

### #3782701 — Mozilla Taskcluster · Unauthenticated RCE via GraphQL `sift $where` (Critical)
- **When:** submitted 2026-06-04 · disclosed 2026 · program **Mozilla**
- **Severity:** Critical (RCE on the instance running Firefox CI)
- **Vector (verbatim):** public GraphQL endpoint `/graphql` lets an
  unauthenticated caller execute arbitrary JS in the web-server Node process.
  The query's `filter` argument is a **free-form JSON object** passed directly
  into the **sift** library (v17.1.3). sift compiles a `$where` string with
  `new Function("obj", "return " + params)` and executes it. `CSP_ENABLED` was
  not set on the deployment → string `$where` executed.
- **Impact:** read full process env — PostgreSQL credentials, Taskcluster
  deployment access token, Auth0/GitHub OAuth client secrets, Pulse
  credentials, DB column-encryption keys. One POST, no auth.
- **Root-cause chain:** (1) `filter` goes straight into `sift(filter)` with no
  validation; (2) sift 17.1.3 turns `$where` string into code via
  `new Function` unless `CSP_ENABLED`.
- **Lesson:** check **library version + its dangerous modes**, and whether the
  deployment sets the kill-switch env (`CSP_ENABLED` here).
- **Link:** `https://hackerone.com/reports/3782701`

---

## 3. Detection checklist (P2/P3)

- [ ] Grep server code for **user-input → library** hand-offs: `filter`,
      `sift`, `match`/regex-from-input, `template`, `render`, `compile`,
      `deserialize`, `load`, `eval`, `Function(`, `merge`, `clone` (deep).
- [ ] For each: is the input **validated/schema'd** before the call, or passed
      as-is? (free-form JSON object = red flag)
- [ ] What does the library do with **string vs object** input? Does it have
      a code-exec mode (`$where`, `new Function`, compiled template, regex
      flags)? Check the installed version.
- [ ] Is there a **kill-switch env** (`CSP_ENABLED`, sandbox flag) and is it
      actually set in the deployment?
- [ ] Is the endpoint **unauthenticated**? (taskcluster: public `/graphql`)
- [ ] Can the result be observed OOB (DNS/callback, timing, error text)?
      If not, RCE is still provable via **error-based** or **deferred**
      detection (e.g. sleep via `new Function` body) — smallest safe proof.

---

## 4. PoC harness (read-only / controlled, authorized target only)

```bash
# 1) benign structure probe — does the endpoint accept arbitrary JSON?
curl -s -X POST "https://TARGET/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }","variables":{"filter":{"$where":"true"}}}'

# 2) controlled code-exec proof WITHOUT shelling out:
#    make the compiled function return a value that changes the response shape
#    (e.g. $where that always matches) and compare vs $where that never matches
#    => proves the string became code.

# 3) if sandboxed env exec is required and explicitly authorized, use an OOB
#    DNS/log callback with a UNIQUE token (never exfiltrate real secrets).

# 4) version check for the library:
grep -E '"sift"|"handlebars"|"lodash"' package-lock.json | head
```

**RoE:** RCE PoCs are controlled-impact — require explicit per-action approval;
prefer proving code execution via response-shape difference or OOB callback,
not shell commands, and **never** read real secrets beyond proving access.

---

## 5. Severity

- Unauth RCE → **Critical** (compromise of the instance + secrets).
- Auth RCE → High–Critical depending on privilege.
- Injection into library *without* observed code exec (only DoS/type errors) →
  Medium-High, still worth reporting (usually one step from RCE).
- Cite: CWE-94/95/1336, CWE-917; use #3782701 (sift `$where`) as the
  real-world template.
