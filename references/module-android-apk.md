# Module — Android APK Static Analysis 📱

Trigger: an in-scope asset is an Android app (Play Store id, `com.*` bundle, or a
provided `.apk`/`.aab`/`.xapk`). Static analysis of a mobile client routinely
leaks API endpoints, hard-coded secrets, and exported components that widen the
server-side attack surface.

> Scope note: the APK is only a **map** to the server-side attack surface. Test
> endpoints/logic bugs against the **authorized in-scope hosts**, not by attacking
> other users' devices. Decompiling an APK you are authorized to test is static
> review; do not install malware, target other users, or exfiltrate real data.

---

## 0. Acquire the APK

| Source | How |
|--------|-----|
| Direct download | Program provides the `.apk`/`.aab` |
| Play Store | `apkeep -a com.target.app ./` (downloads by package id) |
| Split APKs (`.xapk`/`.apks`) | unzip, then merge or analyze `base.apk` |
| On-device pull | `adb shell pm path com.target.app` → `adb pull <path>` |

For an App Bundle / split set, analyze `base.apk` first; config splits rarely
hold code.

## 1. Decompile

**jadx** — Java source (primary). For a large APK (60MB+, tens of thousands of
classes) run it in the background with an absolute output path; an interrupted
run leaves a partial decompile, so verify completeness afterward.

```bash
# quick (foreground, small APK)
jadx -d ./out/jadx "target.apk"

# large APK: background + deobfuscation, then verify class count
jadx --deobf -d /abs/path/out/jadx "target.apk"   # run backgrounded for big apps
```

**apktool** — manifest, resources, and smali (needed for `AndroidManifest.xml`
in readable form + `res/`, `assets/`, string resources).

```bash
apktool d -f -o ./out/apktool "target.apk"
```

Use both: jadx for logic/secrets, apktool for the decoded manifest and resources.
(`aapt dump badging target.apk` gives package id, version, permissions, and
launchable activity fast.)

## 2. AndroidManifest.xml — the first read

| Check | What to look for | Why it matters |
|-------|------------------|----------------|
| `android:exported="true"` | activities / services / receivers / providers reachable by other apps | IPC attack surface; often unintended |
| `android:debuggable="true"` | debug build shipped to prod | runtime hooking, data access |
| `android:allowBackup="true"` | app data extractable via `adb backup` | local data exposure |
| Deep links | `<intent-filter>` with `<data android:scheme=.. host=..>` | unvalidated deep-link → open redirect, auth bypass, IDOR |
| `<provider>` + `grantUriPermissions` | exported ContentProvider, path permissions | file/data leak, SQLi in provider |
| `usesCleartextTraffic="true"` | HTTP allowed | MITM on API traffic |
| `networkSecurityConfig` | pins, trust anchors, cleartext domains | pinning strength / bypassable |
| Custom permissions | `protectionLevel` (normal vs signature) | privilege boundary |

```bash
# exported components (from apktool-decoded manifest)
grep -nE 'android:exported="true"' out/apktool/AndroidManifest.xml
# deep-link schemes/hosts
grep -nE '<data ' out/apktool/AndroidManifest.xml
```

## 3. Exported-component PoC (adb)

For each `exported=true` component, craft a proof of concept and record the exact
command as evidence.

```bash
# exported Activity (parameter/intent handling, unauth screen access)
adb shell am start -n "com.target.app/.SomeExportedActivity"
adb shell am start -n "com.target.app/com.target.app.DeepLinkActivity" \
  -a android.intent.action.VIEW -d "targetapp://path?param=value"

# exported Service / Broadcast
adb shell am startservice -n "com.target.app/.ExportedService"
adb shell am broadcast   -n "com.target.app/.ExportedReceiver" --es key value

# ContentProvider read (path traversal / SQLi in the authority)
adb shell content query --uri content://com.target.app.provider/table
```

Severity depends on impact: a debug-only screen = Low/Info; an exported Activity
that changes account state or exposes another user's data = High. Do not spoof
another real user; use your own test account and synthetic input.

## 4. Secret & endpoint hunting (jadx sources + resources)

```bash
JADX=out/jadx/sources
# API base URLs / endpoints
grep -rniE 'https?://[a-z0-9.-]+(/[a-z0-9/_-]+)?' "$JADX" | grep -viE 'schemas\.android|w3\.org|example\.com' | sort -u
# hard-coded credentials / keys (the classic: API_ID / API_KEY / SIGN / TENANT in an RPC connector)
grep -rniE '(api[_-]?key|secret|passwd|password|token|app[_-]?id|app[_-]?key|tenant|sign[_-]?authcode|client[_-]?secret)\s*=\s*"' "$JADX" | head -50
# Firebase / cloud
grep -rniE 'firebaseio\.com|firebase|googleapis|amazonaws|s3\.|storage\.bucket' "$JADX" out/apktool/res | head
# strings.xml secrets (often google_api_key, maps key, gcm sender)
grep -rniE '(api_key|google|secret|token)' out/apktool/res/values/strings.xml
```

Confirm before reporting: a hard-coded value that is a **public** client id
(OAuth public client, Firebase web config, Maps key with referrer restriction) is
usually **not** a finding. A key that grants server-side privilege, signs
requests, or accesses a paid/admin API is. Verify the key actually works against
an in-scope endpoint before claiming impact.

## 5. Network & transport

| Check | Where | Finding shape |
|-------|-------|---------------|
| Cleartext HTTP endpoints | sources + `network_security_config.xml` | MITM of API traffic |
| Trust-all / custom TrustManager | `checkServerTrusted` empty, `HostnameVerifier` returns true | TLS bypass |
| SSL pinning | OkHttp `CertificatePinner`, network-security-config `<pin-set>` | note strength (bypass only with runtime tooling, out of static scope) |
| WebView | `setJavaScriptEnabled(true)`, `addJavascriptInterface`, `loadUrl` of external | XSS→native bridge, RCE-ish |
| Exported deep link → WebView | deep-link Activity feeds URL into a WebView | open redirect / JS injection |

```bash
grep -rniE 'setJavaScriptEnabled|addJavascriptInterface|setAllowFileAccess|checkServerTrusted|HostnameVerifier|CertificatePinner' out/jadx/sources | head
```

## 6. Local storage & logging

- `SharedPreferences` writing tokens/PII in cleartext; `MODE_WORLD_READABLE`.
- SQLite DBs / files under `getExternalStorage*` (world-readable historically).
- `Log.d/v/i` leaking tokens, request bodies, or PII in production.
- Hard-coded encryption keys / static IVs for "encrypted" local data.

```bash
grep -rniE 'getSharedPreferences|MODE_WORLD|getExternalStorage|Log\.(d|v|i|e)\(' out/jadx/sources | head
```

## 7. Findings Checklist

| Finding | Typical severity | FP check |
|---------|:----------------:|----------|
| Exported Activity changes state / exposes other-user data | High | needs the app's own signature permission? just a debug screen? |
| Exported ContentProvider read/SQLi | High | authority actually reachable + returns data? |
| Hard-coded server-privilege API key/secret | High | key works vs in-scope endpoint? public client id (not a secret)? |
| Deep link → auth bypass / open redirect / IDOR | Medium-High | server re-validates? scheme actually registered? |
| Trust-all TLS / disabled pinning | Medium | prod build? config vs code? |
| WebView `addJavascriptInterface` + external URL | Medium-High | interface exposes sensitive methods? URL attacker-controlled? |
| `debuggable=true` / `allowBackup=true` in prod | Low-Medium | actually shipped in the release build? |
| Token/PII in logs or cleartext SharedPreferences | Low-Medium | reachable without root? real secret? |
| Endpoint disclosure only (no secret) | Info | feeds P2 surface map, not a standalone bug |

## 8. Feed back into the workflow

Endpoints and hosts recovered from the APK are **hypotheses** — normalize them,
re-check scope, and route server-side testing through the standard P2→P4→P5 flow
(`api_auth_probe.py`, orchestrator). Record the decompiled evidence
(`AndroidManifest.xml` excerpt, the offending source snippet, the adb PoC
command) via `evidence_capture.py`, then triage in P5.
