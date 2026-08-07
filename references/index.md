# Reference Index

Use this file as the routing table. Read every selected file completely before acting.

## Always load

- `operating-contract.md`
- `non-qualifying.md` — always check before classifying a finding (saves effort on non-qualifying items)
- `taxonomy-rating.md` — severity taxonomy (source: `vulnerability-rating-taxonomy.json`); load from P1 onward for invariant mapping + P1-P2 hunting checklist, mandatory at P5 for severity baseline
- The current phase file
- `evidence-standard.md` during P4, P5, or any PoC review
- `reporting-templates.md` during P5 or P6
- `officecli-reporting.md` during P6 when the deliverable needs `.docx`/`.xlsx`/`.pptx`
- `oidc-session-refresh.md` during P3/P4 when the target uses Keycloak/OIDC and authenticated probing is needed

## Current phase

| State | Load |
| --- | --- |
| P0 | `p0-authorization.md` |
| P1 | `p1-modeling.md` |
| P2 | `p2-recon.md` |
| P3 | `p3-test-design.md` |
| P4 | `p4-validation.md`, `evidence-standard.md` |
| P5 | `p5-triage.md`, `evidence-standard.md`, `reporting-templates.md` |
| P6 | `p6-report-retest.md`, `evidence-standard.md`, `reporting-templates.md`, `officecli-reporting.md` |

## Quick status

```bash
python3 <skill-dir>/scripts/status.py <engagement-dir>
python3 <skill-dir>/scripts/surface_checklist.py <engagement-dir> --out checklist.md
```

## Target modules

Load all modules that match the architecture:

- `module-web-api-identity.md`: browsers, mobile backends, REST, GraphQL, WebSocket, auth, SSO, sessions, tenants, admin/support tools.
- `module-cloud-ai-supply-chain.md`: cloud, serverless, storage, queues, CI/CD, dependencies, logs, AI/LLM, RAG, tools, agents.
- `module-web3-fintech.md`: wallets, signing, contracts, relayers, bridges, DeFi, payments, custodial flows, balances, ledgers, KYC.
- **`module-business-logic.md`**: payment manipulation, race condition, ATO, JWT, OIDC, SSRF, upload, rate limit bypass. — Always load in MODE:CRITICAL.
- **`module-ai-mcp.md`**: MCP server OAuth, dynamic client registration, CLI installer supply chain, AI plugin manifests, QR login, MCP tool enumeration. — Load when the target has MCP/CLI/AI integration.
- **`module-android-apk.md`**: Android APK static analysis — decompile (jadx/apktool), AndroidManifest (exported components, deep links, debuggable/backup), hard-coded secrets, endpoints, WebView/TLS, adb PoC. — Load when an in-scope asset is an Android app (`.apk`/Play Store id/`com.*` bundle); driven by `scripts/apk_recon.sh`.

## Search hints

For long engagements, search the ledgers by immutable IDs:

```bash
rg -n 'HYP-[0-9]{3}|TST-[0-9]{3}|EV-[0-9]{3}|F-[0-9]{3}' <engagement-dir>
```

Search references by concept before loading extra modules:

```bash
rg -n -i 'oauth|tenant|graphql|websocket|relayer|ledger|rag|pipeline' references/
```
