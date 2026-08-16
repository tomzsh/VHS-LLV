# Reference Index

Use this file to identify reference paths. `context-router.md` is the single
progressive-loading policy authority; follow it before opening a selected
playbook or reference.

## Core/load policy

- `operating-contract.md`, `index.md`, and the current phase file.
- `non-qualifying.md` before classifying a finding.
- `evidence-standard.md` before P4/P5 evidence review.
- `taxonomy-rating.md` from P1 onward when modeling or rating severity.
- `attack-playbooks/00-index.md` from P3 onward.
- `reporting-templates.md` and `officecli-reporting.md` only for P6 deliverables.
- `module-index.md` at P3/P4; load only matching target modules.
- `code-graph-rag-integration.md` only for source/SAST/code-graph work.
- `web2-2026-references.md` when one of the requested Web2 vulnerability classes
  is in scope.
- `account-otp.md` only for signup/OTP work.
- `research-stage.md` only for disclosed research.
- `operator-commands.md`, `tool-catalog.md`, or `crawler-extras.md` only when
  their command/catalog/stage is needed.

## Current phase

| State | Load |
| --- | --- |
| P0 | `p0-authorization.md` |
| P1 | `p1-modeling.md` |
| P2 | `p2-recon.md` |
| P3 | `p3-test-design.md`, `attack-playbooks/00-index.md`, `module-index.md` (pick the module matching in-scope surface) |
| P4 | `p4-validation.md`, `evidence-standard.md`, `attack-playbooks/<type>.md` (re-check before each round) |
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
