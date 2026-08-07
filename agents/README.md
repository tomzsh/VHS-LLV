# Multi-agent contract

Hermes is the orchestrator. Each agent writes only inside `agents/<name>/` and
returns step status (`ok`, `error`, or `timeout`) without killing sibling agents.

## Dependency graph

```text
Recon Agent ──> Crawl Agent ──┬──> Discovery Agent ──┐
                              └──> Scan Agent ───────┼──> Report Agent
Recon metadata ──────────────────────────────────────┘
```

- **Recon Agent:** `subfinder`/`assetfinder`/passive `amass`, `dnsx`, `httpx`;
  optional `naabu` only with explicit RoE permission.
- **Crawl Agent:** `gau`, `katana`; optional `waymore`. Produces URL, JS, and API candidates.
- **Discovery Agent:** `uro`, `arjun`, and opt-in `ffuf` when a real wordlist is supplied.
- **Scan Agent:** critical/high `nuclei`; optional parameterized-URL `dalfox` pass.
- **Report Agent:** combines manifests and counts. It never labels scanner matches as confirmed.

`LinkFinder` and `gf` remain useful analyst helpers, but are not hard dependencies:
the orchestrator already extracts JavaScript/API candidates without assuming a
particular LinkFinder installation layout, while `gf` patterns vary by operator.
