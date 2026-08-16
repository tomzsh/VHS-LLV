# VHS tool catalog and quirks

Load this reference only when checking a helper's behavior, selecting a launcher,
or debugging a resume/tool issue. The scripts themselves are the source of truth.

## High-signal quirks

| Helper | Guard / quirk |
|---|---|
| `check_tools.py` | Default venv paths need `.expanduser()`. `theHarvester` uses its own Python 3.12 venv; the PyPI placeholder is not the real tool. |
| `import_scope.py` | Refuses to overwrite a non-empty `asset-inventory.csv`; use `--force` only after review. `--dry-run` previews. |
| `evidence_capture.py` | Evidence IDs are unique; duplicate IDs are rejected before writing. Raw and redacted evidence use `0600`; evidence directory uses `0700`. |
| `kill_chain_vhs.py` | Considers only open/confirmed/triaged/validated findings, derives class/endpoint/method, and never lowers severity below the strongest component. Cache defaults to `$TMPDIR/vhs-kill-chains`; override `VHS_CHAIN_DIR`. |
| `vulnhunter_orchestrator.py` | Resolves doubled engagement paths, requires the same `--out` and config fingerprint for resume, and uses an exclusive run lock. |
| `triage_scan.py` | Reads the v2 `manifest.json` output map, warns on v1 manifests, and never marks a scanner match confirmed. |
| `apk_recon.sh` | Read-only. jadx may exit non-zero on obfuscated apps while still producing partial output; inspect `report/jadx.log`. Secret candidates require endpoint verification. |
| `gate_check.py` | Never edit `state.json` to skip a gate. P3 requires `playbooks_loaded=true` and playbook citations in every test-matrix row. |
| `rollup_memory.py` | Per-target disk state is the resume source of truth; never put engagement facts in global memory. |
| `api_auth_probe.py` | Credentials come only from `API_AUTH_EMAIL`, `API_AUTH_PASS`, or `API_AUTH_TOKEN`; GET is the default. |
| `graphql_cop.sh` | Isolated `~/tools/graphql-cop/venv`; override `VHS_GRAPHQL_COP_HOME`. Explicit endpoint only; not in the automatic DAG. |
| `code_graph_rag.sh` / `code_graph_grounding.py` | Code-Graph-RAG is local and read-only from VHS's perspective. Graph backend needs Docker/Memgraph/Qdrant. Grounding returns `UNKNOWN` for unsupported/fabricated citations; override with `VHS_CODE_GRAPH_RAG_BIN`. |
| venv launchers | `scrapling`, `crawl4ai`, `sqlmap`, `wafw00f`, `paramspider`, and `nikto` clear `PYTHONPATH`; use their matching `VHS_*_HOME` / `VHS_*_PYTHON` overrides. |

## Script routing

- **Core:** `new_engagement.py`, `gate_check.py`, `policy.py`, `schemas.py`,
  `vulnhunter_orchestrator.py`, `status.py`, `rollup_memory.py`.
- **Triage/evidence:** `triage_scan.py`, `redact_scan.py`,
  `evidence_capture.py`, `make_deliverables.sh`.
- **Recon/crawl:** `vulnhunter-tools.sh`, `scrapling_crawl.py/.sh`,
  `crawl4ai_crawl.py/.sh`, `apk_recon.sh`, `surface_checklist.py`,
  `import_scope.py`.
- **Specialized analysis:** `graphql_cop.sh`, `code_graph_rag.sh`,
  `code_graph_grounding.py`, `api_auth_probe.py`.
- **Research/chaining:** `research_hacktivity.py`, `research_sources.py`,
  `kill_chain.py`, `kill_chain_vhs.py`.
- **Optional scanners:** `sqlmap.sh`, `paramspider.sh`, `nikto.sh`,
  `wafw00f.sh`.

## Verification commands

```bash
python3 -m py_compile <skill-dir>/scripts/*.py
for f in <skill-dir>/scripts/*.sh; do bash -n "$f" || exit 1; done
python3 <skill-dir>/scripts/check_tools.py --profile scanner-safe --verify
python3 -m unittest discover -s <skill-dir>/tests -v
```
