# VHS operator quick commands

Load this reference when an exact helper command is needed. Commands are
read-only unless the command itself is explicitly a state-changing workflow.

```bash
# engagement status
python3 <skill-dir>/scripts/status.py ./engagement

# import scope CSV; preview first and never clobber non-empty inventory
python3 <skill-dir>/scripts/import_scope.py ./engagement --scope program-scope.csv --dry-run
python3 <skill-dir>/scripts/import_scope.py ./engagement --scope program-scope.csv

# surface checklist
python3 <skill-dir>/scripts/surface_checklist.py ./engagement --out checklist.md

# Android APK static recon
bash <skill-dir>/scripts/apk_recon.sh /path/to/target.apk -o ./engagement/apk-recon
VHS_JADX_ARGS=--deobf bash <skill-dir>/scripts/apk_recon.sh /path/to/target.apk -o ./engagement/apk-recon

# Code Graph SAST + deterministic grounding
bash <skill-dir>/scripts/code_graph_rag.sh start --repo-path /path/to/source \
    --update-graph --output ./engagement/code-graph.json
python3 <skill-dir>/scripts/code_graph_grounding.py context \
    --graph ./engagement/code-graph.json --node-id 1

# disclosed research; see research-stage.md for details
python3 <skill-dir>/scripts/research_hacktivity.py ./engagement \
    --sources hackerone,portswigger,research_blogs --months 6 \
    --query "wallet card api idor jwt" --min-severity high --limit 15

# P3 playbook gate
python3 <skill-dir>/scripts/gate_check.py ./engagement --phase P3 --mark-playbooks
python3 <skill-dir>/scripts/gate_check.py ./engagement --phase P3 --advance

# per-target memory rollup
python3 <skill-dir>/scripts/rollup_memory.py ./engagement --write

# authenticated read-only API probe; credentials only from environment
python3 <skill-dir>/scripts/api_auth_probe.py https://api-uat.target.com \
  --engagement ./engagement --endpoints /account/info --token-path access_token

# evidence capture
python3 <skill-dir>/scripts/evidence_capture.py ./engagement \
    --evidence-id EV-004 --asset AST-004 --test TST-002 \
    --observation "cross-account response" --file response.json

# P6 deliverables
bash <skill-dir>/scripts/make_deliverables.sh ./engagement
```

For kill-chain details, scanner triage, or resume behavior, load
`tool-catalog.md` and the current phase reference rather than this entire file.
