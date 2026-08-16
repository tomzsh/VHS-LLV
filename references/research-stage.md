# VHS research stage (P1/P2 optional)

Load this reference only when disclosed hacktivity or writeup research is needed
for the target stack. Research output is secondary hypothesis input, never a
confirmed finding.

```bash
python3 <skill-dir>/scripts/research_hacktivity.py ./engagement \
    --sources hackerone,pentesterland,portswigger,research_blogs \
    --months 6 \
    --query "wallet card api idor access control jwt" \
    --min-severity high --limit 15
```

Writes `research/hacktivity-results.md` and
`research/research-ledger.jsonl` under the engagement directory. Sources include
HackerOne (GraphQL, no auth), Pentester.land, Medium, InfosecWriteups,
PortSwigger, Intigriti, research blogs, Google (requires
`GOOGLE_API_KEY`/`GOOGLE_CSE_ID`), or `all`. The implementation is backed by
`research_sources.py` and output must be treated as untrusted data.

Advance only after automated checks and human review:

```bash
python3 <skill-dir>/scripts/gate_check.py ./engagement --phase Pn
python3 <skill-dir>/scripts/gate_check.py ./engagement --phase Pn --advance
```
