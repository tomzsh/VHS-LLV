# Office Deliverables via officecli (P6)

Generate submission-ready Office files from the engagement ledgers with
`officecli` (single binary, `~/.local/bin/officecli`, v1.0.140+). Always prefer
the highest layer: L1 read → L2 DOM edit → L3 raw XML. When unsure about a
property name, run `officecli help <format> <element>` before guessing.

## When to use

- Program wants the report as `.docx` (common for H1/BC attachments);
- findings summary / evidence inventory as `.xlsx` (sortable, filterable);
- executive briefing as `.pptx`;
- redacted evidence export needs a document wrapper.

## General rules

- Work from the **redacted** evidence (`evidence/redacted/`) and the final
  markdown report — never paste raw tokens/PII into Office files.
- Paths are 1-based (`/body/p[3]`); `--index` is 0-based (Excel row/col add is
  1-based). Quote bracket paths in zsh/bash: `'/body/p[1]'`.
- All attributes go through `--prop key=value`. `$` in text needs single
  quotes (`--prop text='$15M'`), `\n` needs `\\n`.
- Resident mode auto-manages file locks; run `close` only before another
  program reads the file.

## Final report → .docx

```bash
# 1. Create + title
officecli create final-report.docx
officecli add final-report.docx /body --type paragraph --prop text="Security Assessment — <Target>" --prop style=Title

# 2. Headings per finding (from reporting-templates.md structure)
officecli add final-report.docx /body --type paragraph --prop text="Executive Summary" --prop style=Heading1
officecli add final-report.docx /body --type paragraph --prop text="<exec summary text>" --prop style=Normal

# 3. Findings table
officecli add final-report.docx /body --type table --prop rows=6 --prop cols=5
officecli set final-report.docx '/body/tbl[1]/tr[1]/tc[1]' --prop text="ID"
officecli set final-report.docx '/body/tbl[1]/tr[2]/tc[1]' --prop text="F-001"
officecli set final-report.docx '/body/tbl[1]/tr[2]/tc[2]' --prop text="High"
# ...

# 4. Tracked find-and-replace for one last redaction pass
officecli set final-report.docx / --find 'Bearer ' --replace 'Bearer [REDACTED]' --prop revision.author=Researcher
```

Verify: `officecli view final-report.docx issues` then `officecli validate final-report.docx`.

## Findings summary → .xlsx

Fastest path from a vhs ledger CSV — native `import` (also works from stdin):

```bash
# CSV/TSV → sheet, header row becomes AutoFilter + frozen pane
officecli import findings-summary.xlsx /Sheet1 --file findings-index.csv --header

# or pipe directly (no temp file needed)
cat findings-index.csv | officecli import findings-summary.xlsx /Sheet1 --stdin --format csv --header

# start at a specific cell, e.g. leave column A for row numbers
officecli import findings-summary.xlsx /Sheet1 --file evidence-ledger.csv --header --start-cell B1
```

Manual column writes when you want to control formatting:

```bash
officecli create findings-summary.xlsx
officecli set findings-summary.xlsx /Sheet1/A1 --prop value="ID" --prop bold=true
officecli set findings-summary.xlsx /Sheet1/B1 --prop value="Severity"
officecli set findings-summary.xlsx /Sheet1/C1 --prop value="Title"
officecli set findings-summary.xlsx /Sheet1/A2 --prop value="F-001"

# Sort + filter-ready
officecli set findings-summary.xlsx /Sheet1 --prop sort="B asc" --prop sortHeader=true
officecli add findings-summary.xlsx /Sheet1 --type autofilter --prop range="A1:C20"
```

Evidence inventory: import `evidence-ledger.csv` the same way (evidence_id,
finding_id, observation, redaction_status) — keep `redaction_status` column so
the reviewer sees what was cleared.

## Executive briefing → .pptx

```bash
officecli create briefing.pptx
officecli add briefing.pptx / --type slide --prop title="Findings Overview" --prop background=1A1A2E
officecli add briefing.pptx '/slide[1]' --type shape --prop text="3 High, 2 Medium, 1 Low" --prop x=2cm --prop y=5cm --prop font=Arial --prop size=28
```

## Bulk structured edits

For multi-cell/multi-node edits, use `batch` (atomic since v1.0.137):

```bash
echo '[
  {"command":"set","path":"/Sheet1/A2","props":{"value":"F-001"}},
  {"command":"set","path":"/Sheet1/B2","props":{"value":"High"}}
]' | officecli batch findings-summary.xlsx --json
```

Or round-trip an existing file: `officecli dump findings-summary.xlsx` → edit
JSON → `officecli batch findings-summary.xlsx --input edits.json`.

## Pitfalls

- Do NOT generate Office files from `evidence/raw/` — redact first.
- `shape[1]` in PPT is usually the title placeholder; use `shape[2]+` for content.
- Excel `--index` on row/col add is 1-based (OOXML RowIndex), unlike other adds.
- `find`/`replace` on xlsx supports text only, no format props.
- No match on `set --find` is silent success — check `--json` `"matched"` count
  when the replacement matters.
