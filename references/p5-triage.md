# P5 — Root Cause, Severity & Chains

## Objective

Convert validated behavior into deduplicated, defensible findings without overstating impact.

## Finding qualification

A confirmed finding needs:

- broken security invariant;
- affected component and scope;
- prerequisites and attacker position;
- minimal reliable reproduction;
- negative control or equivalent comparison;
- exact demonstrated capability;
- realistic impact;
- evidence IDs;
- root cause;
- remediation direction.

Keep weak signals as observations or inconclusive hypotheses.

## Root-cause deduplication

Group variants when they share:

- the same missing authorization decision;
- the same token-validation defect;
- the same unsafe trust in client-controlled state;
- the same storage or deployment misconfiguration;
- the same parser or normalization boundary;
- the same business-rule omission.

Keep separate findings when remediation owners or controls are materially different, or when one remains exploitable after the other is fixed.

## Chain analysis

Represent a chain as:

```text
precondition -> primitive -> boundary crossed -> action gained -> impact
```

For each link, record evidence and confidence. Do not use a speculative link to upgrade severity.

To enumerate *candidate* chains from the findings you already have, run:

```bash
python3 <skill-dir>/scripts/kill_chain_vhs.py <engagement-dir> \
    --output-format markdown --novel
```

It reads `findings-index.csv`, infers each finding's bug class / endpoint from
its title, root cause, and impact text, and matches known composite patterns
(writing `kill-chains.md`). Only findings with status `open`, `confirmed`,
`triaged`, or `validated` are chained, and a chain's severity is always ≥ the
strongest matched finding. Treat its output as **candidate** chains — each link
still needs the per-link evidence and confidence above before the combined
severity is defensible.

Distinguish:

- **combined exploit chain:** links are jointly required for one impact;
- **variant:** same root cause on another endpoint;
- **amplifier:** increases scale or reliability but is not required;
- **independent finding:** exploitable and remediable on its own.

## Severity

Use the program's impact taxonomy and exclusions first. Then evaluate:

- attacker prerequisites and user interaction;
- privilege and tenant delta;
- confidentiality, integrity, availability, and financial effect;
- affected user and asset population;
- reliability and repeatability;
- reversibility and detection;
- compensating controls;
- demonstrated versus hypothetical impact.

Then cross-reference `taxonomy-rating.md` (source: `vulnerability-rating-taxonomy.json`):

1. Match the finding to its category/subcategory/variant in the taxonomy.
2. Use the variant's `priority` as the **baseline** severity (1=critical,
   2=high, 3=medium, 4=low, 5=informational/NQ).
3. Adjust with the evaluation above and the program's own severity rules.
4. Never assign severity from bug class alone — the taxonomy's own variants
   show the range (e.g. IDOR spans priority 1 (modify/view sensitive, iterable)
   to 5 (view non-sensitive, GUID)). Record the taxonomy variant in the
   severity rationale.

Do not assign severity from bug class alone. “IDOR,” “SSRF,” “XSS,” “key exposure,” or “admin endpoint” can span multiple severities.

Use CVSS only if requested or customary, and explain environmental assumptions. Keep confidence separate from severity.

## Required artifacts

Each row in `findings-index.csv` must include:

- finding ID and title;
- root cause;
- affected assets;
- status;
- severity and severity rationale;
- confidence;
- prerequisite;
- demonstrated impact;
- evidence IDs;
- duplicate/chain relationships;
- remediation owner when known;
- disclosure and retest state.

## Gate

Pass when:

1. every confirmed finding maps to evidence;
2. every severity maps to demonstrated impact and program rules;
3. duplicates and chains are resolved;
4. speculative impact is clearly separated;
5. remediation addresses root cause, not only one request.
