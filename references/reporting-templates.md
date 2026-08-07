# Reporting Templates

## Final report

```markdown
# Security Assessment — <Target>

## Executive Summary
<What was assessed, overall risk, strongest confirmed themes, and limitations.>

## Engagement
- Owner/program:
- Authorization source:
- Assessment dates:
- Environment/build:
- Researcher:
- Permission mode:
- Test identities:

## Scope
### In scope
| Asset | Type | Environment | Notes |
| --- | --- | --- | --- |

### Excluded or not tested
| Asset/surface | Reason |
| --- | --- |

## Methodology and Coverage
<P0–P6 summary and traceability limits.>

## Findings Summary
| ID | Severity | Confidence | Title | Status |
| --- | --- | --- | --- | --- |

## Findings
<Insert one finding section per ID.>

## Systemic Recommendations
1. <Root-cause control>
2. <Detection/monitoring>
3. <Regression coverage>

## Positive Security Observations
<Optional controls that worked as intended.>

## Disclosure Timeline
| UTC date | Event |
| --- | --- |

## Evidence Inventory
| Evidence ID | Finding | Description | Shared/Private |
| --- | --- | --- | --- |

## Retest Status
| Finding | Fix version/date | Result | Residual risk | Evidence |
| --- | --- | --- | --- | --- |

## Limitations
<Unavailable roles, excluded actions, time limits, nondeterminism, or blocked tests.>
```

## Finding

```markdown
### F-### — <Broken control enables exact impact>

**Severity:** <Program rating>  
**Confidence:** <High/Medium/Low>  
**Status:** <Confirmed/Open/Fixed/etc.>  
**Affected assets:** <Exact assets/components>  
**Root cause:** <One-sentence control failure>

#### Summary
<Actor + prerequisite + broken invariant + exact demonstrated capability.>

#### Preconditions
- <Role/account/state>
- <Configuration/version>

#### Expected behavior
<The security invariant.>

#### Actual behavior
<Observed result, without inference inflation.>

#### Minimal reproduction
1. <Create or identify owned canary state.>
2. <Capture baseline.>
3. <Perform one mutation.>
4. <Observe result.>
5. <Run negative control.>
6. <Clean up.>

#### Evidence
| ID | Observation | Private/shared |
| --- | --- | --- |

#### Impact
**Demonstrated:** <Exact evidenced impact.>

**Potential, conditional:** <Clearly labeled assumptions, if useful.>

#### Severity rationale
<Map prerequisites, affected population, capability, reliability, and program taxonomy.>

#### Root cause analysis
<Where and why enforcement fails.>

#### Remediation
1. <Primary server-side/root-cause fix.>
2. <Containment or detection.>
3. <Regression test.>

#### Retest criteria
- <Original PoC fails securely.>
- <Negative control remains valid.>
- <Related variants are covered.>

#### Cleanup and disclosure notes
<State restored, secrets revoked, and communication constraints.>
```

## Compact disclosure email

```text
Subject: [Security Disclosure] <Concise confirmed issue> — <Target>

Hello <Security Team>,

During authorized testing of <scope/program>, I confirmed <one-sentence issue>.
The demonstrated impact is <minimal exact impact>, under <key prerequisites>.

Finding summary:
- ID: F-###
- Severity: <rating, if appropriate>
- Affected asset: <asset>
- Status: Confirmed

I have preserved a minimal, redacted PoC and can provide the full report through
your approved secure channel. I stopped testing after establishing impact and
did not access unrelated user data.

Please confirm receipt and the preferred channel for detailed evidence.

Regards,
<Researcher>
```

## Retest note

```markdown
### Retest — F-###

- Fix version/deployment:
- Retest time (UTC):
- Original baseline:
- Original PoC result:
- Negative control:
- Related variants:
- Result: Fixed / Partially fixed / Not fixed / Regressed / Unable to verify
- Evidence IDs:
- Residual risk:
```
