# CVSS 3.1 Scoring Guide — ported from BountyForge

Ported from https://github.com/Gabson0x/bountyforge (references/cvss-guide.md,
v3.0.0, (c) Gabson0x / Synq Studio, MIT public GitHub) into vhs for P5
severity scoring. Complements `taxonomy-rating.md` (category baseline) with
the exact CVSS 3.1 vector string + justification.

## Vector Format

`CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}`

## Metric Definitions

### Attack Vector (AV)
| Value | Code | When to use |
|-------|------|-------------|
| Network | N | Exploitable remotely over the internet / blockchain |
| Adjacent | A | Requires access to the same network segment |
| Local | L | Requires local access to the machine |
| Physical | P | Requires physical access |

**Default for most web findings: N**

### Attack Complexity (AC)
| Value | Code | When to use |
|-------|------|-------------|
| Low | L | No special conditions; attack succeeds reliably |
| High | H | Requires specific configuration, race condition, or difficult-to-control state |

**If the attack needs a race window, specific token type, or flash loan: consider H**

### Privileges Required (PR)
| Value | Code | When to use |
|-------|------|-------------|
| None | N | No auth required |
| Low | L | Normal user account |
| High | H | Admin / privileged role required |

### User Interaction (UI)
| Value | Code | When to use |
|-------|------|-------------|
| None | N | No victim interaction needed |
| Required | R | Victim must click a link, approve a tx, etc. |

### Scope (S)
| Value | Code | When to use |
|-------|------|-------------|
| Unchanged | U | Impact stays within the vulnerable component |
| Changed | C | Impact extends beyond (e.g., compromised server affects other users, bridge affects other chains) |

**Cross-chain attacks, XSS, and SSRF to internal networks often qualify for C**

### Confidentiality (C)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No confidentiality impact |
| Low | L | Limited info disclosure |
| High | H | Full disclosure of sensitive data |

### Integrity (I)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No integrity impact |
| Low | L | Limited modification, no direct harm |
| High | H | Full modification of data/systems |

### Availability (A)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No availability impact |
| Low | L | Reduced performance or limited disruption |
| High | H | Full denial of service |

## Scoring workflow (vhs P5)

1. Compute the vector string from the metric table above.
2. Cross-check the category baseline from `taxonomy-rating.json` (priority
   1-5) — if the CVSS score and the taxonomy baseline disagree by more than
   one band, re-derive both and record the rationale.
3. Apply BountyForge gate severity adjustments (`bountyforge-judging.md`,
   "Severity Adjustment After Gates").
4. Record the vector + justification in the finding's
   `severity_rationale` column of `findings-index.csv`.
