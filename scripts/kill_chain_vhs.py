#!/usr/bin/env python3
"""vhs wrapper for the BountyForge kill-chain builder (P5 chaining).

Converts vhs findings-index.csv (open/confirmed findings) into the JSONL
shape expected by kill_chain.py, then builds composite attack chains
(A→B→C = higher combined severity). Run AFTER P5 triage, before P6 report.

Usage:
  python3 kill_chain_vhs.py <engagement-dir> [--chain-type <id>] [--novel]
                            [--output-format text|json|markdown] [--dry-run]

Reads:   <engagement>/findings-index.csv   (vhs schema)
Writes:  <engagement>/kill-chains.md       (report)
"""
import argparse
import csv
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

try:
    from kill_chain import KillChainBuilder, CHAIN_PATTERNS, discover_novel_chains
except ImportError:
    sys.exit("[!] kill_chain.py not found next to this script (port from bountyforge)")


# Map free-text finding signals -> the bug_class ids that kill_chain.py's
# CHAIN_PATTERNS actually match on. Ordered longest/most-specific first so a
# phrase like "stored xss" wins over bare "xss". Without this, the scoring
# engine reads f["bug_class"] (never populated by the vhs schema) and every
# pattern scores 0 -> no chain can ever match.
_BUG_CLASS_KEYWORDS = [
    ("xss-stored", ("stored xss", "persistent xss", "stored cross-site")),
    ("xss-reflected", ("reflected xss", "reflected cross-site", "dom xss", "dom-based xss")),
    ("xss-reflected", ("xss", "cross-site scripting")),
    ("idor", ("idor", "insecure direct object", "bola", "broken object level")),
    ("ssrf", ("ssrf", "server-side request forgery", "server side request forgery")),
    ("open-redirect", ("open redirect", "open-redirect", "unvalidated redirect")),
    ("oauth-bypass", ("oauth", "openid", "redirect_uri", "authorization code")),
    ("jwt-bypass", ("jwt", "json web token", "alg:none", "alg none", "algorithm confusion")),
    ("graphql-introspection", ("graphql", "introspection")),
    ("cache-poisoning", ("cache poisoning", "cache-poisoning", "web cache")),
    ("request-smuggling", ("request smuggling", "http smuggling", "desync", "cl.te", "te.cl")),
    ("race-condition-web", ("race condition", "race-condition", "toctou", "double spend")),
    ("cors-misconfiguration", ("cors", "cross-origin resource sharing")),
    ("host-header-injection", ("host header", "host-header")),
    ("csrf", ("csrf", "cross-site request forgery", "cross site request forgery")),
    ("subdomain-takeover", ("subdomain takeover", "subdomain-takeover", "dangling cname")),
    ("api-key-exposure", ("api key", "api-key", "secret exposure", "leaked key", "hardcoded credential", "exposed credential")),
    ("info-disclosure", ("information disclosure", "info disclosure", "info-disclosure", "sensitive data exposure", "pii exposure", "data leak")),
    ("mass-assignment", ("mass assignment", "mass-assignment", "autobind")),
    ("sqli", ("sql injection", "sqli", "sql-injection")),
    ("prototype-pollution", ("prototype pollution", "prototype-pollution", "__proto__")),
    ("xxe", ("xxe", "xml external entity", "xml external-entity")),
    ("path-traversal", ("path traversal", "path-traversal", "directory traversal", "lfi", "local file inclusion")),
    ("deserialization", ("deserialization", "deserialisation", "insecure deserialization", "gadget chain", "ysoserial")),
    ("rce", ("remote code execution", "rce", "command injection", "code execution")),
    ("websocket-hijack", ("websocket", "web socket", "cswsh")),
    ("business-logic", ("business logic", "business-logic", "logic flaw")),
    ("broken-auth", ("broken authentication", "broken auth", "authentication bypass", "auth bypass")),
    ("session-fixation", ("session fixation", "session-fixation")),
]

_METHOD_TOKENS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")

# Endpoint-like token: a /path (optionally with scheme) inside the finding text.
_ENDPOINT_RE = re.compile(r"(?:wss?://[^\s,;]+|https?://[^\s,;]+|/[A-Za-z0-9_./{}:\-]*)")


def _classify_bug(text: str) -> str:
    low = text.lower()
    for bug_class, needles in _BUG_CLASS_KEYWORDS:
        if any(n in low for n in needles):
            return bug_class
    return ""


def _extract_endpoint(text: str) -> str:
    m = _ENDPOINT_RE.search(text or "")
    return m.group(0) if m else ""


def _extract_method(text: str) -> str:
    for tok in _METHOD_TOKENS:
        # word-boundary match so "DELETE" doesn't fire inside "undeleted"
        if re.search(rf"\b{tok}\b", text or ""):
            return tok
    return ""


def findings_from_csv(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            if not any((v or "").strip() for v in r.values()):
                continue
            # Only chain findings that are actually live (open/confirmed).
            status = (r.get("status") or "").strip().lower()
            if status and status not in ("open", "confirmed", "triaged", "validated"):
                continue
            title = r.get("title") or ""
            root_cause = r.get("root_cause") or ""
            assets = r.get("affected_assets") or ""
            impact = r.get("demonstrated_impact") or ""
            blob = " ".join([title, root_cause, impact, assets])
            rows.append({
                "finding_id": r.get("finding_id") or "",
                "title": title,
                "root_cause": root_cause,
                "severity": (r.get("severity") or "medium").strip().lower() or "medium",
                "status": status,
                "affected_assets": assets,
                "confidence": r.get("confidence") or "50",
                # Derived fields the kill_chain.py scoring engine expects:
                "bug_class": _classify_bug(blob),
                "endpoint": _extract_endpoint(blob),
                "method": _extract_method(blob),
            })
    return rows


def _resolve_target(root: Path) -> str:
    """Best-effort target label for the report header.

    Prefer engagement.json's primary_target; fall back to the engagement dir
    name (resolved absolutely so './engagement' doesn't yield an empty string).
    """
    ej = root / "engagement.json"
    if ej.exists():
        try:
            data = json.loads(ej.read_text(encoding="utf-8"))
            for key in ("primary_target", "target", "title"):
                val = (data.get(key) or "").strip()
                if val:
                    return val
        except (json.JSONDecodeError, OSError):
            pass
    name = root.resolve().name
    return name or "engagement"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("engagement_dir")
    ap.add_argument("--chain-type", help="specific chain pattern id")
    ap.add_argument("--novel", action="store_true", help="discover novel chains")
    ap.add_argument("--output-format", default="markdown",
                    choices=["text", "json", "markdown"])
    ap.add_argument("--dry-run", action="store_true",
                    help="print chains without writing report file")
    args = ap.parse_args()

    root = Path(args.engagement_dir)
    findings = findings_from_csv(root / "findings-index.csv")
    if not findings:
        sys.exit(f"[!] no open findings in {root}/findings-index.csv — run P5 first")
    print(f"[kill-chain] {len(findings)} findings loaded from findings-index.csv")

    if args.dry_run:
        # just report what chain patterns could apply
        by_sev = {}
        for f_ in findings:
            by_sev.setdefault(f_.get("severity", "?"), 0)
            by_sev[f_.get("severity", "?")] += 1
        print(f"[dry-run] severity distribution: {by_sev}")
        print(f"[dry-run] available patterns: {[p.chain_id for p in CHAIN_PATTERNS]}")
        return

    target = _resolve_target(root)
    builder = KillChainBuilder(target)
    candidates = builder.build_all_chains(findings)
    candidates = [c for c in candidates if c.matched_findings]

    report = builder.generate_chain_report(candidates) if candidates else \
        "No chain patterns matched the current findings.\n"
    if args.novel:
        novel = discover_novel_chains(findings)
        report += f"\n--- novel chains: {len(novel)} ---\n"
        for n in novel:
            report += f"{n.get('type')}: {n.get('endpoint_root', n.get('potential_impact', ''))}\n"

    out = root / "kill-chains.md"
    if not args.dry_run:
        out.write_text(report, encoding="utf-8")
        print(f"[+] wrote {out.relative_to(root)} ({len(report)} bytes)")
    else:
        print(report)


if __name__ == "__main__":
    main()