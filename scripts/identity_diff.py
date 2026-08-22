#!/usr/bin/env python3
"""Identity differential engine (P4 helper).

Probes the same endpoint set under two or more authenticated identities and
flags responses whose *structure* matches but whose *data* differs — the
signature of IDOR/BOLA, broken multi-tenancy, and privilege escalation.

Identities come from ENV only (never files/prompts):
  VHS_IDA_TOKEN / VHS_IDB_TOKEN   -> direct bearer tokens
  VHS_IDA_EMAIL+VHS_IDA_PASS /
  VHS_IDB_EMAIL+VHS_IDB_PASS      -> login via --login-path per identity

Read-only by design: GET/HEAD only unless separately authorized via the
engagement's allowed_methods plus --allow-state-change.

Output: human summary + machine-readable diff report (JSON) with per-endpoint
verdicts:
  identical        same body both identities (expected for public data)
  data_diff        same shape, different values -> REVIEW (potential IDOR)
  access_diff      one identity 2xx, other 401/403/404 -> expected boundary
  shape_diff       different JSON structure -> usually role-specific fields
  error            request failed

Usage:
  export VHS_IDA_TOKEN=... VHS_IDB_TOKEN=...
  python3 identity_diff.py https://api.example.com \
      --engagement ./engagement \
      --endpoints /api/v1/account,/api/v1/orders/42,/api/v1/users/1001 \
      [--swap-param user_id --swap-values 1001,1002] [--json-out diffs.json]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from api_auth_probe import (  # noqa: E402
    display_endpoint,
    jwt_claims,
    login_allowed,
    redact,
    resolve_endpoint,
    scoped_urlopen,
    state_change_allowed,
)
from policy import PolicyError, ScopePolicy, authorize_run  # noqa: E402


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("base_url", help="API base, e.g. https://api.example.com")
    p.add_argument("--engagement", required=True)
    p.add_argument("--login-path", default="/auth/login")
    p.add_argument("--accept", default="application/json")
    p.add_argument("--endpoints", required=True, help="comma-separated paths to compare")
    p.add_argument("--token-path", default="access_token", help="JSON path to token in login response")
    p.add_argument("--swap-param", default="", help="query param mutated per --swap-values")
    p.add_argument("--swap-values", default="", help="comma-separated values substituted for swap-param")
    p.add_argument("--rate", type=float, default=0.5)
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument(
        "--allow-state-change", action="store_true",
        help="confirm separately authorized non-GET/HEAD requests",
    )
    p.add_argument("--json-out", default="", help="write machine-readable diff report here")
    args = p.parse_args()
    if args.rate < 0 or args.timeout < 1:
        p.error("--rate must be >= 0 and --timeout must be >= 1")
    return args


def identity_token(suffix: str, login_url: str, accept: str, token_path: str,
                   timeout: int, policy: "ScopePolicy") -> str | None:
    """Acquire a bearer token for identity A/B from env or per-identity login."""
    tok = os.environ.get(f"VHS_ID{suffix}_TOKEN")
    if tok:
        return tok
    email = os.environ.get(f"VHS_ID{suffix}_EMAIL")
    pwd = os.environ.get(f"VHS_ID{suffix}_PASS")
    if not (email and pwd):
        return None
    body = json.dumps({"email": email, "password": pwd}).encode()
    req = urllib.request.Request(
        login_url, data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": accept,
                 "User-Agent": "security-research (authorized)"})
    try:
        with scoped_urlopen(req, timeout, policy) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        print(f"[!] identity {suffix} login failed: {exc}")
        return None
    cur = data
    for part in token_path.split("."):
        cur = cur.get(part) if isinstance(cur, dict) else None
    return str(cur) if cur else None


def fetch(url: str, token: str, accept: str, method: str, timeout: int,
          policy: "ScopePolicy") -> tuple[int | None, object]:
    req = urllib.request.Request(
        url, method=method,
        headers={"Authorization": f"Bearer {token}", "Accept": accept,
                 "User-Agent": "security-research (authorized)"})
    try:
        with scoped_urlopen(req, timeout, policy) as resp:
            body = resp.read()
            try:
                return resp.status, json.loads(body.decode())
            except Exception:
                return resp.status, body[:2000].decode(errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode())
        except Exception:
            payload = ""
        return exc.code, payload
    except (urllib.error.URLError, TimeoutError):
        return None, {"error": "unreachable"}
    except PolicyError:
        return None, {"error": "redirect refused"}


def shape(value: object, depth: int = 0) -> object:
    """Structural fingerprint: types and keys, not values."""
    if depth > 6:
        return "…"
    if isinstance(value, dict):
        return {key: shape(item, depth + 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        inner = [shape(item, depth + 1) for item in value[:3]]
        return {"list_of": inner}
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if value is None:
        return "null"
    return type(value).__name__


def leaf_diffs(a: object, b: object, path: str = "$") -> list[str]:
    """Collect paths where two same-shaped structures differ in value."""
    out: list[str] = []
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) & set(b)):
            out.extend(leaf_diffs(a[key], b[key], f"{path}.{key}"))
        return out
    if isinstance(a, list) and isinstance(b, list):
        for index, (item_a, item_b) in enumerate(zip(a, b)):
            out.extend(leaf_diffs(item_a, item_b, f"{path}[{index}]"))
        return out
    if a != b and not (isinstance(a, str) and isinstance(b, str) and a == b):
        out.append(path)
    elif a != b:
        out.append(path)
    return out


def sensitive_paths(paths: list[str]) -> list[str]:
    markers = ("email", "user", "account", "owner", "balance", "amount",
               "address", "phone", "name", "order", "invoice", "card",
               "tenant", "org", "role", "permission", "ssn", "document")
    hits = []
    for path in paths:
        low = path.lower()
        if any(marker in low for marker in markers):
            hits.append(path)
    return hits


def verdict_for(code_a, code_b, body_a, body_b) -> tuple[str, list[str]]:
    ok_a, ok_b = code_a in range(200, 300), code_b in range(200, 300)
    if code_a is None or code_b is None:
        return "error", []
    if ok_a != ok_b:
        # One side sees data, other is refused: that IS the access control working.
        return "access_diff", []
    if not ok_a and not ok_b:
        return "identical", []  # both refused consistently
    shape_a, shape_b = shape(body_a), shape(body_b)
    if shape_a != shape_b:
        return "shape_diff", []
    if body_a == body_b:
        return "identical", []
    diffs = leaf_diffs(body_a, body_b)
    return "data_diff", diffs


def main() -> int:
    args = parse_args()
    parsed_base = urllib.parse.urlsplit(args.base_url)
    if parsed_base.scheme.lower() not in {"http", "https"} or not parsed_base.hostname:
        print("[!] base_url must be an HTTP(S) URL with a hostname", file=sys.stderr)
        return 2
    try:
        engagement, _, policy = authorize_run(
            Path(args.engagement).expanduser().resolve(),
            parsed_base.hostname, "active-safe",
        )
        base = args.base_url.rstrip("/")
        login_url = resolve_endpoint(base, args.login_path, policy)
        endpoints = [
            resolve_endpoint(base, ep.strip(), policy)
            for ep in args.endpoints.split(",") if ep.strip()
        ]
    except PolicyError as exc:
        print(f"[!] authorization refused: {exc}", file=sys.stderr)
        return 2

    method = "GET"
    if not state_change_allowed(engagement, method, args.allow_state_change):
        print("[!] authorization refused: method not permitted", file=sys.stderr)
        return 2
    if not any(os.environ.get(f"VHS_ID{s}_TOKEN") for s in "AB") and not login_allowed(engagement):
        print("[!] authorization refused: credential login requires allowed_methods login/authentication", file=sys.stderr)
        return 2

    tok_a = identity_token("A", login_url, args.accept, args.token_path, args.timeout, policy)
    tok_b = identity_token("B", login_url, args.accept, args.token_path, args.timeout, policy)
    if not tok_a or not tok_b:
        print("[!] need both identities: VHS_IDA_* and VHS_IDB_* env vars", file=sys.stderr)
        return 1

    claims_a = jwt_claims(tok_a)
    claims_b = jwt_claims(tok_b)
    print("=== identity fingerprints ===")
    print(f"A: {json.dumps(redact(claims_a))[:200]}")
    print(f"B: {json.dumps(redact(claims_b))[:200]}")

    swap_values = [v.strip() for v in args.swap_values.split(",") if v.strip()] if args.swap_param else []

    report: list[dict] = []
    review_count = 0
    for endpoint in endpoints:
        variants: list[tuple[str, str]] = [(endpoint, "base")]
        for value in swap_values:
            sep = "&" if "?" in endpoint else "?"
            try:
                variants.append((
                    resolve_endpoint(base, f"{endpoint}{sep}{args.swap_param}={urllib.parse.quote(value)}", policy),
                    f"{args.swap_param}={value}",
                ))
            except PolicyError as exc:
                print(f"[skip] mutation out of scope: {exc}")
                continue

        for url, label in variants:
            code_a, body_a = fetch(url, tok_a, args.accept, method, args.timeout, policy)
            time.sleep(args.rate)
            code_b, body_b = fetch(url, tok_b, args.accept, method, args.timeout, policy)
            time.sleep(args.rate)

            verdict, diffs = verdict_for(code_a, code_b, body_a, body_b)
            flagged = verdict == "data_diff" and bool(sensitive_paths(diffs))
            if verdict == "data_diff":
                review_count += 1
            row = {
                "endpoint": display_endpoint(url),
                "variant": label,
                "status_a": code_a,
                "status_b": code_b,
                "verdict": verdict,
                "diff_paths": diffs[:20],
                "sensitive_overlap": sensitive_paths(diffs)[:10],
                "flagged": flagged,
                "sha_a": hashlib.sha256(json.dumps(body_a, sort_keys=True, default=str).encode()).hexdigest()[:12],
                "sha_b": hashlib.sha256(json.dumps(body_b, sort_keys=True, default=str).encode()).hexdigest()[:12],
            }
            report.append(row)
            marker = "!!" if flagged else ("~" if verdict == "data_diff" else " ")
            print(f"{marker} {row['endpoint']} [{label}] A:{code_a} B:{code_b} -> {verdict}"
                  + (f" | sensitive: {row['sensitive_overlap'][:3]}" if flagged else ""))

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\n[i] full report: {args.json_out}")

    print(f"\n=== summary ===")
    print(f"probes          : {len(report)}")
    print(f"data_diff       : {sum(1 for r in report if r['verdict'] == 'data_diff')} (review each)")
    print(f"flagged+sensitive: {review_count} (strong IDOR/BOLA candidates)")
    print(f"access_diff     : {sum(1 for r in report if r['verdict'] == 'access_diff')} (boundary OK)")
    print("\nNext: validate each data_diff manually per p4-validation.md before claiming anything.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
