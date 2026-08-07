#!/usr/bin/env python3
"""Authenticated read-only API probe (P4 helper).

Generic baseline + mutation probe for REST APIs once test credentials exist.
Read-only by design: GET endpoints only unless --method is explicitly given
for a state-change you are separately authorized to run.

Credentials come from ENV only (never files/prompts):
  API_AUTH_EMAIL / API_AUTH_PASS  -> POST {base}/auth/login (or --login-path)
  API_AUTH_TOKEN                  -> use token directly (skips login)

Usage:
  export API_AUTH_EMAIL=... API_AUTH_PASS=...
  python3 api_auth_probe.py https://api-uat.example.com \
      --login-path /auth/login --accept application/json \
      --endpoints /init /account/info /account/portfolios/info /bank-details

Options:
  --endpoints PATH,PATH,...   GET baselines (comma-separated)
  --swap-param name           IDOR probe: same endpoint with a mutated param
  --swap-id 123               value used for the IDOR mutation (default 1)
  --token-path field          JSON field holding the access token after login
  --rate N                    delay seconds between requests (default 1)
  --method METHOD             override HTTP method (default GET)
  --timeout N                 per-request timeout (default 20)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("base_url", help="API base, e.g. https://api-uat.example.com")
    p.add_argument("--login-path", default="/auth/login", help="login endpoint path")
    p.add_argument("--accept", default="application/json", help="Accept header value")
    p.add_argument("--endpoints", default="", help="comma-separated GET paths")
    p.add_argument("--swap-param", default="", help="query param to mutate for IDOR probe")
    p.add_argument("--swap-id", default="1", help="value for the IDOR mutation")
    p.add_argument("--token-path", default="access_token", help="JSON path to token in login response")
    p.add_argument("--rate", type=float, default=1.0, help="seconds between requests")
    p.add_argument("--method", default="GET", help="HTTP method override")
    p.add_argument("--timeout", type=int, default=20)
    return p.parse_args()


def login(base: str, path: str, accept: str, token_path: str, timeout: int) -> str:
    tok = os.environ.get("API_AUTH_TOKEN")
    if tok:
        print("[+] using API_AUTH_TOKEN from env")
        return tok
    email = os.environ.get("API_AUTH_EMAIL")
    pwd = os.environ.get("API_AUTH_PASS")
    if not (email and pwd):
        print("[!] set API_AUTH_EMAIL+API_AUTH_PASS or API_AUTH_TOKEN")
        sys.exit(1)
    body = json.dumps({"email": email, "password": pwd}).encode()
    req = urllib.request.Request(
        base + path, data=body,
        headers={"Content-Type": "application/json", "Accept": accept,
                 "User-Agent": "security-research (authorized)"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
    except Exception as e:
        print(f"[!] login failed: {e}")
        sys.exit(1)
    # support nested token paths like data.access_token
    cur = data
    for part in token_path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            cur = None
    if not cur:
        print(f"[!] token not found at '{token_path}' in login response; keys: {list(data.keys()) if isinstance(data, dict) else type(data)}")
        sys.exit(1)
    print("[+] login OK, token acquired")
    return str(cur)


def req(base: str, path: str, token: str, accept: str, method: str, timeout: int):
    r = urllib.request.Request(
        base + path, method=method,
        headers={"Authorization": f"Bearer {token}", "Accept": accept,
                 "User-Agent": "security-research (authorized)"})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            body = resp.read()
            try:
                return resp.status, json.loads(body.decode())
            except Exception:
                return resp.status, body[:300].decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:300].decode(errors="replace")


def jwt_claims(token: str) -> dict:
    try:
        _, p, _ = token.split(".")
        pad = p + "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(pad).decode())
    except Exception as e:
        return {"parse_error": str(e)}


def main() -> int:
    args = parse_args()
    base = args.base_url.rstrip("/")
    tok = login(base, args.login_path, args.accept, args.token_path, args.timeout)

    print("\n=== JWT claims (info only) ===")
    print(json.dumps(jwt_claims(tok), indent=2)[:1200])

    endpoints = [e for e in args.endpoints.split(",") if e.strip()]
    if not endpoints:
        print("[!] no --endpoints given; nothing to probe")
        return 1

    print(f"\n=== baseline ({args.method}) ===")
    for ep in endpoints:
        ep = ep if ep.startswith("/") else "/" + ep
        code, body = req(base, ep, tok, args.accept, args.method, args.timeout)
        s = json.dumps(body) if isinstance(body, (dict, list)) else str(body)
        print(f"{args.method} {ep} -> {code} | {s[:140]}")
        time.sleep(args.rate)

    if args.swap_param:
        print(f"\n=== IDOR mutation ({args.swap_param}={args.swap_id}) ===")
        for ep in endpoints:
            ep = ep if ep.startswith("/") else "/" + ep
            sep = "&" if "?" in ep else "?"
            mutated = f"{ep}{sep}{args.swap_param}={args.swap_id}"
            code, body = req(base, mutated, tok, args.accept, args.method, args.timeout)
            s = json.dumps(body) if isinstance(body, (dict, list)) else str(body)
            print(f"{args.method} {mutated} -> {code} | {s[:140]}")
            time.sleep(args.rate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
