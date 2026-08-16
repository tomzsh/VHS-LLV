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
      --engagement ./engagement --login-path /auth/login --accept application/json \
      --endpoints /init /account/info /account/portfolios/info /bank-details

Options:
  --engagement DIR          authorized engagement directory (required)
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
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from policy import PolicyError, ScopePolicy, authorize_run


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("base_url", help="API base, e.g. https://api-uat.example.com")
    p.add_argument("--engagement", required=True, help="authorized engagement directory")
    p.add_argument("--login-path", default="/auth/login", help="login endpoint path")
    p.add_argument("--accept", default="application/json", help="Accept header value")
    p.add_argument("--endpoints", default="", help="comma-separated GET paths")
    p.add_argument("--swap-param", default="", help="query param to mutate for IDOR probe")
    p.add_argument("--swap-id", default="1", help="value for the IDOR mutation")
    p.add_argument("--token-path", default="access_token", help="JSON path to token in login response")
    p.add_argument("--rate", type=float, default=1.0, help="seconds between requests")
    p.add_argument("--method", default="GET", help="HTTP method override")
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument(
        "--allow-state-change",
        action="store_true",
        help="confirm separately authorized non-GET/HEAD target requests",
    )
    args = p.parse_args()
    if args.rate < 0:
        p.error("--rate must be >= 0")
    if args.timeout < 1:
        p.error("--timeout must be >= 1")
    return args


def resolve_endpoint(base_url: str, endpoint: str, policy: ScopePolicy) -> str:
    """Resolve an API endpoint and refuse targets outside the authorized scope."""
    resolved = urllib.parse.urljoin(base_url, endpoint)
    parsed = urllib.parse.urlsplit(resolved)
    if parsed.username is not None or parsed.password is not None:
        raise PolicyError("API endpoint must not contain credentials")
    if not policy.url_allowed(resolved):
        raise PolicyError("API endpoint is not permitted by the engagement scope")
    return resolved


def state_change_allowed(engagement: dict, method: str, explicit_flag: bool) -> bool:
    """Return whether an explicitly requested target method is authorized."""
    normalized_method = method.lower()
    if normalized_method in {"get", "head"}:
        return True
    if not explicit_flag:
        return False
    allowed = {str(value).lower() for value in engagement.get("allowed_methods") or []}
    return normalized_method in allowed or bool({"state_change", "api_state_change"} & allowed)


def login_allowed(engagement: dict) -> bool:
    allowed = {str(value).lower() for value in engagement.get("allowed_methods") or []}
    return bool({"login", "authentication"} & allowed)


def login(login_url: str, accept: str, token_path: str, timeout: int) -> str:
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
        login_url, data=body,
        headers={"Content-Type": "application/json", "Accept": accept,
                 "User-Agent": "security-research (authorized)"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"[!] login failed: HTTP {exc.code}")
        sys.exit(1)
    except (urllib.error.URLError, TimeoutError):
        print("[!] login failed: unreachable")
        sys.exit(1)
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("[!] login failed: invalid response")
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


def req(url: str, token: str, accept: str, method: str, timeout: int) -> tuple[int | None, object]:
    r = urllib.request.Request(
        url, method=method,
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
    except (urllib.error.URLError, TimeoutError):
        return None, {"error": "unreachable"}


def jwt_claims(token: str) -> dict:
    try:
        _, p, _ = token.split(".")
        pad = p + "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(pad).decode())
    except Exception as e:
        return {"parse_error": str(e)}


def redact(value: object) -> object:
    """Keep credential-shaped values out of operator output."""
    if isinstance(value, dict):
        return {
            key: "[redacted]" if any(marker in key.lower() for marker in ("token", "password", "secret", "authorization")) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return re.sub(
            r'(?i)((?:access_)?token|password|pass|secret|authorization)(["\']?\s*[:=]\s*)(?:"[^"]*"|\'[^\']*\'|\S+)',
            r"\1\2[redacted]",
            value,
        )
    return value


def display_endpoint(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return parsed.path + ("?…" if parsed.query else "")


def main() -> int:
    args = parse_args()
    parsed_base = urllib.parse.urlsplit(args.base_url)
    if parsed_base.scheme.lower() not in {"http", "https"} or not parsed_base.hostname:
        print("[!] base_url must be an HTTP(S) URL with a hostname", file=sys.stderr)
        return 2

    try:
        engagement, _, policy = authorize_run(
            Path(args.engagement).expanduser().resolve(),
            parsed_base.hostname,
            "active-safe",
        )
        base = args.base_url.rstrip("/")
        login_url = resolve_endpoint(base, args.login_path, policy)
        endpoints = [
            resolve_endpoint(base, endpoint.strip(), policy)
            for endpoint in args.endpoints.split(",")
            if endpoint.strip()
        ]
    except PolicyError as exc:
        print(f"[!] authorization refused: {exc}", file=sys.stderr)
        return 2

    if not endpoints:
        print("[!] no --endpoints given; nothing to probe")
        return 1

    method = args.method.upper()
    if not state_change_allowed(engagement, method, args.allow_state_change):
        print("[!] authorization refused: method requires --allow-state-change and engagement permission", file=sys.stderr)
        return 2
    if not os.environ.get("API_AUTH_TOKEN") and not login_allowed(engagement):
        print("[!] authorization refused: credential login requires allowed_methods login or authentication", file=sys.stderr)
        return 2

    tok = login(login_url, args.accept, args.token_path, args.timeout)

    print("\n=== JWT claims (info only) ===")
    print(json.dumps(redact(jwt_claims(tok)), indent=2)[:1200])

    print(f"\n=== baseline ({method}) ===")
    for endpoint in endpoints:
        code, body = req(endpoint, tok, args.accept, method, args.timeout)
        s = json.dumps(redact(body)) if isinstance(body, (dict, list)) else str(redact(body))
        print(f"{method} {display_endpoint(endpoint)} -> {code} | {s[:140]}")
        time.sleep(args.rate)

    if args.swap_param:
        print(f"\n=== IDOR mutation ({redact(f'{args.swap_param}={args.swap_id}')}) ===")
        for endpoint in endpoints:
            sep = "&" if "?" in endpoint else "?"
            mutated = resolve_endpoint(base, f"{endpoint}{sep}{args.swap_param}={args.swap_id}", policy)
            code, body = req(mutated, tok, args.accept, method, args.timeout)
            s = json.dumps(redact(body)) if isinstance(body, (dict, list)) else str(redact(body))
            print(f"{method} {display_endpoint(mutated)} -> {code} | {s[:140]}")
            time.sleep(args.rate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
