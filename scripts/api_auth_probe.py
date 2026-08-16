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


STATE_CHANGE_ALIASES = {"state_change", "api_state_change"}
LOGIN_ALIASES = {"login", "authentication"}


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


def normalize_method_permissions(values: object) -> set[str]:
    if not isinstance(values, (list, tuple, set)):
        return set()
    normalized: set[str] = set()
    for value in values:
        token = re.sub(r"[^a-z0-9]+", "_", str(value).strip().casefold()).strip("_")
        if token:
            normalized.add(token)
    return normalized


def state_change_allowed(engagement: dict, method: str, explicit_flag: bool) -> bool:
    """Return whether an explicitly requested target method is authorized."""
    normalized_method = re.sub(
        r"[^a-z0-9]+", "_", method.strip().casefold(),
    ).strip("_")
    allowed = normalize_method_permissions(engagement.get("allowed_methods"))
    prohibited = normalize_method_permissions(engagement.get("prohibited_methods"))
    if normalized_method in prohibited:
        return False
    if normalized_method in {"get", "head"}:
        return True
    if prohibited & STATE_CHANGE_ALIASES:
        return False
    if not explicit_flag:
        return False
    return normalized_method in allowed or bool(STATE_CHANGE_ALIASES & allowed)


def login_allowed(engagement: dict) -> bool:
    allowed = normalize_method_permissions(engagement.get("allowed_methods"))
    prohibited = normalize_method_permissions(engagement.get("prohibited_methods"))
    if prohibited & LOGIN_ALIASES:
        return False
    return bool(LOGIN_ALIASES & allowed)


def url_origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise PolicyError("redirect target must be an HTTP(S) URL with a hostname")
    try:
        port = parsed.port
    except ValueError:
        raise PolicyError("redirect target has an invalid port") from None
    return (
        parsed.scheme.lower(),
        parsed.hostname.rstrip(".").encode("idna").decode("ascii").casefold(),
        port or (443 if parsed.scheme.lower() == "https" else 80),
    )


class ScopeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow only policy-approved redirects on the request's original origin."""

    def __init__(self, policy: ScopePolicy, original_url: str) -> None:
        super().__init__()
        self.policy = policy
        self.original_origin = url_origin(original_url)

    @staticmethod
    def refuse(fp, message: str):
        fp.close()
        raise PolicyError(message)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        parsed = urllib.parse.urlsplit(resolved)
        if parsed.username is not None or parsed.password is not None:
            self.refuse(fp, "redirect target must not contain credentials")
        if not self.policy.url_allowed(resolved):
            self.refuse(fp, "redirect target is not permitted by the engagement scope")
        if url_origin(resolved) != self.original_origin:
            self.refuse(fp, "authenticated redirects must remain on the original origin")
        return super().redirect_request(req, fp, code, msg, headers, resolved)


def scoped_urlopen(
    request: urllib.request.Request,
    timeout: int,
    policy: ScopePolicy | None = None,
):
    effective_policy = policy
    if effective_policy is None:
        parsed = urllib.parse.urlsplit(request.full_url)
        if not parsed.hostname:
            raise PolicyError("request URL must contain a hostname")
        effective_policy = ScopePolicy([parsed.hostname])
    opener = urllib.request.build_opener(
        ScopeRedirectHandler(effective_policy, request.full_url),
    )
    return opener.open(request, timeout=timeout)


def login(
    login_url: str,
    accept: str,
    token_path: str,
    timeout: int,
    policy: ScopePolicy | None = None,
) -> str:
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
        with scoped_urlopen(req, timeout, policy) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"[!] login failed: HTTP {exc.code}")
        sys.exit(1)
    except (urllib.error.URLError, TimeoutError):
        print("[!] login failed: unreachable")
        sys.exit(1)
    except PolicyError:
        print("[!] login failed: redirect refused")
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


def req(
    url: str,
    token: str,
    accept: str,
    method: str,
    timeout: int,
    policy: ScopePolicy | None = None,
) -> tuple[int | None, object]:
    r = urllib.request.Request(
        url, method=method,
        headers={"Authorization": f"Bearer {token}", "Accept": accept,
                 "User-Agent": "security-research (authorized)"})
    try:
        with scoped_urlopen(r, timeout, policy) as resp:
            body = resp.read()
            try:
                return resp.status, json.loads(body.decode())
            except Exception:
                return resp.status, body[:300].decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:300].decode(errors="replace")
    except (urllib.error.URLError, TimeoutError):
        return None, {"error": "unreachable"}
    except PolicyError:
        return None, {"error": "redirect refused"}


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

    tok = login(login_url, args.accept, args.token_path, args.timeout, policy)

    print("\n=== JWT claims (info only) ===")
    print(json.dumps(redact(jwt_claims(tok)), indent=2)[:1200])

    print(f"\n=== baseline ({method}) ===")
    for endpoint in endpoints:
        code, body = req(endpoint, tok, args.accept, method, args.timeout, policy)
        s = json.dumps(redact(body)) if isinstance(body, (dict, list)) else str(redact(body))
        print(f"{method} {display_endpoint(endpoint)} -> {code} | {s[:140]}")
        time.sleep(args.rate)

    if args.swap_param:
        print(f"\n=== IDOR mutation ({redact(f'{args.swap_param}={args.swap_id}')}) ===")
        for endpoint in endpoints:
            sep = "&" if "?" in endpoint else "?"
            mutated = resolve_endpoint(base, f"{endpoint}{sep}{args.swap_param}={args.swap_id}", policy)
            code, body = req(mutated, tok, args.accept, method, args.timeout, policy)
            s = json.dumps(redact(body)) if isinstance(body, (dict, list)) else str(redact(body))
            print(f"{method} {display_endpoint(mutated)} -> {code} | {s[:140]}")
            time.sleep(args.rate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
