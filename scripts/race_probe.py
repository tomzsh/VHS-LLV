#!/usr/bin/env python3
"""Bounded race-condition probe harness for explicitly authorized targets.

Sends a burst of near-simultaneous requests to ONE in-scope endpoint and
records per-request status/latency/body-signal so timing windows can be judged
as evidence. Two stdlib-only modes:

- ``barrier``   : N parallel TLS connections released by a thread barrier
                  (classic concurrent-send; works everywhere).
- ``pipeline``  : one keep-alive connection; every request is written minus its
                  final byte, then all withheld bytes are flushed back-to-back
                  (HTTP/1.1 last-byte synchronization, the single-connection
                  approximation of the single-packet technique).

Guard rails:
- requires engagement authorization AND ``race_testing`` in allowed_methods
  (and not prohibited) - race amplification is never default-on;
- hard cap of 50 requests per burst, single burst per invocation;
- state-changing methods additionally require --allow-state-change AND the
  method (or ``state_change``) in allowed_methods, mirroring api_auth_probe;
- GET/HEAD-only by default.

Matches are timing signals, never confirmed findings; validate at P4.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import PolicyError, authorize_run  # noqa: E402

MAX_REQUESTS_HARD_CAP = 50
READ_CHUNK = 2048


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_request(target: str, method: str, data: str | None, extra_headers: list[str]) -> bytes:
    parsed = urlsplit(target)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {parsed.hostname}",
        "User-Agent: security-research (authorized)",
        "Connection: keep-alive",
        "Accept: */*",
    ]
    body = b""
    if data is not None:
        body = data.encode("utf-8")
        headers.append(f"Content-Length: {len(body)}")
        headers.append("Content-Type: application/x-www-form-urlencoded")
    for header in extra_headers:
        if ":" in header:
            headers.append(header)
    return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body


def open_connection(parsed, timeout: int) -> ssl.SSLSocket | socket.socket:
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    raw = socket.create_connection((parsed.hostname, port), timeout=timeout)
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        return context.wrap_socket(raw, server_hostname=parsed.hostname)
    return raw


def read_response(sock, deadline: float) -> dict:
    sock.settimeout(max(0.2, deadline - time.monotonic()))
    chunks: list[bytes] = []
    try:
        while time.monotonic() < deadline:
            chunk = sock.recv(READ_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                break
    except (socket.timeout, ssl.SSLError, OSError):
        pass
    blob = b"".join(chunks)
    status = blob.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:120] if blob else ""
    return {
        "status_line": status,
        "bytes": len(blob),
        "body_sha256_12": hashlib.sha256(blob).hexdigest()[:12] if blob else "",
    }


def race_barrier(target: str, request: bytes, count: int, timeout: int) -> list[dict]:
    """Parallel connections released together by a barrier."""
    parsed = urlsplit(target)
    sockets = [open_connection(parsed, timeout) for _ in range(count)]
    results: list[dict | None] = [None] * count
    barrier = threading.Barrier(count + 1)

    def worker(index: int) -> None:
        try:
            barrier.wait()
            start = time.monotonic()
            sockets[index].sendall(request)
            results[index] = {"latency_ms": round((time.monotonic() - start) * 1000, 2),
                              **read_response(sockets[index], time.monotonic() + timeout)}
        except Exception as exc:  # noqa: BLE001 - record, never crash the burst
            results[index] = {"latency_ms": None, "status_line": f"error: {exc}", "bytes": 0, "body_sha256_12": ""}
        finally:
            try:
                sockets[index].close()
            except OSError:
                pass

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout + 5)
    return [r or {"latency_ms": None, "status_line": "no-result", "bytes": 0, "body_sha256_12": ""} for r in results]


def race_pipeline(target: str, request: bytes, count: int, timeout: int) -> list[dict]:
    """Single connection, last-byte synchronization (HTTP/1.1 pipelining)."""
    parsed = urlsplit(target)
    sock = open_connection(parsed, timeout)
    try:
        # Pre-write every request minus its final byte, then flush withheld
        # bytes back-to-back so the server sees them arrive together.
        withheld = request[-1:]
        head = request[:-1]
        try:
            sock.sendall(head * count)
            start = time.monotonic()
            sock.sendall(withheld * count)
        except (ssl.SSLError, OSError):
            # Server closed early or rejects pipelining: fall back to one shot.
            start = time.monotonic()
            sock.sendall(request * min(count, 2))
        blob_parts: list[bytes] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not chunk:
                break
            blob_parts.append(chunk)
        blob = b"".join(blob_parts)
        responses = [part for part in blob.split(b"HTTP/1.") if part]
        results = []
        for part in responses:
            status = ("HTTP/1." + part.split(b"\r\n", 1)[0].decode("latin-1", "replace"))[:120]
            results.append({
                "latency_ms": None,
                "status_line": status,
                "bytes": len(part),
                "body_sha256_12": hashlib.sha256(part).hexdigest()[:12],
            })
        while len(results) < count:
            results.append({"latency_ms": None, "status_line": "no-response", "bytes": 0, "body_sha256_12": ""})
        return results[:count]
    finally:
        try:
            sock.close()
        except OSError:
            pass


def summarize(results: list[dict]) -> dict:
    statuses: dict[str, int] = {}
    bodies: dict[str, int] = {}
    for item in results:
        statuses[item["status_line"]] = statuses.get(item["status_line"], 0) + 1
        if item["body_sha256_12"]:
            bodies[item["body_sha256_12"]] = bodies.get(item["body_sha256_12"], 0) + 1
    distinct_bodies = len(bodies)
    mixed = distinct_bodies > 1
    identical_successes = max(bodies.values()) if bodies else 0
    return {
        "distinct_status_lines": len(statuses),
        "distinct_body_hashes": distinct_bodies,
        "identical_response_count": identical_successes,
        "mixed_outcome_signal": mixed,
        "verdict_hint": "race_window_candidate" if mixed or identical_successes > 1 else "no_signal",
    }


def method_allowed(engagement: dict, method: str, *, state_change_flag: bool) -> str | None:
    allowed = {str(v).strip().lower().replace("-", "_") for v in engagement.get("allowed_methods") or []}
    prohibited = {str(v).strip().lower().replace("-", "_") for v in engagement.get("prohibited_methods") or []}
    if "race_testing" in prohibited or "race" in prohibited:
        return "engagement prohibits race testing"
    if "race_testing" not in allowed and "race" not in allowed:
        return "race testing requires explicit allowed_methods entry 'race_testing'"
    if method.upper() in {"GET", "HEAD"}:
        return None
    if prohibited & {method.lower(), "state_change"}:
        return f"engagement prohibits method {method}"
    if not state_change_flag:
        return "state-changing race requires --allow-state-change"
    if not allowed & {method.lower(), "state_change"}:
        return f"method {method} requires an explicit allowed_methods entry"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engagement_dir")
    parser.add_argument("--url", required=True, help="single in-scope endpoint URL")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--data", help="request body for state-changing methods")
    parser.add_argument("--header", action="append", default=[], help="extra header (repeatable), e.g. 'Cookie: ...'")
    parser.add_argument("--count", type=int, default=20, help=f"requests per burst (1-{MAX_REQUESTS_HARD_CAP})")
    parser.add_argument("--mode", choices=("barrier", "pipeline"), default="barrier")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--allow-state-change", action="store_true")
    parser.add_argument("--out", type=Path, help="output JSON path (default: ./race-results.json)")
    args = parser.parse_args()

    if not 1 <= args.count <= MAX_REQUESTS_HARD_CAP:
        parser.error(f"--count must be 1..{MAX_REQUESTS_HARD_CAP}")

    engagement_root = Path(args.engagement_dir).expanduser().resolve()
    parsed = urlsplit(args.url)
    host = parsed.hostname or ""
    try:
        engagement, _, policy = authorize_run(engagement_root, host, "active-safe")
    except PolicyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not policy.url_allowed(args.url):
        print(f"ERROR: URL is not permitted by the engagement scope: {args.url}", file=sys.stderr)
        return 2
    denial = method_allowed(engagement, args.method, state_change_flag=args.allow_state_change)
    if denial:
        print(f"ERROR: {denial}", file=sys.stderr)
        return 2
    if args.method.upper() not in {"GET", "HEAD"} and args.data is None:
        parser.error("--data is required for state-changing race methods")

    request = build_request(args.url, args.method.upper(), args.data, args.header)
    print(f"Burst: {args.count} x {args.method} {args.url} (mode={args.mode})")
    runner = race_barrier if args.mode == "barrier" else race_pipeline
    results = runner(args.url, request, args.count, args.timeout)
    summary = summarize(results)

    record = {
        "generated_at_utc": utc_now(),
        "url": args.url,
        "method": args.method.upper(),
        "mode": args.mode,
        "count": args.count,
        "note": "timing signal only; validate under P4 before reporting",
        "summary": summary,
        "results": results,
    }
    out = args.out or Path("race-results.json")
    out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"results: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
