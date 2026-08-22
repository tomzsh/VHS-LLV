#!/usr/bin/env python3
"""Deep-parse discovered JavaScript files with jsluice (P2/P3 helper).

Downloads each JS URL from the crawl stage's ``javascript_urls.txt`` (or an
explicit --input list), re-verifies every URL against the engagement scope,
then runs local ``jsluice`` analysis to extract:

- additional API endpoints/URLs referenced in code (fed back into discovery);
- embedded secrets (API keys, cloud credentials, tokens).

All target traffic is GET-only and rate-limited. Extracted URLs are written
raw; the caller (orchestrator) scope-filters them before further use.

Usage:
  python3 js_deep_parse.py --engagement ./engagement \
      --input ./run-output/agents/crawl/javascript_urls.txt \
      --outdir ./run-output/agents/jsanalysis \
      [--header "X-HackerOne-Research: researcher"] [--rate 0.5] [--timeout 20]
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import PolicyError, ScopePolicy, authorize_run  # noqa: E402


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--engagement", required=True, help="authorized engagement directory")
    p.add_argument("--input", required=True, help="file with one JS URL per line")
    p.add_argument("--outdir", required=True, help="directory for analysis artifacts")
    p.add_argument("--header", action="append", default=[], help="extra request header (repeatable)")
    p.add_argument("--rate", type=float, default=0.5, help="seconds between downloads")
    p.add_argument("--timeout", type=int, default=20, help="per-download timeout")
    p.add_argument("--max-files", type=int, default=50, help="maximum JS files to analyze")
    p.add_argument("--keep-bodies", action="store_true", help="keep downloaded JS bodies for review")
    args = p.parse_args()
    if args.rate < 0:
        p.error("--rate must be >= 0")
    if args.timeout < 1:
        p.error("--timeout must be >= 1")
    if args.max_files < 1:
        p.error("--max-files must be >= 1")
    return args


def load_urls(path: Path, limit: int) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        url = line.strip()
        if not url or url.startswith("#") or url in seen:
            continue
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        seen.add(url)
        ordered.append(url)
        if len(ordered) >= limit:
            break
    return ordered


def download(url: str, dest: Path, headers: dict[str, str], timeout: int) -> tuple[bool, int]:
    req = urllib.request.Request(
        url, method="GET",
        headers={"User-Agent": "security-research (authorized)", "Accept": "*/*", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            dest.write_bytes(resp.read(int(10 * 1024 * 1024)))  # cap at 10 MB
            return True, resp.status
    except Exception:
        return False, 0


def run_jsluice(mode: str, paths: list[Path]) -> list[dict]:
    """Run jsluice over downloaded files and return parsed JSON lines."""
    results: list[dict] = []
    for batch_start in range(0, len(paths), 25):
        batch = paths[batch_start:batch_start + 25]
        proc = subprocess.run(
            ["jsluice", mode, *[str(pth) for pth in batch]],
            capture_output=True, text=True, timeout=120,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results


def parsed_host(infile: Path) -> str:
    """Return the first in-file hostname so authorize_run can scope-check it."""
    for url in load_urls(infile, 1):
        return urllib.parse.urlsplit(url).hostname or ""
    return ""


def main() -> int:
    args = parse_args()
    root = Path(args.engagement).expanduser().resolve()
    outdir = Path(args.outdir).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    infile = Path(args.input).expanduser().resolve()

    if shutil.which("jsluice") is None:
        print("[!] jsluice not found in PATH; install https://github.com/BishopFox/jsluice")
        return 1
    if not infile.exists():
        print(f"[!] input file missing: {infile}")
        return 1

    try:
        _, _, policy = authorize_run(root, parsed_host(infile), "passive-osint")
    except PolicyError as exc:
        print(f"[!] authorization refused: {exc}", file=sys.stderr)
        return 2

    urls = load_urls(infile, args.max_files)
    if not urls:
        print("[!] no usable JS URLs in input")
        return 1

    headers: dict[str, str] = {}
    for item in args.header:
        name, _, value = item.partition(":")
        if value:
            headers[name.strip()] = value.strip()

    bodies_dir = Path(tempfile.mkdtemp(prefix="vhs-js-"))
    try:
        downloaded: list[Path] = []
        failures = 0
        for index, url in enumerate(urls, 1):
            try:
                if not policy.url_allowed(url):
                    print(f"[skip] out of scope: {url}")
                    time.sleep(args.rate)
                    continue
            except PolicyError:
                print(f"[skip] out of scope: {url}")
                continue
            digest = urllib.parse.quote(url, safe="")[:120]
            dest = bodies_dir / f"{index:04d}_{digest}.js"
            ok, status = download(url, dest, headers, args.timeout)
            if ok:
                downloaded.append(dest)
                print(f"[{index}/{len(urls)}] {status} {url}")
            else:
                failures += 1
                print(f"[{index}/{len(urls)}] fail {url}")
            time.sleep(args.rate)

        if not downloaded:
            print("[!] no JS bodies downloaded; nothing to analyze")
            return 1

        url_hits = run_jsluice("urls", downloaded)
        secret_hits = run_jsluice("secrets", downloaded)

        raw_urls = outdir / "js_extracted_urls_raw.txt"
        raw_urls.write_text(
            "".join(f"{hit.get('url', '')}\n" for hit in url_hits if hit.get("url")),
            encoding="utf-8",
        )
        secrets_file = outdir / "js_secrets.json"
        secrets_file.write_text(json.dumps(secret_hits, indent=2) + "\n", encoding="utf-8")

        # Scope-filtered copy for direct pipeline consumption.
        scoped: list[str] = []
        for hit in url_hits:
            value = hit.get("url", "")
            if not value:
                continue
            try:
                if policy.url_allowed(value):
                    scoped.append(value)
            except PolicyError:
                continue
        (outdir / "js_extracted_urls_scoped.txt").write_text(
            "".join(f"{u}\n" for u in sorted(set(scoped))), encoding="utf-8",
        )

        print(f"\n=== summary ===")
        print(f"files analyzed : {len(downloaded)} (failures: {failures})")
        print(f"urls extracted : {len(url_hits)} ({len(set(scoped))} in-scope)")
        print(f"secrets found  : {len(secret_hits)}")
        print(f"artifacts      : {raw_urls}, {secrets_file}, js_extracted_urls_scoped.txt")
        if secret_hits:
            kinds = {}
            for hit in secret_hits:
                kinds[hit.get("kind", "?")] = kinds.get(hit.get("kind", "?"), 0) + 1
            print(f"secret kinds   : {kinds} — verify manually before reporting")
        return 0
    finally:
        if args.keep_bodies:
            kept = outdir / "bodies"
            kept.mkdir(exist_ok=True)
            for src in bodies_dir.iterdir():
                shutil.copy2(src, kept / src.name)
            print(f"[i] JS bodies kept at {kept}")
        shutil.rmtree(bodies_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
