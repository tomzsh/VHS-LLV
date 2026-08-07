#!/usr/bin/env python3
"""JS-aware deep crawl via crawl4ai (markdown + link extraction).

Slots into the vhs orchestrator crawl stage. Uses crawl4ai's headless-Chromium
crawler to render JS-heavy pages that plain HTTP (gau/waymore/katana) miss, then
extracts links.

CRITICAL: must run under crawl4ai's own venv python3.12 with PYTHONPATH cleared
(the global PYTHONPATH points at a broken scrapling/venv lxml that breaks
crawl4ai's `from lxml import etree`). A convenience driver script
(crawl4ai_crawl.sh) does that for you; you can also run directly:
    env -u PYTHONPATH <crawl4ai>/bin/python crawl4ai_crawl.py --input u.txt

Usage:
    crawl4ai_crawl.py --input urls.txt [--output links.txt] [--timeout 40]
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urljoin

# Guard: refuse to run if PYTHONPATH still points at the broken lxml.
_polluted = os.environ.get("PYTHONPATH", "")
if "/tools/scrapling/" in _polluted:
    print("FATAL: PYTHONPATH polluted with scrapling venv (broken lxml). "
          "Run with PYTHONPATH cleared.", file=sys.stderr)
    sys.exit(2)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", required=True, help="seed URLs file")
    ap.add_argument("--output", help="write discovered URLs here (default stdout)")
    ap.add_argument("--timeout", type=int, default=40)
    args = ap.parse_args()

    seeds = [ln.strip() for ln in Path(args.input).read_text(errors="ignore").splitlines() if ln.strip()]
    if not seeds:
        return 0

    try:
        from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig
    except Exception as exc:
        print(f"FATAL: crawl4ai import failed: {exc}", file=sys.stderr)
        return 2

    import asyncio
    from urllib.parse import urljoin, urlsplit

    async def run_all():
        browser = BrowserConfig(headless=True, verbose=False)
        found: set[str] = set()
        async with AsyncWebCrawler(config=browser) as crawler:
            for seed in seeds:
                try:
                    result = await crawler.arun(url=seed, config=CrawlerRunConfig(
                        page_timeout=8000, verbose=False))
                    pruned = result.html or ""
                    sys.stderr.write(f"[+] {seed}: {len(pruned)} bytes\n")
                    for a in result.links or []:
                        href = a.get("href")
                        if href and not href.startswith(("javascript:", "mailto:", "#")):
                            found.add(urljoin(seed, href))
                except Exception as exc:
                    sys.stderr.write(f"[!] crawl4ai failed {seed}: {exc}\n")
        return found

    found = asyncio.run(_crawl_main(seeds, args.timeout))
    # If the browser smoke path above is preferred, swap the call to run_all().
    # _crawl_main is the stable fallback and is used by default.

    out_lines = sorted(found)
    if args.output:
        Path(args.output).write_text("".join(f"{u}\n" for u in out_lines))
    else:
        sys.stdout.write("".join(f"{u}\n" for u in out_lines))
    sys.stderr.write(f"[*] crawl4ai: {len(out_lines)} unique links from {len(seeds)} seeds\n")
    return 0


async def _crawl_main(seeds, _timeout):
    from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig
    browser = BrowserConfig(headless=True, verbose=False)
    from urllib.parse import urljoin
    found = set()
    async with AsyncWebCrawler(config=browser) as crawler:
        for seed in seeds:
            try:
                result = await crawler.arun(url=seed, config=CrawlerRunConfig(
                    page_timeout=8000, verbose=True))
                html = (getattr(result, "html", "") or "")
                sys.stderr.write(f"[+] {seed[:60]}: {len(html)} bytes\n")
                for a in (getattr(result, "links", []) or []):
                    href = a.get("href") if isinstance(a, dict) else (a or "")
                    if href and not href.startswith(("javascript:", "mailto:", "#")):
                        found.add(urljoin(seed, href))
            except Exception as exc:
                sys.stderr.write(f"[!] crawl4ai failed {seed}: {exc}\n")
    return found


if __name__ == "__main__":
    sys.exit(main())