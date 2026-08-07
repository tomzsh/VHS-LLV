#!/usr/bin/env python3
"""Stealth fetch + link extraction via Scrapling.

Designed to slot into the vhs orchestrator crawl stage. Fetches live URLs with
Scrapling's stealth fetchers (handles 403 / Cloudflare bot pages better than
plain curl/httpx), then extracts same-host links from the rendered HTML.

Usage:
    scrapling_crawl.py --input urls.txt [--output links.txt] [--timeout 35]

Writes discovered absolute URLs to stdout (or --output). Progress goes to stderr.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urljoin, urlsplit


def fetch(url: str, timeout: int) -> str:
    """Fetch page HTML, trying stealth fetcher then standard fetcher."""
    try:
        from scrapling.fetchers import Fetcher, StealthyFetcher
    except ImportError as exc:
        sys.stderr.write(f"[!] scrapling unavailable: {exc}\n")
        return ""

    # Prefer the browser-level stealth fetcher for bot-protected pages.
    try:
        page = StealthyFetcher.fetch(url, timeout=timeout)
        if page and page.status == 200 and page.html_content:
            return page.html_content
    except Exception:
        pass
    try:
        page = Fetcher.get(url, timeout=timeout)
        if page and page.status == 200 and page.html_content:
            return page.html_content
    except Exception as exc:
        sys.stderr.write(f"[!] scrapling fetch failed {url}: {exc}\n")
    return ""


def extract_links(html: str, base: str) -> list[str]:
    """Pull href/src URLs from HTML, normalized to absolute."""
    from lxml import html as lhtml

    links: list[str] = []
    try:
        tree = lhtml.fromstring(html)
        for attr in ("href", "src"):
            for el in tree.xpath(f"//*[@{attr}]"):
                raw = el.get(attr) or ""
                if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:")):
                    continue
                links.append(urljoin(base, raw))
    except Exception:
        pass
    return links


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", required=True, help="file with seed URLs, one per line")
    ap.add_argument("--output", help="write discovered URLs here (default: stdout)")
    ap.add_argument("--timeout", type=int, default=35)
    args = ap.parse_args()

    seeds = [ln.strip() for ln in Path(args.input).read_text(errors="ignore").splitlines() if ln.strip()]
    if not seeds:
        sys.stderr.write("[*] no seed URLs\n")
        return 0

    found: set[str] = set()
    for url in seeds:
        html = fetch(url, args.timeout)
        if html:
            found.update(extract_links(html, url))
            sys.stderr.write(f"[+] {url}: {len(html)} bytes\n")
        else:
            sys.stderr.write(f"[-] {url}: no content\n")

    out_lines = sorted(found)
    if args.output:
        Path(args.output).write_text("".join(f"{u}\n" for u in out_lines))
    else:
        sys.stdout.write("".join(f"{u}\n" for u in out_lines))
    sys.stderr.write(f"[*] scrapling: {len(out_lines)} unique links from {len(seeds)} seeds\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
