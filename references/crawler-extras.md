# Crawler extras: Scrapling and crawl4ai

Load this reference only when the optional crawler packages are installed or
requested. Both run in the active-crawl stage when present; their URL output is
merged into `urls_all.txt` and passes through the normal scope guard.

- **Scrapling:** `scripts/scrapling_crawl.sh --input live_urls.txt` performs
  stealth fetch/link extraction for anti-bot or JS pages. It uses the bundled
  venv; override with `VHS_SCRAPLING_HOME` or `VHS_SCRAPLING_PYTHON`.
- **crawl4ai:** `scripts/crawl4ai_crawl.sh --input live_urls.txt` performs
  JS-rendered link discovery. Override with `VHS_CRAWL4AI_PYTHON` or
  `VHS_CRAWL4AI_HOME`.

Standalone smoke check:

```bash
printf 'https://example.com\n' > /tmp/seeds.txt
python3 <skill-dir>/scripts/scrapling_crawl.py --input /tmp/seeds.txt
<skill-dir>/scripts/crawl4ai_crawl.sh --input /tmp/seeds.txt
```

Crawler output is discovery data only. Reapply scope checks before any active
follow-up and never treat a discovered URL as authorized automatically.
