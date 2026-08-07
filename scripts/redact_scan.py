#!/usr/bin/env python3
"""Flag likely secrets and sensitive values without printing full matches."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("HIGH", "private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("HIGH", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("HIGH", "JWT-like token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")),
    ("HIGH", "bearer authorization", re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+\S+")),
    ("HIGH", "seed phrase label", re.compile(r"(?i)\b(?:seed phrase|mnemonic)\s*[:=]\s*\S+")),
    ("HIGH", "private key assignment", re.compile(r"(?i)\bprivate[_ -]?key\s*[:=]\s*[A-Fa-f0-9x]{24,}")),
    ("MEDIUM", "API key assignment", re.compile(r"(?i)\b(?:api[_ -]?key|secret[_ -]?key|client[_ -]?secret)\s*[:=]\s*\S{12,}")),
    ("MEDIUM", "session cookie", re.compile(r"(?i)\b(?:set-cookie|cookie)\s*:\s*.+")),
    ("MEDIUM", "email address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("MEDIUM", "IPv4 address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

TEXT_SUFFIXES = {".md", ".txt", ".json", ".csv", ".yaml", ".yml", ".log", ".http"}


def preview(line: str, start: int, end: int) -> str:
    left = line[max(0, start - 24) : start]
    right = line[end : end + 24]
    return f"{left}<REDACTED>{right}".strip()


def files_under(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return [
        item
        for item in sorted(path.rglob("*"))
        if item.is_file() and item.suffix.lower() in TEXT_SUFFIXES
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan reports for likely sensitive values.")
    parser.add_argument("path", help="Text file or directory")
    parser.add_argument(
        "--allow-placeholder-email",
        action="store_true",
        help="Ignore example.com email addresses",
    )
    args = parser.parse_args()

    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        raise SystemExit(f"Path does not exist: {target}")

    hits = 0
    high_hits = 0
    for file_path in files_under(target):
        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_no, line in enumerate(lines, 1):
            for severity, label, pattern in PATTERNS:
                for match in pattern.finditer(line):
                    value = match.group(0)
                    if (
                        args.allow_placeholder_email
                        and label == "email address"
                        and value.lower().endswith("@example.com")
                    ):
                        continue
                    hits += 1
                    high_hits += severity == "HIGH"
                    try:
                        relative = file_path.relative_to(target if target.is_dir() else target.parent)
                    except ValueError:
                        relative = file_path
                    print(
                        f"{relative}:{line_no}: [{severity}] {label}: "
                        f"{preview(line, match.start(), match.end())}"
                    )

    if hits:
        print(f"REVIEW REQUIRED: {hits} potential sensitive value(s), {high_hits} high severity")
        return 1
    print("PASS: no configured secret/PII patterns detected")
    print("Manual redaction review is still required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
