#!/usr/bin/env python3
"""Read-only Markdown outline and section slicer for progressive context loading."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


HEADING_RE = re.compile(r"^(#{1,6})[ \t]+(.+?)\s*$")
FENCE_OPEN_RE = re.compile(r"^[ \t]*([`~])\1{2,}")


def parse_headings(text: str) -> list[tuple[int, str, int, int]]:
    """Return ATX headings outside fences with inclusive section line bounds."""
    starts: list[tuple[int, str, int]] = []
    lines = text.splitlines(keepends=True)
    fence_marker: str | None = None
    fence_length = 0

    for line_number, line in enumerate(lines, start=1):
        content = line.rstrip("\r\n")
        if fence_marker is not None:
            stripped = content.lstrip(" \t")
            closer = re.match(re.escape(fence_marker) + r"+", stripped)
            if (
                closer is not None
                and len(closer.group(0)) >= fence_length
                and not stripped[len(closer.group(0)):].strip()
            ):
                fence_marker = None
                fence_length = 0
            continue

        fence = FENCE_OPEN_RE.match(content)
        if fence:
            fence_marker = fence.group(1)
            fence_length = len(fence.group(0).lstrip(" \t"))
            continue

        heading = HEADING_RE.match(content)
        if heading:
            starts.append((len(heading.group(1)), heading.group(2), line_number))

    headings: list[tuple[int, str, int, int]] = []
    for index, (level, title, start_line) in enumerate(starts):
        end_line = len(lines)
        for next_level, _next_title, next_start in starts[index + 1:]:
            if next_level <= level:
                end_line = next_start - 1
                break
        headings.append((level, title, start_line, end_line))
    return headings


def slice_sections(text: str, terms: list[str]) -> str:
    """Return matching sections with nested children, or the original text."""
    normalized_terms = [term.casefold() for term in terms if term]
    matches = [
        (start_line, end_line)
        for _level, title, start_line, end_line in parse_headings(text)
        if any(term in title.casefold() for term in normalized_terms)
    ]
    if not matches:
        return text

    lines = text.splitlines(keepends=True)
    ranges: list[tuple[int, int]] = []
    for start_line, end_line in sorted(matches):
        if ranges and start_line <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end_line))
        else:
            ranges.append((start_line, end_line))
    return "".join("".join(lines[start_line - 1:end_line]) for start_line, end_line in ranges)


def _read_text(path: Path) -> str:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return handle.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, required=True, help="Markdown file to read")
    parser.add_argument("--outline", action="store_true", help="Print heading level, title, and line")
    parser.add_argument("--section", action="append", default=[], help="Heading title term to include")
    parser.add_argument("--full", action="store_true", help="Print the original file exactly")
    args = parser.parse_args(argv)

    text = _read_text(args.file)
    if args.full:
        sys.stdout.write(text)
    elif args.outline:
        for level, title, start_line, _end_line in parse_headings(text):
            print(f"{level}\t{title}\t{start_line}")
    else:
        sys.stdout.write(slice_sections(text, args.section))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
