#!/usr/bin/env python3
"""Read-only Markdown outline and section slicer for progressive context loading."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


HEADING_RE = re.compile(r"^(#{1,6})[ \t]+(.+?)\s*$")
FENCE_OPEN_RE = re.compile(r"^[ \t]*([`~])\1{2,}")
NUMBERING_RE = re.compile(r"^\s*\d+(?:\.\d+)*[.)]?\s*")
FORBIDDEN_SECTION_RE = re.compile(
    r"\bevasion\b|\bpost[- ]?exploitation\b|"
    r"\bddos\b|\bdos\b|\bdenial[- ]?of[- ]?service\b|"
    r"利用|提权|横向|权限维持|持久化|反弹\s*shell|拒绝服务|拒絕服務",
    re.IGNORECASE,
)
# Vocabulary note: the English word "bypass" and its Chinese synonym 绕过 are
# deliberately NOT forbidden terms. Per-vuln-class "Bypass 矩阵" sections are
# input-filter/WAF technique variants for one vulnerability class - standard
# authorized-testing knowledge the P3 test designer needs. Detection evasion,
# exploitation/privesc/lateral movement, persistence, DoS, and post-exploitation
# categories remain refused above and safety sections are always attached.
FORBIDDEN_PLAYBOOKS = {"dos.md", "intranet-postexp.md"}
SAFETY_TITLES = {"不要做的事", "compliance", "safety", "do not", "do not do"}


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


def normalize_heading_title(title: str) -> str:
    return " ".join(title.split()).casefold()


def unnumbered_heading_title(title: str) -> str:
    return normalize_heading_title(NUMBERING_RE.sub("", title))


def is_safety_heading(title: str) -> bool:
    return unnumbered_heading_title(title) in SAFETY_TITLES


def is_forbidden_heading(title: str) -> bool:
    return bool(FORBIDDEN_SECTION_RE.search(unnumbered_heading_title(title)))


def render_ranges(
    text: str,
    included: list[tuple[int, int]],
    excluded: list[tuple[int, int]] | None = None,
) -> str:
    lines = text.splitlines(keepends=True)
    selected = [False] * len(lines)
    for start_line, end_line in included:
        selected[start_line - 1:end_line] = [True] * (end_line - start_line + 1)
    for start_line, end_line in excluded or []:
        selected[start_line - 1:end_line] = [False] * (end_line - start_line + 1)
    return "".join(line for line, keep in zip(lines, selected) if keep)


def slice_sections(text: str, terms: list[str]) -> str:
    """Return matching sections with nested children, or the original text."""
    normalized_terms = [normalize_heading_title(term) for term in terms if term]
    matches = [
        (start_line, end_line)
        for _level, title, start_line, end_line in parse_headings(text)
        if normalize_heading_title(title) in normalized_terms
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


def slice_safe_playbook(text: str, terms: list[str]) -> str:
    """Select exact playbook headings while retaining safety and pruning unsafe sections."""
    requested = {normalize_heading_title(term) for term in terms if term}
    if not requested:
        raise ValueError("safe playbook routing requires at least one exact outline heading")

    headings = parse_headings(text)
    matches = [
        heading for heading in headings
        if normalize_heading_title(heading[1]) in requested
    ]
    matched_titles = {normalize_heading_title(heading[1]) for heading in matches}
    missing = sorted(requested - matched_titles)
    if missing:
        raise ValueError(
            "safe playbook heading not found exactly: " + ", ".join(missing)
        )
    unsafe = []
    for match_level, _match_title, match_start, _match_end in matches:
        for level, title, start_line, end_line in headings:
            if (
                level <= match_level
                and start_line <= match_start <= end_line
                and is_forbidden_heading(title)
                and title not in unsafe
            ):
                unsafe.append(title)
    if unsafe:
        raise ValueError("unsafe section is not routable: " + ", ".join(unsafe))

    safety = [heading for heading in headings if is_safety_heading(heading[1])]
    if not safety:
        raise ValueError("safe playbook has no recognized compliance/safety heading")

    contextual_matches = list(matches)
    for level, _title, start_line, _end_line in matches:
        if level <= 2:
            continue
        parents = [
            heading for heading in headings
            if heading[0] == 2 and heading[2] <= start_line <= heading[3]
        ]
        if parents:
            contextual_matches.append(parents[-1])

    included = [(start, end) for _level, _title, start, end in contextual_matches + safety]
    excluded = [
        (start, end)
        for _level, title, start, end in headings
        if is_forbidden_heading(title)
    ]
    return render_ranges(text, included, excluded)


def _read_text(path: Path) -> str:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return handle.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, required=True, help="Markdown file to read")
    parser.add_argument("--outline", action="store_true", help="Print heading level, title, and line")
    parser.add_argument("--section", action="append", default=[], help="Heading title term to include")
    parser.add_argument("--full", action="store_true", help="Print the original file exactly")
    parser.add_argument(
        "--safe-playbook",
        action="store_true",
        help="Require exact headings, include safety context, and reject unsafe categories",
    )
    args = parser.parse_args(argv)

    text = _read_text(args.file)
    if args.full:
        sys.stdout.write(text)
    elif args.outline:
        for level, title, start_line, _end_line in parse_headings(text):
            print(f"{level}\t{title}\t{start_line}")
    elif args.safe_playbook:
        if args.file.name.casefold() in FORBIDDEN_PLAYBOOKS:
            parser.error(f"playbook category is not routable: {args.file.name}")
        try:
            sys.stdout.write(slice_safe_playbook(text, args.section))
        except ValueError as exc:
            parser.error(str(exc))
    else:
        sys.stdout.write(slice_sections(text, args.section))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
