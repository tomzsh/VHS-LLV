#!/usr/bin/env python3
"""Shared schema helpers for engagement ledgers."""
from __future__ import annotations

import csv
import json
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "ledger_schemas.json"


def load_ledger_schemas() -> dict[str, list[str]]:
    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not data:
        raise RuntimeError(f"Invalid ledger schema file: {CONFIG_PATH}")
    return {str(name): [str(column) for column in columns] for name, columns in data.items()}


LEDGER_SCHEMAS = load_ledger_schemas()


def create_missing_ledgers(root: Path) -> list[str]:
    created: list[str] = []
    root.mkdir(parents=True, exist_ok=True)
    for name, headers in LEDGER_SCHEMAS.items():
        path = root / name
        if path.exists():
            continue
        with path.open("w", encoding="utf-8", newline="") as handle:
            csv.writer(handle).writerow(headers)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        created.append(name)
    return created


def validate_ledger_header(path: Path, expected: list[str]) -> str | None:
    if not path.exists():
        return f"Missing required file: {path.name}"
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        actual = next(reader, [])
    if actual != expected:
        return (
            f"{path.name} header mismatch; expected {expected!r}, got {actual!r}. "
            "Back up the file, then migrate it before continuing."
        )
    return None
