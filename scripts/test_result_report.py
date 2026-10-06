#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Enumerate actual unittest statuses, including standalone statuses after native stdout."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


START = re.compile(r"^test_\S+ \(([^)]+)\) \.\.\.\s*(.*)$")
STATUS = re.compile(r"^(ok|FAIL|ERROR|skipped(?: .*)?)\s*$")


def parse_statuses(log: str) -> dict[str, str]:
    statuses = {}
    pending = None
    for line in log.splitlines():
        match = START.match(line)
        if match:
            if pending is not None:
                raise ValueError("unresolved prior test status")
            pending = match[1]
            value = STATUS.fullmatch(match[2])
        else:
            value = STATUS.fullmatch(line) if pending is not None else None
        if value:
            if pending in statuses:
                raise ValueError("duplicate test ID status")
            statuses[pending] = value[1].split(" ", 1)[0]
            pending = None
    if pending is not None:
        raise ValueError("unresolved final test status")
    return statuses


def validate_totals(log: str, statuses: dict[str, str]) -> None:
    totals = re.findall(r"^Ran (\d+) tests? in [0-9.]+s$", log, re.MULTILINE)
    if len(totals) != 1 or int(totals[0]) != len(statuses):
        raise ValueError("reported/enumerated unittest count mismatch")
    discovered = re.findall(r"Canonical verification: (\d+) tests discovered;", log)
    if discovered and (len(discovered) != 1 or int(discovered[0]) != len(statuses)):
        raise ValueError("discovery/result count mismatch")


def report(log: str, exit_code: int) -> dict:
    statuses = parse_statuses(log)
    validate_totals(log, statuses)
    counts = Counter(statuses.values())
    success = not any(counts[key] for key in ("FAIL", "ERROR", "skipped"))
    if (exit_code == 0) != success:
        raise ValueError("actual exit and enumerated outcome disagree")
    return {"tests": len(statuses), "status_counts": dict(counts), "exit_code": exit_code,
            "log_sha256": hashlib.sha256(log.encode()).hexdigest(),
            "nonpassing_ids": {name: status for name, status in statuses.items() if status != "ok"},
            "enumerated_matches_reported": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("log", type=Path)
    parser.add_argument("--exit-code", type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(report(args.log.read_text(), args.exit_code), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
