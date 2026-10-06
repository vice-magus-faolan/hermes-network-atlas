#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Focused packet-denied harness regressions; NOT Docker/native acceptance."""
from pathlib import Path
import unittest

from offline_guard import deny_network
from verify import check_docker_source


def main() -> int:
    deny_network()
    if not check_docker_source():
        raise ValueError("harness complexity/source check failed")
    root = Path(__file__).resolve().parents[1]
    suite = unittest.defaultTestLoader.discover(str(root / "tests"), pattern="test_docker*.py")
    if suite.countTestCases() == 0:
        raise ValueError("no Docker contract tests discovered")
    print(f"Focused packet-denied harness: {suite.countTestCases()} tests; no real Docker/native effects", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
