#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run canonical offline checks; currently bootstrap tests, not V1 acceptance."""
from __future__ import annotations

import os
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    """Run discovered tests and refuse a misleading zero-test success."""
    os.chdir(ROOT)
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    count = suite.countTestCases()
    if count == 0:
        print("ERROR: no tests discovered")
        return 1
    print(f"Canonical verification: {count} tests discovered", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
