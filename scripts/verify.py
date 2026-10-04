#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run bootstrap, implemented behavior/review regressions, and native-runtime smoke.

Requires a compatible Hermes runtime, an existing TMPDIR, and a candidate-bound
NETWORK_ATLAS_ACCEPTANCE_FIXTURE prepared OUTSIDE this network-denied process.
Missing prerequisites are failures, not skipped integration coverage.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import unittest

from offline_guard import deny_network

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_FILES = ("__init__.py", "config.py", "schemas.py", "updates.py", "tools.py", "commands.py",
                "storage.py", "facts.py", "identity.py", "core.py", "query.py", "batches.py", "render.py",
                "probes.py", "discovery_parse.py", "discovery.py", "reconcile.py", "inspection.py",
                "inspection_parse.py", "inspection_evidence.py", "ssh_identity.py", "unresolved.py")

REQUIRED_CHUNK_TESTS = {
    "test_discovery_chunks.ChunkDiscoveryTests.test_sparse_24_startup_budget_reaches_last_address_and_reconciles_exact_batch",
    "test_discovery_chunks.ChunkDiscoveryTests.test_mid_chunk_deadline_keeps_earlier_positive_and_marks_tail_not_started",
    "test_discovery_chunks.ChunkParserTests.test_hostile_duplicate_out_of_chunk_stats_and_output_bounds",
    "test_status_remediation.StatusBatchBoundsTests.test_legacy_per_address_24_and_25_totals_remain_readable_after_restart",
}


def test_ids(suite: unittest.TestSuite) -> set[str]:
    """Require critical issue regressions in discovery, not just a nonzero count."""
    result = set()
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            result.update(test_ids(item))
        else:
            result.add(item.id())
    return result


def check_source() -> bool:
    """Compile plugin sources and report a conservative AST branch estimate.

    This is a local review signal, not an exact McCabe metric. Count conditions,
    handlers, boolean alternatives, and comprehensions; require refactoring
    above 15 rather than quietly waiving the repository's review threshold.
    """
    valid = True
    maximum = 0
    actual = {path.name for path in ROOT.glob("*.py")}
    if actual != set(PLUGIN_FILES):
        print(f"ERROR: undeclared/absent plugin modules: {actual ^ set(PLUGIN_FILES)}")
        valid = False
    for path in (ROOT / "scripts").glob("*.py"):
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    for filename in PLUGIN_FILES:
        path = ROOT / filename
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=filename)
        compile(tree, filename, "exec")
        for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
            score = 1
            for node in ast.walk(function):
                if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.ExceptHandler, ast.comprehension)):
                    score += 1
                if isinstance(node, ast.BoolOp):
                    score += len(node.values) - 1
            maximum = max(maximum, score)
            if score > 10:
                print(f"Complexity review: {filename}:{function.lineno} {function.name} estimate={score}")
            if score > 15:
                valid = False
    print(f"Plugin source check: maximum conservative branch estimate={maximum}", flush=True)
    return valid


def main() -> int:
    """Run discovered tests and refuse a misleading zero-test success."""
    os.chdir(ROOT)
    deny_network()
    if not check_source():
        print("ERROR: refactor function(s) estimated above 15 before review")
        return 1
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    count = suite.countTestCases()
    if count == 0:
        print("ERROR: no tests discovered")
        return 1
    missing = REQUIRED_CHUNK_TESTS - test_ids(suite)
    if missing:
        print(f"ERROR: bounded chunk regression coverage absent: {sorted(missing)}")
        return 1
    print(f"Canonical verification: {count} tests discovered; cumulative synthetic V1, NOT live validation", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
