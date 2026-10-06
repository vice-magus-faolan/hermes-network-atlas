#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only full native scan; no installer, confirmation, force or config reads."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
import sys

from acceptance_support import HERMES_COMMIT, ROOT, git_head, git_tree
from offline_guard import deny_network


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--core", type=Path, required=True)
    args = parser.parse_args()
    core = args.core.resolve()
    if not (core / ".git").exists() or git_head(core) != HERMES_COMMIT:
        raise ValueError("actual pinned public core checkout required")
    deny_network()
    sys.path.insert(0, str(core))
    from tools.plugin_guard import scan_plugin, should_allow_plugin_install
    result = scan_plugin(ROOT, source="network-atlas@" + git_head())
    allowed, reason = should_allow_plugin_install(result, force=False)
    report = {"candidate_commit": git_head(), "candidate_tree": git_tree(), "hermes_commit": HERMES_COMMIT,
              "admission_executed": False, "force": False, "verdict": result.verdict,
              "policy_allowed": allowed, "policy_reason": reason,
              "finding_count": len(result.findings), "severity_counts": dict(Counter(item.severity for item in result.findings)),
              "scan_provenance": result.scan_provenance, "findings": [asdict(item) for item in result.findings]}
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
