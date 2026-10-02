# SPDX-License-Identifier: GPL-3.0-or-later
"""Mandatory supported admission receipt + socket-denied three-alias native acceptance."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT

spec = importlib.util.spec_from_file_location("acceptance_support", ROOT / "scripts" / "acceptance_support.py")
assert spec and spec.loader
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


class CumulativeAcceptanceTests(unittest.TestCase):
    def test_supported_admission_three_aliases_and_fresh_process_without_collection(self):
        value = os.environ.get("NETWORK_ATLAS_ACCEPTANCE_FIXTURE")
        self.assertTrue(value, "Run scripts/prepare_acceptance.py OUTSIDE network-denied tests; missing admission is FAILURE")
        root = support.fixture_root(value)
        receipt = support.validate_receipt(root)
        home = root / "hermes"
        atlas = home / "network-atlas"
        # Native setup remains untouched. Repeated verification may start a NEW
        # synthetic scenario by removing only this marked fixture's generated data.
        if atlas.exists():
            self.assertFalse(atlas.is_symlink())
            self.assertTrue(atlas.resolve().is_relative_to(root))
            shutil.rmtree(atlas)
        atlas.mkdir(mode=0o700)
        policy = {"version": 1, "networks": {"lab": {"cidr": "192.0.2.0/29", "discovery": {"passive": True, "ping": True}}},
                  "ssh": {"enabled": True, "hosts": {alias: {"alias": alias, "inspect": True} for alias in ("lab-a", "lab-b", "lab-c")}},
                  "limits": {"result_count": 100}, "retention": {"stale_after_days": 14}}
        (atlas / "config.yaml").write_text(json.dumps(policy))
        (atlas / "config.yaml").chmod(0o600)
        fixture = root / "fixture-bin"
        fixture.mkdir(exist_ok=True)
        (fixture / "offline-fixture").touch()
        (fixture / "stage").write_text("baseline")
        (fixture / "calls.jsonl").write_text("")
        # PATH contains ONLY non-forwarding fixture binaries and a Python alias.
        # Missing fixture executable can never resolve the host ip/nmap/ssh.
        python = fixture / "python3"
        python.unlink(missing_ok=True)
        python.symlink_to(receipt["python"])
        for name in ("ip", "nmap", "ssh"):
            shutil.copy2(ROOT / "scripts" / "cumulative_transport.py", fixture / name)
            (fixture / name).chmod(0o700)
        env = support.fixture_environment(root)
        env["PATH"] = str(fixture)
        env["NETWORK_ATLAS_OFFLINE_FIXTURE_DIR"] = str(fixture)
        command = [receipt["python"], str(ROOT / "scripts" / "cumulative_acceptance.py"), receipt["source"]]
        first = subprocess.run([*command, "collect"], env=env, cwd=root, capture_output=True, text=True, timeout=120)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        calls = (fixture / "calls.jsonl").read_bytes()
        log = [json.loads(line) for line in calls.splitlines()]
        self.assertEqual({row["args"][-2] for row in log if row["binary"] == "ssh"}, {"lab-a", "lab-b", "lab-c"})
        self.assertEqual(len([row for row in log if row["binary"] == "nmap"]), 16)
        for name in ("ip", "nmap", "ssh"):
            (fixture / name).unlink()
        second = subprocess.run([*command, "reopen"], env=env, cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(calls, (fixture / "calls.jsonl").read_bytes(), "restart must not collect")
        self.assertTrue(json.loads(second.stdout.splitlines()[-1])["fresh_process_persistence"])
        # Read back exact native installed bytes/selector/generation after tests.
        support.validate_receipt(root)
        print("Cumulative native acceptance: " + first.stdout.splitlines()[-1], flush=True)
        print("Cumulative native restart: " + second.stdout.splitlines()[-1], flush=True)

    def test_missing_stale_or_escaped_fixture_evidence_fails_closed(self):
        with self.assertRaises(ValueError):
            support.fixture_root(os.environ["TMPDIR"])
        with patch.object(support, "git_head", return_value="different"), self.assertRaises(ValueError):
            value = os.environ.get("NETWORK_ATLAS_ACCEPTANCE_FIXTURE")
            self.assertTrue(value, "mandatory native admission fixture absent")
            support.validate_receipt(support.fixture_root(value))
