# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline status boundaries for full-size scopes and lowered inventory pagination."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import redirect_stdout
import io
from ipaddress import ip_network
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
from test_boundaries import synthetic_policy
from test_core import NOW, batches, commands, config, core, query, storage, tools
from test_discovery import discovery, runner, xml


# This child uses the same test module, but loads no operator/profile data.
REOPEN = """
import sys
sys.path[:0] = [sys.argv[1], sys.argv[2]]
from offline_guard import deny_network
deny_network()
from test_status_remediation import public_status
from pathlib import Path
import json
print(json.dumps(public_status(Path(sys.argv[3]))))
"""


def public_status(home: Path) -> dict:
    """Exercise the real tool/slash/operator handlers, with collection forbidden."""
    handlers = tools.Handlers(home)
    parser = argparse.ArgumentParser()
    commands.setup_parser(parser)
    stdout = io.StringIO()
    with patch.object(tools, "collect", side_effect=AssertionError("query collected")), \
            patch.object(tools, "inspect_host", side_effect=AssertionError("query inspected")):
        result = {"direct": query.query(config.load_policy(home), {"view": "status"}),
                  "tool": json.loads(handlers.query({"view": "status"})),
                  "slash": json.loads(handlers.command("status"))}
        with redirect_stdout(stdout):
            result["cli_exit"] = commands.run_command(parser.parse_args(["status"]), home)
        result["cli"] = json.loads(stdout.getvalue())
    return result


class StatusBatchBoundsTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.raw = synthetic_policy()
        (self.home / "network-atlas").mkdir()
        self.configure()

    def configure(self, *, prefix=24, limit=100):
        self.raw["networks"]["lab"]["cidr"] = f"192.0.2.0/{prefix}"
        self.raw["limits"] = {"result_count": limit}
        (self.home / "network-atlas" / "config.yaml").write_text(json.dumps(self.raw))
        self.policy = config.load_policy(self.home)

    def assert_summary(self, batch, receipt, limit):
        expected = Counter(probe["outcome"] for probe in receipt["probes"])
        info = batch["probe_summary"]
        self.assertEqual(batch["id"], receipt["batch_id"])
        self.assertEqual(batch["completion"], receipt["completion"])
        self.assertEqual(info["total_count"], len(receipt["probes"]))
        self.assertEqual(info["outcome_counts"], {key: expected[key] for key in batches.OUTCOMES})
        self.assertEqual(sum(info["coverage_counts"].values()), info["total_count"])
        self.assertEqual(info["failure_count"], info["total_count"] - expected["success"])
        self.assertEqual(info["detail_limit"], limit)
        self.assertEqual(info["returned_count"], min(limit, info["total_count"]))
        self.assertEqual(len(batch["probes"]), info["returned_count"])
        self.assertEqual(info["omitted_count"], info["total_count"] - len(batch["probes"]))
        shown_failures = sum(probe["outcome"] != "success" for probe in batch["probes"])
        self.assertEqual(info["omitted_failure_count"], info["failure_count"] - shown_failures)
        self.assertEqual(shown_failures, min(limit, info["failure_count"]))
        eligible = receipt["completion"] == "complete" and batch["collector"] == "ping"
        self.assertEqual(batch["scope_absence_eligible"], eligible)
        self.assertEqual(info["absence_eligible_count"], int(eligible))

    def assert_public_reopen(self, receipt, limit):
        before = self.policy.database.read_bytes()
        results = public_status(self.home)
        self.assertEqual(results["cli_exit"], 0, results)
        for route in ("direct", "tool", "slash", "cli"):
            self.assertNotIn("error", results[route])
            self.assertEqual(results[route]["known_devices"], 1)
            self.assert_summary(results[route]["last_collection"], receipt, limit)
            self.assertLessEqual(len(storage.response_json(results[route], self.policy.limits.output_bytes).encode()),
                                 self.policy.limits.output_bytes)
        child = subprocess.run([sys.executable, "-c", REOPEN, str(ROOT / "tests"), str(ROOT / "scripts"), str(self.home)],
                               env={"PATH": "/usr/bin:/bin", "HOME": str(self.home / "user"),
                                    "HERMES_HOME": str(self.home), "TMPDIR": os.environ["TMPDIR"],
                                    "PYTHONDONTWRITEBYTECODE": "1"},
                               cwd=self.home, capture_output=True, text=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout), results)
        self.assertEqual(self.policy.database.read_bytes(), before)
        return results

    def ping_scenario(self, prefix, completion, limit):
        # Each subtest owns a fresh synthetic database even when an assertion fails.
        self.temp.cleanup()
        self.setUp()
        self.configure(prefix=prefix, limit=limit)
        size = ip_network(self.policy.networks[0].cidr).num_addresses
        last = str(list(ip_network(self.policy.networks[0].cidr))[-1])
        def transport(argv, *args, **kwargs):
            self.assertEqual(argv[:4], ("nmap", "-sn", "-n", "-PS80,443"))
            if completion == "failed" or completion == "partial" and argv[-1] == last:
                return runner.CommandResult("timeout", diagnostic_code="command_deadline_exceeded")
            return runner.CommandResult("success", xml(argv[-1], up=False))
        with storage.Store(self.policy, writable=True) as store:
            core.create_device(store, "Synthetic known host", now=NOW)
        with patch.object(discovery, "run", transport):
            receipt = json.loads(tools.Handlers(self.home).discover({"network": "lab", "mode": "ping"}))
        self.assertTrue(receipt["persisted"], receipt)
        self.assertEqual(receipt["completion"], completion)
        self.assertEqual(len(receipt["probes"]), size + 1)
        results = self.assert_public_reopen(receipt, limit)
        summary = results["direct"]["last_discovery"]
        self.assertEqual(summary, results["direct"]["last_collection"])
        self.assertEqual(summary["scope_value"], self.policy.networks[0].cidr)
        self.assertEqual(summary["probe_summary"]["coverage_counts"]["exact_network"], int(completion == "complete"))
        self.assertEqual(summary["probe_summary"]["outcome_counts"]["timeout"],
                         size if completion == "failed" else int(completion == "partial"))
        self.assertIsNone(results["direct"]["last_inspection"])

    def test_full_size_ping_complete_partial_failed_and_small_control_after_restart(self):
        for prefix in (24, 25, 26):
            for completion in ("complete", "partial", "failed"):
                with self.subTest(prefix=prefix, completion=completion):
                    self.ping_scenario(prefix, completion, 100)

    def test_full_size_ping_lowered_detail_limits_do_not_change_whole_batch_evidence(self):
        for prefix in (24, 25):
            for completion in ("complete", "partial", "failed"):
                for limit in (1, 2):
                    with self.subTest(prefix=prefix, completion=completion, limit=limit):
                        self.ping_scenario(prefix, completion, limit)

    def test_lowered_limit_passive_and_ssh_status_keep_distinct_complete_evidence(self):
        self.configure(limit=1)
        at = storage.timestamp(NOW)
        with storage.Store(self.policy, writable=True) as store:
            core.create_device(store, "Synthetic known host", now=NOW)
            passive = batches.store_batch(store, "local_passive", "lab", at, at, "partial", (
                batches.Probe("ip_addr", "success", at, at, "local_host", self.policy.networks[0].cidr, "local_interface"),
                batches.Probe("ip_route", "unavailable", at, at, "none", "", "none", "missing_executable"),
                batches.Probe("ip_neigh", "parse_failed", at, at, "none", "", "cached_neighbor", "invalid_bounded_output")), receipt=True)
            ssh_probes = tuple(batches.Probe(f"probe_{i}", outcome, at, at, "none", "", "ssh_response", outcome)
                               for i, outcome in enumerate(batches.OUTCOMES))
            ssh = batches.store_batch(store, "ssh", "lab-router", at, at, "partial", ssh_probes, receipt=True)
        results = self.assert_public_reopen(ssh, 1)
        for route in ("direct", "tool", "slash", "cli"):
            result = results[route]
            self.assert_summary(result["last_discovery"], passive, 1)
            self.assertEqual(result["last_inspection"]["batch_id"], ssh["batch_id"])
            self.assertTrue(result["last_inspection"]["succeeded"])
            self.assertEqual(len(result["last_inspection"]["probes"]), len(batches.OUTCOMES))
            self.assertEqual(result["last_collection"]["probe_summary"]["outcome_counts"],
                             {key: 1 for key in batches.OUTCOMES})

    def test_lowered_limit_passive_and_ssh_complete_and_failed_after_restart(self):
        for collector, count, evidence in (("local_passive", 3, "none"), ("ssh", 7, "ssh_response")):
            for completion, outcome in (("complete", "success"), ("failed", "unavailable")):
                with self.subTest(collector=collector, completion=completion):
                    self.temp.cleanup()
                    self.setUp()
                    self.configure(limit=1)
                    at = storage.timestamp(NOW)
                    probes = tuple(batches.Probe(f"probe_{i}", outcome, at, at, "none", "", evidence, outcome)
                                   for i in range(count))
                    with storage.Store(self.policy, writable=True) as store:
                        core.create_device(store, "Synthetic known host", now=NOW)
                        receipt = batches.store_batch(store, collector, "lab" if collector == "local_passive" else "lab-router",
                                                      at, at, completion, probes, receipt=True)
                    results = self.assert_public_reopen(receipt, 1)
                    result = results["direct"]
                    if collector == "ssh":
                        self.assertIsNone(result["last_discovery"])
                        self.assertEqual(result["last_inspection"]["succeeded"], outcome == "success")
                        self.assertEqual(len(result["last_inspection"]["probes"]), count)
                    else:
                        self.assertEqual(result["last_discovery"], result["last_collection"])
                        self.assertIsNone(result["last_inspection"])

    def test_status_output_cap_still_refuses_without_store_changes(self):
        self.configure(limit=1)
        at = storage.timestamp(NOW)
        with storage.Store(self.policy, writable=True) as store:
            batches.store_batch(store, "ping", "lab", at, at, "complete", (
                batches.Probe("ping_coverage", "success", at, at, "exact_network", self.policy.networks[0].cidr, "ping_response"),))
        before = self.policy.database.read_bytes()
        self.raw["limits"]["output_bytes"] = 128
        (self.home / "network-atlas" / "config.yaml").write_text(json.dumps(self.raw))
        result = public_status(self.home)
        self.assertEqual(result["cli_exit"], 2)
        for route in ("tool", "slash", "cli"):
            self.assertIn("error", result[route])
        self.assertEqual(self.policy.database.read_bytes(), before)
