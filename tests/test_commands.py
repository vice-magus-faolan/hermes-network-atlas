# SPDX-License-Identifier: GPL-3.0-or-later
"""Cumulative operator/status contracts, using only synthetic isolated state."""
import argparse
from contextlib import redirect_stdout
import importlib
import io
import json
from pathlib import Path
from datetime import timedelta
import sys
import unittest
from unittest.mock import patch

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from offline_guard import deny_network
    deny_network()

from helpers import scratch_home
from test_boundaries import synthetic_policy
from test_core import NOW, batches, core, query, storage, config, tools

commands = importlib.import_module("atlas_test_plugin.commands")


class OperatorStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        raw = synthetic_policy()
        directory = self.home / "network-atlas"
        directory.mkdir()
        (directory / "config.yaml").write_text(json.dumps(raw))
        self.policy = config.load_policy(self.home)
        self.handlers = tools.Handlers(self.home)

    def test_empty_status_has_consistent_counts_scopes_and_no_file_effects(self):
        before = set(self.home.rglob("*"))
        result = json.loads(self.handlers.command("status"))
        self.assertEqual(result["stage"], "v1")
        self.assertEqual(result["known_devices"], 0)
        self.assertEqual(result["observed_devices"], 0)
        self.assertEqual(result["stale_devices"], 0)
        self.assertEqual(result["authorized_devices_for_atlas_ssh_inspection"], 0)
        self.assertIsNone(result["last_discovery"])
        self.assertEqual(result["configured_scopes"], [{"name": "lab", "cidr": "192.0.2.0/24", "passive": True,
                                                       "ping": True, "icmp_echo": False, "tcp_ports": [80, 443]}])
        self.assertEqual(set(self.home.rglob("*")), before)

    def test_cli_invalid_policy_refusal_has_explicit_no_effects_receipt(self):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        routes = (["discover", "--network", "lab", "--mode", "ping"],
                  ["status"], ["create", "--name", "Synthetic device"],
                  ["update", "--device-id", "00000000-0000-0000-0000-000000000001",
                   "--field", "description", "--value-json", '"Synthetic assertion"'])
        path = self.home / "network-atlas" / "config.yaml"
        original = path.read_bytes()
        self.addCleanup(path.write_bytes, original)
        for existing_store in (False, True):
            if existing_store:
                with storage.Store(self.policy, writable=True) as store:
                    core.create_device(store, "Existing synthetic device", now=NOW)
            for methods in ({"icmp_echo": 1}, {"tcp_ports": [4403]},
                            {"icmp_echo": True, "options": "-PE"}):
                raw = json.loads(original)
                raw["networks"]["lab"]["discovery"].update(methods)
                path.write_text(json.dumps(raw))
                before = {item.relative_to(self.home): item.read_bytes()
                          for item in self.home.rglob("*") if item.is_file()}
                with patch.object(commands, "_read_command") as read, patch.object(commands, "_write_command") as write:
                    for argv in routes:
                        with self.subTest(existing_store=existing_store, methods=methods, argv=argv):
                            output = io.StringIO()
                            with redirect_stdout(output):
                                code = commands.run_command(parser.parse_args(argv), self.home)
                            result = json.loads(output.getvalue())
                            self.assertEqual(code, 2)
                            self.assertIn("error", result)
                            self.assertIs(result["applied"], False)
                            self.assertIs(result["persisted"], False)
                            self.assertEqual({item.relative_to(self.home): item.read_bytes()
                                              for item in self.home.rglob("*") if item.is_file()}, before)
                    read.assert_not_called()
                    write.assert_not_called()

    def test_discovery_and_inspection_are_distinct_local_qualified_summaries(self):
        old = NOW - timedelta(days=20)
        with storage.Store(self.policy, writable=True) as store:
            known = core.create_device(store, "Known", now=old)["device_id"]
            stale = core.create_device(store, "Previously seen", now=old)["device_id"]
            with store.transaction():
                core.append_fact(store, "device", stale, "hostname", "old-host", "ssh:lab-router",
                                 "observed", batches.timestamp(old), evidence_kind="ssh_response", qualified=True)
                core._positive(store, stale, batches.timestamp(old))
            at = batches.timestamp(NOW)
            passive = batches.store_batch(store, "local_passive", "lab", at, at, "partial", (
                batches.Probe("ip_addr", "success", at, at, "local_host", self.policy.networks[0].cidr, "local_interface"),
                batches.Probe("ip_neigh", "unavailable", at, at, "none", "", "none", "missing_executable")))
            ssh = batches.store_batch(store, "ssh", "lab-router", at, at, "failed", (
                batches.Probe("hostname", "command_failed", at, at, "none", "", "none", "command_failed"),))
        result = query.query(self.policy, {"view": "status"}, now=NOW)
        self.assertEqual(result["known_devices"], 2)
        self.assertEqual(result["stale_devices"], 1)
        self.assertEqual(result["observed_devices"], 0)
        self.assertEqual(result["last_discovery"]["id"], passive)
        self.assertEqual(result["last_discovery"]["completion"], "partial")
        self.assertEqual(result["last_discovery"]["scope_value"], "192.0.2.0/24")
        self.assertFalse(result["last_discovery"]["scope_absence_eligible"])
        self.assertEqual({probe["outcome"] for probe in result["last_discovery"]["probes"]}, {"success", "unavailable"})
        self.assertEqual(result["last_inspection"]["batch_id"], ssh)
        self.assertFalse(result["last_inspection"]["succeeded"])
        self.assertEqual({item["id"] for item in query.query(self.policy, {})["devices"]}, {known, stale})

    def test_shared_foreign_batches_do_not_claim_local_last_discovery(self):
        with storage.Store(self.policy, writable=True) as store:
            at = batches.timestamp(NOW)
            batches.store_batch(store, "ping", "lab", at, at, "complete", (
                batches.Probe("nmap", "success", at, at, "exact_network", "192.0.2.0/24", "ping_response"),))
        raw = {"store": {"shared_sqlite_path": str(self.policy.database)}}
        foreign = config.validate_policy(raw, self.home / "foreign")
        self.assertIsNone(query.query(foreign, {"view": "status"}, now=NOW)["last_discovery"])
        self.assertTrue(query.query(self.policy, {"view": "status"}, now=NOW)["last_discovery"]["scope_absence_eligible"])

    def test_slash_exact_arities_and_usage_no_origin_promotion(self):
        for text in ("", "status extra", "show", "show a b", "map text extra", "discover lab", "inspect a b", "reconcile a b"):
            with self.subTest(text=text):
                result = json.loads(self.handlers.command(text))
                self.assertIn("error", result)
                self.assertIn("usage", result)
                self.assertFalse(result["applied"])
        result = json.loads(self.handlers.command('update {"source":"user"}'))
        self.assertIn("operator CLI", result["error"])
        self.assertFalse(result["applied"])
        self.assertEqual(json.loads(self.handlers.command("help"))["operator_update_route"], "hermes network-atlas update")
        with patch.object(self.handlers, "query", return_value="fixture-query") as read:
            self.assertEqual(self.handlers.command("show fixture-id"), "fixture-query")
            read.assert_called_once_with({"device_id": "fixture-id"})


if __name__ == "__main__":
    unittest.main()
