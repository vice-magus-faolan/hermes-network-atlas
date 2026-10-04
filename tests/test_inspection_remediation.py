# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline A02/A05/A09 regressions: SSH inventory is not an exact-address probe."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from unittest.mock import patch

from helpers import ROOT
from test_core import AtlasFixture, NOW, render
from test_discovery import discovery, xml
from test_inspection import (ALIAS, MAC, MAC2, config, core, inspection, outputs,
                             query, reconcile, runner, storage, tools, updates)


class InspectionReachabilityTests(AtlasFixture):
    def inspected_host(self):
        """Reconcile only the fixed SSH inventory, including disconnected addresses."""
        core.apply_update(self.store, updates.operator_update(
            {"device_id": self.device, "field": "ssh_alias", "value": ALIAS}, self.policy), now=NOW)
        payloads = outputs()
        interfaces = [
            {"ifname": "management0", "address": MAC, "operstate": "UP",
             "addr_info": [{"local": "198.51.100.1", "prefixlen": 24},
                           {"local": "2001:db8::1", "prefixlen": 64}]},
            {"ifname": "disconnected0", "address": MAC2, "operstate": "DOWN",
             "addr_info": [{"local": "203.0.113.42", "prefixlen": 24},
                           {"local": "fe80::1234", "prefixlen": 64}]},
        ]
        payloads["ip -j address"] = json.dumps(interfaces).encode()
        payloads["ip -j link"] = json.dumps(
            [{key: value for key, value in item.items() if key != "addr_info"} for item in interfaces]).encode()
        calls = []

        def transport(argv, limits, deadline, **kwargs):
            calls.append(argv)
            self.assertEqual(argv[-2], ALIAS)
            return runner.CommandResult("success", payloads[argv[-1]])

        with patch.object(inspection, "utc_now", return_value=NOW), patch.object(inspection, "run", transport), patch(
                "subprocess.Popen", side_effect=AssertionError("offline only")):
            receipt = inspection.collect(self.policy, {"target": self.device})
            result = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual([call[-1] for call in calls], [" ".join(command) for _, command, _ in inspection.PROBES])
        self.assertEqual(len(calls), 7)
        self.assertEqual(receipt["completion"], "complete")
        self.assertFalse(result["new"])
        return receipt

    def assert_inventory_not_reachability(self, detail, batch):
        interfaces = {item["fields"]["name"]["value"]: item for item in detail["interfaces"]}
        self.assertEqual(set(interfaces), {"management0", "disconnected0"})
        self.assertEqual(interfaces["management0"]["fields"]["state"]["value"], "UP")
        self.assertEqual(interfaces["disconnected0"]["fields"]["state"]["value"], "DOWN")
        addresses = {item["address"]: item for interface in interfaces.values() for item in interface["addresses"]}
        self.assertEqual(set(addresses), {"198.51.100.1", "2001:db8::1", "203.0.113.42", "fe80::1234"})
        for address in addresses.values():
            with self.subTest(address=address["address"]):
                self.assertFalse(address["reachable_by_this_probe"])
                self.assertTrue(address["current"])
                self.assertTrue(address["qualified"])
                self.assertTrue(address["observed_in_batch"])
                self.assertEqual(address["batch_id"], batch)
                self.assertEqual(address["evidence_kind"], "ssh_response")
                self.assertEqual(address["source"], "ssh:" + ALIAS)
                self.assertEqual(address["confidence"], "observed")
                self.assertIsNotNone(address["first_seen"])
                self.assertIsNotNone(address["last_seen"])
        access = detail["access"][0]
        self.assertEqual(access["alias"], ALIAS)
        self.assertTrue(access["authorized_for_atlas_ssh_inspection"])
        self.assertTrue(access["last_inspection"]["succeeded"])
        self.assertEqual(access["last_inspection"]["alias"], ALIAS)
        self.assertEqual(access["last_inspection"]["batch_id"], batch)

    def test_up_down_and_link_local_inventory_preserves_alias_success_and_history(self):
        receipt = self.inspected_host()
        before = self.counts()
        with patch.object(inspection, "run", side_effect=AssertionError("query must not inspect")), patch.object(
                discovery, "run", side_effect=AssertionError("query must not discover")), patch.object(query, "utc_now", return_value=NOW):
            self.assert_inventory_not_reachability(self.detail(), receipt["batch_id"])
            handlers = tools.Handlers(self.home)
            public = json.loads(handlers.query({"device_id": self.device}))
            slash = json.loads(handlers.command("show " + self.device))
            code, cli = self.cli(["query", "--query-json", json.dumps({"device_id": self.device})])
            self.assertEqual(code, 0)
            for result in (public, slash, cli):
                self.assertFalse(result["discovery_performed"])
                self.assert_inventory_not_reachability(result["devices"][0], receipt["batch_id"])
            for address in ("198.51.100.1", "203.0.113.42", "fe80::1234"):
                detail = query.query(self.policy, {"address": address}, now=NOW)["devices"][0]
                self.assertEqual(detail["id"], self.device)
                self.assert_inventory_not_reachability(detail, receipt["batch_id"])
            history = query.query(self.policy, {"view": "history", "device_id": self.device}, now=NOW)["observations"]
            assignments = [fact for fact in history if fact["field"] == "assignment"]
            self.assertEqual(len(assignments), 4)
            self.assertTrue(all(fact["source"] == "ssh:" + ALIAS and fact["confidence"] == "observed" for fact in assignments))
            status = query.query(self.policy, {"view": "status"}, now=NOW)
            self.assertTrue(status["last_inspection"]["succeeded"])
            self.assertEqual(status["last_inspection"]["alias"], ALIAS)
        self.assertEqual(self.counts(), before)

    def test_reopened_fresh_process_query_maps_and_exports_do_not_collect_or_promote(self):
        receipt = self.inspected_host()
        before = self.counts()
        with storage.Store(self.policy) as reopened, reopened.snapshot():
            row = reopened.require("devices", self.device)
            self.assert_inventory_not_reachability(query.device_detail(reopened, row, NOW), receipt["batch_id"])
        (self.home / "synthetic-phase1-home").touch()
        expected_query = query.query(self.policy, {}, now=NOW)
        expected_map = render.render_map(self.policy, now=NOW)
        child = subprocess.run([sys.executable, str(ROOT / "scripts/phase1_reopen.py"), str(self.home)],
                               cwd=self.home, env={"PATH": str(self.home / "no-executables"),
                               "TMPDIR": os.environ["TMPDIR"], "HOME": str(self.home / "user"),
                               "HERMES_HOME": str(self.home), "PYTHONDONTWRITEBYTECODE": "1"},
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(result["query"], expected_query)
        self.assertEqual(result["map"], expected_map)
        self.assertEqual(result["history_count"], before["observations"])
        self.assert_inventory_not_reachability(result["query"]["devices"][0], receipt["batch_id"])
        self.assertEqual(self.counts(), before)
        with patch.object(inspection, "run", side_effect=AssertionError("map/export must not inspect")), patch.object(
                discovery, "run", side_effect=AssertionError("map/export must not discover")), patch(
                "subprocess.Popen", side_effect=AssertionError("map/export must not execute")):
            self.assertIn("stored knowledge, not live reachability", expected_map["text"])
            self.assertIn("Authorization is not reachability", expected_map["markdown"])
            self.assertIn("never a reachability claim", expected_map["mermaid"])
            paths = render.export_map(self.policy, expected_map, now=NOW)
        self.assertEqual(len(paths), 2)
        self.assertEqual((self.policy.exports / "network_map.md").read_text(), expected_map["markdown"])
        self.assertEqual((self.policy.exports / "network_map.mmd").read_text(), expected_map["mermaid"])

    def test_exact_address_ping_positive_control_does_not_promote_sibling_addresses(self):
        self.inspected_host()
        raw = json.loads(json.dumps(self.raw))
        raw["networks"] = {"one": {"cidr": "198.51.100.1/32", "discovery": {"passive": False, "ping": True}}}
        policy = config.validate_policy(raw, self.home)
        with patch.object(discovery, "run", return_value=runner.CommandResult("success", xml("198.51.100.1", MAC))) as transport:
            receipt = discovery.collect(policy, {"network": "one", "mode": "ping"})
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(transport.call_args.args[0][-1], "198.51.100.1/32")
        reconcile.reconcile(policy, {"batch_id": receipt["batch_id"]})
        detail = query.query(policy, {"device_id": self.device}, now=NOW)["devices"][0]
        addresses = [item for interface in detail["interfaces"] for item in interface["addresses"]]
        ping = [item for item in addresses if item["evidence_kind"] == "ping_response"]
        self.assertEqual(len(ping), 1)
        self.assertEqual(ping[0]["address"], "198.51.100.1")
        self.assertTrue(ping[0]["qualified"])
        self.assertTrue(ping[0]["reachable_by_this_probe"])
        inventory = [item for item in addresses if item["evidence_kind"] == "ssh_response"]
        self.assertEqual(len(inventory), 4)
        self.assertTrue(all(not item["reachable_by_this_probe"] for item in inventory))
        self.assertTrue(detail["access"][0]["last_inspection"]["succeeded"])
