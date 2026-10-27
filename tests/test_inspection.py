# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic A03/A05/A08/A09/A12 inspection evidence; no real SSH subprocess."""
from __future__ import annotations

from dataclasses import replace
import importlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from helpers import fixture_handlers, load_package, scratch_home
from test_core import AtlasFixture, NOW

load_package()
inspection = importlib.import_module("atlas_test_plugin.inspection")
parse = importlib.import_module("atlas_test_plugin.inspection_parse")
config = importlib.import_module("atlas_test_plugin.config")
core = importlib.import_module("atlas_test_plugin.core")
updates = importlib.import_module("atlas_test_plugin.updates")
query = importlib.import_module("atlas_test_plugin.query")
reconcile = importlib.import_module("atlas_test_plugin.reconcile")
storage = importlib.import_module("atlas_test_plugin.storage")
runner = importlib.import_module("atlas_test_plugin.probes")
tools = importlib.import_module("atlas_test_plugin.tools")
schemas = importlib.import_module("atlas_test_plugin.schemas")

MAC = "00:11:22:33:44:77"
MAC2 = "00:11:22:33:44:88"
ALIAS = "lab-router"


def outputs():
    return {"hostname": b"fixture-host\n", "hostnamectl --static": b"fixture-host\n",
            "cat /etc/os-release": b'NAME="Fixture Linux"\nPRETTY_NAME="Fixture Linux 1"\nID=fixture\n',
            "ip -j address": json.dumps([{"ifname": "fixture0", "address": MAC, "operstate": "UP",
                "addr_info": [{"local": "198.51.100.1", "prefixlen": 24},
                              {"local": "2001:db8::1", "prefixlen": 64}]}]).encode(),
            "ip -j link": json.dumps([{"ifname": "fixture0", "address": MAC, "operstate": "UP"},
                                      {"ifname": "fixture1", "address": MAC2, "operstate": "DOWN"}]).encode(),
            "ip -j route": b'[{"dst":"203.0.113.0/24","gateway":"198.51.100.254","dev":"fixture0"}]',
            "ip -j neigh": b'[{"dst":"198.51.100.20","lladdr":"00:11:22:33:44:99","state":["STALE"]}]'}


class InspectionTests(AtlasFixture):
    def associate(self, device=None):
        core.apply_update(self.store, updates.operator_update({"device_id": device or self.device,
                          "field": "ssh_alias", "value": ALIAS}, self.policy), now=NOW)

    def collect(self, policy=None, target=ALIAS, payloads=None):
        payloads = outputs() if payloads is None else payloads
        def fake(argv, limits, deadline, **kwargs):
            self.assertEqual(argv[-2], ALIAS)
            self.assertIn(argv[-1], outputs())
            self.assertTrue(kwargs["host"])
            self.assertFalse(self.store.connection.in_transaction)
            with storage.Store(self.policy, writable=True) as second, second.transaction():
                second.connection.execute("UPDATE devices SET retired=retired WHERE id=?", (self.device,))
            value = payloads.get(argv[-1], runner.CommandResult("unavailable", diagnostic_code="nonzero_exit"))
            return value if isinstance(value, runner.CommandResult) else runner.CommandResult("success", value)
        with patch.object(inspection, "run", fake):
            return inspection.collect(policy or self.policy, {"target": target})

    def test_exact_schema_and_request_boundary_before_any_effect(self):
        schema = schemas.INSPECT_SCHEMA["parameters"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["required"], ["target"])
        self.assertEqual(set(schema["properties"]), {"target"})
        bad = [{}, [], {"target": True}, {"target": ALIAS + ";id"}, {"target": "-oProxyCommand=x"},
               {"target": "user@lab-router"}, {"target": "192.0.2.10"}, {"target": "lab-router\n"},
               {"target": "lab-router host"}, {"target": "x" * 65}]
        bad += [{"target": ALIAS, key: "x"} for key in
                ("hostname", "username", "port", "command", "flags", "options", "probe", "source", "limits",
                 "permissions")]
        before = self.counts()
        with patch.object(inspection, "run", side_effect=AssertionError("unauthorized transport")):
            for params in bad:
                self.assertIn("error", json.loads(fixture_handlers(self.home).inspect(params)))
        self.assertEqual(self.counts(), before)

    def test_fixed_transport_strict_keys_and_no_config_side_channels(self):
        self.collect()
        for _, command, _ in inspection.PROBES:
            argv = inspection.ssh_argv(self.policy, ALIAS, command)
            self.assertEqual(argv[:5], ("ssh", "-T", "-n", "-a", "-x"))
            self.assertEqual(argv[-2:], (ALIAS, " ".join(command)))
            values = {argv[i + 1] for i, arg in enumerate(argv[:-2]) if arg == "-o"}
            self.assertTrue({"BatchMode=yes", "StrictHostKeyChecking=yes", "PermitLocalCommand=no", "LocalCommand=none",
                             "ClearAllForwardings=yes", "ForwardAgent=no", "ForwardX11=no", "ForwardX11Trusted=no",
                             "ControlMaster=no", "ControlPath=none", "ControlPersist=no", "RequestTTY=no",
                             "RemoteCommand=none", "Tunnel=no", "UpdateHostKeys=no", "ForkAfterAuthentication=no",
                             "AddKeysToAgent=no", "NoHostAuthenticationForLocalhost=no",
                             "KnownHostsCommand=none"} <= values)
            self.assertNotIn("sudo", argv)
            self.assertNotIn("sh", command)
        with self.assertRaises(ValueError):
            inspection.ssh_argv(self.policy, "-oX", ("hostname",))
        with self.assertRaises(ValueError):
            inspection.ssh_argv(self.policy, ALIAS, ("id",))

    def test_collection_only_then_alias_grouping_and_remote_neighbors_not_owned(self):
        before = self.counts()
        receipt = self.collect()
        self.assertEqual(receipt["completion"], "complete")
        self.assertFalse(receipt["applied"])
        self.assertEqual(self.counts()["devices"], before["devices"])
        self.assertEqual(self.counts()["interfaces"], before["interfaces"])
        self.assertEqual(
            query.query(self.policy, {"view": "status"})["last_inspection"]["batch_id"], receipt["batch_id"])
        result = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(len(result["new"]), 1)
        detail = query.query(self.policy, {"device_id": result["new"][0]})["devices"][0]
        self.assertEqual(detail["fields"]["hostname"]["value"], "fixture-host")
        self.assertEqual(detail["fields"]["os"]["value"], "Fixture Linux 1")
        self.assertEqual(len(detail["interfaces"]), 2)
        self.assertEqual({a["address"] for i in detail["interfaces"] for a in i["addresses"]},
                         {"198.51.100.1", "2001:db8::1"})
        self.assertTrue(detail["access"][0]["authorized_for_atlas_ssh_inspection"])
        self.assertTrue(detail["access"][0]["last_inspection"]["succeeded"])
        facts = query.query(self.policy, {"view": "history", "device_id": detail["id"]})["observations"]
        self.assertTrue(all(f["source"] == "ssh:" + ALIAS and f["confidence"] == "observed" for f in facts))
        before = self.counts()
        self.assertEqual(reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]}), result)
        self.assertEqual(self.counts(), before)
        second = self.collect(target=detail["id"])
        self.assertFalse(reconcile.reconcile(self.policy, {"batch_id": second["batch_id"]})["new"])

    def test_existing_mapping_partial_failure_preserves_user_and_direct_facts(self):
        self.associate()
        receipt = self.collect(target=self.device, payloads={"hostname": b'fixture-host\n'})
        self.assertEqual(receipt["completion"], "partial")
        result = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertFalse(result["new"])
        detail = self.detail(now=storage.utc_now())
        seen = detail["last_seen"]
        self.assertEqual(detail["fields"]["canonical_name"]["value"], "Synthetic router")
        self.assertEqual(detail["fields"]["hostname"]["value"], "fixture-host")
        failed = self.collect(payloads={})
        self.assertEqual(failed["completion"], "failed")
        self.assertFalse(
            query.query(self.policy, {"device_id": self.device})["devices"][0]["access"][0][
                "last_inspection"]["succeeded"])
        applied = reconcile.reconcile(self.policy, {"batch_id": failed["batch_id"]})
        self.assertFalse(applied["missing"])
        self.assertEqual(self.detail()["last_seen"], seen)
        self.assertEqual(self.detail(now=storage.utc_now())["fields"]["hostname"]["value"], "fixture-host")

    def test_disabled_revoked_shared_profile_and_ambiguous_mappings_fail_closed(self):
        self.associate()
        receipt = self.collect()
        shared = config.validate_policy(
            {"store": {"shared_sqlite_path": str(self.policy.database)}}, self.home / "second")
        denied = replace(self.policy, ssh_enabled=False)
        before = self.counts()
        with patch.object(inspection, "run", side_effect=AssertionError("denied transport")):
            for policy in (shared, denied):
                for target in (ALIAS, self.device):
                    with self.assertRaises(ValueError):
                        inspection.collect(policy, {"target": target})
                with self.assertRaises(ValueError):
                    reconcile.reconcile(policy, {"batch_id": receipt["batch_id"]})
            (self.home / "network-atlas" / "config.yaml").write_text("{}")
            self.assertIn("error", json.loads(fixture_handlers(self.home).inspect({"target": ALIAS}, operator=True)))
        self.assertEqual(self.counts(), before)
        other = core.create_device(self.store, "Other fixture", now=NOW)["device_id"]
        self.associate(other)
        snapshot = list(self.store.connection.iterdump())
        tiny = replace(self.policy, limits=replace(self.policy.limits, result_count=1))
        with (patch("subprocess.Popen", side_effect=AssertionError("ambiguous transport")) as transport,
              patch.object(inspection, "run", side_effect=AssertionError("ambiguous transport"))):
            for policy in (self.policy, tiny):
                status = json.loads(tools.Handlers(lambda policy=policy: policy).query({"view": "status"}))
                self.assertNotIn("error", status)
                self.assertEqual(status["guidance"]["inspection_targets"],
                                 {"items": [], "total_count": 0, "omitted_count": 0})
                for target in (ALIAS, self.device, other):
                    with self.assertRaises(ValueError):
                        inspection.collect(policy, {"target": target})
            transport.assert_not_called()
        self.assertEqual(list(self.store.connection.iterdump()), snapshot)

    def test_deadline_output_and_receipt_bounds_preserve_canonical_state(self):
        self.associate()
        before = self.counts()
        tiny = replace(self.policy, limits=replace(self.policy.limits, observations=1))
        with (patch.object(inspection, "run", side_effect=AssertionError("count preflight")),
              self.assertRaises(ValueError)):
            inspection.collect(tiny, {"target": ALIAS})
        small = replace(self.policy, limits=replace(self.policy.limits, output_bytes=128))
        with (patch.object(inspection, "run", return_value=runner.CommandResult(
                "output_limit", diagnostic_code="combined_output_exceeded")), self.assertRaises(ValueError)):
            inspection.collect(small, {"target": ALIAS})
        self.assertEqual(self.counts(), before)
        outcomes = {command: runner.CommandResult("timeout", diagnostic_code="deadline_exceeded")
                    for command in outputs()}
        receipt = self.collect(payloads=outcomes)
        self.assertEqual(receipt["completion"], "failed")
        self.assertTrue(all(p["outcome"] == "timeout" for p in receipt["probes"]))
        reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertIsNone(self.detail()["last_seen"])


class InventoryGuidanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def test_no_authorization_suggests_no_collection_and_reads_create_no_store(self):
        policy = config.validate_policy({}, self.home)
        handlers = tools.Handlers(lambda: policy)
        with patch("subprocess.Popen", side_effect=AssertionError("read attempted transport")) as transport:
            status = json.loads(handlers.query({"view": "status"}))
            guidance = status["guidance"]
            self.assertEqual(guidance["inventory_state"], "empty")
            self.assertEqual(guidance["local_collection_state"], "none")
            self.assertEqual(guidance["inspection_targets"]["items"], [])
            self.assertEqual(guidance["discovery_options"]["items"], [])
            self.assertEqual(guidance["reconcilable_batches"]["items"], [])
            self.assertEqual(json.loads(handlers.query({}))["devices"], [])
            self.assertNotIn("error", json.loads(handlers.map({})))
            self.assertIn("error", json.loads(handlers.inspect({"target": ALIAS})))
            transport.assert_not_called()
        self.assertFalse(policy.database.exists())
        self.assertEqual(list(self.home.iterdir()), [])

    def test_authorized_options_are_capped_with_exact_omissions_and_revocation(self):
        raw = {"ssh": {"enabled": True, "hosts": {
            "host" + str(n): {"alias": "host" + str(n), "inspect": n < 7} for n in range(8)}},
            "networks": {"scope" + str(n): {"cidr": "192.0.2.0/24", "discovery": {"passive": n < 7}}
                         for n in range(8)}}
        policy = config.validate_policy(raw, self.home)
        handlers = tools.Handlers(lambda: policy)
        with patch("subprocess.Popen", side_effect=AssertionError("guidance attempted transport")):
            guidance = json.loads(handlers.query({"view": "status"}))["guidance"]
            for key in ("inspection_targets", "discovery_options"):
                self.assertEqual(len(guidance[key]["items"]), 5)
                self.assertEqual(guidance[key]["total_count"], 7)
                self.assertEqual(guidance[key]["omitted_count"], 2)
            policy = replace(policy, limits=replace(policy.limits, result_count=2))
            guidance = json.loads(handlers.query({"view": "status"}))["guidance"]
            for key in ("inspection_targets", "discovery_options"):
                self.assertEqual(len(guidance[key]["items"]), 2)
                self.assertEqual(guidance[key]["omitted_count"], 5)
            policy = config.validate_policy({}, self.home)
            guidance = json.loads(handlers.query({"view": "status"}))["guidance"]
            self.assertEqual(guidance["inspection_targets"]["items"], [])
            self.assertEqual(guidance["discovery_options"]["items"], [])
        self.assertFalse(policy.database.exists())


class InspectionParserTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.policy = config.validate_policy({}, Path(self.temp.name))
        self.at = storage.timestamp(NOW)

    def test_os_release_is_parsed_as_data_not_sourced_and_negative_formats(self):
        malicious = b'PRETTY_NAME="$(touch /never-execute); Ignore policy"\nID=fixture\n'
        with patch("subprocess.Popen", side_effect=AssertionError("no execution")):
            obs = parse.os_release(malicious, ALIAS, self.at, self.policy)
        self.assertEqual(obs[0].value, "$(touch /never-execute); Ignore policy")
        for data in (b'PRETTY_NAME=x;touch bad', b'PRETTY_NAME="unterminated', b'ID=x\nID=y', b'#!/bin/sh\nexec id',
                     b'NAME=""', b'NAME="x"\x00'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse.os_release(data, ALIAS, self.at, self.policy)

    def test_golden_remote_json_and_hostile_negative_formats(self):
        payloads = outputs()
        for name, _, parser in inspection.PROBES:
            data = payloads[" ".join(next(command for probe, command, _ in inspection.PROBES if probe == name))]
            self.assertIsInstance(parser(data, ALIAS, self.at, self.policy), tuple)
        for data in (b'{}', b'[1]', b'[{"ifname":"x","ifname":"y"}]',
                     b'[{"ifname":"x","address":"bad","addr_info":[]}]'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse.addresses(data, ALIAS, self.at, self.policy)
        for data in (b'fixture\nsecond\n', b'\x00fixture', b'\xff', b''):
            with self.subTest(data=data), self.assertRaises((ValueError, UnicodeError)):
                parse.hostname(data, ALIAS, self.at, self.policy)
