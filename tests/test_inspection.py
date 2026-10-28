# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic A03/A05/A08/A09/A12 inspection evidence; no real SSH subprocess."""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import importlib
import json
from pathlib import Path
import time
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
render = importlib.import_module("atlas_test_plugin.render")
batches = importlib.import_module("atlas_test_plugin.batches")
topology = importlib.import_module("atlas_test_plugin.topology")

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


class TopologyInspectionTests(AtlasFixture):
    """Drive the real public producers, not a seeded finished relationship."""

    def setUp(self):
        super().setUp()
        self.clock = NOW + timedelta(hours=1)
        for module in (inspection, reconcile, query, render):
            clock = patch.object(module, "utc_now", lambda: self.clock)
            clock.start()
            self.addCleanup(clock.stop)
        self.handlers = tools.Handlers(lambda: self.policy)
        self.peer_mac = "00:11:22:33:44:99"

    def payloads(self):
        payloads = outputs()
        payloads["ip -j neigh"] = json.dumps([{"dst": "198.51.100.254", "dev": "fixture0",
                                             "lladdr": self.peer_mac, "state": ["REACHABLE"]}]).encode()
        return payloads

    def public_collect(self, payloads, policy=None):
        calls = []
        def fake(argv, *args, **kwargs):
            self.assertEqual(argv[-2], ALIAS)
            self.assertIn(argv[-1], outputs())
            calls.append(argv[-1])
            value = payloads.get(argv[-1], runner.CommandResult("unavailable", diagnostic_code="nonzero_exit"))
            return value if isinstance(value, runner.CommandResult) else runner.CommandResult("success", value)
        handlers = tools.Handlers(lambda: policy or self.policy)
        with patch.object(inspection, "run", fake):
            receipt = json.loads(handlers.inspect({"target": ALIAS}))
        self.assertNotIn("error", receipt)
        self.assertEqual(calls, [" ".join(command) for _, command, _ in inspection.PROBES])
        return receipt

    def apply(self, payloads=None):
        receipt = self.public_collect(self.payloads() if payloads is None else payloads)
        result = json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]}))
        self.assertNotIn("error", result)
        return receipt, result

    def known_peer(self, context="foreign", mac=None):
        policy = replace(self.policy, home=self.home / context)
        payloads = outputs()
        address = [{"ifname": "gateway0", "address": mac or self.peer_mac,
                    "addr_info": [{"local": "198.51.100.254", "prefixlen": 24}]}]
        payloads["ip -j address"] = json.dumps(address).encode()
        payloads["ip -j link"] = json.dumps([{"ifname": "gateway0", "address": mac or self.peer_mac}]).encode()
        payloads["ip -j route"] = payloads["ip -j neigh"] = b'[]'
        receipt = self.public_collect(payloads, policy)
        applied = json.loads(tools.Handlers(lambda: policy).reconcile({"batch_id": receipt["batch_id"]}))
        self.assertNotIn("error", applied)
        device = query.query(policy, {"access_method": "ssh"}, now=self.clock)["devices"][0]["id"]
        return policy, device

    def topology(self, receipt, policy=None):
        result = json.loads(tools.Handlers(lambda: policy or self.policy).query(
            {"view": "topology", "batch_id": receipt["batch_id"]}))
        self.assertNotIn("error", result)
        self.assertFalse(result["has_more"])
        return result["observations"]

    def assert_no_edges(self):
        result = json.loads(self.handlers.query({"relationship": "routes_via"}))
        self.assertNotIn("error", result)
        self.assertEqual(result["devices"], [])
        for format_name in ("text", "markdown", "mermaid"):
            rendered = json.loads(self.handlers.map({"format": format_name}))
            self.assertNotIn("error", rendered)
            self.assertNotIn("configured next hop", rendered["content"])

    def manual_graph(self):
        """Native assertions exceed the collector bound, but not any device bound."""
        devices = [core.create_device(self.store, f"M{n:03}", now=self.clock)["device_id"] for n in range(100)]
        # 4,099 links among 100 devices, each incident to at most 82 links.
        # Keep a separate degree-one pair and the fixture's isolated device.
        for n in range(4099):
            source = n // 41
            target = (source + n % 41 + 1) % len(devices)
            self.update("relationship", {"target_device": devices[target], "relationship_type": "physical"},
                        device=devices[source], now=self.clock)
        source, target = [core.create_device(self.store, name, now=self.clock)["device_id"]
                          for name in ("Manual source", "Manual target")]
        receipt = self.update("relationship", {"target_device": target, "relationship_type": "physical"},
                              device=source, now=self.clock)
        edge = self.store.connection.execute("SELECT entity_id FROM observations WHERE id=?",
                                             (receipt["observation_id"],)).fetchone()[0]
        ids = {row[0] for row in self.store.connection.execute(
            "SELECT id FROM relations WHERE relationship_type='physical'")}
        self.assertEqual(len(ids), 4100)
        self.assertGreater(len(ids), self.policy.limits.observations)
        return source, target, edge, ids, devices

    def test_manual_graph_preserves_six_public_views_and_real_per_device_overflow(self):
        source, target, edge_id, manual_ids, devices = self.manual_graph()
        before = list(self.store.connection.iterdump())
        with patch("subprocess.Popen", side_effect=AssertionError("reads never collect")):
            isolated = json.loads(self.handlers.query({"device_id": self.device}))
            self.assertNotIn("error", isolated)
            self.assertEqual(isolated["devices"][0]["relationships"], [])
            linked = json.loads(self.handlers.query({"device_id": source}))
            self.assertNotIn("error", linked)
            edge = linked["devices"][0]["relationships"][0]
            self.assertEqual([r["id"] for r in linked["devices"][0]["relationships"]], [edge_id])
            self.assertEqual((edge["source_device"], edge["target_device"]), (source, target))
            fact = edge["facts"]["relationship"]["evidence"][0]
            self.assertEqual((fact["source"], fact["confidence"], fact["observed_at"]),
                             ("user", "user_supplied", storage.timestamp(self.clock)))
            pages = [json.loads(self.handlers.query({"limit": 1, "offset": offset})) for offset in (0, 1)]
            for page in pages:
                self.assertNotIn("error", page)
                self.assertEqual(len(page["devices"]), 1)
                self.assertTrue(page["has_more"])
            self.assertNotEqual(pages[0]["devices"][0]["id"], pages[1]["devices"][0]["id"])
            status = json.loads(self.handlers.query({"view": "status"}))
            self.assertNotIn("error", status)
            self.assertEqual(status["known_devices"], 103)
            self.assertEqual(status["guidance"]["devices_without_relationships"], 1)
            filtered = json.loads(self.handlers.query({"relationship": "physical", "related_to": target}))
            self.assertNotIn("error", filtered)
            self.assertEqual([d["id"] for d in filtered["devices"]], [source])
            self.assertEqual([r["id"] for r in filtered["devices"][0]["relationships"]], [edge_id])
            physical_page = json.loads(self.handlers.query({"relationship": "physical", "limit": 1}))
            self.assertNotIn("error", physical_page)
            self.assertEqual(len(physical_page["devices"]), 1)
            self.assertTrue(physical_page["has_more"])
            self.assertTrue(physical_page["devices"][0]["relationships"])
            with patch.object(render, "_render", wraps=render._render) as projection:
                mapped = json.loads(self.handlers.map({"format": "text"}))
            self.assertNotIn("error", mapped)
            self.assertEqual(mapped["content"].count("physical [user_supplied]"), 4100)
            projected = {r["id"]: r for d in projection.call_args.args[0] for r in d["relationships"]}
            self.assertEqual(set(projected), manual_ids)
            for edge in projected.values():
                fact = edge["facts"]["relationship"]["evidence"][0]
                self.assertEqual((fact["source"], fact["confidence"], fact["observed_at"]),
                                 ("user", "user_supplied", storage.timestamp(self.clock)))
        self.assertEqual(list(self.store.connection.iterdump()), before)
        # A truly high-degree device must still fail, without poisoning the pair.
        hub = core.create_device(self.store, "Overflow hub", now=self.clock)["device_id"]
        for device in [*devices, source]:
            self.update("relationship", {"target_device": device, "relationship_type": "physical"},
                        device=hub, now=self.clock)
        with self.assertRaisesRegex(ValueError, "entity detail exceeds configured result bound"):
            query.query(self.policy, {"device_id": hub}, now=self.clock)
        refused = json.loads(self.handlers.query({"device_id": hub}))
        self.assertIn("atlas state or bounds", refused["error"])
        self.assertFalse(refused["applied"])
        unaffected = json.loads(self.handlers.query({"device_id": target}))
        self.assertNotIn("error", unaffected)
        self.assertEqual([r["id"] for r in unaffected["devices"][0]["relationships"]], [edge_id])

    def test_large_manual_graph_keeps_frozen_route_support_withdrawal_and_operator_override(self):
        manual, _, manual_id, manual_ids, _ = self.manual_graph()
        _, peer = self.known_peer()
        payloads = self.payloads()
        payloads["ip -j route"] = json.dumps([
            {"dst": "default", "gateway": "198.51.100.254", "dev": "fixture0"},
            {"dst": "203.0.113.0/24", "gateway": "198.51.100.254", "dev": "fixture0"},
            {"dst": "198.18.0.0/24", "gateway": "198.51.100.253", "dev": "fixture0"}]).encode()
        neighbors = json.loads(payloads["ip -j neigh"])
        payloads["ip -j neigh"] = json.dumps([*neighbors, {**neighbors[0], "dst": "198.51.100.253"}]).encode()
        receipt, applied = self.apply(payloads)
        source = applied["new"][0]
        edge_id = applied["relationships"][0]
        relation = self.store.connection.execute("SELECT * FROM relations WHERE id=?", (edge_id,)).fetchone()
        frozen = self.store.connection.execute("SELECT value_json FROM observations WHERE id=?",
                                                (relation["observation_id"],)).fetchone()[0]
        self.assertEqual(json.loads(frozen)["route_evidence_count"], 2)
        def current_ids():
            result = json.loads(self.handlers.query({"relationship": "routes_via"}))
            self.assertNotIn("error", result)
            return {r["id"] for d in result["devices"] for r in d["relationships"]}
        self.assertEqual(current_ids(), {edge_id})
        interface = relation["target_interface"]
        core.add_address(self.store, interface, "198.51.100.253", 24, now=self.clock)
        # The later-eligible third route was never a frozen member of this edge.
        assignment = self.store.connection.execute(
            "SELECT id FROM addresses WHERE interface_id=? AND address='198.51.100.254' AND ended_at IS NULL",
            (interface,)).fetchone()[0]
        core.end_address(self.store, assignment, now=self.clock)
        self.assertEqual(current_ids(), set())
        routes = [row for row in self.topology(receipt) if row["kind"] == "route"]
        self.assertEqual({row["resolution"]["reason"] for row in routes if row["value"]["gateway"].endswith("254")},
                         {"ambiguous_or_missing_gateway_assignment"})
        later = next(row for row in routes if row["value"]["gateway"].endswith("253"))
        self.assertEqual(later["resolution"]["reason"], "not_derived_at_application")
        # An assertion on the withdrawn edge bypasses only collector eligibility.
        asserted_at = storage.timestamp(self.clock)
        assertion = self.update("relationship", {"target_device": peer, "relationship_type": "routes_via",
                                "source_interface": relation["source_interface"], "target_interface": interface},
                                device=source, now=self.clock)
        self.assertEqual(current_ids(), {edge_id})
        # Fresh collector support coexists with that assertion, then withdraws
        # on a newer failed attempt. A further healthy edge withdraws on age.
        payloads["ip -j route"] = json.dumps([
            {"dst": "198.18.0.0/24", "gateway": "198.51.100.253", "dev": "fixture0"}]).encode()
        _, successor = self.apply(payloads)
        self.assertEqual(len(successor["relationships"]), 1)
        self.assertEqual(current_ids(), {edge_id, *successor["relationships"]})
        self.public_collect({})
        self.assertEqual(current_ids(), {edge_id})
        selected = json.loads(self.handlers.query({"device_id": source}))["devices"][0]["relationships"][0]
        self.assertEqual(selected["facts"]["relationship"]["evidence"][0]["confidence"], "user_supplied")
        _, successor = self.apply(payloads)
        self.assertEqual(len(successor["relationships"]), 1)
        self.assertEqual(current_ids(), {edge_id, *successor["relationships"]})
        self.clock += timedelta(days=self.policy.stale_after_days + 1)
        self.assertEqual(current_ids(), {edge_id})
        # Expired collector support cannot label the surviving assertion as a configured next hop.
        asserted = json.loads(self.handlers.query({"device_id": source}))
        self.assertNotIn("error", asserted)
        self.assertEqual([r["id"] for r in asserted["devices"][0]["relationships"]], [edge_id])
        selected = asserted["devices"][0]["relationships"][0]
        self.assertEqual((selected["source_device"], selected["target_device"], selected["relationship_type"],
                          selected["source_interface"], selected["target_interface"]),
                         (source, peer, "routes_via", relation["source_interface"], interface))
        evidence = selected["facts"]["relationship"]["evidence"]
        self.assertEqual([(fact["id"], fact["source"], fact["confidence"], fact["observed_at"])
                          for fact in evidence],
                         [(assertion["observation_id"], "user", "user_supplied", asserted_at)])
        detail = json.loads(self.handlers.query({"device_id": manual}))
        self.assertNotIn("error", detail)
        self.assertEqual([r["id"] for r in detail["devices"][0]["relationships"]], [manual_id])
        status = json.loads(self.handlers.query({"view": "status"}))
        self.assertNotIn("error", status)
        self.assertEqual(status["guidance"]["devices_without_relationships"], 1)
        with patch.object(render, "_render", wraps=render._render) as projection:
            mapped = json.loads(self.handlers.map({"format": "text"}))
        self.assertNotIn("error", mapped)
        self.assertEqual(mapped["content"].count("physical [user_supplied]"), 4100)
        self.assertEqual(mapped["content"].count("routes_via [user_supplied]"), 1)
        self.assertEqual(mapped["content"].count("configured next hop"), 0)
        projected = {r["id"]: r for d in projection.call_args.args[0] for r in d["relationships"]}
        self.assertEqual(set(projected), manual_ids | {edge_id})
        self.assertEqual(projected[edge_id], selected)
        self.assertEqual(self.store.connection.execute("SELECT value_json FROM observations WHERE id=?",
                         (relation["observation_id"],)).fetchone()[0], frozen)

    def test_public_next_hop_retains_provenance_query_map_replay_and_foreign_history(self):
        foreign, peer = self.known_peer()
        # Preserve every existing logical row, not SQLite page/journal bytes.
        retained = {name: self.store.connection.execute(f"SELECT * FROM {name} ORDER BY rowid").fetchall()
                    for name in self.counts()}
        payloads = self.payloads()
        payloads["ip -j route"] = json.dumps([
            {"dst": "default", "gateway": "198.51.100.254", "dev": "fixture0"},
            {"dst": "203.0.113.0/24", "gateway": "198.51.100.254", "dev": "fixture0"},
            {"dst": "198.51.100.254", "dev": "fixture0", "scope": "link"}]).encode()
        receipt = self.public_collect(payloads)
        probe = next(p for p in receipt["probes"] if p["name"] == "ssh_route")
        self.assertEqual((probe["outcome"], probe["observation_count"]), ("success", 4))
        raw = self.topology(receipt)
        self.assertEqual({row["kind"] for row in raw}, {"route", "neighbor"})
        self.assertEqual({row["value"]["dst"] for row in raw if row["kind"] == "route"},
                         {"default", "203.0.113.0/24", "198.51.100.254/32"})
        self.assertTrue(all(row["source"] == "ssh:" + ALIAS and row["confidence"] == "observed"
                            and not row["qualified"] and row["policy_context"] == str(self.home) for row in raw))
        route = next(row for row in raw if row["kind"] == "route" and row["value"]["dst"] == "default")
        self.assertEqual(route["resolution"]["reason"], "unapplied_or_ambiguous_origin")
        applied = json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]}))
        self.assertNotIn("error", applied)
        self.assertEqual(len(applied["relationships"]), 1)
        self.assertEqual(applied["unresolved"], [])
        source = applied["new"][0]
        detail = json.loads(self.handlers.query({"device_id": source}))["devices"][0]
        self.assertEqual({i["mac_address"] for i in detail["interfaces"]}, {MAC, MAC2})
        self.assertNotIn("198.51.100.254", {a["address"] for i in detail["interfaces"] for a in i["addresses"]})
        edge = detail["relationships"][0]
        self.assertEqual(edge["target_device"], peer)
        self.assertEqual(edge["id"], applied["relationships"][0])
        fact = edge["facts"]["relationship"]["evidence"][0]
        self.assertEqual(fact["confidence"], "inferred")
        self.assertEqual(fact["value"]["route_evidence_count"], 2)
        self.assertEqual(fact["value"]["evidence_query"], {"view": "topology", "batch_id": receipt["batch_id"]})
        self.assertNotIn("route_evidence_ids", fact["value"])
        self.assertTrue(fact["explanation"])
        self.assertEqual(fact["observed_at"], route["observed_at"])
        routes = [row for row in self.topology(receipt) if row["kind"] == "route"]
        self.assertEqual({row["resolution"]["relationship_id"] for row in routes if row["value"]["gateway"]},
                         {edge["id"]})
        route = next(row for row in routes if row["value"]["dst"] == "default")
        self.assertEqual(route["origin_device"], source)
        self.assertEqual(route["resolution"]["relationship_id"], edge["id"])
        connected = next(row for row in routes if row["value"]["dst"] == "198.51.100.254/32")
        self.assertEqual(connected["resolution"]["reason"], "no_next_hop")
        self.assertEqual({d["id"] for d in json.loads(self.handlers.query(
            {"relationship": "routes_via"}))["devices"]}, {source, peer})
        related = json.loads(self.handlers.query({"relationship": "routes_via", "related_to": peer}))
        self.assertEqual([d["id"] for d in related["devices"]], [source])
        for format_name in ("text", "markdown", "mermaid"):
            content = json.loads(self.handlers.map({"format": format_name}))["content"]
            self.assertIn("configured next hop", content)
            self.assertIn("inferred", content)
            if format_name == "mermaid":
                self.assertIn("n" + source.replace("-", "") + " -.->", content)
        for name, rows in retained.items():
            for row in rows:
                current = self.store.connection.execute(f"SELECT * FROM {name} WHERE id=?", (row["id"],)).fetchone()
                self.assertEqual(tuple(current), tuple(row))
        snapshot = list(self.store.connection.iterdump())
        self.assertEqual(json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]})), applied)
        self.assertEqual(list(self.store.connection.iterdump()), snapshot)
        shared = replace(foreign, ssh_enabled=False)
        self.assertTrue(all(not row["local_policy_context"] for row in self.topology(receipt, shared)))
        self.assertTrue(all(row["local_policy_context"] and "local_context" not in row
                            for row in self.topology(receipt)))
        shared_handlers = tools.Handlers(lambda: shared)
        self.assertEqual(json.loads(shared_handlers.query({"device_id": source}))["devices"][0][
            "relationships"][0]["id"], edge["id"])
        with patch.object(inspection, "run", side_effect=AssertionError("knowledge is not collection authority")):
            self.assertIn("error", json.loads(shared_handlers.inspect({"target": ALIAS})))
            self.assertIn("error", json.loads(shared_handlers.reconcile({"batch_id": receipt["batch_id"]})))
        self.assertEqual(list(self.store.connection.iterdump()), snapshot)

    def indexed_call(self, operation, params, batch_id, route_count):
        """Observe real work, without replacing the resolver or its deadline."""
        loads, parsed = [], []
        initialize, index = topology.BatchIndex.__init__, topology.BatchIndex._index
        def load(instance, store, selected):
            loads.append(selected)
            initialize(instance, store, selected)
        def record(instance, row):
            parsed.append(row["subject_kind"])
            index(instance, row)
        with (patch.object(topology.BatchIndex, "__init__", load),
              patch.object(topology.BatchIndex, "_index", record),
              patch.object(topology, "_peer", wraps=topology._peer) as peer,
              patch.object(topology, "_source_interface", wraps=topology._source_interface) as source):
            result = json.loads(operation(params))
        self.assertNotIn("error", result)
        self.assertEqual(loads, [batch_id])
        self.assertEqual(parsed.count("route"), route_count)
        self.assertEqual(parsed.count("neighbor"), 1)
        self.assertEqual(peer.call_count, 1)
        self.assertEqual(source.call_count, 1)
        return result

    def test_four_thousand_routes_apply_under_tight_deadline_and_keep_all_views_bounded(self):
        _, peer = self.known_peer()
        # Supported policy lowering, not a raised production cap. Ten seconds is
        # below the reported 30s failure with headroom for both CI architectures.
        self.policy = replace(self.policy, limits=replace(self.policy.limits, operation_timeout_seconds=10))
        payloads = self.payloads()
        routes = [{"dst": f"198.18.{n // 256}.{n % 256}/32", "dev": "fixture0",
                   **({"gateway": "198.51.100.254"} if n % 4 else {})} for n in range(4000)]
        payloads["ip -j route"] = json.dumps(routes).encode()
        receipt = self.public_collect(payloads)
        self.assertEqual(receipt["completion"], "complete")
        self.assertEqual(next(p for p in receipt["probes"] if p["name"] == "ssh_route")["observation_count"], 4001)
        started = time.monotonic()
        applied = self.indexed_call(self.handlers.reconcile, {"batch_id": receipt["batch_id"]},
                                    receipt["batch_id"], 4000)
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(applied["unresolved"], [])
        self.assertEqual(len(applied["relationships"]), 1)
        source = applied["new"][0]
        edge_id = applied["relationships"][0]
        views = [{}, {"device_id": source}, {"device_id": peer},
                 {"relationship": "routes_via"}, {"related_to": peer}]
        for params in views:
            answer = self.indexed_call(self.handlers.query, params, receipt["batch_id"], 4000)
            self.assertTrue(answer["devices"])
            if params == {"relationship": "routes_via"}:
                self.assertEqual({d["id"] for d in answer["devices"]}, {source, peer})
            if params == {"related_to": peer}:
                self.assertEqual([d["id"] for d in answer["devices"]], [source])
            for device in answer["devices"]:
                if device["id"] in {source, peer}:
                    self.assertEqual([r["id"] for r in device["relationships"]], [edge_id])
                    fact = device["relationships"][0]["facts"]["relationship"]["value"]
                    self.assertEqual(fact["route_evidence_count"], 3000)
                    self.assertNotIn("route_evidence_ids", fact)
            self.assertLess(len(json.dumps(answer)), 50000)
        status = self.indexed_call(self.handlers.query, {"view": "status"}, receipt["batch_id"], 4000)
        self.assertEqual(status["known_devices"], 3)
        self.assertEqual(status["guidance"]["devices_without_relationships"], 1)
        self.assertEqual(status["guidance"]["historical_unresolved_applications"], 0)
        for format_name in ("text", "markdown", "mermaid"):
            rendered = self.indexed_call(self.handlers.map, {"format": format_name}, receipt["batch_id"], 4000)
            self.assertEqual(rendered["content"].count("configured next hop"), 1)
        members, retained = [], []
        offset = 0
        while True:
            page = json.loads(self.handlers.query({"view": "topology", "batch_id": receipt["batch_id"],
                                                   "limit": 100, "offset": offset}))
            self.assertNotIn("error", page)
            self.assertLessEqual(len(page["observations"]), 100)
            for row in page["observations"]:
                self.assertTrue(row["local_policy_context"])
                self.assertEqual(row["source"], "ssh:" + ALIAS)
                self.assertEqual(row["confidence"], "observed")
                self.assertTrue(row["probe_id"] and row["observed_at"])
                if row["kind"] == "route":
                    retained.append(row["id"])
                    if row["value"]["gateway"]:
                        self.assertEqual(row["resolution"]["relationship_id"], edge_id)
                        self.assertTrue(row["resolution"]["supporting_evidence_ids"])
                        members.append(row["id"])
                    else:
                        self.assertEqual(row["resolution"]["reason"], "no_next_hop")
            if not page["has_more"]:
                break
            offset += page["limit"]
        self.assertEqual(len(set(retained)), 4000)
        self.assertEqual(len(set(members)), 3000)
        stored = self.store.connection.execute("SELECT o.value_json FROM observations o JOIN relations r "
            "ON r.observation_id=o.id WHERE r.id=?", (edge_id,)).fetchone()[0]
        self.assertEqual(json.loads(stored)["route_evidence_ids"], sorted(members))
        snapshot = list(self.store.connection.iterdump())
        self.assertEqual(json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]})), applied)
        self.assertEqual(list(self.store.connection.iterdump()), snapshot)

    def test_group_uses_eligible_members_and_never_merges_distinct_interfaces(self):
        _, peer = self.known_peer()
        peer_interface = self.store.connection.execute("SELECT id FROM interfaces WHERE device_id=?",
                                                       (peer,)).fetchone()[0]
        core.add_address(self.store, peer_interface, "198.51.100.253", 24, now=self.clock)
        payloads = self.payloads()
        routes = [{"dst": "default", "gateway": "198.51.100.254", "dev": "fixture0"},
                  {"dst": "203.0.113.0/24", "gateway": "198.51.100.253", "dev": "fixture0"},
                  {"dst": "192.0.2.0/24", "gateway": "198.51.100.252", "dev": "fixture0"}]
        payloads["ip -j route"] = json.dumps(routes).encode()
        neighbors = [{"dst": route["gateway"], "dev": "fixture0", "lladdr": self.peer_mac,
                      "state": ["REACHABLE"]} for route in routes]
        payloads["ip -j neigh"] = json.dumps(neighbors).encode()
        receipt, applied = self.apply(payloads)
        self.assertEqual(len(applied["relationships"]), 1)
        rows = [row for row in self.topology(receipt) if row["kind"] == "route"]
        members = [row for row in rows if row["value"]["gateway"] != "198.51.100.252"]
        self.assertEqual({r["resolution"]["relationship_id"] for r in members}, set(applied["relationships"]))
        self.assertEqual([item["reason"] for item in applied["unresolved"]],
                         ["ambiguous_or_missing_gateway_assignment"])
        # One member loses its otherwise-eligible gateway assignment; the other
        # still supports the same edge. No stale per-request cache may survive.
        other = core.create_device(self.store, "Conflicting gateway", now=self.clock)["device_id"]
        other_interface = core.add_interface(self.store, other, "other0", "00:11:22:33:44:aa", now=self.clock)
        core.add_address(self.store, other_interface, "198.51.100.254", 24, now=self.clock)
        filtered = json.loads(self.handlers.query({"relationship": "routes_via"}))
        self.assertEqual({d["id"] for d in filtered["devices"]}, {applied["new"][0], peer})
        reasons = {r["value"]["gateway"]: r["resolution"]["reason"] for r in self.topology(receipt)
                   if r["kind"] == "route"}
        self.assertEqual(reasons, {"198.51.100.254": "ambiguous_or_missing_gateway_assignment",
                                   "198.51.100.253": "supported",
                                   "198.51.100.252": "ambiguous_or_missing_gateway_assignment"})
        core.add_address(self.store, other_interface, "198.51.100.253", 24, now=self.clock)
        core.add_address(self.store, peer_interface, "198.51.100.252", 24, now=self.clock)
        self.assert_no_edges()
        rows = [row for row in self.topology(receipt) if row["kind"] == "route"]
        for row in rows:
            if row["value"]["gateway"] == "198.51.100.252":
                self.assertEqual(row["resolution"]["reason"], "not_derived_at_application")
                self.assertNotIn("relationship_id", row["resolution"])
            else:
                self.assertEqual(row["resolution"]["relationship_id"], applied["relationships"][0])
        self.assertEqual(json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]})), applied)
        # Fresh collection to two distinct source interfaces must keep two edges,
        # even though both next-hop addresses belong to the same target interface.
        assignments = self.store.connection.execute("SELECT id FROM addresses WHERE interface_id=?",
                                                    (other_interface,)).fetchall()
        for assignment in assignments:
            core.end_address(self.store, assignment[0], now=self.clock)
        routes[1]["dev"] = neighbors[1]["dev"] = "fixture1"
        payloads["ip -j route"] = json.dumps(routes).encode()
        payloads["ip -j neigh"] = json.dumps(neighbors).encode()
        _, successor = self.apply(payloads)
        self.assertEqual(len(successor["relationships"]), 2)
        detail = json.loads(self.handlers.query({"device_id": peer}))["devices"][0]
        self.assertEqual(len({edge["source_interface"] for edge in detail["relationships"]}), 2)

    def test_unknown_peer_never_created_and_later_identity_requires_new_collection(self):
        receipt, applied = self.apply()
        self.assertEqual(len(applied["new"]), 1)
        self.assertFalse(applied.get("relationships"))
        route = next(row for row in self.topology(receipt) if row["kind"] == "route")
        self.assertEqual(route["resolution"]["reason"], "no_unique_stable_peer")
        self.assertEqual([item["reason"] for item in applied["unresolved"]], ["no_unique_stable_peer"])
        parameters = {"view": "unresolved", "batch_id": receipt["batch_id"], "summary": True}
        summary = json.loads(self.handlers.query(parameters))["summary"]
        self.assertEqual(summary["current_unresolved_observation_count"], 1)
        self.assert_no_edges()
        self.known_peer()
        route = next(row for row in self.topology(receipt) if row["kind"] == "route")
        self.assertEqual(route["resolution"]["reason"], "not_derived_at_application")
        self.assertEqual(json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]})), applied)
        self.assert_no_edges()
        _, successor = self.apply()
        self.assertEqual(len(successor["relationships"]), 1)
        summary = json.loads(self.handlers.query(parameters))["summary"]
        self.assertEqual(summary["current_unresolved_observation_count"], 0)
        self.assertEqual(summary["inactive_observation_count"], 1)

    def noisy_interfaces(self):
        payloads = self.payloads()
        interfaces = [{"ifname": "fixture0", "address": MAC, "operstate": "UP",
                       "addr_info": [{"local": "198.51.100.1", "prefixlen": 24}]}]
        interfaces += [{"ifname": f"veth{n:03}", "address": f"02:00:00:00:00:{n:02x}", "operstate": "UP",
                        "addr_info": [{"local": f"192.0.2.{n + 1}", "prefixlen": 24}]} for n in range(40)]
        interfaces.append({"ifname": "collision0", "address": MAC2, "operstate": "UP", "addr_info": []})
        payloads["ip -j address"] = json.dumps(interfaces).encode()
        payloads["ip -j link"] = json.dumps([{key: value for key, value in row.items() if key != "addr_info"}
                                            for row in interfaces]).encode()
        payloads["ip -j route"] = json.dumps([
            {"dst": "default", "gateway": "198.51.100.254", "dev": "fixture0"},
            {"dst": "203.0.113.0/24", "gateway": "198.51.100.253", "dev": "fixture0", "table": 100}]).encode()
        return payloads

    def test_actionable_uncertainty_survives_virtual_noise_and_complete_read_only_drilldown(self):
        core.add_interface(self.store, self.device, "other0", MAC2, now=self.clock)
        receipt = self.public_collect(self.noisy_interfaces())
        self.assertEqual(receipt["completion"], "complete")
        self.assertTrue(all(probe["outcome"] == "success" for probe in receipt["probes"]))
        parameters = {"view": "unresolved", "batch_id": receipt["batch_id"], "summary": True}
        kinds = [row[0] for row in self.store.connection.execute(
            "SELECT subject_kind FROM observations WHERE batch_id=? AND entity_id IS NULL",
            (receipt["batch_id"],))]
        self.assertEqual(kinds.count("route"), 2)
        self.assertGreater(sum(kind not in {"route", "neighbor"} for kind in kinds), 0)
        before = list(self.store.connection.iterdump())
        files = {p.name: p.read_bytes() for p in self.policy.database.parent.glob("atlas.sqlite3*")}
        with patch("subprocess.Popen", side_effect=AssertionError("reads never collect")):
            pending = json.loads(self.handlers.query(parameters))
        self.assertNotIn("error", pending)
        self.assertEqual(pending["total_count"], len(kinds))
        self.assertEqual({key: value for key, value in pending["summary"].items() if key != "uncertainty"},
                         {"unapplied_observation_count": len(kinds) - kinds.count("neighbor"),
                          "supporting_observation_count": kinds.count("neighbor"),
                          "current_unresolved_observation_count": 0, "resolved_observation_count": 0,
                          "unknown_observation_count": 0, "inactive_observation_count": 0})
        self.assertEqual(pending["summary"]["uncertainty"]["observation_count"], 0)
        self.assertEqual(pending["summary"]["uncertainty"]["reasons"], [])
        self.assertEqual(list(self.store.connection.iterdump()), before)
        self.assertEqual({p.name: p.read_bytes() for p in self.policy.database.parent.glob("atlas.sqlite3*")}, files)
        applied = json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]}))
        self.assertNotIn("error", applied)
        summary = applied["uncertainty"]
        self.assertEqual(summary["temporal_scope"], "at_application")
        self.assertEqual(summary["observation_count"], 206)
        self.assertEqual(summary["subject_count"], 43)
        reasons = {group["reason"]: group for group in summary["reasons"]}
        self.assertEqual(set(reasons), {"no_unique_stable_interface", "no_unique_stable_peer", "unsupported_route"})
        self.assertEqual(reasons["no_unique_stable_interface"]["observation_count"], 204)
        self.assertEqual(reasons["no_unique_stable_interface"]["subject_count"], 41)
        self.assertLessEqual(len(applied["unresolved"]), 5)
        self.assertEqual({row["reason"] for row in applied["unresolved"]}, set(reasons))
        self.assertTrue(any(row.get("candidate_device_ids") == [self.device] for row in applied["unresolved"]))
        self.assertEqual(applied["unresolved_omitted_count"], 201)
        self.assertLess(len(json.dumps(summary)), 8000)
        device = json.loads(self.handlers.query({"device_id": applied["new"][0]}))["devices"][0]
        self.assertEqual([i["mac_address"] for i in device["interfaces"]], [MAC])
        original = [dict(row) for row in self.store.connection.execute(
            "SELECT * FROM observations WHERE batch_id=? AND entity_id IS NULL ORDER BY observed_at DESC,id",
            (receipt["batch_id"],))]
        saved = self.store.connection.execute("SELECT result_json FROM applications WHERE batch_id=?",
                                             (receipt["batch_id"],)).fetchone()[0]
        self.assertEqual(len(json.loads(saved)["unresolved"]), 206)
        before = list(self.store.connection.iterdump())
        files = {p.name: p.read_bytes() for p in self.policy.database.parent.glob("atlas.sqlite3*")}
        with patch("subprocess.Popen", side_effect=AssertionError("reads never collect")):
            current = json.loads(self.handlers.query(parameters))
            self.assertNotIn("error", current)
            self.assertEqual(current["total_count"], len(original))
            self.assertEqual(current["summary"]["current_unresolved_observation_count"], 206)
            self.assertEqual(current["summary"]["uncertainty"]["subject_count"], 43)
            self.assertEqual(current["summary"]["supporting_observation_count"], 1)
            self.assertGreater(current["summary"]["resolved_observation_count"], 0)
            self.assertLess(len(json.dumps(current)), 10000)
            retained = []
            for offset in range(0, len(original), 23):
                page = json.loads(self.handlers.query({"view": "unresolved", "batch_id": receipt["batch_id"],
                                                       "limit": 23, "offset": offset}))
                self.assertNotIn("error", page)
                self.assertEqual(page["total_count"], len(original))
                self.assertEqual(page["omitted_count"], len(original) - len(page["evidence"]))
                retained.extend(page["evidence"])
            self.assertEqual([row["id"] for row in retained], [row["id"] for row in original])
            for row, raw in zip(retained, original, strict=True):
                self.assertEqual((row["value"], row["source"], row["observed_at"], row["batch"]["id"],
                                  row["probe"]["id"], row["subject_anchor"]),
                                 (json.loads(raw["value_json"]), raw["source"], raw["observed_at"], raw["batch_id"],
                                  raw["probe_id"], json.loads(raw["subject_anchor"])))
        self.assertEqual(list(self.store.connection.iterdump()), before)
        self.assertEqual({p.name: p.read_bytes() for p in self.policy.database.parent.glob("atlas.sqlite3*")}, files)
        self.assertEqual(json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]})), applied)
        small = replace(self.policy, limits=replace(self.policy.limits, result_count=2))
        truncated = json.loads(tools.Handlers(lambda: small).query(parameters))
        self.assertNotIn("error", truncated)
        reasons = truncated["summary"]["uncertainty"]
        self.assertEqual((reasons["reason_count"], reasons["omitted_reason_count"], len(reasons["reasons"])), (3, 1, 2))
        self.assertEqual(reasons["observation_count"], 206)

    def test_complete_saved_conflicts_survive_noise_and_replay_without_history_changes(self):
        payloads = self.noisy_interfaces()
        interfaces = json.loads(payloads["ip -j address"])
        for n in range(7):
            interfaces += [{"ifname": f"duplicate{n}_{side}", "address": f"00:22:33:44:55:{n:02x}",
                            "operstate": "UP", "addr_info": []} for side in (0, 1)]
        payloads["ip -j address"] = json.dumps(interfaces).encode()
        payloads["ip -j link"] = json.dumps([{key: value for key, value in row.items() if key != "addr_info"}
                                            for row in interfaces]).encode()
        receipt = self.public_collect(payloads)
        applied = json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]}))
        self.assertNotIn("error", applied)
        saved = json.loads(self.store.connection.execute(
            "SELECT result_json FROM applications WHERE batch_id=?", (receipt["batch_id"],)).fetchone()[0])
        self.assertEqual(applied["conflicting"], saved["conflicting"])
        self.assertEqual(len(applied["conflicting"]), 7)
        self.assertTrue(all("evidence_id" not in entry for entry in applied["conflicting"]))
        self.assertEqual((applied["conflicting_total_count"], applied["conflicting_omitted_count"]), (7, 0))
        uncertainty = applied["uncertainty"]
        self.assertEqual(uncertainty["conflict_record_count"], 7)
        self.assertEqual(uncertainty["conflict_reasons"], [
            {"reason": "duplicate_remote_interface_mac", "conflict_record_count": 7}])
        self.assertEqual(uncertainty["observation_count"], len(saved["unresolved"]))
        self.assertIn("no_unique_stable_peer", {group["reason"] for group in uncertainty["reasons"]})
        originals = [row[0] for row in self.store.connection.execute(
            "SELECT id FROM observations WHERE batch_id=? AND entity_id IS NULL ORDER BY observed_at DESC,id",
            (receipt["batch_id"],))]
        before = list(self.store.connection.iterdump())
        with patch("subprocess.Popen", side_effect=AssertionError("replay must not collect")):
            self.assertEqual(json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]})), applied)
            retained = []
            for offset in range(0, len(originals), 23):
                page = json.loads(self.handlers.query({"view": "unresolved", "batch_id": receipt["batch_id"],
                                                       "limit": 23, "offset": offset}))
                self.assertNotIn("error", page)
                retained.extend(row["id"] for row in page["evidence"])
            self.assertEqual(retained, originals)
        self.assertEqual(list(self.store.connection.iterdump()), before)

    def test_connected_only_retains_evidence_without_unresolved_receipt_or_status_warning(self):
        payloads = self.payloads()
        connected = {"dst": "198.51.100.0/24", "dev": "fixture0", "protocol": "kernel", "scope": "link"}
        payloads["ip -j route"] = json.dumps([connected, {**connected, "dst": "198.51.100.254"}]).encode()
        payloads["ip -j neigh"] = b'[]'
        receipt, applied = self.apply(payloads)
        self.assertEqual(applied["unresolved"], [])
        self.assertFalse(applied.get("relationships"))
        routes = self.topology(receipt)
        self.assertEqual({row["value"]["dst"] for row in routes}, {"198.51.100.0/24", "198.51.100.254/32"})
        self.assertTrue(all(row["resolution"]["reason"] == "no_next_hop" for row in routes))
        guidance = json.loads(self.handlers.query({"view": "status"}))["guidance"]
        self.assertEqual(guidance["historical_unresolved_applications"], 0)
        self.assertFalse(any("Historical applications recorded unresolved" in note for note in guidance["notes"]))
        self.assert_no_edges()
        snapshot = list(self.store.connection.iterdump())
        self.assertEqual(json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]})), applied)
        self.assertEqual(list(self.store.connection.iterdump()), snapshot)
        for changes, reason in (({"dev": "unknown0"}, "unresolved_source_interface"),
                                ({"dev": ""}, "unsupported_route")):
            payloads["ip -j route"] = json.dumps([{**connected, **changes}]).encode()
            batch, result = self.apply(payloads)
            self.assertEqual([item["reason"] for item in result["unresolved"]], [reason])
            self.assertEqual(self.topology(batch)[0]["resolution"]["reason"], reason)
            self.assert_no_edges()
        payloads["ip -j route"] = json.dumps([connected, {**connected, "dev": "fixture1"}]).encode()
        batch, result = self.apply(payloads)
        self.assertEqual([item["reason"] for item in result["unresolved"]], ["conflicting_routes"] * 2)
        self.assertTrue(all(row["resolution"]["reason"] == "conflicting_routes" for row in self.topology(batch)))
        guidance = json.loads(self.handlers.query({"view": "status"}))["guidance"]
        self.assertGreater(guidance["historical_unresolved_applications"], 0)
        self.assert_no_edges()

    def test_stale_neighbor_and_conflicting_routes_or_neighbors_remain_unresolved(self):
        self.known_peer()
        cases = []
        for state in ("STALE", "FAILED", "INCOMPLETE", "DELAY", "PROBE", "NONE", "NOARP"):
            payloads = self.payloads()
            neighbors = json.loads(payloads["ip -j neigh"])
            neighbors[0]["state"] = [state]
            payloads["ip -j neigh"] = json.dumps(neighbors).encode()
            cases.append((payloads, "unusable_neighbor_state"))
        for changes, reason in (({"lladdr": "02:11:22:33:44:99"}, "no_unique_stable_peer"),
                                ({"lladdr": "00:11:22:33:44:aa"}, "no_unique_stable_peer"),
                                ({"dev": "other0"}, "missing_neighbor")):
            payloads = self.payloads()
            neighbors = json.loads(payloads["ip -j neigh"])
            neighbors[0].update(changes)
            payloads["ip -j neigh"] = json.dumps(neighbors).encode()
            cases.append((payloads, reason))
        payloads = self.payloads()
        neighbors = json.loads(payloads["ip -j neigh"])
        neighbors.append({**neighbors[0], "lladdr": "00:11:22:33:44:aa"})
        payloads["ip -j neigh"] = json.dumps(neighbors).encode()
        cases.append((payloads, "conflicting_neighbors"))
        payloads = self.payloads()
        routes = json.loads(payloads["ip -j route"])
        routes.append({**routes[0], "gateway": "198.51.100.253"})
        payloads["ip -j route"] = json.dumps(routes).encode()
        cases.append((payloads, "conflicting_routes"))
        for payloads, reason in cases:
            with self.subTest(reason=reason, payloads=payloads):
                _, positive = self.apply()
                self.assertTrue(positive["relationships"])
                receipt, applied = self.apply(payloads)
                self.assertFalse(applied.get("relationships"))
                routes = [row for row in self.topology(receipt) if row["kind"] == "route"]
                self.assertTrue(all(row["resolution"]["reason"] == reason for row in routes))
                self.assert_no_edges()

    def test_stale_assignment_failed_or_empty_latest_and_age_never_leave_current_edges(self):
        self.known_peer()
        receipt, applied = self.apply()
        original_batch = receipt["batch_id"]
        original = self.store.connection.execute("SELECT result_json FROM applications WHERE batch_id=?",
                                                 (receipt["batch_id"],)).fetchone()[0]
        for payloads in ({}, {"ip -j route": b'[]', "ip -j neigh": b'[]'}):
            self.public_collect(payloads)
            self.assert_no_edges()
            route = next(row for row in self.topology(receipt) if row["kind"] == "route")
            self.assertEqual(route["resolution"]["reason"], "superseded_inspection")
            receipt, applied = self.apply()
            self.assertTrue(applied["relationships"])
        snapshot = list(self.store.connection.iterdump())
        self.clock += timedelta(days=self.policy.stale_after_days + 1)
        self.assert_no_edges()
        self.assertTrue(all(row["stale"] for row in self.topology(receipt)))
        self.assertEqual(list(self.store.connection.iterdump()), snapshot)
        fresh, result = self.apply()
        self.assertFalse(result.get("relationships"))
        route = next(row for row in self.topology(fresh) if row["kind"] == "route")
        self.assertEqual(route["resolution"]["reason"], "unqualified_or_stale_gateway_assignment")
        self.known_peer()
        _, result = self.apply()
        self.assertTrue(result["relationships"])
        self.assertEqual(self.store.connection.execute("SELECT result_json FROM applications WHERE batch_id=?",
                         (original_batch,)).fetchone()[0], original)

    def test_current_ip_or_stable_mac_ambiguity_withdraws_only_inference(self):
        _, peer = self.known_peer()
        receipt, applied = self.apply()
        self.assertTrue(applied["relationships"])
        self.known_peer(context="other-peer", mac="00:11:22:33:44:aa")
        self.assert_no_edges()
        route = next(row for row in self.topology(receipt) if row["kind"] == "route")
        self.assertEqual(route["resolution"]["reason"], "ambiguous_or_missing_gateway_assignment")
        # An operator assertion remains explicitly distinct from the withdrawn inference.
        source = applied["new"][0]
        edge = self.store.connection.execute("SELECT * FROM relations WHERE id=?",
                                            (applied["relationships"][0],)).fetchone()
        self.update("relationship", {"target_device": peer, "relationship_type": "routes_via",
                    "source_interface": edge["source_interface"], "target_interface": edge["target_interface"]},
                    device=source, now=self.clock)
        self.assertTrue(json.loads(self.handlers.query({"relationship": "routes_via"}))["devices"])
        selected = json.loads(self.handlers.query({"device_id": source}))["devices"][0]["relationships"][0]
        self.assertEqual(selected["facts"]["relationship"]["evidence"][0]["confidence"], "user_supplied")
        other = core.create_device(self.store, "Colliding peer", now=self.clock)["device_id"]
        core.add_interface(self.store, other, "collision0", self.peer_mac, now=self.clock)
        fresh, result = self.apply()
        self.assertFalse(result.get("relationships"))
        route = next(row for row in self.topology(fresh) if row["kind"] == "route")
        self.assertEqual(route["resolution"]["reason"], "no_unique_stable_peer")

    def test_topology_page_bounds_filters_and_malformed_or_unsupported_probes(self):
        self.known_peer()
        receipt, _ = self.apply()
        page = json.loads(self.handlers.query({"view": "topology", "batch_id": receipt["batch_id"], "limit": 1}))
        self.assertTrue(page["has_more"])
        second = json.loads(self.handlers.query({"view": "topology", "batch_id": receipt["batch_id"],
                                                "limit": 1, "offset": 1}))
        self.assertFalse(second["has_more"])
        self.assertNotEqual(page["observations"][0]["id"], second["observations"][0]["id"])
        matching = json.loads(self.handlers.query({"view": "topology", "batch_id": receipt["batch_id"],
                                                  "address": "198.51.100.254"}))
        self.assertEqual(len(matching["observations"]), 2)
        for extra in ({"device_id": self.device}, {"relationship": "routes_via"}, {"limit": 0}):
            self.assertIn("error", json.loads(self.handlers.query({"view": "topology", **extra})))
        for changes in ({"nexthops": []}, {"flags": ["linkdown"]}, {"table": 100}, {"type": "blackhole"},
                        {"gateway": "", "nexthops": []}, {"gateway": "", "nhid": 1},
                        {"gateway": "", "via": {"family": "inet", "host": "198.51.100.254"}},
                        {"gateway": "", "encap": {}}, {"gateway": "", "flags": ["linkdown"]},
                        {"gateway": "", "table": 100}, {"gateway": "", "type": "blackhole"},
                        {"gateway": "", "dst": "2001:db8::1"}):
            payloads = self.payloads()
            routes = json.loads(payloads["ip -j route"])
            routes[0].update(changes)
            payloads["ip -j route"] = json.dumps(routes).encode()
            batch, result = self.apply(payloads)
            self.assertFalse(result.get("relationships"))
            route = next(row for row in self.topology(batch) if row["kind"] == "route")
            self.assertEqual(route["resolution"]["reason"], "unsupported_route")
            self.assertEqual([item["reason"] for item in result["unresolved"]], ["unsupported_route"])
            if changes.get("dst") == "2001:db8::1":
                self.assertEqual(route["value"]["dst"], "2001:db8::1/128")
            self.assert_no_edges()
        invalid_probes = [("ip -j route", b'[{"gateway":"bad"}]'),
                          ("ip -j neigh", b'[{"dst":"198.51.100.254","state":["BAD"]}]')]
        for dst in ("203.0.113.7/24", "203.0.113.0/024", "not-an-address", "2001:db8::1%fixture0"):
            invalid_probes.append(("ip -j route", json.dumps([
                {"dst": "default", "gateway": "198.51.100.254", "dev": "fixture0"},
                {"dst": dst, "dev": "fixture0"}]).encode()))
        for command, invalid in invalid_probes:
            payloads = self.payloads()
            payloads[command] = invalid
            batch = self.public_collect(payloads)
            probe = "ssh_route" if command.endswith("route") else "ssh_neigh"
            self.assertEqual(next(p for p in batch["probes"] if p["name"] == probe)["outcome"], "parse_failed")
            if probe == "ssh_route":
                self.assertFalse(any(row["kind"] == "route" for row in self.topology(batch)))
            self.assert_no_edges()
        # Durable admission still rejects bare/noncanonical destinations; only
        # the native parser may translate iproute2's missing-prefix spelling.
        at = storage.timestamp(self.clock)
        canonical = parse.routes(outputs()["ip -j route"], ALIAS, at, self.policy)[0]
        snapshot = list(self.store.connection.iterdump())
        for dst in ("198.51.100.254", "2001:db8::1", "203.0.113.7/24", "203.0.113.0/024"):
            value = {**dict(canonical.value), "dst": dst}
            observation = replace(canonical, value=tuple(value.items()))
            probe = batches.Probe("ssh_route", "success", at, at, "exact_target", ALIAS, "ssh_response",
                                   observations=(observation,))
            with self.subTest(dst=dst), self.assertRaises(ValueError):
                batches.store_batch(self.store, "ssh", ALIAS, at, at, "complete", (probe,))
        self.assertEqual(list(self.store.connection.iterdump()), snapshot)

    def test_topology_transaction_rollback_retry_and_probe_overflow(self):
        self.known_peer()
        receipt = self.public_collect(self.payloads())
        snapshot = list(self.store.connection.iterdump())
        audit = storage.Store.audit
        def interrupted(store, operation, action, actor, at, **kwargs):
            if action == "logical_relationship_inferred":
                raise RuntimeError("synthetic topology audit failure")
            return audit(store, operation, action, actor, at, **kwargs)
        with patch.object(storage.Store, "audit", interrupted), self.assertRaises(RuntimeError):
            self.handlers.reconcile({"batch_id": receipt["batch_id"]})
        self.assertEqual(list(self.store.connection.iterdump()), snapshot)
        result = json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]}))
        self.assertNotIn("error", result)
        self.assertTrue(result["relationships"])
        policy = replace(self.policy, limits=replace(self.policy.limits, observations=32))
        payloads = self.payloads()
        payloads["ip -j route"] = json.dumps(json.loads(payloads["ip -j route"]) * 32).encode()
        # 32 routes plus the code-owned alias exceed the per-probe budget;
        # never keep a deceptively successful prefix of routing evidence.
        overflow = self.public_collect(payloads, policy)
        route = next(probe for probe in overflow["probes"] if probe["name"] == "ssh_route")
        self.assertEqual(route["outcome"], "parse_failed")
        self.assertEqual(route["observation_count"], 0)
        self.assertFalse(any(row["kind"] == "route" for row in self.topology(overflow)))
        self.assert_no_edges()

    def test_origin_ambiguity_and_retirement_do_not_relabel_inference_as_fact(self):
        self.known_peer()
        receipt, applied = self.apply()
        source = applied["new"][0]
        self.update("retired", True, device=source, now=self.clock)
        self.assert_no_edges()
        route = next(row for row in self.topology(receipt) if row["kind"] == "route")
        self.assertEqual(route["resolution"]["reason"], "retired_endpoint")
        self.update("retired", False, device=source, now=self.clock)
        self.assertTrue(json.loads(self.handlers.query({"relationship": "routes_via"}))["devices"])
        self.update("ssh_alias", ALIAS, device=self.device, now=self.clock)
        self.assert_no_edges()
        route = next(row for row in self.topology(receipt) if row["kind"] == "route")
        self.assertEqual(route["resolution"]["reason"], "unapplied_or_ambiguous_origin")
        self.assertIsNone(route["origin_device"])
        snapshot = list(self.store.connection.iterdump())
        summary = json.loads(self.handlers.query(
            {"view": "unresolved", "batch_id": receipt["batch_id"], "summary": True}))
        self.assertNotIn("error", summary)
        self.assertEqual(summary["summary"]["unapplied_observation_count"], 0)
        self.assertEqual(summary["summary"]["current_unresolved_observation_count"], 1)
        self.assertEqual([group["reason"] for group in summary["summary"]["uncertainty"]["reasons"]],
                         ["unapplied_or_ambiguous_origin"])
        self.assertEqual(list(self.store.connection.iterdump()), snapshot)


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
