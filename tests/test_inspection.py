# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic A03/A05/A08/A09/A12 inspection evidence; no real SSH subprocess."""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
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
render = importlib.import_module("atlas_test_plugin.render")
batches = importlib.import_module("atlas_test_plugin.batches")

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

    def test_public_next_hop_retains_provenance_query_map_replay_and_foreign_history(self):
        foreign, peer = self.known_peer()
        # Preserve every existing logical row, not SQLite page/journal bytes.
        retained = {name: self.store.connection.execute(f"SELECT * FROM {name} ORDER BY rowid").fetchall()
                    for name in self.counts()}
        payloads = self.payloads()
        payloads["ip -j route"] = json.dumps([
            {"dst": "default", "gateway": "198.51.100.254", "dev": "fixture0"},
            {"dst": "198.51.100.254", "dev": "fixture0", "scope": "link"}]).encode()
        receipt = self.public_collect(payloads)
        probe = next(p for p in receipt["probes"] if p["name"] == "ssh_route")
        self.assertEqual((probe["outcome"], probe["observation_count"]), ("success", 3))
        raw = self.topology(receipt)
        self.assertEqual({row["kind"] for row in raw}, {"route", "neighbor"})
        self.assertEqual({row["value"]["dst"] for row in raw if row["kind"] == "route"},
                         {"default", "198.51.100.254/32"})
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
        self.assertEqual(fact["value"]["route_evidence_id"], route["id"])
        self.assertTrue(fact["explanation"])
        self.assertEqual(fact["observed_at"], route["observed_at"])
        routes = [row for row in self.topology(receipt) if row["kind"] == "route"]
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
        self.assertTrue(all(not row["local_context"] for row in self.topology(receipt, shared)))
        shared_handlers = tools.Handlers(lambda: shared)
        self.assertEqual(json.loads(shared_handlers.query({"device_id": source}))["devices"][0][
            "relationships"][0]["id"], edge["id"])
        with patch.object(inspection, "run", side_effect=AssertionError("knowledge is not collection authority")):
            self.assertIn("error", json.loads(shared_handlers.inspect({"target": ALIAS})))
            self.assertIn("error", json.loads(shared_handlers.reconcile({"batch_id": receipt["batch_id"]})))
        self.assertEqual(list(self.store.connection.iterdump()), snapshot)

    def test_unknown_peer_never_created_and_later_identity_requires_new_collection(self):
        receipt, applied = self.apply()
        self.assertEqual(len(applied["new"]), 1)
        self.assertFalse(applied.get("relationships"))
        route = next(row for row in self.topology(receipt) if row["kind"] == "route")
        self.assertEqual(route["resolution"]["reason"], "no_unique_stable_peer")
        self.assertEqual([item["reason"] for item in applied["unresolved"]], ["no_unique_stable_peer"])
        self.assert_no_edges()
        self.known_peer()
        route = next(row for row in self.topology(receipt) if row["kind"] == "route")
        self.assertEqual(route["resolution"]["reason"], "not_derived_at_application")
        self.assertEqual(json.loads(self.handlers.reconcile({"batch_id": receipt["batch_id"]})), applied)
        self.assert_no_edges()
        _, successor = self.apply()
        self.assertEqual(len(successor["relationships"]), 1)

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
