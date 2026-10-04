# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline A03/A07/A08/A10 fixtures: no real ip/Nmap/network/SSH invocation."""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import importlib
from ipaddress import ip_network
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from helpers import ROOT, load_package, scratch_home
from test_core import AtlasFixture, NOW

load_package()
discovery = importlib.import_module("atlas_test_plugin.discovery")
parse = importlib.import_module("atlas_test_plugin.discovery_parse")
runner = importlib.import_module("atlas_test_plugin.probes")
batches = importlib.import_module("atlas_test_plugin.batches")
reconcile = importlib.import_module("atlas_test_plugin.reconcile")
core = importlib.import_module("atlas_test_plugin.core")
config = importlib.import_module("atlas_test_plugin.config")
storage = importlib.import_module("atlas_test_plugin.storage")
query = importlib.import_module("atlas_test_plugin.query")
tools = importlib.import_module("atlas_test_plugin.tools")

MAC = "00:11:22:33:44:55"
MAC2 = "00:11:22:33:44:66"


def assert_stopped(test: unittest.TestCase, descendant: int) -> None:
    """SIGKILL scheduling is asynchronous; give init a bounded reap opportunity."""
    deadline = time.monotonic() + 0.5
    status = Path("/proc") / str(descendant) / "status"
    while status.exists():
        try:
            state = status.read_text()
        except FileNotFoundError:
            return
        if "State:\tZ" in state:
            return
        if time.monotonic() >= deadline:
            test.fail("owned descendant survived SIGKILL")
        time.sleep(0.01)


def xml(target="192.0.2.10", mac=MAC, up=True, responder=None):
    network = ip_network(target)
    address = responder or str(network.network_address)
    host = ('<host><status state="up"/><address addr="' + address + '" addrtype="ipv4"/>' +
            (('<address addr="' + mac + '" addrtype="mac"/>') if mac else '') + '</host>') if up else ''
    return ('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>' + host +
            '<runstats><finished exit="success"/><hosts up="' + str(int(up)) + '" down="' + str(network.num_addresses - int(up)) +
            '" total="' + str(network.num_addresses) + '"/></runstats></nmaprun>').encode()


def observation(mac=MAC, address="192.0.2.10", at=NOW, state=None, prefix=32):
    return batches.Observation("address", batches.Anchor("mac", mac), "assignment",
                               (("address", address), ("prefix_length", prefix)), storage.timestamp(at), state)


class DiscoveryTests(AtlasFixture):
    def passive(self, *, neighbor_state="STALE"):
        def fake(argv, limits, deadline, **kwargs):
            self.assertFalse(self.store.connection.in_transaction)
            # A separate write completes while the collector is still running.
            with storage.Store(self.policy, writable=True) as second, second.transaction():
                second.connection.execute("UPDATE devices SET retired=retired WHERE id=?", (self.device,))
            self.assertGreater(deadline, time.monotonic())
            payloads = {
                ("ip", "-j", "addr"): [{"ifname": "fixture;$(ignored)", "address": MAC, "operstate": "UP",
                                         "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}, {"local": "198.51.100.1", "prefixlen": 24}]}],
                ("ip", "-j", "route"): [{"dst": "198.51.100.0/24", "gateway": "192.0.2.254", "dev": "fixture0"}],
                ("ip", "-j", "neigh"): [{"dst": "192.0.2.10", "lladdr": MAC2, "state": [neighbor_state]}],
            }
            self.assertIn(argv, payloads)
            return runner.CommandResult("success", json.dumps(payloads[argv]).encode())
        with patch.object(discovery, "run", fake):
            return discovery.collect(self.policy, {"network": "lab", "mode": "passive"})

    def test_passive_fixed_argv_scope_atomic_no_canonical_mutation(self):
        before = self.counts()
        receipt = self.passive()
        self.assertEqual(receipt["completion"], "complete")
        self.assertTrue(receipt["persisted"])
        self.assertFalse(receipt["applied"])
        self.assertEqual(self.counts()["devices"], before["devices"])
        self.assertEqual(self.store.connection.execute("SELECT SUM(absence_eligible) FROM probes").fetchone()[0], 0)
        evidence = self.store.connection.execute("SELECT * FROM observations WHERE batch_id=?", (receipt["batch_id"],)).fetchall()
        self.assertEqual(len(evidence), 4)
        self.assertTrue(all(row["entity_id"] is None for row in evidence))
        self.assertFalse(any('198.51.100' in row["value_json"] for row in evidence))
        applied = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(len(applied["new"]), 2)
        self.assertFalse(applied["missing"])
        devices = query.query(self.policy, {})["devices"]
        cached = next(row for row in devices if any(i["mac_address"] == MAC2 for i in row["interfaces"]))
        self.assertIsNone(cached["last_seen"])
        self.assertEqual(cached["status"], "known")
        self.assertEqual(cached["interfaces"][0]["addresses"][0]["evidence_kind"], "cached_neighbor")

    def test_discover_handler_boundary_policy_reload_and_disabled_mode(self):
        handler = tools.Handlers(self.home)
        bad = [{}, [], {"network": "192.0.2.0/24", "mode": "ping"}, {"network": "lab", "mode": "-sV"},
               {"network": "lab;touch x", "mode": "passive"}, {"network": "lab", "mode": True}]
        bad += [{"network": "lab", "mode": "ping", key: "x"} for key in ("command", "target", "flags", "path", "source", "limits")]
        with patch.object(discovery, "run", side_effect=AssertionError("unauthorized probe")):
            for params in bad:
                self.assertIn("error", json.loads(handler.discover(params)))
            (self.home / "network-atlas" / "config.yaml").write_text("{}")
            self.assertIn("error", json.loads(handler.discover({"network": "lab", "mode": "ping"}, operator=True)))
            self.assertIn("error", json.loads(handler.command("discover lab passive")))
        self.assertEqual(self.counts()["batches"], 0)

    def test_partial_positive_survives_other_probe_failure(self):
        def fake(argv, *args, **kwargs):
            if argv[-1] == "addr":
                return runner.CommandResult("success", b'[{"ifname":"fixture0","address":"00:11:22:33:44:55","addr_info":[{"local":"192.0.2.1","prefixlen":24}]}]')
            return runner.CommandResult("unavailable", diagnostic_code="executable_missing")
        with patch.object(discovery, "run", fake):
            receipt = discovery.collect(self.policy, {"network": "lab", "mode": "passive"})
        self.assertEqual(receipt["completion"], "partial")
        result = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(len(result["new"]), 1)
        self.assertFalse(result["missing"])
        detail = query.query(self.policy, {"device_id": result["new"][0]})["devices"][0]
        self.assertIsNotNone(detail["last_seen"])

    def test_malformed_output_failed_batch_does_not_refresh_or_absent(self):
        with patch.object(discovery, "run", return_value=runner.CommandResult("success", b'{"command":"do not execute"}')):
            receipt = discovery.collect(self.policy, {"network": "lab", "mode": "passive"})
        self.assertEqual(receipt["completion"], "failed")
        self.assertEqual({row["outcome"] for row in receipt["probes"]}, {"parse_failed"})
        result = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertFalse(result["missing"])
        self.assertIsNone(self.detail()["last_seen"])
        self.assertIsNone(self.detail()["last_checked"])

    def test_ping_every_configured_address_fixed_no_udp_or_services(self):
        self.raw["networks"]["lab"]["cidr"] = "192.0.2.8/30"
        self.policy = config.validate_policy(self.raw, self.home)
        seen = set()
        lock = threading.Lock()
        active = maximum = 0
        def fake(argv, limits, deadline, **kwargs):
            nonlocal active, maximum
            self.assertEqual(argv[:4], ("nmap", "-sn", "-n", "-PS80,443"))
            self.assertEqual(argv[4:-1], ("--host-timeout", "10s", "--max-parallelism", "4", "--max-rate", "32", "-oX", "-"))
            self.assertTrue(kwargs["host"])
            target = argv[-1]
            self.assertEqual(target, "192.0.2.8/30")
            with lock:
                active += 1
                maximum = max(active, maximum)
                seen.add(target)
            time.sleep(0.02)
            with lock:
                active -= 1
            return runner.CommandResult("success", xml(target, responder="192.0.2.10"))
        with patch.object(discovery, "run", fake):
            receipt = discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(len(seen), 1)
        self.assertEqual(len(receipt["probes"]), 5)
        self.assertLessEqual(maximum, self.policy.limits.concurrent_probes)
        self.assertEqual(receipt["completion"], "complete")
        self.assertEqual(self.store.connection.execute("SELECT COUNT(*) FROM probes WHERE absence_eligible=1").fetchone()[0], 1)
        result = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(len(result["new"]), 1)

    def test_ping_out_of_target_injection_and_missing_dependency_no_install(self):
        self.raw["networks"]["lab"]["cidr"] = "192.0.2.10/32"
        policy = config.validate_policy(self.raw, self.home)
        for outcome in (runner.CommandResult("success", xml("198.51.100.10")),
                        runner.CommandResult("unavailable", diagnostic_code="executable_missing")):
            with self.subTest(outcome=outcome.outcome), patch.object(discovery, "run", return_value=outcome):
                receipt = discovery.collect(policy, {"network": "lab", "mode": "ping"})
            self.assertEqual(receipt["completion"], "failed")
            self.assertEqual(receipt["probes"][0]["observation_count"], 0)
            result = reconcile.reconcile(policy, {"batch_id": receipt["batch_id"]})
            self.assertFalse(result["new"])
            self.assertFalse(result["missing"])

    def test_response_and_observation_overflow_roll_back_batch(self):
        before = self.counts()
        small = replace(self.policy, limits=replace(self.policy.limits, output_bytes=128))
        with patch.object(discovery, "run", return_value=runner.CommandResult("unavailable", diagnostic_code="executable_missing")), self.assertRaises(ValueError):
            discovery.collect(small, {"network": "lab", "mode": "passive"})
        self.assertEqual(self.counts(), before)
        tiny = replace(self.policy, limits=replace(self.policy.limits, observations=1))
        with patch.object(discovery, "run", side_effect=AssertionError("must preflight count")), self.assertRaises(ValueError):
            discovery.collect(tiny, {"network": "lab", "mode": "passive"})


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.policy = config.validate_policy({}, Path(self.temp.name))
        self.at = storage.timestamp(NOW)

    def test_nmap_golden_numeric_host_and_negative_xml(self):
        self.assertEqual(parse.nmap(xml(), "192.0.2.10", self.at, self.policy)[0], observation())
        self.assertEqual(parse.nmap(xml(up=False), "192.0.2.10", self.at, self.policy), ())
        bad = [b"<nmaprun/>", xml().replace(b'exit="success"', b'exit="error"'), xml().replace(b'total="1"', b'total="2"'),
               xml().replace(b'<host>', b'<host timedout="true">'), xml("198.51.100.10"),
               b'<!DOCTYPE nmaprun [<!ENTITY x "injected">]><nmaprun/>', b'<nmaprun><']
        for data in bad:
            with self.subTest(data=data[:80]), self.assertRaises((ValueError, parse.ElementTree.ParseError)):
                parse.nmap(data, "192.0.2.10", self.at, self.policy)

    def test_ip_golden_v6_scope_failed_neighbors_and_negative_formats(self):
        data = b'[{"dst":"2001:db8::1","lladdr":"00:11:22:33:44:55","state":["FAILED"]}]'
        result = parse.neighbors(data, "2001:db8::/64", self.at, self.policy)
        self.assertEqual(result[0].neighbor_state, "FAILED")
        self.assertEqual(dict(result[0].value)["prefix_length"], 128)
        bad = [b'{}', b'[1]', b'[{"dst":"192.0.2.1","dst":"192.0.2.2"}]',
               b'[{"dst":"192.0.2.10","lladdr":"$(id)","state":["STALE"]}]',
               b'[{"dst":"192.0.2.10","state":["UP"]}]']
        for payload in bad:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                parse.neighbors(payload, "192.0.2.0/24", self.at, self.policy)
        with self.assertRaises(ValueError):
            parse.addresses(b'[{"ifname":"fixture","addr_info":[{"local":"192.0.2.1","prefixlen":true}]}]', "192.0.2.0/24", self.at, self.policy)
        with self.assertRaises(ValueError):
            parse.routes(b'[{"gateway":"not-ip"}]', "192.0.2.0/24", self.at, self.policy)


class ReconciliationTests(AtlasFixture):
    def batch(self, observations=(), *, at=NOW, collector="ping", outcome="success"):
        stamp = storage.timestamp(at)
        evidence = "ping_response" if collector == "ping" else "cached_neighbor"
        coverage = "exact_network" if collector == "ping" else "local_host"
        probe = batches.Probe("synthetic", outcome, stamp, stamp, coverage, "192.0.2.0/24", evidence,
                             observations=tuple(observations))
        return batches.store_batch(self.store, collector, "lab", stamp, stamp,
                                   "complete" if outcome == "success" else "failed", (probe,))

    def apply(self, batch, at=NOW):
        return reconcile.reconcile(self.policy, {"batch_id": batch}, now=at)

    def test_new_changed_unchanged_ip_movement_multi_address_idempotent_reopen(self):
        first = self.batch([observation(), observation(address="192.0.2.11")])
        result = self.apply(first)
        self.assertEqual(len(result["new"]), 1)
        device = result["new"][0]
        counts = self.counts()
        self.assertEqual(self.apply(first), result)
        self.assertEqual(self.counts(), counts)
        second = self.batch([observation(address="192.0.2.12", at=NOW + timedelta(days=1))], at=NOW + timedelta(days=1))
        changed = self.apply(second, NOW + timedelta(days=1))
        self.assertIn(device, changed["changed"])
        detail = self.detail(device=device, now=NOW + timedelta(days=1))
        self.assertEqual({a["address"] for a in detail["interfaces"][0]["addresses"]}, {"192.0.2.10", "192.0.2.11", "192.0.2.12"})
        third = self.batch([observation(address="192.0.2.12", at=NOW + timedelta(days=2))], at=NOW + timedelta(days=2))
        unchanged = self.apply(third, NOW + timedelta(days=2))
        self.assertIn(device, unchanged["unchanged"])
        self.assertEqual(detail["id"], device)
        self.assertEqual(self.detail(device=device, now=NOW + timedelta(days=2))["first_seen"], storage.timestamp(NOW))
        with storage.Store(self.policy) as reader:
            stored = json.loads(reader.connection.execute("SELECT result_json FROM applications WHERE batch_id=?", (first,)).fetchone()[0])
            self.assertEqual(stored, result)

    def test_missing_not_offline_stale_threshold_never_seen_reappearance_retired(self):
        first = self.apply(self.batch([observation()]))
        device = first["new"][0]
        missing = self.apply(self.batch(at=NOW + timedelta(days=1)), NOW + timedelta(days=1))
        self.assertEqual(missing["missing"][0]["meaning"], "not_observed_in_this_run")
        self.assertEqual(self.detail(device=device, now=NOW + timedelta(days=1))["status"], "observed")
        stale = self.apply(self.batch(at=NOW + timedelta(days=15)), NOW + timedelta(days=15))
        self.assertIn(device, stale["changed"])
        self.assertEqual(self.detail(device=device, now=NOW + timedelta(days=15))["status"], "stale")
        self.assertEqual(self.detail(now=NOW + timedelta(days=15))["status"], "known")
        seen = self.apply(self.batch([observation(at=NOW + timedelta(days=16))], at=NOW + timedelta(days=16)), NOW + timedelta(days=16))
        self.assertIn(device, seen["changed"])
        self.assertEqual(self.detail(device=device, now=NOW + timedelta(days=16))["status"], "observed")
        self.update("retired", True, device=device)
        self.apply(self.batch([observation(at=NOW + timedelta(days=17))], at=NOW + timedelta(days=17)), NOW + timedelta(days=17))
        self.assertEqual(self.detail(device=device, now=NOW + timedelta(days=17))["status"], "retired")
        self.assertEqual(self.counts()["devices"], 2)

    def test_cached_failed_and_incomplete_neighbors_do_not_refresh_seen_or_check(self):
        iface = core.add_interface(self.store, self.device, "fixture", MAC, now=NOW)
        for state in ("FAILED", "INCOMPLETE", "STALE", "REACHABLE"):
            self.apply(self.batch([observation(state=state)], collector="local_passive"))
            self.assertIsNone(self.detail()["last_seen"])
            self.assertFalse(self.detail()["interfaces"][0]["addresses"][0]["qualified"])
            if state in {"FAILED", "INCOMPLETE"}:
                self.assertIsNone(self.detail()["last_checked"])
        self.assertEqual(self.detail()["interfaces"][0]["id"], iface)
        self.assertEqual(self.detail()["last_checked"], storage.timestamp(NOW))

    def test_mac_collision_randomization_unresolved_ip_and_address_ownership_conflict(self):
        iface = core.add_interface(self.store, self.device, "fixture", MAC, now=NOW)
        core.add_address(self.store, iface, "192.0.2.10", 32, now=NOW)
        result = self.apply(self.batch([observation(mac=MAC2)]))
        self.assertNotEqual(result["new"][0], self.device)
        self.assertTrue(result["conflicting"])
        original = self.detail()
        self.assertIsNone(original["last_seen"])
        # IP-only response cannot attest its existing owner, but is not absence.
        unresolved = batches.Observation("address", batches.Anchor("unresolved", "ip_only"), "assignment",
                                         (("address", "192.0.2.10"), ("prefix_length", 32)), storage.timestamp(NOW))
        answer = self.apply(self.batch([unresolved, observation(mac="02:11:22:33:44:55", address="192.0.2.20")]))
        self.assertEqual(len(answer["unresolved"]), 2)
        self.assertFalse(answer["missing"])
        self.assertIsNone(self.detail()["last_seen"])
        other = core.create_device(self.store, "colliding fixture", now=NOW)["device_id"]
        core.add_interface(self.store, other, "fixture2", MAC, now=NOW)
        collision = self.apply(self.batch([observation()]))
        self.assertTrue({self.device, other} <= set(collision["unresolved"][0]["candidate_device_ids"]))
        self.assertTrue(collision["conflicting"])
        self.assertEqual(collision["new"], [])

    def test_failed_scan_does_not_check_or_assert_missing(self):
        device = self.apply(self.batch([observation()]))["new"][0]
        before = self.detail(device=device)
        result = self.apply(self.batch(outcome="timeout", at=NOW + timedelta(days=1)), NOW + timedelta(days=1))
        self.assertFalse(result["missing"])
        after = self.detail(device=device, now=NOW + timedelta(days=1))
        self.assertEqual((before["last_seen"], before["last_checked"]), (after["last_seen"], after["last_checked"]))

    def test_transaction_failure_overflow_and_repeat_are_atomic(self):
        batch = self.batch([observation()])
        before = self.counts()
        with patch.object(reconcile.Application, "event", side_effect=RuntimeError("synthetic audit failure")), self.assertRaises(RuntimeError):
            self.apply(batch)
        self.assertEqual(self.counts(), before)
        tiny = replace(self.policy, limits=replace(self.policy.limits, output_bytes=128))
        with self.assertRaises(ValueError):
            reconcile.reconcile(tiny, {"batch_id": batch}, now=NOW)
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.store.connection.execute("SELECT COUNT(*) FROM applications").fetchone()[0], 0)
        result = self.apply(batch)
        counts = self.counts()
        self.assertEqual(self.apply(batch), result)
        self.assertEqual(self.counts(), counts)

    def test_latest_selection_unknown_id_scope_revocation_and_shared_profile(self):
        first = self.batch([observation()])
        second = self.batch(at=NOW + timedelta(seconds=1))
        self.assertEqual(reconcile.reconcile(self.policy, {}, now=NOW + timedelta(seconds=1))["batch_id"], second)
        self.assertEqual(reconcile.reconcile(self.policy, {}, now=NOW + timedelta(seconds=1))["batch_id"], first)
        for params in ({"batch_id": "unknown"}, {"batch_id": "';SELECT 1"}, {"source": "user"}, {"batch_id": None}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                reconcile.reconcile(self.policy, params, now=NOW)
        revoked = config.validate_policy({}, self.home)
        with self.assertRaises(ValueError):
            reconcile.reconcile(revoked, {"batch_id": first}, now=NOW)
        second_profile = config.validate_policy({**self.raw, "store": {"shared_sqlite_path": str(self.policy.database)}}, self.home / "other")
        with self.assertRaises(ValueError):
            reconcile.reconcile(second_profile, {"batch_id": first}, now=NOW)
        self.assertFalse(second_profile.home.exists())


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        (self.home / "offline-fixture").touch()
        self.env = patch.dict(os.environ, {"NETWORK_ATLAS_OFFLINE_FIXTURE_DIR": str(self.home)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.limits = replace(config.Limits(), command_timeout_seconds=1, host_timeout_seconds=1)

    def run_probe(self, mode, limits=None, deadline=None):
        return runner.run((sys.executable, str(ROOT / "scripts" / "offline_probe.py"), mode),
                          limits or self.limits, deadline or time.monotonic() + 10, host=True)

    def test_actual_stream_combined_output_limit_and_success(self):
        self.assertEqual(self.run_probe("echo").stdout, b"safe-output")
        result = self.run_probe("flood", replace(self.limits, output_bytes=1000))
        self.assertEqual(result.outcome, "output_limit")
        self.assertEqual(result.stdout, b"")
        self.assertEqual(self.run_probe("echo", replace(self.limits, output_bytes=17)).outcome, "output_limit")
        self.assertEqual(self.run_probe("echo", replace(self.limits, output_bytes=18)).outcome, "success")

    def test_actual_host_and_operation_deadlines_owned_child_reaped(self):
        children = []
        real = runner.subprocess.Popen
        def spawn(*args, **kwargs):
            self.assertFalse(kwargs["shell"])
            self.assertTrue(kwargs["start_new_session"])
            child = real(*args, **kwargs)
            children.append(child)
            return child
        for mode, duration in (("sleep", 10), ("fork", 0.15)):
            started = time.monotonic()
            with patch.object(runner.subprocess, "Popen", spawn):
                result = self.run_probe(mode, deadline=time.monotonic() + duration)
            self.assertEqual(result.outcome, "timeout")
            self.assertLess(time.monotonic() - started, 1.8)
        self.assertTrue(all(child.poll() is not None for child in children))
        for child in children:
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)
        parent, descendant = json.loads((self.home / "owned-pids.json").read_text())
        self.assertEqual(parent, children[-1].pid)
        assert_stopped(self, descendant)

    def test_missing_executable_and_expired_operation_no_spawn(self):
        result = runner.run((str(self.home / "missing-executable"),), self.limits, time.monotonic() + 1)
        self.assertEqual(result.outcome, "unavailable")
        with patch.object(runner.subprocess, "Popen", side_effect=AssertionError("expired operation must not spawn")):
            result = runner.run(("never",), self.limits, time.monotonic() - 1)
        self.assertEqual(result.outcome, "not_started")
