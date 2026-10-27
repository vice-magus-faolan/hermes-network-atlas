# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic chunk scheduling, hostile XML and full-scope accounting; no network."""
from collections import Counter
from dataclasses import replace
from ipaddress import ip_network
from pathlib import Path
import importlib
import os
import sqlite3
import sys
import unittest
from unittest.mock import patch

if __name__ == "__main__":
    from network_guard import deny_network
    deny_network()

import test_discovery as fixture

transport = importlib.import_module("atlas_test_plugin.host_transport")


def chunk_xml(scope, responders=(), *, down_records=(), excluded=()):
    network = ip_network(scope)
    targets = [str(ip) for ip in network if str(ip) not in excluded]
    hosts = []
    ordered = (*responders, *down_records, *(ip for ip in targets if ip not in (*responders, *down_records)))
    for address in ordered:
        state = "up" if address in responders else "down"
        reason = "syn-ack" if state == "up" else "no-response"
        hosts.append(f'<host><status state="{state}" reason="{reason}"/>'
                     f'<address addr="{address}" addrtype="ipv4"/>'
                     '<address addr="00:11:22:33:44:55" addrtype="mac"/></host>')
    up = len(responders)
    return ('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>' + ''.join(hosts) +
            f'<runstats><finished exit="success"/><hosts up="{up}" down="{len(targets) - up}" '
            f'total="{len(targets)}"/></runstats></nmaprun>').encode()


class ChunkDiscoveryTests(fixture.AtlasFixture):
    def native_ping(self, policy, result):
        (self.home / "offline-fixture").touch()
        spawn = fixture.runner.subprocess.Popen
        calls = []

        def offline(argv, **kwargs):
            self.assertEqual(argv[0], "nmap")
            calls.append(argv)
            return spawn((sys.executable, str(fixture.ROOT / "tests" / "offline_probe.py"),
                          "nmap-fixture", *argv[1:]), **kwargs)

        with (patch.dict(os.environ, {"NETWORK_ATLAS_OFFLINE_FIXTURE_DIR": str(self.home),
                                     "NETWORK_ATLAS_OFFLINE_NMAP_RESULT": result}),
              patch.object(fixture.runner.subprocess, "Popen", offline)):
            receipt = fixture.discovery.collect(policy, {"network": "lab", "mode": "ping"})
        return receipt, calls

    def test_native_no_route_is_unknown_but_completed_no_reply_is_checked(self):
        self.raw["networks"]["lab"]["cidr"] = "192.0.2.10/32"
        policy = fixture.config.validate_policy(self.raw, self.home)
        interface = fixture.core.add_interface(self.store, self.device, "fixture", fixture.MAC, now=fixture.NOW)
        fixture.core.add_address(self.store, interface, "192.0.2.10", 32, now=fixture.NOW)
        for result in ("no-route", "no-targets", "no-reply", "positive"):
            with self.subTest(result=result):
                receipt, calls = self.native_ping(policy, result)
                complete = result in {"no-reply", "positive"}
                self.assertEqual(receipt["completion"], "complete" if complete else "failed")
                if result in {"no-route", "no-targets"}:
                    self.assertEqual(receipt["probes"][0]["outcome"], "unavailable")
                    self.assertEqual(receipt["probes"][0]["diagnostic_code"],
                                     "nmap_route_unavailable" if result == "no-route" else "nmap_incomplete_coverage")
                self.assertEqual(len(calls), 1)
                status = fixture.query.query(policy, {"view": "status"})["last_discovery"]
                self.assertEqual(status["scope_absence_eligible"], complete)
                batch = receipt["batch_id"]
                history = {table: [tuple(row) for row in self.store.connection.execute(
                    f"SELECT * FROM {table} WHERE batch_id=?" +
                    (" AND entity_id IS NULL" if table == "observations" else ""), (batch,))]
                    for table in ("probes", "observations")}
                with fixture.storage.Store(policy) as reader:
                    saved = reader.connection.execute("SELECT completion FROM batches WHERE id=?", (batch,)).fetchone()
                    self.assertEqual(saved[0], receipt["completion"])
                applied = fixture.reconcile.reconcile(policy, {"batch_id": batch})
                self.assertEqual(bool(applied["missing"]), result == "no-reply")
                if not complete:
                    self.assertIsNone(self.detail()["last_checked"])
                self.assertEqual(fixture.reconcile.reconcile(policy, {"batch_id": batch}), applied)
                for table, rows in history.items():
                    self.assertEqual([tuple(row) for row in self.store.connection.execute(
                        f"SELECT * FROM {table} WHERE batch_id=?" +
                        (" AND entity_id IS NULL" if table == "observations" else ""), (batch,))], rows)
                self.assertNotIn("private fixture", str(list(self.store.connection.iterdump())))
        self.assertIsNotNone(self.detail()["last_seen"])

    def test_native_exclusions_use_configured_scope_not_chunk_boundaries(self):
        for cidr in ("192.0.2.8/30", "192.0.2.10/31", "192.0.2.10/32", "192.0.2.0/27"):
            with self.subTest(cidr=cidr):
                self.raw["networks"]["lab"]["cidr"] = cidr
                policy = fixture.config.validate_policy(self.raw, self.home)
                receipt, calls = self.native_ping(policy, "no-reply")
                network = policy.networks[0]
                excluded = {str(ip) for ip in ip_network(cidr) if transport.excluded(network, str(ip))}
                actual = set()
                for argv in calls:
                    blocked = set(argv[argv.index("--exclude") + 1].split(",")) if "--exclude" in argv else set()
                    actual.update(str(ip) for ip in ip_network(argv[-1]) if str(ip) not in blocked)
                self.assertEqual(actual, {str(ip) for ip in ip_network(cidr)} - excluded)
                self.assertEqual(receipt["completion"], "partial" if excluded else "complete")
                self.assertEqual(Counter(p["diagnostic_code"] for p in receipt["probes"][:-1])[
                    "destination_excluded"], len(excluded))

    def test_all_excluded_scope_never_launches_and_small_completed_boundary_stays_complete(self):
        self.raw["networks"]["lab"]["cidr"] = "127.0.0.1/32"
        policy = fixture.config.validate_policy(self.raw, self.home)
        with patch.object(fixture.runner.subprocess, "Popen", side_effect=AssertionError("excluded spawn")):
            receipt = fixture.discovery.collect(policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(receipt["completion"], "failed")
        self.assertEqual(receipt["probes"][0]["diagnostic_code"], "destination_excluded")
        self.raw["networks"]["lab"]["cidr"] = "192.0.2.10/31"
        policy = fixture.config.validate_policy(self.raw, self.home)
        clock = [0.0]

        def completed(argv, limits, deadline, **kwargs):
            clock[0] = deadline + 0.01
            return fixture.runner.CommandResult("success", chunk_xml(argv[-1]))

        with (patch.object(fixture.discovery.time, "monotonic", side_effect=lambda: clock[0]),
              patch.object(fixture.discovery, "run", side_effect=completed) as run):
            receipt = fixture.discovery.collect(policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(run.call_count, 1)
        self.assertEqual(receipt["completion"], "complete")
        self.assertEqual({p["diagnostic_code"] for p in receipt["probes"][:-1]}, {"completed_at_boundary"})

    def test_sparse_24_startup_budget_reaches_last_eligible_address_and_reconciles_exact_batch(self):
        # A fixed three-second process/wave cost: the legacy four-worker per-IP
        # scheduler needs 64 waves and cannot fit the transport budget. Chunks
        # cost the same startup but need only 16 sequential children. Not a claim
        # about actual Nmap/network timing.
        clock = [0.0]
        calls = []
        def transport(argv, limits, deadline, **kwargs):
            target = ip_network(argv[-1])
            calls.append(target)
            if target.num_addresses == 1:
                index = int(target.network_address) - int(ip_network("192.0.2.0/24").network_address)
                end = (index // limits.concurrent_probes + 1) * 3.0
            else:
                end = clock[0] + 3.0
            clock[0] = max(clock[0], min(end, deadline))
            if end > deadline:
                return fixture.runner.CommandResult("timeout", diagnostic_code="deadline_exceeded")
            responders = tuple(ip for ip in ("192.0.2.1", "192.0.2.254") if fixture.parse._ip(ip) in target)
            return fixture.runner.CommandResult("success", chunk_xml(
                str(target), responders, excluded=fixture.exclusions(argv)))
        with patch.object(fixture.discovery.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(fixture.discovery, "run", transport):
            receipt = fixture.discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(receipt["completion"], "partial", Counter(p["outcome"] for p in receipt["probes"]))
        self.assertEqual(len(calls), 16)
        self.assertEqual({net.num_addresses for net in calls}, {16})
        self.assertEqual(len(receipt["probes"]), 257)
        self.assertEqual(sum(p["observation_count"] for p in receipt["probes"]), 2)
        answer = fixture.reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(len(answer["new"]), 1)
        detail = self.detail(device=answer["new"][0])
        self.assertEqual({a["address"] for a in detail["interfaces"][0]["addresses"]}, {"192.0.2.1", "192.0.2.254"})
        before = self.counts()
        self.assertEqual(fixture.reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]}), answer)
        self.assertEqual(self.counts(), before)
        status = fixture.query.query(self.policy, {"view": "status"})["last_discovery"]
        self.assertEqual(status["probe_summary"]["total_count"], 257)
        self.assertEqual(status["probe_summary"]["address_count"], 256)
        self.assertEqual(status["probe_summary"]["address_outcome_counts"]["success"], 254)
        self.assertFalse(status["scope_absence_eligible"])

    def test_mid_chunk_deadline_keeps_earlier_positive_and_marks_tail_not_started(self):
        clock = [0.0]
        calls = []
        def transport(argv, limits, deadline, **kwargs):
            self.assertLess(clock[0], deadline)
            calls.append(argv[-1])
            if len(calls) == 1:
                clock[0] += 1
                return fixture.runner.CommandResult("success", chunk_xml(
                    argv[-1], ("192.0.2.1",), excluded=fixture.exclusions(argv)))
            clock[0] = deadline
            return fixture.runner.CommandResult("timeout", diagnostic_code="deadline_exceeded")
        with patch.object(fixture.discovery.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(fixture.discovery, "run", transport):
            receipt = fixture.discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(len(calls), 2)
        self.assertEqual(receipt["completion"], "partial")
        addresses = receipt["probes"][:-1]
        self.assertEqual(Counter(p["outcome"] for p in addresses),
                         {"success": 15, "timeout": 16, "not_started": 223, "unavailable": 2})
        self.assertEqual({p["diagnostic_code"] for p in addresses[16:32]}, {"deadline_exceeded"})
        self.assertEqual({p["diagnostic_code"] for p in addresses[32:-1]}, {"operation_deadline_exceeded"})
        self.assertEqual(sum(p["observation_count"] for p in addresses), 1)
        answer = fixture.reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(len(answer["new"]), 1)
        self.assertFalse(answer["missing"])
        status = fixture.query.query(self.policy, {"view": "status"})["last_discovery"]
        self.assertFalse(status["scope_absence_eligible"])
        self.assertEqual(status["probe_summary"]["address_count"], 256)
        self.assertEqual(status["probe_summary"]["address_outcome_counts"]["not_started"], 223)

    def test_completed_at_transport_boundary_retained_no_late_chunk(self):
        clock = [0.0]
        calls = []
        def transport(argv, limits, deadline, **kwargs):
            calls.append(argv[-1])
            clock[0] = deadline + 0.01  # completed I/O; time passed on return/parse
            return fixture.runner.CommandResult("success", chunk_xml(
                argv[-1], ("192.0.2.1",), excluded=fixture.exclusions(argv)))
        with patch.object(fixture.discovery.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(fixture.discovery, "run", transport):
            receipt = fixture.discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(Counter(p["outcome"] for p in receipt["probes"][:-1]),
                         {"success": 15, "not_started": 239, "unavailable": 2})
        self.assertEqual({p["diagnostic_code"] for p in receipt["probes"][1:16]}, {"completed_at_boundary"})
        self.assertEqual(sum(p["observation_count"] for p in receipt["probes"]), 1)

    def test_last_completed_chunk_at_boundary_keeps_positive_without_covering_exclusions(self):
        raw = {**self.raw, "networks": {"lab": {"cidr": "192.0.2.0/27", "allow_public": True,
                                             "discovery": {"passive": True, "ping": True}}}}
        policy = fixture.config.validate_policy(raw, self.home)
        clock = [0.0]
        calls = []
        def transport(argv, limits, deadline, **kwargs):
            calls.append(argv[-1])
            clock[0] = deadline + 0.01 if len(calls) == 2 else 1.0
            responders = ("192.0.2.30",) if len(calls) == 2 else ()
            return fixture.runner.CommandResult("success", chunk_xml(
                argv[-1], responders, excluded=fixture.exclusions(argv)))
        with (patch.object(fixture.discovery.time, "monotonic", side_effect=lambda: clock[0]),
              patch.object(fixture.discovery, "run", transport)):
            receipt = fixture.discovery.collect(policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(receipt["completion"], "partial")
        self.assertEqual(receipt["probes"][30]["diagnostic_code"], "completed_at_boundary")
        self.assertEqual(receipt["probes"][30]["observation_count"], 1)
        self.assertFalse(fixture.query.query(policy, {"view": "status"})["last_discovery"]["scope_absence_eligible"])

    def test_deadline_rechecked_immediately_before_owned_spawn(self):
        with patch.object(fixture.runner.time, "monotonic", side_effect=(0.0, 0.0, 2.0)), \
                patch.object(fixture.runner.subprocess, "Popen", side_effect=AssertionError("late spawn")):
            result = fixture.runner.run(("never",), self.policy.limits, 1.0)
        self.assertEqual(result.outcome, "not_started")
        self.assertEqual(result.diagnostic_code, "operation_deadline_exceeded")

    def test_fixed_argv_serial_process_internal_concurrency_rate_and_lowered_bounds(self):
        for concurrency in (1, 2, 4):
            policy = replace(self.policy, limits=replace(
                self.policy.limits, concurrent_probes=concurrency, host_timeout_seconds=2))
            calls = []
            def transport(argv, limits, deadline, *, concurrency=concurrency, calls=calls, **kwargs):
                self.assertTrue(kwargs["host"])  # whole chunk is externally host-bounded too
                base = argv[:argv.index("--exclude")] if "--exclude" in argv else argv[:-1]
                self.assertEqual(base, ("nmap", "-sn", "-n", "-PS80,443", "-v", "--host-timeout", "2s",
                                             "--max-parallelism", str(concurrency), "--max-rate",
                                             str(concurrency * 8), "-oX", "-"))
                calls.append(argv[-1])
                return fixture.runner.CommandResult("success", chunk_xml(argv[-1], excluded=fixture.exclusions(argv)))
            with patch.object(fixture.discovery, "run", transport):
                result = fixture.discovery.collect(policy, {"network": "lab", "mode": "ping"})
            self.assertEqual(calls, [str(net) for net in ip_network("192.0.2.0/24").subnets(new_prefix=28)])
            self.assertEqual(result["completion"], "partial")

    def test_failed_chunk_output_parser_and_persistence_do_not_damage_history(self):
        for bad in (fixture.runner.CommandResult("output_limit", diagnostic_code="combined_output_exceeded"),
                    fixture.runner.CommandResult("success", b'<nmaprun>'),
                    fixture.runner.CommandResult("success", chunk_xml("198.51.100.0/28", ("198.51.100.1",)))):
            calls = []
            def transport(argv, *args, calls=calls, bad=bad, **kwargs):
                calls.append(argv[-1])
                return bad if len(calls) == 2 else fixture.runner.CommandResult(
                    "success", chunk_xml(argv[-1], excluded=fixture.exclusions(argv)))
            with patch.object(fixture.discovery, "run", transport):
                receipt = fixture.discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
            self.assertEqual(receipt["completion"], "partial")
            self.assertEqual(sum(p["outcome"] != "success" for p in receipt["probes"][:-1]), 18)
            self.assertFalse(fixture.reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})["missing"])
        before = self.counts()
        with (patch.object(fixture.discovery, "run", side_effect=lambda argv, *a, **k:
                           fixture.runner.CommandResult("success", chunk_xml(
                               argv[-1], excluded=fixture.exclusions(argv)))),
              patch.object(fixture.storage.Store, "audit",
                           side_effect=sqlite3.OperationalError("synthetic persistence failure")),
              self.assertRaises(sqlite3.OperationalError)):
            fixture.discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(self.counts(), before)


class ChunkParserTests(unittest.TestCase):
    def setUp(self):
        self.temp = fixture.scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.policy = fixture.config.validate_policy({}, Path(self.temp.name))
        self.at = fixture.storage.timestamp(fixture.NOW)

    def test_summary_cannot_replace_down_reasons_or_explicit_host_accounting(self):
        good = chunk_xml("192.0.2.10/32")
        for reason, code in ((b"net-unreach", "nmap_route_unavailable"),
                             (b"no-route", "nmap_route_unavailable"),
                             (b"reject-route", "nmap_route_unavailable"),
                             (b"host-unreach", "nmap_discovery_unavailable"),
                             (b"perm-denied", "nmap_discovery_unavailable"),
                             (b"unknown", "nmap_discovery_unavailable")):
            with self.subTest(reason=reason), self.assertRaises(fixture.parse.NmapCoverageError) as error:
                fixture.parse.nmap(good.replace(b"no-response", reason), "192.0.2.10/32", self.at, self.policy)
            self.assertEqual(error.exception.diagnostic_code, code)
        omitted = good[:good.index(b"<host>")] + good[good.index(b"</host>") + len(b"</host>"):]
        with self.assertRaisesRegex(fixture.parse.NmapCoverageError, "nmap_incomplete_coverage"):
            fixture.parse.nmap(omitted, "192.0.2.10/32", self.at, self.policy)
        with self.assertRaises(fixture.parse.NmapCoverageError):
            fixture.parse.nmap(good.replace(b' reason="no-response"', b''),
                               "192.0.2.10/32", self.at, self.policy)

    def test_multi_host_accounting_down_records_and_boundaries(self):
        data = chunk_xml("192.0.2.0/28", ("192.0.2.0", "192.0.2.15"), down_records=("192.0.2.7",))
        observations = fixture.parse.nmap(data, "192.0.2.0/28", self.at, self.policy)
        self.assertEqual({dict(o.value)["address"] for o in observations}, {"192.0.2.0", "192.0.2.15"})
        self.assertEqual(fixture.parse.nmap(chunk_xml("192.0.2.0/28"), "192.0.2.0/28", self.at, self.policy), ())

    def test_hostile_duplicate_out_of_chunk_stats_and_output_bounds(self):
        good = chunk_xml("192.0.2.0/28", ("192.0.2.1", "192.0.2.15"))
        bad = [good.replace(b'192.0.2.15', b'192.0.2.1'), good.replace(b'192.0.2.15', b'192.0.2.16'),
               good.replace(b'total="16"', b'total="15"'), good.replace(b'up="2" down="14"', b'up="1" down="15"'),
               good.replace(b'up="2" down="14"', b'up="2" down="-1"'),
               good.replace(b'<host>', b'<host timedout="true">'),
               good.replace(b'state="up"', b'state="unknown"'),
               good.replace(b'<host>', b'<host><address addr="2001:db8::1" addrtype="ipv6"/>'),
               good.replace(b'<!DOCTYPE nmaprun>', b'<!DOCTYPE nmaprun SYSTEM "file:///never-read">'),
               good.replace(b'<!DOCTYPE nmaprun>', b'<!DOCTYPE nmaprun [<!ENTITY x "boom">]>'),
               good.decode().encode('utf-16'), b'<nmaprun><',
               good.replace(b'</nmaprun>', b'<runstats/></nmaprun>'),
               good.replace(b'<address addr="192.0.2.1" addrtype="ipv4"/>',
                            b'<address addr="192.0.2.1" addrtype="ipv4"/>' * 2)]
        for data in bad:
            with (self.subTest(data=data[:100]),
                  self.assertRaises((ValueError, fixture.parse.ElementTree.ParseError, UnicodeError))):
                fixture.parse.nmap(data, "192.0.2.0/28", self.at, self.policy)
        tiny = replace(self.policy, limits=replace(self.policy.limits, observations=1))
        with self.assertRaises(ValueError):
            fixture.parse.nmap(good, "192.0.2.0/28", self.at, tiny)
        element_flood = good.replace(b'</nmaprun>', b'<x/>' * 49 + b'</nmaprun>')
        with self.assertRaises(ValueError):
            fixture.parse.nmap(element_flood, "192.0.2.0/28", self.at, tiny)
        exact = replace(self.policy, limits=replace(self.policy.limits, output_bytes=len(good)))
        self.assertEqual(len(fixture.parse.nmap(good, "192.0.2.0/28", self.at, exact)), 2)
        with self.assertRaises(ValueError):
            fixture.parse.nmap(good, "192.0.2.0/28", self.at,
                               replace(exact, limits=replace(exact.limits, output_bytes=len(good) - 1)))


if __name__ == "__main__":
    unittest.main()
