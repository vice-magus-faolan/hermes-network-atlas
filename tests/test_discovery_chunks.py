# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic chunk scheduling, hostile XML and full-scope accounting; no network."""
from collections import Counter
from dataclasses import replace
from ipaddress import ip_network
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import patch

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from offline_guard import deny_network
    deny_network()

import test_discovery as fixture


def chunk_xml(scope, responders=(), *, down_records=()):
    network = ip_network(scope)
    hosts = []
    for address in (*responders, *down_records):
        state = "up" if address in responders else "down"
        hosts.append(f'<host><status state="{state}"/><address addr="{address}" addrtype="ipv4"/>'
                     '<address addr="00:11:22:33:44:55" addrtype="mac"/></host>')
    up = len(responders)
    return ('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>' + ''.join(hosts) +
            f'<runstats><finished exit="success"/><hosts up="{up}" down="{network.num_addresses - up}" '
            f'total="{network.num_addresses}"/></runstats></nmaprun>').encode()


class ChunkDiscoveryTests(fixture.AtlasFixture):
    def test_sparse_24_startup_budget_reaches_last_address_and_reconciles_exact_batch(self):
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
            responders = tuple(ip for ip in ("192.0.2.1", "192.0.2.255") if fixture.parse._ip(ip) in target)
            return fixture.runner.CommandResult("success", chunk_xml(str(target), responders))
        with patch.object(fixture.discovery.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(fixture.discovery, "run", transport):
            receipt = fixture.discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(receipt["completion"], "complete", Counter(p["outcome"] for p in receipt["probes"]))
        self.assertEqual(len(calls), 16)
        self.assertEqual({net.num_addresses for net in calls}, {16})
        self.assertEqual(len(receipt["probes"]), 257)
        self.assertEqual(sum(p["observation_count"] for p in receipt["probes"]), 2)
        answer = fixture.reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(len(answer["new"]), 1)
        detail = self.detail(device=answer["new"][0])
        self.assertEqual({a["address"] for a in detail["interfaces"][0]["addresses"]}, {"192.0.2.1", "192.0.2.255"})
        before = self.counts()
        self.assertEqual(fixture.reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]}), answer)
        self.assertEqual(self.counts(), before)
        status = fixture.query.query(self.policy, {"view": "status"})["last_discovery"]
        self.assertEqual(status["probe_summary"]["total_count"], 257)
        self.assertEqual(status["probe_summary"]["address_count"], 256)
        self.assertEqual(status["probe_summary"]["address_outcome_counts"]["success"], 256)
        self.assertTrue(status["scope_absence_eligible"])

    def test_mid_chunk_deadline_keeps_earlier_positive_and_marks_tail_not_started(self):
        clock = [0.0]
        calls = []
        def transport(argv, limits, deadline, **kwargs):
            self.assertLess(clock[0], deadline)
            calls.append(argv[-1])
            if len(calls) == 1:
                clock[0] += 1
                return fixture.runner.CommandResult("success", chunk_xml(argv[-1], ("192.0.2.1",)))
            clock[0] = deadline
            return fixture.runner.CommandResult("timeout", diagnostic_code="deadline_exceeded")
        with patch.object(fixture.discovery.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(fixture.discovery, "run", transport):
            receipt = fixture.discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(len(calls), 2)
        self.assertEqual(receipt["completion"], "partial")
        addresses = receipt["probes"][:-1]
        self.assertEqual(Counter(p["outcome"] for p in addresses), {"success": 16, "timeout": 16, "not_started": 224})
        self.assertEqual({p["diagnostic_code"] for p in addresses[16:32]}, {"deadline_exceeded"})
        self.assertEqual({p["diagnostic_code"] for p in addresses[32:]}, {"operation_deadline_exceeded"})
        self.assertEqual(sum(p["observation_count"] for p in addresses), 1)
        answer = fixture.reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(len(answer["new"]), 1)
        self.assertFalse(answer["missing"])
        status = fixture.query.query(self.policy, {"view": "status"})["last_discovery"]
        self.assertFalse(status["scope_absence_eligible"])
        self.assertEqual(status["probe_summary"]["address_count"], 256)
        self.assertEqual(status["probe_summary"]["address_outcome_counts"]["not_started"], 224)

    def test_completed_at_transport_boundary_retained_no_late_chunk(self):
        clock = [0.0]
        calls = []
        def transport(argv, limits, deadline, **kwargs):
            calls.append(argv[-1])
            clock[0] = deadline + 0.01  # completed I/O; time passed on return/parse
            return fixture.runner.CommandResult("success", chunk_xml(argv[-1], ("192.0.2.1",)))
        with patch.object(fixture.discovery.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(fixture.discovery, "run", transport):
            receipt = fixture.discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(Counter(p["outcome"] for p in receipt["probes"][:-1]), {"success": 16, "not_started": 240})
        self.assertEqual({p["diagnostic_code"] for p in receipt["probes"][:16]}, {"completed_at_boundary"})
        self.assertEqual(sum(p["observation_count"] for p in receipt["probes"]), 1)

    def test_last_completed_chunk_at_boundary_keeps_complete_coverage(self):
        raw = {**self.raw, "networks": {"lab": {"cidr": "192.0.2.0/27", "discovery": {"passive": True, "ping": True}}}}
        policy = fixture.config.validate_policy(raw, self.home)
        clock = [0.0]
        calls = []
        def transport(argv, limits, deadline, **kwargs):
            calls.append(argv[-1])
            clock[0] = deadline + 0.01 if len(calls) == 2 else 1.0
            responders = ("192.0.2.31",) if len(calls) == 2 else ()
            return fixture.runner.CommandResult("success", chunk_xml(argv[-1], responders))
        with patch.object(fixture.discovery.time, "monotonic", side_effect=lambda: clock[0]), patch.object(fixture.discovery, "run", transport):
            receipt = fixture.discovery.collect(policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(receipt["completion"], "complete")
        self.assertEqual(receipt["probes"][31]["diagnostic_code"], "completed_at_boundary")
        self.assertEqual(receipt["probes"][31]["observation_count"], 1)
        self.assertTrue(fixture.query.query(policy, {"view": "status"})["last_discovery"]["scope_absence_eligible"])

    def test_deadline_rechecked_immediately_before_owned_spawn(self):
        with patch.object(fixture.runner.time, "monotonic", side_effect=(0.0, 0.0, 2.0)), \
                patch.object(fixture.runner.subprocess, "Popen", side_effect=AssertionError("late spawn")):
            result = fixture.runner.run(("never",), self.policy.limits, 1.0)
        self.assertEqual(result.outcome, "not_started")
        self.assertEqual(result.diagnostic_code, "operation_deadline_exceeded")

    def test_fixed_argv_serial_process_internal_concurrency_rate_and_lowered_bounds(self):
        for concurrency in (1, 2, 4):
            policy = replace(self.policy, limits=replace(self.policy.limits, concurrent_probes=concurrency, host_timeout_seconds=2))
            calls = []
            def transport(argv, limits, deadline, **kwargs):
                self.assertTrue(kwargs["host"])  # whole chunk is externally host-bounded too
                self.assertEqual(argv[:-1], ("nmap", "-sn", "-n", "-PS80,443", "--host-timeout", "2s",
                                             "--max-parallelism", str(concurrency), "--max-rate", str(concurrency * 8), "-oX", "-"))
                calls.append(argv[-1])
                return fixture.runner.CommandResult("success", chunk_xml(argv[-1]))
            with patch.object(fixture.discovery, "run", transport):
                result = fixture.discovery.collect(policy, {"network": "lab", "mode": "ping"})
            self.assertEqual(calls, [str(net) for net in ip_network("192.0.2.0/24").subnets(new_prefix=28)])
            self.assertEqual(result["completion"], "complete")

    def test_failed_chunk_output_parser_and_persistence_do_not_damage_history(self):
        for bad in (fixture.runner.CommandResult("output_limit", diagnostic_code="combined_output_exceeded"),
                    fixture.runner.CommandResult("success", b'<nmaprun>'),
                    fixture.runner.CommandResult("success", chunk_xml("198.51.100.0/28", ("198.51.100.1",)))):
            calls = []
            def transport(argv, *args, **kwargs):
                calls.append(argv[-1])
                return bad if len(calls) == 2 else fixture.runner.CommandResult("success", chunk_xml(argv[-1]))
            with patch.object(fixture.discovery, "run", transport):
                receipt = fixture.discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
            self.assertEqual(receipt["completion"], "partial")
            self.assertEqual(sum(p["outcome"] != "success" for p in receipt["probes"][:-1]), 16)
            self.assertFalse(fixture.reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})["missing"])
        before = self.counts()
        with patch.object(fixture.discovery, "run", side_effect=lambda argv, *a, **k: fixture.runner.CommandResult("success", chunk_xml(argv[-1]))), \
                patch.object(fixture.storage.Store, "audit", side_effect=sqlite3.OperationalError("synthetic persistence failure")), \
                self.assertRaises(sqlite3.OperationalError):
            fixture.discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(self.counts(), before)


class ChunkParserTests(unittest.TestCase):
    def setUp(self):
        self.temp = fixture.scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.policy = fixture.config.validate_policy({}, Path(self.temp.name))
        self.at = fixture.storage.timestamp(fixture.NOW)

    def test_multi_host_accounting_down_records_and_boundaries(self):
        data = chunk_xml("192.0.2.0/28", ("192.0.2.0", "192.0.2.15"), down_records=("192.0.2.7",))
        observations = fixture.parse.nmap(data, "192.0.2.0/28", self.at, self.policy)
        self.assertEqual({dict(o.value)["address"] for o in observations}, {"192.0.2.0", "192.0.2.15"})
        self.assertEqual(fixture.parse.nmap(chunk_xml("192.0.2.0/28"), "192.0.2.0/28", self.at, self.policy), ())

    def test_hostile_duplicate_out_of_chunk_stats_and_output_bounds(self):
        good = chunk_xml("192.0.2.0/28", ("192.0.2.1", "192.0.2.15"))
        bad = [good.replace(b'192.0.2.15', b'192.0.2.1'), good.replace(b'192.0.2.15', b'192.0.2.16'),
               good.replace(b'total="16"', b'total="15"'), good.replace(b'up="2" down="14"', b'up="1" down="15"'),
               good.replace(b'up="2" down="14"', b'up="2" down="-1"'), good.replace(b'<host>', b'<host timedout="true">'),
               good.replace(b'<status state="up"/>', b'<status state="unknown"/>'),
               good.replace(b'<host>', b'<host><address addr="2001:db8::1" addrtype="ipv6"/>'),
               good.replace(b'<!DOCTYPE nmaprun>', b'<!DOCTYPE nmaprun SYSTEM "file:///never-read">'),
               good.replace(b'<!DOCTYPE nmaprun>', b'<!DOCTYPE nmaprun [<!ENTITY x "boom">]>'),
               good.decode().encode('utf-16'), b'<nmaprun><',
               good.replace(b'</nmaprun>', b'<runstats/></nmaprun>'),
               good.replace(b'<address addr="192.0.2.1" addrtype="ipv4"/>', b'<address addr="192.0.2.1" addrtype="ipv4"/>' * 2)]
        for data in bad:
            with self.subTest(data=data[:100]), self.assertRaises((ValueError, fixture.parse.ElementTree.ParseError, UnicodeError)):
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
            fixture.parse.nmap(good, "192.0.2.0/28", self.at, replace(exact, limits=replace(exact.limits, output_bytes=len(good) - 1)))


if __name__ == "__main__":
    unittest.main()
