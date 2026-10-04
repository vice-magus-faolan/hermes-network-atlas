# SPDX-License-Identifier: GPL-3.0-or-later
"""Additional synthetic boundary controls for partial scope and child lifecycle."""
from dataclasses import replace
from datetime import timedelta
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_discovery as fixture


class AdditionalDiscoveryTests(fixture.AtlasFixture):
    def test_latest_eligible_skips_revoked_scope_and_batch_receipt_exact_boundary(self):
        at = fixture.storage.timestamp(fixture.NOW)
        probe = fixture.batches.Probe("ping", "success", at, at, "exact_network", "192.0.2.0/24", "ping_response")
        receipt = fixture.batches.store_batch(self.store, "ping", "lab", at, at, "complete", (probe,), receipt=True)
        size = len(fixture.storage.response_json(receipt, self.policy.limits.output_bytes).encode())
        exact = replace(self.policy, limits=replace(self.policy.limits, output_bytes=size))
        with fixture.storage.Store(exact, writable=True) as store:
            boundary = fixture.batches.store_batch(store, "ping", "lab", at, at, "complete", (probe,), receipt=True)
        self.assertEqual(len(fixture.storage.response_json(boundary, size).encode()), size)
        before = self.counts()
        small = replace(exact, limits=replace(exact.limits, output_bytes=size - 1))
        with fixture.storage.Store(small, writable=True) as store, self.assertRaises(ValueError):
            fixture.batches.store_batch(store, "ping", "lab", at, at, "complete", (probe,), receipt=True)
        self.assertEqual(self.counts(), before)
        # Apply both same-time ping batches, then create a fresh eligible ping and
        # a later passive batch. Revoking passive skips it rather than blocking
        # selection of the still-authorized older ping.
        fixture.reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]}, now=fixture.NOW)
        fixture.reconcile.reconcile(self.policy, {"batch_id": boundary["batch_id"]}, now=fixture.NOW)
        ping = fixture.batches.store_batch(self.store, "ping", "lab", at, at, "complete", (probe,))
        later = fixture.storage.timestamp(fixture.NOW + timedelta(seconds=1))
        passive = replace(probe, probe_name="ip_neigh", started_at=later, ended_at=later, coverage_kind="local_host", evidence_kind="cached_neighbor")
        fixture.batches.store_batch(self.store, "local_passive", "lab", later, later, "complete", (passive,))
        self.raw["networks"]["lab"]["discovery"]["passive"] = False
        policy = fixture.config.validate_policy(self.raw, self.home)
        result = fixture.reconcile.reconcile(policy, {}, now=fixture.NOW + timedelta(seconds=1))
        self.assertEqual(result["batch_id"], ping)

    def test_active_partial_keeps_positive_but_never_asserts_scope_absence(self):
        self.raw["networks"]["lab"]["cidr"] = "192.0.2.0/27"
        policy = fixture.config.validate_policy(self.raw, self.home)
        iface = fixture.core.add_interface(self.store, self.device, "known", fixture.MAC2, now=fixture.NOW)
        fixture.core.add_address(self.store, iface, "192.0.2.9", 32, now=fixture.NOW)
        def fake(argv, *args, **kwargs):
            if argv[-1] == "192.0.2.0/28":
                return fixture.runner.CommandResult("success", fixture.xml(argv[-1], responder="192.0.2.10"))
            return fixture.runner.CommandResult("timeout", diagnostic_code="deadline_exceeded")
        with patch.object(fixture.discovery, "run", fake):
            receipt = fixture.discovery.collect(policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(receipt["completion"], "partial")
        answer = fixture.reconcile.reconcile(policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(len(answer["new"]), 1)
        self.assertFalse(answer["missing"])
        self.assertIsNone(self.detail()["last_checked"])
        self.assertEqual(self.store.connection.execute("SELECT SUM(absence_eligible) FROM probes").fetchone()[0], 0)

    def test_whole_operation_bounds_real_owned_children_and_no_late_spawn(self):
        self.raw["networks"]["lab"]["cidr"] = "192.0.2.0/27"
        self.raw["limits"].update(operation_timeout_seconds=1, concurrent_probes=1)
        policy = fixture.config.validate_policy(self.raw, self.home)
        (self.home / "offline-fixture").touch()
        children = []
        real = subprocess.Popen
        def record(*args, **kwargs):
            child = real(*args, **kwargs)
            children.append(child)
            return child
        def sleeping(argv, limits, deadline, **kwargs):
            return fixture.runner.run((sys.executable, str(fixture.ROOT / "scripts" / "offline_probe.py"), "sleep"), limits, deadline, host=True)
        started = time.monotonic()
        with patch.dict(os.environ, {"NETWORK_ATLAS_OFFLINE_FIXTURE_DIR": str(self.home)}), patch.object(fixture.discovery, "run", sleeping), patch.object(fixture.runner.subprocess, "Popen", record):
            receipt = fixture.discovery.collect(policy, {"network": "lab", "mode": "ping"})
        self.assertLess(time.monotonic() - started, 1.4)
        self.assertEqual(receipt["completion"], "failed")
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertEqual({p["outcome"] for p in receipt["probes"][:16]}, {"timeout"})
        self.assertEqual({p["outcome"] for p in receipt["probes"][16:-1]}, {"not_started"})
        self.assertEqual(self.store.connection.execute("SELECT SUM(absence_eligible) FROM probes").fetchone()[0], 0)

    def test_aggregate_observation_overflow_disqualifies_coverage(self):
        policy = replace(self.policy, limits=replace(self.policy.limits, observations=5))
        at = fixture.storage.timestamp(fixture.NOW)
        probes = tuple(fixture.batches.Probe("ping_" + str(i), "success", at, at, "none", "", "ping_response",
                       observations=(fixture.observation(),) * 2) for i in range(4))
        coverage = fixture.batches.Probe("ping_coverage", "success", at, at, "exact_network", "192.0.2.0/24", "ping_response")
        limited = fixture.discovery._batch_bound(probes + (coverage,), policy)
        self.assertLessEqual(sum(len(probe.observations) for probe in limited), 5)
        self.assertEqual(limited[-1].outcome, "parse_failed")
        self.assertEqual(limited[-1].coverage_kind, "none")

    def test_local_same_host_multi_interface_state_and_no_existing_device_merge(self):
        at = fixture.storage.timestamp(fixture.NOW)
        observations = (fixture.observation(prefix=24), fixture.observation(mac=fixture.MAC2, address="192.0.2.20", prefix=24),
                        fixture.batches.Observation("interface", fixture.batches.Anchor("mac", fixture.MAC), "state", "UP", at))
        probe = fixture.batches.Probe("ip_addr", "success", at, at, "local_host", "192.0.2.0/24", "local_interface", observations=observations)
        batch = fixture.batches.store_batch(self.store, "local_passive", "lab", at, at, "complete", (probe,))
        result = fixture.reconcile.reconcile(self.policy, {"batch_id": batch}, now=fixture.NOW)
        self.assertEqual(len(result["new"]), 1)
        device = result["new"][0]
        detail = self.detail(device=device)
        self.assertEqual(len(detail["interfaces"]), 2)
        self.assertEqual(next(i for i in detail["interfaces"] if i["mac_address"] == fixture.MAC)["fields"]["state"]["value"], "UP")
        other = fixture.core.create_device(self.store, "other local fixture", now=fixture.NOW)["device_id"]
        third_mac = "00:11:22:33:44:77"
        fixture.core.add_interface(self.store, other, "other", third_mac, now=fixture.NOW)
        second_probe = replace(probe, observations=(fixture.observation(), fixture.observation(mac=third_mac, address="192.0.2.30")))
        second = fixture.batches.store_batch(self.store, "local_passive", "lab", at, at, "complete", (second_probe,))
        answer = fixture.reconcile.reconcile(self.policy, {"batch_id": second}, now=fixture.NOW)
        self.assertIn("local_host_multiple_devices", {entry["reason"] for entry in answer["conflicting"]})
        self.assertFalse(answer["new"])
        self.assertEqual(len(self.detail(device=device)["interfaces"]), 2)
        self.assertEqual(len(self.detail(device=other)["interfaces"]), 1)

    def test_reconcile_concurrent_writer_busy_and_failure_leaves_retryable_batch(self):
        at = fixture.storage.timestamp(fixture.NOW)
        probe = fixture.batches.Probe("ping", "success", at, at, "exact_network", "192.0.2.0/24", "ping_response", observations=(fixture.observation(),))
        batch = fixture.batches.store_batch(self.store, "ping", "lab", at, at, "complete", (probe,))
        before = self.counts()
        with self.store.transaction(), self.assertRaises(sqlite3.OperationalError):
            fixture.reconcile.reconcile(self.policy, {"batch_id": batch}, now=fixture.NOW)
        self.assertEqual(self.counts(), before)
        self.assertEqual(len(fixture.reconcile.reconcile(self.policy, {"batch_id": batch}, now=fixture.NOW)["new"]), 1)

    def test_old_batch_does_not_regress_seen_check_or_assignment_time(self):
        new_time = fixture.NOW + timedelta(days=2)
        def batch(at):
            stamp = fixture.storage.timestamp(at)
            probe = fixture.batches.Probe("ping", "success", stamp, stamp, "exact_network", "192.0.2.0/24", "ping_response", observations=(fixture.observation(at=at),))
            return fixture.batches.store_batch(self.store, "ping", "lab", stamp, stamp, "complete", (probe,))
        newer = fixture.reconcile.reconcile(self.policy, {"batch_id": batch(new_time)}, now=new_time)
        device = newer["new"][0]
        fixture.reconcile.reconcile(self.policy, {"batch_id": batch(fixture.NOW)}, now=new_time)
        detail = self.detail(device=device, now=new_time)
        self.assertEqual(detail["first_seen"], fixture.storage.timestamp(fixture.NOW))
        self.assertEqual(detail["last_seen"], fixture.storage.timestamp(new_time))
        self.assertEqual(detail["last_checked"], fixture.storage.timestamp(new_time))
        assignment = detail["interfaces"][0]["addresses"][0]
        self.assertEqual(assignment["last_seen"], fixture.storage.timestamp(new_time))
        self.assertEqual(assignment["first_seen"], fixture.storage.timestamp(fixture.NOW))


class AdditionalRunnerTests(unittest.TestCase):
    def test_successful_leader_exit_cleans_descendant_not_unrelated_process(self):
        with fixture.scratch_home() as directory:
            home = Path(directory)
            (home / "offline-fixture").touch()
            argv = (sys.executable, str(fixture.ROOT / "scripts" / "offline_probe.py"))
            with patch.dict(os.environ, {"NETWORK_ATLAS_OFFLINE_FIXTURE_DIR": str(home)}):
                unrelated = subprocess.Popen((*argv, "sleep"), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                try:
                    result = fixture.runner.run((*argv, "fork_exit"), fixture.config.Limits(), time.monotonic() + 3)
                    self.assertEqual(result.outcome, "success")
                    self.assertIsNone(unrelated.poll())
                    parent, descendant = json.loads((home / "owned-pids.json").read_text())
                    self.assertNotEqual(parent, unrelated.pid)
                    fixture.assert_stopped(self, descendant)
                finally:
                    unrelated.kill()
                    unrelated.wait()
