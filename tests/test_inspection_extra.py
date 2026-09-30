# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline inspection identity, atomicity and actual owned-child bound regressions."""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import json
import importlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
import test_inspection as fixtures
from test_inspection import (outputs, ALIAS, MAC, MAC2, inspection, core, config,
                             runner, reconcile, query, storage, tools, updates)
from test_core import AtlasFixture, NOW


class ExtraInspectionTests(AtlasFixture):
    collect = fixtures.InspectionTests.collect
    associate = fixtures.InspectionTests.associate

    def test_failed_unmapped_alias_retains_attempt_without_fabricating_device(self):
        before = self.counts()
        receipt = self.collect(payloads={})
        result = reconcile.reconcile(self.policy, {})
        self.assertEqual(result["batch_id"], receipt["batch_id"])
        self.assertFalse(result["new"])
        self.assertEqual(self.counts()["devices"], before["devices"])
        self.assertEqual(self.counts()["aliases"], 0)
        self.assertEqual(self.counts()["access_evidence"], 0)
        attempt = query.query(self.policy, {"view": "status"})["last_inspection"]
        self.assertFalse(attempt["succeeded"])
        self.assertEqual(attempt["completion"], "failed")

    def test_foreign_same_alias_cannot_anchor_local_device_and_inference_not_mapping(self):
        self.update("ssh_alias", ALIAS, operator=False)
        with patch.object(inspection, "run", side_effect=AssertionError("no inferred access")), self.assertRaises(ValueError):
            inspection.collect(self.policy, {"target": self.device})
        other = config.validate_policy(self.raw, self.home / "foreign")
        other = replace(other, database=self.policy.database)
        with storage.Store(other, writable=True) as store:
            core.apply_update(store, updates.operator_update({"device_id": self.device, "field": "ssh_alias", "value": ALIAS}, other), now=NOW)
        with patch.object(inspection, "run", side_effect=AssertionError("no foreign access")), self.assertRaises(ValueError):
            inspection.collect(self.policy, {"target": self.device})
        receipt = self.collect()
        result = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(len(result["new"]), 1)
        self.assertNotEqual(result["new"][0], self.device)
        self.assertIsNone(self.detail()["last_seen"])

    def test_two_authorized_aliases_for_device_require_explicit_alias(self):
        self.associate()
        raw = json.loads(json.dumps(self.raw))
        raw["ssh"]["hosts"]["second"] = {"alias": "second", "inspect": True}
        policy = config.validate_policy(raw, self.home)
        with storage.Store(policy, writable=True) as store:
            core.apply_update(store, updates.operator_update({"device_id": self.device, "field": "ssh_alias", "value": "second"}, policy), now=NOW)
        with patch.object(inspection, "run", side_effect=AssertionError("must select alias")), self.assertRaises(ValueError):
            inspection.collect(policy, {"target": self.device})
        self.assertEqual(self.collect(policy)["completion"], "complete")

    def test_duplicate_remote_macs_and_foreign_interface_preserved(self):
        self.associate()
        other = core.create_device(self.store, "Different fixture", now=NOW)["device_id"]
        core.add_interface(self.store, other, "original", MAC, now=NOW)
        original = query.query(self.policy, {"device_id": other}, now=NOW)["devices"][0]
        receipt = self.collect()
        result = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertTrue(result["conflicting"])
        self.assertEqual(query.query(self.policy, {"device_id": other}, now=NOW)["devices"][0], original)
        self.assertEqual({i["mac_address"] for i in self.detail(now=storage.utc_now())["interfaces"]}, {MAC2})
        payloads = outputs()
        payloads["ip -j address"] = b'[]'
        payloads["ip -j link"] = json.dumps([{"ifname": "one", "address": MAC2}, {"ifname": "two", "address": MAC2}]).encode()
        before = self.detail(now=storage.utc_now())["interfaces"]
        receipt = self.collect(payloads=payloads)
        result = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertTrue(any(row["reason"] == "duplicate_remote_interface_mac" for row in result["conflicting"]))
        self.assertEqual(self.detail(now=storage.utc_now())["interfaces"], before)

    def test_partial_malformed_oversized_and_empty_ip_success_qualifies_target_only(self):
        self.associate()
        payloads = {"hostname": b'good\n', "ip -j address": b'[{"ifname":"x","addr_info":[{"local":"bad","prefixlen":24}]}]',
                    "ip -j route": b'[{"dst":"192.0.2.0/23"}]', "ip -j neigh": b'[{"dst":"bad"}]',
                    "cat /etc/os-release": b'x' * (self.policy.limits.output_bytes + 1)}
        receipt = self.collect(payloads=payloads)
        self.assertEqual(receipt["completion"], "partial")
        self.assertIn("parse_failed", {row["outcome"] for row in receipt["probes"]})
        result = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertFalse(result["missing"])
        self.assertFalse(self.detail(now=storage.utc_now())["interfaces"])
        empty = self.collect(payloads={"ip -j address": b'[]'})
        reconcile.reconcile(self.policy, {"batch_id": empty["batch_id"]})
        self.assertIsNotNone(self.detail()["last_checked"])

    def test_collection_mapping_race_atomicity_and_reconcile_retry(self):
        self.associate()
        other = core.create_device(self.store, "Competing association", now=NOW)["device_id"]
        before = self.counts()["batches"]
        def changed(*args, **kwargs):
            self.associate(other)
            return runner.CommandResult("success", b"fixture\n")
        with patch.object(inspection, "run", changed), self.assertRaises(ValueError):
            inspection.collect(self.policy, {"target": self.device})
        self.assertEqual(self.counts()["batches"], before)
        # Use a separate fixture context with no conflicting alias for retry.
        policy = replace(self.policy, home=self.home / "fresh-context")
        receipt = self.collect(policy)
        before = self.counts()
        original = storage.Store.audit
        def refuse(store, operation, action, actor, at, **kwargs):
            if action == "inspection_outcome":
                raise RuntimeError("synthetic access audit refusal")
            return original(store, operation, action, actor, at, **kwargs)
        with patch.object(storage.Store, "audit", refuse), self.assertRaises(RuntimeError):
            reconcile.reconcile(policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(self.counts(), before)
        result = reconcile.reconcile(policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(len(result["new"]), 1)
        self.assertEqual(reconcile.reconcile(policy, {"batch_id": receipt["batch_id"]}), result)

    def test_query_map_never_collect_and_surface_unknown_flags_refused(self):
        self.associate()
        with patch.object(inspection, "run", side_effect=AssertionError("reads never inspect")):
            self.assertNotIn("error", json.loads(tools.Handlers(self.home).query({})))
            self.assertNotIn("error", json.loads(tools.Handlers(self.home).map({})))
            self.assertIn("error", json.loads(tools.Handlers(self.home).command("inspect lab-router id")))
            self.assertIn("error", json.loads(tools.Handlers(self.home).command("inspect -oX")))
        import argparse
        import importlib
        setup_parser = importlib.import_module("atlas_test_plugin.commands").setup_parser
        parser = argparse.ArgumentParser(allow_abbrev=False)
        setup_parser(parser)
        for extra in ("--command", "--username", "--port", "--probe", "--flags", "--options", "--source"):
            with self.subTest(extra=extra), self.assertRaises(SystemExit), patch("sys.stderr"):
                parser.parse_args(["inspect", "--target", ALIAS, extra, "x"])

    def test_reconcile_deadline_after_access_write_rolls_back_and_retry_is_exact(self):
        receipt = self.collect()
        before = self.counts()
        clock = 0.0
        original = reconcile._ssh_access
        def expire(app):
            nonlocal clock
            original(app)
            self.assertEqual(app.store.connection.execute("SELECT COUNT(*) FROM access_evidence").fetchone()[0], 1)
            clock = 1000.0
        with patch.object(reconcile.time, "monotonic", lambda: clock), patch.object(reconcile, "_ssh_access", expire), self.assertRaises(ValueError):
            reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.store.connection.execute("SELECT COUNT(*) FROM applications").fetchone()[0], 0)
        with storage.Store(self.policy) as reopened:
            self.assertEqual(reopened.connection.execute("SELECT COUNT(*) FROM access_evidence").fetchone()[0], 0)
        result = reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]})
        before = self.counts()
        self.assertEqual(reconcile.reconcile(self.policy, {"batch_id": receipt["batch_id"]}), result)
        self.assertEqual(self.counts(), before)

    def test_current_policy_latest_selection_skips_revoked_alias(self):
        receipt = self.collect()
        policy = replace(self.policy, ssh_enabled=False)
        with self.assertRaises(ValueError):
            reconcile.reconcile(policy, {})
        result = reconcile.reconcile(self.policy, {})
        self.assertEqual(result["batch_id"], receipt["batch_id"])
        mapped = query.query(self.policy, {"access_method": "ssh"})["devices"]
        self.assertEqual(len(mapped), 1)
        self.assertFalse(query.query(policy, {"access_method": "ssh"})["devices"])
        self.assertFalse(query.query(policy, {"device_id": mapped[0]["id"]})["devices"][0]["access"][0]["authorized_for_atlas_ssh_inspection"])

    def test_later_legacy_access_record_is_not_hidden_by_older_attempt(self):
        self.associate()
        self.collect(payloads={})
        batches = importlib.import_module("atlas_test_plugin.batches")
        recorded = batches.record_access(self.store, self.device, ALIAS, True, "fixture", now=storage.utc_now() + timedelta(seconds=1))
        detail = self.detail(now=storage.utc_now())
        self.assertEqual(detail["access"][0]["last_inspection"]["id"], recorded)
        self.assertEqual(query.query(self.policy, {"view": "status"})["last_inspection"]["id"], recorded)


class ActualInspectionBoundsTests(AtlasFixture):
    def test_host_wide_deadline_real_owned_child_only_once_and_persisted_failures(self):
        fixture = self.home / "fixture"
        fixture.mkdir()
        (fixture / "offline-fixture").touch()
        spawned = []
        original = subprocess.Popen
        def own(*args, **kwargs):
            child = original(*args, **kwargs)
            spawned.append(child)
            return child
        def fake(argv, limits, deadline, **kwargs):
            return runner.run((sys.executable, str(ROOT / "scripts/offline_probe.py"), "sleep"), limits, deadline, **kwargs)
        policy = replace(self.policy, limits=replace(self.policy.limits, host_timeout_seconds=1, operation_timeout_seconds=4))
        with patch.dict(os.environ, {"NETWORK_ATLAS_OFFLINE_FIXTURE_DIR": str(fixture)}), patch.object(inspection, "run", fake), patch.object(runner.subprocess, "Popen", own):
            receipt = inspection.collect(policy, {"target": ALIAS})
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].returncode)
        self.assertFalse(Path("/proc", str(spawned[0].pid)).exists())
        self.assertEqual(receipt["completion"], "failed")
        self.assertEqual({probe["outcome"] for probe in receipt["probes"]}, {"timeout"})
        self.assertEqual(query.query(policy, {"view": "status"})["last_inspection"]["batch_id"], receipt["batch_id"])

    def test_real_output_cap_and_missing_ssh_never_installs_or_persists_raw_stderr(self):
        fixture = self.home / "fixture"
        fixture.mkdir()
        (fixture / "offline-fixture").touch()
        def fake(argv, limits, deadline, **kwargs):
            return runner.run((sys.executable, str(ROOT / "scripts/offline_probe.py"), "flood"), limits, deadline, **kwargs)
        policy = replace(self.policy, limits=replace(self.policy.limits, output_bytes=4096))
        with patch.dict(os.environ, {"NETWORK_ATLAS_OFFLINE_FIXTURE_DIR": str(fixture)}), patch.object(inspection, "run", fake):
            receipt = inspection.collect(policy, {"target": ALIAS})
        self.assertEqual({probe["outcome"] for probe in receipt["probes"]}, {"output_limit"})
        with patch.dict(os.environ, {"PATH": str(fixture)}):
            missing = inspection.collect(self.policy, {"target": ALIAS})
        self.assertEqual({probe["diagnostic_code"] for probe in missing["probes"]}, {"executable_missing"})

    def test_whole_operation_expiry_after_transport_rolls_back_all_batch_evidence(self):
        before = self.counts()
        deadline = 100.0
        def expired(argv, *args, **kwargs):
            nonlocal deadline
            deadline = 1000.0
            return runner.CommandResult("success", b'fixture\n')
        with patch.object(inspection.time, "monotonic", lambda: deadline), patch.object(inspection, "run", expired), self.assertRaises(ValueError):
            inspection.collect(self.policy, {"target": ALIAS})
        self.assertEqual(self.counts(), before)
