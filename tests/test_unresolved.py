# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded original collector evidence, synthetic shared stores, no network effects."""
from dataclasses import replace
import argparse
from contextlib import redirect_stdout
from datetime import timedelta
import importlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import time
import unittest
from unittest.mock import patch

from helpers import ROOT, load_package, scratch_home
from test_core import NOW
from test_boundaries import synthetic_policy

load_package()
sys.path.insert(0, str(ROOT / "scripts"))
from offline_guard import deny_network
deny_network()
batches = importlib.import_module("atlas_test_plugin.batches")
config = importlib.import_module("atlas_test_plugin.config")
core = importlib.import_module("atlas_test_plugin.core")
query = importlib.import_module("atlas_test_plugin.query")
reconcile = importlib.import_module("atlas_test_plugin.reconcile")
storage = importlib.import_module("atlas_test_plugin.storage")
tools = importlib.import_module("atlas_test_plugin.tools")
unresolved = importlib.import_module("atlas_test_plugin.unresolved")
inspection = importlib.import_module("atlas_test_plugin.inspection")
commands = importlib.import_module("atlas_test_plugin.commands")

MAC = "00:11:22:33:44:55"


class UnresolvedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.raw = synthetic_policy()
        self.policy = config.validate_policy(self.raw, self.home)
        self.store = storage.Store(self.policy, writable=True)
        self.addCleanup(self.store.__exit__)
        (self.home / "network-atlas" / "config.yaml").write_text(json.dumps(self.raw))

    def observation(self, address="192.0.2.10", *, anchor=None, at=NOW, state=None):
        return batches.Observation("address", anchor or batches.Anchor("unresolved", "ping_" + address.replace(".", "_")),
                                   "assignment", (("address", address), ("prefix_length", 32)), storage.timestamp(at), state)

    def batch(self, observations=(), *, at=NOW, collector="ping", partial=False, store=None):
        stamp = storage.timestamp(at)
        probe = batches.Probe("positive", "success", stamp, stamp,
                             "exact_network" if collector == "ping" else "local_host", "192.0.2.0/24",
                             "ping_response" if collector == "ping" else "cached_neighbor", observations=tuple(observations))
        probes = (probe,)
        if partial:
            probes += (batches.Probe("failed", "timeout", stamp, stamp, "none", "", "none"),)
        return batches.store_batch(store or self.store, collector, "lab", stamp, stamp,
                                   "partial" if partial else "complete", probes)

    def apply(self, batch, at=NOW, policy=None):
        return reconcile.reconcile(policy or self.policy, {"batch_id": batch}, now=at)

    def read(self, *, policy=None, now=NOW, **params):
        return query.query(policy or self.policy, {"view": "unresolved", **params}, now=now)

    def rows(self, **params):
        return self.read(**params)["evidence"]

    def snapshot(self):
        return {table: [tuple(row) for row in self.store.connection.execute("SELECT * FROM " + table)]
                for table in (*storage.IMMUTABLE_TABLES, "devices", "interfaces", "addresses", "aliases", "sqlite_master")}

    def test_zero_devices_multiple_responses_and_stored_reasons(self):
        batch = self.batch([self.observation("192.0.2." + str(n)) for n in range(10, 17)])
        before_apply = self.rows()
        self.assertEqual(len(before_apply), 7)
        self.assertEqual({row["identity_state"] for row in before_apply}, {"never_reconciled"})
        applied = self.apply(batch)
        self.assertEqual(applied["new"], [])
        self.assertEqual(len(applied["unresolved"]), 7)
        before = self.snapshot()
        result = self.read()
        self.assertFalse(result["has_more"])
        self.assertFalse(result["discovery_performed"])
        self.assertEqual(query.query(self.policy, {}, now=NOW)["devices"], [])
        self.assertEqual({r["identity_state"] for r in result["evidence"]}, {"reconciled_unresolved"})
        for row in result["evidence"]:
            self.assertEqual(row["identity_reason"], "no_unique_stable_interface")
            self.assertEqual(row["candidate_device_ids"], [])
            self.assertEqual(row["subject_anchor"]["kind"], "unresolved")
            self.assertTrue(row["historical_responder_evidence"])
            self.assertTrue(row["qualified"])
            self.assertEqual(row["freshness"], "fresh")
            self.assertEqual(row["confidence"], "observed")
            self.assertEqual(row["source"], "ping")
            self.assertEqual(row["batch"]["id"], batch)
            self.assertEqual(row["batch"]["policy_context"], str(self.home))
            self.assertTrue(row["batch"]["local_policy_context"])
            self.assertEqual(row["application"]["applied_at"], applied["applied_at"])
        self.assertEqual(self.snapshot(), before)

    def test_exact_address_batch_validation_and_empty_unknown(self):
        first = self.batch([self.observation(), self.observation("192.0.2.11")])
        second = self.batch([self.observation()])
        empty = self.batch()
        self.assertEqual(len(self.rows(address="192.0.2.10")), 2)
        self.assertEqual(len(self.rows(batch_id=first, address="192.0.2.10")), 1)
        self.assertEqual(self.rows(batch_id=second, address="192.0.2.11"), [])
        self.assertEqual(self.rows(batch_id=empty), [])
        self.assertEqual(self.rows(address="198.51.100.99"), [])
        for params in ({"batch_id": "unknown"}, {"batch_id": "../atlas"}, {"batch_id": "x' OR 1=1"},
                       {"batch_id": "a" * 65}, {"batch_id": None}, {"address": "192.0.2.0/24"},
                       {"address": "192.000.2.10"}, {"address": "fe80::1%eth0"}, {"address": "2001:DB8::1"},
                       {"limit": True}, {"limit": 101}, {"offset": -1}, {"offset": 10001},
                       {"source": "user"}, {"device_id": "x"}, {"text": "x"}, {"command": "id"}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                self.read(**params)
        for view in ("devices", "history", "status"):
            with self.subTest(view=view), self.assertRaises(ValueError):
                query.query(self.policy, {"view": view, "batch_id": first}, now=NOW)

    def test_missing_store_does_not_create_and_validates_batch(self):
        policy = config.validate_policy({}, self.home / "missing")
        answer = self.read(policy=policy, limit=2, offset=1)
        self.assertEqual(answer["evidence"], [])
        self.assertEqual((answer["limit"], answer["offset"], answer["has_more"]), (2, 1, False))
        with self.assertRaises(ValueError):
            self.read(policy=policy, batch_id="unknown")
        self.assertFalse(policy.home.exists())

    def test_tie_safe_pagination_duplicate_history_and_lowered_caps(self):
        first = self.batch([self.observation() for _ in range(5)])
        self.batch([self.observation() for _ in range(2)])
        all_rows = self.rows()
        expected = [row[0] for row in self.store.connection.execute(
            "SELECT id FROM observations WHERE entity_id IS NULL ORDER BY observed_at DESC,id")]
        self.assertEqual([row["id"] for row in all_rows], expected)
        pages = [self.read(limit=2, offset=offset) for offset in (0, 2, 4, 6, 8)]
        self.assertEqual([page["has_more"] for page in pages], [True, True, True, False, False])
        self.assertEqual([row["id"] for page in pages for row in page["evidence"]], expected)
        filtered = [self.read(batch_id=first, limit=2, offset=n) for n in (0, 2, 4)]
        self.assertEqual([p["has_more"] for p in filtered], [True, True, False])
        small = replace(self.policy, limits=replace(self.policy.limits, result_count=1, page_offset=2))
        self.assertTrue(self.read(policy=small)["has_more"])
        with self.assertRaises(ValueError):
            self.read(policy=small, limit=2)
        with self.assertRaises(ValueError):
            self.read(policy=small, offset=3)

    def test_freshness_exact_boundary_future_and_unqualified_neighbor(self):
        self.batch([self.observation()])
        self.batch([self.observation("192.0.2.11", state="REACHABLE")], collector="local_passive")
        self.assertEqual(self.rows(now=NOW + timedelta(days=14), address="192.0.2.10")[0]["freshness"], "fresh")
        stale = self.rows(now=NOW + timedelta(days=14, microseconds=1), address="192.0.2.10")[0]
        self.assertEqual(stale["freshness"], "stale")
        self.assertTrue(stale["historical_responder_evidence"])
        self.assertEqual(self.rows(now=NOW - timedelta(microseconds=1), address="192.0.2.10")[0]["freshness"], "future")
        cached = self.rows(address="192.0.2.11")[0]
        self.assertFalse(cached["qualified"])
        self.assertFalse(cached["historical_responder_evidence"])
        self.assertEqual(cached["freshness"], "unqualified")

    def test_partial_and_legacy_failed_completion_keep_probe_coverage(self):
        batch = self.batch([self.observation()], partial=True)
        row = self.rows(batch_id=batch)[0]
        self.assertEqual(row["batch"]["completion"], "partial")
        self.assertEqual(row["batch"]["probe_summary"]["outcome_counts"]["timeout"], 1)
        self.assertFalse(row["batch"]["scope_absence_eligible"])
        self.assertEqual(row["probe"]["coverage_kind"], "exact_network")
        self.assertEqual(row["probe"]["coverage_value"], "192.0.2.0/24")
        stamp = storage.timestamp(NOW)
        for completion in ("complete", "partial", "failed"):
            legacy = "legacy-" + completion
            with self.store.transaction():
                self.store.connection.execute("INSERT INTO batches SELECT ?,schema_version,collector,source,policy_context,scope_kind,scope_name,scope_value,started_at,ended_at,? FROM batches WHERE id=?", (legacy, completion, batch))
                self.store.connection.execute("INSERT INTO probes VALUES (?,?,?,?,?,?,?,?,?,?,?)", (legacy, legacy, "legacy", "unavailable", stamp, stamp, "none", "", "none", 0, "missing"))
            self.assertEqual(self.rows(batch_id=legacy), [])

    def test_later_resolution_exact_anchor_not_ip_and_original_copies_labeled(self):
        ip_only = self.batch([self.observation()])
        self.apply(ip_only)
        stable = self.batch([self.observation(anchor=batches.Anchor("mac", MAC), at=NOW + timedelta(days=1))], at=NOW + timedelta(days=1))
        applied = self.apply(stable, NOW + timedelta(days=1))
        # Same IP with a different anchor is NOT an identity resolution of the ping row.
        old = self.rows(batch_id=ip_only, now=NOW + timedelta(days=1))[0]
        self.assertEqual(old["identity_state"], "reconciled_unresolved")
        self.assertEqual(old["current_address_candidate_device_ids"], applied["new"])
        own = self.rows(batch_id=stable, now=NOW + timedelta(days=1))[0]
        self.assertEqual(own["identity_state"], "resolved_in_batch")
        self.assertEqual(own["resolved_device_ids"], applied["new"])
        later = self.batch([self.observation(anchor=batches.Anchor("mac", MAC), at=NOW + timedelta(days=2))], at=NOW + timedelta(days=2))
        self.apply(later, NOW + timedelta(days=2))
        self.assertEqual(self.rows(batch_id=stable, now=NOW + timedelta(days=2))[0]["identity_state"], "subsequently_resolved")
        self.assertEqual(len(self.rows(now=NOW + timedelta(days=2))), 3)

    def test_unreconciled_then_same_anchor_resolved_and_later_conflict(self):
        anchor = batches.Anchor("mac", MAC)
        first = self.batch([self.observation(anchor=anchor)])
        later = self.batch([self.observation(anchor=anchor, at=NOW + timedelta(days=1))], at=NOW + timedelta(days=1))
        device = self.apply(later, NOW + timedelta(days=1))["new"][0]
        old = self.rows(batch_id=first, now=NOW + timedelta(days=1))[0]
        self.assertEqual(old["identity_state"], "subsequently_resolved")
        self.assertIsNone(old["application"])
        self.assertEqual(old["lineage"]["batch_id"], later)
        other = core.create_device(self.store, "Synthetic collision", now=NOW)["device_id"]
        core.add_interface(self.store, other, "fixture", MAC, now=NOW)
        conflict = self.batch([self.observation(anchor=anchor, at=NOW + timedelta(days=2))], at=NOW + timedelta(days=2))
        self.apply(conflict, NOW + timedelta(days=2))
        old = self.rows(batch_id=first, now=NOW + timedelta(days=2))[0]
        self.assertEqual(old["identity_state"], "subsequently_conflicting")
        self.assertEqual(set(old["lineage"]["candidate_device_ids"]), {device, other})
        current = self.rows(batch_id=conflict, now=NOW + timedelta(days=2))[0]
        self.assertEqual(current["identity_state"], "reconciled_conflicting")
        self.assertEqual(set(current["candidate_device_ids"]), {device, other})

    def test_shared_foreign_knowledge_visible_without_authority_separate_store_empty(self):
        batch = self.batch([self.observation()])
        self.apply(batch)
        home = self.home / "reader"
        reader = config.validate_policy({"store": {"shared_sqlite_path": str(self.policy.database)}}, home)
        foreign = self.rows(policy=reader, batch_id=batch)[0]
        self.assertEqual(foreign["batch"]["policy_context"], str(self.home))
        self.assertFalse(foreign["batch"]["local_policy_context"])
        self.assertEqual(foreign["identity_state"], "reconciled_unresolved")
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.apply(batch, policy=reader)
        with patch.object(inspection, "run", side_effect=AssertionError("foreign inspection")), self.assertRaises(ValueError):
            inspection.collect(reader, {"target": "lab-router"})
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.rows(policy=config.validate_policy({}, home)), [])
        self.assertFalse(home.exists())

    def test_foreign_same_mac_does_not_resolve_local_lineage(self):
        anchor = batches.Anchor("mac", MAC)
        batch = self.batch([self.observation(anchor=anchor)])
        reader = config.validate_policy({**self.raw, "store": {"shared_sqlite_path": str(self.policy.database)}}, self.home / "other")
        with storage.Store(reader, writable=True) as store:
            foreign = self.batch([self.observation(anchor=anchor)], store=store)
        self.apply(foreign, policy=reader)
        self.assertEqual(self.rows(batch_id=batch)[0]["identity_state"], "never_reconciled")
        self.assertEqual(self.rows(batch_id=foreign)[0]["identity_state"], "resolved_in_batch")

    def test_public_handler_cli_read_only_output_cap_and_no_collection(self):
        self.batch([self.observation()])
        before = self.snapshot()
        handler = tools.Handlers(self.home)
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        output = io.StringIO()
        with patch.object(tools, "collect", side_effect=AssertionError("query collected")), patch.object(tools, "reconcile", side_effect=AssertionError("query reconciled")), patch.object(tools, "inspect_host", side_effect=AssertionError("query inspected")):
            self.assertEqual(len(json.loads(handler.query({"view": "unresolved"}))["evidence"]), 1)
            with redirect_stdout(output):
                self.assertEqual(commands.run_command(parser.parse_args(["query", "--query-json", '{"view":"unresolved"}']), self.home), 0)
            self.assertEqual(len(json.loads(output.getvalue())["evidence"]), 1)
        self.raw["limits"] = {"output_bytes": 128}
        (self.home / "network-atlas" / "config.yaml").write_text(json.dumps(self.raw))
        self.assertIn("error", json.loads(handler.query({"view": "unresolved"})))
        self.assertEqual(self.snapshot(), before)

    def test_operation_deadline_refuses_without_mutation(self):
        self.batch([self.observation()])
        before = self.snapshot()
        query.validate_query({"view": "unresolved"}, self.policy)
        with patch.object(storage.time, "monotonic", side_effect=[0, 1000]), self.assertRaisesRegex(ValueError, "deadline"):
            self.read()
        self.assertEqual(self.snapshot(), before)

    def test_running_sql_interrupted_and_snapshot_closed(self):
        self.batch([self.observation()])
        before = self.snapshot()
        small = replace(self.policy, limits=replace(self.policy.limits, operation_timeout_seconds=0.05))
        def expensive(store, params, now):
            store.connection.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT sum(x) FROM n").fetchone()
        started = time.monotonic()
        with patch.object(unresolved, "_page", expensive), self.assertRaisesRegex(sqlite3.OperationalError, "interrupted"):
            self.read(policy=small)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(self.snapshot(), before)

    def test_reconciled_unresolved_later_resolved_same_interface_anchor(self):
        stamp = storage.timestamp(NOW)
        anchor = batches.Anchor("mac", MAC)
        observations = tuple(batches.Observation("interface", anchor, "name", name, stamp) for name in ("fixture0", "fixture1"))
        probe = batches.Probe("interfaces", "success", stamp, stamp, "local_host", "192.0.2.0/24", "local_interface", observations=observations)
        first = batches.store_batch(self.store, "local_passive", "lab", stamp, stamp, "complete", (probe,))
        self.apply(first)
        self.assertEqual({row["identity_state"] for row in self.rows(batch_id=first)}, {"reconciled_unresolved"})
        later_stamp = storage.timestamp(NOW + timedelta(days=1))
        positive = batches.Observation("interface", anchor, "name", "fixture0", later_stamp)
        later_probe = batches.Probe("interfaces", "success", later_stamp, later_stamp, "local_host", "192.0.2.0/24", "local_interface", observations=(positive,))
        later = batches.store_batch(self.store, "local_passive", "lab", later_stamp, later_stamp, "complete", (later_probe,))
        device = self.apply(later, NOW + timedelta(days=1))["new"][0]
        old = self.rows(batch_id=first, now=NOW + timedelta(days=1))
        self.assertEqual({row["identity_state"] for row in old}, {"subsequently_resolved"})
        self.assertTrue(all(row["lineage"]["resolved_device_ids"] == [device] for row in old))
        self.assertTrue(all(row["identity_reason"] == "no_unique_stable_interface" for row in old))

    def test_address_ownership_conflict_not_identity_or_authority_transfer(self):
        first = self.batch([self.observation(anchor=batches.Anchor("mac", MAC))])
        self.apply(first)
        other = self.batch([self.observation(anchor=batches.Anchor("mac", "00:11:22:33:44:66"))])
        result = self.apply(other)
        self.assertEqual(result["conflicting"][0]["reason"], "address_ownership")
        row = self.rows(batch_id=other)[0]
        self.assertEqual(row["identity_state"], "resolved_in_batch")
        self.assertTrue(row["address_ownership_conflict"])
        self.assertEqual(len(row["current_address_candidate_device_ids"]), 2)
        self.assertEqual(row["resolved_device_ids"], result["new"])
        small = replace(self.policy, limits=replace(self.policy.limits, result_count=1))
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.rows(batch_id=other, policy=small)
        self.assertEqual(self.snapshot(), before)

    def test_full_page_ceiling_limit_plus_one(self):
        batch = self.batch([self.observation() for _ in range(101)])
        page = self.read(batch_id=batch, limit=100)
        self.assertEqual(len(page["evidence"]), 100)
        self.assertTrue(page["has_more"])
        final = self.read(batch_id=batch, limit=100, offset=100)
        self.assertEqual(len(final["evidence"]), 1)
        self.assertFalse(final["has_more"])

    def test_applied_without_identity_result_is_not_labeled_unresolved(self):
        batch = self.batch([self.observation()])
        with self.store.transaction():
            self.store.connection.execute("INSERT INTO applications VALUES (?,?,?,?,?)", ("empty-application", batch, 1, storage.timestamp(NOW), storage.encode({"unresolved": []})))
        row = self.rows(batch_id=batch)[0]
        self.assertEqual(row["identity_state"], "applied_without_identity_result")
        self.assertIsNone(row["identity_reason"])

    def test_receipt_size_and_identity_candidate_bounds_refuse_without_changes(self):
        device = core.create_device(self.store, "Synthetic router", now=NOW)["device_id"]
        other = core.create_device(self.store, "Synthetic other", now=NOW)["device_id"]
        for owner in (device, other):
            core.add_interface(self.store, owner, "fixture", MAC, now=NOW)
        batch = self.batch([self.observation(anchor=batches.Anchor("mac", MAC))])
        self.apply(batch)
        before = self.snapshot()
        small = replace(self.policy, limits=replace(self.policy.limits, result_count=1))
        with self.assertRaisesRegex(ValueError, "candidates"):
            self.rows(policy=small, batch_id=batch)
        small = replace(self.policy, limits=replace(self.policy.limits, output_bytes=128))
        with self.assertRaisesRegex(ValueError, "application"):
            self.rows(policy=small, batch_id=batch)
        self.assertEqual(self.snapshot(), before)

    def test_ssh_address_inventory_is_qualified_but_not_address_response(self):
        stamp = storage.timestamp(NOW)
        obs = self.observation(anchor=batches.Anchor("mac", MAC))
        alias = batches.Observation("device", batches.Anchor("alias", "lab-router", str(self.home)), "ssh_alias", "lab-router", stamp)
        probe = batches.Probe("synthetic", "success", stamp, stamp, "exact_target", "lab-router", "ssh_response", observations=(obs, alias))
        batch = batches.store_batch(self.store, "ssh", "lab-router", stamp, stamp, "complete", (probe,))
        rows = self.rows(batch_id=batch)
        address = next(row for row in rows if row["address"])
        device = next(row for row in rows if row["subject_kind"] == "device")
        self.assertTrue(address["qualified"])
        self.assertFalse(address["historical_responder_evidence"])
        self.assertTrue(device["historical_responder_evidence"])

    def test_legacy_completions_and_all_outcomes_visible_on_positive_row(self):
        stamp = storage.timestamp(NOW)
        for completion in ("complete", "partial", "failed"):
            batch = "legacy-positive-" + completion
            original = self.batch([self.observation()])
            with self.store.transaction():
                self.store.connection.execute("INSERT INTO batches SELECT ?,schema_version,collector,source,policy_context,scope_kind,scope_name,scope_value,started_at,ended_at,? FROM batches WHERE id=?", (batch, completion, original))
                for outcome in batches.OUTCOMES:
                    self.store.connection.execute("INSERT INTO probes VALUES (?,?,?,?,?,?,?,?,?,?,?)", (batch + "-" + outcome, batch, outcome, outcome, stamp, stamp, "none", "", "none", 0, "legacy"))
                self.store.connection.execute("INSERT INTO observations SELECT ?,?,NULL,subject_kind,subject_anchor,entity_id,field,value_json,source,confidence,observed_at,evidence_kind,explanation,neighbor_state,qualified FROM observations WHERE batch_id=?", (batch + "-observation", batch, original))
            row = self.rows(batch_id=batch)[0]
            self.assertEqual(row["batch"]["completion"], completion)
            self.assertEqual(row["batch"]["probe_summary"]["outcome_counts"], dict.fromkeys(batches.OUTCOMES, 1))
            self.assertEqual(row["batch"]["probe_summary"]["failure_count"], len(batches.OUTCOMES) - 1)
            self.assertIsNone(row["probe"])

    def test_same_timestamp_latest_application_and_reused_unresolved_label(self):
        anchor = batches.Anchor("mac", MAC)
        first = self.batch([self.observation(anchor=anchor)])
        self.apply(first)
        later = self.batch([self.observation(anchor=anchor)])
        self.apply(later)
        old = self.rows(batch_id=first)[0]
        self.assertEqual(old["identity_state"], "subsequently_resolved")
        self.assertEqual(old["lineage"]["batch_id"], later)
        label = batches.Anchor("unresolved", "reused-label")
        unknown = self.batch([self.observation(anchor=label)])
        unrelated = self.batch([self.observation("192.0.2.11", anchor=label)])
        self.apply(unrelated)
        self.assertEqual(self.rows(batch_id=unknown)[0]["identity_state"], "never_reconciled")

    def test_oversized_stored_original_and_invalid_address_refuse_read_only(self):
        first = self.batch([self.observation()])
        for name, payload in (("large", storage.encode({"address": "192.0.2.10", "data": "x" * 2048})),
                              ("wrong-type", storage.encode("not an address object"))):
            with self.store.transaction():
                self.store.connection.execute("INSERT INTO observations SELECT ?,batch_id,probe_id,subject_kind,subject_anchor,entity_id,field,?,source,confidence,observed_at,evidence_kind,explanation,neighbor_state,qualified FROM observations WHERE batch_id=? ORDER BY id LIMIT 1", (name, payload, first))
        before = self.snapshot()
        small = replace(self.policy, limits=replace(self.policy.limits, output_bytes=1024))
        with self.assertRaisesRegex(ValueError, "byte bound"):
            self.rows(policy=small, batch_id=first)
        with self.assertRaisesRegex(ValueError, "invalid stored address"):
            self.rows(batch_id=first)
        self.assertEqual(self.snapshot(), before)

    def test_malformed_stored_receipt_entries_fail_in_public_error_envelope(self):
        for entry in (None, "not an entry", {}, {"evidence_id": []},
                      {"reason": None}, {"reason": []}, {"candidate_device_ids": None},
                      {"candidate_device_ids": "not a list"}, {"candidate_device_ids": [[]]}):
            with self.subTest(entry=entry):
                batch = self.batch([self.observation()])
                evidence_id = self.rows(batch_id=batch)[0]["id"]
                if isinstance(entry, dict) and "evidence_id" not in entry and entry:
                    entry = {"evidence_id": evidence_id, "reason": "synthetic", **entry}
                with self.store.transaction():
                    self.store.connection.execute("INSERT INTO applications VALUES (?,?,?,?,?)",
                        ("receipt-" + batch, batch, 1, storage.timestamp(NOW), storage.encode({"unresolved": [entry]})))
                before = self.snapshot()
                with self.assertRaisesRegex(ValueError, "invalid stored application"):
                    self.rows(batch_id=batch)
                answer = json.loads(tools.Handlers(self.home).query({"view": "unresolved", "batch_id": batch}))
                self.assertEqual(answer, {"error": "invalid query or local policy", "applied": False})
                self.assertEqual(self.snapshot(), before)

    def test_malformed_later_receipt_refuses_original_lineage_read_only(self):
        anchor = batches.Anchor("mac", MAC)
        first = self.batch([self.observation(anchor=anchor)])
        later = self.batch([self.observation(anchor=anchor)])
        with self.store.transaction():
            self.store.connection.execute("INSERT INTO applications VALUES (?,?,?,?,?)",
                ("invalid-later", later, 1, storage.timestamp(NOW), storage.encode({"unresolved": [None]})))
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "invalid stored application"):
            self.rows(batch_id=first)
        self.assertEqual(self.snapshot(), before)

    def collect_chunks(self, *, partial, mac=""):
        from test_discovery import discovery, runner, xml
        clock, calls = [0.0], []
        def transport(argv, limits, deadline, **kwargs):
            calls.append(argv[-1])
            if partial and len(calls) == 2:
                clock[0] = deadline
                return runner.CommandResult("timeout", diagnostic_code="deadline_exceeded")
            clock[0] += 1
            return runner.CommandResult("success", xml(argv[-1], mac=mac))
        with patch.object(discovery.time, "monotonic", side_effect=lambda: clock[0]), patch.object(discovery, "utc_now", return_value=NOW), patch.object(discovery, "run", transport):
            receipt = discovery.collect(self.policy, {"network": "lab", "mode": "ping"})
        self.assertEqual(len(calls), 2 if partial else 16)
        return receipt

    def test_chunk_evidence_partial_not_started_and_complete_bounded_pages(self):
        for partial in (True, False):
            with self.subTest(partial=partial):
                receipt = self.collect_chunks(partial=partial)
                batch = receipt["batch_id"]
                page = self.read(batch_id=batch, limit=1)
                row = page["evidence"][0]
                self.assertEqual(row["identity_state"], "never_reconciled")
                self.assertEqual(page["has_more"], not partial)
                totals = row["batch"]["probe_summary"]
                self.assertEqual(totals["total_count"], 257)
                self.assertEqual(totals["address_count"], 256)
                self.assertEqual(totals["address_outcome_counts"]["success"], 16 if partial else 256)
                self.assertEqual(totals["address_outcome_counts"]["timeout"], 16 if partial else 0)
                self.assertEqual(totals["address_outcome_counts"]["not_started"], 224 if partial else 0)
                self.assertEqual(totals["failure_count"], 241 if partial else 0)
                self.assertEqual(row["batch"]["scope_absence_eligible"], not partial)
                self.assertTrue(row["historical_responder_evidence"])
                self.assertEqual(row["probe"]["outcome"], "success")
                self.assertEqual(row["probe"]["coverage_kind"], "none")
                self.assertFalse(row["probe"]["absence_eligible"])
                result = self.apply(batch)
                self.assertEqual(result["new"], [])
                self.assertFalse(result["missing"])
                before = self.snapshot()
                reader = replace(self.policy, limits=replace(self.policy.limits, result_count=1))
                row = self.rows(policy=reader, batch_id=batch)[0]
                self.assertEqual(row["batch"]["probe_summary"], totals)
                self.assertEqual(row["identity_state"], "reconciled_unresolved")
                self.assertEqual(row["identity_reason"], "no_unique_stable_interface")
                self.assertEqual(self.snapshot(), before)

    def test_partial_chunk_original_later_lineage_and_foreign_visibility(self):
        receipt = self.collect_chunks(partial=True, mac=MAC)
        batch = receipt["batch_id"]
        device = self.apply(batch)["new"][0]
        later = self.batch([self.observation(anchor=batches.Anchor("mac", MAC))])
        self.apply(later)
        row = self.rows(batch_id=batch)[0]
        self.assertEqual(row["identity_state"], "subsequently_resolved")
        self.assertEqual(row["resolved_device_ids"], [device])
        self.assertEqual(row["application"]["batch_id"], batch)
        self.assertEqual(row["lineage"]["batch_id"], later)
        self.assertEqual(row["lineage"]["resolved_device_ids"], [device])
        reader = config.validate_policy({"store": {"shared_sqlite_path": str(self.policy.database)},
                                         "limits": {"result_count": 1}}, self.home / "foreign")
        before = self.snapshot()
        foreign = self.rows(policy=reader, batch_id=batch)[0]
        self.assertEqual(foreign["lineage"], row["lineage"])
        self.assertEqual(foreign["batch"]["probe_summary"], row["batch"]["probe_summary"])
        self.assertFalse(foreign["batch"]["local_policy_context"])
        self.assertEqual(foreign["batch"]["completion"], "partial")
        self.assertFalse(foreign["batch"]["scope_absence_eligible"])
        with self.assertRaises(ValueError):
            self.apply(batch, policy=reader)
        with patch.object(inspection, "run", side_effect=AssertionError("foreign inspection")), self.assertRaises(ValueError):
            inspection.collect(reader, {"target": "lab-router"})
        self.assertEqual(self.snapshot(), before)
