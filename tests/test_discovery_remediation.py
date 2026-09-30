# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline regressions for Phase 2 review: local collisions and atomic budgets."""
from dataclasses import replace
from datetime import timedelta
import json
import sqlite3
import time
from unittest.mock import patch

import test_discovery as fixture


def local_row(name, address, mac=fixture.MAC, state="UP"):
    return {"ifname": name, "address": mac, "operstate": state,
            "addr_info": [{"local": address, "prefixlen": 24}]}


class LocalCollisionTests(fixture.AtlasFixture):
    def collect_rows(self, rows):
        def transport(argv, *args, **kwargs):
            payload = rows if argv[-1] == "addr" else []
            return fixture.runner.CommandResult("success", json.dumps(payload).encode())
        with patch.object(fixture.discovery, "run", transport):
            return fixture.discovery.collect(self.policy, {"network": "lab", "mode": "passive"})["batch_id"]

    def assert_replay(self, batch, result):
        before = self.counts()
        self.assertEqual(fixture.reconcile.reconcile(self.policy, {"batch_id": batch}), result)
        self.assertEqual(self.counts(), before)

    def test_duplicate_mac_local_rows_both_orders_are_unresolved(self):
        rows = [local_row("eth_fixture", "192.0.2.10"),
                local_row("bridge_fixture", "192.0.2.20", state="DOWN")]
        for ordered in (rows, rows[::-1]):
            with self.subTest(names=[row["ifname"] for row in ordered]):
                batch = self.collect_rows(ordered)
                answer = fixture.reconcile.reconcile(self.policy, {"batch_id": batch})
                self.assertFalse(answer["new"])
                self.assertEqual(len(answer["unresolved"]), 6)
                self.assertIn("duplicate_local_interface_mac", {entry["reason"] for entry in answer["conflicting"]})
                self.assertEqual(self.counts()["interfaces"], 0)
                # Preserve every parsed value as immutable, unassigned evidence.
                evidence = self.store.connection.execute("SELECT * FROM observations WHERE batch_id=?", (batch,)).fetchall()
                self.assertEqual(len(evidence), 6)
                self.assertTrue(all(row["entity_id"] is None for row in evidence))
                self.assert_replay(batch, answer)

    def test_duplicate_mac_does_not_overwrite_existing_interface_or_clocks(self):
        interface = fixture.core.add_interface(self.store, self.device, "original", fixture.MAC, now=fixture.NOW)
        fixture.core.add_address(self.store, interface, "192.0.2.1", 24, now=fixture.NOW)
        before = self.detail()
        batch = self.collect_rows([local_row("eth_fixture", "192.0.2.10"),
                                   local_row("bridge_fixture", "192.0.2.20", state="DOWN")])
        answer = fixture.reconcile.reconcile(self.policy, {"batch_id": batch})
        self.assertTrue(answer["unresolved"])
        self.assertTrue(all(self.device in item["candidate_device_ids"] for item in answer["unresolved"]))
        self.assertEqual(self.detail(), before)
        self.assert_replay(batch, answer)

    def test_single_interface_multi_address_and_distinct_mac_same_host_controls(self):
        first = local_row("eth_fixture", "192.0.2.10")
        first["addr_info"].append({"local": "192.0.2.11", "prefixlen": 24})
        batch = self.collect_rows([first, local_row("other_fixture", "192.0.2.20", fixture.MAC2)])
        answer = fixture.reconcile.reconcile(self.policy, {"batch_id": batch})
        self.assertEqual(len(answer["new"]), 1)
        self.assertFalse(answer["unresolved"])
        self.assertFalse(answer["conflicting"])
        interfaces = self.detail(device=answer["new"][0], now=fixture.storage.utc_now())["interfaces"]
        self.assertEqual(len(interfaces), 2)
        first_interface = next(row for row in interfaces if row["mac_address"] == fixture.MAC)
        self.assertEqual(first_interface["fields"]["name"]["value"], "eth_fixture")
        self.assertEqual({row["address"] for row in first_interface["addresses"]}, {"192.0.2.10", "192.0.2.11"})
        self.assert_replay(batch, answer)

    def test_duplicate_local_names_fail_probe_instead_of_hiding_rows(self):
        batch = self.collect_rows([local_row("eth_fixture", "192.0.2.10"),
                                   local_row("eth_fixture", "192.0.2.20")])
        outcome = self.store.connection.execute("SELECT outcome FROM probes WHERE batch_id=? AND probe_name='ip_addr'", (batch,)).fetchone()[0]
        self.assertEqual(outcome, "parse_failed")

    def test_collision_outside_scope_still_blocks_mac_without_importing_ip(self):
        batch = self.collect_rows([local_row("eth_fixture", "192.0.2.10"),
                                   local_row("bridge_fixture", "198.51.100.20")])
        answer = fixture.reconcile.reconcile(self.policy, {"batch_id": batch})
        self.assertFalse(answer["new"])
        self.assertTrue(answer["unresolved"])
        self.assertTrue(answer["conflicting"])
        values = [row[0] for row in self.store.connection.execute("SELECT value_json FROM observations WHERE batch_id=?", (batch,))]
        self.assertFalse(any("198.51.100.20" in value for value in values))


class ReconcileBudgetTests(fixture.AtlasFixture):
    def batch(self, count=20):
        at = fixture.storage.timestamp(fixture.NOW)
        interface = fixture.core.add_interface(self.store, self.device, "original", fixture.MAC, now=fixture.NOW)
        observations = (fixture.batches.Observation("interface", fixture.batches.Anchor("mac", fixture.MAC), "state", "UP", at),) * count
        probe = fixture.batches.Probe("ip_addr", "success", at, at, "local_host", "192.0.2.0/24", "local_interface", observations=observations)
        batch = fixture.batches.store_batch(self.store, "local_passive", "lab", at, at, "complete", (probe,))
        return batch, interface

    def assert_retryable(self, batch, before, detail):
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.detail(), detail)
        with fixture.storage.Store(self.policy) as reader:
            self.assertEqual(reader.connection.execute("SELECT COUNT(*) FROM applications WHERE batch_id=?", (batch,)).fetchone()[0], 0)
            self.assertEqual(reader.connection.execute("SELECT COUNT(*) FROM observations WHERE batch_id=? AND entity_id IS NOT NULL", (batch,)).fetchone()[0], 0)
            self.assertEqual(reader.require("batches", batch)["completion"], "complete")
        answer = fixture.reconcile.reconcile(self.policy, {"batch_id": batch}, now=fixture.NOW)
        self.assertTrue(answer["applied"])
        after = self.counts()
        self.assertEqual(fixture.reconcile.reconcile(self.policy, {"batch_id": batch}, now=fixture.NOW), answer)
        self.assertEqual(self.counts(), after)

    def test_lowered_deadline_rolls_back_after_actual_canonical_writes_reopen_retry(self):
        batch, _ = self.batch()
        before, detail = self.counts(), self.detail()
        policy = replace(self.policy, limits=replace(self.policy.limits, operation_timeout_seconds=1))
        elapsed = [10.0]
        original = fixture.reconcile._apply_observation
        applied = []
        def consume(app, row):
            original(app, row)
            applied.append(row["id"])
            # Advance the monotonic budget only after real canonical writes.
            if len(applied) == 2:
                elapsed[0] += 2.0
        with patch.object(time, "monotonic", lambda: elapsed[0]), patch.object(fixture.reconcile, "_apply_observation", consume):
            with self.assertRaisesRegex((ValueError, sqlite3.OperationalError), "deadline|interrupted"):
                fixture.reconcile.reconcile(policy, {"batch_id": batch}, now=fixture.NOW)
        self.assertEqual(len(applied), 2)
        self.assert_retryable(batch, before, detail)

    def test_expiry_before_commit_rolls_back_application_result_and_events(self):
        batch, _ = self.batch(1)
        before, detail = self.counts(), self.detail()
        elapsed = [10.0]
        original = fixture.reconcile._apply
        def consume(*args):
            result = original(*args)
            elapsed[0] += 121.0
            return result
        with patch.object(time, "monotonic", lambda: elapsed[0]), patch.object(fixture.reconcile, "_apply", consume):
            with self.assertRaisesRegex((ValueError, sqlite3.OperationalError), "deadline|interrupted"):
                fixture.reconcile.reconcile(self.policy, {"batch_id": batch}, now=fixture.NOW)
        self.assert_retryable(batch, before, detail)

    def test_busy_wait_uses_remaining_shared_budget_during_initialization(self):
        batch, _ = self.batch(1)
        before, detail = self.counts(), self.detail()
        policy = replace(self.policy, limits=replace(self.policy.limits, operation_timeout_seconds=1, busy_timeout_ms=5000))
        # Leave only a small remaining budget; do not rely on a tight real-time
        # assertion. The real SQLite lock wait must use that remaining allowance.
        original = fixture.storage._initialize
        configured = []
        def inspect(connection):
            configured.append(connection.execute("PRAGMA busy_timeout").fetchone()[0])
            return original(connection)
        with self.store.transaction(), patch.object(fixture.storage, "_initialize", inspect):
            started = time.monotonic()
            with self.assertRaises((ValueError, sqlite3.OperationalError)):
                fixture.reconcile.reconcile(policy, {"batch_id": batch}, now=fixture.NOW)
            self.assertLess(time.monotonic() - started, 3.0)
        self.assertTrue(configured)
        self.assertLessEqual(configured[0], 1000)
        self.assert_retryable(batch, before, detail)

    def test_ordinary_success_historical_selection_is_entity_and_field_targeted(self):
        batch, interface = self.batch(2)
        selections = []
        original = fixture.reconcile.selected_facts
        def record(connection, *args, **kwargs):
            statements = []
            connection.set_trace_callback(statements.append)
            try:
                return original(connection, *args, **kwargs)
            finally:
                connection.set_trace_callback(None)
                selections.extend(statement for statement in statements if statement.startswith("WITH latest"))
        with patch.object(fixture.reconcile, "selected_facts", record):
            result = fixture.reconcile.reconcile(self.policy, {"batch_id": batch}, now=fixture.NOW)
        self.assertTrue(result["applied"])
        self.assertEqual(self.detail()["interfaces"][0]["fields"]["state"]["value"], "UP")
        self.assertTrue(selections)
        for statement in selections:
            historical = statement.split("), ranked")[0]
            self.assertIn("entity_id='" + interface + "'", historical)
            self.assertIn("field='state'", historical)

    def test_large_same_field_batch_selects_twice_not_per_observation(self):
        batch, _ = self.batch(2000)
        with patch.object(fixture.reconcile, "selected_facts", wraps=fixture.reconcile.selected_facts) as select:
            result = fixture.reconcile.reconcile(self.policy, {"batch_id": batch}, now=fixture.NOW)
        self.assertTrue(result["applied"])
        self.assertEqual(select.call_count, 2)
        copies = self.store.connection.execute("SELECT COUNT(*) FROM observations WHERE batch_id=? AND entity_id IS NOT NULL", (batch,)).fetchone()[0]
        self.assertEqual(copies, 2000)
        self.assertEqual(self.detail()["interfaces"][0]["fields"]["state"]["value"], "UP")

    def test_final_field_event_references_winner_not_last_out_of_order_copy(self):
        fixture.core.add_interface(self.store, self.device, "original", fixture.MAC, now=fixture.NOW)
        at, older = fixture.storage.timestamp(fixture.NOW), fixture.storage.timestamp(fixture.NOW - timedelta(seconds=1))
        observations = tuple(fixture.batches.Observation("interface", fixture.batches.Anchor("mac", fixture.MAC), "state", state, stamp)
                             for state, stamp in (("UP", at), ("DOWN", older)))
        probe = fixture.batches.Probe("ip_addr", "success", older, at, "local_host", "192.0.2.0/24", "local_interface", observations=observations)
        batch = fixture.batches.store_batch(self.store, "local_passive", "lab", older, at, "complete", (probe,))
        answer = fixture.reconcile.reconcile(self.policy, {"batch_id": batch}, now=fixture.NOW)
        self.assertIn(self.device, answer["changed"])
        self.assertEqual(self.detail()["interfaces"][0]["fields"]["state"]["value"], "UP")
        events = self.store.connection.execute("SELECT details_json FROM audit_events WHERE batch_id=? AND action='field_observed'", (batch,)).fetchall()
        self.assertEqual(len(events), 1)
        selected = json.loads(events[0][0])["selected_evidence_ids"]
        self.assertEqual(len(selected), 1)
        winner = self.store.connection.execute("SELECT * FROM observations WHERE id=?", (selected[0],)).fetchone()
        self.assertEqual(json.loads(winner["value_json"]), "UP")
        self.assertEqual(winner["observed_at"], at)
        copies = self.store.connection.execute("SELECT COUNT(*) FROM observations WHERE batch_id=? AND entity_id IS NOT NULL", (batch,)).fetchone()[0]
        self.assertEqual(copies, 2)

    def test_sql_progress_interrupts_running_statement_and_rolls_back(self):
        batch, _ = self.batch(1)
        before, detail = self.counts(), self.detail()
        elapsed, visits = [10.0], []
        original = fixture.reconcile._apply_observation
        def consume(app, row):
            original(app, row)
            def advance(value):
                visits.append(value)
                if value == 10:
                    elapsed[0] += 121.0
                return value
            app.store.connection.create_function("fixture_advance", 1, advance)
            app.store.connection.execute("""WITH RECURSIVE numbers(n) AS
              (VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n<100000)
              SELECT SUM(fixture_advance(n)) FROM numbers""").fetchone()
        with patch.object(time, "monotonic", lambda: elapsed[0]), patch.object(fixture.reconcile, "_apply_observation", consume):
            with self.assertRaisesRegex(sqlite3.OperationalError, "interrupted"):
                fixture.reconcile.reconcile(self.policy, {"batch_id": batch}, now=fixture.NOW)
        self.assertIn(10, visits)
        self.assertLess(len(visits), 100000)
        self.assert_retryable(batch, before, detail)

    def test_initialization_time_is_not_rebased_for_later_write_lock(self):
        batch, _ = self.batch(1)
        before, detail = self.counts(), self.detail()
        policy = replace(self.policy, limits=replace(self.policy.limits, operation_timeout_seconds=1, busy_timeout_ms=5000))
        elapsed, allowances, deadlines = [10.0], [], []
        original = fixture.storage._initialize
        def consume(connection):
            original(connection)
            deadlines.append(connection.deadline)
            elapsed[0] += 0.75
            allowances.append(connection.execute("PRAGMA busy_timeout").fetchone()[0])
            # Lock only after initialization, while the shared budget is spent.
            self.store.connection.execute("BEGIN IMMEDIATE")
        try:
            with patch.object(time, "monotonic", lambda: elapsed[0]), patch.object(fixture.storage, "_initialize", consume):
                with self.assertRaises(sqlite3.OperationalError):
                    fixture.reconcile.reconcile(policy, {"batch_id": batch}, now=fixture.NOW)
        finally:
            if self.store.connection.in_transaction:
                self.store.connection.execute("ROLLBACK")
        self.assertEqual(deadlines, [11.0])
        self.assertEqual(allowances, [250])
        self.assert_retryable(batch, before, detail)
