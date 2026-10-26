# SPDX-License-Identifier: GPL-3.0-or-later
"""Producer-backed continuation: exact subsets, immutable history and fail-closed intent."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib
import json
from pathlib import Path
import sqlite3
import threading
import time
import unittest
from unittest.mock import patch

from helpers import load_package, scratch_home
from synthetic_sockets import SyntheticSockets

load_package()
config, endpoints, continuation, schedule, transport, capability, storage, tools, batches = (
    importlib.import_module('atlas_test_plugin.' + name) for name in
    ('config', 'endpoints', 'endpoint_continuation', 'host_schedule', 'host_transport',
     'host_discovery', 'storage', 'tools', 'batches'))


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.policy = config.validate_policy({
            'networks': {'lab': {'cidr': '192.0.2.0/27',
                                 'endpoints': {'enabled': True, 'tcp_ports': [22, 2222]}}},
            'limits': {'operation_timeout_seconds': 2, 'host_timeout_seconds': 1}}, self.home)

    def handler(self, policy=None):
        return tools.Handlers(lambda: policy or self.policy)

    def installed(self, fixture):
        stack = ExitStack()
        stack.enter_context(fixture.install(schedule, transport, capability))
        for module in (endpoints, continuation, storage, batches):
            stack.enter_context(patch.object(module, 'time', fixture.clock))
        return stack

    def invoke(self, params, *, response=None, policy=None):
        policy = policy or self.policy
        fixture = SyntheticSockets(response)
        with self.installed(fixture):
            result = json.loads(self.handler(policy).check_endpoints(params))
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        self.assertLessEqual(fixture.peak, policy.limits.concurrent_probes)
        reserve = min(policy.limits.busy_timeout_ms / 1000, policy.limits.operation_timeout_seconds / 4)
        self.assertLessEqual(fixture.clock.now - fixture.calls[0][0] if fixture.calls else 0,
                             policy.limits.operation_timeout_seconds - reserve + 1e-6)
        self.assertEqual(len(fixture.calls), len({(a, p) for _, a, p in fixture.calls}))
        return result, {(address, port) for _, address, port in fixture.calls}

    def partial(self):
        result, calls = self.invoke({'network': 'lab'}, response=lambda address, port:
                                    'closed' if address == '192.0.2.1' else 'filtered')
        self.assertTrue(result['queryable'], result)
        self.assertEqual(result['completion'], 'partial')
        self.assertGreater(result['state_counts']['no_response'], 0)
        self.assertGreater(result['state_counts']['not_started'], 0)
        return result, calls

    def rows(self, batch):
        return endpoints.query_endpoints(self.policy, {'batch_id': batch, 'limit': 100, 'offset': 0})['endpoints']

    def saved_count(self, batch):
        # A response page is capped; total_count verifies the complete child.
        return endpoints.query_endpoints(self.policy, {'batch_id': batch, 'limit': 1, 'offset': 0})['total_count']

    def history(self, batch=None):
        with storage.Store(self.policy) as store:
            if batch is None:
                return tuple(store.connection.iterdump())
            return {table: [tuple(row) for row in store.connection.execute(
                f'SELECT * FROM {table} WHERE {"id" if table == "batches" else "batch_id"}=? ORDER BY rowid',
                (batch,))] for table in ('batches', 'probes', 'applications', 'audit_events', 'observations')}

    def preview(self, batch):
        return json.loads(self.handler().check_endpoints({'preview_batch_id': batch}))

    def test_timed_out_producer_preview_targeted_successor_and_immutable_history(self):
        first, prior_calls = self.partial()
        batch = first['batch_id']
        before = self.history(batch)
        saved_rows = self.rows(batch)
        history = self.history()
        database_bytes = self.policy.database.read_bytes()
        with patch.object(transport, 'begin_endpoint', side_effect=AssertionError('preview transport')):
            preview = self.preview(batch)
        self.assertEqual(self.history(), history)
        self.assertEqual(self.policy.database.read_bytes(), database_bytes)
        remaining = {(row['address'], row['port']) for row in saved_rows if row['state'] == 'not_started'}
        self.assertEqual({(row['address'], row['port']) for row in preview['remaining']}, remaining)
        self.assertEqual(preview['progress']['attempted'], len(prior_calls))
        self.assertEqual(preview['progress']['excluded'], 4)
        self.assertEqual(preview['progress']['still_unattempted'], len(remaining))
        second, calls = self.invoke({'continue_batch_id': batch})
        self.assertTrue(second['queryable'], second)
        self.assertTrue(second['collection_performed'])
        self.assertEqual(calls, remaining)
        self.assertFalse(calls & prior_calls)
        child = second['batch_id']
        self.assertEqual(second['parent_batch_id'], batch)
        child_rows = self.rows(child)
        self.assertEqual(len(child_rows), len(remaining))
        self.assertEqual({row['parent_batch_id'] for row in child_rows}, {batch})
        self.assertEqual({(row['address'], row['port']) for row in child_rows}, remaining)
        self.assertGreater(min(row['started_at'] for row in child_rows), max(row['checked_at'] for row in saved_rows))
        self.assertEqual(self.history(batch), before)
        self.assertEqual(self.rows(batch), saved_rows)
        final = self.preview(child)
        self.assertEqual(final['state'], 'exhausted')
        self.assertEqual(final['progress']['attempted'], len(prior_calls) + len(calls))
        self.assertEqual(final['progress']['total'], 64)
        self.assertEqual(final['progress']['runs'], 2)
        self.assertEqual(final['progress']['still_unattempted'], 0)
        self.assertEqual(final['progress']['responded'], first['state_counts']['closed'] + len(calls))
        ancestor = self.preview(batch)
        self.assertEqual(ancestor['state'], 'continued')
        self.assertEqual(ancestor['successor_batch_id'], child)
        self.assertEqual(ancestor['progress'], preview['progress'])
        self.assertEqual(ancestor['progress']['scope'], 'selected_batch_ancestry')
        history = self.history()
        exhausted, no_calls = self.invoke({'continue_batch_id': child})
        self.assertEqual(exhausted['state'], 'exhausted')
        repeated, repeated_calls = self.invoke({'continue_batch_id': batch})
        self.assertEqual(repeated['batch_id'], child)
        self.assertFalse(repeated['collection_performed'])
        self.assertTrue(repeated['queryable'])
        self.assertFalse(no_calls or repeated_calls)
        self.assertEqual(self.history(), history)

    def test_lower_deadline_retains_truthful_unstarted_work_and_bounded_preview(self):
        first, _ = self.partial()
        lower = replace(self.policy, limits=replace(self.policy.limits, operation_timeout_seconds=1, result_count=2))
        preview = json.loads(self.handler(lower).check_endpoints({'preview_batch_id': first['batch_id']}))
        self.assertEqual(len(preview['remaining']), 2)
        self.assertEqual(preview['omitted_remaining'], preview['progress']['still_unattempted'] - 2)
        second, calls = self.invoke({'continue_batch_id': first['batch_id']},
                                    response=lambda address, port: 'filtered', policy=lower)
        self.assertTrue(second['queryable'], second)
        self.assertGreater(second['state_counts']['not_started'], 0)
        self.assertGreater(second['state_counts']['no_response'], 0)
        self.assertLess(len(calls), preview['progress']['still_unattempted'])
        next_preview = self.preview(second['batch_id'])
        self.assertEqual(next_preview['progress']['still_unattempted'], second['state_counts']['not_started'])

    def utc_invoke(self, params, at, *, claim_at=None):
        # Replace UTC alone. Socket waits, validation, SQL and publication all
        # consume the real operation/host clocks, including the persistence reserve.
        fixture = SyntheticSockets(lambda address, port: 'closed' if address == '192.0.2.1' else 'filtered')
        started = time.monotonic()
        with patch.object(fixture, 'clock', time), fixture.install(schedule, transport, capability), \
                ExitStack() as stack:
            for module in (endpoints, continuation, schedule, storage):
                stack.enter_context(patch.object(module, 'utc_now', return_value=at))
            if claim_at is not None:
                stack.enter_context(patch.object(continuation, 'utc_now', side_effect=[claim_at, at, at]))
            result = json.loads(self.handler().check_endpoints(params))
        self.assertLess(time.monotonic() - started, self.policy.limits.operation_timeout_seconds + 0.1)
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        self.assertLessEqual(fixture.peak, self.policy.limits.concurrent_probes)
        calls = {(a, p) for _, a, p in fixture.calls}
        self.assertEqual(len(calls), len(fixture.calls))
        return result, calls

    def clock_rollback_lifecycle(self, *, before_claim):
        self.policy = replace(self.policy, limits=replace(self.policy.limits, concurrent_probes=1))
        parent_at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        child_at = parent_at - timedelta(days=1)
        claim_at = child_at if before_claim else parent_at + timedelta(days=1)
        first, prior_calls = self.utc_invoke({'network': 'lab'}, parent_at)
        self.assertTrue(first.get('queryable'), first)
        self.assertTrue(prior_calls)
        parent = first['batch_id']
        original, original_rows = self.history(parent), self.rows(parent)
        remaining = {(row['address'], row['port']) for row in original_rows if row['state'] == 'not_started'}
        self.assertTrue(remaining)
        second, calls = self.utc_invoke({'continue_batch_id': parent}, child_at, claim_at=claim_at)
        self.assertTrue(second.get('queryable'), second)
        self.assertTrue(calls)
        self.assertLessEqual(calls, remaining)
        self.assertFalse(calls & prior_calls)
        child = second['batch_id']
        child_rows = self.rows(child)
        self.assertEqual({row['parent_batch_id'] for row in child_rows}, {parent})
        self.assertEqual({row['checked_at'] for row in child_rows}, {storage.timestamp(child_at)})
        self.assertEqual(self.history(parent), original)
        self.assertEqual(self.rows(parent), original_rows)
        with storage.Store(self.policy) as store:
            claim = tuple(store.connection.execute(
                'SELECT * FROM endpoint_continuations WHERE parent_batch_id=?', (parent,)).fetchone())
        self.assertEqual(claim[3], storage.timestamp(claim_at))
        self.assertLess(storage.timestamp(child_at), storage.timestamp(parent_at if before_claim else claim_at))
        history, physical = self.history(), self.policy.database.read_bytes()
        with patch.object(transport, 'begin_endpoint', side_effect=AssertionError('cold recovery contacted')):
            # Every handler/store is fresh: no request-local reservation survives.
            preview = self.preview(child)
            ancestor = self.preview(parent)
            self.assertEqual(self.policy.database.read_bytes(), physical)
            resumed = json.loads(self.handler().command('resume-endpoints ' + child))
            repeated = json.loads(self.handler().check_endpoints({'continue_batch_id': parent}))
        self.assertEqual(ancestor['state'], 'continued')
        self.assertEqual(ancestor['successor_batch_id'], child)
        self.assertEqual(preview['progress']['runs'], 2)
        self.assertEqual(preview['progress']['attempted'], len(prior_calls | calls))
        self.assertEqual(preview['progress']['still_unattempted'], len(remaining - calls))
        self.assertTrue(resumed['queryable'] and repeated['queryable'], (resumed, repeated))
        self.assertFalse(resumed['collection_performed'] or repeated['collection_performed'])
        self.assertEqual(repeated['batch_id'], child)
        self.assertEqual(self.history(), history)
        self.assertEqual(self.rows(child), child_rows)
        third, new_calls = self.utc_invoke({'continue_batch_id': child}, child_at - timedelta(days=1))
        self.assertTrue(third.get('queryable'), third)
        self.assertTrue(new_calls)
        self.assertLessEqual(new_calls, remaining - calls)
        self.assertFalse(new_calls & (calls | prior_calls))
        self.assertEqual(self.preview(third['batch_id'])['progress']['attempted'],
                         len(prior_calls | calls | new_calls))
        self.assertEqual(self.history(parent), original)
        self.assertEqual(self.rows(child), child_rows)
        with storage.Store(self.policy) as store:
            self.assertEqual(tuple(store.connection.execute(
                'SELECT * FROM endpoint_continuations WHERE parent_batch_id=?', (parent,)).fetchone()), claim)

    def test_clock_rollback_before_claim_preserves_producer_and_cold_lineage(self):
        self.clock_rollback_lifecycle(before_claim=True)

    def test_clock_rollback_after_claim_preserves_producer_and_cold_lineage(self):
        self.clock_rollback_lifecycle(before_claim=False)

    def test_rollback_saved_child_still_requires_current_owner_and_grants(self):
        first, _ = self.partial()
        at = datetime(2026, 1, 2, tzinfo=timezone.utc)
        second, _ = self.utc_invoke({'continue_batch_id': first['batch_id']}, at)
        self.assertTrue(second.get('queryable'), second)
        network = self.policy.networks[0]
        policies = [replace(self.policy, home=self.home / 'foreign'), replace(self.policy, networks=()),
                    replace(self.policy, networks=(replace(network, endpoint_ports=()),)),
                    replace(self.policy, networks=(replace(network, cidr='192.0.2.32/27'),)),
                    replace(self.policy, networks=(replace(network, endpoint_ports=(22, 443)),))]
        before = self.history()
        with patch.object(transport, 'begin_endpoint', side_effect=AssertionError('revoked child contacted')):
            for policy in policies:
                for key in ('preview_batch_id', 'continue_batch_id', 'batch_id'):
                    result = json.loads(self.handler(policy).check_endpoints({key: second['batch_id']}))
                    self.assertIn('error', result, (policy, key, result))
        self.assertEqual(self.history(), before)

    def test_saved_links_reject_wrong_identity_scope_selection_and_invalid_times(self):
        network = self.policy.networks[0]
        self.policy = replace(self.policy, networks=(network, replace(network, name='other')))
        mutations = (
            ('batches', 'UPDATE batches SET policy_context="foreign" WHERE id=?'),
            ('batches', 'UPDATE batches SET scope_name="other" WHERE id=?'),
            ('batches', 'UPDATE batches SET scope_value="192.0.2.32/27" WHERE id=?'),
            ('endpoint_continuations', 'UPDATE endpoint_continuations SET selection_json=\'["tcp_22_15"]\' '
                                      'WHERE child_batch_id=?'),
            ('endpoint_continuations', 'UPDATE endpoint_continuations SET child_batch_id=parent_batch_id '
                                      'WHERE child_batch_id=?'),
            ('endpoint_continuations', 'UPDATE endpoint_continuations SET created_at="invalid" WHERE child_batch_id=?'),
            ('probes', 'UPDATE probes SET started_at="9999-01-01T00:00:00Z" WHERE batch_id=?'),
        )
        for table, sql in mutations:
            with self.subTest(table=table, sql=sql):
                first, _ = self.partial()
                second, _ = self.invoke({'continue_batch_id': first['batch_id']},
                                        response=lambda address, port: 'filtered')
                self.assertTrue(second['queryable'], second)
                with storage.Store(self.policy, writable=True) as store, store.transaction():
                    store.connection.execute(f'DROP TRIGGER IF EXISTS immutable_{table}_UPDATE')
                    store.connection.execute(sql, (second['batch_id'],))
                before = self.history()
                with patch.object(transport, 'begin_endpoint', side_effect=AssertionError('wrong link contacted')):
                    for batch in (first['batch_id'], second['batch_id']):
                        for key in ('preview_batch_id', 'continue_batch_id', 'batch_id'):
                            # A root-only resume need not inspect its descendants.
                            if batch == first['batch_id'] and key == 'batch_id':
                                continue
                            result = json.loads(self.handler().check_endpoints({key: batch}))
                            self.assertIn('error', result, (table, key, result))
                self.assertEqual(self.history(), before)

    def test_within_child_utc_reversal_keeps_unsaved_reservation_uncertain(self):
        first, _ = self.partial()
        before = self.history(first['batch_id'])
        at = storage.utc_now() + timedelta(days=1)
        with patch.object(continuation, 'utc_now', side_effect=[at, at, at - timedelta(days=1)]), \
                patch.object(schedule, 'utc_now', return_value=at):
            result, calls = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertTrue(calls)
        self.assertFalse(result['persisted'])
        self.assertEqual(result['stage'], 'uncertain')
        self.assertEqual(self.rows(result['batch_id']), [])
        history = self.history()
        preview = self.preview(first['batch_id'])
        self.assertEqual(preview['state'], 'uncertain')
        self.assertEqual(preview['successor_batch_id'], result['batch_id'])
        repeated, no_calls = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertFalse(no_calls)
        self.assertEqual(repeated['stage'], 'uncertain')
        self.assertEqual(self.history(), history)
        self.assertEqual(self.history(first['batch_id']), before)

    def test_long_progressing_chain_exhausts_without_repeated_contacts_or_history_changes(self):
        self.policy = config.validate_policy({
            'networks': {'lab': {'cidr': '192.0.2.0/24',
                                 'endpoints': {'enabled': True, 'tcp_ports': [22, 443, 2222, 22000]}}},
            'limits': {'operation_timeout_seconds': 10, 'host_timeout_seconds': 1,
                       'concurrent_probes': 1}}, self.home)
        limits = self.policy.limits
        def response(address, port):
            return 'closed' if port == 22 else 'filtered'
        result, attempted = self.invoke({'network': 'lab'}, response=response)
        self.assertTrue(result['queryable'], result)
        root = result['batch_id']
        original = self.history(root)
        original_rows = self.rows(root)
        claims = []
        responded = result['state_counts']['closed']
        physical_rows = result['observation_count']
        preview = self.preview(root)
        for run in range(1, 1025):
            self.assertEqual(preview['progress']['runs'], run)
            self.assertEqual(preview['progress']['total'], 1024)
            self.assertEqual(preview['progress']['attempted'], len(attempted))
            self.assertEqual(preview['progress']['responded'], responded)
            self.assertEqual(preview['progress']['excluded'], 8)
            self.assertEqual(preview['progress']['unavailable'], 0)
            self.assertEqual(preview['progress']['still_unattempted'], 1016 - len(attempted))
            if preview['state'] == 'exhausted':
                break
            remaining = preview['progress']['still_unattempted']
            result, calls = self.invoke({'continue_batch_id': result['batch_id']}, response=response)
            self.assertTrue(result['queryable'], result)
            self.assertEqual(result['observation_count'], remaining)
            self.assertGreater(len(calls), 0)
            self.assertFalse(calls & attempted)
            self.assertFalse(any(address in {'192.0.2.0', '192.0.2.255'} for address, _ in calls))
            self.assertEqual(result['state_counts']['no_response'] + result['state_counts']['closed'], len(calls))
            self.assertEqual(result['state_counts']['unavailable'], 0)
            attempted |= calls
            responded += result['state_counts']['closed']
            physical_rows += result['observation_count']
            with storage.Store(self.policy) as store:
                saved_claims = [tuple(row) for row in store.connection.execute(
                    'SELECT * FROM endpoint_continuations ORDER BY rowid')]
            self.assertEqual(saved_claims[:-1], claims)
            self.assertEqual(len(saved_claims), run)
            claims = saved_claims
            preview = self.preview(result['batch_id'])
        self.assertEqual(preview['state'], 'exhausted')
        self.assertGreater(physical_rows, config.Limits().observations)
        self.assertGreater(preview['progress']['runs'], 4)
        self.assertEqual(len(attempted), 1016)
        self.assertEqual(responded, 254)
        self.assertEqual(self.policy.limits, limits)
        self.assertEqual(self.history(root), original)
        self.assertEqual(self.rows(root), original_rows)
        before = self.history()
        exhausted, calls = self.invoke({'continue_batch_id': result['batch_id']})
        self.assertEqual(exhausted['state'], 'exhausted')
        self.assertFalse(calls)
        self.assertEqual(self.history(), before)

    def test_structural_batch_bound_refuses_before_reservation_and_bounds_ancestry_reads(self):
        first, _ = self.partial()
        second, _ = self.invoke({'continue_batch_id': first['batch_id']},
                                response=lambda address, port: 'filtered')
        self.assertTrue(second['queryable'], second)
        self.assertGreater(self.preview(second['batch_id'])['progress']['still_unattempted'], 0)
        before = self.history()
        with patch.object(continuation, 'LINEAGE_BATCH_LIMIT', 2):
            self.assertEqual(self.preview(second['batch_id'])['state'], 'ready')
            result, calls = self.invoke({'continue_batch_id': second['batch_id']})
        self.assertIn('lineage batch limit', result['error'])
        self.assertIn('retain saved IDs and history for operator review', result['error'])
        self.assertFalse(calls)
        with patch.object(continuation, 'LINEAGE_BATCH_LIMIT', 1):
            for key in ('preview_batch_id', 'continue_batch_id'):
                result, calls = self.invoke({key: second['batch_id']})
                self.assertIn('lineage batch limit', result['error'])
                self.assertFalse(calls)
        self.assertEqual(self.history(), before)

    def real_continue(self, batch, *, policy=None):
        fixture = SyntheticSockets(lambda address, port: 'filtered')
        started = time.monotonic()
        with patch.object(fixture, 'clock', time), fixture.install(schedule, transport, capability):
            result = json.loads(self.handler(policy).check_endpoints({'continue_batch_id': batch}))
        elapsed = time.monotonic() - started
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        calls = {(a, p) for _, a, p in fixture.calls}
        self.assertEqual(len(calls), len(fixture.calls))
        self.assertLess(elapsed, (policy or self.policy).limits.operation_timeout_seconds + 0.1)
        print(f'real continuation: elapsed={elapsed:.3f}s contacts={len(calls)} '
              f'stage={result.get("stage")} error={result.get("error")}')
        return result, calls

    def test_real_deadline_deep_full_grid_saves_after_contacts(self):
        # Setup uses virtual sockets; the timed action charges real validation,
        # SQL and transport to the SAME unpatched operation clock.
        self.policy = config.validate_policy({
            'networks': {'lab': {'cidr': '192.0.2.0/24',
                                 'endpoints': {'enabled': True, 'tcp_ports': [22, 443, 2222, 22000]}}},
            'limits': {'operation_timeout_seconds': 5, 'host_timeout_seconds': 10,
                       'concurrent_probes': 1}}, self.home)
        result, attempted = self.invoke({'network': 'lab'}, response=lambda address, port: 'filtered')
        root = result['batch_id']
        original = self.history(root)
        for _ in range(17):
            result, calls = self.invoke({'continue_batch_id': result['batch_id']},
                                        response=lambda address, port: 'filtered')
            self.assertTrue(result['queryable'], result)
            self.assertFalse(calls & attempted)
            attempted |= calls
        result, calls = self.real_continue(result['batch_id'])
        self.assertTrue(calls, result)
        self.assertTrue(result.get('queryable'), result)
        self.assertFalse(calls & attempted)
        attempted |= calls
        self.assertEqual(self.history(root), original)
        self.assertEqual(self.saved_count(result['batch_id']), result['observation_count'])
        for _ in range(16):
            result, calls = self.invoke({'continue_batch_id': result['batch_id']},
                                        response=lambda address, port: 'filtered')
            self.assertTrue(result['queryable'], result)
            self.assertFalse(calls & attempted)
            attempted |= calls
        # The same full-grid run35 may progress or refuse BEFORE a reservation,
        # depending on actual CPU/SQL cost. It must never strand contacted work.
        before = self.history()
        result, calls = self.real_continue(result['batch_id'])
        if result.get('queryable'):
            self.assertTrue(calls)
            self.assertFalse(calls & attempted)
            self.assertEqual(self.saved_count(result['batch_id']), result['observation_count'])
        else:
            self.assertIn('error', result)
            self.assertFalse(calls)
            self.assertFalse(result.get('collection_performed', False))
            self.assertEqual(self.history(), before)
        self.assertEqual(self.history(root), original)

    def test_real_deadline_large_zero_progress_history_is_saved_or_refused_before_effects(self):
        self.policy = config.validate_policy({
            'networks': {'lab': {'cidr': '192.0.2.0/24',
                                 'endpoints': {'enabled': True, 'tcp_ports': [22, 443, 2222, 22000]}}},
            'limits': {'operation_timeout_seconds': 5, 'host_timeout_seconds': 10,
                       'concurrent_probes': 1}}, self.home)
        result, attempted = self.invoke({'network': 'lab'}, response=lambda address, port: 'filtered')
        original = schedule.Scheduler.run
        def starved(scheduler):
            # Setup-only external scheduling starvation. The real producer still
            # emits and persists each genuine all-not-started child normally.
            schedule.time.sleep(max(0, scheduler.deadline - schedule.time.monotonic()))
            return original(scheduler)
        with patch.object(schedule.Scheduler, 'run', starved):
            for _ in range(39):
                result, calls = self.invoke({'continue_batch_id': result['batch_id']})
                self.assertTrue(result['queryable'], result)
                self.assertFalse(calls)
        before = self.history()
        batch = result['batch_id']
        shorter = replace(self.policy, limits=replace(self.policy.limits, operation_timeout_seconds=3))
        result, calls = self.real_continue(batch, policy=shorter)
        if result.get('queryable'):
            self.assertTrue(calls)
            self.assertFalse(calls & attempted)
            attempted |= calls
            batch = result['batch_id']
            before = self.history()
        else:
            self.assertIn('error', result)
            self.assertFalse(calls)
            self.assertFalse(result.get('collection_performed', False))
            self.assertEqual(self.history(), before)
        # Lowering SQL lock patience must not remove the
        # CPU/serialization reserve from an otherwise admitted operation.
        low_busy = replace(self.policy, limits=replace(self.policy.limits, busy_timeout_ms=1))
        result, calls = self.real_continue(batch, policy=low_busy)
        if result.get('queryable'):
            self.assertTrue(calls)
            self.assertFalse(calls & attempted)
            self.assertEqual(self.saved_count(result['batch_id']), result['observation_count'])
        else:
            self.assertIn('error', result)
            self.assertFalse(calls)
            self.assertFalse(result.get('collection_performed', False))
            self.assertEqual(self.history(), before)

    def test_intervening_commit_revalidates_ancestry_before_reservation(self):
        first, _ = self.partial()
        second, _ = self.invoke({'continue_batch_id': first['batch_id']},
                                response=lambda address, port: 'filtered')
        original = continuation._continue
        tampered = []
        def changed(reader, version, lineage, deadline):
            with storage.Store(self.policy, writable=True) as store, store.transaction():
                store.connection.execute('DROP TRIGGER immutable_probes_UPDATE')
                store.connection.execute('UPDATE probes SET probe_name="tcp_22_999" '
                                         'WHERE id=(SELECT id FROM probes WHERE batch_id=? LIMIT 1)',
                                         (first['batch_id'],))
            tampered.extend(self.history())
            return original(reader, version, lineage, deadline)
        with patch.object(continuation, '_continue', changed):
            result, calls = self.invoke({'continue_batch_id': second['batch_id']})
        self.assertIn('error', result)
        self.assertFalse(calls)
        self.assertEqual(self.history(), tuple(tampered))

    def test_request_local_reservation_is_bound_and_no_history_replayed_after_contact(self):
        first, _ = self.partial()
        original = continuation.store_batch
        def stored(store, *args, **kwargs):
            reservation = kwargs['endpoint_reservation']
            self.assertEqual(reservation.selection(store), reservation.lineage.remaining)
            with storage.Store(self.policy) as other, self.assertRaises(ValueError):
                reservation.selection(other)
            policy = store.policy
            store.policy = replace(policy, limits=replace(policy.limits, observations=1))
            try:
                with self.assertRaises(ValueError):
                    reservation.selection(store)
            finally:
                store.policy = policy
            with self.assertRaises(ValueError):
                reservation.selection(store, child=first['batch_id'])
            return original(store, *args, **kwargs)
        with patch.object(continuation, 'store_batch', stored), \
                patch.object(continuation, 'load_lineage', wraps=continuation.load_lineage) as replay:
            result, calls = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertTrue(result['queryable'], result)
        self.assertTrue(calls)
        self.assertEqual(replay.call_count, 1)
        # Cold recovery is a separate invocation and must replay complete history.
        with patch.object(continuation, 'load_lineage', wraps=continuation.load_lineage) as cold:
            result = json.loads(self.handler().check_endpoints({'batch_id': result['batch_id']}))
        self.assertTrue(result['queryable'], result)
        self.assertEqual(cold.call_count, 1)

    def test_invalid_missing_foreign_revoked_changed_intent_has_zero_effects(self):
        missing = self.handler()
        for key in ('preview_batch_id', 'continue_batch_id'):
            self.assertIn('error', json.loads(missing.check_endpoints({key: 'unknown'})))
        self.assertFalse(self.policy.database.exists())
        first, _ = self.partial()
        network = self.policy.networks[0]
        foreign = replace(self.policy, home=self.home / 'foreign')
        policies = [foreign, replace(self.policy, networks=()),
                    replace(self.policy, networks=(replace(network, endpoint_ports=()),)),
                    replace(self.policy, networks=(replace(network, cidr='192.0.2.32/27'),)),
                    replace(self.policy, networks=(replace(network, endpoint_ports=(22, 443)),)),
                    replace(self.policy, limits=replace(self.policy.limits, observations=1)),
                    replace(self.policy, limits=replace(self.policy.limits, output_bytes=1))]
        before = self.history()
        with patch.object(transport, 'begin_endpoint', side_effect=AssertionError('invalid intent contacted')):
            for policy in policies:
                for key in ('preview_batch_id', 'continue_batch_id'):
                    result = json.loads(self.handler(policy).check_endpoints({key: first['batch_id']}))
                    self.assertIn('error', result, (policy, key, result))
                    if policy.limits.observations == 1:
                        self.assertIn('limits.observations', result['error'])
                        self.assertIn('check the configured limit against the original grid', result['error'])
            for params in ({'continue_batch_id': first['batch_id'], 'network': 'lab'},
                           {'continue_batch_id': first['batch_id'], 'ports': [22]},
                           {'preview_batch_id': '../unsafe'}, {'continue_batch_id': False}):
                self.assertIn('error', json.loads(self.handler().check_endpoints(params)))
        self.assertEqual(self.history(), before)

    def test_malformed_selection_names_the_actual_public_field_without_effects(self):
        first, _ = self.partial()
        before = self.history()
        with patch.object(transport, 'begin_endpoint', side_effect=AssertionError('invalid selection contacted')):
            for key in ('preview_batch_id', 'continue_batch_id'):
                for value in ('PRIVATE/INVALID', False):
                    with self.subTest(key=key, value=value):
                        emitted = self.handler().check_endpoints({key: value})
                        result = json.loads(emitted)
                        self.assertTrue(result['error'].startswith(key + ':'), result)
                        self.assertIn('stable saved endpoint batch ID required', result['error'])
                        self.assertFalse(result['applied'] or result['persisted'])
                        self.assertNotIn('PRIVATE', emitted)
                        self.assertNotIn(str(self.home), emitted)
        self.assertEqual(self.history(), before)
        self.assertNotIn('error', self.preview(first['batch_id']))
        self.assertEqual(self.history(), before)

    def test_concurrent_valid_intents_reserve_one_successor_before_transport(self):
        first, _ = self.partial()
        entered, release = threading.Event(), threading.Event()
        original = continuation.Scheduler.run
        def paused(scheduler):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('fixture coordination timed out')
            return original(scheduler)
        fixture = SyntheticSockets()
        with self.installed(fixture), patch.object(continuation.Scheduler, 'run', paused):
            with ThreadPoolExecutor(max_workers=2) as pool:
                collecting = pool.submit(self.handler().check_endpoints, {'continue_batch_id': first['batch_id']})
                try:
                    self.assertTrue(entered.wait(5))
                    blocked = json.loads(pool.submit(self.handler().check_endpoints,
                                                     {'continue_batch_id': first['batch_id']}).result(5))
                    self.assertEqual(blocked['stage'], 'uncertain')
                    self.assertIn('may still be in progress', blocked['error'])
                    self.assertIn('preview parent again', blocked['error'])
                    self.assertFalse(blocked['collection_performed'])
                    self.assertFalse(fixture.calls)
                finally:
                    release.set()
                winner = json.loads(collecting.result(5))
        self.assertTrue(winner['queryable'], winner)
        self.assertEqual(blocked['batch_id'], winner['batch_id'])
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        with storage.Store(self.policy) as store:
            self.assertEqual(store.connection.execute('SELECT COUNT(*) FROM endpoint_continuations').fetchone()[0], 1)
        self.assertEqual(len(fixture.calls), len({(a, p) for _, a, p in fixture.calls}))

    def test_interruption_before_publication_is_cold_uncertain_and_never_recollected(self):
        first, _ = self.partial()
        fixture = SyntheticSockets()
        with self.installed(fixture), patch('synthetic_sockets.SyntheticSelector.register',
                                           side_effect=KeyboardInterrupt()), self.assertRaises(KeyboardInterrupt):
            self.handler().check_endpoints({'continue_batch_id': first['batch_id']})
        self.assertTrue(fixture.calls)
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        before = self.history()
        preview = self.preview(first['batch_id'])
        self.assertEqual(preview['state'], 'uncertain')
        self.assertIsNotNone(preview['successor_batch_id'])
        repeated, calls = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertFalse(calls)
        self.assertEqual(repeated['stage'], 'uncertain')
        self.assertEqual(repeated['batch_id'], preview['successor_batch_id'])
        self.assertEqual(self.history(), before)
        self.assertIn('error', json.loads(self.handler().check_endpoints({'batch_id': repeated['batch_id']})))

    def test_projection_failure_cold_resume_and_repeated_continue_have_zero_transport(self):
        first, _ = self.partial()
        original = storage.Store.audit
        def failed(store, operation, action, *args, **kwargs):
            if action == 'endpoints_projected':
                raise sqlite3.OperationalError('synthetic projection interruption')
            return original(store, operation, action, *args, **kwargs)
        with patch.object(storage.Store, 'audit', failed):
            second, _ = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertTrue(second['persisted'], second)
        self.assertFalse(second['projected'])
        with patch.object(transport, 'begin_endpoint', side_effect=AssertionError('recovery contact')):
            resumed = json.loads(self.handler().command('resume-endpoints ' + second['batch_id']))
            repeated = json.loads(self.handler().check_endpoints({'continue_batch_id': first['batch_id']}))
        self.assertTrue(resumed['queryable'], resumed)
        self.assertTrue(repeated['queryable'], repeated)
        self.assertFalse(resumed['collection_performed'] or repeated['collection_performed'])
        self.assertEqual(self.preview(second['batch_id'])['state'], 'exhausted')

    def test_failed_child_publication_keeps_claim_and_never_recollects(self):
        first, _ = self.partial()
        before = self.history(first['batch_id'])
        original = storage.Store.audit
        def failed(store, operation, action, *args, **kwargs):
            if action == 'batch_stored':
                raise sqlite3.OperationalError('synthetic child publication failure')
            return original(store, operation, action, *args, **kwargs)
        with patch.object(storage.Store, 'audit', failed):
            result, calls = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertTrue(calls)
        self.assertFalse(result['persisted'])
        self.assertTrue(result['collection_performed'])
        self.assertEqual(result['stage'], 'uncertain')
        self.assertEqual(self.history(first['batch_id']), before)
        self.assertEqual(self.rows(result['batch_id']), [])
        history = self.history()
        repeated, calls = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertFalse(calls)
        self.assertEqual(repeated['batch_id'], result['batch_id'])
        self.assertEqual(repeated['stage'], 'uncertain')
        self.assertEqual(self.history(), history)

    def test_malformed_saved_evidence_refuses_before_claim_or_transport(self):
        first, _ = self.partial()
        second, _ = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertTrue(second['queryable'], second)
        with storage.Store(self.policy, writable=True) as store, store.transaction():
            store.connection.execute('DROP TRIGGER immutable_probes_UPDATE')
            store.connection.execute('UPDATE probes SET probe_name="tcp_22_99" '
                                     'WHERE id=(SELECT id FROM probes WHERE batch_id=? LIMIT 1)',
                                     (first['batch_id'],))
        before = self.history()
        with patch.object(transport, 'begin_endpoint', side_effect=AssertionError('corrupt evidence contacted')):
            for batch in (first['batch_id'], second['batch_id']):
                for key in ('preview_batch_id', 'continue_batch_id'):
                    self.assertIn('error', json.loads(self.handler().check_endpoints({key: batch})))
        self.assertEqual(self.history(), before)

    def test_contradictory_projection_and_saved_selection_cannot_authorize_contact(self):
        first, _ = self.partial()
        with storage.Store(self.policy, writable=True) as store, store.transaction():
            store.connection.execute('DROP TRIGGER immutable_endpoint_observations_UPDATE')
            store.connection.execute('UPDATE endpoint_observations SET state="open",qualified=1 '
                                     'WHERE probe_id=(SELECT id FROM probes WHERE batch_id=? '
                                     'AND outcome="not_started" LIMIT 1)', (first['batch_id'],))
        before = self.history()
        result, calls = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertIn('contradictory saved projection', result['error'])
        self.assertFalse(calls)
        self.assertEqual(self.history(), before)
        other, _ = self.partial()
        with patch.object(continuation.Scheduler, 'run', side_effect=KeyboardInterrupt()), \
                self.assertRaises(KeyboardInterrupt):
            self.handler().check_endpoints({'continue_batch_id': other['batch_id']})
        with storage.Store(self.policy, writable=True) as store, store.transaction():
            store.connection.execute('DROP TRIGGER immutable_endpoint_continuations_UPDATE')
            store.connection.execute('UPDATE endpoint_continuations SET selection_json=? WHERE parent_batch_id=?',
                                     ('["tcp_22_1"]', other['batch_id']))
        before = self.history()
        result, calls = self.invoke({'continue_batch_id': other['batch_id']})
        self.assertIn('inconsistent saved reservation', result['error'])
        self.assertFalse(calls)
        self.assertEqual(self.history(), before)

    def test_schema2_read_only_preview_upgrade_rollback_and_immutable_claim(self):
        with patch.object(storage, '_migrate_continuations', return_value=None):
            first, _ = self.partial()
        before = self.history(first['batch_id'])
        with storage.Store(self.policy) as store:
            self.assertEqual(store.schema_version, 2)
        physical = self.policy.database.read_bytes()
        self.assertEqual(self.preview(first['batch_id'])['state'], 'ready')
        self.assertEqual(self.policy.database.read_bytes(), physical)
        original = storage._migrate_continuations
        def interrupted(connection):
            original(connection)
            raise sqlite3.OperationalError('synthetic schema3 interruption')
        with patch.object(storage, '_migrate_continuations', interrupted):
            result, calls = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertIn('error', result)
        self.assertFalse(calls)
        with storage.Store(self.policy) as store:
            self.assertEqual(store.schema_version, 2)
            self.assertIsNone(store.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='endpoint_continuations'").fetchone())
        result, _ = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertTrue(result['queryable'], result)
        self.assertEqual(self.history(first['batch_id']), before)
        with storage.Store(self.policy, writable=True) as store:
            self.assertEqual(store.schema_version, 3)
            for sql in ('UPDATE endpoint_continuations SET rowid=rowid', 'DELETE FROM endpoint_continuations'):
                with store.transaction(), self.assertRaises(sqlite3.IntegrityError):
                    store.connection.execute(sql)
