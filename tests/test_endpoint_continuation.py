# SPDX-License-Identifier: GPL-3.0-or-later
"""Producer-backed continuation: exact subsets, immutable history and fail-closed intent."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace
import importlib
import json
from pathlib import Path
import sqlite3
import threading
import unittest
from unittest.mock import patch

from helpers import load_package, scratch_home
from synthetic_sockets import SyntheticSockets

load_package()
config, endpoints, continuation, schedule, transport, capability, storage, tools = (
    importlib.import_module('atlas_test_plugin.' + name) for name in
    ('config', 'endpoints', 'endpoint_continuation', 'host_schedule', 'host_transport',
     'host_discovery', 'storage', 'tools'))


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
        for module in (endpoints, continuation, storage):
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
