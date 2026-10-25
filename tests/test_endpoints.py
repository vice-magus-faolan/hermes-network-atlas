# SPDX-License-Identifier: GPL-3.0-or-later
"""Endpoint authorization, outcomes, recovery, projection and additive upgrade tests."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import errno
import importlib
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

from helpers import ROOT, fixture_handlers, fixture_policy, load_package, scratch_home
from synthetic_sockets import SyntheticSockets

load_package()
config, endpoints, schedule, transport, capability, storage, query, tools, core, reconcile, batches = (
    importlib.import_module('atlas_test_plugin.' + name) for name in
    ('config', 'endpoints', 'host_schedule', 'host_transport', 'host_discovery',
     'storage', 'query', 'tools', 'core', 'reconcile', 'batches'))


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def policy(self, *, ports=None, cidr='192.0.2.8/31', limits=None):
        raw = {'networks': {'lab': {'cidr': cidr, 'endpoints': {'enabled': True, 'tcp_ports': ports or [22, 2222]}}}}
        if limits:
            raw['limits'] = limits
        path = self.home / 'network-atlas' / 'config.yaml'
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(raw))
        return fixture_policy(self.home)

    def collect(self, policy, fixture=None):
        fixture = fixture or SyntheticSockets(lambda address, port: 'positive' if port == 22 else 'closed')
        with fixture.install(schedule, transport, capability), patch.object(endpoints, 'time', fixture.clock), \
                patch('subprocess.Popen', side_effect=AssertionError('no helper')):
            result = endpoints.check(policy, {'network': 'lab'})
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        self.assertLessEqual(fixture.peak, policy.limits.concurrent_probes)
        return result

    def rows(self, policy, **filters):
        return query.query(policy, {'view': 'endpoints', **filters})

    def counts(self, policy):
        with storage.Store(policy) as store:
            return {table: store.connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in
                    ('batches', 'probes', 'applications', 'audit_events',
                     'endpoint_observations', 'devices', 'observations')}

    def test_primary_durable_open_closed_timestamp_provenance_overview_no_identity(self):
        policy = self.policy()
        result = self.collect(policy)
        self.assertTrue(
            result['persisted'] and result['applied'] and result['projected'] and result['queryable'], result)
        self.assertEqual(result['state_counts'],
                         {'open': 2, 'closed': 2, 'no_response': 0, 'unavailable': 0, 'not_started': 0})
        page = self.rows(policy)
        self.assertEqual(page['total_count'], 4)
        self.assertEqual({row['batch_id'] for row in page['endpoints']}, {result['batch_id']})
        self.assertEqual({row['policy_context'] for row in page['endpoints']}, {str(self.home)})
        self.assertEqual({row['collector'] for row in page['endpoints']}, {'tcp_endpoint'})
        for row in page['endpoints']:
            storage.parse_time(row['checked_at'])
            self.assertTrue(row['qualified'])
            self.assertIsNone(row['device_id'])
            self.assertEqual(row['scope_value'], '192.0.2.8/31')
        status = query.query(policy, {'view': 'status'})
        self.assertEqual(
            (status['known_devices'], status['endpoint_count'], status['endpoint_observation_count']), (0, 4, 4))
        self.assertNotIn('endpoint_query_available', status)
        self.assertIsNone(status['last_discovery'])
        self.assertEqual(self.counts(policy)['observations'], 0)
        with self.assertRaises(ValueError):
            reconcile.reconcile(policy, {'batch_id': result['batch_id']})
        before = self.counts(policy)
        with patch.object(transport, 'begin_endpoint', side_effect=AssertionError('resume collected')):
            resumed = endpoints.check(policy, {'batch_id': result['batch_id']})
        self.assertTrue(resumed['queryable'])
        self.assertFalse(resumed['collection_performed'])
        self.assertEqual(self.counts(policy), before)
        self.assertEqual(self.rows(policy), page)

    def test_policy_separate_opt_in_and_strict_ports_and_no_greeting_surface(self):
        legacy = config.validate_policy(
            {'networks': {'lab': {'cidr': '192.0.2.8/31', 'discovery': {'ping': True}}}}, self.home)
        self.assertEqual(legacy.networks[0].endpoint_ports, ())
        with patch.object(transport.socket, 'socket', side_effect=AssertionError('unauthorized socket')):
            with self.assertRaises(ValueError):
                endpoints.check(legacy, {'network': 'lab'})
        invalid = [{'enabled': True}, {'tcp_ports': [22]}, {'enabled': False, 'tcp_ports': [22]},
                   {'enabled': 1, 'tcp_ports': [22]}, {'enabled': True, 'tcp_ports': [4403]},
                   *({'enabled': True, 'tcp_ports': ports}
                     for ports in ([True], [0], [-1], [65536], [22, 22], [1, 2, 3, 4, 5], ['22'], [22.0])),
                   {'enabled': True, 'tcp_ports': [22], 'ssh_greeting': 'SSH-2.0-evil\n' * 4096}]
        for settings in invalid:
            with self.subTest(settings=str(settings)[:100]), self.assertRaises(config.ConfigError):
                config.validate_policy(
                    {'networks': {'lab': {'cidr': '192.0.2.8/31', 'endpoints': settings}}}, self.home)
        policy = self.policy()
        self.assertFalse(policy.networks[0].ping)
        with self.assertRaises(config.ConfigError):
            config.validate_policy({'networks': {'lab': {'cidr': '2001:db8::/64',
                                                       'endpoints': {'enabled': True, 'tcp_ports': [22]}}}}, self.home)

    def test_all_public_request_injections_refuse_before_effects(self):
        policy = self.policy()
        handler = fixture_handlers(self.home)
        with patch.object(transport.socket, 'socket', side_effect=AssertionError('unexpected socket')):
            for params in ({}, {'network': 'lab', 'batch_id': 'x'}, {'network': '192.0.2.8'},
                           {'network': '-oProxyCommand=id'},
                           {'batch_id': "x' OR 1=1--"}, {'network': 'lab; id'}, {'network': 'unknown'},
                           *({'network': 'lab', key: 'bad' * 4096} for key in (
                               'target', 'port', 'ports', 'flags', 'source', 'command', 'limits',
                               'ssh_greeting', 'banner'))):
                result = json.loads(handler.check_endpoints(params))
                self.assertIn('error', result)
                self.assertFalse(result['persisted'])
            for text in ('check-endpoints', 'check-endpoints lab extra', 'resume-endpoints',
                         'resume-endpoints x extra'):
                self.assertIn('error', json.loads(handler.command(text)))
            network = policy.networks[0]
            for target, port in [('example.invalid', 22), ('192.0.2.10', 22), ('192.0.2.8', 4403),
                                 ('192.0.2.8', 443), ('127.0.0.1', 22)]:
                with self.assertRaises(ValueError):
                    transport.begin_endpoint(network, target, port, 1e20)
            forged = replace(network, endpoint_ports=(4403,))
            with self.assertRaises(ValueError):
                transport.begin_endpoint(forged, '192.0.2.8', 4403, 1e20)
        self.assertFalse(policy.database.exists())

    def test_closed_timeout_unavailable_not_started_partial_and_aggregate_budget(self):
        policy = self.policy(cidr='192.0.2.0/24', ports=[22, 2222, 22000, 443],
                             limits={'operation_timeout_seconds': 2, 'host_timeout_seconds': 1})
        fixture = SyntheticSockets(lambda address, port: 'closed' if address == '192.0.2.1' else 'filtered')
        result = self.collect(policy, fixture)
        self.assertEqual(result['completion'], 'partial')
        counts = result['state_counts']
        self.assertGreater(counts['closed'], 0)
        self.assertGreater(counts['no_response'], 0)
        self.assertGreater(counts['unavailable'], 0)
        self.assertGreater(counts['not_started'], 0)
        self.assertEqual(sum(counts.values()), 1024)
        calls = fixture.calls
        self.assertEqual(len(calls), len({(address, port) for _, address, port in calls}))
        self.assertLessEqual(fixture.clock.now - calls[0][0], 1.5 + 1e-6)
        self.assertTrue(all(later[0] - earlier[0] >= 1 / 32 - 1e-7
                            for earlier, later in zip(calls, calls[1:], strict=False)))
        small = self.policy()
        with patch.object(transport.socket, 'socket', side_effect=PermissionError(
                errno.EACCES, 'private remote diagnostic')):
            failed = endpoints.check(small, {'network': 'lab'})
        self.assertEqual(failed['completion'], 'failed')
        self.assertEqual(failed['state_counts']['unavailable'], 4)
        self.assertNotIn('private remote diagnostic', json.dumps(failed))

    def test_completion_counts_eligible_work_without_losing_excluded_history(self):
        for cidr, total, excluded in (('192.0.2.8/30', 8, 4), ('192.0.2.8/31', 4, 0), ('192.0.2.8/32', 2, 0)):
            with self.subTest(cidr=cidr):
                policy = self.policy(cidr=cidr)
                result = self.collect(policy)
                self.assertEqual(result['completion'], 'complete')
                self.assertEqual(result['observation_count'], total)
                rows = self.rows(policy, batch_id=result['batch_id'])['endpoints']
                self.assertEqual(len(rows), total)
                self.assertEqual(sum(row['diagnostic_code'] == 'destination_excluded' for row in rows), excluded)
                self.assertTrue(all(row['completion'] == 'complete' for row in rows))
        policy = self.policy(cidr='192.0.2.8/30')
        fixture = SyntheticSockets()
        started = storage.timestamp(storage.utc_now())
        with fixture.install(schedule, transport, capability):
            probes = schedule.Scheduler(policy.networks[0], policy, fixture.clock.now + 10, endpoints=True).run()
        with storage.Store(policy, writable=True) as store:
            with self.assertRaisesRegex(ValueError, 'inconsistent completion'):
                batches.store_batch(store, 'tcp_endpoint', 'lab', started,
                                    storage.timestamp(storage.utc_now()), 'partial', probes)
        for state in ('filtered', 'unavailable', 'not_started'):
            with self.subTest(state=state):
                fixture = SyntheticSockets(lambda address, port: 'positive' if port == 22 else 'filtered')
                original = transport.begin_endpoint
                def begin(network, address, port, deadline, *, state=state, original=original):
                    if port == 2222 and state != 'filtered':
                        return None, (('unavailable', 'transport_permission_denied', False) if state == 'unavailable'
                                      else ('not_started', 'effective_deadline_before_start', False))
                    return original(network, address, port, deadline)
                with patch.object(transport, 'begin_endpoint', begin):
                    result = self.collect(policy, fixture)
                self.assertEqual(result['completion'], 'partial')
                self.assertEqual(result['observation_count'], 8)
        policy = self.policy(cidr='127.0.0.1/32')
        with patch.object(transport.socket, 'socket', side_effect=AssertionError('excluded destination contacted')):
            result = endpoints.check(policy, {'network': 'lab'})
        self.assertEqual(result['completion'], 'failed')
        self.assertEqual(result['state_counts']['unavailable'], 2)
        self.assertTrue(result['queryable'])

    def test_persistence_failure_rolls_back_and_readback_failure_retains_exact_resume(self):
        policy = self.policy()
        original = self.collect(policy)
        before = self.counts(policy)
        with patch.object(storage.Store, 'audit', side_effect=sqlite3.OperationalError(
                'synthetic persistence failure')):
            with self.assertRaises(sqlite3.Error):
                self.collect(policy)
        self.assertEqual(self.counts(policy), before)
        with patch.object(endpoints, 'store_batch', return_value={}), self.assertRaises(ValueError):
            self.collect(policy)
        self.assertEqual(self.counts(policy), before)
        with patch.object(endpoints, 'query_endpoints', side_effect=sqlite3.OperationalError(
                'synthetic readback failure')):
            failed = self.collect(policy)
        self.assertTrue(failed['persisted'] and failed['projected'] and failed['applied'])
        self.assertFalse(failed['queryable'])
        self.assertEqual(failed['stage'], 'readback')
        self.assertNotEqual(failed['batch_id'], original['batch_id'])
        self.assertTrue(failed['error'].startswith('endpoint store:'), failed)
        self.assertNotIn('synthetic readback failure', json.dumps(failed))
        stored = self.rows(policy, batch_id=failed['batch_id'])
        with patch.object(transport, 'begin_endpoint', side_effect=AssertionError('resume collected')):
            recovered = endpoints.check(policy, {'batch_id': failed['batch_id']})
        self.assertTrue(recovered['queryable'])
        self.assertEqual(self.rows(policy, batch_id=failed['batch_id']), stored)

    def test_projection_rollback_and_concurrent_resume_no_duplicates_or_new_events(self):
        policy = self.policy()
        original_audit = storage.Store.audit
        def audit(store, operation, action, *args, **kwargs):
            if action == 'endpoints_projected':
                raise sqlite3.OperationalError('projection failure after inserts')
            return original_audit(store, operation, action, *args, **kwargs)
        with patch.object(storage.Store, 'audit', audit):
            failed = self.collect(policy)
        self.assertTrue(failed['persisted'])
        self.assertFalse(failed['applied'] or failed['queryable'])
        self.assertEqual(failed['stage'], 'projection')
        self.assertEqual(self.counts(policy)['endpoint_observations'], 0)
        self.assertTrue(failed['error'].startswith('endpoint store:'), failed)
        self.assertNotIn('projection failure after inserts', json.dumps(failed))
        self.assertEqual(query.query(policy, {'view': 'status'})['unprojected_endpoint_batches'], 1)
        with patch.object(transport, 'begin_endpoint', side_effect=AssertionError('resume collected')):
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(
                    lambda _: endpoints.check(policy, {'batch_id': failed['batch_id']}), range(2)))
        self.assertTrue(all(result['queryable'] for result in results), results)
        counts = self.counts(policy)
        self.assertEqual((counts['endpoint_observations'], counts['applications'], counts['audit_events']), (4, 1, 2))
        self.assertEqual(query.query(policy, {'view': 'status'})['unprojected_endpoint_batches'], 0)

    def test_query_bounds_pagination_history_and_address_reuse_never_attributed(self):
        policy = self.policy()
        first = self.collect(policy)
        page = self.rows(policy, batch_id=first['batch_id'])
        with storage.Store(policy, writable=True) as store:
            for name, mac in (('old-owner', '00:11:22:33:44:55'), ('new-owner', '00:11:22:33:44:66')):
                device = core.create_device(store, name)['device_id']
                interface = core.add_interface(store, device, 'eth0', mac)
                core.add_address(store, interface, '192.0.2.8', 31)
        second = self.collect(policy)
        self.assertEqual(self.rows(policy, batch_id=first['batch_id']), page)
        rows = self.rows(policy, address='192.0.2.8')['endpoints']
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row['device_id'] is None for row in rows))
        self.assertEqual({row['batch_id'] for row in rows}, {first['batch_id'], second['batch_id']})
        all_rows = self.rows(policy)['endpoints']
        pages = [self.rows(policy, limit=1, offset=index) for index in range(8)]
        self.assertEqual([p['endpoints'][0] for p in pages], all_rows)
        self.assertFalse(pages[-1]['has_more'])
        for params in ({'limit': True}, {'limit': 101}, {'offset': -1}, {'name': 'x'},
                       {'batch_id': "' OR 1=1--"}, {'address': 'hostname'}):
            with self.assertRaises(ValueError):
                self.rows(policy, **params)
        self.assertEqual(self.rows(policy, batch_id='unknown')['endpoints'], [])
        small = replace(policy, limits=replace(policy.limits, output_bytes=400))
        with self.assertRaises(ValueError):
            self.rows(small)

    def test_shared_knowledge_no_foreign_resume_or_revoked_policy_and_isolated_store(self):
        policy = self.policy(limits={'observations': 4})
        result = self.collect(policy)
        other = config.validate_policy({'store': {'shared_sqlite_path': str(policy.database)}}, self.home / 'reader')
        self.assertEqual(self.rows(other), self.rows(policy))
        self.assertEqual(other.authorized_aliases, ())
        with self.assertRaises(ValueError):
            endpoints.check(other, {'batch_id': result['batch_id']})
        with self.assertRaises(ValueError):
            endpoints.check(other, {'network': 'lab'})
        same_grants = replace(policy, home=other.home)
        with self.assertRaises(ValueError):
            endpoints.check(same_grants, {'batch_id': result['batch_id']})
        isolated = config.validate_policy({}, self.home / 'isolated')
        self.assertEqual(self.rows(isolated)['endpoints'], [])
        self.assertFalse(isolated.database.exists())
        path = self.home / 'network-atlas' / 'config.yaml'
        original = path.read_bytes()
        self.addCleanup(path.write_bytes, original)
        page = self.rows(policy)
        with storage.Store(policy) as store:
            history = tuple(store.connection.iterdump())
        # Enlargements exceed the SAME budget that admitted the saved batch.
        # Port replacement and a one-record limit also require full saved-name
        # identity, not just a count comparison or a current-limit-sized prefix.
        for change, network_change, budget in (
                ('ports', {'endpoints': {'enabled': True, 'tcp_ports': [22]}}, 4),
                ('disabled', {'endpoints': {'enabled': False}}, 4),
                ('removed', {}, 4),
                ('cidr', {'cidr': '192.0.2.10/31'}, 4),
                ('observations', {}, 3),
                ('observations_minimum', {}, 1),
                ('widen_cidr', {'cidr': '192.0.2.8/30'}, 4),
                ('widen_ports', {'endpoints': {'enabled': True, 'tcp_ports': [22, 2222, 443]}}, 4),
                ('widen_cidr_lower_budget', {'cidr': '192.0.2.8/30'}, 1),
                ('widen_ports_lower_budget', {'endpoints': {'enabled': True, 'tcp_ports': [22, 2222, 443]}}, 1),
                ('replace_ports_lower_budget', {'endpoints': {'enabled': True, 'tcp_ports': [22, 443]}}, 1)):
            raw = json.loads(original)
            if change == 'removed':
                raw['networks'] = {}
            else:
                raw['networks']['lab'].update(network_change)
            raw['limits'] = {'observations': budget, 'output_bytes': 500}
            path.write_text(json.dumps(raw))
            with self.subTest(change=change), patch.object(endpoints.Scheduler, 'run') as collect, \
                    patch.object(transport.socket, 'socket') as socket, patch('subprocess.Popen') as spawn:
                emitted = fixture_handlers(self.home).check_endpoints({'batch_id': result['batch_id']})
                failed = json.loads(emitted)
                if change.startswith('observations'):
                    self.assertTrue(failed['error'].startswith('limits.observations:'), failed)
                    self.assertIn('record budget', failed['error'])
                    self.assertNotIn('network/port authorization', failed['error'])
                else:
                    self.assertTrue(failed['error'].startswith('endpoint policy:'), failed)
                    self.assertIn('network/port authorization', failed['error'])
                    self.assertNotIn('limits.observations', failed['error'])
                self.assertLessEqual(len(emitted.encode()), 500)
                self.assertEqual(failed['batch_id'], result['batch_id'])
                self.assertEqual(failed['completion'], result['completion'])
                self.assertEqual(failed['stage'], 'projection')
                self.assertTrue(failed['persisted'])
                self.assertFalse(failed['queryable'] or failed['collection_performed'])
                self.assertTrue(failed['applied'] and failed['projected'])
                for private in (str(self.home), '192.0.2.', '2222'):
                    self.assertNotIn(private, emitted)
                collect.assert_not_called()
                socket.assert_not_called()
                spawn.assert_not_called()
            with storage.Store(policy) as store:
                self.assertEqual(tuple(store.connection.iterdump()), history)
            self.assertEqual(self.rows(policy), page)
        path.write_bytes(original)
        with patch.object(endpoints.Scheduler, 'run') as collect:
            recovered = json.loads(fixture_handlers(self.home).check_endpoints({'batch_id': result['batch_id']}))
            self.assertTrue(recovered['queryable'])
            self.assertFalse(recovered['collection_performed'])
            collect.assert_not_called()
        with storage.Store(policy) as store:
            self.assertEqual(tuple(store.connection.iterdump()), history)

    def test_owned_socket_cleanup_on_registration_failure_and_interrupt(self):
        policy = self.policy()
        for error in (OSError('selector failed'), KeyboardInterrupt()):
            fixture = SyntheticSockets()
            with fixture.install(schedule, transport, capability), patch.object(endpoints, 'time', fixture.clock), \
                    patch('synthetic_sockets.SyntheticSelector.register', side_effect=error), \
                    self.assertRaises(type(error)):
                endpoints.check(policy, {'network': 'lab'})
            self.assertTrue(all(sock.closed for sock in fixture.sockets))
        self.assertFalse(policy.database.exists())

    def test_record_and_output_bounds_preflight_and_real_handler_recovery_receipt(self):
        policy = self.policy(limits={'observations': 3})
        with patch.object(transport.socket, 'socket', side_effect=AssertionError('budget refused too late')):
            with self.assertRaises(ValueError):
                endpoints.check(policy, {'network': 'lab'})
        self.assertFalse(policy.database.exists())
        policy = self.policy(limits={'output_bytes': 1})
        with patch.object(transport.socket, 'socket', side_effect=AssertionError('output refused too late')):
            with self.assertRaises(ValueError):
                endpoints.check(policy, {'network': 'lab'})
        self.assertFalse(policy.database.exists())
        recovery = {'batch_id': '0' * 36, 'persisted': True, 'applied': False, 'projected': False,
                    'queryable': False, 'stage': 'projection', 'collection_performed': False,
                    'completion': 'complete',
                    'error': ('limits.observations: endpoint address/port grid exceeds configured record budget; '
                              'restore sufficient limits and resume this batch')}
        minimum = len(storage.response_json(recovery, config.Limits().output_bytes).encode())
        self.policy(limits={'output_bytes': minimum - 1})
        with patch.object(endpoints.Scheduler, 'run') as collect, patch.object(transport.socket, 'socket') as socket:
            refused = json.loads(fixture_handlers(self.home).check_endpoints({'network': 'lab'}))
            self.assertTrue(refused['error'].startswith('atlas state or bounds:'), refused)
            self.assertFalse(refused['persisted'])
            collect.assert_not_called()
            socket.assert_not_called()
        self.assertFalse(policy.database.exists())
        policy = self.policy(limits={'output_bytes': 500})
        fixture = SyntheticSockets()
        with fixture.install(schedule, transport, capability), patch.object(endpoints, 'time', fixture.clock):
            emitted = fixture_handlers(self.home).check_endpoints({'network': 'lab'})
        self.assertLessEqual(len(emitted.encode()), 500)
        failed = json.loads(emitted)
        self.assertIn('error', failed)
        self.assertTrue(failed['persisted'], failed)
        self.assertTrue(failed['error'].startswith('endpoint state or bounds:'), failed)
        self.assertFalse(failed['queryable'])
        self.assertEqual(failed['stage'], 'readback')
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        with storage.Store(policy) as store:
            history = tuple(store.connection.iterdump())
        self.policy(limits={'observations': 3, 'output_bytes': 500})
        with patch.object(endpoints.Scheduler, 'run') as collect, \
                patch.object(transport.socket, 'socket') as socket, patch('subprocess.Popen') as spawn:
            emitted = fixture_handlers(self.home).check_endpoints({'batch_id': failed['batch_id']})
            limited = json.loads(emitted)
            self.assertLessEqual(len(emitted.encode()), 500)
            self.assertTrue(limited['error'].startswith('limits.observations:'), limited)
            self.assertIn('record budget', limited['error'])
            self.assertNotIn('network/port authorization', limited['error'])
            for key in ('batch_id', 'completion', 'persisted', 'applied', 'projected'):
                self.assertEqual(limited[key], failed[key])
            self.assertEqual(limited['stage'], 'projection')
            self.assertFalse(limited['queryable'] or limited['collection_performed'])
            for private in (str(self.home), '192.0.2.', '2222'):
                self.assertNotIn(private, emitted)
            collect.assert_not_called()
            socket.assert_not_called()
            spawn.assert_not_called()
        with storage.Store(policy) as store:
            self.assertEqual(tuple(store.connection.iterdump()), history)
        restored = self.policy()
        with patch.object(transport.socket, 'socket', side_effect=AssertionError('recovery recollected')):
            recovered = json.loads(fixture_handlers(self.home).check_endpoints({'batch_id': failed['batch_id']}))
        self.assertTrue(recovered['queryable'])
        self.assertEqual(self.counts(restored)['batches'], 1)

    def test_tcp_immediate_results_numeric_transport_and_no_receive_or_payload(self):
        policy = self.policy(ports=[22])
        cases = ((0, 'open', 'tcp_connected_response'),
                 (errno.ECONNREFUSED, 'closed', 'tcp_refused_response'),
                 (errno.ETIMEDOUT, 'no_response', 'effective_transport_deadline'),
                 (errno.EHOSTUNREACH, 'no_response', 'tcp_host_unreachable'),
                 (errno.EACCES, 'unavailable', 'transport_permission_denied'),
                 (errno.EPROTONOSUPPORT, 'unavailable', 'transport_protocol_unsupported'),
                 (errno.EMFILE, 'unavailable', 'transport_socket_failed'))
        for completed in (False, True):
            for code, state, diagnostic in cases:
                with self.subTest(completed=completed, code=code):
                    fixture = SyntheticSockets()
                    def connected(sock, target, *, completed=completed, code=code):
                        sock._start(*target)
                        return errno.EINPROGRESS if completed else code
                    with (fixture.install(schedule, transport, capability),
                          patch.object(endpoints, 'time', fixture.clock),
                          patch('synthetic_sockets.SyntheticSocket.connect_ex', connected),
                          patch('synthetic_sockets.SyntheticSocket.getsockopt', return_value=code),
                          patch('synthetic_sockets.SyntheticSocket.recvfrom',
                                side_effect=AssertionError('TCP payload read')),
                          patch('synthetic_sockets.SyntheticSocket.sendto',
                                side_effect=AssertionError('TCP payload sent'))):
                        result = endpoints.check(policy, {'network': 'lab'})
                    self.assertEqual(result['state_counts'][state], 2)
                    self.assertEqual(result['completion'], 'complete' if state in {'open', 'closed'} else 'failed')
                    rows = self.rows(policy, batch_id=result['batch_id'])['endpoints']
                    self.assertEqual({row['diagnostic_code'] for row in rows}, {diagnostic})
                    self.assertEqual({row['coverage'] for row in rows},
                                     {'not_checked' if state == 'unavailable' else 'attempted_address_port_only'})
                    self.assertEqual({row['qualified'] for row in rows}, {state in {'open', 'closed'}})
                    self.assertTrue(all(sock.closed for sock in fixture.sockets))
                    self.assertEqual({sock.protocol for sock in fixture.sockets}, {transport.socket.IPPROTO_TCP})

    def test_additive_v1_migration_read_only_no_effects_rollback_and_immutable_history(self):
        policy = self.policy()
        policy = replace(policy, networks=(replace(policy.networks[0], ping=True),))
        policy.database.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(policy.database) as connection:
            connection.executescript((ROOT / 'storage_schema.sql').read_text())
            # Build an otherwise genuine v1 store, including shipped immutable guards.
            for table in storage.IMMUTABLE_TABLES:
                for action in ('UPDATE', 'DELETE'):
                    connection.execute(f"CREATE TRIGGER immutable_{table}_{action} BEFORE {action} ON {table} "
                                       "BEGIN SELECT RAISE(ABORT,'immutable evidence'); END;")
        with patch.object(storage, '_migrate_endpoints', side_effect=AssertionError('read-only attempted migration')):
            with storage.Store(policy) as old:
                self.assertEqual(old.schema_version, 1)
            before = policy.database.read_bytes()
            self.assertEqual(self.rows(policy)['endpoints'], [])
            self.assertEqual(policy.database.read_bytes(), before)
        # Add historical v1 rows through the existing native writer without upgrading.
        with patch.object(storage, '_migrate_endpoints', return_value=None):
            with storage.Store(policy, writable=True) as old:
                core.create_device(old, 'historical')
                at = storage.timestamp(storage.utc_now())
                observation = batches.Observation(
                    'address', batches.Anchor('unresolved', 'legacy_address'), 'assignment',
                    (('address', '192.0.2.8'), ('prefix_length', 32)), at)
                probe = batches.Probe('ping_0', 'success', at, at, 'none', '', 'ping_response', 'ok', (observation,))
                batches.store_batch(old, 'ping', 'lab', at, at, 'complete', (probe,))
                history = {table: [tuple(row) for row in old.connection.execute(f'SELECT * FROM {table}')]
                           for table in storage.IMMUTABLE_TABLES}
        real_migrate = storage._migrate_endpoints
        def interrupted(connection):
            real_migrate(connection)
            raise sqlite3.OperationalError('migration interrupted after DDL')
        with patch.object(storage, '_migrate_endpoints', interrupted), self.assertRaises(sqlite3.Error):
            storage.Store(policy, writable=True)
        with storage.Store(policy) as old:
            self.assertEqual(old.schema_version, 1)
            self.assertIsNone(old.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='endpoint_observations'").fetchone())
        result = self.collect(policy)
        self.assertTrue(result['queryable'])
        with storage.Store(policy, writable=True) as migrated:
            self.assertEqual(migrated.schema_version, 2)
            for table, rows in history.items():
                actual = [tuple(row) for row in migrated.connection.execute(f'SELECT * FROM {table}')]
                self.assertEqual(actual[:len(rows)], rows)
            for table in ('batches', 'probes', 'observations', 'applications', 'audit_events', 'endpoint_observations'):
                for operation in ('UPDATE', 'DELETE'):
                    with migrated.transaction(), self.assertRaises(sqlite3.IntegrityError):
                        migrated.connection.execute(
                            f'UPDATE {table} SET rowid=rowid' if operation == 'UPDATE' else f'DELETE FROM {table}')
