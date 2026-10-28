# SPDX-License-Identifier: GPL-3.0-or-later
"""Mixed protocol evidence through real handlers, owned transport and recovery."""
from dataclasses import replace
import importlib
import errno
import json
from pathlib import Path
import socket
import sqlite3
import unittest
from unittest.mock import patch

from helpers import load_package, scratch_home
from synthetic_sockets import SyntheticSockets

load_package()
config, endpoints, schedule, transport, capability, storage, continuation, tools = (
    importlib.import_module('atlas_test_plugin.' + name) for name in
    ('config', 'endpoints', 'host_schedule', 'host_transport', 'host_discovery',
     'storage', 'endpoint_continuation', 'tools'))


class UDPEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.raw: dict = {'networks': {'lab': {'cidr': '192.0.2.8/31', 'allow_public': True,
                    'endpoints': {'enabled': True, 'tcp_ports': [22000], 'udp_ports': [21027, 22000]}}}}

    def policy(self):
        return config.validate_policy(self.raw, self.home)

    @staticmethod
    def handlers(policy):
        return tools.Handlers(lambda: policy)

    def invoke(self, params, fixture=None, policy=None):
        policy = policy or self.policy()
        fixture = fixture or SyntheticSockets()
        with fixture.install(schedule, transport, capability), patch.object(endpoints, 'time', fixture.clock), \
                patch.object(continuation, 'time', fixture.clock), patch.object(storage, 'time', fixture.clock):
            result = json.loads(self.handlers(policy).check_endpoints(params))
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        self.assertLessEqual(fixture.peak, policy.limits.concurrent_probes)
        return result, fixture

    def rows(self, policy=None, **filters):
        return json.loads(self.handlers(policy or self.policy()).query({'view': 'endpoints', **filters}))

    def history(self, policy=None):
        with storage.Store(policy or self.policy()) as store:
            return {table: [tuple(row) for row in store.connection.execute(f'SELECT * FROM {table} ORDER BY rowid')]
                    for table in (*storage.IMMUTABLE_TABLES, 'endpoint_observations', 'endpoint_continuations')}

    def test_mixed_protocol_collision_truth_and_provenance(self):
        receipt, fixture = self.invoke({'network': 'lab'}, SyntheticSockets(
            udp_response=lambda a, p: 'positive' if p == 22000 else 'closed'))
        self.assertTrue(receipt['queryable'], receipt)
        self.assertEqual(receipt['observation_count'], 6)
        rows = self.rows()['endpoints']
        self.assertEqual({(r['address'], r['protocol'], r['port']) for r in rows},
                         {(a, protocol, port) for a in ('192.0.2.8', '192.0.2.9')
                          for protocol, port in (('tcp', 22000), ('udp', 21027), ('udp', 22000))})
        self.assertEqual(len(fixture.protocol_calls), 6)
        for row in rows:
            self.assertEqual(row['policy_context'], str(self.home))
            self.assertEqual(row['collector'], 'endpoint')
            self.assertEqual(row['scope_value'], '192.0.2.8/31')
            self.assertTrue(row['qualified'])
            self.assertIsNone(row['device_id'])
            self.assertTrue(row['probe_id'] and row['batch_id'] and row['started_at'] and row['checked_at'])
            if row['protocol'] == 'udp':
                self.assertEqual(row['probe_method'], 'udp_empty_datagram_v1')
                self.assertEqual(row['state'], 'open' if row['port'] == 22000 else 'closed')
        status = json.loads(self.handlers(self.policy()).command('status'))
        self.assertEqual((status['endpoint_count'], status['responding_endpoint_count']), (6, 6))
        self.assertEqual(status['known_devices'], 0)
        old = self.history()
        with patch.object(transport.socket, 'socket', side_effect=AssertionError('resume traffic')):
            resumed = json.loads(self.handlers(self.policy()).command('resume-endpoints ' + receipt['batch_id']))
        self.assertTrue(resumed['queryable'], resumed)
        self.assertFalse(resumed['collection_performed'])
        self.assertEqual(self.history(), old)
        revoked = replace(self.policy(), networks=())
        self.assertEqual(self.rows(revoked)['endpoints'], rows)
        shared = replace(revoked, home=self.home / 'reader')
        self.assertEqual(self.rows(shared)['endpoints'], rows)
        with patch.object(transport.socket, 'socket', side_effect=AssertionError('foreign traffic')):
            self.assertIn('error', json.loads(self.handlers(shared).check_endpoints({'batch_id': receipt['batch_id']})))
        self.assertEqual(self.history(), old)

    def test_udp_silence_malformed_wrong_peer_unreachable_and_local_failure(self):
        self.raw['networks']['lab']['endpoints'] = {'udp_ports': [21027]}
        cases = (('filtered', 'no_response', 'effective_transport_deadline'),
                 ('malformed', 'no_response', 'effective_transport_deadline'),
                 ('wrong_address', 'no_response', 'effective_transport_deadline'),
                 ('wrong_port', 'no_response', 'effective_transport_deadline'),
                 ('unreachable', 'no_response', 'udp_host_unreachable'),
                 ('denied', 'unavailable', 'udp_receive_transport_permission_denied'))
        for state, expected, diagnostic in cases:
            with self.subTest(state=state):
                receipt, fixture = self.invoke({'network': 'lab'}, SyntheticSockets(
                    udp_response=lambda a, p, state=state: state))
                self.assertTrue(receipt['queryable'], receipt)
                rows = self.rows(batch_id=receipt['batch_id'])['endpoints']
                self.assertEqual({r['state'] for r in rows}, {expected})
                self.assertEqual({r['diagnostic_code'] for r in rows}, {diagnostic})
                self.assertFalse(any(r['qualified'] for r in rows))
                self.assertEqual(len(fixture.calls), 2)

    def test_strict_independent_udp_policy_and_pre_effect_aggregate_bound(self):
        for ports, reason in (([True], 'integer'), ([0], '1..65535'), ([65536], '1..65535'),
                              ([22, 22], 'distinct'), ([7], 'excluded'), ([19], 'excluded'),
                              ([4403], 'excluded'), (list(range(100, 133)), '32'), ('22', 'list')):
            with self.subTest(ports=ports):
                self.raw['networks']['lab']['endpoints']['udp_ports'] = ports
                with self.assertRaisesRegex(config.ConfigError, reason):
                    self.policy()
        for ports in ([1, 65535], list(range(100, 132)), []):
            self.raw['networks']['lab']['endpoints']['udp_ports'] = ports
            self.assertEqual(self.policy().networks[0].endpoint_udp_ports, tuple(ports))
        self.raw['networks']['lab']['endpoints'] = {'udp_ports': [22000]}
        self.assertEqual(self.policy().networks[0].endpoint_ports, ())
        self.raw['networks']['lab']['endpoints'].update({'enabled': True, 'tcp_ports': [7, 19]})
        self.assertEqual(self.policy().networks[0].endpoint_ports, (7, 19))
        self.raw['networks']['lab']['cidr'] = '192.0.2.0/24'
        self.raw['networks']['lab']['endpoints'] = {'enabled': True, 'tcp_ports': list(range(100, 116)),
                                                  'udp_ports': [22000]}
        with patch.object(endpoints, 'Scheduler') as scheduler, patch.object(endpoints, 'Store') as opened:
            receipt = json.loads(self.handlers(self.policy()).check_endpoints({'network': 'lab'}))
        self.assertIn('limits.observations', receipt['error'])
        scheduler.assert_not_called()
        opened.assert_not_called()
        self.assertFalse(self.policy().database.exists())

    def test_partial_mixed_grid_exact_continuation_and_immutable_history(self):
        self.raw['networks']['lab']['cidr'] = '192.0.2.0/27'
        self.raw['limits'] = {'operation_timeout_seconds': 2, 'host_timeout_seconds': 1}
        with patch.object(endpoints, '_project', side_effect=sqlite3.OperationalError('interrupted')):
            first, fixture = self.invoke({'network': 'lab'}, SyntheticSockets(udp_response=lambda a, p: 'filtered'))
        self.assertTrue(first['persisted'] and not first['applied'], first)
        raw = self.history()
        with patch.object(transport.socket, 'socket', side_effect=AssertionError('resume contacts')):
            resumed = json.loads(self.handlers(self.policy()).check_endpoints({'batch_id': first['batch_id']}))
        self.assertTrue(resumed['queryable'], resumed)
        self.assertEqual(self.history()['probes'], raw['probes'])
        rows = self.rows(limit=100)['endpoints']
        remaining = {(r['address'], r['protocol'], r['port']) for r in rows if r['state'] == 'not_started'}
        self.assertTrue(remaining)
        before = self.history()
        for udp in ((), (22000,)):
            changed = replace(self.policy(), networks=(replace(self.policy().networks[0], endpoint_udp_ports=udp),))
            with patch.object(transport.socket, 'socket', side_effect=AssertionError('changed grid contacted')):
                for key in ('batch_id', 'preview_batch_id', 'continue_batch_id'):
                    self.assertIn('error', json.loads(self.handlers(changed).check_endpoints({key: first['batch_id']})))
            self.assertEqual(self.history(), before)
        second, next_fixture = self.invoke({'continue_batch_id': first['batch_id']})
        self.assertTrue(second['queryable'], second)
        calls = {(a, 'udp' if p == socket.IPPROTO_UDP else 'tcp', port)
                 for _, a, p, port in next_fixture.protocol_calls}
        self.assertTrue(calls)
        self.assertLessEqual(calls, remaining)
        self.assertFalse(calls & {(a, 'udp' if p == socket.IPPROTO_UDP else 'tcp', port)
                                 for _, a, p, port in fixture.protocol_calls})
        for table in ('batches', 'probes', 'applications', 'endpoint_observations'):
            self.assertEqual(self.history()[table][:len(before[table])], before[table])
        with patch.object(transport.socket, 'socket', side_effect=AssertionError('repeat contacts')):
            repeated = json.loads(self.handlers(self.policy()).command('continue-endpoints ' + first['batch_id']))
        self.assertEqual(repeated['batch_id'], second['batch_id'])
        self.assertFalse(repeated['collection_performed'])

    def test_schema3_tcp_history_readonly_upgrade_rollback_and_udp_append(self):
        udp_policy = self.policy()
        self.raw['networks']['lab']['endpoints'].pop('udp_ports')
        tcp_policy = self.policy()
        # Produce genuine shipped-format TCP evidence, not hand-inserted rows.
        with patch.object(storage, '_migrate_endpoint_protocols', return_value=None):
            old, _ = self.invoke({'network': 'lab'}, policy=tcp_policy)
        self.assertTrue(old['queryable'], old)
        history = self.history(tcp_policy)
        rows = self.rows(tcp_policy)
        with storage.Store(tcp_policy) as store:
            self.assertEqual(store.schema_version, 3)
        physical = tcp_policy.database.read_bytes()
        self.assertEqual(self.rows(udp_policy), rows)
        self.assertEqual(tcp_policy.database.read_bytes(), physical)
        migrate = storage._migrate_endpoint_protocols
        def interrupted(connection):
            migrate(connection)
            raise sqlite3.OperationalError('after projection replacement')
        with patch.object(storage, '_migrate_endpoint_protocols', interrupted):
            failed, _ = self.invoke({'network': 'lab'}, policy=udp_policy)
        self.assertIn('error', failed)
        self.assertEqual(self.history(tcp_policy), history)
        with storage.Store(tcp_policy) as store:
            self.assertEqual(store.schema_version, 3)
        new, _ = self.invoke({'network': 'lab'}, policy=udp_policy)
        self.assertTrue(new['queryable'], new)
        for table, old_rows in history.items():
            self.assertEqual(self.history(udp_policy)[table][:len(old_rows)], old_rows)
        self.assertEqual(self.rows(tcp_policy, batch_id=old['batch_id'])['endpoints'], rows['endpoints'])
        with patch.object(transport.socket, 'socket', side_effect=AssertionError('old resume contact')):
            resumed = json.loads(self.handlers(tcp_policy).check_endpoints({'batch_id': old['batch_id']}))
        self.assertTrue(resumed['queryable'], resumed)
        with storage.Store(tcp_policy, writable=True) as store:
            self.assertEqual(store.schema_version, 4)
            for sql in ('UPDATE endpoint_observations SET rowid=rowid', 'DELETE FROM endpoint_observations'):
                with self.assertRaises(sqlite3.IntegrityError):
                    store.connection.execute(sql)

    def test_udp_effect_boundary_lifetime_local_errors_and_shared_receive_budget(self):
        network = self.policy().networks[0]
        fixture = SyntheticSockets()
        with fixture.install(schedule, transport, capability):
            deadline = fixture.clock.now + 1
            attempt, outcome = transport.begin_endpoint(network, '192.0.2.8', 22000, deadline, protocol='udp')
            self.assertIsNone(outcome)  # connect/send never qualifies
            self.assertEqual(attempt.protocol, 'udp')
            self.assertEqual(fixture.sockets[0].packet, b'')
            fixture.clock.now = deadline
            with patch.object(attempt.sock, 'recvfrom', side_effect=AssertionError('late read')):
                self.assertEqual(transport.ready(attempt, 10)[0][0], 'timeout')
            attempt.sock.close()
            for port, protocol in ((4403, 'tcp'), (7, 'udp'), (19, 'udp'), (4403, 'udp'), (53, 'udp')):
                with self.assertRaises(ValueError):
                    transport.begin_endpoint(network, '192.0.2.8', port, deadline + 1, protocol=protocol)
            for address in ('192.0.2.99', '127.0.0.1', 'host.example'):
                with self.assertRaises(ValueError):
                    transport.begin_endpoint(network, address, 22000, deadline + 1, protocol='udp')
        self.assertEqual(len(fixture.sockets), 1)
        # ECONNREFUSED at connect/send is a local failure, NOT the post-send
        # kernel rejection evidence returned by recvfrom on a connected socket.
        for method in ('connect_ex', 'send'):
            fixture = SyntheticSockets()
            with fixture.install(schedule, transport, capability), patch(
                    'synthetic_sockets.SyntheticSocket.' + method, side_effect=OSError(errno.ECONNREFUSED, 'local')):
                attempt, outcome = transport.begin_endpoint(network, '192.0.2.8', 22000,
                                                             fixture.clock.now + 1, protocol='udp')
            self.assertIsNone(attempt)
            self.assertEqual(outcome, ('unavailable', 'transport_socket_failed', False))
            self.assertTrue(all(s.closed for s in fixture.sockets))
        self.raw['networks']['lab']['cidr'] = '192.0.2.0/28'
        self.raw['limits'] = {'output_bytes': 4096, 'result_count': 1}
        with patch('synthetic_sockets.SyntheticSocket.recvfrom',
                   side_effect=lambda size: (b'x' * size, ('192.0.2.1', 22000))):
            receipt, fixture = self.invoke({'network': 'lab'})
        self.assertTrue(receipt['queryable'], receipt)
        rows = self.rows(limit=1, batch_id=receipt['batch_id'])
        self.assertEqual(rows['total_count'], 48)
        with storage.Store(self.policy()) as store:
            codes = {r[0] for r in store.connection.execute('SELECT diagnostic_code FROM probes')}
        self.assertIn('shared_receive_limit', codes)
        self.assertIn('receive_budget_before_start', codes)
        self.assertLessEqual(fixture.peak, 4)
        preview = json.loads(self.handlers(self.policy()).check_endpoints({'preview_batch_id': receipt['batch_id']}))
        self.assertEqual(preview['progress']['attempted'], len(fixture.protocol_calls))

    def test_mixed_cancellation_closes_all_owned_sockets_without_persistence(self):
        fixture = SyntheticSockets(udp_response=lambda a, p: 'filtered')
        with fixture.install(schedule, transport, capability), patch(
                'synthetic_sockets.SyntheticSelector.select', side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self.handlers(self.policy()).check_endpoints({'network': 'lab'})
        self.assertTrue(fixture.sockets)
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        self.assertFalse(self.policy().database.exists())
