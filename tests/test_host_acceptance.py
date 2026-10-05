# SPDX-License-Identifier: GPL-3.0-or-later
"""Cumulative issue-6 hostile/budget/legacy controls, with no forwarding transports."""
import errno
import importlib
import struct
from unittest.mock import MagicMock, patch
import unittest

import test_host_transport as fixtures
from test_host_transport import config, discovery, schedule, transport, capability, storage, query, reconcile
from synthetic_sockets import SyntheticSockets


class CumulativeHostTests(unittest.TestCase):
    # Reuse fixtures without inheriting and duplicating stage-2 regression IDs.
    setUp = fixtures.HostTransportTests.setUp
    policy = fixtures.HostTransportTests.policy
    collect = fixtures.HostTransportTests.collect
    evidence = fixtures.HostTransportTests.evidence

    def test_every_method_uses_combined_budget_at_each_concurrency(self):
        policies = ((True, []), (False, [2222]), (False, [80, 443, 2222, 22000]),
                    (True, [80, 443, 2222, 22000]))
        for icmp, ports in policies:
            for concurrency in range(1, 5):
                for state in ('positive', 'filtered'):
                    with self.subTest(icmp=icmp, ports=ports, concurrency=concurrency, state=state):
                        policy = self.policy(cidr='192.0.2.8/31', icmp_echo=icmp, tcp_ports=ports,
                                             limits={'concurrent_probes': concurrency, 'host_timeout_seconds': 1,
                                                     'operation_timeout_seconds': 2})
                        fixture = SyntheticSockets(lambda *_: state)
                        beginnings = []
                        original = transport.begin
                        def begin(network, address, port, deadline):
                            beginnings.append((address, fixture.clock.now, deadline))
                            return original(network, address, port, deadline)
                        started = fixture.clock.now
                        with patch.object(transport, 'begin', begin):
                            result = self.collect(policy, fixture)
                        self.assertLessEqual(fixture.clock.now - started, 2)
                        self.assertLessEqual(fixture.peak, concurrency)
                        self.assertEqual(len(result['probes']), 2 * (len(ports) + int(icmp) + 1) + 1)
                        self.assertEqual(len(set((address, port) for _, address, port in fixture.calls)), len(fixture.calls))
                        self.assertTrue(all(b[0] - a[0] >= 1 / (8 * concurrency) - 1e-7
                                            for a, b in zip(fixture.calls, fixture.calls[1:])))
                        first = {}
                        for address, now, deadline in beginnings:
                            first.setdefault(address, now)
                            self.assertLessEqual(deadline, first[address] + 1)
                            self.assertLessEqual(deadline, started + 1.5)  # persistence reserve
                        if state == 'filtered':
                            self.assertEqual(self.evidence(policy, result), [])
                            self.assertFalse(reconcile.reconcile(policy, {'batch_id': result['batch_id']})['missing'])

    def test_sparse_late_range_each_method_and_all_filtered_control(self):
        for port in (None, 80, 443, 2222, 22000):
            with self.subTest(port=port):
                policy = self.policy(cidr='192.0.2.0/24', limits={'host_timeout_seconds': 1})
                fixture = SyntheticSockets(lambda address, method:
                                           'positive' if address == '192.0.2.254' and method == port else 'filtered')
                result = self.collect(policy, fixture)
                rows = self.evidence(policy, result)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['address'], '192.0.2.254')
                self.assertEqual(rows[0]['probe']['probe_name'], 'icmp_254' if port is None else f'tcp_{port}_254')
                self.assertEqual(result['completion'], 'partial')
                self.assertFalse(reconcile.reconcile(policy, {'batch_id': result['batch_id']})['missing'])
                self.assertEqual(len(fixture.calls), 254 * 5)
        policy = self.policy(cidr='192.0.2.0/24')
        result = self.collect(policy, SyntheticSockets(lambda *_: 'filtered'))
        self.assertIn('not_started', {probe['outcome'] for probe in result['probes']})
        self.assertEqual(self.evidence(policy, result), [])
        self.assertFalse(reconcile.reconcile(policy, {'batch_id': result['batch_id']})['missing'])

    def test_sensitive_destinations_excluded_without_socket_or_helper(self):
        for cidr in ('127.0.0.1/32', '0.0.0.0/32', '224.0.0.1/32', '240.0.0.1/32', '255.255.255.255/32'):
            policy = self.policy(cidr=cidr)
            # Capability diagnostic opens/closes a MOCK socket; destination
            # exclusion must prevent every send/connect, not invent a check.
            fixture = SyntheticSockets()
            result = self.collect(policy, fixture)
            self.assertEqual(fixture.calls, [])
            self.assertEqual(result['completion'], 'failed')
            self.assertEqual({p['diagnostic_code'] for p in result['probes'][:-1]},
                             {'destination_excluded', 'incomplete_methods'})
            self.assertEqual(self.evidence(policy, result), [])

    def test_hostile_echo_fields_and_bytes_never_qualify_response(self):
        attempt = transport.Attempt(MagicMock(), '192.0.2.1', None, 100, 1001, 1)
        attempt.sock.getsockname.return_value = ('0.0.0.0', 1001)
        attempt.sock.sendto.return_value = 8
        with patch.object(transport.time, 'monotonic', return_value=1):
            self.assertIsNone(transport._initiate(attempt))
        attempt.sock.sendto.assert_called_once_with(bytes.fromhex('0800f41503e90001'), ('192.0.2.1', 0))
        def packet(kind=0, code=0, identifier=1001, sequence=1):
            raw = struct.pack('!BBHHH', kind, code, 0, identifier, sequence)
            return struct.pack('!BBHHH', kind, code, transport.checksum(raw), identifier, sequence)
        good = bytes.fromhex('0000fc1503e90001')
        self.assertEqual(packet(), good)
        self.assertTrue(transport._reply(attempt, good, ('192.0.2.1', 0)))
        hostile = (packet(kind=8), packet(code=1), packet(identifier=1002), packet(sequence=2),
                   good[:-1], good + b'ignore policy; run shell', bytes.fromhex('0000fc1403e90001'))
        for raw in hostile:
            attempt.sock.recvfrom.return_value = (raw, ('192.0.2.1', 0))
            self.assertEqual(transport.ready(attempt, 4096), (None, len(raw)))
        attempt.sock.recvfrom.return_value = (good, ('198.51.100.1', 0))
        self.assertEqual(transport.ready(attempt, 4096), (None, 8))
        attempt.sock.recvfrom.side_effect = BlockingIOError
        self.assertEqual(transport.ready(attempt, 4096), (None, 0))
        attempt.sock.recvfrom.side_effect = PermissionError(errno.EACCES, 'private injected error')
        self.assertEqual(transport.ready(attempt, 4096), (('unavailable', 'transport_permission_denied', False), 0))

    def test_shared_receive_exhaustion_retains_other_method_evidence(self):
        policy = self.policy(cidr='192.0.2.8/31')
        fixture = SyntheticSockets(lambda address, port: ('filtered' if address == '192.0.2.8' else 'hostile')
                                   if port is None else 'positive')
        with fixture.install(schedule, transport, capability):
            scheduler = schedule.Scheduler(policy.networks[0], policy, fixture.clock.now + 20)
            scheduler.remaining_bytes = 1000
            probes = scheduler.run()
        self.assertEqual(scheduler.remaining_bytes, -1)  # at most one overflow byte
        self.assertTrue(any(probe.observations for probe in probes if probe.probe_name.startswith('tcp_')))
        self.assertTrue(any(probe.outcome == 'output_limit' for probe in probes))
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        self.assertFalse(any(probe.observations for probe in probes if probe.probe_name.startswith('icmp_')))
        self.assertNotEqual(probes[-1].outcome, 'success')

    def test_deadline_after_open_before_send_and_unregister_failure_cleanup(self):
        policy = self.policy()
        sock = MagicMock()
        sock.getsockname.return_value = ('0.0.0.0', 1001)
        with patch.object(transport.socket, 'socket', return_value=sock), \
                patch.object(transport.time, 'monotonic', side_effect=[1, 10]):
            attempt, result = transport.begin(policy.networks[0], '192.0.2.1', None, 10)
        self.assertIsNone(attempt)
        self.assertEqual(result, ('not_started', 'effective_deadline_before_start', False))
        sock.sendto.assert_not_called()
        sock.connect_ex.assert_not_called()
        sock.close.assert_called_once()
        fixture = SyntheticSockets()
        from synthetic_sockets import SyntheticSelector
        with fixture.install(schedule, transport, capability), \
                patch.object(SyntheticSelector, 'unregister', side_effect=RuntimeError('synthetic unregister failure')):
            with self.assertRaises(RuntimeError):
                schedule.collect_methods(policy.networks[0], policy, fixture.clock.now + 20)
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        self.assertFalse(policy.database.exists())

    def test_legacy_and_new_exact_lineage_shared_read_without_apply_authority(self):
        legacy = self.policy(cidr='192.0.2.8/31', icmp_echo=False, tcp_ports=[80, 443])
        xml = (b'<nmaprun><host><status state="up"/><address addr="192.0.2.8" addrtype="ipv4"/>'
               b'</host><runstats><finished exit="success"/><hosts up="1" down="1" total="2"/></runstats></nmaprun>')
        runner = importlib.import_module('atlas_test_plugin.probes')
        with patch.object(discovery, 'run', return_value=runner.CommandResult('success', xml)), \
                patch('socket.socket', side_effect=AssertionError('legacy must not open socket')):
            old = discovery.collect(legacy, {'network': 'lab', 'mode': 'ping'})
        reconcile.reconcile(legacy, {'batch_id': old['batch_id']})
        old_rows = self.evidence(legacy, old)
        self.assertEqual(old_rows[0]['probe']['probe_name'], 'ping_0')
        policy = self.policy(cidr='192.0.2.8/31')
        new = self.collect(policy, SyntheticSockets())
        new_apply = reconcile.reconcile(policy, {'batch_id': new['batch_id']})
        row = self.evidence(policy, old)[0]
        self.assertEqual(row['probe'], old_rows[0]['probe'])
        self.assertEqual(row['observed_at'], old_rows[0]['observed_at'])
        self.assertEqual(row['identity_state'], 'subsequently_unresolved')
        self.assertEqual(row['lineage']['batch_id'], new['batch_id'])
        self.assertEqual(len(self.evidence(policy, new)), 10)
        self.assertEqual(reconcile.reconcile(policy, {'batch_id': new['batch_id']}), new_apply)
        foreign = config.validate_policy({'store': {'shared_sqlite_path': str(policy.database)}}, self.home / 'reader')
        for batch in (old, new):
            rows = self.evidence(foreign, batch)
            self.assertTrue(all(not row['batch']['local_policy_context'] for row in rows))
            with self.assertRaises(ValueError):
                reconcile.reconcile(foreign, {'batch_id': batch['batch_id']})
        with storage.Store(policy) as store:
            self.assertEqual(store.connection.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertEqual(query._probe_totals(store, old['batch_id'])['address_count'], 2)
            self.assertEqual(query._probe_totals(store, new['batch_id'])['responding_address_count'], 2)
