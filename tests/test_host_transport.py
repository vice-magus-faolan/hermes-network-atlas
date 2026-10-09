# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue-6 host-only transport, accounting and atomic historical evidence regressions."""
from contextlib import ExitStack
from dataclasses import replace
import errno
import importlib
import json
from pathlib import Path
import socket
import struct
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
if __name__ == '__main__':
    from offline_guard import deny_network
    deny_network()
from synthetic_sockets import SyntheticSockets
from helpers import load_package, scratch_home

load_package()
config, discovery, schedule, transport, capability, storage, query, reconcile = (
    importlib.import_module('atlas_test_plugin.' + name) for name in
    ('config', 'discovery', 'host_schedule', 'host_transport', 'host_discovery', 'storage', 'query', 'reconcile'))


class HostTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def policy(self, *, cidr='192.0.2.0/29', icmp_echo=True, tcp_ports=None, limits=None):
        raw = {'networks': {'lab': {'cidr': cidr, 'discovery': {'ping': True, 'passive': True,
               'icmp_echo': icmp_echo, 'tcp_ports': [80, 443, 2222, 22000] if tcp_ports is None else tcp_ports}}}}
        if limits:
            raw['limits'] = limits
        return config.validate_policy(raw, self.home)

    def collect(self, policy, fixture):
        with fixture.install(schedule, transport, capability), patch.object(discovery, 'time', fixture.clock), \
                patch('subprocess.Popen', side_effect=AssertionError('no helper or legacy child')):
            result = discovery.collect(policy, {'network': 'lab', 'mode': 'ping'})
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        self.assertLessEqual(fixture.peak, policy.limits.concurrent_probes)
        return result

    def evidence(self, policy, result):
        return query.query(policy, {'view': 'unresolved', 'batch_id': result['batch_id']})['evidence']

    def test_icmp_only_positive_survives_filtered_web_and_retains_times(self):
        policy = self.policy(tcp_ports=[80, 443])
        fixture = SyntheticSockets(lambda address, port: 'positive' if port is None else 'filtered')
        result = self.collect(policy, fixture)
        self.assertEqual(result['completion'], 'partial')
        evidence = self.evidence(policy, result)
        self.assertEqual(len(evidence), 6)
        self.assertTrue(all(row['probe']['probe_name'].startswith('icmp_') for row in evidence))
        self.assertTrue(all(row['historical_responder_evidence'] for row in evidence))
        self.assertTrue(all(row['probe']['started_at'] <= row['observed_at'] <= row['probe']['ended_at'] for row in evidence))
        self.assertFalse(reconcile.reconcile(policy, {'batch_id': result['batch_id']})['missing'])
        self.assertEqual(query.query(policy, {})['devices'], [])

    def test_tcp_2222_and_optional_22000_only_positives(self):
        for port in (2222, 22000):
            policy = self.policy(icmp_echo=False, tcp_ports=[port])
            fixture = SyntheticSockets(lambda address, selected: 'positive' if selected == port else 'filtered')
            result = self.collect(policy, fixture)
            self.assertEqual({row['probe']['probe_name'].split('_')[1] for row in self.evidence(policy, result)}, {str(port)})
            self.assertEqual({call[2] for call in fixture.calls}, {port})
            self.assertEqual(result['completion'], 'partial')  # excluded network/broadcast, never absence

    def test_mixed_duplicates_retained_address_counts_deduplicated_after_restart(self):
        policy = self.policy(cidr='192.0.2.8/31')
        result = self.collect(policy, SyntheticSockets())
        self.assertEqual(result['completion'], 'complete')
        self.assertEqual(len(self.evidence(policy, result)), 10)
        applied = reconcile.reconcile(policy, {'batch_id': result['batch_id']})
        self.assertEqual(len(applied['unresolved']), 10)
        self.assertEqual(query.query(policy, {})['devices'], [])
        with storage.Store(policy) as store:
            totals = query._probe_totals(store, result['batch_id'])
            self.assertEqual((totals['address_count'], totals['responding_address_count'], totals['total_count']), (2, 2, 13))
            self.assertEqual(store.connection.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
        self.assertEqual(reconcile.reconcile(policy, {'batch_id': result['batch_id']}), applied)
        self.assertEqual(len(self.evidence(policy, result)), 10)

    def test_denied_missing_icmp_does_not_suppress_tcp_and_no_fallback(self):
        for number in (errno.EACCES, errno.EPROTONOSUPPORT):
            policy = self.policy(tcp_ports=[2222])
            fixture = SyntheticSockets(icmp_error=number)
            result = self.collect(policy, fixture)
            self.assertEqual(result['completion'], 'partial')
            self.assertEqual(len(self.evidence(policy, result)), 6)
            self.assertTrue(all(call[2] == 2222 for call in fixture.calls))
            self.assertTrue(all(row['probe']['probe_name'].startswith('tcp_2222_') for row in self.evidence(policy, result)))

    def test_all_filtered_timeouts_not_offline_or_packets_for_unstarted(self):
        policy = self.policy(cidr='192.0.2.0/24', limits={'operation_timeout_seconds': 2, 'host_timeout_seconds': 1})
        fixture = SyntheticSockets(lambda *_: 'filtered')
        result = self.collect(policy, fixture)
        self.assertEqual(result['completion'], 'failed')
        self.assertEqual(self.evidence(policy, result), [])
        codes = {probe['outcome'] for probe in result['probes']}
        self.assertIn('timeout', codes)
        self.assertIn('not_started', codes)
        self.assertFalse(reconcile.reconcile(policy, {'batch_id': result['batch_id']})['missing'])
        attempts = sum(probe['name'].startswith(('tcp_', 'icmp_')) and probe['outcome'] == 'timeout' for probe in result['probes'])
        self.assertEqual(attempts, len(fixture.calls))

    def test_scope_and_4403_caller_forgery_refuse_before_transport(self):
        policy = self.policy()
        network = policy.networks[0]
        with patch('socket.socket', side_effect=AssertionError('forbidden socket')):
            for port in (4403, 22, True, '2222'):
                with self.assertRaises(ValueError):
                    transport.begin(network, '192.0.2.1', port, 100)
            for address in ('example.test', '192.0.2.1;id', '198.51.100.1', '192.0.2.0', '192.0.2.7'):
                with self.assertRaises(ValueError):
                    transport.begin(network, address, 2222, 100)
            for key in ('tcp_ports', 'icmp_echo', 'source', 'operator', 'command', 'options'):
                with self.assertRaises(ValueError):
                    discovery.collect(policy, {'network': 'lab', 'mode': 'ping', key: True})
            malformed = replace(policy, networks=(replace(network, tcp_ports=(4403,)),))
            with self.assertRaises(ValueError):
                discovery.collect(malformed, {'network': 'lab', 'mode': 'ping'})
        self.assertFalse(policy.database.exists())

    def test_runtime_method_failure_preserves_other_method_positive(self):
        policy = self.policy(tcp_ports=[2222])
        original = transport._initiate
        for failed_method in ('tcp', 'icmp'):
            def initiate(attempt):
                if (attempt.port is None) == (failed_method == 'icmp'):
                    raise PermissionError(errno.EPERM, 'synthetic runtime denial')
                return original(attempt)
            fixture = SyntheticSockets()
            with patch.object(transport, '_initiate', initiate):
                result = self.collect(policy, fixture)
            evidence = self.evidence(policy, result)
            self.assertEqual(len(evidence), 6)
            prefix = 'tcp_' if failed_method == 'icmp' else 'icmp_'
            self.assertTrue(all(row['probe']['probe_name'].startswith(prefix) for row in evidence))
            self.assertEqual(result['completion'], 'partial')

    def test_host_budget_is_not_renewed_per_method_or_port(self):
        policy = self.policy(cidr='192.0.2.1/32', limits={'concurrent_probes': 1, 'host_timeout_seconds': 1})
        fixture = SyntheticSockets(lambda *_: 'filtered')
        deadlines = []
        original = transport.begin
        def begin(network, address, port, deadline):
            deadlines.append((fixture.clock.now, deadline))
            return original(network, address, port, deadline)
        with patch.object(transport, 'begin', begin):
            result = self.collect(policy, fixture)
        self.assertEqual(len(deadlines), 5)
        first = deadlines[0][0]
        self.assertTrue(all(deadline <= first + 1 for _, deadline in deadlines))
        self.assertTrue(all(deadline - start <= 1 / 6 + 1e-7 for start, deadline in deadlines))
        self.assertEqual({row['outcome'] for row in result['probes'][:-1]}, {'timeout'})

    def test_combined_probe_bound_before_capability_or_transport(self):
        policy = self.policy(limits={'observations': 48})  # 8 * (5 + 1) + 1 = 49
        with patch('socket.socket', side_effect=AssertionError('pre-effect bound')):
            with self.assertRaisesRegex(ValueError, 'probe count'):
                discovery.collect(policy, {'network': 'lab', 'mode': 'ping'})
        self.assertFalse(policy.database.exists())

    def test_round_robin_late_range_rate_concurrency_and_single_host_deadline(self):
        policy = self.policy(cidr='192.0.2.0/24')
        fixture = SyntheticSockets()
        result = self.collect(policy, fixture)
        self.assertEqual(len(fixture.calls), 254 * 5)
        self.assertIn('192.0.2.254', {call[1] for call in fixture.calls})
        self.assertEqual([call[1] for call in fixture.calls[:3]], [f'192.0.2.{i}' for i in range(1, 4)])
        self.assertEqual(len({call[2] for call in fixture.calls[:15]}), 5)
        spacing = 1 / (8 * policy.limits.concurrent_probes)
        self.assertTrue(all(b[0] - a[0] >= spacing - 1e-7 for a, b in zip(fixture.calls, fixture.calls[1:])))
        self.assertEqual(len(result['probes']), 1537)
        with storage.Store(policy) as store:
            self.assertEqual(query._probe_totals(store, result['batch_id'])['responding_address_count'], 254)
        self.assertLess(fixture.clock.now - fixture.calls[0][0], 120)

    def test_completed_scheduler_returns_without_idle_operation_wait(self):
        policy = self.policy(cidr='192.0.2.8/31')
        fixture = SyntheticSockets()
        started = fixture.clock.now
        result = self.collect(policy, fixture)
        self.assertEqual(result['completion'], 'complete')
        self.assertLess(fixture.clock.now - started, 2)

    def test_output_limit_is_shared_across_methods_owned_sockets_close(self):
        policy = self.policy(limits={'output_bytes': 6000})
        fixture = SyntheticSockets(lambda *_: 'hostile')
        fixture.clock.now += 1
        with fixture.install(schedule, transport, capability):
            scheduler = schedule.Scheduler(policy.networks[0], policy, fixture.clock.now + 10)
            scheduler.remaining_bytes = 7
            probes = scheduler.run()
        self.assertTrue(any(probe.outcome == 'output_limit' for probe in probes))
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        self.assertFalse(any(probe.observations for probe in probes if probe.probe_name.startswith('icmp_')))

    def test_interruption_selector_failure_and_expired_before_send_close_only_owned(self):
        policy = self.policy()
        fixture = SyntheticSockets(lambda *_: 'filtered')
        with fixture.install(schedule, transport, capability), patch.object(schedule.selectors, 'DefaultSelector') as factory:
            selector = MagicMock()
            factory.return_value.__enter__.return_value = selector
            selector.register.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                schedule.collect_methods(policy.networks[0], policy, fixture.clock.now + 20)
        self.assertTrue(all(sock.closed for sock in fixture.sockets))
        with patch('socket.socket', side_effect=AssertionError('expired no socket')), patch.object(transport.time, 'monotonic', return_value=10):
            attempt, result = transport.begin(policy.networks[0], '192.0.2.1', 2222, 10)
            self.assertIsNone(attempt)
            self.assertEqual(result[0], 'not_started')

    def test_icmp_golden_header_and_hostile_reply_validation(self):
        request = bytes.fromhex('0800f41503e90001')
        self.assertEqual(transport.checksum(request), 0)
        sock = MagicMock()
        attempt = transport.Attempt(sock, '192.0.2.1', None, 100, 1001, 1)
        reply = bytes.fromhex('0000fc1503e90001')
        # Generate checksum with the production Internet checksum to test matching separately.
        header = struct.pack('!BBHHH', 0, 0, 0, 1001, 1)
        reply = struct.pack('!BBHHH', 0, 0, transport.checksum(header), 1001, 1)
        self.assertTrue(transport._reply(attempt, reply, ('192.0.2.1', 0)))
        for packet, source in ((reply, ('198.51.100.1', 0)), (reply + b'payload', ('192.0.2.1', 0)),
                               (request, ('192.0.2.1', 0)), (reply[:-1], ('192.0.2.1', 0))):
            self.assertFalse(transport._reply(attempt, packet, source))

    def test_tcp_refusal_is_response_only_after_connect_not_socket_setup(self):
        policy = self.policy(icmp_echo=False, tcp_ports=[2222])
        with patch('socket.socket', side_effect=OSError(errno.ECONNREFUSED, 'synthetic local setup error')):
            attempt, result = transport.begin(policy.networks[0], '192.0.2.1', 2222, transport.time.monotonic() + 10)
        self.assertIsNone(attempt)
        self.assertEqual(result, ('unavailable', 'transport_socket_failed', False))
        fixture = SyntheticSockets(lambda *_: 'refused')
        result = self.collect(policy, fixture)
        self.assertEqual(len(self.evidence(policy, result)), 6)
        self.assertTrue(all(row['probe']['diagnostic_code'] == 'tcp_refused_response' for row in self.evidence(policy, result)))

    def test_persistence_failure_retains_history_and_output_receipt_rolls_back(self):
        policy = self.policy(cidr='192.0.2.8/31')
        first = self.collect(policy, SyntheticSockets())
        with storage.Store(policy) as store:
            before = store.connection.execute('SELECT COUNT(*) FROM batches').fetchone()[0]
        with patch.object(discovery, 'store_batch', side_effect=ValueError('synthetic persistence failure')):
            with self.assertRaises(ValueError):
                self.collect(policy, SyntheticSockets())
        small = replace(policy, limits=replace(policy.limits, output_bytes=100))
        with self.assertRaises(ValueError):
            self.collect(small, SyntheticSockets())
        with storage.Store(policy) as store:
            self.assertEqual(store.connection.execute('SELECT COUNT(*) FROM batches').fetchone()[0], before)
        self.assertEqual(len(self.evidence(policy, first)), 10)

    def test_original_later_lineage_and_foreign_methods_do_not_transfer_authority(self):
        policy = self.policy(cidr='192.0.2.8/31')
        first = self.collect(policy, SyntheticSockets())
        applied = reconcile.reconcile(policy, {'batch_id': first['batch_id']})
        second = self.collect(policy, SyntheticSockets())
        reconcile.reconcile(policy, {'batch_id': second['batch_id']})
        originals = self.evidence(policy, first)
        self.assertTrue(all(row['identity_state'] == 'subsequently_unresolved' for row in originals))
        self.assertTrue(all(row['application']['id'] == applied['id'] for row in originals))
        self.assertTrue(all(row['lineage']['batch_id'] == second['batch_id'] for row in originals))
        foreign = config.validate_policy({'store': {'shared_sqlite_path': str(policy.database)}}, self.home / 'foreign')
        rows = self.evidence(foreign, first)
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(not row['batch']['local_policy_context'] for row in rows))
        with patch('socket.socket', side_effect=AssertionError('foreign evidence is not a grant')):
            with self.assertRaises(ValueError):
                discovery.collect(foreign, {'network': 'lab', 'mode': 'ping'})

    def test_native_fixture_assertions_through_ordinary_local_public_handlers(self):
        # This checks harness logic only; actual native registration/admission is
        # still mandatory in test_acceptance and is never replaced by this adapter.
        import native_host_acceptance
        tools = importlib.import_module('atlas_test_plugin.tools')
        commands = importlib.import_module('atlas_test_plugin.commands')
        directory = self.home / 'network-atlas'
        directory.mkdir()
        raw = {'networks': {'lab': {'cidr': '192.0.2.0/29', 'discovery': {'ping': True}}}}
        (directory / 'config.yaml').write_text(json.dumps(raw))
        handler = tools.Handlers(self.home)
        class Adapter:
            def tool(self, name, params):
                return json.loads({'network_query': handler.query, 'network_discover': handler.discover}[name](params))
            def slash(self, text):
                return json.loads(handler.command(text))
            def cli(adapter, argv):
                import argparse
                import io
                from contextlib import redirect_stdout
                parser = argparse.ArgumentParser()
                commands.setup_parser(parser)
                output = io.StringIO()
                with redirect_stdout(output):
                    code = commands.run_command(parser.parse_args(argv), self.home)
                self.assertEqual(code, 0, output.getvalue())
                return json.loads(output.getvalue())
        native_host_acceptance.collect_methods(Adapter(), self.home, self.home)
        native_host_acceptance.reopen_methods(Adapter(), self.home)


if __name__ == '__main__':
    unittest.main()
