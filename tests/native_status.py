# SPDX-License-Identifier: GPL-3.0-or-later
"""Truthful diagnostics and eligibility through stock native tool/slash/CLI adapters."""
from contextlib import ExitStack
import importlib
import json
import os
from unittest.mock import patch

from cumulative_acceptance import NativeAtlas


def statuses(atlas):
    return (atlas.tool('network_query', {'view': 'status'}), atlas.slash('status'), atlas.cli(['status']))


def availability(atlas, home):
    raw = {'networks': {
        'passive': {'cidr': '192.168.1.0/31', 'discovery': {'passive': True}},
        'legacy': {'cidr': '192.168.2.0/31', 'discovery': {'ping': True}},
        'sockets': {'cidr': '192.168.3.0/31', 'discovery': {'ping': True, 'icmp_echo': True, 'tcp_ports': [2222]},
                    'endpoints': {'enabled': True, 'tcp_ports': [2222], 'udp_ports': [22000]}},
        'icmp': {'cidr': '192.168.4.0/31', 'discovery': {'ping': True, 'icmp_echo': True, 'tcp_ports': []}}},
        'ssh': {'enabled': True, 'hosts': {'lab': {'alias': 'lab', 'inspect': True}}}}
    atlas.ctx.set_config('policy', raw)
    database = home / 'plugin-data' / 'network-atlas' / 'atlas.sqlite3'
    config_before = (home / 'config.yaml').read_bytes()
    fixture_bins = []
    for index, present in enumerate(((), ('ip',), ('ssh',), ('ip', 'nmap', 'ssh'))):
        directory = home.parent / f'status-bin-{index}'
        directory.mkdir()
        for name in ('ip', 'nmap', 'ssh'):
            binary = directory / name
            binary.write_text('#!/bin/sh\nexit 99\n')
            binary.chmod(0o700 if name in present else 0o600)
        fixture_bins.append((directory, present))
    # Exercise both no-store and populated-store reads; never initialize via status.
    for populated in (False, True):
        if populated:
            assert atlas.cli(['create', '--name', 'Synthetic status history'])['device_id']
        before = database.read_bytes() if database.exists() else None
        for directory, present in fixture_bins:
            with patch.dict(os.environ, {'PATH': str(directory)}):
                replies = statuses(atlas)
            assert replies[0] == replies[1] == replies[2]
            for result in replies:
                assert 'error' not in result, result
                assert 'collection_available' not in result and 'ssh_transport_available' not in result
                checked = result['availability']
                assert checked['executable_presence'] == {name: name in present for name in ('ip', 'nmap', 'ssh')}
                for method, name in (('passive', 'ip'), ('legacy_ping', 'nmap'), ('ssh_inspection', 'ssh')):
                    assert checked['methods'][method] == ('unverified' if name in present else 'missing_executable')
                for method in ('socket_ping', 'tcp_endpoints', 'udp_endpoints'):
                    assert checked['methods'][method] == 'unverified'
                assert checked['runtime'] == 'unverified'
                guidance = result['guidance']
                assert guidance['inspection_targets']['items'] == [
                    {'tool': 'network_inspect', 'parameters': {'target': 'lab'}}]
                assert guidance['discovery_options']['total_count'] == 4
                workflow = guidance['inventory_workflow']
                assert 'policy eligibility' in workflow and 'runtime availability' in workflow
                assert 'executable presence' in workflow and 'unverified' in workflow
                assert 'batch_id' in workflow and 'device ID' in workflow
                assert not result.get('discovery_performed')
                assert len(json.dumps(result).encode()) <= 1048576
            assert (database.read_bytes() if database.exists() else None) == before
            assert (home / 'config.yaml').read_bytes() == config_before
    # Presence cannot grant actions after policy revocation. Keep complete keys
    # because native set_config merges dictionaries rather than replacing them.
    for network in raw['networks'].values():
        network['discovery'] = {'passive': False, 'ping': False, 'icmp_echo': False}
        network['endpoints'] = {'enabled': False, 'tcp_ports': [], 'udp_ports': []}
    raw['ssh']['enabled'] = False
    atlas.ctx.set_config('policy', raw)
    with patch.dict(os.environ, {'PATH': str(fixture_bins[-1][0])}):
        for result in statuses(atlas):
            assert all(result['availability']['executable_presence'].values())
            assert result['guidance']['inspection_targets']['items'] == []
            assert result['guidance']['discovery_options']['items'] == []


def eligibility(atlas, home):
    database = home / 'plugin-data' / 'network-atlas' / 'atlas.sqlite3'
    cases = (
        ('192.0.2.0/31', False, False, [], False),
        ('2001:db8::/64', False, False, [], False),
        ('192.0.2.0/31', True, False, [], False),
        ('192.0.2.0/31', False, True, [], True),
        ('192.0.2.0/31', False, False, [22000], True),
        ('192.168.1.0/31', False, False, [], False),
    )
    for cidr, ping, tcp, udp, endpoints in cases:
        atlas.ctx.set_config('policy', {'networks': {'lab': {
            'cidr': cidr, 'allow_public': False,
            'discovery': {'passive': True, 'ping': ping, 'icmp_echo': False, 'tcp_ports': [80, 443]},
            'endpoints': {'enabled': tcp, 'tcp_ports': [2222] if tcp else [], 'udp_ports': udp}}}})
        config_before = (home / 'config.yaml').read_bytes()
        results = statuses(atlas)
        for status in results:
            options = status['guidance']['discovery_options']['items']
            assert options == [{'tool': 'network_discover', 'parameters': {'network': 'lab', 'mode': 'passive'}}]
        for operation, needs_opt_in in (('ping', ping), ('check-endpoints', endpoints)):
            if operation == 'ping':
                replies = (atlas.tool('network_discover', {'network': 'lab', 'mode': 'ping'}),
                           atlas.slash('discover lab ping'),
                           atlas.cli(['discover', '--network', 'lab', '--mode', 'ping'], expected_code=2))
            else:
                replies = (atlas.tool('network_check_endpoints', {'network': 'lab'}),
                           atlas.slash('check-endpoints lab'),
                           atlas.cli(['check-endpoints', 'lab'], expected_code=2))
            for result in replies:
                assert 'error' in result, result
                assert ('networks.lab.allow_public' in result['error']) == needs_opt_in, result
                if not needs_opt_in:
                    assert ('network/mode' if operation == 'ping' else 'network.endpoints') in result['error'], result
                assert not result.get('persisted') and not result.get('collection_performed')
        assert not database.exists()
        assert (home / 'config.yaml').read_bytes() == config_before
    # A deliberately authorized public active method remains a useful suggestion;
    # passive IPv6 above must never be offered an ineffective public opt-in.
    atlas.ctx.set_config('policy', {'networks': {'lab': {'cidr': '192.0.2.0/31', 'allow_public': True,
                                                         'discovery': {'ping': True}}}})
    for result in statuses(atlas):
        assert {'tool': 'network_discover', 'parameters': {'network': 'lab', 'mode': 'ping'}} in (
            result['guidance']['discovery_options']['items'])


def run(home, root, mode):
    atlas = NativeAtlas(root)
    loaded = next(item for item in atlas.manager._plugins.values() if item.manifest.name == 'network-atlas')
    storage = importlib.import_module(loaded.module.__name__ + '.storage')
    original = storage.Store.__init__
    def read_only_store(self, policy, **kwargs):
        assert not kwargs.get('writable', False), 'status attempted a writable store'
        return original(self, policy, **kwargs)
    with ExitStack() as stack:
        stack.enter_context(patch('subprocess.Popen', side_effect=AssertionError('diagnostic executed a process')))
        stack.enter_context(patch('socket.socket', side_effect=AssertionError('diagnostic opened a socket')))
        if mode == 'status_eligibility':
            stack.enter_context(patch.object(storage.Store, '__init__', read_only_store))
            eligibility(atlas, home)
        else:
            # The fixture create is an intentional native write; guard reads
            # separately so a no-op byte comparison cannot hide attempted writes.
            original_statuses = statuses
            def guarded_statuses(current):
                with patch.object(storage.Store, '__init__', read_only_store):
                    return original_statuses(current)
            with patch(__name__ + '.statuses', guarded_statuses):
                availability(atlas, home)
    atlas.manager.unload()
    print(json.dumps({'mode': mode, 'native_dispatch': True, 'read_only_no_contact': True}))
    return 0
