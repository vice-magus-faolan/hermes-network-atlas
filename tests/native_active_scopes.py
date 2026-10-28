# SPDX-License-Identifier: GPL-3.0-or-later
"""Active scope admission through stock native tool, slash and CLI adapters."""
from contextlib import ExitStack, closing
from dataclasses import replace
from ipaddress import ip_network
import json
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

from cumulative_acceptance import NativeAtlas
from native_host_acceptance import _modules
from synthetic_sockets import SyntheticSockets


def policy(cidr, *, allow_public=None, sockets=False) -> dict:
    network = {'cidr': cidr, 'allow_public': False,
               'discovery': {'passive': True, 'ping': True, 'icmp_echo': False, 'tcp_ports': [80, 443]},
               'endpoints': {'enabled': True, 'tcp_ports': [2222]}}
    if sockets:
        network['discovery'].update(icmp_echo=True, tcp_ports=[2222])
    if allow_public is not None:
        network['allow_public'] = allow_public
    return {'networks': {'lab': network}}


def dispatch(atlas, route, operation, value='lab', *, refused=False):
    if route == 'tool':
        if operation in {'ping', 'passive'}:
            return atlas.tool('network_discover', {'network': value, 'mode': operation})
        if operation == 'reconcile':
            return atlas.tool('network_reconcile', {'batch_id': value})
        key = {'check-endpoints': 'network', 'resume-endpoints': 'batch_id',
               'preview-endpoints': 'preview_batch_id', 'continue-endpoints': 'continue_batch_id'}[operation]
        return atlas.tool('network_check_endpoints', {key: value})
    if operation in {'ping', 'passive'}:
        text, argv = f'discover {value} {operation}', ['discover', '--network', value, '--mode', operation]
    elif operation == 'reconcile':
        text, argv = f'reconcile {value}', ['reconcile', '--batch-id', value]
    else:
        text, argv = f'{operation} {value}', [operation, value]
    return (atlas.slash(text) if route == 'slash'
            else atlas.cli(argv, expected_code=2 if refused else 0))


def history(database):
    if not database.exists():
        return None
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as connection:
        return list(connection.iterdump())


def refusal(result):
    assert 'networks.lab.allow_public' in result.get('error', ''), result
    assert not result.get('collection_performed') and not result.get('persisted'), result


def negative_scopes(atlas, database):
    # Another named network's grant cannot authorize lab. is_private is not an
    # RFC1918 classifier: documentation, loopback and reserved ranges stay denied.
    for cidr in ('8.8.8.0/24', '192.186.1.0/24', '192.0.2.0/24', '127.0.0.1/32',
                 '0.0.0.0/32', '224.0.0.0/24', '240.0.0.0/24', '100.64.0.0/24', '198.18.0.0/24'):
        for sockets in (False, True):
            raw = policy(cidr, sockets=sockets)
            if cidr != '8.8.8.0/24':
                raw['networks']['other'] = {'cidr': '8.8.4.0/31', 'allow_public': True}
            atlas.ctx.set_config('policy', raw)
            before = history(database)
            with patch('socket.socket', side_effect=AssertionError('refused socket')) as socket, \
                    patch('subprocess.Popen', side_effect=AssertionError('refused child')) as child:
                for route in ('tool', 'slash', 'cli'):
                    for operation in ('ping', 'check-endpoints'):
                        refusal(dispatch(atlas, route, operation, refused=True))
                status = atlas.slash('status')
                assert status['configured_scopes'][0]['allow_public'] is False, status
                options = status['guidance']['discovery_options']['items']
                assert all(item['parameters'] != {'network': 'lab', 'mode': 'ping'} for item in options)
                assert 'error' not in atlas.tool('network_map', {})
                socket.assert_not_called()
                child.assert_not_called()
            assert history(database) == before


def positive_scopes(atlas, modules):
    schedule, transport, capability, discovery = modules
    endpoints = sys.modules[schedule.__package__ + '.endpoints']
    for cidr, opt_in in (('192.168.1.0/24', None), ('10.1.1.0/31', None),
                         ('172.16.1.0/31', None), ('169.254.1.0/31', None), ('8.8.8.0/31', True)):
        atlas.ctx.set_config('policy', policy(cidr, allow_public=opt_in, sockets=True))
        for route in ('tool', 'slash', 'cli'):
            for operation in ('ping', 'check-endpoints'):
                fixture = SyntheticSockets()
                with fixture.install(schedule, transport, capability), ExitStack() as stack:
                    for module in (discovery, endpoints):
                        stack.enter_context(patch.object(module, 'time', fixture.clock))
                    result = dispatch(atlas, route, operation)
                assert result['persisted'] and 'error' not in result, result
                assert fixture.calls and all(sock.closed for sock in fixture.sockets)
        status = atlas.tool('network_query', {'view': 'status'})
        assert status['configured_scopes'][0]['allow_public'] is bool(opt_in)


def saved_work(atlas, modules, database):
    schedule, transport, capability, discovery = modules
    prefix = schedule.__package__ + '.'
    endpoints = sys.modules[prefix + 'endpoints']
    storage = sys.modules[prefix + 'storage']
    runner = sys.modules[prefix + 'probes']
    raw = policy('8.8.8.0/27', allow_public=True)
    raw['limits'] = {'operation_timeout_seconds': 2, 'host_timeout_seconds': 1}
    atlas.ctx.set_config('policy', raw)
    fixture = SyntheticSockets(lambda address, port: 'filtered')
    with fixture.install(schedule, transport, capability), ExitStack() as stack:
        for module in (endpoints, storage):
            stack.enter_context(patch.object(module, 'time', fixture.clock))
        saved = atlas.tool('network_check_endpoints', {'network': 'lab'})
    assert saved['queryable'] and saved['state_counts']['not_started'] > 0, saved

    def nmap(argv, *args, **kwargs):
        excluded = argv[argv.index('--exclude') + 1].split(',') if '--exclude' in argv else ()
        targets = [str(ip) for ip in ip_network(argv[-1]) if str(ip) not in excluded]
        hosts = ''.join('<host><status state="down" reason="no-response"/>'
                        f'<address addr="{ip}" addrtype="ipv4"/></host>' for ip in targets)
        count = len(targets)
        xml = ('<nmaprun>' + hosts + '<runstats><finished exit="success"/>'
               f'<hosts up="0" down="{count}" total="{count}"/></runstats></nmaprun>')
        return runner.CommandResult('success', xml.encode())

    # Exercise legacy Nmap admission as well as sockets, with synthetic output.
    with patch.object(discovery, 'run', nmap):
        ping = atlas.slash('discover lab ping')
    assert ping['persisted'] and ping['completion'] == 'partial', ping
    page = atlas.tool('network_query', {'view': 'endpoints', 'batch_id': saved['batch_id']})
    raw['networks']['lab']['allow_public'] = False
    atlas.ctx.set_config('policy', raw)
    before = history(database)
    with patch('socket.socket', side_effect=AssertionError('revoked socket')) as socket, \
            patch('subprocess.Popen', side_effect=AssertionError('revoked child')) as child:
        for route in ('tool', 'slash', 'cli'):
            for operation in ('preview-endpoints', 'continue-endpoints', 'reconcile'):
                value = ping['batch_id'] if operation == 'reconcile' else saved['batch_id']
                refusal(dispatch(atlas, route, operation, value, refused=True))
            resumed = dispatch(atlas, route, 'resume-endpoints', saved['batch_id'], refused=True)
            assert resumed['batch_id'] == saved['batch_id'] and resumed['persisted'], resumed
            assert not resumed['collection_performed'] and 'networks.lab.allow_public' in resumed['error'], resumed
        assert atlas.tool('network_query', {'view': 'endpoints', 'batch_id': saved['batch_id']}) == page
        status = atlas.cli(['status'])
        assert status['guidance']['reconcilable_batches']['items'] == []
        assert 'error' not in atlas.tool('network_map', {})
        socket.assert_not_called()
        child.assert_not_called()
    assert history(database) == before
    # Passive collection is still permitted for the same public scope, even
    # with active methods configured but no allow_public grant.
    with patch.object(discovery, 'run', return_value=runner.CommandResult('success', b'[]')):
        passive = atlas.cli(['discover', '--network', 'lab', '--mode', 'passive'])
    assert passive['persisted'] and passive['completion'] == 'complete', passive
    raw['networks']['lab']['allow_public'] = True
    atlas.ctx.set_config('policy', raw)
    assert atlas.cli(['resume-endpoints', saved['batch_id']])['queryable']
    assert 'error' not in atlas.tool('network_reconcile', {'batch_id': ping['batch_id']})
    fixture = SyntheticSockets()
    with fixture.install(schedule, transport, capability), patch.object(endpoints, 'time', fixture.clock):
        continued = atlas.slash('continue-endpoints ' + saved['batch_id'])
    assert continued['queryable'] and continued['collection_performed'] and fixture.calls, continued
    assert all(sock.closed for sock in fixture.sockets)
    assert atlas.tool('network_query', {'view': 'endpoints', 'batch_id': saved['batch_id']}) == page


def snapshots(atlas, modules, home):
    schedule, transport, _, discovery = modules
    config = sys.modules[schedule.__package__ + '.config']
    endpoints = sys.modules[schedule.__package__ + '.endpoints']
    omitted = policy('8.8.8.0/31')
    del omitted['networks']['lab']['allow_public']
    assert config.validate_policy(omitted, home).networks[0].allow_public is False
    for invalid in (1, 'true', [], None):
        raw = policy('8.8.8.0/31')
        raw['networks']['lab']['allow_public'] = invalid
        try:
            config.validate_policy(raw, home)
        except config.ConfigError as exc:
            assert 'networks.lab.allow_public' in str(exc)
        else:
            raise AssertionError('non-boolean opt-in accepted')
    checked = config.validate_policy(policy('8.8.8.0/31', allow_public=True), home)
    revoked = replace(checked, networks=(replace(checked.networks[0], allow_public=False),))
    with patch('socket.socket', side_effect=AssertionError('snapshot socket')) as socket, \
            patch('subprocess.Popen', side_effect=AssertionError('snapshot child')) as child:
        for action in (lambda: discovery.collect(revoked, {'network': 'lab', 'mode': 'ping'}),
                       lambda: endpoints.check(revoked, {'network': 'lab'}),
                       lambda: transport.begin_endpoint(revoked.networks[0], '8.8.8.0', 2222, 1e20)):
            try:
                action()
            except config.ConfigError as exc:
                assert 'networks.lab.allow_public' in str(exc)
            else:
                raise AssertionError('revoked immutable snapshot accepted')
        socket.assert_not_called()
        child.assert_not_called()
    # A public opt-in does not override excluded destinations or TCP 4403.
    for cidr in ('127.0.0.1/32', '0.0.0.0/32', '224.0.0.1/32', '240.0.0.1/32'):
        network = config.validate_policy(policy(cidr, allow_public=True), home).networks[0]
        assert transport.excluded(network, str(ip_network(cidr).network_address))
    raw = policy('8.8.8.0/31', allow_public=True)
    raw['networks']['lab']['endpoints']['tcp_ports'] = [4403]
    try:
        config.validate_policy(raw, home)
    except config.ConfigError:
        pass
    else:
        raise AssertionError('sensitive port accepted')


def run(home: Path, root: Path):
    atlas = NativeAtlas(root)
    modules = _modules()
    database = home / 'plugin-data' / 'network-atlas' / 'atlas.sqlite3'
    negative_scopes(atlas, database)
    positive_scopes(atlas, modules)
    saved_work(atlas, modules, database)
    snapshots(atlas, modules, home)
    atlas.manager.unload()
    print(json.dumps({'mode': 'active_scopes', 'native_scope_admission': True, 'network_denied': True}))
    return 0
