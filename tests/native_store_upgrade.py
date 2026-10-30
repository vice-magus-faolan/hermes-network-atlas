#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Operator schema choice and endpoint pause through real native registrations."""
import importlib
import json
import os
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

from cumulative_acceptance import NativeAtlas
from native_host_acceptance import _modules
from network_guard import deny_network
from synthetic_sockets import SyntheticSockets


def history(storage, policy):
    with storage.Store(policy) as store:
        return {table: [list(row) for row in store.connection.execute(f'SELECT * FROM {table} ORDER BY rowid')]
                for table in (*storage.IMMUTABLE_TABLES, 'endpoint_observations', 'endpoint_continuations',
                              'devices', 'interfaces', 'addresses', 'relations', 'aliases')}


def schema(storage, policy):
    with storage.Store(policy) as store:
        return store.schema_version, [list(row) for row in store.connection.execute(
            'SELECT * FROM sqlite_master ORDER BY name')]


def collect(atlas, schedule, transport, capability, endpoints, *, response='positive'):
    fixture = SyntheticSockets(udp_response=lambda a, p: response)
    with fixture.install(schedule, transport, capability), patch.object(endpoints, 'time', fixture.clock):
        receipt = atlas.cli(['check-endpoints', 'lab'])
    assert receipt['queryable'], receipt
    assert all(sock.closed for sock in fixture.sockets)
    return receipt, fixture


def refuse_old(atlas, storage, policy, transport):
    before, ddl = history(storage, policy), schema(storage, policy)
    with patch.object(transport.socket, 'socket', side_effect=AssertionError('schema refusal socket')), \
            patch('subprocess.Popen', side_effect=AssertionError('schema refusal subprocess')):
        results = [atlas.tool('network_check_endpoints', {'network': 'lab'}),
                   atlas.slash('check-endpoints lab'),
                   atlas.cli(['check-endpoints', 'lab'], expected_code=2),
                   atlas.tool('network_discover', {'network': 'lab', 'mode': 'passive'}),
                   atlas.cli(['discover', '--network', 'lab', '--mode', 'ping'], expected_code=2),
                   atlas.tool('network_inspect', {'target': 'lab-router'}),
                   atlas.cli(['create', '--name', 'Refused write'], expected_code=2)]
    for result in results:
        assert 'upgrade-store --writers-stopped' in result['error'], result
        assert not result['persisted'] and not result['applied'], result
    assert history(storage, policy) == before and schema(storage, policy) == ddl
    assert atlas.cli(['query'])['devices']
    assert atlas.slash('status')['endpoint_observation_count'] == 2
    assert 'error' in atlas.slash('upgrade-store --writers-stopped')
    assert 'error' in atlas.tool('network_check_endpoints', {'network': 'lab', 'upgrade': True})
    try:
        atlas.parser.parse_args(['upgrade-store'])
    except SystemExit as error:
        assert error.code == 2
    else:
        raise AssertionError('upgrade requires stopped-writer confirmation')
    assert history(storage, policy) == before and schema(storage, policy) == ddl
    return before, ddl


def pause_and_udp(atlas, config, schedule, transport, capability, endpoints):
    raw = atlas.ctx.get_config('policy', {})
    raw['networks']['lab']['endpoints'] = {'enabled': False, 'tcp_ports': [22000], 'udp_ports': [22000]}
    atlas.ctx.set_config('policy', raw)
    with patch.object(transport.socket, 'socket', side_effect=AssertionError('paused native socket')):
        for result in (atlas.tool('network_check_endpoints', {'network': 'lab'}),
                       atlas.slash('check-endpoints lab'), atlas.cli(['check-endpoints', 'lab'], expected_code=2)):
            assert 'network.endpoints' in result['error'] and not result['persisted'], result
    assert config.load_policy(atlas.ctx).networks[0].endpoint_methods == ()
    # Native dictionary writes merge: explicitly replace the retained TCP list.
    raw['networks']['lab']['endpoints'] = {'enabled': True, 'tcp_ports': [], 'udp_ports': [22000]}
    atlas.ctx.set_config('policy', raw)
    receipt, fixture = collect(atlas, schedule, transport, capability, endpoints, response='malformed')
    assert {protocol for _, _, protocol, _ in fixture.protocol_calls} == {transport.socket.IPPROTO_UDP}
    rows = atlas.tool('network_query', {'view': 'endpoints', 'batch_id': receipt['batch_id']})['endpoints']
    assert len(rows) == 2
    assert all(r['diagnostic_code'] == 'udp_nonempty_reply_inconclusive'
               and r['state'] == 'no_response' and not r['qualified']
               and r['coverage'] == 'attempted_address_port_only' for r in rows), rows
    latest = atlas.slash('status')['last_collection']
    assert {p['diagnostic_code'] for p in latest['probes']} == {'udp_nonempty_reply_inconclusive'}


def prepare_upgrade(atlas, storage, policy, transport, schedule, capability, endpoints, version):
    """Produce a populated old schema and prove pre-effect upgrade refusal."""
    migration = {3: '_migrate_endpoint_protocols', 4: '_migrate_relation_indexes',
                 5: '_migrate_observation_indexes'}[version]
    with patch.object(storage, 'SCHEMA_VERSION', version), patch.object(storage, migration, return_value=None):
        source = atlas.cli(['create', '--name', 'Historical source'])['device_id']
        target = atlas.cli(['create', '--name', 'Historical target'])['device_id']
        atlas.update(source, 'relationship', {'target_device': target, 'relationship_type': 'hosted_on'})
        old, _ = collect(atlas, schedule, transport, capability, endpoints)
    before, ddl = refuse_old(atlas, storage, policy, transport)
    assert ddl[0] == version
    names = {row[1] for row in ddl[1]}
    assert 'observation_batch' not in names
    assert ({'relation_source_device', 'relation_target_device'} <= names) == (version == 5)
    return old, before, ddl


def assert_relation_indexes(storage, policy):
    with storage.Store(policy) as store:
        for name, columns in (('relation_source_device', ['source_device']),
                              ('relation_target_device', ['target_device']),
                              ('observation_batch', ['batch_id', 'entity_id'])):
            assert [row['name'] for row in store.connection.execute(f'PRAGMA index_info({name})')] == columns


def main():
    root, mode = Path(sys.argv[1]), sys.argv[2]
    home, scratch = Path(os.environ['HERMES_HOME']), Path(os.environ['TMPDIR'])
    assert home.is_relative_to(scratch) and (scratch / 'synthetic-atlas-home').is_file()
    deny_network()
    atlas = NativeAtlas(root)
    schedule, transport, capability, _ = _modules()
    package = schedule.__package__
    assert package is not None
    config, storage, endpoints, conversion = (importlib.import_module(package + '.' + name) for name in
                                               ('config', 'storage', 'endpoints', 'conversion'))
    raw = atlas.ctx.get_config('policy', {})
    raw['networks']['lab'].update({'cidr': '192.0.2.8/31', 'allow_public': True,
                                 'endpoints': {'enabled': True, 'tcp_ports': [22000]}})
    atlas.ctx.set_config('policy', raw)
    policy = config.load_policy(atlas.ctx)
    saved = scratch / 'upgrade.json'
    if mode in {'store_upgrade', 'store_upgrade_indexes', 'store_upgrade_batch_indexes'}:
        version = {'store_upgrade': 3, 'store_upgrade_indexes': 4, 'store_upgrade_batch_indexes': 5}[mode]
        old, before, ddl = prepare_upgrade(atlas, storage, policy, transport, schedule, capability, endpoints, version)
        # Legacy conversion copies exact old bytes/logical schema; it never
        # silently upgrades the source OR the copied destination on cold retry.
        copied = scratch / 'legacy-copy.sqlite3'
        assert conversion._copy_store(policy.database, copied, home)
        assert not conversion._copy_store(policy.database, copied, home)
        from dataclasses import replace
        assert history(storage, replace(policy, database=copied)) == before
        assert schema(storage, replace(policy, database=copied)) == ddl
        migrate = storage._migrate_observation_indexes
        def interrupted(connection):
            migrate(connection)
            raise sqlite3.OperationalError('synthetic interruption after index creation')
        with patch.object(storage, '_migrate_observation_indexes', interrupted):
            failed = atlas.cli(['upgrade-store', '--writers-stopped'], expected_code=2)
        assert not failed['persisted'] and schema(storage, policy) == ddl
        assert history(storage, policy) == before
        saved.write_text(json.dumps({'history': before, 'schema': ddl, 'old_batch': old['batch_id']}))
    elif mode in {'store_upgrade_reopen', 'store_upgrade_indexes_reopen', 'store_upgrade_batch_indexes_reopen'}:
        data = json.loads(saved.read_text())
        assert history(storage, policy) == data['history']
        assert list(schema(storage, policy)) == data['schema']
        upgraded = atlas.cli(['upgrade-store', '--writers-stopped'])
        assert upgraded == {'upgraded': True, 'schema_version': 6, 'collection_performed': False}
        assert schema(storage, policy)[0] == 6
        assert_relation_indexes(storage, policy)
        assert history(storage, policy) == data['history']
        ddl = schema(storage, policy)
        assert atlas.cli(['upgrade-store', '--writers-stopped']) == upgraded
        assert schema(storage, policy) == ddl and history(storage, policy) == data['history']
        old = atlas.tool('network_query', {'view': 'endpoints', 'batch_id': data['old_batch']})
        assert old['total_count'] == 2 and all(r['protocol'] == 'tcp' for r in old['endpoints'])
        atlas.cli(['create', '--name', 'Current writer'])
        assert len(atlas.cli(['query'])['devices']) == 3
        pause_and_udp(atlas, config, schedule, transport, capability, endpoints)
    else:
        raise ValueError('unknown fixture mode')
    atlas.manager.unload()
    print(json.dumps({'mode': mode, 'fresh_native_process_persistence': mode.endswith('_reopen')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
