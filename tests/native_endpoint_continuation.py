#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Timed-out native producer -> explicit subset -> cold owner/shared/isolated reads."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

from cumulative_acceptance import NativeAtlas
from native_host_acceptance import _modules
from network_guard import deny_network
from synthetic_sockets import SyntheticSockets


def main():
    root, mode = Path(sys.argv[1]), sys.argv[2]
    home, scratch = Path(os.environ['HERMES_HOME']), Path(os.environ['TMPDIR'])
    assert home.is_relative_to(scratch) and (scratch / 'synthetic-atlas-home').is_file()
    deny_network()
    atlas = NativeAtlas(root)
    schedule, transport, capability, _ = _modules()
    assert schedule.__package__ is not None
    prefix = schedule.__package__ + '.'
    endpoints = sys.modules[prefix + 'endpoints']
    storage = sys.modules[prefix + 'storage']
    snapshot = scratch / 'continuation.json'
    if mode == 'collect':
        fixture = SyntheticSockets(lambda address, port: 'closed' if address == '192.0.2.1' else 'filtered')
        with fixture.install(schedule, transport, capability), ExitStack() as stack:
            for module in (endpoints, storage):
                stack.enter_context(patch.object(module, 'time', fixture.clock))
            first = atlas.tool('network_check_endpoints', {'network': 'lab'})
        assert first['queryable'] and first['state_counts']['not_started'] > 0, first
        assert first['state_counts']['no_response'] > 0
        assert all(sock.closed for sock in fixture.sockets)
        original = atlas.tool('network_query', {'view': 'endpoints', 'batch_id': first['batch_id'], 'limit': 100})
        database = scratch / 'shared.sqlite3'
        before = database.read_bytes()
        preview = atlas.cli(['preview-endpoints', first['batch_id']])
        assert database.read_bytes() == before
        remaining = {(r['address'], r['port']) for r in original['endpoints'] if r['state'] == 'not_started'}
        assert {(r['address'], r['port']) for r in preview['remaining']} == remaining
        fixture = SyntheticSockets()
        # The lazy continuation import is ours, not a replacement native runtime.
        __import__(prefix + 'endpoint_continuation')
        continuation = sys.modules[prefix + 'endpoint_continuation']
        with fixture.install(schedule, transport, capability), ExitStack() as stack:
            for module in (endpoints, storage, continuation):
                stack.enter_context(patch.object(module, 'time', fixture.clock))
            second = atlas.slash('continue-endpoints ' + first['batch_id'])
        assert second['queryable'] and second['collection_performed'], second
        assert {(a, p) for _, a, p in fixture.calls} == remaining
        assert all(sock.closed for sock in fixture.sockets)
        child = atlas.tool('network_query', {'view': 'endpoints', 'batch_id': second['batch_id'], 'limit': 100})
        assert child['total_count'] == len(remaining)
        assert min(r['started_at'] for r in child['endpoints']) > max(r['checked_at'] for r in original['endpoints'])
        assert atlas.tool('network_query', {'view': 'endpoints', 'batch_id': first['batch_id'],
                                           'limit': 100}) == original
        progress = atlas.cli(['preview-endpoints', second['batch_id']])
        assert progress['state'] == 'exhausted' and progress['progress']['still_unattempted'] == 0
        ancestor = atlas.slash('preview-endpoints ' + first['batch_id'])
        assert ancestor['successor_batch_id'] == second['batch_id']
        assert ancestor['progress'] == preview['progress']
        assert ancestor['progress']['scope'] == 'selected_batch_ancestry'
        page = atlas.tool('network_query', {'view': 'endpoints', 'limit': 100})
        snapshot.write_text(json.dumps({'first': first, 'second': second, 'original': original,
                                       'progress': progress, 'page': page}))
    elif mode == 'owner':
        data = json.loads(snapshot.read_text())
        assert atlas.slash('preview-endpoints ' + data['second']['batch_id']) == data['progress']
        for resumed in (atlas.cli(['continue-endpoints', data['first']['batch_id']]),
                        atlas.tool('network_check_endpoints', {'batch_id': data['second']['batch_id']})):
            assert resumed['queryable'] and not resumed['collection_performed'], resumed
        exhausted = atlas.tool('network_check_endpoints', {'continue_batch_id': data['second']['batch_id']})
        assert exhausted['state'] == 'exhausted' and not exhausted['collection_performed']
        assert atlas.tool('network_query', {'view': 'endpoints', 'limit': 100}) == data['page']
    elif mode == 'reader':
        data = json.loads(snapshot.read_text())
        assert atlas.tool('network_query', {'view': 'endpoints', 'limit': 100}) == data['page']
        assert atlas.slash('status')['configured_networks'] == []
        for key in ('preview_batch_id', 'continue_batch_id', 'batch_id'):
            assert 'error' in atlas.tool('network_check_endpoints', {key: data['first']['batch_id']})
    elif mode == 'isolated':
        assert atlas.tool('network_query', {'view': 'endpoints'})['total_count'] == 0
        assert 'error' in atlas.tool('network_check_endpoints', {'preview_batch_id': 'missing'})
        assert not (home / 'plugin-data' / 'network-atlas' / 'atlas.sqlite3').exists()
    else:
        raise ValueError('unknown fixture mode')
    atlas.manager.unload()
    print(json.dumps({'mode': mode, 'native_dispatch': True, 'synthetic_continuation': True, 'network_denied': True}))


if __name__ == '__main__':
    main()
