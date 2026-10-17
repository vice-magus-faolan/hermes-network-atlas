#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fresh native processes share endpoint evidence, never collection/SSH grants."""
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
    snapshot = scratch / 'endpoints.json'
    if mode == 'collect':
        schedule, transport, capability, _ = _modules()
        assert schedule.__package__ is not None
        endpoints = sys.modules[schedule.__package__ + '.endpoints']
        receipts = []
        for route in ('tool', 'slash', 'cli'):
            fixture = SyntheticSockets(lambda address, port: 'positive' if port == 22 else 'closed')
            with fixture.install(schedule, transport, capability), patch.object(endpoints, 'time', fixture.clock):
                if route == 'tool':
                    receipt = atlas.tool('network_check_endpoints', {'network': 'lab'})
                elif route == 'slash':
                    receipt = atlas.slash('check-endpoints lab')
                else:
                    receipt = atlas.cli(['check-endpoints', '--network', 'lab'])
            assert receipt['queryable'] and receipt['persisted'] and receipt['projected'], receipt
            assert all(sock.closed for sock in fixture.sockets)
            assert atlas.slash('resume-endpoints ' + receipt['batch_id'])['queryable']
            assert atlas.cli(['check-endpoints', '--batch-id', receipt['batch_id']])['queryable']
            receipts.append(receipt)
        page = atlas.cli(['query', '--query-json', '{"view":"endpoints"}'])
        assert page['total_count'] == 12 and not page['has_more'], page
        assert {row['state'] for row in page['endpoints']} == {'open', 'closed'}
        for params in ({'network': 'lab', 'port': 4403}, {'network': 'lab', 'source': 'user'},
                       {'network': 'lab', 'ssh_greeting': 'SSH-2.0-hostile\n' * 4096}):
            assert 'error' in atlas.tool('network_check_endpoints', params)
        snapshot.write_text(json.dumps({'page': page, 'batches': [receipt['batch_id'] for receipt in receipts]}))
    elif mode == 'reader':
        data = json.loads(snapshot.read_text())
        assert atlas.cli(['query', '--query-json', '{"view":"endpoints"}']) == data['page']
        assert atlas.tool('network_query', {'view': 'endpoints'}) == data['page']
        status = atlas.slash('status')
        assert status['known_devices'] == 0 and status['endpoint_count'] == 4 and status['endpoint_observation_count'] == 12
        assert status['authorized_for_atlas_ssh_inspection'] == [] and status['configured_networks'] == []
        for batch in data['batches']:
            result = atlas.cli(['check-endpoints', '--batch-id', batch], expected_code=2)
            assert 'error' in result and not result['applied']
        assert 'error' in atlas.tool('network_check_endpoints', {'network': 'lab'})
        assert 'error' in atlas.tool('network_inspect', {'target': 'lab'})
    elif mode == 'isolated':
        assert atlas.tool('network_query', {'view': 'endpoints'})['total_count'] == 0
        assert atlas.slash('status')['endpoint_count'] == 0
        assert not (home / 'network-atlas' / 'atlas.sqlite3').exists()
    else:
        raise ValueError('unknown fixture mode')
    assert atlas.tool('network_query', {})['devices'] == []
    atlas.manager.unload()
    print(json.dumps({'mode': mode, 'native_dispatch': True, 'network_denied': True}))


if __name__ == '__main__':
    main()
