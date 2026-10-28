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
            fixture = SyntheticSockets(lambda address, port: 'positive' if port == 22 else 'closed',
                                       udp_response=lambda address, port: 'positive' if port == 22000 else 'closed')
            with fixture.install(schedule, transport, capability), patch.object(endpoints, 'time', fixture.clock):
                if route == 'tool':
                    receipt = atlas.tool('network_check_endpoints', {'network': 'lab'})
                elif route == 'slash':
                    receipt = atlas.slash('check-endpoints lab')
                else:
                    receipt = atlas.cli(['check-endpoints', 'lab'])
            assert receipt['queryable'] and receipt['persisted'] and receipt['projected'], receipt
            assert receipt['completion'] == 'complete' and receipt['observation_count'] == 1792, receipt
            assert receipt['state_counts'] == {'open': 508, 'closed': 1270, 'no_response': 0,
                                               'unavailable': 14, 'not_started': 0}, receipt
            assert all(sock.closed for sock in fixture.sockets)
            assert fixture.peak <= 4
            assert len(fixture.protocol_calls) == len({(a, protocol, p) for _, a, protocol, p in
                                                       fixture.protocol_calls}) == 1778
            assert {p for _, _, p in fixture.calls} == {22, 2222, 8006, 8384, 21027, 22000}
            assert all(a not in {'192.168.1.0', '192.168.1.255'} for _, a, _ in fixture.calls)
            assert all(b[0] - a[0] >= 1 / 32 - 1e-7
                       for a, b in zip(fixture.calls, fixture.calls[1:], strict=False))
            for resumed in (atlas.tool('network_check_endpoints', {'batch_id': receipt['batch_id']}),
                            atlas.slash('resume-endpoints ' + receipt['batch_id']),
                            atlas.cli(['resume-endpoints', receipt['batch_id']])):
                assert resumed['queryable'] and not resumed['collection_performed']
            receipts.append(receipt)
        page = atlas.cli(['query', '--query-json', '{"view":"endpoints"}'])
        assert page['total_count'] == 5376 and page['has_more'], page
        rows = []
        for offset in range(0, page['total_count'], 100):
            part = atlas.tool('network_query', {'view': 'endpoints', 'limit': 100, 'offset': offset})
            assert part['total_count'] == 5376
            assert part['has_more'] == (offset + len(part['endpoints']) < 5376)
            rows.extend(part['endpoints'])
        assert len(rows) == len({row['probe_id'] for row in rows}) == 5376
        assert {row['state'] for row in rows} == {'open', 'closed', 'unavailable'}
        assert {row['port'] for row in rows} == {22, 2222, 8006, 8384, 21027, 22000}
        assert {row['protocol'] for row in rows} == {'tcp', 'udp'}
        assert {row['probe_method'] for row in rows} == {'tcp_connect', 'udp_empty_datagram_v1'}
        assert {row['policy_context'] for row in rows} == {str(home)}
        assert {row['scope_value'] for row in rows} == {'192.168.1.0/24'}
        status = atlas.slash('status')
        assert status['configured_scopes'][0]['tcp_ports'] == [80, 443]
        assert status['configured_scopes'][0]['ping'] is False
        assert status['configured_scopes'][0]['endpoint_ports'] == [22, 2222, 8006, 8384, 22000]
        assert status['configured_scopes'][0]['endpoint_udp_ports'] == [21027, 22000]
        exported = atlas.tool('network_map', {'format': 'markdown', 'export': True})
        assert '192.168.1.' not in exported['content']  # no invented endpoint/device association
        assert all(Path(path).is_relative_to(home) and Path(path).is_file() for path in exported['exports'])
        for params in ({'network': 'lab', 'batch_id': receipts[0]['batch_id']},
                       {'network': 'lab', 'port': 4403}, {'network': 'lab', 'source': 'user'},
                       {'network': 'lab', 'ssh_greeting': 'SSH-2.0-hostile\n' * 4096}):
            assert 'error' in atlas.tool('network_check_endpoints', params)
        snapshot.write_text(json.dumps({'page': page, 'batches': [receipt['batch_id'] for receipt in receipts]}))
    elif mode == 'reader':
        data = json.loads(snapshot.read_text())
        assert atlas.cli(['query', '--query-json', '{"view":"endpoints"}']) == data['page']
        assert atlas.tool('network_query', {'view': 'endpoints'}) == data['page']
        status = atlas.slash('status')
        assert (status['known_devices'] == 0 and status['endpoint_count'] == 1792
                and status['endpoint_observation_count'] == 5376)
        assert status['authorized_for_atlas_ssh_inspection'] == [] and status['configured_networks'] == []
        for batch in data['batches']:
            result = atlas.cli(['resume-endpoints', batch], expected_code=2)
            assert 'error' in result and not result['applied']
        assert 'error' in atlas.tool('network_check_endpoints', {'network': 'lab'})
        assert 'error' in atlas.tool('network_inspect', {'target': 'lab'})
    elif mode == 'isolated':
        assert atlas.tool('network_query', {'view': 'endpoints'})['total_count'] == 0
        assert atlas.slash('status')['endpoint_count'] == 0
        assert not (home / 'plugin-data' / 'network-atlas' / 'atlas.sqlite3').exists()
    else:
        raise ValueError('unknown fixture mode')
    assert atlas.tool('network_query', {})['devices'] == []
    atlas.manager.unload()
    print(json.dumps({'mode': mode, 'native_dispatch': True, 'network_denied': True}))


if __name__ == '__main__':
    main()
