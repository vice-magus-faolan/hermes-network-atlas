# SPDX-License-Identifier: GPL-3.0-or-later
"""Admitted installed module transport fixtures via REAL native public dispatch."""
from __future__ import annotations

import errno
import json
from pathlib import Path
import sys
from unittest.mock import patch

from synthetic_sockets import SyntheticSockets


def _modules():
    schedule = next(module for name, module in sys.modules.items() if name.endswith('.host_schedule'))
    package = schedule.__package__
    assert package is not None
    return tuple(sys.modules[package + '.' + name] for name in
                 ('host_schedule', 'host_transport', 'host_discovery', 'discovery'))


def collect_methods(atlas, home: Path, root: Path) -> None:
    """Collect three public routes per policy; never use a production socket."""
    path = home / 'network-atlas' / 'config.yaml'
    original = path.read_bytes()
    scenarios = [({'icmp_echo': True, 'tcp_ports': [80, 443]}, 'icmp', None),
                 ({'icmp_echo': True, 'tcp_ports': []}, 'icmp', None),
                 ({'icmp_echo': False, 'tcp_ports': [2222]}, 'tcp', None),
                 ({'icmp_echo': False, 'tcp_ports': [22000]}, 'tcp', None),
                 ({'icmp_echo': True, 'tcp_ports': [2222, 22000]}, 'mixed', None),
                 ({'icmp_echo': True, 'tcp_ports': [80, 443, 2222, 22000]}, 'mixed', None),
                 ({'icmp_echo': True, 'tcp_ports': [2222]}, 'tcp', errno.EACCES),
                 ({'icmp_echo': True, 'tcp_ports': [2222]}, 'tcp', errno.EPROTONOSUPPORT),
                 ({'icmp_echo': True, 'tcp_ports': [80, 443, 2222, 22000]}, 'filtered', None)]
    records = []
    try:
        for methods, kind, error in scenarios:
            raw = json.loads(original)
            raw['networks']['methodlab'] = {'cidr': '192.0.2.8/31', 'discovery': {'ping': True, **methods}}
            path.write_text(json.dumps(raw))
            records.extend(_scenario(atlas, methods, kind, error))
        (root / 'host-methods.json').write_text(json.dumps(records, sort_keys=True))
    finally:
        path.write_bytes(original)


def _scenario(atlas, methods, kind, error):
    schedule, transport, capability, discovery = _modules()
    records = []
    for route in ('tool', 'slash', 'cli'):
        fixture = SyntheticSockets(lambda address, port: _response(kind, port), icmp_error=error)
        with fixture.install(schedule, transport, capability), patch.object(discovery, 'time', fixture.clock):
            result = _dispatch(atlas, route)
        assert result['persisted'] and not result['applied'], result
        assert all(sock.closed for sock in fixture.sockets)
        evidence = atlas.tool('network_query', {'view': 'unresolved', 'batch_id': result['batch_id']})
        rows = evidence['evidence']
        expected = _expected_positives(methods, kind)
        assert len(rows) == expected and not evidence['has_more'], evidence
        assert all(row['historical_responder_evidence'] and row['identity_state'] == 'never_reconciled' for row in rows)
        assert all(not row['current_address_candidate_device_ids'] for row in rows)
        _check_counts(atlas, methods, kind, error, result, fixture)
        if kind == 'icmp':
            assert all(row['probe']['probe_name'].startswith('icmp_') for row in rows)
        if kind == 'tcp':
            assert all(row['probe']['probe_name'].startswith('tcp_' + str(methods['tcp_ports'][0]) + '_') for row in rows)
        records.append({'batch_id': result['batch_id'], 'evidence': evidence})
    return records


def _response(kind, port):
    if kind == 'filtered' or kind == 'icmp' and port is not None:
        return 'filtered'
    return 'positive'


def _expected_positives(methods, kind):
    if kind == 'filtered':
        return 0
    if kind == 'mixed':
        return 2 * (len(methods['tcp_ports']) + 1)
    return 2


def _check_counts(atlas, methods, kind, error, result, fixture):
    summary = atlas.tool('network_query', {'view': 'status'})['last_discovery']['probe_summary']
    assert summary['address_count'] == 2
    assert summary['responding_address_count'] == (0 if kind == 'filtered' else 2)
    completion = 'partial'
    if kind == 'filtered':
        completion = 'failed'
    elif error is None and (kind != 'icmp' or not methods['tcp_ports']):
        completion = 'complete'
    assert result['completion'] == completion, result
    assert fixture.peak <= 4
    assert len({(address, port) for _, address, port in fixture.calls}) == len(fixture.calls)
    requested = set(methods['tcp_ports'])
    if methods['icmp_echo'] and error is None:
        requested.add(None)
    assert {port for _, _, port in fixture.calls} == requested


def _dispatch(atlas, route):
    if route == 'tool':
        return atlas.tool('network_discover', {'network': 'methodlab', 'mode': 'ping'})
    if route == 'slash':
        return atlas.slash('discover methodlab ping')
    return atlas.cli(['discover', '--network', 'methodlab', '--mode', 'ping'])


def reopen_methods(atlas, root: Path) -> None:
    """Read installed persisted method/time/identity evidence without rediscovery."""
    for record in json.loads((root / 'host-methods.json').read_text()):
        assert atlas.tool('network_query', {'view': 'unresolved', 'batch_id': record['batch_id']}) == record['evidence']
