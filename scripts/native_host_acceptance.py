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
                 ({'icmp_echo': False, 'tcp_ports': [2222]}, 'tcp', None),
                 ({'icmp_echo': True, 'tcp_ports': [2222, 22000]}, 'mixed', None),
                 ({'icmp_echo': True, 'tcp_ports': [2222]}, 'tcp', errno.EACCES)]
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
        fixture = SyntheticSockets(lambda address, port: 'filtered' if kind == 'icmp' and port is not None else 'positive',
                                   icmp_error=error)
        with fixture.install(schedule, transport, capability), patch.object(discovery, 'time', fixture.clock):
            result = _dispatch(atlas, route)
        assert result['persisted'] and not result['applied'], result
        assert all(sock.closed for sock in fixture.sockets)
        evidence = atlas.tool('network_query', {'view': 'unresolved', 'batch_id': result['batch_id']})
        rows = evidence['evidence']
        expected = 2 * (1 if kind != 'mixed' else 3)
        assert len(rows) == expected and not evidence['has_more'], evidence
        assert all(row['historical_responder_evidence'] and row['identity_state'] == 'never_reconciled' for row in rows)
        assert all(not row['current_address_candidate_device_ids'] for row in rows)
        assert rows[0]['batch']['probe_summary']['address_count'] == 2
        assert rows[0]['batch']['probe_summary']['responding_address_count'] == 2
        assert result['completion'] == ('complete' if error is None and kind != 'icmp' else 'partial')
        if kind == 'icmp':
            assert all(row['probe']['probe_name'].startswith('icmp_') for row in rows)
        if kind == 'tcp':
            assert all(row['probe']['probe_name'].startswith('tcp_2222_') for row in rows)
        records.append({'batch_id': result['batch_id'], 'evidence': evidence})
    return records


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
