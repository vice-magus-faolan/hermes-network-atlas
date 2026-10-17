# SPDX-License-Identifier: GPL-3.0-or-later
"""Named TCP checks -> immutable batch -> endpoint projection -> fresh readback.

No service/identity inference or application bytes. Persistence is the recovery
boundary; application uses the existing unique-per-batch transactional marker.
"""
from __future__ import annotations

from ipaddress import ip_network
import json
import re
import sqlite3
import time

from .batches import Probe, _scope, _validate_probes, store_batch
from .config import NAME_PATTERN, Network, Policy, validate_network
from .host_schedule import Scheduler
from .storage import Store, encode, identifier, response_json, timestamp, utc_now

STATES = ('open', 'closed', 'no_response', 'unavailable', 'not_started')
RESULTS = {
    ('success', 'tcp_connected_response'): ('open', True),
    ('success', 'tcp_refused_response'): ('closed', True),
    ('timeout', 'effective_transport_deadline'): ('no_response', False),
    ('not_started', 'effective_deadline_before_start'): ('not_started', False),
    ('not_started', 'operation_deadline_exceeded'): ('not_started', False),
    ('not_started', 'host_deadline_before_start'): ('not_started', False),
    **{('unavailable', code): ('unavailable', False) for code in (
        'destination_excluded', 'transport_permission_denied', 'transport_protocol_unsupported', 'transport_socket_failed')},
}


def network_policy(policy: Policy, name: str) -> Network:
    """Endpoint grants are independent of ping, ICMP, legacy ports and SSH."""
    network = next((item for item in policy.networks if item.name == name), None)
    if network is None:
        raise ValueError('unknown endpoint scope')
    validate_network(network)
    if not network.endpoint_ports:
        raise ValueError('endpoint checks disabled')
    if ip_network(network.cidr).num_addresses * len(network.endpoint_ports) > policy.limits.observations:
        raise ValueError('endpoint scope exceeds record budget')
    return network


def plans(network: Network) -> dict[str, tuple[str, int]]:
    """Exact code-owned grid, including excluded/unstarted destinations as evidence."""
    return {f'tcp_{port}_{index}': (str(address), port)
            for index, address in enumerate(ip_network(network.cidr)) for port in network.endpoint_ports}


def validate_probes(policy: Policy, name: str, probes: tuple[Probe, ...]) -> dict[str, tuple[str, int]]:
    """Reject missing/duplicate/forged evidence before storage or projection."""
    expected = plans(network_policy(policy, name))
    if len(probes) != len(expected) or {probe.probe_name for probe in probes} != set(expected):
        raise ValueError('incomplete endpoint accounting or changed port policy')
    for probe in probes:
        if (probe.outcome, probe.diagnostic_code) not in RESULTS or probe.observations or probe.evidence_kind != 'tcp_endpoint':
            raise ValueError('invalid endpoint evidence')
    return expected


def _owned_batch(store: Store, batch_id: str):
    batch = store.require('batches', batch_id)
    if batch['collector'] != 'tcp_endpoint' or batch['policy_context'] != str(store.policy.home):
        raise ValueError('not locally owned endpoint evidence')
    return batch


def _stored(store: Store, batch_id: str):
    batch = _owned_batch(store, batch_id)
    kind, scope, _ = _scope(store, 'tcp_endpoint', batch['scope_name'])
    if (batch['scope_kind'], batch['scope_value']) != (kind, scope):
        raise ValueError('endpoint scope changed')
    network_policy(store.policy, batch['scope_name'])
    return batch


def _project(store: Store, batch) -> dict:
    """One transaction serializes double resumes and prevents partial projections."""
    rows = store.connection.execute('SELECT * FROM probes WHERE batch_id=? ORDER BY probe_name LIMIT ?',
                                    (batch['id'], store.policy.limits.observations + 1)).fetchall()
    probes = tuple(Probe(row['probe_name'], row['outcome'], row['started_at'], row['ended_at'], row['coverage_kind'],
                         row['coverage_value'], row['evidence_kind'], row['diagnostic_code']) for row in rows)
    _validate_probes(store, 'tcp_endpoint', 'network', batch['scope_value'], batch['started_at'], batch['ended_at'], batch['completion'], probes)
    grid = validate_probes(store.policy, batch['scope_name'], probes)
    previous = store.connection.execute('SELECT result_json FROM applications WHERE batch_id=?', (batch['id'],)).fetchone()
    if previous is not None:
        return json.loads(previous[0])
    counts: dict[str, int] = dict.fromkeys(STATES, 0)
    for row in rows:
        address, port = grid[row['probe_name']]
        state, qualified = RESULTS[(row['outcome'], row['diagnostic_code'])]
        store.connection.execute('INSERT INTO endpoint_observations VALUES (?,?,?,?,?,?)',
                                 (row['id'], address, 'tcp', port, state, int(qualified)))
        counts[state] += 1
    at, application = timestamp(utc_now()), identifier()
    result = {'id': application, 'batch_id': batch['id'], 'applied': True, 'projected': True,
              'observation_count': len(rows), 'state_counts': counts, 'applied_at': at}
    response_json(result, store.policy.limits.output_bytes)
    store.connection.execute('INSERT INTO applications VALUES (?,?,?,?,?)', (application, batch['id'], 1, at, encode(result)))
    store.audit(application, 'endpoints_projected', 'tcp_endpoint', at, batch=batch['id'], details={'observation_count': len(rows)})
    return result


def _receipt(batch: str | None = None) -> dict:
    return {'batch_id': batch, 'persisted': batch is not None, 'applied': False, 'projected': False,
            'queryable': False, 'stage': 'collection', 'collection_performed': False}


def check(policy: Policy, params: object) -> dict:
    """Collect once, or resume a genuine local batch without any network effects."""
    if not isinstance(params, dict) or set(params) not in ({'network'}, {'batch_id'}):
        raise ValueError('select a configured network OR exact batch ID')
    key = next(iter(params))
    value = params[key]
    if not isinstance(value, str) or re.fullmatch(NAME_PATTERN, value) is None:
        raise ValueError('invalid endpoint scope/batch name')
    deadline = time.monotonic() + policy.limits.operation_timeout_seconds
    # Ensure even a post-commit failure receipt can be emitted before any effects.
    response_json({**_receipt('0' * 36), 'stage': 'projection', 'completion': 'complete',
                   'error': 'endpoint stage failed; resume this batch'},
                  policy.limits.output_bytes)
    receipt = _receipt()
    if key == 'network':
        network = network_policy(policy, value)
        started = timestamp(utc_now())
        reserve = min(policy.limits.busy_timeout_ms / 1000, policy.limits.operation_timeout_seconds / 4)
        probes = Scheduler(network, policy, deadline - reserve, endpoints=True).run()
        successes = sum(probe.outcome == 'success' for probe in probes)
        completion = 'complete' if successes == len(probes) else 'partial' if successes else 'failed'
        with Store(policy, writable=True, deadline=deadline) as store:
            batch_id = store_batch(store, 'tcp_endpoint', value, started, timestamp(utc_now()), completion, probes, deadline=deadline)
            assert isinstance(batch_id, str)
        receipt = {**_receipt(batch_id), 'collection_performed': True, 'completion': completion}
    else:
        # Validate ID/ownership before claiming anything persisted. Never create
        # a missing store on the resume path or borrow another profile's grant.
        with Store(policy, deadline=deadline) as store:
            batch = _owned_batch(store, value)
            previous = store.connection.execute('SELECT 1 FROM applications WHERE batch_id=?', (value,)).fetchone()
            receipt = {**_receipt(value), 'completion': batch['completion'],
                       'applied': previous is not None, 'projected': previous is not None}
    return _finish(policy, receipt, deadline)


def _finish(policy: Policy, receipt: dict, deadline: float) -> dict:
    receipt['stage'] = 'projection'
    try:
        with Store(policy, writable=True, deadline=deadline) as store, store.transaction():
            batch = _stored(store, receipt['batch_id'])
            receipt['completion'] = batch['completion']
            result = _project(store, batch)
            completion = batch['completion']
        receipt.update(applied=True, projected=True, completion=completion)
        receipt['stage'] = 'readback'
        # New connection + snapshot after commit, with the SAME aggregate deadline.
        readback = query_endpoints(policy, {'batch_id': receipt['batch_id'], 'limit': 1, 'offset': 0}, deadline=deadline)
        if readback['total_count'] != result['observation_count']:
            raise ValueError('endpoint readback mismatch')
        receipt.update(queryable=True, stage='queryable', observation_count=result['observation_count'],
                       state_counts=result['state_counts'])
        response_json(receipt, policy.limits.output_bytes)
        return receipt
    except (OSError, ValueError, sqlite3.Error):
        # Do not erase a durable ID, claim rolled-back work applied, or retry a
        # probe just because projection/query/output failed after persistence.
        receipt['error'] = 'endpoint stage failed; resume this batch'
        # Keep this recovery receipt small even when final result exceeded output.
        receipt.pop('state_counts', None)
        receipt.pop('observation_count', None)
        return receipt


def endpoint_counts(store: Store) -> dict:
    """Global knowledge counters; these never confer local collection authority."""
    batches = store.connection.execute("SELECT COUNT(*) FROM batches WHERE collector='tcp_endpoint'").fetchone()[0]
    pending = store.connection.execute("SELECT COUNT(*) FROM batches b WHERE collector='tcp_endpoint' "
                                       "AND NOT EXISTS (SELECT 1 FROM applications a WHERE a.batch_id=b.id)").fetchone()[0]
    if store.schema_version < 2:
        return {'endpoint_count': 0, 'endpoint_observation_count': 0, 'endpoint_evidence_batches': batches,
                'responding_endpoint_count': 0, 'unprojected_endpoint_batches': pending}
    row = store.connection.execute('SELECT COUNT(*),COUNT(DISTINCT address || char(0) || port),'
        'COUNT(DISTINCT CASE WHEN qualified=1 THEN address || char(0) || port END) FROM endpoint_observations').fetchone()
    return {'endpoint_count': row[1], 'endpoint_observation_count': row[0], 'endpoint_evidence_batches': batches,
            'responding_endpoint_count': row[2], 'unprojected_endpoint_batches': pending}


def query_endpoints(policy: Policy, args: dict, *, deadline: float | None = None) -> dict:
    """Bounded historical evidence, independent of device identity and local grants."""
    limit, offset = args['limit'], args['offset']
    empty = {'endpoints': [], 'total_count': 0, 'has_more': False, 'limit': limit, 'offset': offset,
             'discovery_performed': False, 'identity': 'not_established', 'current_reachability': 'not_established'}
    if not policy.database.exists():
        return empty
    end = deadline if deadline is not None else time.monotonic() + policy.limits.operation_timeout_seconds
    with Store(policy, deadline=end) as store, store.snapshot():
        if store.schema_version < 2:
            return empty
        clauses, bindings = [], []
        for key, column in (('address', 'e.address'), ('batch_id', 'b.id')):
            if key in args:
                clauses.append(column + '=?')
                bindings.append(args[key])
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        source = ' FROM endpoint_observations e JOIN probes p ON p.id=e.probe_id JOIN batches b ON b.id=p.batch_id'
        total = store.connection.execute('SELECT COUNT(*)' + source + where, bindings).fetchone()[0]
        rows = store.connection.execute('SELECT e.*,p.batch_id,p.probe_name,p.outcome,p.diagnostic_code,p.started_at,p.ended_at AS checked_at,'
            'b.collector,b.source,b.policy_context,b.scope_name,b.scope_value,b.completion' + source + where +
            ' ORDER BY p.ended_at,e.probe_id LIMIT ? OFFSET ?', (*bindings, limit + 1, offset)).fetchall()
        result = {**empty, 'endpoints': [{**dict(row), 'qualified': bool(row['qualified']),
                    'qualification': 'historical_tcp_response_only' if row['qualified'] else 'no_response_or_no_check',
                    'coverage': 'not_checked' if row['state'] in {'not_started', 'unavailable'} else 'attempted_address_port_only',
                    'historical': True, 'device_id': None} for row in rows[:limit]],
                  'total_count': total, 'has_more': len(rows) > limit}
        response_json(result, policy.limits.output_bytes)
        return result
