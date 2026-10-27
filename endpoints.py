# SPDX-License-Identifier: GPL-3.0-or-later
"""Named TCP checks -> immutable batch -> endpoint projection -> fresh readback.

No service/identity inference or application bytes. Persistence is the recovery
boundary; application uses the existing unique-per-batch transactional marker.
"""
from __future__ import annotations

from contextlib import nullcontext
from ipaddress import ip_network
import json
import re
import sqlite3
import time
from typing import TYPE_CHECKING

from .batches import Probe, _scope, _validate_probes, store_batch
from .config import ActiveScopeError, ConfigError, Limits, NAME_PATTERN, Network, Policy, validate_network
from .errors import RequestError, StoreError
from .host_schedule import Scheduler
from .storage import Store, encode, identifier, response_json, timestamp, utc_now

if TYPE_CHECKING:
    from .endpoint_continuation import Reservation

STATES = ('open', 'closed', 'no_response', 'unavailable', 'not_started')
RECOVERY_ERRORS = {
    'observations': ('limits.observations: endpoint address/port grid exceeds configured record budget; '
                     'restore sufficient limits and resume this batch'),
    'policy': 'endpoint policy: check current network/port authorization and resume this batch',
    'store': 'endpoint store: check database availability and compatible schema; resume this batch',
    'io': 'endpoint local I/O: check store access and available space; resume this batch',
    'state': 'endpoint state or bounds: check stored evidence and configured limits; resume this batch',
}
RESULTS = {
    ('success', 'tcp_connected_response'): ('open', True),
    ('success', 'tcp_refused_response'): ('closed', True),
    ('timeout', 'effective_transport_deadline'): ('no_response', False),
    ('timeout', 'tcp_host_unreachable'): ('no_response', False),
    ('not_started', 'effective_deadline_before_start'): ('not_started', False),
    ('not_started', 'operation_deadline_exceeded'): ('not_started', False),
    ('not_started', 'host_deadline_before_start'): ('not_started', False),
    **{('unavailable', code): ('unavailable', False) for code in (
        'destination_excluded', 'transport_permission_denied',
        'transport_protocol_unsupported', 'transport_socket_failed')},
}


class EndpointObservationLimitError(RequestError):
    """The saved endpoint grid no longer fits the current observation budget."""


def _authorized_network(policy: Policy, name: str) -> Network:
    """Endpoint grants are independent of ping, ICMP, legacy ports and SSH."""
    network = next((item for item in policy.networks if item.name == name), None)
    if network is None:
        raise RequestError('network: select a configured endpoint network')
    validate_network(network, active=True)
    if not network.endpoint_ports:
        raise RequestError('network.endpoints: explicit enablement and nonempty tcp_ports required')
    return network


def network_policy(policy: Policy, name: str) -> Network:
    """Refuse over-budget collection before planning or transport effects."""
    network = _authorized_network(policy, name)
    if ip_network(network.cidr).num_addresses * len(network.endpoint_ports) > policy.limits.observations:
        raise EndpointObservationLimitError(
            'limits.observations: endpoint address/port grid exceeds configured record budget; '
            'check the configured limit against the original grid before retrying')
    return network


def plans(network: Network) -> dict[str, tuple[str, int]]:
    """Exact code-owned grid, including excluded/unstarted destinations as evidence."""
    return {f'tcp_{port}_{index}': (str(address), port)
            for index, address in enumerate(ip_network(network.cidr)) for port in network.endpoint_ports}


def validate_probes(policy: Policy, name: str, probes: tuple[Probe, ...], *,
                    selection: tuple[str, ...] | None = None) -> dict[str, tuple[str, int]]:
    """Reject missing/duplicate/forged evidence before storage or projection."""
    network = _authorized_network(policy, name)
    addresses = ip_network(network.cidr).num_addresses
    # Compare saved authorization before budget: expansion is not a request to
    # increase collection limits. Only matching, in-budget grids become plans.
    names = (set(selection) if selection is not None else {
        f'tcp_{port}_{index}' for index in range(addresses) for port in network.endpoint_ports})
    if len(probes) != len(names) or {probe.probe_name for probe in probes} != names:
        raise RequestError('network.endpoints.tcp_ports: endpoint evidence grid must match current port policy')
    expected = plans(network_policy(policy, name))
    if not names <= expected.keys():
        raise RequestError('network.endpoints.tcp_ports: saved selection is outside current port policy')
    for probe in probes:
        if ((probe.outcome, probe.diagnostic_code) not in RESULTS
                or probe.observations or probe.evidence_kind != 'tcp_endpoint'):
            raise ValueError('invalid endpoint evidence')
    return expected


def _owned_batch(store: Store, batch_id: str):
    batch = store.require('batches', batch_id)
    if batch['collector'] != 'tcp_endpoint' or batch['policy_context'] != str(store.policy.home):
        raise RequestError('batch_id: select endpoint evidence owned by this profile')
    return batch


def _stored(store: Store, batch_id: str):
    batch = _owned_batch(store, batch_id)
    _authorized_network(store.policy, batch['scope_name'])
    kind, scope, _ = _scope(store, 'tcp_endpoint', batch['scope_name'])
    if (batch['scope_kind'], batch['scope_value']) != (kind, scope):
        raise RequestError('network.cidr: saved endpoint scope must match current network policy')
    return batch


def _project(store: Store, batch, *, reservation: Reservation | None = None) -> dict:
    """One transaction serializes double resumes and prevents partial projections."""
    # Historical identity must remain visible after a policy limit is lowered.
    # The immutable hard ceiling bounds reads; current limits still gate use.
    rows = store.connection.execute('SELECT * FROM probes WHERE batch_id=? ORDER BY probe_name LIMIT ?',
                                    (batch['id'], Limits().observations + 1)).fetchall()
    probes = tuple(Probe(row['probe_name'], row['outcome'], row['started_at'], row['ended_at'], row['coverage_kind'],
                         row['coverage_value'], row['evidence_kind'], row['diagnostic_code']) for row in rows)
    from .endpoint_continuation import saved_selection
    grid = validate_probes(store.policy, batch['scope_name'], probes,
                           selection=saved_selection(store, batch['id'], reservation))
    _validate_probes(store, 'tcp_endpoint', 'network', batch['scope_value'], batch['started_at'],
                     batch['ended_at'], batch['completion'], probes)
    previous = store.connection.execute(
        'SELECT result_json FROM applications WHERE batch_id=?', (batch['id'],)).fetchone()
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
    store.connection.execute(
        'INSERT INTO applications VALUES (?,?,?,?,?)', (application, batch['id'], 1, at, encode(result)))
    store.audit(application, 'endpoints_projected', 'tcp_endpoint', at, batch=batch['id'],
                details={'observation_count': len(rows)})
    return result


def _receipt(batch: str | None = None) -> dict:
    return {'batch_id': batch, 'persisted': batch is not None, 'applied': False, 'projected': False,
            'queryable': False, 'stage': 'collection', 'collection_performed': False}


def longest_recovery_error(policy: Policy, *additional: str) -> str:
    """Reserve named-scope diagnostics as well as static post-persistence errors.

    Include granted scopes too: the same envelope must fit no-contact recovery
    after their grants are withdrawn. Names and diagnostics are validated ASCII.
    """
    return max((*RECOVERY_ERRORS.values(), *additional,
                *(str(ActiveScopeError(network.name)) for network in policy.networks)), key=len)


def collection_completion(probes: tuple[Probe, ...]) -> str:
    """Exclude ineligible destinations, not genuine failed or unstarted work."""
    eligible = [probe for probe in probes if probe.diagnostic_code != 'destination_excluded']
    successes = sum(probe.outcome == 'success' for probe in eligible)
    if not successes:
        return 'failed'
    return 'complete' if successes == len(eligible) else 'partial'


def check(policy: Policy, params: object) -> dict:
    """Collect once, or resume a genuine local batch without any network effects."""
    if isinstance(params, dict) and set(params) in ({'preview_batch_id'}, {'continue_batch_id'}):
        from .endpoint_continuation import continuation
        return continuation(policy, params)
    if not isinstance(params, dict) or set(params) not in ({'network'}, {'batch_id'}):
        raise RequestError('endpoint arguments: select a configured network OR exact batch_id, no other arguments')
    key = next(iter(params))
    value = params[key]
    if not isinstance(value, str) or re.fullmatch(NAME_PATTERN, value) is None:
        raise RequestError(f'{key}: stable configured network name or batch ID required')
    deadline = time.monotonic() + policy.limits.operation_timeout_seconds
    # Ensure even a post-commit failure receipt can be emitted before any effects.
    response_json({**_receipt('0' * 36), 'stage': 'projection', 'completion': 'complete',
                   'error': longest_recovery_error(policy)},
                  policy.limits.output_bytes)
    receipt = _receipt()
    if key == 'network':
        network = network_policy(policy, value)
        started = timestamp(utc_now())
        reserve = min(policy.limits.busy_timeout_ms / 1000, policy.limits.operation_timeout_seconds / 4)
        probes = Scheduler(network, policy, deadline - reserve, endpoints=True).run()
        completion = collection_completion(probes)
        with Store(policy, writable=True, deadline=deadline) as store:
            batch_id = store_batch(store, 'tcp_endpoint', value, started, timestamp(utc_now()),
                                   completion, probes, deadline=deadline)
            if not isinstance(batch_id, str):
                raise ValueError('endpoint persistence did not return a batch ID')
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


def _finish(policy: Policy, receipt: dict, deadline: float, *, reservation: Reservation | None = None) -> dict:
    receipt['stage'] = 'projection'
    try:
        if reservation is not None and reservation.policy is not policy:
            raise RequestError('endpoint continuation: matching request-local policy required')
        context = nullcontext(reservation.store) if reservation is not None else Store(
            policy, writable=True, deadline=deadline)
        with context as store, store.transaction():
            batch = _stored(store, receipt['batch_id'])
            receipt['completion'] = batch['completion']
            result = _project(store, batch, reservation=reservation)
            completion = batch['completion']
        receipt.update(applied=True, projected=True, completion=completion)
        receipt['stage'] = 'readback'
        # New connection + snapshot after commit, with the SAME aggregate deadline.
        readback = query_endpoints(
            policy, {'batch_id': receipt['batch_id'], 'limit': 1, 'offset': 0}, deadline=deadline)
        if readback['total_count'] != result['observation_count']:
            raise ValueError('endpoint readback mismatch')
        receipt.update(queryable=True, stage='queryable', observation_count=result['observation_count'],
                       state_counts=result['state_counts'])
        response_json(receipt, policy.limits.output_bytes)
        return receipt
    except (OSError, ValueError, sqlite3.Error) as exc:
        # Do not erase a durable ID, claim rolled-back work applied, or retry a
        # probe just because projection/query/output failed after persistence.
        category = ('observations' if isinstance(exc, EndpointObservationLimitError) else
                    'policy' if isinstance(exc, (ConfigError, RequestError)) else
                    'store' if isinstance(exc, (sqlite3.Error, StoreError)) else
                    'io' if isinstance(exc, OSError) else 'state')
        receipt['error'] = str(exc) if isinstance(exc, ActiveScopeError) else RECOVERY_ERRORS[category]
        # Keep this recovery receipt small even when final result exceeded output.
        receipt.pop('state_counts', None)
        receipt.pop('observation_count', None)
        return receipt


def endpoint_counts(store: Store) -> dict:
    """Global knowledge counters; these never confer local collection authority."""
    batches = store.connection.execute("SELECT COUNT(*) FROM batches WHERE collector='tcp_endpoint'").fetchone()[0]
    pending = store.connection.execute(
        "SELECT COUNT(*) FROM batches b WHERE collector='tcp_endpoint' "
        "AND NOT EXISTS (SELECT 1 FROM applications a WHERE a.batch_id=b.id)").fetchone()[0]
    if store.schema_version < 2:
        return {'endpoint_count': 0, 'endpoint_observation_count': 0, 'endpoint_evidence_batches': batches,
                'responding_endpoint_count': 0, 'unprojected_endpoint_batches': pending}
    row = store.connection.execute(
        'SELECT COUNT(*),COUNT(DISTINCT address || char(0) || port),'
        'COUNT(DISTINCT CASE WHEN qualified=1 THEN address || char(0) || port END) '
        'FROM endpoint_observations').fetchone()
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
        parent = 'NULL AS parent_batch_id'
        if store.schema_version >= 3:
            source += ' LEFT JOIN endpoint_continuations c ON c.child_batch_id=b.id'
            parent = 'c.parent_batch_id'
        total = store.connection.execute('SELECT COUNT(*)' + source + where, bindings).fetchone()[0]
        rows = store.connection.execute(
            'SELECT e.*,p.batch_id,p.probe_name,p.outcome,p.diagnostic_code,p.started_at,p.ended_at AS checked_at,'
            'b.collector,b.source,b.policy_context,b.scope_name,b.scope_value,b.completion,' + parent + source + where +
            ' ORDER BY p.ended_at,e.probe_id LIMIT ? OFFSET ?', (*bindings, limit + 1, offset)).fetchall()
        result = {**empty, 'endpoints': [{**dict(row), 'qualified': bool(row['qualified']),
                    'qualification': 'historical_tcp_response_only' if row['qualified'] else 'no_response_or_no_check',
                    'coverage': ('not_checked' if row['state'] in {'not_started', 'unavailable'}
                                 else 'attempted_address_port_only'),
                    'historical': True, 'device_id': None} for row in rows[:limit]],
                  'total_count': total, 'has_more': len(rows) > limit}
        response_json(result, policy.limits.output_bytes)
        return result
